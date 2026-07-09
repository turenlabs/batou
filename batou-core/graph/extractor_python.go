// Per-language extractor: Python.
//
// Walks a tree-sitter Python tree and yields FuncSignatures for every
// top-level `def func_name(...)` and `class Cls: def method_name(...)`.
// Class methods are emitted with names of the form "Cls.method_name" so
// FuncNode IDs line up with the Go path's "Receiver.Method" shape and
// with the Java extractor's "Outer.Inner.method" naming.
//
// Scope of this initial implementation:
//   - Top-level functions and class methods (including methods on
//     nested classes: "Outer.Inner.method").
//   - Type annotations on parameters and return values become canonical
//     types when the import scope resolves them.
//   - Source/sink types come from pythonTypeCatalog below — Flask /
//     Django / FastAPI request shapes for the common web frameworks.
//
// Closures (lambdas and nested defs) are emitted as FuncSignatures with
// canonical names anchored by line:col so the IDs match the builder's
// closure FuncNodes byte-for-byte. The `IsClosure` flag distinguishes
// them from regular defs for downstream propagation.
//
// Known limitations (documented for follow-up):
//   - Comprehensions (`[x for x in ...]`) are not emitted (rarely
//     security-relevant; they have their own implicit scope but no
//     callable identity).
//   - Closed-over (captured) variables from outer scope are not tracked
//     here — taint propagation through captures is the tsflow engine's
//     responsibility, not the builder/extractor.
//   - `from x import *` does not contribute to canonical type
//     resolution.
package graph

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

type pythonExtractor struct{}

func (pythonExtractor) Language() rules.Language { return rules.LangPython }

func (pythonExtractor) ExtractFunctions(ctx *ExtractContext) []FuncSignature {
	tree := pythonTree(ctx)
	if tree == nil {
		return nil
	}
	imports := extractPythonImports(tree.Root())
	var sigs []FuncSignature
	walkPythonTypes(tree.Root(), "", imports, &sigs)
	return sigs
}

func (pythonExtractor) ResolveVarType(ctx *ExtractContext, varName string, line int) string {
	return ""
}

func pythonTree(ctx *ExtractContext) *ast.Tree {
	if ctx == nil {
		return nil
	}
	if t, ok := ctx.TSTree.(*ast.Tree); ok && t != nil {
		return t
	}
	if ctx.Content == nil {
		return nil
	}
	return ast.Parse(ctx.Content, rules.LangPython)
}

// extractPythonImports walks the top-level import nodes and returns a
// short-name → fully-qualified-name map. Only direct top-level imports
// are considered (matching Python's actual binding semantics for module-
// level names); imports inside `if`/`try` blocks aren't tracked here.
func extractPythonImports(root *ast.Node) map[string]string {
	imports := map[string]string{}
	if root == nil {
		return imports
	}
	for i := 0; i < root.ChildCount(); i++ {
		child := root.Child(i)
		switch child.Type() {
		case "import_statement":
			collectImportStatement(child, imports)
		case "import_from_statement":
			// Pass empty thisPkg + nil star slice — the extractor only
			// cares about the type-name → FQN map. isInit=false has no
			// effect when thisPkg is empty.
			var stars []string
			collectImportFromStatement(child, "", false, imports, &stars)
		}
	}
	return imports
}

// walkPythonTypes recurses into class/function declarations, threading
// the enclosing class path as a dot-separated prefix.
func walkPythonTypes(n *ast.Node, prefix string, imports map[string]string, sigs *[]FuncSignature) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "class_definition":
			name := nodeFieldText(child, "name")
			childPrefix := name
			if prefix != "" && name != "" {
				childPrefix = prefix + "." + name
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkPythonTypes(body, childPrefix, imports, sigs)
			}
		case "function_definition":
			fullName := nodeFieldText(child, "name")
			if prefix != "" && fullName != "" {
				fullName = prefix + "." + fullName
			}
			if sig := extractPythonFunction(child, prefix, imports); sig != nil {
				*sigs = append(*sigs, *sig)
			}
			// Descend into the body to emit closure signatures for any
			// nested lambdas / nested defs. Class definitions inside the
			// body are handled separately by their own recursion arm.
			if body := child.ChildByFieldName("body"); body != nil && fullName != "" {
				walkPythonClosureSigs(body, fullName, imports, sigs)
			}
		case "decorated_definition":
			// Unwrap decorators; the actual definition is a nested
			// function_definition / class_definition.
			for j := 0; j < child.ChildCount(); j++ {
				c := child.Child(j)
				if c == nil {
					continue
				}
				switch c.Type() {
				case "function_definition":
					fullName := nodeFieldText(c, "name")
					if prefix != "" && fullName != "" {
						fullName = prefix + "." + fullName
					}
					if sig := extractPythonFunction(c, prefix, imports); sig != nil {
						*sigs = append(*sigs, *sig)
					}
					if body := c.ChildByFieldName("body"); body != nil && fullName != "" {
						walkPythonClosureSigs(body, fullName, imports, sigs)
					}
				case "class_definition":
					name := nodeFieldText(c, "name")
					childPrefix := name
					if prefix != "" && name != "" {
						childPrefix = prefix + "." + name
					}
					if body := c.ChildByFieldName("body"); body != nil {
						walkPythonTypes(body, childPrefix, imports, sigs)
					}
				}
			}
		default:
			walkPythonTypes(child, prefix, imports, sigs)
		}
	}
}

// walkPythonClosureSigs recurses into a function body, emitting a
// FuncSignature for every lambda and nested def encountered. The
// canonical names use the same line:col anchors as the builder's
// closure FuncNodes so signatures and nodes line up by ID. Nested
// closures get nested prefixes ("outer.lambda@L1:C1.inner@L2:C2").
//
// Stops at `class_definition` boundaries — class methods inside a body
// are reached via the outer `walkPythonTypes` recursion arm; emitting
// them again here would duplicate signatures.
func walkPythonClosureSigs(body *ast.Node, enclosing string, imports map[string]string, sigs *[]FuncSignature) {
	if body == nil {
		return
	}
	var visit func(n *ast.Node, currentName string)
	visit = func(n *ast.Node, currentName string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "class_definition":
			// Don't descend into nested classes from inside a function
			// body — they're emitted by the top-level recursion.
			return
		case "lambda":
			line := int(n.StartRow()) + 1
			col := int(n.StartCol())
			closureName := currentName + ".lambda@" + itoa(line) + ":" + itoa(col)
			sig := extractPythonLambda(n, closureName, imports)
			if sig != nil {
				*sigs = append(*sigs, *sig)
			}
			if lambdaBody := n.ChildByFieldName("body"); lambdaBody != nil {
				visit(lambdaBody, closureName)
			}
			return
		case "function_definition":
			name := nodeFieldText(n, "name")
			if name == "" {
				return
			}
			line := int(n.StartRow()) + 1
			col := int(n.StartCol())
			closureName := currentName + "." + name + "@" + itoa(line) + ":" + itoa(col)
			if sig := extractPythonFunctionWithName(n, closureName, imports); sig != nil {
				sig.IsClosure = true
				*sigs = append(*sigs, *sig)
			}
			if defBody := n.ChildByFieldName("body"); defBody != nil {
				visit(defBody, closureName)
			}
			return
		case "decorated_definition":
			// Recurse through to the inner function_definition.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c == nil {
					continue
				}
				switch c.Type() {
				case "function_definition", "lambda":
					visit(c, currentName)
				}
			}
			return
		}
		for _, c := range n.NamedChildren() {
			visit(c, currentName)
		}
	}
	for _, c := range body.NamedChildren() {
		visit(c, enclosing)
	}
}

// itoa is a tiny non-allocating substitute for strconv.Itoa, kept local
// to avoid pulling another import into a hot path.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// extractPythonFunctionWithName is like extractPythonFunction but with
// an externally-supplied fully-qualified name (used for closures whose
// names embed line:col anchors that the caller computes).
func extractPythonFunctionWithName(n *ast.Node, fullName string, imports map[string]string) *FuncSignature {
	if n == nil || fullName == "" {
		return nil
	}
	sig := &FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
	}
	if params := n.ChildByFieldName("parameters"); params != nil {
		sig.Params = extractPythonParams(params, imports)
	}
	if ret := n.ChildByFieldName("return_type"); ret != nil {
		rawType := strings.TrimSpace(ret.Text())
		canonical := canonicalizePythonType(rawType, imports)
		r := ReturnTaint{
			Index:         0,
			Type:          rawType,
			CanonicalType: canonical,
		}
		if cat, ok := pythonTypeCatalog.LookupSourceReturn(canonical); ok {
			r.IsSourceType = true
			r.SourceCategory = cat
		} else if cat, ok := pythonTypeCatalog.LookupSource(canonical); ok {
			r.IsSourceType = true
			r.SourceCategory = cat
		}
		sig.Returns = append(sig.Returns, r)
	}
	return sig
}

// extractPythonLambda produces a FuncSignature for a `lambda` node. The
// lambda parameters live under `lambda_parameters` rather than the
// `parameters` node used by `function_definition`, and lambdas have no
// return-type annotation, so we collect params separately from
// extractPythonFunction.
func extractPythonLambda(n *ast.Node, fullName string, imports map[string]string) *FuncSignature {
	if n == nil || fullName == "" {
		return nil
	}
	sig := &FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
		IsClosure: true,
	}
	if params := n.ChildByFieldName("parameters"); params != nil {
		sig.Params = extractPythonParams(params, imports)
	}
	return sig
}

func extractPythonFunction(n *ast.Node, prefix string, imports map[string]string) *FuncSignature {
	name := nodeFieldText(n, "name")
	if name == "" {
		return nil
	}
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	sig := &FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
	}
	if params := n.ChildByFieldName("parameters"); params != nil {
		sig.Params = extractPythonParams(params, imports)
	}
	// Return type annotation, if any.
	if ret := n.ChildByFieldName("return_type"); ret != nil {
		rawType := strings.TrimSpace(ret.Text())
		canonical := canonicalizePythonType(rawType, imports)
		r := ReturnTaint{
			Index:         0,
			Type:          rawType,
			CanonicalType: canonical,
		}
		if cat, ok := pythonTypeCatalog.LookupSourceReturn(canonical); ok {
			r.IsSourceType = true
			r.SourceCategory = cat
		} else if cat, ok := pythonTypeCatalog.LookupSource(canonical); ok {
			r.IsSourceType = true
			r.SourceCategory = cat
		}
		sig.Returns = append(sig.Returns, r)
	}
	return sig
}

func extractPythonParams(params *ast.Node, imports map[string]string) []ParamTaint {
	var out []ParamTaint
	idx := 0
	for _, child := range params.NamedChildren() {
		var rawType, paramName string
		switch child.Type() {
		case "identifier":
			paramName = strings.TrimSpace(child.Text())
		case "typed_parameter":
			// typed_parameter has an identifier child and a `type:` field.
			for _, c := range child.NamedChildren() {
				if c.Type() == "identifier" && paramName == "" {
					paramName = strings.TrimSpace(c.Text())
				}
			}
			if typeNode := child.ChildByFieldName("type"); typeNode != nil {
				rawType = strings.TrimSpace(typeNode.Text())
			}
		case "default_parameter":
			if nameNode := child.ChildByFieldName("name"); nameNode != nil {
				paramName = strings.TrimSpace(nameNode.Text())
			}
		case "typed_default_parameter":
			if nameNode := child.ChildByFieldName("name"); nameNode != nil {
				paramName = strings.TrimSpace(nameNode.Text())
			}
			if typeNode := child.ChildByFieldName("type"); typeNode != nil {
				rawType = strings.TrimSpace(typeNode.Text())
			}
		case "list_splat_pattern", "dictionary_splat_pattern":
			// *args / **kwargs — emit with their identifier name; no
			// type annotation tracked.
			for _, c := range child.NamedChildren() {
				if c.Type() == "identifier" && paramName == "" {
					paramName = strings.TrimSpace(c.Text())
				}
			}
		default:
			continue
		}
		// Skip implicit `self`/`cls` at index 0 of a method? The
		// canonical Go signature includes the receiver as an unnamed
		// position-0 metadata entry; we do the same here so positional
		// indices line up with Python's call semantics (self IS arg 0
		// for method calls on instances). Keeping it avoids surprising
		// off-by-ones in interproc type matching.
		canonical := canonicalizePythonType(rawType, imports)
		p := ParamTaint{
			Index:         idx,
			Name:          paramName,
			Type:          rawType,
			CanonicalType: canonical,
		}
		if cat, ok := pythonTypeCatalog.LookupSource(canonical); ok {
			p.IsSourceType = true
			p.SourceCategory = cat
		}
		if cat, ok := pythonTypeCatalog.LookupSink(canonical); ok {
			p.IsSinkType = true
			p.SinkCategory = cat
		}
		out = append(out, p)
		idx++
	}
	return out
}

// canonicalizePythonType resolves a raw Python type annotation to its
// fully-qualified name using the import map. Handles:
//   - Plain type: "Request" → "flask.Request" (when `from flask import
//     Request`)
//   - Dotted: "flask.Request" → "flask.Request" (already qualified)
//   - Generic: "List[str]" → "typing.List[str]" (head resolved)
//   - Unresolved: returns the input unchanged
func canonicalizePythonType(raw string, imports map[string]string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	head := raw
	tail := ""
	if i := strings.IndexAny(raw, "[("); i >= 0 {
		head = raw[:i]
		tail = raw[i:]
	}
	head = strings.TrimSpace(head)
	if strings.Contains(head, ".") {
		// Already qualified — resolve only the leftmost segment via
		// imports (e.g. `flask.Request` stays as-is; `req.Request`
		// stays as-is too).
		leftDot := strings.IndexByte(head, '.')
		alias := head[:leftDot]
		if fqn, ok := imports[alias]; ok {
			return fqn + head[leftDot:] + tail
		}
		return raw
	}
	if fqn, ok := imports[head]; ok {
		return fqn + tail
	}
	return raw
}

// pythonTypeCatalog is the initial Python framework source/sink type
// catalog. Covers Flask, Django, FastAPI, and the standard library's
// most common request shapes. Additional framework coverage belongs in
// follow-up PRs; this PR is the resolver foundation.
var pythonTypeCatalog = &TypeCatalog{
	SourceParam: map[string]taint.SourceCategory{
		// Flask
		"flask.Request": taint.SrcUserInput,
		"flask.request": taint.SrcUserInput,
		// Django
		"django.http.HttpRequest":         taint.SrcUserInput,
		"django.http.request.HttpRequest": taint.SrcUserInput,
		// FastAPI / Starlette
		"fastapi.Request":            taint.SrcUserInput,
		"starlette.requests.Request": taint.SrcUserInput,
		// AIOHTTP
		"aiohttp.web.Request": taint.SrcUserInput,
		// Bottle
		"bottle.Request": taint.SrcUserInput,
	},
	SinkParam: map[string]taint.SinkCategory{
		// JDBC-ish DBAPI handles — passing one to your own function
		// means the function can run arbitrary SQL against it.
		"sqlite3.Connection":  taint.SnkSQLQuery,
		"sqlite3.Cursor":      taint.SnkSQLQuery,
		"psycopg2.connection": taint.SnkSQLQuery,
		"psycopg2.cursor":     taint.SnkSQLQuery,
	},
	SourceReturn: map[string]taint.SourceCategory{
		"flask.Request":              taint.SrcUserInput,
		"django.http.HttpRequest":    taint.SrcUserInput,
		"fastapi.Request":            taint.SrcUserInput,
		"starlette.requests.Request": taint.SrcUserInput,
	},
}

// PythonTypeCatalog returns the Python type catalog. Exposed for tests
// and follow-up loop PRs that want to extend the framework coverage.
func PythonTypeCatalog() *TypeCatalog { return pythonTypeCatalog }

func init() {
	RegisterExtractor(pythonExtractor{})
}
