// C++ FuncNode builder (PR-Gcpp).
//
// The generic regex-based path in buildGenericNodes can't see C++'s
// `std::string getName(const Request& req) { ... }` /
// `namespace ns { ... }` / `struct Foo { void bar() {} }` structure,
// doesn't qualify method names with their owning type, and does NOT
// populate FuncNode.RawCalls — which the cross-file resolver needs to
// walk per-call expressions. This file implements a tree-sitter-based
// C++ builder mirroring the Swift / Java / Lua builders:
//
//   - `T foo(...)`                          → FuncNode "foo" (free fn).
//   - `namespace ns { T foo(...) }`         → FuncNode "ns.foo".
//   - `struct Foo { void bar() {} }`        → FuncNode "Foo.bar"
//     (methods defined inline in a class/struct body).
//   - `void Foo::bar(...) { ... }`          → FuncNode "Foo.bar"
//     (out-of-line method definition — the qualified declarator scope is
//     promoted to the FuncNode prefix so a `Foo::bar` call resolves to
//     the same node as the inline form).
//   - Nested namespaces / types flow through with dotted prefixes
//     (`Outer.Inner.method`).
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls whose
//     bare name matches a known node in this file. The cross-file pass
//     (resolver_cpp.go) handles cross-translation-unit resolution via
//     `#include "x.h"` → sibling `.cpp`/`.h` files.
//
// C++ name qualification is `::`-separated in the source (`ns::func`,
// `Class::method`) but we normalise to a dotted prefix internally so the
// resolver's suffix-match loop is the same shape as every other port
// (Swift/Lua/Java all key on the dotted basename). The walker also
// records both the bare and `::`-qualified call text so the resolver can
// strip the scope.
//
// Every line here is reached only for C-family files (rules.LangC and
// rules.LangCPP): UpdateFileWithAST dispatches to buildCPPNodes solely from
// its `case rules.LangC, rules.LangCPP` arm, so this builder cannot alter
// graph construction for any other language. The file's own language is
// threaded through as `lang`, selecting the tree-sitter grammar and being
// stamped onto each FuncNode.Language.
package graph

import (
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildCPPNodes is the C/C++-specific equivalent of buildSwiftNodes /
// buildLuaNodes. Returns nil ONLY when tree-sitter parsing fails, letting
// the caller (UpdateFileWithAST) fall back to the generic regex path. On
// a successful parse it returns a non-nil slice (possibly empty, on a warm
// rescan where every content-hash-unchanged node is reused) so the
// dispatcher keeps the type-qualified C/C++ nodes instead of clobbering them
// with the generic builder.
//
// The `lang` parameter is the file's own language (rules.LangC for `.c`/`.h`,
// rules.LangCPP for `.cpp`/`.hpp`/...). It selects the grammar for the
// fallback parse and is stamped onto each FuncNode.Language so the cross-file
// walker routes the node to the matching taint catalog. The C and C++ grammars
// share the function_definition / call_expression / preproc_include /
// struct_specifier shapes this walker consumes, so one traversal handles both;
// namespace nodes simply never appear in C.
func buildCPPNodes(cg *CallGraph, filePath, content string, lang rules.Language, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), lang)
	}
	if tree == nil || tree.Root() == nil {
		return nil
	}

	oldNodes := make(map[string]*FuncNode)
	for _, n := range cg.NodesInFile(filePath) {
		oldNodes[n.ID] = n
	}
	cg.RemoveFile(filePath)

	// Non-nil empty slice: a successful parse with zero *changed* nodes
	// (the warm-rescan content-hash-reuse case) must still return non-nil
	// so UpdateFileWithAST does NOT fall back to the generic regex builder
	// and clobber the type-qualified nodes we just re-registered. `nil`
	// is reserved for genuine parse failure (handled above). Mirrors the
	// Swift / Java / Lua builders.
	updatedIDs := []string{}
	callMap := make(map[string][]string)

	walkCPPBuilderNodes(tree.Root(), "", cg, filePath, content, lang, oldNodes, &updatedIDs, callMap)

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "Type::name" / "ns::name" calls are left to the cross-file pass.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			bare := callName
			if i := strings.LastIndex(bare, "::"); i >= 0 {
				bare = bare[i+2:]
			}
			if strings.ContainsRune(bare, '.') {
				continue
			}
			// Exact qualified match first (`ns::func` written exactly).
			if strings.Contains(callName, "::") {
				qualified := strings.ReplaceAll(callName, "::", ".")
				calleeID := FuncID(filePath, qualified)
				if cg.GetNode(calleeID) != nil {
					cg.AddEdge(callerID, calleeID)
					continue
				}
			}
			calleeID := FuncID(filePath, bare)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
				continue
			}
			// Method / namespace suffix match: caller does `doThing()`
			// which might actually be `Type.doThing` / `ns.doThing`.
			for _, n := range cg.NodesInFile(filePath) {
				if strings.HasSuffix(n.Name, "."+bare) {
					cg.AddEdge(callerID, n.ID)
					break
				}
			}
		}
	}

	return updatedIDs
}

// walkCPPBuilderNodes recursively visits the tree, threading the dotted
// scope prefix and emitting one FuncNode per `function_definition`. A
// `namespace_definition` introduces a namespace prefix; a
// `class_specifier` / `struct_specifier` introduces a type prefix for the
// methods in its body. Out-of-line method definitions
// (`void Foo::bar() {}`) carry their scope in the declarator, handled in
// emitCPPFunc.
func walkCPPBuilderNodes(
	n *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "namespace_definition":
			nsName := cppNamespaceName(child)
			nsPrefix := nsName
			if prefix != "" && nsName != "" {
				nsPrefix = prefix + "." + nsName
			} else if nsName == "" {
				nsPrefix = prefix
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkCPPBuilderNodes(body, nsPrefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			} else {
				walkCPPBuilderNodes(child, nsPrefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			}
		case "class_specifier", "struct_specifier", "union_specifier":
			typeName := cppTypeDeclName(child)
			typePrefix := typeName
			if prefix != "" && typeName != "" {
				typePrefix = prefix + "." + typeName
			} else if typeName == "" {
				typePrefix = prefix
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkCPPBuilderNodes(body, typePrefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			} else {
				walkCPPBuilderNodes(child, typePrefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			}
		case "function_definition":
			name, scope := cppFuncDeclName(child)
			if name == "" {
				continue
			}
			fullName := name
			// An out-of-line declarator scope (`Foo::bar`) overrides the
			// lexical prefix; combine a lexical prefix with the scope.
			effectivePrefix := prefix
			if scope != "" {
				if prefix != "" {
					effectivePrefix = prefix + "." + scope
				} else {
					effectivePrefix = scope
				}
			}
			if effectivePrefix != "" {
				fullName = effectivePrefix + "." + name
			}
			emitCPPFunc(child, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
		case "template_declaration", "linkage_specification",
			"declaration", "preproc_if", "preproc_ifdef":
			// Descend into wrappers that may contain function definitions
			// (templated functions, extern "C" blocks, conditionally-
			// compiled regions) without introducing a scope prefix.
			walkCPPBuilderNodes(child, prefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
		default:
			walkCPPBuilderNodes(child, prefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
		}
	}
}

// cppNamespaceName returns the declared name of a namespace_definition, or
// "" for an anonymous namespace.
func cppNamespaceName(decl *tsast.Node) string {
	if nm := decl.ChildByFieldName("name"); nm != nil {
		return strings.TrimSpace(nm.Text())
	}
	for _, c := range decl.NamedChildren() {
		if c.Type() == "namespace_identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// cppTypeDeclName returns the declared type name of a class / struct /
// union specifier. The name is on the `name` field (a `type_identifier`),
// or the first type_identifier child.
func cppTypeDeclName(decl *tsast.Node) string {
	if nm := decl.ChildByFieldName("name"); nm != nil {
		return cppLastScopeSegment(strings.TrimSpace(nm.Text()))
	}
	for _, c := range decl.NamedChildren() {
		if c.Type() == "type_identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// cppFuncDeclName returns the simple function name and (for out-of-line
// definitions) the dotted scope of a `function_definition` node. The name
// lives on the `declarator` field — a `function_declarator` whose own
// `declarator` is an `identifier` (free fn / inline method),
// `field_identifier` (inline method), or `qualified_identifier`
// (`Foo::bar` out-of-line) / `destructor_name` / `operator_name`.
//
// Returns ("getName", "")        for `T getName(...)`.
// Returns ("bar", "Foo")         for `void Foo::bar(...)`.
// Returns ("baz", "ns.Foo")      for `void ns::Foo::baz(...)`.
func cppFuncDeclName(fn *tsast.Node) (name, scope string) {
	decl := fn.ChildByFieldName("declarator")
	// Unwrap pointer / reference declarators (`T* foo()`, `T& foo()`).
	for decl != nil {
		switch decl.Type() {
		case "pointer_declarator", "reference_declarator":
			inner := decl.ChildByFieldName("declarator")
			if inner == nil {
				inner = firstCPPNamedDeclarator(decl)
			}
			decl = inner
		default:
			goto haveDecl
		}
	}
haveDecl:
	if decl == nil || decl.Type() != "function_declarator" {
		return "", ""
	}
	id := decl.ChildByFieldName("declarator")
	if id == nil {
		return "", ""
	}
	switch id.Type() {
	case "identifier", "field_identifier", "destructor_name", "operator_name":
		return strings.TrimSpace(id.Text()), ""
	case "qualified_identifier":
		full := strings.TrimSpace(id.Text())
		// `Foo::bar` → name "bar", scope "Foo". `ns::Foo::bar` → name
		// "bar", scope "ns.Foo".
		segs := splitCPPScope(full)
		if len(segs) == 0 {
			return "", ""
		}
		name = segs[len(segs)-1]
		if len(segs) > 1 {
			scope = strings.Join(segs[:len(segs)-1], ".")
		}
		return name, scope
	}
	// Fallback: last identifier-ish token of the declarator text.
	return cppLastScopeSegment(strings.TrimSpace(id.Text())), ""
}

// firstCPPNamedDeclarator returns the first named child that looks like a
// declarator (used when the `declarator` field is absent on a pointer /
// reference declarator).
func firstCPPNamedDeclarator(n *tsast.Node) *tsast.Node {
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "function_declarator", "pointer_declarator",
			"reference_declarator", "identifier", "field_identifier",
			"qualified_identifier":
			return c
		}
	}
	return nil
}

// splitCPPScope splits a `::`-qualified identifier into its segments,
// dropping any template-argument tails (`Foo<int>::bar` → ["Foo", "bar"]).
func splitCPPScope(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "::")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if i := strings.IndexByte(p, '<'); i >= 0 {
			p = p[:i]
		}
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cppLastScopeSegment returns the final `::`-separated segment of a
// possibly-qualified name (`ns::Foo` → "Foo", `Foo<int>` → "Foo").
func cppLastScopeSegment(s string) string {
	segs := splitCPPScope(s)
	if len(segs) == 0 {
		return strings.TrimSpace(s)
	}
	return segs[len(segs)-1]
}

// emitCPPFunc creates (or reuses) a FuncNode for fn with the already-
// qualified fullName, then walks the body to collect RawCalls into
// callMap[node.ID].
func emitCPPFunc(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if fn == nil || fullName == "" {
		return
	}
	node := registerCPPFunc(fn, fullName, cg, filePath, content, lang, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	walkCPPBodyForCalls(fn, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerCPPFunc builds or reuses a FuncNode for fn.
func registerCPPFunc(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
) *FuncNode {
	startLine := int(fn.StartRow()) + 1
	endLine := int(fn.EndRow()) + 1
	bodyStart := fn.StartByte()
	bodyEnd := fn.EndByte()
	bodyText := ""
	if int(bodyStart) >= 0 && int(bodyEnd) <= len(content) && bodyStart < bodyEnd {
		bodyText = content[bodyStart:bodyEnd]
	}
	hash := ContentHash(bodyText)
	id := FuncID(filePath, fullName)

	if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
		old.RawCalls = nil
		cg.AddNode(old)
		return old
	}
	node := &FuncNode{
		ID:          id,
		FilePath:    filePath,
		Name:        fullName,
		StartLine:   startLine,
		EndLine:     endLine,
		ContentHash: hash,
		LastScanAt:  time.Now(),
		Language:    lang,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkCPPBodyForCalls walks a function body and records every
// `call_expression` node's textual function reference into
// callMap[outer.ID]. We don't descend into nested function / type
// declarations — those become separate top-level nodes elsewhere.
func walkCPPBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_definition", "class_specifier",
			"struct_specifier", "namespace_definition", "union_specifier":
			// Don't descend into nested function / type declarations — they
			// become separate top-level nodes. (The root passed in here is
			// the outer's own definition, so we still walk its body below
			// via NamedChildren before the guard can fire on the root.)
			if n != root {
				return
			}
		case "call_expression":
			if name := cppCallName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls nested in arguments
			// (`system(getName(req).c_str())`) are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// cppCallName returns the canonical raw-name form of a C++
// `call_expression` node:
//
//	"foo"          for `foo(...)`              (identifier callee)
//	"ns::foo"      for `ns::foo(...)`          (qualified_identifier callee)
//	"obj.method"   for `obj.method(...)`       (field_expression callee)
//	""             for deeper / unrecognised shapes.
//
// The `::`-qualified form is preserved so the resolver's suffix match can
// strip the namespace / class scope; the `.`-receiver form is preserved
// so a same-file `this->method()` resolves by method basename.
func cppCallName(n *tsast.Node) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		// Some grammar revisions don't field the callee; take the first
		// named child, unless it is the argument list.
		if kids := n.NamedChildren(); len(kids) > 0 && kids[0].Type() != "argument_list" {
			fn = kids[0]
		}
	}
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text())
	case "qualified_identifier":
		return strings.TrimSpace(fn.Text())
	case "field_expression":
		// `obj.method` / `ptr->method` — keep the trailing field name; the
		// receiver is a runtime value, not an import alias.
		if fld := fn.ChildByFieldName("field"); fld != nil {
			return strings.TrimSpace(fld.Text())
		}
		return cppLastScopeSegment(strings.TrimSpace(fn.Text()))
	case "template_function":
		// `foo<T>(...)` — strip the template argument tail.
		if name := fn.ChildByFieldName("name"); name != nil {
			return strings.TrimSpace(name.Text())
		}
		return cppLastScopeSegment(strings.TrimSpace(fn.Text()))
	case "parenthesized_expression":
		return ""
	}
	return ""
}
