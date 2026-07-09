package graph

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/astflow"
	"github.com/turenlabs/batou-rules/rules"
)

// ClosureSuffixFormat is the suffix appended to an enclosing function's name
// to identify a closure literal that lives inside it. The line:col coordinates
// come from fset.Position(funcLit.Pos()) so the same source produces the same
// IDs across runs. Two closures on the same line at different columns get
// distinct IDs; nested closures get nested suffixes (".closure@L:C.closure@L:C").
const ClosureSuffixFormat = ".closure@%d:%d"

// FormatClosureName returns the canonical "<EnclosingName>.closure@<line>:<col>"
// name for a closure literal at the given fileset position. Used both by the
// builder when emitting closure FuncNodes and by tests when asserting their IDs.
func FormatClosureName(enclosingName string, line, col int) string {
	return enclosingName + fmt.Sprintf(ClosureSuffixFormat, line, col)
}

// isClosureName reports whether a FuncNode name belongs to a closure literal
// (i.e. contains a ".closure@" segment). Used by the resolver and interproc
// passes to apply closure-specific behavior — closures have no exported name,
// so the only edges that target them are the synthetic edge from the
// immediate enclosing function.
func isClosureName(name string) bool {
	return strings.Contains(name, ".closure@")
}

// UpdateFile parses a file and updates the call graph with its function
// nodes and call relationships. Returns the list of function IDs that
// were updated (so we know which callers to re-analyze).
func UpdateFile(cg *CallGraph, filePath string, content string, lang rules.Language) []string {
	return UpdateFileWithAST(cg, filePath, content, lang, nil, nil)
}

// UpdateFileWithAST is like UpdateFile but accepts pre-parsed ASTs to avoid
// redundant parsing: `parsed` is the go/ast for Go files; `tsTree` is the
// tree-sitter tree (the same one Layer-2 already produced) reused by the
// tree-sitter builders so they don't re-parse the file a second time. Either
// may be nil, in which case the relevant builder parses on demand.
func UpdateFileWithAST(cg *CallGraph, filePath string, content string, lang rules.Language, parsed *astflow.GoParseResult, tsTree *tsast.Tree) []string {
	switch lang {
	case rules.LangGo:
		return buildGoNodes(cg, filePath, content, parsed)
	case rules.LangPython:
		// Python uses a tree-sitter-based builder so it can emit
		// class-qualified method nodes and populate RawCalls for the
		// cross-file resolver. Falls back to the generic regex path
		// when tree-sitter parsing fails.
		if ids := buildPythonNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangJavaScript, rules.LangTypeScript:
		// JS/TS uses a tree-sitter-based builder for the same reasons as
		// Python — class methods get qualified names, CommonJS / ESM
		// exports get the right node names, and RawCalls is populated
		// so the cross-file resolver has something to walk. Falls back
		// to the generic regex path when parsing fails.
		if ids := buildJSNodes(cg, filePath, content, lang, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangJava:
		// Java uses a tree-sitter-based builder so class methods get
		// qualified names ("Cls.method"), constructors are emitted as
		// "Cls.Cls" (so `new Cls(...)` resolves through the same
		// lookup), and RawCalls is populated for the cross-file
		// resolver. Falls back to the generic regex path when parsing
		// fails.
		if ids := buildJavaNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangRuby:
		// Ruby uses a tree-sitter-based builder so class / module
		// methods get qualified names ("Cls.method", "Mod.method"),
		// Sinatra DSL route blocks get a synthetic FuncNode anchored
		// to the route's call coordinates, and RawCalls is populated
		// for the cross-file resolver. Falls back to the generic regex
		// path when parsing fails.
		if ids := buildRubyNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangPHP:
		// PHP uses a tree-sitter-based builder that emits namespace-
		// qualified function and method nodes (e.g. "App\Foo::bar"),
		// constructors as "Cls::__construct", and closures bound to
		// variables/properties. RawCalls is populated so the cross-file
		// PHP resolver (composer.json PSR-4 + same-namespace probe) has
		// per-call expressions to walk. Falls back to the generic regex
		// path when tree-sitter parsing fails.
		if ids := buildPHPNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangLua:
		// Lua uses a tree-sitter-based builder so module-table methods get
		// qualified names ("M.handler"), `local function` defs get a node,
		// and RawCalls is populated so the cross-file resolver (require()
		// path resolution, see resolver_lua.go) has per-call expressions to
		// walk. Falls back to the generic regex path when tree-sitter
		// parsing fails.
		if ids := buildLuaNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangKotlin:
		// Kotlin uses a tree-sitter-based builder so class / object / companion
		// methods get qualified names ("Cls.method"), top-level functions get
		// a package-qualified node ("pkg.getName"), overloads get distinct node
		// IDs (no FuncID collision), and RawCalls is populated for the
		// cross-file resolver (resolver_kotlin.go — package + import
		// resolution). Falls back to the generic regex path when tree-sitter
		// parsing fails.
		if ids := buildKotlinNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangGroovy:
		// Groovy uses a tree-sitter-based builder so class methods get
		// package-qualified names ("app.A.getName"), free functions get a
		// package-qualified node ("app.foo"), top-level script statements get
		// a synthetic "app.<groovyScriptMain>" node, and RawCalls is
		// populated for the cross-file resolver (resolver_groovy.go —
		// package-qualified same-package resolution). Falls back to the
		// generic regex path when tree-sitter parsing fails.
		if ids := buildGroovyNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangPerl:
		// Perl uses a tree-sitter-based builder so package subs get
		// qualified names ("Pkg::sub") under the enclosing `package`
		// declaration, top-level subs get a bare node, and RawCalls is
		// populated so the cross-file resolver (use/require + Pkg::sub
		// resolution, see resolver_perl.go) has per-call expressions to
		// walk. Falls back to the generic regex path when tree-sitter
		// parsing fails.
		if ids := buildPerlNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangShell:
		// Shell uses a tree-sitter-based builder so each `name() { ... }` /
		// `function name { ... }` definition gets a bare-name FuncNode, a
		// synthetic "<module>" node captures the script's top-level
		// statements, and RawCalls is populated (every command-word in the
		// body) so the cross-file resolver (source-graph-scoped bare-name
		// resolution, see resolver_shell.go) has per-call expressions to walk.
		// Falls back to the generic regex path when tree-sitter parsing fails.
		if ids := buildShellNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangC, rules.LangCPP:
		// C/C++ use a tree-sitter-based builder so namespace functions and
		// class/struct methods get qualified names ("ns.func", "Cls.method"),
		// out-of-line definitions ("void Cls::method() {}") map to the same
		// node as their inline form, and RawCalls is populated for the
		// cross-file resolver (resolver_cpp.go — #include "x.h" → sibling
		// .cpp/.h resolution). Falls back to the generic regex path when
		// tree-sitter parsing fails.
		if ids := buildCPPNodes(cg, filePath, content, lang, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangSwift:
		// Swift uses a tree-sitter-based builder so methods on struct /
		// class / enum / extension types get qualified names ("Type.method"),
		// free functions get a bare node, and RawCalls is populated so the
		// cross-file resolver (same-module bare-symbol resolution, see
		// resolver_swift.go) has per-call expressions to walk. Falls back to
		// the generic regex path when tree-sitter parsing fails.
		if ids := buildSwiftNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangRust:
		// Rust uses a tree-sitter-based builder so free functions and impl
		// methods get FuncNodes and RawCalls is populated so the cross-file
		// resolver (mod/use file resolution, see resolver_rust.go) has
		// per-call expressions to walk. Falls back to the generic regex
		// path when tree-sitter parsing fails.
		if ids := buildRustNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	case rules.LangCSharp:
		// C# uses a tree-sitter-based builder so class methods get
		// qualified names ("Cls.Method"), constructors are emitted as
		// "Cls.Cls" (so `new Cls(...)` resolves through the same lookup),
		// namespaces (block- and file-scoped) thread into the dotted
		// prefix, and RawCalls is populated for the cross-file resolver
		// (resolver_csharp.go — namespace + using resolution). Falls back
		// to the generic regex path when tree-sitter parsing fails.
		if ids := buildCSharpNodes(cg, filePath, content, tsTree); ids != nil {
			return ids
		}
		return buildGenericNodes(cg, filePath, content, lang)
	default:
		return buildGenericNodes(cg, filePath, content, lang)
	}
}

// buildGoNodes uses go/ast to extract function declarations and call
// relationships from Go source code.
func buildGoNodes(cg *CallGraph, filePath string, content string, parsed *astflow.GoParseResult) []string {
	if parsed == nil {
		parsed = astflow.ParseGo(content, filePath)
		if parsed == nil {
			return nil
		}
	}

	fset := parsed.Fset
	f := parsed.File

	// Snapshot old nodes from this file so we can detect changes.
	oldNodes := make(map[string]*FuncNode)
	for _, node := range cg.NodesInFile(filePath) {
		oldNodes[node.ID] = node
	}

	// Remove old nodes for this file before adding new ones.
	cg.RemoveFile(filePath)

	var updatedIDs []string
	// Map from function node ID to the list of callees (raw names) found in its body.
	callMap := make(map[string][]string)

	// Extract package name.
	pkgName := ""
	if f.Name != nil {
		pkgName = f.Name.Name
	}

	// Walk all FuncDecl nodes to create FuncNodes. For each FuncDecl we
	// also walk its body looking for FuncLit (closure) literals and emit
	// a separate FuncNode per closure. Each call expression is attributed
	// to its innermost enclosing function (FuncDecl or FuncLit) so the
	// canonical "factory returns a handler" pattern doesn't leak the
	// closure's calls onto the outer function.
	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		// Build function name: "FuncName" or "Receiver.Method".
		funcName := funcDecl.Name.Name
		if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
			recvType := exprTypeName(funcDecl.Recv.List[0].Type)
			if recvType != "" {
				funcName = recvType + "." + funcDecl.Name.Name
			}
		}

		// Body-less function declarations (//go:linkname stubs, assembly
		// stubs, cgo externs) have nil Body. They have no source we can
		// analyze, so skip them — including from call-graph registration.
		if funcDecl.Body == nil {
			continue
		}

		id := FuncID(filePath, funcName)
		startPos := fset.Position(funcDecl.Pos())
		endPos := fset.Position(funcDecl.End())

		// Extract the function body text for hashing.
		bodyStart := fset.Position(funcDecl.Body.Lbrace).Offset
		bodyEnd := fset.Position(funcDecl.Body.Rbrace).Offset + 1
		bodyText := ""
		if bodyStart >= 0 && bodyEnd <= len(content) && bodyStart < bodyEnd {
			bodyText = content[bodyStart:bodyEnd]
		}
		hash := ContentHash(bodyText)

		// Check if the content actually changed. We can only fast-path
		// the outer node here — closure children inside this body will
		// be re-built on every walk, but they share the same hash check
		// against oldNodes inside walkFuncBody, so unchanged closures
		// also keep their TaintSig.
		outerUnchanged := false
		if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
			// Outer node unchanged — re-add it as-is to preserve taint
			// sig. We still walk the body so closure nodes are rebuilt
			// (they live in the same file but are tracked separately).
			cg.AddNode(old)
			outerUnchanged = true
		}

		var node *FuncNode
		if outerUnchanged {
			node = cg.GetNode(id)
			// Reset RawCalls before re-walking so the visitor's append
			// doesn't double the entries on every rescan. The Calls /
			// CalledBy edges are rebuilt by the same-file resolve pass
			// at the end of buildGoNodes, but those entries are deduped
			// by AddEdge — RawCalls itself is not deduped, so reset it.
			node.RawCalls = nil
		} else {
			node = &FuncNode{
				ID:          id,
				FilePath:    filePath,
				Name:        funcName,
				Package:     pkgName,
				StartLine:   startPos.Line,
				EndLine:     endPos.Line,
				ContentHash: hash,
				LastScanAt:  time.Now(),
				Language:    rules.LangGo,
			}
			cg.AddNode(node)
			updatedIDs = append(updatedIDs, id)
		}

		// Walk the FuncDecl body, emitting closure nodes for every
		// nested *ast.FuncLit and attributing each call expression to
		// the innermost enclosing function.
		closureIDs := walkFuncBody(
			cg,
			funcDecl.Body,
			node,
			funcName,
			filePath,
			pkgName,
			content,
			fset,
			oldNodes,
			callMap,
		)
		updatedIDs = append(updatedIDs, closureIDs...)
	}

	// Resolve call edges. For each call, try to find a matching node in the graph.
	// We check: same file with exact name, or same file with selector match.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			// Try exact match in the same file first.
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
				continue
			}
			// Try matching just the function name part (for method calls where
			// the receiver might differ in how we recorded the ID).
			parts := strings.SplitN(callName, ".", 2)
			if len(parts) == 2 {
				// Look for any node in the graph whose name ends with .MethodName
				// in the same file.
				for _, node := range cg.NodesInFile(filePath) {
					if strings.HasSuffix(node.Name, "."+parts[1]) {
						cg.AddEdge(callerID, node.ID)
						break
					}
				}
			}
		}
	}

	return updatedIDs
}

// walkFuncBody walks body and:
//   - Emits a closure FuncNode for every *ast.FuncLit encountered, with
//     deterministic ID "<filepath>:<enclosingName>.closure@<line>:<col>".
//   - Adds a synthetic call edge from each FuncLit's immediate enclosing
//     function (FuncDecl or outer FuncLit) to the closure node, so the
//     callgraph reflects "the outer function constructs/returns this
//     closure". The closure's CalledBy lists its immediate parent.
//   - Attributes each *ast.CallExpr to the innermost enclosing function
//     (closure or outer FuncDecl), populating callMap and the node's
//     RawCalls. This means a call inside `return func(...) { Foo() }`
//     belongs to the closure, NOT the outer function.
//
// Returns the IDs of newly-created closure nodes so the caller can append
// them to the file's updatedIDs list. callMap is keyed by FuncNode.ID and
// receives the raw call expressions for each function/closure body.
//
// outer is the top-level FuncDecl's node (used as the initial "innermost
// enclosing" target on the stack). outerName is the outer function's
// canonical name used as the prefix for closure names; for nested closures
// the prefix grows ("Outer.closure@10:5.closure@12:9").
func walkFuncBody(
	cg *CallGraph,
	body *ast.BlockStmt,
	outer *FuncNode,
	outerName string,
	filePath string,
	pkgName string,
	content string,
	fset *token.FileSet,
	oldNodes map[string]*FuncNode,
	callMap map[string][]string,
) []string {
	if body == nil || outer == nil {
		return nil
	}

	// Stack of "innermost enclosing" function info. Each frame carries
	// the FuncNode the current subtree's calls/closures should be
	// attributed to and the name to use as a closure-name prefix.
	type frame struct {
		node *FuncNode
		name string // canonical name used as prefix for child closure IDs
	}
	stack := []frame{{node: outer, name: outerName}}
	cur := func() frame { return stack[len(stack)-1] }
	push := func(f frame) { stack = append(stack, f) }
	pop := func() { stack = stack[:len(stack)-1] }

	// Per-node call accumulator. We can't write directly to callMap[id]
	// inside the visitor because the slice would race with itself across
	// nested closures; collect per-frame and flush in a deterministic
	// order.
	calls := map[string][]string{outer.ID: nil}

	var newClosureIDs []string

	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			// Inspect calls f(nil) when ascending out of a subtree. Pop
			// only when we pushed something on the way down — push/pop
			// must stay balanced.
			pop()
			return false
		}

		switch node := n.(type) {
		case *ast.FuncLit:
			// Emit a closure FuncNode and a synthetic edge from the
			// current innermost-enclosing function to it.
			parent := cur()
			startPos := fset.Position(node.Pos())
			endPos := fset.Position(node.End())
			closureName := FormatClosureName(parent.name, startPos.Line, startPos.Column)
			closureID := FuncID(filePath, closureName)

			// Hash the closure body for change detection.
			bodyText := ""
			if node.Body != nil {
				bs := fset.Position(node.Body.Lbrace).Offset
				be := fset.Position(node.Body.Rbrace).Offset + 1
				if bs >= 0 && be <= len(content) && bs < be {
					bodyText = content[bs:be]
				}
			}
			hash := ContentHash(bodyText)

			var closureNode *FuncNode
			if old, exists := oldNodes[closureID]; exists && old.ContentHash == hash {
				// Closure body unchanged — reuse the old node so its
				// TaintSig survives across rescans. The synthetic edge
				// to the parent still needs to be re-established below.
				// Reset RawCalls so the walk's append doesn't double the
				// entries (Calls/CalledBy edges get rebuilt by AddEdge
				// which dedupes).
				old.RawCalls = nil
				cg.AddNode(old)
				closureNode = old
			} else {
				closureNode = &FuncNode{
					ID:          closureID,
					FilePath:    filePath,
					Name:        closureName,
					Package:     pkgName,
					StartLine:   startPos.Line,
					EndLine:     endPos.Line,
					ContentHash: hash,
					LastScanAt:  time.Now(),
					Language:    rules.LangGo,
				}
				cg.AddNode(closureNode)
				newClosureIDs = append(newClosureIDs, closureID)
			}

			// Synthetic edge: parent function "calls" this closure. The
			// closure has no exported name (it's identified only by its
			// line:col position), so this synthetic edge is the only way
			// a graph consumer can find it. We deliberately DO NOT add
			// the closure name to RawCalls — RawCalls is consumed by the
			// cross-file resolver, which interprets entries as "pkg.Func"
			// or "Func" call expressions. A closure name with line:col
			// coordinates isn't a real call expression and would just
			// land in UnresolvedCalls. The synthetic edge is enough.
			cg.AddEdge(parent.node.ID, closureID)

			// Initialize the closure's call slot and push it onto the
			// stack so deeper nodes get attributed to it.
			calls[closureID] = nil
			push(frame{node: closureNode, name: closureName})
			return true

		case *ast.CallExpr:
			// Attribute this call to the innermost enclosing function.
			callee := callExprName(node.Fun)
			if callee != "" {
				curID := cur().node.ID
				calls[curID] = append(calls[curID], callee)
			}
			// Push a placeholder so push/pop stays balanced on ascent.
			push(cur())
			return true

		default:
			// Push a placeholder for every non-func node so push/pop
			// stays balanced with the nil-ascent callback.
			push(cur())
			return true
		}
	})

	// Flush call accumulators back to the caller-owned callMap, and
	// preserve them on each node's RawCalls (same shape as the legacy
	// FuncDecl-only path).
	for id, list := range calls {
		callMap[id] = append(callMap[id], list...)
		if node := cg.GetNode(id); node != nil {
			// Append rather than replace — the closure-emission step
			// already added the closure's deterministic name to the
			// outer's RawCalls.
			if list != nil {
				node.RawCalls = append(node.RawCalls, list...)
			}
		}
	}

	return newClosureIDs
}

// callExprName returns the canonical raw-name form of a call expression's
// function reference: "pkg.Func" / "recv.Method" for selectors, "Func" for
// bare identifiers, "" for everything else (literal calls, conversions on
// complex expressions, etc.).
func callExprName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := f.X.(*ast.Ident); ok {
			return ident.Name + "." + f.Sel.Name
		}
	case *ast.Ident:
		return f.Name
	}
	return ""
}

// exprTypeName extracts the type name from a receiver expression.
func exprTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprTypeName(t.X)
	case *ast.IndexExpr:
		// Generic type: Type[T]
		return exprTypeName(t.X)
	default:
		return ""
	}
}

// buildGenericNodes uses scope detection + regex patterns to extract
// function declarations and call relationships for non-Go languages.
func buildGenericNodes(cg *CallGraph, filePath string, content string, lang rules.Language) []string {
	scopes := taint.DetectScopes(content, lang)

	// Snapshot old nodes for change detection.
	oldNodes := make(map[string]*FuncNode)
	for _, node := range cg.NodesInFile(filePath) {
		oldNodes[node.ID] = node
	}

	// Remove old nodes for this file.
	cg.RemoveFile(filePath)

	var updatedIDs []string
	callMap := make(map[string][]string)

	for _, scope := range scopes {
		if scope.Name == "__top_level__" {
			continue
		}

		id := FuncID(filePath, scope.Name)
		hash := ContentHash(scope.Body)

		// Check if unchanged.
		if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
			cg.AddNode(old)
			continue
		}

		node := &FuncNode{
			ID:          id,
			FilePath:    filePath,
			Name:        scope.Name,
			StartLine:   scope.StartLine,
			EndLine:     scope.EndLine,
			ContentHash: hash,
			LastScanAt:  time.Now(),
			Language:    lang,
		}
		cg.AddNode(node)
		updatedIDs = append(updatedIDs, id)

		// Extract call relationships from the scope body using language-specific patterns.
		calls := extractCalls(scope.Body, lang)
		callMap[id] = calls
	}

	// Resolve call edges within the same file.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
			}
		}
	}

	return updatedIDs
}

// Language-specific call extraction patterns.
var (
	// Python: funcname( or obj.method(
	pyCallRe   = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*\(`)
	pyMethodRe = regexp.MustCompile(`\b\w+\.([a-zA-Z_]\w*)\s*\(`)

	// JavaScript/TypeScript: funcname(, obj.method(, new ClassName(
	jsCallRe   = regexp.MustCompile(`\b([a-zA-Z_$]\w*)\s*\(`)
	jsMethodRe = regexp.MustCompile(`\b\w+\.([a-zA-Z_$]\w*)\s*\(`)
	jsNewRe    = regexp.MustCompile(`\bnew\s+([a-zA-Z_$]\w*)\s*\(`)

	// Java: methodName(, ClassName.method(, new ClassName(
	javaCallRe   = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*\(`)
	javaMethodRe = regexp.MustCompile(`\b([A-Z]\w*)\.([a-zA-Z_]\w*)\s*\(`)
	javaNewRe    = regexp.MustCompile(`\bnew\s+([A-Z]\w*)\s*\(`)

	// PHP: funcname(, $obj->method(, ClassName::method(
	phpCallRe   = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*\(`)
	phpMethodRe = regexp.MustCompile(`->([a-zA-Z_]\w*)\s*\(`)
	phpStaticRe = regexp.MustCompile(`([A-Z]\w*)::([a-zA-Z_]\w*)\s*\(`)

	// Ruby: funcname(, obj.method (may or may not have parens)
	rubyCallRe   = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*[\(]`)
	rubyMethodRe = regexp.MustCompile(`\b\w+\.([a-zA-Z_]\w*)`)

	// C/C++: funcname(, obj.method(, obj->method(, Class::method(
	cCallRe  = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*\(`)
	cArrowRe = regexp.MustCompile(`->([a-zA-Z_]\w*)\s*\(`)
	cScopeRe = regexp.MustCompile(`\b([a-zA-Z_]\w*)::([a-zA-Z_]\w*)\s*\(`)
)

// Common keywords that should not be treated as function calls.
var callKeywords = map[string]bool{
	"if": true, "else": true, "for": true, "while": true, "do": true,
	"switch": true, "case": true, "return": true, "break": true, "continue": true,
	"try": true, "catch": true, "finally": true, "throw": true, "throws": true,
	"class": true, "interface": true, "struct": true, "enum": true,
	"import": true, "from": true, "package": true, "require": true,
	"var": true, "let": true, "const": true, "type": true, "def": true,
	"func": true, "function": true, "async": true, "await": true,
	"new": true, "delete": true, "typeof": true, "instanceof": true,
	"print": true, "println": true, "printf": true, "fmt": true,
	"nil": true, "null": true, "true": true, "false": true,
	"self": true, "this": true, "super": true, "cls": true,
}

// extractCalls returns a deduplicated list of function/method names called in the body.
func extractCalls(body string, lang rules.Language) []string {
	seen := make(map[string]bool)
	var result []string

	addCall := func(name string) {
		if name == "" || callKeywords[name] || seen[name] {
			return
		}
		seen[name] = true
		result = append(result, name)
	}

	switch lang {
	case rules.LangPython:
		for _, m := range pyCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range pyMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}

	case rules.LangJavaScript, rules.LangTypeScript:
		for _, m := range jsCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range jsMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range jsNewRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}

	case rules.LangJava, rules.LangCSharp:
		for _, m := range javaCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range javaMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[2])
		}
		for _, m := range javaNewRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}

	case rules.LangPHP:
		for _, m := range phpCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range phpMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range phpStaticRe.FindAllStringSubmatch(body, -1) {
			addCall(m[2])
		}

	case rules.LangRuby:
		for _, m := range rubyCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range rubyMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}

	case rules.LangC, rules.LangCPP:
		for _, m := range cCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range cArrowRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range cScopeRe.FindAllStringSubmatch(body, -1) {
			addCall(m[2])
		}

	default:
		// Fallback: look for generic function call pattern identifier(
		for _, m := range pyCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
	}

	return result
}
