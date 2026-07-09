// Perl FuncNode builder (PR-Gperl).
//
// The generic regex-based path in buildGenericNodes can't see Perl's
// `sub foo { ... }` structure, doesn't qualify subroutine names with their
// enclosing `package`, and does NOT populate FuncNode.RawCalls — which the
// cross-file resolver needs to walk per-call expressions. This file
// implements a tree-sitter-based Perl builder mirroring the Lua / Rust
// builders:
//
//   - `sub foo { ... }` at file scope under `package Foo;` → FuncNode
//     "Foo.foo" (the package name qualifies the sub so a cross-file
//     `Foo::foo(...)` call resolves to it). When no `package` precedes the
//     sub, the implicit `main` package is used and the node is named "foo".
//   - `package Foo { sub bar { ... } }` (block form) → FuncNode "Foo.bar".
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls whose
//     bare/qualified name matches a known node in this file. The cross-file
//     pass handles `Foo::bar` calls whose package is only known via the
//     resolver's `use Foo;` binding.
//
// Perl package scoping is statement-ordered: a `package Foo;` statement
// (no block) sets the current package for every subsequent statement until
// the next `package` statement or end of file. The builder threads the
// "current package" through a single top-level walk so each sub is
// qualified with the package in effect at its declaration point — the same
// model the tsflow per-file walker uses.
//
// Anonymous subs (`my $cb = sub { ... }`) are NOT emitted as separate
// nodes — Perl's cross-file idiom is a *named* package sub exported or
// called fully-qualified, which is exactly what cross-file resolution
// needs. The per-file tsflow walker already handles inline sub bodies.
//
// Every line here is reached only for rules.LangPerl files: UpdateFile-
// WithAST dispatches to buildPerlNodes solely from its `case rules.LangPerl`
// arm, so this builder cannot alter graph construction for any other
// language.
package graph

import (
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// perlDefaultPackage is the implicit package a Perl file is in before any
// `package` statement (Perl's `main`).
const perlDefaultPackage = "main"

// buildPerlNodes is the Perl-specific equivalent of buildLuaNodes /
// buildRustNodes. Returns nil when tree-sitter parsing fails, letting the
// caller (UpdateFileWithAST) fall back to the generic regex path.
func buildPerlNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangPerl)
	}
	if tree == nil || tree.Root() == nil {
		return nil
	}

	oldNodes := make(map[string]*FuncNode)
	for _, n := range cg.NodesInFile(filePath) {
		oldNodes[n.ID] = n
	}
	cg.RemoveFile(filePath)

	var updatedIDs []string
	callMap := make(map[string][]string)

	walkPerlBuilderNodes(tree.Root(), perlDefaultPackage, cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Synthesize a file-scope script node for top-level code. Perl entry
	// scripts (`.pl`) commonly call subs from `use`d modules at file scope —
	// outside any `sub` — so without this node a flat caller like
	// `system(A::get_name($cgi))` in main.pl has no FuncNode and the cross-
	// file walker (which only considers caller FuncNodes) never fires. The
	// node spans the whole file and captures every top-level call; its body
	// line-range covers the call sites so the call-site index resolves them.
	// This is the Perl analog of the PHP flat-script top-level handling.
	emitPerlTopLevel(tree.Root(), cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Return a non-nil slice when tree-sitter parsed this file so
	// UpdateFileWithAST does not fall back to the generic regex builder on
	// a warm rescan (which would clobber the tree-sitter nodes and drop
	// RawCalls). Mirrors buildLuaNodes / buildRubyNodes.
	if updatedIDs == nil {
		updatedIDs = []string{}
	}

	// Same-file resolution: RawCalls that hit a known node in this file
	// become Calls/CalledBy edges immediately. A qualified call
	// "Pkg.sub" is resolved against same-file package-qualified nodes;
	// a bare "sub" against same-package nodes. Cross-package /
	// cross-file calls are left to the resolver (the package may be a
	// `use`d module only known to the resolver).
	for callerID, calls := range callMap {
		for _, callName := range calls {
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
				continue
			}
			// Suffix match: caller does `foo()` which might actually be
			// `Pkg.foo` on the package; or `Pkg.foo()` whose node is bare.
			wantSuffix := callName
			if i := strings.LastIndex(callName, "."); i >= 0 {
				wantSuffix = callName[i+1:]
			}
			for _, n := range cg.NodesInFile(filePath) {
				if n.Name == wantSuffix || strings.HasSuffix(n.Name, "."+wantSuffix) {
					cg.AddEdge(callerID, n.ID)
					break
				}
			}
		}
	}

	return updatedIDs
}

// perlTopLevelName is the synthetic FuncNode name for a Perl file's
// file-scope (outside any sub) code. `__main__` mirrors Perl's implicit
// main package and won't collide with a real sub name (`sub __main__` is
// not idiomatic).
const perlTopLevelName = "__main__"

// emitPerlTopLevel synthesizes a file-scope script node capturing every
// call that appears at the file's top level (not inside any sub). The node
// spans the whole file so the cross-file walker can treat flat entry-script
// code as a caller. When there are no top-level calls, no node is emitted.
func emitPerlTopLevel(
	root *tsast.Node,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if root == nil {
		return
	}
	var topCalls []string
	var topLines []int
	collectPerlTopLevelCalls(root, &topCalls, &topLines)
	if len(topCalls) == 0 {
		return
	}

	startLine := int(root.StartRow()) + 1
	endLine := int(root.EndRow()) + 1
	// Hash the whole file content so a warm rescan reuses the node when the
	// file is unchanged.
	hash := ContentHash(content)
	id := FuncID(filePath, perlTopLevelName)

	if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
		old.RawCalls = nil
		cg.AddNode(old)
		old.RawCalls = append(old.RawCalls, topCalls...)
		return
	}
	node := &FuncNode{
		ID:          id,
		FilePath:    filePath,
		Name:        perlTopLevelName,
		StartLine:   startLine,
		EndLine:     endLine,
		ContentHash: hash,
		LastScanAt:  time.Now(),
		Language:    rules.LangPerl,
	}
	cg.AddNode(node)
	node.RawCalls = append(node.RawCalls, topCalls...)
	callMap[id] = append(callMap[id], topCalls...)
	*updatedIDs = append(*updatedIDs, id)
}

// collectPerlTopLevelCalls walks the file's top-level statements (NOT
// descending into `subroutine_declaration_statement` bodies, which become
// their own nodes) and records every call expression's name + start line.
// It DOES descend into `package Foo { ... }` blocks' non-sub statements so
// top-level code inside a block-form package is still captured.
func collectPerlTopLevelCalls(n *tsast.Node, calls *[]string, lines *[]int) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "subroutine_declaration_statement":
			// Skip — sub bodies are separate nodes.
			continue
		case "function_call_expression", "ambiguous_function_call_expression",
			"method_call_expression":
			if name := perlCallName(child); name != "" {
				*calls = append(*calls, name)
				*lines = append(*lines, int(child.StartRow())+1)
			}
			// Descend to catch calls nested in arguments.
			collectPerlTopLevelCalls(child, calls, lines)
		default:
			collectPerlTopLevelCalls(child, calls, lines)
		}
	}
}

// walkPerlBuilderNodes recursively visits the program tree, threading the
// current package through statement order. It emits one FuncNode per
// `subroutine_declaration_statement` (qualified with the package in effect)
// and recurses into `package Foo { ... }` block bodies with the block's
// package. Calls inside each sub body are collected into callMap.
func walkPerlBuilderNodes(
	n *tsast.Node,
	currentPkg string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "package_statement":
			pkg := perlPackageName(child)
			if body := child.ChildByFieldName("body"); body != nil {
				// Block form: `package Foo { ... }` — the package applies only
				// inside the block.
				blockPkg := currentPkg
				if pkg != "" {
					blockPkg = pkg
				}
				walkPerlBuilderNodes(body, blockPkg, cg, filePath, content, oldNodes, updatedIDs, callMap)
				continue
			}
			// Statement form: `package Foo;` — sets the current package for
			// all subsequent siblings.
			if pkg != "" {
				currentPkg = pkg
			}
		case "subroutine_declaration_statement":
			name := perlSubName(child)
			if name != "" {
				full := perlQualify(currentPkg, name)
				emitPerlSub(child, full, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		default:
			walkPerlBuilderNodes(child, currentPkg, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// perlPackageName returns the package name of a `package_statement` node
// (the `name` field, e.g. "Foo::Bar"). Returns "" when absent.
func perlPackageName(pkg *tsast.Node) string {
	nameNode := pkg.ChildByFieldName("name")
	if nameNode == nil {
		return ""
	}
	return strings.TrimSpace(nameNode.Text())
}

// perlSubName returns the bare subroutine name of a
// `subroutine_declaration_statement` node (the `name` field, a `bareword`).
func perlSubName(fn *tsast.Node) string {
	nameNode := fn.ChildByFieldName("name")
	if nameNode == nil {
		return ""
	}
	return strings.TrimSpace(nameNode.Text())
}

// perlQualify joins a package and bare sub name into our dotted convention.
// The `main` package is dropped so a top-level `sub foo` is named "foo"
// (mirroring how a cross-file `main::foo` is rare and `foo` is the common
// form). A non-main package qualifies: "Foo" + "bar" → "Foo.bar".
func perlQualify(pkg, sub string) string {
	if pkg == "" || pkg == perlDefaultPackage {
		return sub
	}
	return pkg + "." + sub
}

// emitPerlSub creates (or reuses) a FuncNode for fn with the already-
// qualified fullName, then walks the body to collect RawCalls into
// callMap[node.ID].
func emitPerlSub(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if fn == nil || fullName == "" {
		return
	}
	node := registerPerlSub(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	walkPerlBodyForCalls(fn, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerPerlSub builds or reuses a FuncNode for fn.
func registerPerlSub(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
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
		Language:    rules.LangPerl,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkPerlBodyForCalls walks a sub body and records every call
// expression's textual function reference into callMap[outer.ID]. We don't
// descend into nested sub declarations — those become separate nodes
// elsewhere.
func walkPerlBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "subroutine_declaration_statement":
			// Don't descend into nested sub declarations — they're separate
			// top-level nodes or inline callbacks out of scope for the
			// cross-file pass. (The root passed in is the outer's own
			// declaration, so we still walk its body below.)
			if n != root {
				return
			}
		case "function_call_expression", "ambiguous_function_call_expression",
			"method_call_expression":
			if name := perlCallName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls nested in arguments are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// perlCallName returns the canonical raw-name form of a Perl call node:
//
//	"foo"        for `foo(...)`            (bare function call)
//	"Pkg.bar"    for `Pkg::bar(...)`       (package-qualified function call —
//	             `::` normalised to `.` so it shares the builder's node-name
//	             convention)
//	"method"     for `$obj->method(...)`   (method call — the invocant is a
//	             runtime object handle, keyed by method name only)
//	""           for unrecognised shapes.
func perlCallName(n *tsast.Node) string {
	switch n.Type() {
	case "method_call_expression":
		m := n.ChildByFieldName("method")
		if m != nil {
			return strings.TrimSpace(m.Text())
		}
		return ""
	case "function_call_expression", "ambiguous_function_call_expression":
		fn := n.ChildByFieldName("function")
		if fn == nil {
			return ""
		}
		return perlNormalizeColons(strings.TrimSpace(fn.Text()))
	}
	return ""
}

// perlNormalizeColons turns a `Pkg::sub` text into `Pkg.sub` (last `::`
// becomes `.`; deeper `A::B::sub` → "A::B.sub" keeps the package path
// intact so the resolver's leading-segment lookup still works).
func perlNormalizeColons(s string) string {
	s = strings.TrimSpace(s)
	i := strings.LastIndex(s, "::")
	if i < 0 {
		return s
	}
	return s[:i] + "." + s[i+2:]
}
