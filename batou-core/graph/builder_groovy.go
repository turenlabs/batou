// Groovy FuncNode builder (PR-Ggroovy).
//
// The generic regex-based path in buildGenericNodes can't see Groovy's
// `class A { String getName(req) {...} }` / `def foo() {...}` structure,
// doesn't qualify method names with their owning class, and does NOT
// populate FuncNode.RawCalls — which the cross-file resolver needs to walk
// per-call expressions. This file implements a tree-sitter-based Groovy
// builder mirroring the C# / Java builders (Groovy is a JVM language with a
// file-level `package a.b.c` declaration):
//
//   - Each node name is PACKAGE-QUALIFIED with the file's `package`
//     declaration, exactly like the C# / Java builders thread the namespace
//     into the dotted prefix. `package app` + `class A { String getName }` →
//     FuncNode "app.A.getName"; a free function `def foo()` in `package app`
//     → "app.foo"; the script-main node → "app.<groovyScriptMain>". A file
//     with no `package` declaration uses the bare names ("A.getName", "foo",
//     "<groovyScriptMain>"). This package prefix is what lets the cross-file
//     resolver (resolver_groovy.go) distinguish a `boltSession.run()` in
//     package `app.neo4j` from an unrelated CLI `static void run(String[])`
//     in package `app.cli` — bare-suffix matching cross-wired them.
//   - `class A { String getName(req) {...} }` → method node (the
//     tree-sitter-groovy grammar exposes the class body as a `closure` and
//     each method as a `function_definition` whose `function` field is the
//     method name).
//   - Nested classes flow through with dotted prefixes
//     ("app.Outer.Inner.m").
//   - Top-level SCRIPT statements (Groovy files are scripts: `def n =
//     getName(req)` and `"cmd $n".execute()` can sit directly under the
//     source_file with no enclosing function) are attributed to a synthetic
//     FuncNode named "<package>.<groovyScriptMain>" so the script-level
//     caller exists in the graph and its body is walked for RawCalls. This
//     is the key Groovy difference from the JVM class-only languages
//     (Java / C#).
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls whose
//     bare name matches a known node in this file. The cross-file pass
//     handles same-package cross-file resolution.
//
// Cross-file resolution (resolver_groovy.go) keys nodes by absolute file
// path (importPathForNode returns node.FilePath, mirroring C# / Java) and
// resolves a `Recv.method` call by matching "<callerPackage>.<class>.<method>"
// across nodes whose owning file declares the caller's package — the C#
// same-namespace model. This eliminates the bare-suffix cross-package
// method-name collisions of the earlier single-bucket model.
//
// Every line here is reached only for rules.LangGroovy files:
// UpdateFileWithAST dispatches to buildGroovyNodes solely from its
// `case rules.LangGroovy` arm, so this builder cannot alter graph
// construction for any other language.
package graph

import (
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// groovyScriptMainName is the synthetic node name for a Groovy file's
// top-level (script) statements. Groovy source files execute their
// top-level statements directly, so a caller / sink can live outside any
// declared function; this node makes that script body a first-class
// FuncNode the cross-file pass can treat as a caller.
const groovyScriptMainName = "<groovyScriptMain>"

// buildGroovyNodes is the Groovy-specific equivalent of buildSwiftNodes /
// buildLuaNodes. Returns nil ONLY when tree-sitter parsing fails, letting
// the caller (UpdateFileWithAST) fall back to the generic regex path. On a
// successful parse it returns a non-nil slice (possibly empty, on a warm
// rescan where every content-hash-unchanged node is reused) so the
// dispatcher keeps the class-qualified Groovy nodes instead of clobbering
// them with the generic builder.
func buildGroovyNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangGroovy)
	}
	if tree == nil || tree.Root() == nil {
		return nil
	}

	oldNodes := make(map[string]*FuncNode)
	for _, n := range cg.NodesInFile(filePath) {
		oldNodes[n.ID] = n
	}
	cg.RemoveFile(filePath)

	// Non-nil empty slice: a successful parse with zero *changed* nodes (the
	// warm-rescan content-hash-reuse case) must still return non-nil so
	// UpdateFileWithAST does NOT fall back to the generic regex builder and
	// clobber the class-qualified nodes we just re-registered. nil is
	// reserved for genuine parse failure (handled above). Mirrors the Swift /
	// Lua / Java builders.
	updatedIDs := []string{}
	callMap := make(map[string][]string)

	root := tree.Root()

	// Extract the file's `package a.b.c` declaration once. It becomes the
	// dotted prefix on every node name (method, free function, and the
	// script-main node), exactly like the C# / Java builders thread the
	// namespace. An empty package (no declaration) leaves names bare.
	pkgPrefix := groovyPackageName(root)

	walkGroovyBuilderNodes(root, pkgPrefix, cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Synthetic script-main node for the file's top-level statements. Walk
	// the top level (source_file) collecting calls that are NOT inside a
	// declared function / class so a script-level caller (`def n =
	// getName(req); "cmd $n".execute()`) exists in the graph.
	emitGroovyScriptMain(root, pkgPrefix, cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Same-file resolution: bare-name RawCalls that hit a known node in this
	// file become Calls/CalledBy edges immediately. Qualified "Type.name"
	// calls are left to the cross-file pass.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			if strings.ContainsRune(callName, '.') {
				continue
			}
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
				continue
			}
			// Method suffix match: caller does `doThing()` which might
			// actually be `Type.doThing` on `this`.
			for _, n := range cg.NodesInFile(filePath) {
				if strings.HasSuffix(n.Name, "."+callName) {
					cg.AddEdge(callerID, n.ID)
					break
				}
			}
		}
	}

	return updatedIDs
}

// groovyPackageName returns the dotted package name declared by the file's
// `package a.b.c` statement, or "" when the file has no package declaration.
// The tree-sitter-groovy grammar exposes it as a `groovy_package` node
// (child of source_file) wrapping a `qualified_name` whose text is the
// dotted package path. Mirrors csharpNamespaceName for the C# builder.
func groovyPackageName(root *tsast.Node) string {
	if root == nil {
		return ""
	}
	for _, child := range root.NamedChildren() {
		if child.Type() != "groovy_package" {
			continue
		}
		if qn := child.ChildByFieldName("name"); qn != nil {
			return strings.TrimSpace(qn.Text())
		}
		for _, c := range child.NamedChildren() {
			if c.Type() == "qualified_name" || c.Type() == "identifier" ||
				c.Type() == "scoped_identifier" {
				return strings.TrimSpace(c.Text())
			}
		}
	}
	return ""
}

// walkGroovyBuilderNodes recursively visits the tree, threading the dotted
// package+class prefix and emitting one FuncNode per `function_definition` /
// `method_definition`. A `class_definition` introduces a class prefix for
// the methods declared in its body `closure`. The initial prefix is the
// file's package (so a free function `foo` in `package app` becomes
// "app.foo" and a method `A.getName` becomes "app.A.getName"). Calls inside
// each function body go into callMap.
func walkGroovyBuilderNodes(
	n *tsast.Node,
	prefix string,
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
		case "class_definition", "interface_definition",
			"enum_definition", "trait_definition":
			className := groovyTypeDeclName(child)
			classPrefix := className
			if prefix != "" && className != "" {
				classPrefix = prefix + "." + className
			}
			if body := groovyTypeBody(child); body != nil {
				walkGroovyBuilderNodes(body, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			} else {
				walkGroovyBuilderNodes(child, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "function_definition", "method_definition":
			name := groovyFuncDeclName(child)
			if name == "" {
				continue
			}
			fullName := name
			if prefix != "" {
				fullName = prefix + "." + name
			}
			emitGroovyFunc(child, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap)
		default:
			walkGroovyBuilderNodes(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// groovyTypeDeclName returns the declared class/interface/enum/trait name.
// The grammar fields the name as `name`; fall back to the first identifier
// child.
func groovyTypeDeclName(decl *tsast.Node) string {
	if nm := decl.ChildByFieldName("name"); nm != nil {
		return strings.TrimSpace(nm.Text())
	}
	for _, c := range decl.NamedChildren() {
		if c.Type() == "identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// groovyTypeBody returns the body of a class/interface/enum/trait. The
// tree-sitter-groovy grammar exposes the body as a `closure` (fielded
// `body`) wrapping the member declarations; fall back to the first
// `closure` child.
func groovyTypeBody(decl *tsast.Node) *tsast.Node {
	if b := decl.ChildByFieldName("body"); b != nil {
		return b
	}
	for _, c := range decl.NamedChildren() {
		if c.Type() == "closure" || c.Type() == "class_body" {
			return c
		}
	}
	return nil
}

// groovyFuncDeclName returns the simple name of a `function_definition` /
// `method_definition` node. The grammar fields the method NAME as
// `function` (even when a return type is present, the return type is a
// separate leading identifier child and the name lands on the `function`
// field). Fall back to the last identifier preceding the parameter_list.
func groovyFuncDeclName(fn *tsast.Node) string {
	if nm := fn.ChildByFieldName("function"); nm != nil {
		return strings.TrimSpace(nm.Text())
	}
	if nm := fn.ChildByFieldName("name"); nm != nil {
		return strings.TrimSpace(nm.Text())
	}
	// Fallback: the identifier immediately before the parameter_list. For
	// `String getName(req)` the children are [identifier "String",
	// identifier "getName", parameter_list]; the name is the last identifier
	// before parameter_list.
	var lastIdent string
	for _, c := range fn.NamedChildren() {
		if c.Type() == "parameter_list" {
			break
		}
		if c.Type() == "identifier" {
			lastIdent = strings.TrimSpace(c.Text())
		}
	}
	return lastIdent
}

// emitGroovyFunc creates (or reuses) a FuncNode for fn with the already-
// qualified fullName, then walks the body to collect RawCalls into
// callMap[node.ID].
func emitGroovyFunc(
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
	node := registerGroovyFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	walkGroovyBodyForCalls(fn, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerGroovyFunc builds or reuses a FuncNode for fn. startLine/endLine
// and the body-text content hash are derived from the node's byte span.
func registerGroovyFunc(
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
		Language:    rules.LangGroovy,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// emitGroovyScriptMain emits a synthetic FuncNode covering the file's
// top-level (script) statements: every call expression that is NOT inside a
// declared function or class. Groovy executes top-level statements
// directly, so a cross-file caller and a sink can both live outside any
// `def` — the milestone B.groovy is exactly this shape. The node spans the
// whole file so the walker's body extraction and call-index lookup cover
// every script line.
func emitGroovyScriptMain(
	root *tsast.Node,
	pkgPrefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if root == nil {
		return
	}
	scriptName := groovyScriptMainName
	if pkgPrefix != "" {
		scriptName = pkgPrefix + "." + groovyScriptMainName
	}
	id := FuncID(filePath, scriptName)
	startLine := int(root.StartRow()) + 1
	endLine := int(root.EndRow()) + 1
	hash := ContentHash(content)

	var node *FuncNode
	if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
		old.RawCalls = nil
		cg.AddNode(old)
		node = old
	} else {
		node = &FuncNode{
			ID:          id,
			FilePath:    filePath,
			Name:        scriptName,
			StartLine:   startLine,
			EndLine:     endLine,
			ContentHash: hash,
			LastScanAt:  time.Now(),
			Language:    rules.LangGroovy,
		}
		cg.AddNode(node)
		*updatedIDs = append(*updatedIDs, id)
	}

	// Collect top-level calls: walk only the direct top-level statements,
	// not descending into class / function bodies (those are separate
	// nodes). The script-main call collection records every call found in
	// statements at the source_file level.
	collectGroovyScriptCalls(root, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// collectGroovyScriptCalls records every `function_call` in the file's
// top-level statements, skipping the bodies of declared functions and
// classes (those become their own nodes). It descends through ordinary
// statement / expression wrappers but stops at any
// function_definition/method_definition/class_definition boundary.
func collectGroovyScriptCalls(root *tsast.Node, scriptNode *FuncNode, callMap map[string][]string) {
	if root == nil || scriptNode == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_definition", "method_definition",
			"class_definition", "interface_definition",
			"enum_definition", "trait_definition":
			// Declared scope — its calls belong to that node, not the script.
			return
		case "function_call":
			if name := groovyCallName(n); name != "" {
				callMap[scriptNode.ID] = append(callMap[scriptNode.ID], name)
			}
			// Fall through so nested calls in arguments are captured too.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	// Visit children of the root (the source_file), not the root itself, so
	// the source_file node doesn't trip the declared-scope guard.
	for _, c := range root.NamedChildren() {
		visit(c)
	}
}

// walkGroovyBodyForCalls walks a function body and records every
// `function_call` node's textual function reference into callMap[outer.ID].
// We don't descend into nested function / class declarations — those become
// separate top-level nodes elsewhere.
func walkGroovyBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_definition", "method_definition",
			"class_definition", "interface_definition",
			"enum_definition", "trait_definition":
			// Don't descend into nested function / class declarations — they
			// become separate top-level nodes. (The root passed in here is the
			// outer's own declaration, so we still walk its body below via
			// NamedChildren before the guard can fire on the root.)
			if n != root {
				return
			}
		case "function_call":
			if name := groovyCallName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls nested in arguments
			// (`run(getName(req))`) are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// groovyCallName returns the canonical raw-name form of a Groovy
// `function_call` node:
//
//	"foo"         for `foo(...)`            (identifier callee)
//	"recv.method" for `recv.method(...)`    (dotted_identifier callee)
//	"method"      for `"...".method(...)`   (dotted_identifier whose receiver
//	              is a literal / non-identifier — only the method is keyed)
//	""            for deeper / unrecognised shapes.
//
// The grammar fields the callee as `function`: a bare `identifier` or a
// `dotted_identifier` chain whose leaf identifiers are the receiver and the
// method. We keep the receiver only when it is itself an identifier so the
// resolver's suffix match can strip it; for a string-literal receiver
// (`"cmd $n".execute`) only the method name is keyed.
func groovyCallName(n *tsast.Node) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text())
	case "dotted_identifier":
		// Collect the identifier leaves of the dotted chain. The LAST
		// identifier is the method; the FIRST is the receiver when it is an
		// identifier.
		var idents []string
		for i := 0; i < fn.ChildCount(); i++ {
			c := fn.Child(i)
			if c.Type() == "identifier" {
				idents = append(idents, strings.TrimSpace(c.Text()))
			}
		}
		switch len(idents) {
		case 0:
			return ""
		case 1:
			// Only one identifier leaf — the receiver is a non-identifier
			// (string literal, parenthesised expr): key the method only.
			return idents[0]
		default:
			// recv.method — keep first.last so the resolver can strip the
			// receiver via its suffix match.
			return idents[0] + "." + idents[len(idents)-1]
		}
	}
	return ""
}
