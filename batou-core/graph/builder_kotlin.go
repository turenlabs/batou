// Kotlin FuncNode builder.
//
// The generic regex-based path in buildGenericNodes can't see class /
// object boundaries, doesn't qualify method names with their owning type,
// and does NOT populate FuncNode.RawCalls — which the cross-file resolver
// needs to walk per-call expressions. This file implements a
// tree-sitter-based Kotlin builder that closes those gaps (the Java / C#
// analog, using the Kotlin grammar's node names):
//
//   - `class Foo { fun bar() {} }` becomes a FuncNode named "Foo.bar"
//     (mirrors the Java / C# / Python / JS extractor naming).
//   - `object Util { fun clean() {} }` and `companion object` members get
//     the same Type.method qualification ("Util.clean").
//   - Top-level free functions get a bare node ("getName").
//   - Nested types flow through with dotted prefixes:
//     `class Outer { class Inner { fun m() {} } }` → "Outer.Inner.m".
//   - Each call expression inside a function body is attributed to its
//     innermost enclosing function and recorded in RawCalls in the bare /
//     "Receiver.method" form the Kotlin resolver expects.
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls that map
//     to a node in the same file. The cross-file pass handles the rest.
//
// Inline lambdas / anonymous functions passed as callbacks are NOT emitted
// as separate nodes — the Kotlin cross-file idiom is a *named* function /
// method, which is what cross-file resolution needs. The per-file tsflow
// walker already handles callback bodies.
//
// Every line here is reached only for rules.LangKotlin files: UpdateFile-
// WithAST dispatches to buildKotlinNodes solely from its
// `case rules.LangKotlin` arm, so this builder cannot alter graph
// construction for any other language.
package graph

import (
	"fmt"
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildKotlinNodes is the Kotlin-specific equivalent of buildJavaNodes /
// buildCSharpNodes. Returns nil ONLY when tree-sitter parsing fails,
// letting the caller (UpdateFileWithAST) fall back to the generic regex
// path. On a successful parse it returns a non-nil slice (possibly empty,
// when a warm rescan reuses every content-hash-unchanged node) so the
// dispatcher keeps the type-qualified Kotlin nodes instead of clobbering
// them with the generic builder.
func buildKotlinNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangKotlin)
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
	// and clobber the type-qualified nodes we just re-registered. nil is
	// reserved for genuine parse failure (handled above). Mirrors
	// buildJavaNodes / buildCSharpNodes.
	updatedIDs := []string{}
	callMap := make(map[string][]string)

	// Kotlin namespace resolution mirrors C#: the file's `package a.b.c`
	// declaration is threaded as the OUTERMOST prefix of every node name
	// (free function `getName` → "a.b.c.getName"; method `Foo.bar` →
	// "a.b.c.Foo.bar"). resolver_kotlin.go matches same-package calls by
	// node-name prefix (Package == caller's package), so the package must
	// live in the node name. A file with no `package` header threads an
	// empty prefix (bare names), exactly like a C# file with no namespace.
	pkgPrefix := kotlinFilePackage(tree.Root())

	// seenIDs disambiguates overload collisions: two `fun expectHttpBody()`
	// overloads at different lines/arities share one qualified name and
	// therefore one FuncID, which would silently merge their bodies (and
	// their RawCalls / sinks) onto a single node — the diagnosed phantom-
	// sink defect. registerKotlinFunc consults seenIDs and appends a
	// disambiguating "#<arity>@<line>" suffix to the node NAME (not the
	// resolver-visible qualified name used for matching) so each overload
	// gets a distinct ID while still resolving by basename suffix.
	seenIDs := make(map[string]int)

	walkKotlinBuilderNodes(tree.Root(), pkgPrefix, cg, filePath, content, oldNodes, &updatedIDs, callMap, seenIDs)

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "Receiver.name" calls are left to the cross-file pass — the receiver
	// may be an import alias / same-package type only known to the resolver.
	//
	// Node names now carry the package prefix, so a bare call `doThing()`
	// no longer matches a node whose ID is "pkg.doThing" by exact FuncID;
	// the suffix match below (".doThing") is the primary same-file path.
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
			// Suffix match: caller does `doThing()` which resolves to a
			// node named "pkg.doThing" (free function) or "Cls.doThing"
			// (method on `this`) in this file — accept the suffix match
			// same as the Java / C# builders. Skip self-edges so an
			// overload-disambiguated node doesn't edge to itself.
			for _, n := range cg.NodesInFile(filePath) {
				if n.ID == callerID {
					continue
				}
				if n.Name == callName || strings.HasSuffix(n.Name, "."+callName) {
					cg.AddEdge(callerID, n.ID)
					break
				}
			}
		}
	}

	return updatedIDs
}

// kotlinFilePackage returns the file's `package a.b.c` declaration (dotted,
// no trailing dot) from the source_file root, or "" when the file has no
// package header. Threaded as the outermost node-name prefix so the
// resolver can match same-package calls by node-name prefix (the C# model).
func kotlinFilePackage(root *tsast.Node) string {
	if root == nil {
		return ""
	}
	for i := 0; i < root.ChildCount(); i++ {
		c := root.Child(i)
		if c != nil && c.Type() == "package_header" {
			return kotlinPackageName(c)
		}
	}
	return ""
}

// walkKotlinBuilderNodes recursively visits class / object / interface
// declarations and top-level functions, threading the dotted type prefix
// and emitting one FuncNode per discovered function. Calls inside each
// function body go into callMap.
//
// The Kotlin grammar nests a type's members inside a `class_body` child,
// while top-level functions live directly under `source_file`. Both
// `class_declaration` and `object_declaration` use a `type_identifier`
// child for the type name (NOT a `name` field) and a `class_body` child
// for the members.
func walkKotlinBuilderNodes(
	n *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
	seenIDs map[string]int,
) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "class_declaration", "object_declaration":
			typeName := kotlinTypeName(child)
			typePrefix := typeName
			if prefix != "" && typeName != "" {
				typePrefix = prefix + "." + typeName
			}
			if body := kotlinClassBody(child); body != nil {
				walkKotlinClassBodyForBuilder(body, typePrefix, cg, filePath, content, oldNodes, updatedIDs, callMap, seenIDs)
			}
		case "function_declaration":
			// Top-level free function (or one emitted directly under
			// source_file). Qualified by the file's package prefix.
			emitKotlinFunc(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap, seenIDs)
		default:
			// Descend through source_file / statements / etc.
			walkKotlinBuilderNodes(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap, seenIDs)
		}
	}
}

// walkKotlinClassBodyForBuilder emits a FuncNode for every function in a
// class / object body, recursing into nested type declarations and
// companion objects.
func walkKotlinClassBodyForBuilder(
	body *tsast.Node,
	typePrefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
	seenIDs map[string]int,
) {
	if body == nil {
		return
	}
	for _, child := range body.NamedChildren() {
		switch child.Type() {
		case "function_declaration":
			emitKotlinMethod(child, typePrefix, cg, filePath, content, oldNodes, updatedIDs, callMap, seenIDs)
		case "class_declaration", "object_declaration":
			nestedName := kotlinTypeName(child)
			nestedPrefix := nestedName
			if typePrefix != "" && nestedName != "" {
				nestedPrefix = typePrefix + "." + nestedName
			}
			if nbody := kotlinClassBody(child); nbody != nil {
				walkKotlinClassBodyForBuilder(nbody, nestedPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap, seenIDs)
			}
		case "companion_object":
			// `companion object { fun create() {} }` — members are visible
			// as `Type.create()` from other files. Keep the owning type
			// prefix (don't add a "Companion" segment) so the call
			// `Type.create()` resolves directly.
			if cbody := kotlinClassBody(child); cbody != nil {
				walkKotlinClassBodyForBuilder(cbody, typePrefix, cg, filePath, content, oldNodes, updatedIDs, callMap, seenIDs)
			}
		}
	}
}

// emitKotlinMethod is the entry point for a method inside a type body. The
// fully-qualified name is "<typePrefix>.<methodName>".
func emitKotlinMethod(
	method *tsast.Node,
	typePrefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
	seenIDs map[string]int,
) {
	methodName := kotlinFuncName(method)
	if methodName == "" {
		return
	}
	fullName := methodName
	if typePrefix != "" {
		fullName = typePrefix + "." + methodName
	}
	emitKotlinFuncWithName(method, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap, seenIDs)
}

// emitKotlinFunc emits a top-level / bare function node, qualifying with
// prefix when one is threaded (rare at file level — usually empty).
func emitKotlinFunc(
	fn *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
	seenIDs map[string]int,
) {
	name := kotlinFuncName(fn)
	if name == "" {
		return
	}
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	emitKotlinFuncWithName(fn, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap, seenIDs)
}

// emitKotlinFuncWithName creates (or reuses) a FuncNode for fn with the
// already-qualified fullName, then walks its body to collect RawCalls into
// callMap[node.ID].
func emitKotlinFuncWithName(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
	seenIDs map[string]int,
) {
	if fn == nil || fullName == "" {
		return
	}
	node := registerKotlinFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs, seenIDs)
	if node == nil {
		return
	}
	// Function body is a `function_body` child (block `{ ... }` or
	// expression-body `= expr`). When absent, scan the node itself.
	body := kotlinFuncBody(fn)
	if body == nil {
		body = fn
	}
	walkKotlinBodyForCalls(body, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerKotlinFunc builds or reuses a FuncNode for fn.
//
// Overload disambiguation: Kotlin permits two `fun expectHttpBody(...)`
// overloads at different lines in one type. Both qualify to the same
// fullName ("Type.expectHttpBody") and therefore the same FuncID. Without
// disambiguation the second AddNode silently overwrites the first AND
// callMap[node.ID] aggregates RawCalls from BOTH bodies onto one node — so
// a sink in overload B is attributed to overload A's body, then persisted
// onto its TaintSig, producing the diagnosed phantom-sink false positive.
//
// We give each colliding overload a distinct Name/ID by appending a
// "#<arity>@<startLine>" suffix (the FIRST occurrence keeps the clean name,
// later ones are suffixed). The resolver strips this suffix
// (kotlinStripOverloadSuffix) before matching, so resolution still works by
// the clean "Type.method" / ".method" form; only node identity is split.
func registerKotlinFunc(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	seenIDs map[string]int,
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

	// Disambiguate overloads: if this fullName was already emitted in this
	// build pass, suffix the name with the function's arity and start line
	// so each overload owns a distinct node. The first occurrence keeps the
	// clean fullName so single-definition functions are unaffected.
	uniqueName := fullName
	if seenIDs != nil {
		if seenIDs[fullName] > 0 {
			arity := kotlinFuncArity(fn)
			uniqueName = fmt.Sprintf("%s#%d@%d", fullName, arity, startLine)
		}
		seenIDs[fullName]++
	}
	id := FuncID(filePath, uniqueName)

	if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
		old.RawCalls = nil
		cg.AddNode(old)
		return old
	}
	node := &FuncNode{
		ID:          id,
		FilePath:    filePath,
		Name:        uniqueName,
		StartLine:   startLine,
		EndLine:     endLine,
		ContentHash: hash,
		LastScanAt:  time.Now(),
		Language:    rules.LangKotlin,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// kotlinFuncArity returns the number of declared parameters of a
// function_declaration (the count of `parameter` / `class_parameter`
// children inside the `function_value_parameters` node). Used to
// disambiguate overloads by arity. Returns 0 when no parameter list is
// found.
func kotlinFuncArity(fn *tsast.Node) int {
	if fn == nil {
		return 0
	}
	for _, c := range fn.NamedChildren() {
		if c.Type() != "function_value_parameters" {
			continue
		}
		n := 0
		for _, p := range c.NamedChildren() {
			if p.Type() == "parameter" || p.Type() == "class_parameter" {
				n++
			}
		}
		return n
	}
	return 0
}

// walkKotlinBodyForCalls walks a function body and records every call
// expression's textual function reference into callMap[outer.ID]. We don't
// descend into nested function / type declarations — those are emitted as
// separate nodes elsewhere.
func walkKotlinBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_declaration", "class_declaration",
			"object_declaration", "companion_object":
			// Don't descend into nested declarations — they become separate
			// nodes. (The root passed in here is the outer's own body, not
			// its declaration, so this only fires on genuinely nested defs.)
			return
		case "call_expression":
			if name := kotlinCallText(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls inside arguments are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// kotlinCallText returns the canonical raw-name form of a Kotlin
// call_expression's function reference. The function part is the first
// child of the call_expression — either a `simple_identifier` (bare call)
// or a `navigation_expression` (`recv.method`). Returns:
//
//	"foo"          for `foo(...)`              (bare identifier)
//	"recv.bar"     for `recv.bar(...)`         (single-level navigation)
//	""             for chained `a.b.c()` calls and complex shapes — those
//	               can't be resolved without type inference.
func kotlinCallText(n *tsast.Node) string {
	if n == nil {
		return ""
	}
	// The first NAMED child is the callee expression; the call_suffix
	// holds the arguments.
	var fn *tsast.Node
	for _, c := range n.NamedChildren() {
		if c.Type() == "call_suffix" {
			continue
		}
		fn = c
		break
	}
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "simple_identifier":
		return strings.TrimSpace(fn.Text())
	case "navigation_expression":
		return kotlinNavCallText(fn)
	}
	return ""
}

// kotlinNavCallText resolves a `recv.method` navigation_expression to
// "recv.method", collapsing a `this`-receiver to the bare method name.
// Returns "" when the receiver is itself a call / nested navigation
// (chained calls we can't pin without type inference).
func kotlinNavCallText(nav *tsast.Node) string {
	children := nav.NamedChildren()
	if len(children) < 2 {
		return ""
	}
	recvNode := children[0]
	// The method name is the last simple_identifier in the trailing
	// navigation_suffix.
	method := kotlinLastNavIdent(nav)
	if method == "" {
		return ""
	}
	if recvNode.Type() != "simple_identifier" {
		// Chained / call-expression receiver — can't pin.
		return ""
	}
	recv := strings.TrimSpace(recvNode.Text())
	if recv == "this" || recv == "super" {
		return method
	}
	return recv + "." + method
}

// kotlinLastNavIdent returns the last simple_identifier inside the
// trailing navigation_suffix of a navigation_expression (the method name).
func kotlinLastNavIdent(nav *tsast.Node) string {
	children := nav.NamedChildren()
	if len(children) == 0 {
		return ""
	}
	last := children[len(children)-1]
	if last.Type() != "navigation_suffix" {
		return ""
	}
	var ident string
	for _, c := range last.NamedChildren() {
		if c.Type() == "simple_identifier" {
			ident = strings.TrimSpace(c.Text())
		}
	}
	return ident
}

// kotlinTypeName returns the short type name from a class_declaration /
// object_declaration (the `type_identifier` child).
func kotlinTypeName(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		if c.Type() == "type_identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// kotlinClassBody returns the `class_body` (or `enum_class_body`) child of
// a type declaration, or nil when the type has no body.
func kotlinClassBody(n *tsast.Node) *tsast.Node {
	for _, c := range n.NamedChildren() {
		if c.Type() == "class_body" || c.Type() == "enum_class_body" {
			return c
		}
	}
	return nil
}

// kotlinFuncName returns the function name (the `simple_identifier` child
// immediately after the `fun` keyword) of a function_declaration.
func kotlinFuncName(fn *tsast.Node) string {
	for _, c := range fn.NamedChildren() {
		if c.Type() == "simple_identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// kotlinFuncBody returns the `function_body` child of a
// function_declaration, or nil when absent.
func kotlinFuncBody(fn *tsast.Node) *tsast.Node {
	for _, c := range fn.NamedChildren() {
		if c.Type() == "function_body" {
			return c
		}
	}
	return nil
}
