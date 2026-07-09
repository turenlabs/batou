// Ruby FuncNode builder.
//
// The generic regex-based path in buildGenericNodes can't see Ruby's
// class / module / singleton-method structure, doesn't qualify method
// names with their owning type, and does NOT populate FuncNode.RawCalls
// — which the cross-file resolver needs to walk per-call expressions.
// This file implements a tree-sitter-based Ruby builder mirroring the
// Java / Python / JS builders:
//
//   - Top-level `def foo(...)`               → FuncNode "foo".
//   - `class Cls; def bar; end; end`         → "Cls.bar".
//   - `class Cls; def self.baz; end; end`    → "Cls.baz" (singleton).
//   - `module M; def self.bar; end; end`     → "M.bar".
//   - Nested classes / modules               → "Outer.Inner.method".
//   - Sinatra/Roda DSL `get '/x' do ... end` → "<prefix>get@<line>:<col>"
//     synthetic node carrying the block's request-handling calls.
//   - `define_method(:dyn) do ... end`       → "<prefix>.dyn"
//     (indistinguishable from a regular `def dyn`).
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls
//     whose name matches a known node in this file. The cross-file
//     pass handles the rest.
package graph

import (
	"fmt"
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildRubyNodes is the Ruby-specific equivalent of buildJavaNodes /
// buildPythonNodes. Returns nil when tree-sitter parsing fails, letting
// the caller fall back to the generic regex path.
func buildRubyNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangRuby)
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

	walkRubyBuilderNodes(tree.Root(), "", cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "Alias.name" calls are left to the cross-file pass.
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
			// Class-method suffix match: caller does `do_thing` which
			// might actually be `Cls.do_thing` on `self`.
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

// walkRubyBuilderNodes recursively visits class / module declarations
// and top-level method / DSL calls, threading the dotted class prefix
// and emitting one FuncNode per discovered method, singleton method,
// route block, or define_method binding.
func walkRubyBuilderNodes(
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
		case "class", "module":
			name := rubyTypeName(child)
			childPrefix := name
			if prefix != "" && name != "" {
				childPrefix = prefix + "." + name
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkRubyBuilderNodes(body, childPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "method":
			emitRubyMethodNode(child, prefix, false, cg, filePath, content, oldNodes, updatedIDs, callMap)
		case "singleton_method":
			emitRubyMethodNode(child, prefix, true, cg, filePath, content, oldNodes, updatedIDs, callMap)
		case "call":
			handleRubyBuilderDSLCall(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		case "body_statement", "program":
			walkRubyBuilderNodes(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		default:
			walkRubyBuilderNodes(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// emitRubyMethodNode emits a FuncNode for a `method` or
// `singleton_method`. The naming convention treats instance and
// singleton methods identically — `Cls#method` and `Cls.method` both
// become "Cls.method" so cross-file resolution doesn't need to know
// the distinction (Ruby calls usually look the same at the call site).
func emitRubyMethodNode(
	method *tsast.Node,
	classPrefix string,
	isSingleton bool,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	nameNode := method.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	methodName := strings.TrimSpace(nameNode.Text())
	if methodName == "" {
		return
	}
	fullName := methodName
	if classPrefix != "" {
		fullName = classPrefix + "." + methodName
	}
	registerRubyFuncWithBody(method, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap)
}

// handleRubyBuilderDSLCall mirrors handleRubyDSLCall in the extractor:
// it identifies Sinatra/Roda HTTP-verb route blocks, `define_method`
// bindings, and `namespace`-style grouping DSLs, emitting nodes and
// recording RawCalls for the appropriate ones.
func handleRubyBuilderDSLCall(
	n *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	methodNode := n.ChildByFieldName("method")
	if methodNode == nil {
		return
	}
	if recv := n.ChildByFieldName("receiver"); recv != nil {
		return
	}
	methodName := strings.TrimSpace(methodNode.Text())
	if methodName == "" {
		return
	}
	block := n.ChildByFieldName("block")
	if block == nil {
		return
	}

	switch {
	case methodName == "define_method":
		emitRubyDefineMethodNode(n, block, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
	case rubyDSLRouteVerbs[methodName]:
		emitRubyRouteBlockNode(n, block, methodName, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
	case rubyDSLNamespaceVerbs[methodName]:
		if body := block.ChildByFieldName("body"); body != nil {
			walkRubyBuilderNodes(body, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// emitRubyDefineMethodNode handles `define_method(:dyn) do ... end`.
func emitRubyDefineMethodNode(
	n, block *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	name := ""
	for _, a := range args.NamedChildren() {
		switch a.Type() {
		case "simple_symbol":
			name = strings.TrimPrefix(strings.TrimSpace(a.Text()), ":")
		case "string":
			name = rubyStripStringLiteral(a)
		}
		if name != "" {
			break
		}
	}
	if name == "" {
		return
	}
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	registerRubyFuncWithBody(n, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap)
}

// emitRubyRouteBlockNode handles Sinatra/Roda HTTP-verb DSL blocks.
// The block body is the actual handler — that's where request-derived
// taint enters — so we anchor the FuncNode to the call's coordinates
// and use the verb + line:col as the synthetic name.
func emitRubyRouteBlockNode(
	n, block *tsast.Node,
	verb, prefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	line := int(n.StartRow()) + 1
	col := int(n.StartCol())
	name := fmt.Sprintf("%s@%d:%d", verb, line, col)
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	registerRubyFuncWithBody(n, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap)
}

// registerRubyFuncWithBody creates (or reuses) a FuncNode for fn with
// the already-qualified fullName, then walks the body to collect
// RawCalls into callMap[node.ID]. This is the shared tail of every
// method / route / define_method emission.
func registerRubyFuncWithBody(
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
	node := registerRubyFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	walkRubyBodyForCalls(fn, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerRubyFunc builds or reuses a FuncNode for fn.
func registerRubyFunc(
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
		Language:    rules.LangRuby,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkRubyBodyForCalls walks a method body and records every `call`
// node's textual function reference into callMap[outer.ID]. We don't
// descend into nested method / class / module declarations — those
// become separate top-level nodes elsewhere.
func walkRubyBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "method", "singleton_method", "class", "module":
			// Don't descend — these are emitted as separate nodes.
			return
		case "call":
			if name := rubyInvocationName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls nested in arguments / blocks are
			// also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	for _, c := range root.NamedChildren() {
		visit(c)
	}
}

// rubyInvocationName returns the canonical raw-name form of a Ruby
// `call` node. Shapes:
//
//	foo(...)         — no receiver, just method name → "foo"
//	obj.method(...)  — identifier receiver           → "obj.method"
//	Cls.method(...)  — constant receiver             → "Cls.method"
//	Foo::Bar.method  — scope_resolution receiver     → "Foo.Bar.method"
//	a.b.c.method     — chained call receiver         → "" (can't pin)
//	self.method      — self receiver                  → "method"
func rubyInvocationName(n *tsast.Node) string {
	methodNode := n.ChildByFieldName("method")
	if methodNode == nil {
		return ""
	}
	method := strings.TrimSpace(methodNode.Text())
	if method == "" {
		return ""
	}
	recv := n.ChildByFieldName("receiver")
	if recv == nil {
		return method
	}
	switch recv.Type() {
	case "identifier", "constant":
		text := strings.TrimSpace(recv.Text())
		if text == "self" {
			return method
		}
		return text + "." + method
	case "scope_resolution":
		// `Foo::Bar` → `Foo.Bar` (normalised to our dotted convention).
		text := strings.ReplaceAll(strings.TrimSpace(recv.Text()), "::", ".")
		return text + "." + method
	case "self":
		return method
	}
	// Chained / complex receiver — can't pin without type inference.
	return ""
}
