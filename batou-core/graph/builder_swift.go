// Swift FuncNode builder (PR-Gswift).
//
// The generic regex-based path in buildGenericNodes can't see Swift's
// `func handler(_ req: Request)` / `struct Foo { func bar() {} }`
// structure, doesn't qualify method names with their owning type, and
// does NOT populate FuncNode.RawCalls — which the cross-file resolver
// needs to walk per-call expressions. This file implements a
// tree-sitter-based Swift builder mirroring the Lua / Java builders:
//
//   - `func foo(...)`                  → FuncNode "foo" (free function).
//   - `struct Foo { func bar() {} }`   → FuncNode "Foo.bar" (method on a
//     struct/class/enum — all parse as `class_declaration`).
//   - `extension Foo { func baz() {} }`→ FuncNode "Foo.baz" (methods on
//     an extension are visible by the type's name).
//   - Nested types flow through with dotted prefixes
//     (`Outer.Inner.method`).
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls whose
//     bare name matches a known node in this file. The cross-file pass
//     handles same-module bare-name resolution across files.
//
// In one Swift module every top-level func and every method is visible
// across all files by bare name — `import X` is module-level only, never
// per-symbol — so cross-file resolution (resolver_swift.go) keys all
// Swift nodes under one shared module bucket and resolves a call by its
// bare suffix.
//
// Every line here is reached only for rules.LangSwift files:
// UpdateFileWithAST dispatches to buildSwiftNodes solely from its
// `case rules.LangSwift` arm, so this builder cannot alter graph
// construction for any other language.
package graph

import (
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildSwiftNodes is the Swift-specific equivalent of buildLuaNodes /
// buildJavaNodes. Returns nil ONLY when tree-sitter parsing fails,
// letting the caller (UpdateFileWithAST) fall back to the generic regex
// path. On a successful parse it returns a non-nil slice (possibly empty,
// on a warm rescan where every content-hash-unchanged node is reused) so
// the dispatcher keeps the type-qualified Swift nodes instead of
// clobbering them with the generic builder.
func buildSwiftNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangSwift)
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
	// Java / Lua builders.
	updatedIDs := []string{}
	callMap := make(map[string][]string)

	walkSwiftBuilderNodes(tree.Root(), "", cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "Type.name" calls are left to the cross-file pass.
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
			// actually be `Type.doThing` on `self`.
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

// walkSwiftBuilderNodes recursively visits the tree, threading the dotted
// type prefix and emitting one FuncNode per `function_declaration`. A
// `class_declaration` (struct/class/enum) or `extension_declaration`
// introduces a type prefix for the methods in its body. Calls inside each
// function body go into callMap.
func walkSwiftBuilderNodes(
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
		case "class_declaration", "extension_declaration",
			"protocol_declaration", "enum_declaration":
			typeName := swiftTypeDeclName(child)
			typePrefix := typeName
			if prefix != "" && typeName != "" {
				typePrefix = prefix + "." + typeName
			}
			if body := swiftTypeBody(child); body != nil {
				walkSwiftBuilderNodes(body, typePrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			} else {
				// No recognised body field — still descend so partial parses
				// don't drop nested declarations.
				walkSwiftBuilderNodes(child, typePrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "function_declaration":
			name := swiftFuncDeclName(child)
			if name == "" {
				continue
			}
			fullName := name
			if prefix != "" {
				fullName = prefix + "." + name
			}
			emitSwiftFunc(child, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap)
		default:
			walkSwiftBuilderNodes(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// swiftTypeDeclName returns the declared type name of a class / struct /
// enum / extension / protocol declaration. The name is on the `name`
// field (a `type_identifier`), or — for extensions, which the grammar may
// expose without a `name` field — the first `user_type` / `type_identifier`
// child.
func swiftTypeDeclName(decl *tsast.Node) string {
	if nm := decl.ChildByFieldName("name"); nm != nil {
		return strings.TrimSpace(nm.Text())
	}
	for _, c := range decl.NamedChildren() {
		switch c.Type() {
		case "type_identifier":
			return strings.TrimSpace(c.Text())
		case "user_type":
			// `extension Foo` exposes the extended type as a user_type.
			return swiftLastIdent(c.Text())
		}
	}
	return ""
}

// swiftTypeBody returns the body node of a type declaration. struct /
// class / enum bodies are `class_body`; extension / protocol bodies are
// `extension_body` / `protocol_body` in some grammar revisions but fall
// back to a `class_body`-shaped named child.
func swiftTypeBody(decl *tsast.Node) *tsast.Node {
	if b := decl.ChildByFieldName("body"); b != nil {
		return b
	}
	for _, c := range decl.NamedChildren() {
		switch c.Type() {
		case "class_body", "enum_class_body", "extension_body",
			"protocol_body":
			return c
		}
	}
	return nil
}

// swiftFuncDeclName returns the simple name of a `function_declaration`
// node: the `name` field's `simple_identifier`.
func swiftFuncDeclName(fn *tsast.Node) string {
	if nm := fn.ChildByFieldName("name"); nm != nil {
		return strings.TrimSpace(nm.Text())
	}
	// Fallback: first simple_identifier child.
	for _, c := range fn.NamedChildren() {
		if c.Type() == "simple_identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// emitSwiftFunc creates (or reuses) a FuncNode for fn with the already-
// qualified fullName, then walks the body to collect RawCalls into
// callMap[node.ID].
func emitSwiftFunc(
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
	node := registerSwiftFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	walkSwiftBodyForCalls(fn, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerSwiftFunc builds or reuses a FuncNode for fn.
func registerSwiftFunc(
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
		Language:    rules.LangSwift,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkSwiftBodyForCalls walks a function body and records every
// `call_expression` node's textual function reference into
// callMap[outer.ID]. We don't descend into nested function / type
// declarations — those become separate top-level nodes elsewhere.
func walkSwiftBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
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
			"extension_declaration", "protocol_declaration",
			"enum_declaration":
			// Don't descend into nested function / type declarations — they
			// become separate top-level nodes. (The root passed in here is
			// the outer's own declaration, so we still walk its body below
			// via NamedChildren before the guard can fire on the root.)
			if n != root {
				return
			}
		case "call_expression":
			if name := swiftCallName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls nested in arguments
			// (`system(getName(req))`) are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// swiftCallName returns the canonical raw-name form of a Swift
// `call_expression` node:
//
//	"foo"        for `foo(...)`           (simple_identifier callee)
//	"obj.method" for `obj.method(...)`    (navigation_expression callee)
//	""           for deeper / unrecognised shapes.
//
// Mirrors the swiftConfig.extractCallName logic in langconfig.go but
// preserves the receiver for navigation calls so the resolver's suffix
// match can strip it.
func swiftCallName(n *tsast.Node) string {
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		switch c.Type() {
		case "simple_identifier":
			return strings.TrimSpace(c.Text())
		case "navigation_expression":
			recv := ""
			if target := c.ChildByFieldName("target"); target != nil {
				recv = swiftLastIdent(target.Text())
			}
			suffix := lastSwiftNavSuffix(c)
			if suffix == "" {
				return ""
			}
			if recv == "" {
				return suffix
			}
			return recv + "." + suffix
		case "call_suffix":
			// Reached the argument list without finding a callee.
			return ""
		}
	}
	return ""
}

// lastSwiftNavSuffix returns the final `navigation_suffix` identifier of a
// navigation_expression (`req.query` → "query", `a.b.c` → "c").
func lastSwiftNavSuffix(n *tsast.Node) string {
	var last string
	var walk func(node *tsast.Node)
	walk = func(node *tsast.Node) {
		if node == nil {
			return
		}
		if node.Type() == "navigation_suffix" {
			for i := 0; i < node.ChildCount(); i++ {
				c := node.Child(i)
				if c.Type() == "simple_identifier" {
					last = strings.TrimSpace(c.Text())
				}
			}
		}
		for _, c := range node.NamedChildren() {
			walk(c)
		}
	}
	walk(n)
	return last
}

// swiftLastIdent returns the last identifier token in s (used to pull a
// variable / type name out of an LHS / receiver expression).
func swiftLastIdent(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "let ")
	s = strings.TrimPrefix(s, "var ")
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}
