// Rust FuncNode builder (PR-Grust).
//
// The generic regex-based path in buildGenericNodes can't see Rust's
// `fn foo(...)` / `impl Type { fn method(...) }` structure and does NOT
// populate FuncNode.RawCalls — which the cross-file resolver needs to
// walk per-call expressions. This file implements a tree-sitter-based
// Rust builder mirroring the Lua / JS / Java builders:
//
//   - `fn foo(...)`                    → FuncNode "foo" (free function).
//   - `pub fn foo(...)`                → FuncNode "foo".
//   - `impl Type { fn method(...) }`   → FuncNode "method" (bare method
//     name — DetectScopes / the per-file taint walker name impl methods
//     bare, and the cross-file resolver matches on the trailing suffix so
//     bare vs "Type.method" both satisfy a resolved call).
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls whose
//     bare name matches a known node in this file. The cross-file pass
//     handles `alias.name` qualified calls (the leading segment may be a
//     `mod`-bound module only known to the resolver) and bare calls that
//     `use`-flatten to a function in another file.
//
// THE KEY RUST SUBTLETY (vs Lua): `use a::get_name;` flattens the import
// so the call site is a BARE `get_name(...)`, not `a.get_name()`. The
// builder therefore records bare call names verbatim; the resolver
// (resolver_rust.go) re-maps a bare call to the file the `use` brought it
// in from.
//
// Every line here is reached only for rules.LangRust files: UpdateFile-
// WithAST dispatches to buildRustNodes solely from its `case rules.LangRust`
// arm, so this builder cannot alter graph construction for any other
// language.
package graph

import (
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildRustNodes is the Rust-specific equivalent of buildLuaNodes /
// buildJSNodes. Returns nil when tree-sitter parsing fails, letting the
// caller (UpdateFileWithAST) fall back to the generic regex path.
func buildRustNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangRust)
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

	walkRustBuilderNodes(tree.Root(), cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Return a non-nil slice when tree-sitter parsed this file so
	// UpdateFileWithAST does not fall back to the generic regex builder on
	// a warm rescan (which would clobber the tree-sitter nodes and drop
	// RawCalls). Mirrors buildLuaNodes.
	if updatedIDs == nil {
		updatedIDs = []string{}
	}

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "alias.name" calls are left to the cross-file pass — the leading
	// segment may be a `mod`-bound module only known to the resolver.
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
			// Method-suffix match: caller does `run()` which might be an
			// impl method emitted as "Type.run" by a future qualifier.
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

// walkRustBuilderNodes recursively visits the program tree, emitting one
// FuncNode per `function_item` (free function or impl method) and
// collecting calls inside each body into callMap.
func walkRustBuilderNodes(
	n *tsast.Node,
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
		case "function_item":
			name := rustFunctionDeclName(child)
			if name != "" {
				emitRustFunc(child, name, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "impl_item":
			// `impl Type { ... }` / `impl Trait for Type { ... }`: the
			// methods live under the `body` declaration_list. Emit each
			// method with its bare name (DetectScopes names impl methods
			// bare, and the resolver suffix-matches).
			if body := child.ChildByFieldName("body"); body != nil {
				for _, m := range body.NamedChildren() {
					if m.Type() != "function_item" {
						continue
					}
					name := rustFunctionDeclName(m)
					if name != "" {
						emitRustFunc(m, name, cg, filePath, content, oldNodes, updatedIDs, callMap)
					}
				}
			}
		default:
			// Descend into modules (`mod foo { ... }`), trait bodies, and
			// other containers so nested function_items are still found.
			walkRustBuilderNodes(child, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// rustFunctionDeclName returns the name of a `function_item` node — the
// `name` field, which is a plain `identifier`.
func rustFunctionDeclName(fn *tsast.Node) string {
	nameNode := fn.ChildByFieldName("name")
	if nameNode == nil {
		return ""
	}
	return strings.TrimSpace(nameNode.Text())
}

// emitRustFunc creates (or reuses) a FuncNode for fn with name fullName,
// then walks the body to collect RawCalls into callMap[node.ID].
func emitRustFunc(
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
	node := registerRustFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	walkRustBodyForCalls(fn, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerRustFunc builds or reuses a FuncNode for fn.
func registerRustFunc(
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
		Language:    rules.LangRust,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkRustBodyForCalls walks a function body and records every
// `call_expression` node's textual function reference into
// callMap[outer.ID]. We don't descend into nested function_item nodes —
// those become separate top-level nodes elsewhere.
func walkRustBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_item", "closure_expression":
			// Don't descend into nested function-like nodes — they're
			// either separate top-level nodes or inline closures out of
			// scope for the 1-hop cross-file pass. The root passed in here
			// is the outer's own declaration, so we still walk its body
			// below via NamedChildren before the guard can fire on the root.
			if n != root {
				return
			}
		case "call_expression":
			if name := rustCallName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls nested in arguments
			// (`db.query(m.get_id())`) are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// rustCallName returns the canonical raw-name form of a Rust
// `call_expression` node:
//
//	"foo"        for `foo(...)`               (bare identifier — the
//	             use-flattened shape `use a::foo; foo(...)`)
//	"a.other"    for `a::other(...)`          (scoped_identifier whose
//	             leading path segment is `a` and method `other`)
//	"Command.new" for `Command::new(...)`     (scoped_identifier is keyed
//	             uniformly as lead "." method; a std ctor like this just
//	             never matches a user node, so it is harmless)
//	"method"     for `recv.method(...)`       (field_expression — the
//	             receiver is a runtime value, so only the method name is
//	             keyed; the same-file pass / sink scanner handles it)
//	""           for deeper / unrecognised shapes.
func rustCallName(n *tsast.Node) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text())
	case "scoped_identifier":
		name := fn.ChildByFieldName("name")
		path := fn.ChildByFieldName("path")
		if name == nil {
			return ""
		}
		method := strings.TrimSpace(name.Text())
		if path == nil {
			return method
		}
		lead := rustLeadingPathIdent(path)
		if lead == "" {
			return method
		}
		return lead + "." + method
	case "field_expression":
		f := fn.ChildByFieldName("field")
		if f != nil {
			return strings.TrimSpace(f.Text())
		}
	case "generic_function":
		// `foo::<T>(...)` — the turbofish wraps the callee. Recurse into
		// the inner function reference.
		if inner := fn.ChildByFieldName("function"); inner != nil {
			if inner.Type() == "identifier" {
				return strings.TrimSpace(inner.Text())
			}
			if inner.Type() == "scoped_identifier" {
				if nm := inner.ChildByFieldName("name"); nm != nil {
					return strings.TrimSpace(nm.Text())
				}
			}
		}
	}
	return ""
}

// rustLeadingPathIdent returns the leading identifier of a
// `scoped_identifier` path. For `a` (a bare identifier) it returns "a";
// for a nested `std::process::Command` it returns "std". Only the leading
// segment matters for the resolver's alias lookup.
func rustLeadingPathIdent(path *tsast.Node) string {
	cur := path
	for cur != nil {
		switch cur.Type() {
		case "identifier":
			return strings.TrimSpace(cur.Text())
		case "scoped_identifier":
			cur = cur.ChildByFieldName("path")
		default:
			return ""
		}
	}
	return ""
}
