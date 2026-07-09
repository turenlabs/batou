// Lua FuncNode builder (PR-Glua).
//
// The generic regex-based path in buildGenericNodes can't see Lua's
// `function M.handler(...)` / `local function f(...)` structure, doesn't
// qualify method names with their owning module table, and does NOT
// populate FuncNode.RawCalls — which the cross-file resolver needs to
// walk per-call expressions. This file implements a tree-sitter-based
// Lua builder mirroring the Ruby / JS / Python builders:
//
//   - `function foo(...)`              → FuncNode "foo".
//   - `local function foo(...)`        → FuncNode "foo".
//   - `function M.handler(...)`        → FuncNode "M.handler".
//   - `function M:method(...)`         → FuncNode "M.method" (colon-method
//     normalised to a dot so cross-file resolution doesn't need to know
//     the receiver-sugar distinction).
//   - `M.handler = function(...) end`  → FuncNode "M.handler" (function
//     expression assigned to a table field / variable).
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls whose
//     bare name matches a known node in this file. The cross-file pass
//     handles `alias.name` calls (the receiver may be a `require` alias
//     only known to the resolver).
//
// Anonymous functions passed as callback arguments are NOT emitted as
// separate nodes — Lua's module idiom is a *named* table of functions
// (`function M.x() end ... return M`), which is exactly what cross-file
// resolution needs. The per-file tsflow walker already handles inline
// callback bodies.
//
// Every line here is reached only for rules.LangLua files: UpdateFile-
// WithAST dispatches to buildLuaNodes solely from its `case rules.LangLua`
// arm, so this builder cannot alter graph construction for any other
// language.
package graph

import (
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildLuaNodes is the Lua-specific equivalent of buildRubyNodes /
// buildJSNodes. Returns nil when tree-sitter parsing fails, letting the
// caller (UpdateFileWithAST) fall back to the generic regex path.
func buildLuaNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangLua)
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

	walkLuaBuilderNodes(tree.Root(), cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// See buildRubyNodes: return a non-nil slice when tree-sitter parsed
	// this file so UpdateFileWithAST does not fall back to the generic
	// regex builder on a warm rescan (which would clobber the tree-sitter
	// nodes and drop RawCalls).
	if updatedIDs == nil {
		updatedIDs = []string{}
	}

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "alias.name" calls are left to the cross-file pass — the receiver
	// may be a `require` alias only known to the resolver.
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
			// Module-method suffix match: caller does `do_thing()` which
			// might actually be `M.do_thing` on the module table.
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

// walkLuaBuilderNodes recursively visits the program tree, emitting one
// FuncNode per `function_statement` (covers both `function` and `local
// function`) and per function-expression assigned to a variable / table
// field. Calls inside each function body are collected into callMap.
func walkLuaBuilderNodes(
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
		case "function_statement", "local_function_statement":
			name := luaFunctionDeclName(child)
			if name != "" {
				emitLuaFunc(child, name, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "variable_declaration", "variable_assignment":
			// `M.handler = function(...) end` / `local f = function(...) end`.
			lhs, fnExpr := luaAssignedFunction(child)
			if lhs != "" && fnExpr != nil {
				emitLuaFunc(fnExpr, lhs, cg, filePath, content, oldNodes, updatedIDs, callMap)
				continue
			}
			// Otherwise descend (the RHS might be a tableconstructor with
			// function fields, or a nested block).
			walkLuaBuilderNodes(child, cg, filePath, content, oldNodes, updatedIDs, callMap)
		default:
			walkLuaBuilderNodes(child, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// luaFunctionDeclName returns the qualified name of a `function_statement`
// or `local_function_statement` node. The name is on the `name` field,
// which is either a plain `identifier` (`function foo` / `local function
// foo`) or a `function_name` node holding the dotted/colon path
// (`function M.handler`, `function M:method`). Colon methods are
// normalised to a dot so `M:method` and `M.method` share one node name.
func luaFunctionDeclName(fn *tsast.Node) string {
	nameNode := fn.ChildByFieldName("name")
	if nameNode == nil {
		return ""
	}
	switch nameNode.Type() {
	case "identifier":
		return strings.TrimSpace(nameNode.Text())
	case "function_name":
		return luaQualifiedName(nameNode)
	}
	// Fallback: the raw text with colons normalised to dots.
	return luaNormalizeColons(strings.TrimSpace(nameNode.Text()))
}

// luaQualifiedName joins the identifier segments of a `function_name`
// node into our dotted convention. `M.handler` → "M.handler";
// `M:method` → "M.method"; `a.b.c` → "a.b.c". Separator tokens
// (`table_dot`, `:`) are skipped; only the identifier leaves contribute.
func luaQualifiedName(nameNode *tsast.Node) string {
	var parts []string
	for i := 0; i < nameNode.ChildCount(); i++ {
		c := nameNode.Child(i)
		if c.Type() == "identifier" {
			parts = append(parts, strings.TrimSpace(c.Text()))
		}
	}
	return strings.Join(parts, ".")
}

// luaNormalizeColons turns a `M:method` text into `M.method`.
func luaNormalizeColons(s string) string {
	return strings.ReplaceAll(s, ":", ".")
}

// luaAssignedFunction inspects a `variable_declaration` / `variable_
// assignment` node for the `lhs = function(...) end` shape and returns
// the LHS name plus the function-expression node. Returns ("", nil) when
// the RHS isn't a function expression.
func luaAssignedFunction(n *tsast.Node) (string, *tsast.Node) {
	var lhs string
	var fnExpr *tsast.Node
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		switch c.Type() {
		case "variable_declarator":
			// `local f = ...`: name on the `name` field, value on `value`.
			if nm := c.ChildByFieldName("name"); nm != nil {
				lhs = luaNormalizeColons(strings.TrimSpace(nm.Text()))
			}
			if v := c.ChildByFieldName("value"); v != nil && isLuaFunctionExpr(v) {
				fnExpr = v
			}
		case "variable_list":
			// `M.handler = ...`: LHS is the first variable in the list.
			if lhs == "" {
				lhs = luaNormalizeColons(strings.TrimSpace(firstLuaVarText(c)))
			}
		case "expression_list":
			if fnExpr == nil {
				for j := 0; j < c.ChildCount(); j++ {
					cc := c.Child(j)
					if isLuaFunctionExpr(cc) {
						fnExpr = cc
						break
					}
				}
			}
		default:
			if fnExpr == nil && isLuaFunctionExpr(c) && c.FieldName() == "value" {
				fnExpr = c
			}
		}
	}
	return lhs, fnExpr
}

// isLuaFunctionExpr reports whether a node is an anonymous-function
// expression. The tree-sitter-lua grammar names these `function_
// definition` (sometimes `function`); accept both to be resilient.
func isLuaFunctionExpr(n *tsast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "function_definition", "function", "function_expression":
		return true
	}
	return false
}

// firstLuaVarText returns the dotted text of the first variable in a
// `variable_list` (e.g. `M.handler`). It joins identifier / dot_index
// leaves so `M.handler` survives intact.
func firstLuaVarText(varList *tsast.Node) string {
	for _, c := range varList.NamedChildren() {
		switch c.Type() {
		case "identifier":
			return strings.TrimSpace(c.Text())
		case "dot_index_expression":
			return strings.TrimSpace(c.Text())
		}
	}
	return strings.TrimSpace(varList.Text())
}

// emitLuaFunc creates (or reuses) a FuncNode for fn with the already-
// qualified fullName, then walks the body to collect RawCalls into
// callMap[node.ID].
func emitLuaFunc(
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
	node := registerLuaFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	walkLuaBodyForCalls(fn, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerLuaFunc builds or reuses a FuncNode for fn.
func registerLuaFunc(
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
		Language:    rules.LangLua,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkLuaBodyForCalls walks a function body and records every
// `function_call` node's textual function reference into
// callMap[outer.ID]. We don't descend into nested function declarations
// — those become separate top-level nodes elsewhere.
func walkLuaBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_statement", "local_function_statement",
			"function_definition", "function_expression":
			// Don't descend into nested function-like nodes — they're
			// either separate top-level nodes or inline callbacks out of
			// scope for the cross-file pass. (The root passed in here is
			// the outer's own declaration, so we still walk its body below
			// via NamedChildren before the guard can fire on the root.)
			if n != root {
				return
			}
		case "function_call":
			if name := luaCallName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls nested in arguments (`db:query(m.x())`)
			// are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// luaCallName returns the canonical raw-name form of a Lua
// `function_call` node:
//
//	"foo"        for `foo(...)`            (single prefix identifier)
//	"alias.bar"  for `alias.bar(...)`      (two prefix identifiers, or a
//	             dot_index_expression prefix `table.field`)
//	"bar"        for `recv:bar(...)`       (colon method — the receiver is
//	             a runtime value, so only the method name is keyed; the
//	             same-file pass / sink scanner handles it)
//	""           for deeper / unrecognised shapes.
//
// In the tree-sitter-lua grammar a `m.get_id()` call is a flat
// `function_call` with two `identifier` children both fielded `prefix`
// (`m`, `get_id`); `os.execute(...)` may instead nest a
// `dot_index_expression` prefix. Both shapes are handled.
func luaCallName(n *tsast.Node) string {
	// Colon-method call: identifier ... self_call_colon identifier.
	for i := 0; i+2 < n.ChildCount(); i++ {
		if n.Child(i+1).Type() == "self_call_colon" {
			recv := n.Child(i)
			method := n.Child(i + 2)
			if recv.Type() == "identifier" && method.Type() == "identifier" {
				// Key colon calls by method name only — the receiver is a
				// runtime connection/object handle, not an import alias.
				return strings.TrimSpace(method.Text())
			}
		}
	}

	// dot_index_expression prefix: `table.field(...)`.
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.Type() == "dot_index_expression" {
			table := c.ChildByFieldName("table")
			field := c.ChildByFieldName("field")
			if table != nil && field != nil {
				return strings.TrimSpace(table.Text()) + "." + strings.TrimSpace(field.Text())
			}
		}
	}

	// Flat prefix identifiers: collect the leading run of `prefix`-fielded
	// identifiers (before the argument parens).
	var idents []string
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.Type() == "identifier" {
			idents = append(idents, strings.TrimSpace(c.Text()))
			continue
		}
		// Stop at the first non-identifier (the call parens / args).
		if c.Type() == "function_call_paren" || c.Type() == "function_arguments" ||
			c.Type() == "string" || c.Type() == "tableconstructor" {
			break
		}
	}
	switch len(idents) {
	case 0:
		return ""
	case 1:
		return idents[0]
	default:
		// `m.get_id` → "m.get_id"; deeper chains keep first.last so the
		// resolver's alias lookup (first segment) still works.
		return idents[0] + "." + idents[len(idents)-1]
	}
}
