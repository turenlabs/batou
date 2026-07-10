package graph

import (
	"path/filepath"
	"testing"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// TestLuaNormalizeColons pins the colon → dot normalisation that keeps
// `M:method` and `M.method` on one node name.
func TestLuaNormalizeColons(t *testing.T) {
	cases := []struct{ in, want string }{
		{"M:method", "M.method"},
		{"M.handler", "M.handler"},
		{"a:b:c", "a.b.c"},
		{"plain", "plain"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := luaNormalizeColons(tc.in); got != tc.want {
			t.Errorf("luaNormalizeColons(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestLuaBuilder_ColonMethodNormalized: `function M:method()` declares a
// colon method; the builder must register it under the dot-normalised
// name "M.method" so cross-file resolution needn't know the sugar.
func TestLuaBuilder_ColonMethodNormalized(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "service.lua")
	src := `local M = {}

function M:method(x)
    return x
end

function M.helper(y)
    return M:method(y)
end

return M
`
	UpdateFile(cg, filePath, src, rules.LangLua)

	if n := cg.GetNode(filePath + ":M.method"); n == nil {
		t.Errorf("M.method (colon method) not normalised; have %v", nodeIDsInFile(cg, filePath))
	}
	if n := cg.GetNode(filePath + ":M.helper"); n == nil {
		t.Errorf("M.helper not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

// TestLuaBuilder_AssignedFunction_KnownGap documents a grammar mismatch in
// the assignment path (luaAssignedFunction): the vendored tree-sitter-lua
// grammar parses `M.handler = function() end` as a `variable_declaration`
// whose `variable_declarator` IS the name-fielded child (there is no inner
// `name` field and no `variable_list` node), so the builder's declarator /
// variable_list arms never bind an LHS and NO FuncNode is emitted for
// assignment-bound functions today. If this test starts failing because
// the node appears, the gap was fixed — move these asserts to a positive
// test and delete this one.
func TestLuaBuilder_AssignedFunction_KnownGap(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "routes.lua")
	src := `local M = {}

M.handler = function(req)
    return db.query(req)
end

return M
`
	UpdateFile(cg, filePath, src, rules.LangLua)

	if n := cg.GetNode(filePath + ":M.handler"); n != nil {
		t.Errorf("assignment-bound function now emits a node (%v) — the grammar gap "+
			"documented here was fixed; promote this test to a positive assertion", n.ID)
	}
}

// TestFirstLuaVarText covers firstLuaVarText's identifier and raw-text
// fallback branches directly. (The `variable_list` shape the builder
// passes it never occurs with the current vendored grammar — see
// TestLuaBuilder_AssignedFunction_KnownGap — so we exercise the helper's
// contract on real parsed nodes.)
func TestFirstLuaVarText(t *testing.T) {
	src := "M.handler = function() end\n"
	tree := tsast.Parse([]byte(src), rules.LangLua)
	if tree == nil || tree.Root() == nil {
		t.Fatal("Lua parse failed")
	}
	// Find the variable_declarator (named children: identifiers M, handler)
	// and the value `function` node (no identifier children → fallback).
	var declarator, fnExpr *tsast.Node
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "variable_declarator":
			declarator = n
		case "function":
			fnExpr = n
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(tree.Root())
	if declarator == nil || fnExpr == nil {
		t.Fatal("parse did not produce variable_declarator + function nodes")
	}

	// First identifier child wins.
	if got := firstLuaVarText(declarator); got != "M" {
		t.Errorf("firstLuaVarText(declarator) = %q, want first identifier 'M'", got)
	}
	// No identifier / dot_index_expression children → trimmed raw text.
	if got := firstLuaVarText(fnExpr); got == "" {
		t.Errorf("firstLuaVarText(function node) = empty, want raw-text fallback")
	}
}
