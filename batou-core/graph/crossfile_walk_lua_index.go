// File-level Lua call-site index (PR-Glua).
//
// Mirrors crossfile_walk_ruby_index.go. findLuaCallSites parses the
// caller's file content with tree-sitter every time it's invoked;
// WalkCrossFileTaintFlows calls it inside an O(callers × callees) loop.
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every `function_call` node by its method
// basename.
//
// The cache is intentionally pass-scoped: callers create a fresh
// luaCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// luaCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`local x = foo(...)`).
type luaCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// luaCallIndex is a pre-walked map of basename → call sites found in a
// single file's content.
type luaCallIndex struct {
	byBaseName map[string][]luaCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *luaCallIndex) lookup(callerNode *FuncNode, baseName string) []luaCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]luaCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// luaCallIndexCache memoizes per-file-content luaCallIndex instances.
type luaCallIndexCache struct {
	byContent map[string]*luaCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newLuaCallIndexCache returns an empty cache.
func newLuaCallIndexCache() *luaCallIndexCache {
	return &luaCallIndexCache{
		byContent: make(map[string]*luaCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *luaCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access.
func (c *luaCallIndexCache) get(content string) *luaCallIndex {
	if c == nil {
		return buildLuaCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildLuaCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildLuaCallIndex parses content once, walks the tree once, and records
// every `function_call` grouped by its method basename. Assignment-style
// call sites (`local x = foo(...)`) populate assignedTo.
func buildLuaCallIndex(content string) *luaCallIndex {
	idx := &luaCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangLua)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]luaCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "variable_declaration", "variable_assignment":
			// Record the LHS so a call on the RHS gets assignedTo set.
			lhs, callNode := luaAssignCallTarget(n)
			if callNode != nil {
				visit(callNode, lhs)
				// Continue into any non-call children too.
				for _, c := range n.NamedChildren() {
					if c != callNode {
						visit(c, "")
					}
				}
				return
			}
		case "function_call":
			base := luaCallBaseName(n)
			if base != "" {
				cs := luaCallSite{line: int(n.StartRow()) + 1, assignedTo: assignTarget}
				cs.args = luaCallArgs(n)
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in arguments
			// (`db:query(m.get_id())`) are indexed under their own basename.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// luaAssignCallTarget returns (lhsName, rhsCallNode) for a
// `local x = foo(...)` / `x = foo(...)` node, or ("", nil) when the RHS
// isn't a direct function_call.
func luaAssignCallTarget(n *tsast.Node) (string, *tsast.Node) {
	lhs := ""
	var call *tsast.Node
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		switch c.Type() {
		case "variable_declarator":
			// The declarator IS the parent's `name` slot; its first
			// identifier child is the bound variable. The call result is a
			// SIBLING fielded `value` (handled by the `function_call` arm
			// below), not a child of the declarator.
			if lhs == "" {
				lhs = luaDeclaratorName(c)
			}
			if v := c.ChildByFieldName("value"); v != nil && v.Type() == "function_call" {
				call = v
			}
		case "variable_list":
			if lhs == "" {
				for _, vc := range c.NamedChildren() {
					if vc.Type() == "identifier" {
						lhs = strings.TrimSpace(vc.Text())
						break
					}
				}
			}
		case "expression_list":
			if call == nil {
				for _, ec := range c.NamedChildren() {
					if ec.Type() == "function_call" {
						call = ec
						break
					}
				}
			}
		case "function_call":
			if c.FieldName() == "value" && call == nil {
				call = c
			}
		}
	}
	return lhs, call
}

// luaCallBaseName returns the method basename a `function_call` resolves
// to: for `foo()` → "foo", for `m.get_id()` → "get_id", for
// `db:query()` → "query". Mirrors the basenames the resolver / walker key
// call sites by.
func luaCallBaseName(call *tsast.Node) string {
	name := luaCallName(call)
	if name == "" {
		return ""
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

// luaCallArgs returns positional argument text from a `function_call`'s
// `function_arguments` child.
func luaCallArgs(call *tsast.Node) []string {
	var args *tsast.Node
	if a := call.ChildByFieldName("args"); a != nil {
		args = a
	} else {
		for i := 0; i < call.ChildCount(); i++ {
			if call.Child(i).Type() == "function_arguments" {
				args = call.Child(i)
				break
			}
		}
	}
	if args == nil {
		return nil
	}
	var out []string
	for _, child := range args.NamedChildren() {
		out = append(out, strings.TrimSpace(child.Text()))
	}
	return out
}

// findLuaCallSites parses callerContent and returns every call to a
// function whose simple basename equals extractBaseName(calleeName),
// within the caller node's line range.
func findLuaCallSites(callerContent string, callerNode *FuncNode, calleeName string) []luaCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildLuaCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findLuaCallSitesIndexed is the cache-aware variant of findLuaCallSites.
func findLuaCallSitesIndexed(cache *luaCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []luaCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findLuaCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
