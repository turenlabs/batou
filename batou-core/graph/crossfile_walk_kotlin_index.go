// File-level Kotlin call-site index.
//
// Mirrors crossfile_walk_csharp_index.go / crossfile_walk_lua_index.go.
// findKotlinCallSites parses the caller's file content with tree-sitter
// every time it's invoked; WalkCrossFileTaintFlows calls it inside an
// O(callers × callees) loop. This file adds a per-pass cache that parses
// each file once, walks the tree once, and indexes every call_expression
// node by its called-function basename.
//
// The cache is intentionally pass-scoped: callers create a fresh
// kotlinCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// kotlinCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`val x = foo(...)` /
// `var x = foo(...)` / `x = foo(...)` form).
type kotlinCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// kotlinCallIndex is a pre-walked map of basename → call sites found in a
// single file's content.
type kotlinCallIndex struct {
	byBaseName map[string][]kotlinCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *kotlinCallIndex) lookup(callerNode *FuncNode, baseName string) []kotlinCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]kotlinCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// kotlinCallIndexCache memoizes per-file-content kotlinCallIndex instances.
type kotlinCallIndexCache struct {
	byContent map[string]*kotlinCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newKotlinCallIndexCache returns an empty cache.
func newKotlinCallIndexCache() *kotlinCallIndexCache {
	return &kotlinCallIndexCache{
		byContent: make(map[string]*kotlinCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *kotlinCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access. Returns a
// non-nil index even on parse failure so we don't retry failed parses on
// every caller in the file.
func (c *kotlinCallIndexCache) get(content string) *kotlinCallIndex {
	if c == nil {
		return buildKotlinCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildKotlinCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildKotlinCallIndex parses content once, walks the tree once, and
// records every call_expression node grouped by its called-function
// basename. Assignment-style call sites populate assignedTo, captured from
// the enclosing property_declaration (`val x = foo()` / `var x = foo()`) or
// an assignment (`x = foo()`).
func buildKotlinCallIndex(content string) *kotlinCallIndex {
	idx := &kotlinCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangKotlin)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]kotlinCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "property_declaration":
			// `val n = foo(...)` / `var n = foo(...)`. The bound name is the
			// simple_identifier inside the variable_declaration child;
			// propagate it into the RHS subtree so the call gets assignedTo.
			name := kotlinPropertyBindingName(n)
			if name != "" {
				for _, c := range n.NamedChildren() {
					visit(c, name)
				}
				return
			}
		case "assignment":
			// `x = foo(...)`. LHS is the first simple_identifier; RHS is the
			// last named child.
			name := kotlinAssignmentLHS(n)
			named := n.NamedChildren()
			if name != "" && len(named) > 0 {
				visit(named[len(named)-1], name)
				return
			}
		case "call_expression":
			base := kotlinCallBaseName(n)
			if base != "" {
				cs := kotlinCallSite{
					line:       int(n.StartRow()) + 1,
					assignedTo: assignTarget,
				}
				cs.args = extractKotlinCallSiteArgs(n)
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in arguments
			// (`exec(getName(req))`) are indexed too.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// kotlinPropertyBindingName returns the bound variable name of a
// property_declaration (`val n = ...` → "n"), reading the simple_identifier
// inside the variable_declaration child.
func kotlinPropertyBindingName(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		if c.Type() == "variable_declaration" {
			for _, gc := range c.NamedChildren() {
				if gc.Type() == "simple_identifier" {
					return strings.TrimSpace(gc.Text())
				}
			}
		}
	}
	return ""
}

// kotlinAssignmentLHS returns the LHS identifier of an `assignment` node
// (`x = ...` → "x").
func kotlinAssignmentLHS(n *tsast.Node) string {
	// Fast path: the LHS identifier is the first named child (`x = ...`).
	if kids := n.NamedChildren(); len(kids) > 0 && kids[0].Type() == "simple_identifier" {
		return strings.TrimSpace(kids[0].Text())
	}
	// Fallback: scan named children for the first simple_identifier.
	for _, c := range n.NamedChildren() {
		if c.Type() == "simple_identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// kotlinCallBaseName returns the simple method/function name a tree-sitter
// call_expression resolves to: `foo(...)` → "foo", `recv.bar(...)` → "bar".
// Mirrors the basename the resolver / walker key call sites by
// (extractBaseName of the callee node name).
func kotlinCallBaseName(call *tsast.Node) string {
	name := kotlinCallText(call)
	if name == "" {
		return ""
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// extractKotlinCallSiteArgs returns positional argument text from a
// call_expression's `call_suffix → value_arguments → value_argument`
// chain. Only the call_suffix DIRECTLY under this call_expression is read
// (so nested call args aren't swept in).
func extractKotlinCallSiteArgs(call *tsast.Node) []string {
	var suffix *tsast.Node
	for _, c := range call.NamedChildren() {
		if c.Type() == "call_suffix" {
			suffix = c
			break
		}
	}
	if suffix == nil {
		return nil
	}
	var valueArgs *tsast.Node
	for _, c := range suffix.NamedChildren() {
		if c.Type() == "value_arguments" {
			valueArgs = c
			break
		}
	}
	if valueArgs == nil {
		return nil
	}
	var args []string
	for _, va := range valueArgs.NamedChildren() {
		if va.Type() != "value_argument" {
			continue
		}
		args = append(args, strings.TrimSpace(va.Text()))
	}
	return args
}

// findKotlinCallSites parses callerContent and returns every call to a
// function whose simple basename equals extractBaseName(calleeName), within
// the caller node's line range.
func findKotlinCallSites(callerContent string, callerNode *FuncNode, calleeName string) []kotlinCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildKotlinCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findKotlinCallSitesIndexed is the cache-aware variant of
// findKotlinCallSites. When cache is nil the behaviour matches the uncached
// path: parse from scratch and walk.
func findKotlinCallSitesIndexed(cache *kotlinCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []kotlinCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findKotlinCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
