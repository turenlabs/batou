// File-level Perl call-site index (PR-Gperl).
//
// Mirrors crossfile_walk_lua_index.go. findPerlCallSites parses the
// caller's file content with tree-sitter every time it's invoked;
// WalkCrossFileTaintFlows calls it inside an O(callers × callees) loop.
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every call expression by its method basename.
//
// The cache is intentionally pass-scoped: callers create a fresh
// perlCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// perlCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`my $x = foo(...)`).
type perlCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// perlCallIndex is a pre-walked map of basename → call sites found in a
// single file's content.
type perlCallIndex struct {
	byBaseName map[string][]perlCallSite
}

// lookup returns the cached call sites whose basename matches and whose line
// falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *perlCallIndex) lookup(callerNode *FuncNode, baseName string) []perlCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]perlCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// perlCallIndexCache memoizes per-file-content perlCallIndex instances.
type perlCallIndexCache struct {
	byContent map[string]*perlCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newPerlCallIndexCache returns an empty cache.
func newPerlCallIndexCache() *perlCallIndexCache {
	return &perlCallIndexCache{
		byContent: make(map[string]*perlCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *perlCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access.
func (c *perlCallIndexCache) get(content string) *perlCallIndex {
	if c == nil {
		return buildPerlCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildPerlCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildPerlCallIndex parses content once, walks the tree once, and records
// every call expression grouped by its method basename. Assignment-style
// call sites (`my $x = foo(...)`) populate assignedTo.
func buildPerlCallIndex(content string) *perlCallIndex {
	idx := &perlCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangPerl)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]perlCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "assignment_expression":
			// Record the LHS so a call on the RHS gets assignedTo set.
			lhs, callNode := perlAssignCallTarget(n)
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
		case "function_call_expression", "ambiguous_function_call_expression",
			"method_call_expression":
			base := perlCallBaseName(n)
			if base != "" {
				cs := perlCallSite{line: int(n.StartRow()) + 1, assignedTo: assignTarget}
				cs.args = perlCallArgs(n)
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in arguments
			// (`system(A::get_name($cgi))`) are indexed under their own
			// basename.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// perlAssignCallTarget returns (lhsName, rhsCallNode) for a
// `my $x = foo(...)` / `$x = foo(...)` assignment_expression node, or
// ("", nil) when the RHS isn't a direct call expression.
func perlAssignCallTarget(n *tsast.Node) (string, *tsast.Node) {
	lhs := ""
	if l := n.ChildByFieldName("left"); l != nil {
		lhs = perlLHSName(l)
	}
	var call *tsast.Node
	if r := n.ChildByFieldName("right"); r != nil {
		switch r.Type() {
		case "function_call_expression", "ambiguous_function_call_expression",
			"method_call_expression":
			call = r
		}
	}
	return lhs, call
}

// perlLHSName extracts the bound scalar name from an assignment LHS, which
// is either a `variable_declaration` (`my $x`) or a bare `scalar` (`$x`).
func perlLHSName(lhs *tsast.Node) string {
	target := lhs
	if lhs.Type() == "variable_declaration" {
		if v := lhs.ChildByFieldName("variable"); v != nil {
			target = v
		} else {
			// Fallback: first scalar child.
			for _, c := range lhs.NamedChildren() {
				if c.Type() == "scalar" {
					target = c
					break
				}
			}
		}
	}
	// Pull the varname out of the scalar node.
	for _, c := range target.NamedChildren() {
		if c.Type() == "varname" {
			return strings.TrimSpace(c.Text())
		}
	}
	if target.Type() == "varname" {
		return strings.TrimSpace(target.Text())
	}
	return ""
}

// perlCallBaseName returns the method basename a call expression resolves
// to: for `foo()` → "foo", for `A::get_name()` → "get_name", for
// `$obj->method()` → "method". Mirrors the basenames the resolver / walker
// key call sites by.
func perlCallBaseName(call *tsast.Node) string {
	name := perlCallName(call)
	if name == "" {
		return ""
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

// perlCallArgs returns positional argument text from a call expression's
// `arguments` field (a single node or a `list_expression` of args).
func perlCallArgs(call *tsast.Node) []string {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	if args.Type() == "list_expression" {
		var out []string
		for _, child := range args.NamedChildren() {
			out = append(out, strings.TrimSpace(child.Text()))
		}
		return out
	}
	// Single argument.
	return []string{strings.TrimSpace(args.Text())}
}

// findPerlCallSites parses callerContent and returns every call to a sub
// whose simple basename equals extractBaseName(calleeName), within the
// caller node's line range.
func findPerlCallSites(callerContent string, callerNode *FuncNode, calleeName string) []perlCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildPerlCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findPerlCallSitesIndexed is the cache-aware variant of findPerlCallSites.
func findPerlCallSitesIndexed(cache *perlCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []perlCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findPerlCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
