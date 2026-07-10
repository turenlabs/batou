// File-level Rust call-site index (PR-Grust).
//
// Mirrors crossfile_walk_lua_index.go. findRustCallSites parses the
// caller's file content with tree-sitter every time it's invoked;
// WalkCrossFileTaintFlows calls it inside an O(callers × callees) loop.
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every `call_expression` node by its method
// basename.
//
// The cache is intentionally pass-scoped: callers create a fresh
// rustCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// rustCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`let x = foo(...)`).
type rustCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// rustCallIndex is a pre-walked map of basename → call sites found in a
// single file's content.
type rustCallIndex struct {
	byBaseName map[string][]rustCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *rustCallIndex) lookup(callerNode *FuncNode, baseName string) []rustCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]rustCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// rustCallIndexCache memoizes per-file-content rustCallIndex instances.
type rustCallIndexCache struct {
	byContent map[string]*rustCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newRustCallIndexCache returns an empty cache.
func newRustCallIndexCache() *rustCallIndexCache {
	return &rustCallIndexCache{
		byContent: make(map[string]*rustCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *rustCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access.
func (c *rustCallIndexCache) get(content string) *rustCallIndex {
	if c == nil {
		return buildRustCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildRustCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildRustCallIndex parses content once, walks the tree once, and records
// every `call_expression` grouped by its method basename. Assignment-style
// call sites (`let x = foo(...)`) populate assignedTo from the enclosing
// let_declaration's `pattern` field.
func buildRustCallIndex(content string) *rustCallIndex {
	idx := &rustCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangRust)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]rustCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "let_declaration":
			// `let x = foo(...)` — capture the bound variable so a call on
			// the value side gets assignedTo set.
			lhs, callNode := rustLetCallTarget(n)
			if callNode != nil {
				visit(callNode, lhs)
				for _, c := range n.NamedChildren() {
					if c != callNode {
						visit(c, "")
					}
				}
				return
			}
		case "call_expression":
			base := rustCallBaseName(n)
			if base != "" {
				cs := rustCallSite{line: int(n.StartRow()) + 1, assignedTo: assignTarget}
				cs.args = extractRustCallArgs(n)
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in arguments
			// (`db.query(get_id())`) are indexed under their own basename.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// rustLetCallTarget returns (lhsName, rhsCallNode) for a
// `let x = foo(...)` node, or ("", nil) when the value isn't a direct
// call_expression. The pattern field holds the bound variable; the value
// field holds the call.
func rustLetCallTarget(n *tsast.Node) (string, *tsast.Node) {
	lhs := ""
	if pat := n.ChildByFieldName("pattern"); pat != nil && pat.Type() == "identifier" {
		lhs = strings.TrimSpace(pat.Text())
	}
	val := n.ChildByFieldName("value")
	if val == nil {
		return lhs, nil
	}
	if val.Type() == "call_expression" {
		return lhs, val
	}
	return lhs, nil
}

// rustCallBaseName returns the method basename a `call_expression`
// resolves to: for `foo()` → "foo", for `a::other()` → "other", for
// `recv.method()` → "method". Mirrors the basenames the resolver / walker
// key call sites by.
func rustCallBaseName(call *tsast.Node) string {
	name := rustCallName(call)
	if name == "" {
		return ""
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

// extractRustCallArgs returns positional argument text from a
// `call_expression`'s `arguments` child.
func extractRustCallArgs(call *tsast.Node) []string {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	var out []string
	for _, child := range args.NamedChildren() {
		out = append(out, strings.TrimSpace(child.Text()))
	}
	return out
}

// findRustCallSites parses callerContent and returns every call to a
// function whose simple basename equals extractBaseName(calleeName),
// within the caller node's line range.
func findRustCallSites(callerContent string, callerNode *FuncNode, calleeName string) []rustCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildRustCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findRustCallSitesIndexed is the cache-aware variant of findRustCallSites.
func findRustCallSitesIndexed(cache *rustCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []rustCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findRustCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
