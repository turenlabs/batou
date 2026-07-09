// File-level Swift call-site index (PR-Gswift).
//
// Mirrors crossfile_walk_lua_index.go. findSwiftCallSites parses the
// caller's file content with tree-sitter every time it's invoked;
// WalkCrossFileTaintFlows calls it inside an O(callers × callees) loop.
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every `call_expression` node by its method
// basename.
//
// The cache is intentionally pass-scoped: callers create a fresh
// swiftCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// swiftCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`let x = foo(...)`).
type swiftCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// swiftCallIndex is a pre-walked map of basename → call sites found in a
// single file's content.
type swiftCallIndex struct {
	byBaseName map[string][]swiftCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *swiftCallIndex) lookup(callerNode *FuncNode, baseName string) []swiftCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]swiftCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// swiftCallIndexCache memoizes per-file-content swiftCallIndex instances.
type swiftCallIndexCache struct {
	byContent map[string]*swiftCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newSwiftCallIndexCache returns an empty cache.
func newSwiftCallIndexCache() *swiftCallIndexCache {
	return &swiftCallIndexCache{
		byContent: make(map[string]*swiftCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *swiftCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access.
func (c *swiftCallIndexCache) get(content string) *swiftCallIndex {
	if c == nil {
		return buildSwiftCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildSwiftCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildSwiftCallIndex parses content once, walks the tree once, and
// records every `call_expression` grouped by its method basename.
// Assignment-style call sites (`let x = foo(...)`) populate assignedTo
// from the enclosing `property_declaration` pattern.
func buildSwiftCallIndex(content string) *swiftCallIndex {
	idx := &swiftCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangSwift)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]swiftCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "property_declaration", "assignment":
			// Record the LHS so a call on the RHS gets assignedTo set.
			lhs, callNode := swiftAssignCallTarget(n)
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
		case "call_expression":
			base := swiftCallBaseName(n)
			if base != "" {
				cs := swiftCallSite{line: int(n.StartRow()) + 1, assignedTo: assignTarget}
				cs.args = swiftCallArgs(n)
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in arguments
			// (`system(getName(req))`) are indexed under their own basename.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// swiftAssignCallTarget returns (lhsName, rhsCallNode) for a
// `let x = foo(...)` / `var x = foo(...)` / `x = foo(...)` node, or
// ("", nil) when the RHS isn't a direct call_expression.
func swiftAssignCallTarget(n *tsast.Node) (string, *tsast.Node) {
	lhs := ""
	var call *tsast.Node
	switch n.Type() {
	case "property_declaration":
		// `let n = getName(req)`: pattern holds the bound identifier;
		// the value field holds the RHS expression.
		if p := n.ChildByFieldName("name"); p != nil {
			lhs = swiftPatternName(p)
		}
		if lhs == "" {
			// Some grammar revisions expose the pattern as a named child
			// rather than a `name` field.
			for _, c := range n.NamedChildren() {
				if c.Type() == "pattern" {
					lhs = swiftPatternName(c)
					break
				}
			}
		}
		if v := n.ChildByFieldName("value"); v != nil && v.Type() == "call_expression" {
			call = v
		}
		if call == nil {
			for _, c := range n.NamedChildren() {
				if c.Type() == "call_expression" {
					call = c
					break
				}
			}
		}
	case "assignment":
		// `x = foo(...)`: first simple_identifier is the LHS, the trailing
		// expression is the RHS.
		named := n.NamedChildren()
		for _, c := range named {
			if c.Type() == "directly_assignable_expression" || c.Type() == "simple_identifier" {
				lhs = swiftLastIdent(c.Text())
				break
			}
		}
		for i := len(named) - 1; i >= 0; i-- {
			if named[i].Type() == "call_expression" {
				call = named[i]
				break
			}
		}
	}
	return lhs, call
}

// swiftPatternName returns the bound identifier of a `pattern` node
// (`let n` → "n"): its first simple_identifier child, or the trimmed
// node text.
func swiftPatternName(pat *tsast.Node) string {
	for _, c := range pat.NamedChildren() {
		if c.Type() == "simple_identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return swiftLastIdent(pat.Text())
}

// swiftCallBaseName returns the method basename a `call_expression`
// resolves to: for `foo()` → "foo", for `obj.method()` → "method".
// Mirrors the basenames the resolver / walker key call sites by.
func swiftCallBaseName(call *tsast.Node) string {
	name := swiftCallName(call)
	if name == "" {
		return ""
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

// swiftCallArgs returns positional argument text from a
// `call_expression`'s `call_suffix` → `value_arguments` children.
func swiftCallArgs(call *tsast.Node) []string {
	var out []string
	for i := 0; i < call.ChildCount(); i++ {
		c := call.Child(i)
		if c.Type() != "call_suffix" {
			continue
		}
		for j := 0; j < c.ChildCount(); j++ {
			va := c.Child(j)
			if va.Type() != "value_arguments" {
				continue
			}
			for _, arg := range va.NamedChildren() {
				if arg.Type() != "value_argument" {
					continue
				}
				if v := arg.ChildByFieldName("value"); v != nil {
					out = append(out, strings.TrimSpace(v.Text()))
					continue
				}
				named := arg.NamedChildren()
				if len(named) > 0 {
					out = append(out, strings.TrimSpace(named[len(named)-1].Text()))
				}
			}
		}
	}
	return out
}

// findSwiftCallSites parses callerContent and returns every call to a
// function whose simple basename equals extractBaseName(calleeName),
// within the caller node's line range.
func findSwiftCallSites(callerContent string, callerNode *FuncNode, calleeName string) []swiftCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildSwiftCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findSwiftCallSitesIndexed is the cache-aware variant of
// findSwiftCallSites.
func findSwiftCallSitesIndexed(cache *swiftCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []swiftCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findSwiftCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
