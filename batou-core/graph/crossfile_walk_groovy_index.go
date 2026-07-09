// File-level Groovy call-site index (PR-Ggroovy).
//
// Mirrors crossfile_walk_swift_index.go. findGroovyCallSites parses the
// caller's file content with tree-sitter every time it's invoked;
// WalkCrossFileTaintFlows calls it inside an O(callers × callees) loop.
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every `function_call` node by its method basename.
//
// The cache is intentionally pass-scoped: callers create a fresh
// groovyCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// groovyCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`def x = foo(...)` /
// `x = foo(...)`).
type groovyCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// groovyCallIndex is a pre-walked map of basename → call sites found in a
// single file's content.
type groovyCallIndex struct {
	byBaseName map[string][]groovyCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *groovyCallIndex) lookup(callerNode *FuncNode, baseName string) []groovyCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]groovyCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// groovyCallIndexCache memoizes per-file-content groovyCallIndex instances.
type groovyCallIndexCache struct {
	byContent map[string]*groovyCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newGroovyCallIndexCache returns an empty cache.
func newGroovyCallIndexCache() *groovyCallIndexCache {
	return &groovyCallIndexCache{
		byContent: make(map[string]*groovyCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *groovyCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access.
func (c *groovyCallIndexCache) get(content string) *groovyCallIndex {
	if c == nil {
		return buildGroovyCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildGroovyCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildGroovyCallIndex parses content once, walks the tree once, and
// records every `function_call` grouped by its method basename.
// Assignment-style call sites (`def x = foo(...)` / `x = foo(...)`)
// populate assignedTo from the enclosing `declaration` / `assignment`.
func buildGroovyCallIndex(content string) *groovyCallIndex {
	idx := &groovyCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangGroovy)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]groovyCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "declaration", "assignment":
			// `def n = getName(req)` (declaration) / `n = getName(req)`
			// (assignment). Record the LHS so a call on the RHS gets
			// assignedTo set.
			lhs, callNode := groovyAssignCallTarget(n)
			if callNode != nil {
				visit(callNode, lhs)
				for _, c := range n.NamedChildren() {
					if c != callNode {
						visit(c, "")
					}
				}
				return
			}
		case "function_call":
			base := groovyCallBaseName(n)
			if base != "" {
				cs := groovyCallSite{line: int(n.StartRow()) + 1, assignedTo: assignTarget}
				cs.args = groovyCallArgs(n)
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in arguments
			// (`run(getName(req))`) are indexed under their own basename.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// groovyAssignCallTarget returns (lhsName, rhsCallNode) for a
// `def x = foo(...)` (declaration) or `x = foo(...)` (assignment) node, or
// ("", nil) when the RHS isn't a direct function_call.
func groovyAssignCallTarget(n *tsast.Node) (string, *tsast.Node) {
	lhs := ""
	var call *tsast.Node
	switch n.Type() {
	case "declaration":
		// `def n = getName(req)`: first identifier is the bound variable; the
		// function_call child is the init expression (no `value` field in the
		// tree-sitter-groovy grammar).
		for _, c := range n.NamedChildren() {
			switch c.Type() {
			case "identifier":
				if lhs == "" {
					lhs = strings.TrimSpace(c.Text())
				}
			case "function_call":
				if call == nil {
					call = c
				}
			}
		}
	case "assignment":
		// `n = getName(req)`: left field is the LHS, right field the RHS.
		if l := n.ChildByFieldName("left"); l != nil {
			lhs = groovyLastIdent(l.Text())
		}
		if rhs := n.ChildByFieldName("right"); rhs != nil && rhs.Type() == "function_call" {
			call = rhs
		}
		if call == nil {
			for _, c := range n.NamedChildren() {
				if c.Type() == "function_call" {
					call = c
					break
				}
			}
		}
	}
	return lhs, call
}

// groovyLastIdent returns the last identifier token in s (used to pull a
// variable name out of an LHS expression).
func groovyLastIdent(s string) string {
	s = strings.TrimSpace(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// groovyCallBaseName returns the method basename a `function_call` resolves
// to: for `foo()` → "foo", for `recv.method()` → "method". Mirrors the
// basenames the resolver / walker key call sites by.
func groovyCallBaseName(call *tsast.Node) string {
	name := groovyCallName(call)
	if name == "" {
		return ""
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

// groovyCallArgs returns positional argument text from a `function_call`'s
// `argument_list` child. Each named child of the argument_list is one
// positional argument expression.
func groovyCallArgs(call *tsast.Node) []string {
	var out []string
	var argList *tsast.Node
	if a := call.ChildByFieldName("arguments"); a != nil {
		argList = a
	} else {
		for _, c := range call.NamedChildren() {
			if c.Type() == "argument_list" {
				argList = c
				break
			}
		}
	}
	if argList == nil {
		return out
	}
	for _, arg := range argList.NamedChildren() {
		out = append(out, strings.TrimSpace(arg.Text()))
	}
	return out
}

// findGroovyCallSites parses callerContent and returns every call to a
// function whose simple basename equals extractBaseName(calleeName), within
// the caller node's line range.
func findGroovyCallSites(callerContent string, callerNode *FuncNode, calleeName string) []groovyCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildGroovyCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findGroovyCallSitesIndexed is the cache-aware variant of
// findGroovyCallSites.
func findGroovyCallSitesIndexed(cache *groovyCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []groovyCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findGroovyCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
