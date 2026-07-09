// File-level C++ call-site index (PR-Gcpp).
//
// Mirrors crossfile_walk_swift_index.go / crossfile_walk_lua_index.go.
// findCPPCallSites parses the caller's file content with tree-sitter every
// time it's invoked; WalkCrossFileTaintFlows calls it inside an
// O(callers × callees) loop. This file adds a per-pass cache that parses
// each file once, walks the tree once, and indexes every `call_expression`
// node by its method basename.
//
// The cache is intentionally pass-scoped: callers create a fresh
// cppCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// cppCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`std::string x = foo(...)`).
type cppCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// cppCallIndex is a pre-walked map of basename → call sites found in a
// single file's content.
type cppCallIndex struct {
	byBaseName map[string][]cppCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *cppCallIndex) lookup(callerNode *FuncNode, baseName string) []cppCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]cppCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// cppCallIndexCache memoizes per-file-content cppCallIndex instances.
type cppCallIndexCache struct {
	byContent map[string]*cppCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newCPPCallIndexCache returns an empty cache.
func newCPPCallIndexCache() *cppCallIndexCache {
	return &cppCallIndexCache{
		byContent: make(map[string]*cppCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *cppCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access.
func (c *cppCallIndexCache) get(content string, lang rules.Language) *cppCallIndex {
	if c == nil {
		return buildCPPCallIndex(content, lang)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildCPPCallIndex(content, lang)
	c.byContent[content] = idx
	return idx
}

// buildCPPCallIndex parses content once, walks the tree once, and records
// every `call_expression` grouped by its method basename. Assignment-style
// call sites (`std::string x = foo(...)`) populate assignedTo from the
// enclosing `init_declarator` / `assignment_expression`.
func buildCPPCallIndex(content string, lang rules.Language) *cppCallIndex {
	idx := &cppCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), lang)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]cppCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "init_declarator", "assignment_expression":
			// Record the LHS so a call on the RHS gets assignedTo set.
			lhs, callNode := cppAssignCallTarget(n)
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
			base := cppCallBaseName(n)
			if base != "" {
				cs := cppCallSite{line: int(n.StartRow()) + 1, assignedTo: assignTarget}
				cs.args = cppCallArgs(n)
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

// cppAssignCallTarget returns (lhsName, rhsCallNode) for an
// `init_declarator` (`T x = foo(...)`) or an `assignment_expression`
// (`x = foo(...)`), or ("", nil) when the RHS isn't a direct
// call_expression.
func cppAssignCallTarget(n *tsast.Node) (string, *tsast.Node) {
	lhs := ""
	var call *tsast.Node
	switch n.Type() {
	case "init_declarator":
		// `T x = foo(...)`: the `declarator` field holds the bound
		// identifier; the `value` field holds the RHS expression.
		if d := n.ChildByFieldName("declarator"); d != nil {
			lhs = cppDeclaratorName(d)
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
	case "assignment_expression":
		// `x = foo(...)`: `left` is the LHS, `right` the RHS.
		if l := n.ChildByFieldName("left"); l != nil {
			lhs = cppDeclaratorName(l)
		}
		if rgt := n.ChildByFieldName("right"); rgt != nil && rgt.Type() == "call_expression" {
			call = rgt
		}
		if call == nil {
			named := n.NamedChildren()
			for i := len(named) - 1; i >= 0; i-- {
				if named[i].Type() == "call_expression" {
					call = named[i]
					break
				}
			}
		}
	}
	return lhs, call
}

// cppDeclaratorName returns the bound variable name from a declarator /
// LHS node, unwrapping pointer / reference declarators.
func cppDeclaratorName(n *tsast.Node) string {
	cur := n
	for cur != nil {
		switch cur.Type() {
		case "identifier", "field_identifier":
			return strings.TrimSpace(cur.Text())
		case "pointer_declarator", "reference_declarator",
			"init_declarator":
			inner := cur.ChildByFieldName("declarator")
			if inner == nil {
				inner = firstCPPNamedDeclarator(cur)
			}
			cur = inner
			continue
		}
		// Fallback: last identifier-ish token.
		return cppLastIdent(cur.Text())
	}
	return ""
}

// cppCallBaseName returns the method basename a `call_expression`
// resolves to: for `foo()` → "foo", for `ns::foo()` → "foo", for
// `obj.method()` → "method". Mirrors the basenames the resolver / walker
// key call sites by.
func cppCallBaseName(call *tsast.Node) string {
	name := cppCallName(call)
	if name == "" {
		return ""
	}
	if i := strings.LastIndex(name, "::"); i >= 0 {
		return strings.TrimSpace(name[i+2:])
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		return strings.TrimSpace(name[i+1:])
	}
	return name
}

// cppCallArgs returns positional argument text from a `call_expression`'s
// `arguments` (`argument_list`) child.
func cppCallArgs(call *tsast.Node) []string {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		for _, c := range call.NamedChildren() {
			if c.Type() == "argument_list" {
				args = c
				break
			}
		}
	}
	if args == nil {
		return nil
	}
	var out []string
	for _, a := range args.NamedChildren() {
		out = append(out, strings.TrimSpace(a.Text()))
	}
	return out
}

// cppLastIdent returns the last identifier token in s.
func cppLastIdent(s string) string {
	s = strings.TrimSpace(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// findCPPCallSites parses callerContent and returns every call to a
// function whose simple basename equals extractBaseName(calleeName),
// within the caller node's line range.
func findCPPCallSites(callerContent string, callerNode *FuncNode, calleeName string) []cppCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildCPPCallIndex(callerContent, callerNode.Language)
	return idx.lookup(callerNode, baseName)
}

// findCPPCallSitesIndexed is the cache-aware variant of findCPPCallSites.
func findCPPCallSitesIndexed(cache *cppCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []cppCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findCPPCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent, callerNode.Language)
	return idx.lookup(callerNode, baseName)
}
