// File-level Ruby call-site index (PR-Gruby).
//
// Mirrors crossfile_walk_python_index.go and crossfile_walk_javascript_index.go.
// findRubyCallSites parses the caller's file content with tree-sitter
// every time it's invoked. WalkCrossFileTaintFlows calls it inside an
// O(callers × callees) loop — on a real Rails monorepo that's thousands
// of full-file parses against the same content, dominating wall-clock.
//
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every `call` node by its method basename.
// Subsequent lookups become an O(matching entries) filter on a
// pre-built slice — no tree-sitter, no recursive walk.
//
// As with the Python / JS variants, the cache is intentionally
// pass-scoped: callers create a fresh `rubyCallIndexCache` for each
// pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// rubyCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`x = foo(...)` form).
type rubyCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// rubyCallIndex is a pre-walked map of basename → call sites found in a
// single file's content. Lookups apply the caller range filter on the
// fly, mirroring the line constraint findRubyCallSites enforces.
type rubyCallIndex struct {
	byBaseName map[string][]rubyCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine]. Returns
// nil when nothing matches or when the index wasn't built.
func (idx *rubyCallIndex) lookup(callerNode *FuncNode, baseName string) []rubyCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]rubyCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// rubyCallIndexCache memoizes per-file-content rubyCallIndex instances.
// Keyed by content identity; loaders cache content per pass so the same
// file maps to the same backing string.
type rubyCallIndexCache struct {
	byContent map[string]*rubyCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newRubyCallIndexCache returns an empty cache.
func newRubyCallIndexCache() *rubyCallIndexCache {
	return &rubyCallIndexCache{
		byContent: make(map[string]*rubyCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *rubyCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for the given content, building it on first
// access. Returns a non-nil index even on parse failure so we don't
// retry failed parses on every caller in the file.
func (c *rubyCallIndexCache) get(content string) *rubyCallIndex {
	if c == nil {
		return buildRubyCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildRubyCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildRubyCallIndex parses content once and walks the tree once,
// recording every `call` node grouped by its method basename.
// Assignment-style call sites (`x = foo(...)`) populate the assignedTo
// field exactly as findRubyCallSites does.
func buildRubyCallIndex(content string) *rubyCallIndex {
	idx := &rubyCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangRuby)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]rubyCallSite)

	var visit func(n *tsast.Node, parentAssignTarget string)
	visit = func(n *tsast.Node, parentAssignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "call":
			baseName := rubyCallBaseName(n)
			if baseName != "" {
				cs := rubyCallSite{
					line:       int(n.StartRow()) + 1,
					assignedTo: parentAssignTarget,
				}
				if argList := n.ChildByFieldName("arguments"); argList != nil {
					cs.args = extractRubyCallArgs(argList)
				}
				idx.byBaseName[baseName] = append(idx.byBaseName[baseName], cs)
			}
		case "assignment":
			lhs := n.ChildByFieldName("left")
			rhs := n.ChildByFieldName("right")
			if lhs != nil && rhs != nil && lhs.Type() == "identifier" {
				name := strings.TrimSpace(lhs.Text())
				visit(rhs, name)
				return
			}
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// rubyCallBaseName returns the method name a tree-sitter `call` node
// resolves to. Mirrors the cases matchesRubyCallName recognises: bare
// identifiers and trailing segments of dotted / scope-resolved
// receivers. Returns "" when the call has no `method` field
// (defensive).
func rubyCallBaseName(call *tsast.Node) string {
	m := call.ChildByFieldName("method")
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m.Text())
}

// findRubyCallSitesIndexed is the cache-aware variant of
// findRubyCallSites. When cache is nil the behaviour matches the
// uncached path: parse from scratch and walk.
func findRubyCallSitesIndexed(cache *rubyCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []rubyCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findRubyCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
