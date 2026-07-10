// File-level PHP call-site index (PR-Gphp).
//
// Mirrors crossfile_walk_ruby_index.go. findPHPCallSites parses the
// caller's file content with tree-sitter every time it's invoked;
// WalkCrossFileTaintFlows calls it inside an O(callers × callees) loop —
// on a real Laravel / Symfony monorepo that's thousands of full-file
// parses against the same content, dominating wall-clock.
//
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every PHP call node
// (function_call_expression / scoped_call_expression /
// member_call_expression) by its method basename. Subsequent lookups
// become an O(matching entries) filter on a pre-built slice — no
// tree-sitter, no recursive walk.
//
// As with the Ruby / Lua variants, the cache is intentionally
// pass-scoped: callers create a fresh phpCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// phpCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`$x = foo(...)` form).
type phpCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// phpCallIndex is a pre-walked map of basename → call sites found in a
// single file's content. Lookups apply the caller range filter on the
// fly, mirroring the line constraint findPHPCallSites enforces.
type phpCallIndex struct {
	byBaseName map[string][]phpCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine]. Returns
// nil when nothing matches or when the index wasn't built.
func (idx *phpCallIndex) lookup(callerNode *FuncNode, baseName string) []phpCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]phpCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// phpCallIndexCache memoizes per-file-content phpCallIndex instances.
// Keyed by content identity; loaders cache content per pass so the same
// file maps to the same backing string.
type phpCallIndexCache struct {
	byContent map[string]*phpCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newPHPCallIndexCache returns an empty cache.
func newPHPCallIndexCache() *phpCallIndexCache {
	return &phpCallIndexCache{
		byContent: make(map[string]*phpCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *phpCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for the given content, building it on first
// access. Returns a non-nil index even on parse failure so we don't
// retry failed parses on every caller in the file.
func (c *phpCallIndexCache) get(content string) *phpCallIndex {
	if c == nil {
		return buildPHPCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildPHPCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildPHPCallIndex parses content once and walks the tree once,
// recording every PHP call node grouped by its method basename.
// Assignment-style call sites (`$x = foo(...)`) populate the assignedTo
// field exactly as findPHPCallSites does.
//
// PHP call shapes handled:
//   - function_call_expression  : `foo(...)`         → basename "foo"
//   - scoped_call_expression    : `Cls::bar(...)`    → basename "bar"
//   - member_call_expression    : `$obj->baz(...)`   → basename "baz"
//
// The basename is matched against extractBaseName(calleeName) — the
// builder records callee names like `Cls::find` / `find`, whose
// extractBaseName strips the `Cls::` / receiver prefix and any `.`
// suffix to the bare method name.
func buildPHPCallIndex(content string) *phpCallIndex {
	idx := &phpCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangPHP)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]phpCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "assignment_expression":
			// `$x = foo(...)` — record the LHS so a direct call on the
			// RHS gets assignedTo set.
			lhs := n.ChildByFieldName("left")
			rhs := n.ChildByFieldName("right")
			if lhs != nil && rhs != nil && phpIsCallNode(rhs) {
				name := phpAssignLHSName(lhs)
				base := phpCallBaseName(rhs)
				if base != "" {
					cs := phpCallSite{line: int(rhs.StartRow()) + 1, assignedTo: name}
					cs.args = phpCallArgs(rhs)
					idx.byBaseName[base] = append(idx.byBaseName[base], cs)
				}
				// Recurse into the RHS's argument calls (and any other
				// children) without re-indexing the RHS call itself.
				for _, c := range rhs.NamedChildren() {
					visit(c, "")
				}
				// Recurse the LHS too (defensive; usually a variable).
				visit(lhs, "")
				return
			}
		case "function_call_expression", "scoped_call_expression",
			"member_call_expression":
			base := phpCallBaseName(n)
			if base != "" {
				cs := phpCallSite{line: int(n.StartRow()) + 1, assignedTo: assignTarget}
				cs.args = phpCallArgs(n)
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in arguments
			// (`$db->query($repo->get($n))`) are indexed under their own
			// basename.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// phpIsCallNode reports whether n is one of the three PHP call-expression
// node types the walker indexes.
func phpIsCallNode(n *tsast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "function_call_expression", "scoped_call_expression",
		"member_call_expression":
		return true
	}
	return false
}

// phpAssignLHSName returns the bare variable name a PHP assignment LHS
// binds to. `$x` → "x", `$this->foo` → "foo". The leading `$` is
// stripped so it matches the token form used downstream.
func phpAssignLHSName(lhs *tsast.Node) string {
	text := strings.TrimSpace(lhs.Text())
	// `$this->prop` / `$obj->prop` → trailing member name.
	if i := strings.LastIndex(text, "->"); i >= 0 {
		text = text[i+2:]
	}
	text = strings.TrimPrefix(text, "$")
	return strings.TrimSpace(text)
}

// phpCallBaseName returns the method basename a PHP call node resolves
// to. For `foo()` → "foo"; for `Cls::bar()` → "bar"; for `$obj->baz()`
// → "baz". Returns "" when the call has no name field (variable calls
// like `$f()` are skipped — the builder skips them too).
func phpCallBaseName(call *tsast.Node) string {
	switch call.Type() {
	case "function_call_expression":
		fn := call.ChildByFieldName("function")
		if fn == nil {
			return ""
		}
		switch fn.Type() {
		case "name":
			return strings.TrimSpace(fn.Text())
		case "qualified_name":
			full := strings.TrimPrefix(strings.TrimSpace(fn.Text()), `\`)
			if i := strings.LastIndex(full, `\`); i >= 0 {
				return full[i+1:]
			}
			return full
		}
		return ""
	case "scoped_call_expression", "member_call_expression":
		name := call.ChildByFieldName("name")
		if name == nil {
			return ""
		}
		return strings.TrimSpace(name.Text())
	}
	return ""
}

// phpCallArgs returns positional argument text from a PHP call node's
// `arguments` child. Each `argument` wrapper's inner expression text is
// returned; named args and spreads are returned as their raw text. The
// walker treats every argument as positional — coarse but sufficient for
// the cross-file arg-taint check.
func phpCallArgs(call *tsast.Node) []string {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	var out []string
	for _, child := range args.NamedChildren() {
		// tree-sitter-php wraps each positional/named arg in an
		// `argument` node; the value is its (only) named child. Fall back
		// to the wrapper's own text when there's no inner named child.
		if child.Type() == "argument" {
			inner := child.NamedChildren()
			if len(inner) > 0 {
				out = append(out, strings.TrimSpace(inner[0].Text()))
				continue
			}
		}
		out = append(out, strings.TrimSpace(child.Text()))
	}
	return out
}

// findPHPCallSites parses callerContent and returns every call to a
// function whose simple basename equals phpBaseName(calleeName), within
// the caller node's line range. phpBaseName (not the shared
// extractBaseName) is used because PHP callee names are `Cls::method` /
// `App\Cls::method`, whose bare method name needs `::` and `\` stripping.
func findPHPCallSites(callerContent string, callerNode *FuncNode, calleeName string) []phpCallSite {
	baseName := phpBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildPHPCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findPHPCallSitesIndexed is the cache-aware variant of findPHPCallSites.
// When cache is nil the behaviour matches the uncached path: parse from
// scratch and walk.
func findPHPCallSitesIndexed(cache *phpCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []phpCallSite {
	baseName := phpBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findPHPCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
