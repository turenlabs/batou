// File-level Shell call-site index (PR-Gshell).
//
// Mirrors crossfile_walk_swift_index.go. findShellCallSites parses the
// caller's file content with tree-sitter every time it's invoked;
// WalkCrossFileTaintFlows calls it inside an O(callers × callees) loop.
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every function-call `command` node by its
// command-word basename.
//
// THE SHELL WRINKLE: function calls and built-in/external commands are the
// same `command` node type. The index records EVERY command-word; lookups
// for a specific callee basename naturally pick out only the matching
// calls.
//
// Assignment capture: `n=$(get_name)` parses as a `variable_assignment`
// (name field `n`) whose `value` is a `command_substitution` wrapping the
// `command` node. We thread the assignment target down so the call site
// for `get_name` records assignedTo="n" — the Path-B (tainted-return)
// linkage.
//
// The cache is intentionally pass-scoped: callers create a fresh
// shellCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// shellCallSite captures a single command/call discovered inside a caller's
// body. line is 1-based file-absolute; args lists positional argument
// expressions in order; assignedTo, when non-empty, is the variable
// receiving the call's return value (`n=$(get_name)`).
type shellCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// shellCallIndex is a pre-walked map of command-word basename → call sites
// found in a single file's content.
type shellCallIndex struct {
	byBaseName map[string][]shellCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *shellCallIndex) lookup(callerNode *FuncNode, baseName string) []shellCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]shellCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// shellCallIndexCache memoizes per-file-content shellCallIndex instances.
type shellCallIndexCache struct {
	byContent map[string]*shellCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newShellCallIndexCache returns an empty cache.
func newShellCallIndexCache() *shellCallIndexCache {
	return &shellCallIndexCache{
		byContent: make(map[string]*shellCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *shellCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access.
func (c *shellCallIndexCache) get(content string) *shellCallIndex {
	if c == nil {
		return buildShellCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildShellCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildShellCallIndex parses content once, walks the tree once, and records
// every `command` node grouped by its command-word basename. Assignment-
// style call sites (`n=$(get_name)`) populate assignedTo from the enclosing
// `variable_assignment`.
func buildShellCallIndex(content string) *shellCallIndex {
	idx := &shellCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangShell)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]shellCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "variable_assignment":
			// Record the LHS so a call on the RHS (`n=$(get_name)`) gets
			// assignedTo set. The value field is a command_substitution;
			// descend into it carrying the target.
			lhs, valNode := shellAssignTarget(n)
			if valNode != nil {
				visit(valNode, lhs)
				for _, c := range n.NamedChildren() {
					if c != valNode {
						visit(c, "")
					}
				}
				return
			}
		case "command_substitution":
			// A `$(...)` wrapper threads the enclosing assignment target down
			// to its direct command child (`n=$(get_name)` → the `get_name`
			// command's assignedTo is "n"). Only the FIRST/direct command
			// carries the target; deeper nesting resets to "".
			passed := false
			for _, c := range n.NamedChildren() {
				if c.Type() == "command" && !passed {
					visit(c, assignTarget)
					passed = true
					continue
				}
				visit(c, "")
			}
			return
		case "command":
			base := shellCallBaseName(n)
			if base != "" {
				cs := shellCallSite{line: int(n.StartRow()) + 1, assignedTo: assignTarget}
				cs.args = shellCallArgs(n)
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in argument command
			// substitutions are indexed under their own basename too.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// shellAssignTarget returns (lhsName, valueNode) for a `variable_assignment`
// whose value is a command substitution (`n=$(get_name)`), or ("", nil)
// when the RHS isn't a substitution carrying a command.
func shellAssignTarget(n *tsast.Node) (string, *tsast.Node) {
	lhs := ""
	if nm := n.ChildByFieldName("name"); nm != nil {
		lhs = strings.TrimSpace(nm.Text())
	}
	val := n.ChildByFieldName("value")
	if val == nil {
		return "", nil
	}
	// Only thread assignTarget through value shapes that can wrap a command
	// (command_substitution: `$(...)` / `` `...` ``). For a plain string /
	// word value there is no nested call to attribute.
	switch val.Type() {
	case "command_substitution":
		return lhs, val
	}
	return "", nil
}

// shellCallBaseName returns the command-word a `command` node names
// (`get_name arg` → "get_name", `eval "$x"` → "eval"). Mirrors the basename
// the resolver / walker key call sites by.
func shellCallBaseName(call *tsast.Node) string {
	return shellCommandWord(call)
}

// shellCallArgs returns the positional argument text of a `command` node:
// every child carried under the "argument" field (word / string /
// concatenation / simple_expansion / ...).
func shellCallArgs(call *tsast.Node) []string {
	var out []string
	for i := 0; i < call.ChildCount(); i++ {
		c := call.Child(i)
		if c.FieldName() == "argument" {
			out = append(out, strings.TrimSpace(c.Text()))
		}
	}
	return out
}

// findShellCallSites parses callerContent and returns every call to a
// command whose basename equals extractBaseName(calleeName), within the
// caller node's line range.
func findShellCallSites(callerContent string, callerNode *FuncNode, calleeName string) []shellCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildShellCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findShellCallSitesIndexed is the cache-aware variant of
// findShellCallSites.
func findShellCallSitesIndexed(cache *shellCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []shellCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findShellCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
