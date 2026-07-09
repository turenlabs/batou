// File-level Python call-site index.
//
// findPythonCallSites parses the caller's file content with tree-sitter
// every time it's invoked. PropagateSignaturesAcrossCallgraph and
// WalkCrossFileTaintFlows both call it inside an O(callers × callees)
// loop — and PropagateSignaturesAcrossCallgraph runs up to 12 iterations.
// On Django (2955 Python files, 5598 in-project edges) that's tens of
// thousands of full-file tree-sitter parses against the same content,
// dominating wall-clock time.
//
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every `call` node by its called-function
// basename. Subsequent lookups become an O(matching entries) filter on a
// pre-built slice — no tree-sitter, no recursive walk.
//
// The cache is intentionally pass-scoped: callers create a fresh
// `pythonCallIndexCache` for each PropagateSignaturesAcrossCallgraph /
// WalkCrossFileTaintFlows invocation. We don't memoize globally because
// scanner content can change between scans and the cache key is the
// caller's file path (which the loaders already disambiguate per-pass).

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// pythonCallIndex is a pre-walked map of basename → call sites found in
// a single file's content. Lookups apply the caller range filter on the
// fly, mirroring the line constraint findPythonCallSites enforces.
type pythonCallIndex struct {
	byBaseName map[string][]pythonCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine]. Returns
// nil when nothing matches or when the index wasn't built (parse failure).
func (idx *pythonCallIndex) lookup(callerNode *FuncNode, baseName string) []pythonCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]pythonCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// pythonCallIndexCache memoizes per-file-content pythonCallIndex
// instances. Keyed by content identity (we store the *string* the loader
// returned; loaders cache content per pass so the same file maps to the
// same backing string). A separate field tracks parse failures so we
// don't retry them inside one pass.
type pythonCallIndexCache struct {
	byContent map[string]*pythonCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go), sharing
	// this cache's pass-scoped lifetime.
	san *sanitizerFactsMemo
}

// newPythonCallIndexCache returns an empty cache.
func newPythonCallIndexCache() *pythonCallIndexCache {
	return &pythonCallIndexCache{
		byContent: make(map[string]*pythonCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe so
// uncached (nil-cache) callers fall back to per-gate computation.
func (c *pythonCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for the given content, building it on first
// access. Returns a non-nil index even on parse failure (the byBaseName
// map will be nil; lookup() handles that gracefully) so we don't retry
// failed parses on every caller in the file.
func (c *pythonCallIndexCache) get(content string) *pythonCallIndex {
	if c == nil {
		// Fallback: build on the fly without caching. Preserves correctness
		// when callers pass nil (e.g. unit tests of the underlying helpers).
		return buildPythonCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildPythonCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildPythonCallIndex parses content once and walks the tree once,
// recording every `call` node grouped by its function basename.
// Assignment-style call sites (`x = foo(...)`) populate the assignedTo
// field exactly as findPythonCallSites does.
func buildPythonCallIndex(content string) *pythonCallIndex {
	idx := &pythonCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangPython)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]pythonCallSite)

	var visit func(n *tsast.Node, parentAssignTarget string)
	visit = func(n *tsast.Node, parentAssignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "call":
			baseName := callBaseName(n)
			if baseName != "" {
				cs := pythonCallSite{
					line:       int(n.StartRow()) + 1,
					assignedTo: parentAssignTarget,
				}
				if argList := n.ChildByFieldName("arguments"); argList != nil {
					cs.args, cs.keywordArg = extractPythonCallArgs(argList)
				}
				idx.byBaseName[baseName] = append(idx.byBaseName[baseName], cs)
			}
		case "assignment":
			// Detect `x = callee(...)` — propagate the assigned name down
			// into the RHS visit so the call's assignedTo is recorded.
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

// callBaseName returns the simple-name a tree-sitter `call` node's
// function reference resolves to. Mirrors the cases matchesPythonCallName
// recognises: bare identifiers, single-level attribute, and the trailing
// segment of a chained attribute. Returns "" when the call uses a shape
// the cross-file walker doesn't model (e.g. subscript indexing).
func callBaseName(call *tsast.Node) string {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text())
	case "attribute":
		attr := fn.ChildByFieldName("attribute")
		if attr != nil {
			return strings.TrimSpace(attr.Text())
		}
	}
	return ""
}

// findPythonCallSitesIndexed is the cache-aware variant of
// findPythonCallSites. When cache is nil the behaviour matches the
// original: parse from scratch and walk. When cache is non-nil the
// content is parsed once and the resulting basename index is reused
// across every (caller, callee) pair the pass examines.
func findPythonCallSitesIndexed(cache *pythonCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []pythonCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findPythonCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
