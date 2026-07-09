// File-level JavaScript / TypeScript call-site index (PR-Gjs).
//
// Mirrors crossfile_walk_python_index.go. findJavaScriptCallSites parses
// the caller's file content with tree-sitter every time it's invoked.
// PropagateSignaturesAcrossCallgraph and WalkCrossFileTaintFlows both
// call it inside an O(callers × callees) loop — on a real Node monorepo
// that's thousands of full-file parses against the same content,
// dominating wall-clock time.
//
// This file adds a per-pass cache that parses each file once, walks the
// tree once, and indexes every call_expression / new_expression node by
// its called-function basename. Subsequent lookups become an
// O(matching entries) filter on a pre-built slice — no tree-sitter, no
// recursive walk.
//
// Like the Python index, the cache is intentionally pass-scoped:
// callers create a fresh `javascriptCallIndexCache` for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// javascriptCallSite captures a single call expression discovered
// inside a caller's body. line is 1-based file-absolute; args lists
// positional argument expressions in order; assignedTo, when non-empty,
// is the variable receiving the call's return value
// (`const x = foo(...)` / `x = foo(...)` form). Alias of the shared
// crossfileCallSite (crossfile_walk_core.go) so the shared walk core
// consumes the index's lookups without conversion.
type javascriptCallSite = crossfileCallSite

// javascriptCallIndex is a pre-walked map of basename → call sites
// found in a single file's content. Lookups apply the caller range
// filter on the fly, mirroring the line constraint
// findJavaScriptCallSites enforces.
type javascriptCallIndex struct {
	byBaseName map[string][]javascriptCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine]. Returns
// nil when nothing matches or when the index wasn't built.
func (idx *javascriptCallIndex) lookup(callerNode *FuncNode, baseName string) []javascriptCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]javascriptCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// javascriptCallIndexCache memoizes per-file-content javascriptCallIndex
// instances. Keyed by content identity; loaders cache content per pass
// so the same file maps to the same backing string.
type javascriptCallIndexCache struct {
	byContent map[string]*javascriptCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newJavaScriptCallIndexCache returns an empty cache.
func newJavaScriptCallIndexCache() *javascriptCallIndexCache {
	return &javascriptCallIndexCache{
		byContent: make(map[string]*javascriptCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *javascriptCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for the given content, building it on first
// access. Returns a non-nil index even on parse failure so we don't
// retry failed parses on every caller in the file. filePath routes .tsx
// content through the JSX-aware grammar (see ast.ParseFile).
func (c *javascriptCallIndexCache) get(content string, lang rules.Language, filePath string) *javascriptCallIndex {
	if c == nil {
		return buildJavaScriptCallIndex(content, lang, filePath)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildJavaScriptCallIndex(content, lang, filePath)
	c.byContent[content] = idx
	return idx
}

// buildJavaScriptCallIndex parses content once and walks the tree
// once, recording every call_expression / new_expression node grouped
// by its function basename. Assignment-style call sites
// (`const x = foo(...)` / `x = foo(...)`) populate the assignedTo
// field exactly as findJavaScriptCallSites does.
func buildJavaScriptCallIndex(content string, lang rules.Language, filePath string) *javascriptCallIndex {
	idx := &javascriptCallIndex{}
	if content == "" {
		return idx
	}
	if lang != rules.LangJavaScript && lang != rules.LangTypeScript {
		lang = rules.LangJavaScript
	}
	tree := tsast.ParseFile([]byte(content), lang, filePath)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]javascriptCallSite)

	var visit func(n *tsast.Node, parentAssignTarget string)
	visit = func(n *tsast.Node, parentAssignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "call_expression", "new_expression":
			baseName := jsCallBaseName(n)
			if baseName != "" {
				cs := javascriptCallSite{
					line:       int(n.StartRow()) + 1,
					assignedTo: parentAssignTarget,
				}
				if argList := n.ChildByFieldName("arguments"); argList != nil {
					cs.args = extractJavaScriptCallArgs(argList)
				}
				idx.byBaseName[baseName] = append(idx.byBaseName[baseName], cs)
			}
		case "variable_declarator":
			name := nodeFieldText(n, "name")
			val := n.ChildByFieldName("value")
			if name != "" && val != nil {
				visit(val, strings.TrimSpace(name))
				return
			}
		case "assignment_expression":
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

// jsCallBaseName returns the simple-name a tree-sitter
// call_expression / new_expression node's function reference resolves
// to. Mirrors the cases matchesJavaScriptCallName recognises: bare
// identifiers and the trailing segment of a single-level member
// expression. Returns "" for shapes the cross-file walker doesn't
// model (chained member calls, subscript, etc.).
func jsCallBaseName(call *tsast.Node) string {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		fn = call.ChildByFieldName("constructor")
	}
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text())
	case "member_expression":
		prop := fn.ChildByFieldName("property")
		if prop != nil {
			return strings.TrimSpace(prop.Text())
		}
	}
	return ""
}

// findJavaScriptCallSitesIndexed is the cache-aware variant of
// findJavaScriptCallSites. When cache is nil the behaviour matches the
// uncached path: parse from scratch and walk.
func findJavaScriptCallSitesIndexed(cache *javascriptCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string, lang rules.Language) []javascriptCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findJavaScriptCallSites(callerContent, callerNode, calleeName, lang)
	}
	idx := cache.get(callerContent, lang, callerNode.FilePath)
	return idx.lookup(callerNode, baseName)
}
