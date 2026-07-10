// File-level C# call-site index.
//
// Mirrors crossfile_walk_javascript_index.go. findCSharpCallSites parses
// the caller's file content with tree-sitter every time it's invoked;
// WalkCrossFileTaintFlows calls it inside an O(callers × callees) loop. On
// a real ASP.NET solution that's thousands of full-file parses against the
// same content. This file adds a per-pass cache that parses each file
// once, walks the tree once, and indexes every invocation_expression /
// object_creation_expression node by its called-function basename.
//
// The cache is intentionally pass-scoped: callers create a fresh
// csharpCallIndexCache for each pass.

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// csharpCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`var x = Foo(...)` /
// `string x = Foo(...)` / `x = Foo(...)` form).
type csharpCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// csharpCallIndex is a pre-walked map of basename → call sites found in a
// single file's content.
type csharpCallIndex struct {
	byBaseName map[string][]csharpCallSite
}

// lookup returns the cached call sites whose basename matches and whose
// line falls inside [callerNode.StartLine, callerNode.EndLine].
func (idx *csharpCallIndex) lookup(callerNode *FuncNode, baseName string) []csharpCallSite {
	if idx == nil || idx.byBaseName == nil || baseName == "" {
		return nil
	}
	all := idx.byBaseName[baseName]
	if len(all) == 0 {
		return nil
	}
	out := make([]csharpCallSite, 0, len(all))
	for _, cs := range all {
		if cs.line < callerNode.StartLine || cs.line > callerNode.EndLine {
			continue
		}
		out = append(out, cs)
	}
	return out
}

// csharpCallIndexCache memoizes per-file-content csharpCallIndex instances.
type csharpCallIndexCache struct {
	byContent map[string]*csharpCallIndex
	// san memoizes per-file catalog sanitizer AssignmentFacts for the
	// caller-side sanitizer gate (crossfile_sanitizer_gate.go).
	san *sanitizerFactsMemo
}

// newCSharpCallIndexCache returns an empty cache.
func newCSharpCallIndexCache() *csharpCallIndexCache {
	return &csharpCallIndexCache{
		byContent: make(map[string]*csharpCallIndex),
		san:       newSanitizerFactsMemo(),
	}
}

// sanitizerMemo returns the pass-scoped sanitizer-facts memo; nil-safe.
func (c *csharpCallIndexCache) sanitizerMemo() *sanitizerFactsMemo {
	if c == nil {
		return nil
	}
	return c.san
}

// get returns the index for content, building it on first access. Returns
// a non-nil index even on parse failure so we don't retry failed parses on
// every caller in the file.
func (c *csharpCallIndexCache) get(content string) *csharpCallIndex {
	if c == nil {
		return buildCSharpCallIndex(content)
	}
	if idx, ok := c.byContent[content]; ok {
		return idx
	}
	idx := buildCSharpCallIndex(content)
	c.byContent[content] = idx
	return idx
}

// buildCSharpCallIndex parses content once, walks the tree once, and
// records every invocation_expression / object_creation_expression node
// grouped by its called-function basename. Assignment-style call sites
// populate assignedTo, captured from the enclosing variable_declarator (a
// `var x = Foo()` / `string x = Foo()` local declaration) or an
// assignment_expression LHS (`x = Foo()`).
func buildCSharpCallIndex(content string) *csharpCallIndex {
	idx := &csharpCallIndex{}
	if content == "" {
		return idx
	}
	tree := tsast.Parse([]byte(content), rules.LangCSharp)
	if tree == nil || tree.Root() == nil {
		return idx
	}
	idx.byBaseName = make(map[string][]csharpCallSite)

	var visit func(n *tsast.Node, assignTarget string)
	visit = func(n *tsast.Node, assignTarget string) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "variable_declarator":
			// `var x = Foo(...)` / `string x = Foo(...)`. The declarator's
			// `name` field is the bound variable; the initializer is an
			// unnamed child after `=` (the C# grammar does not field it
			// `value`). Propagate the assigned name into the declarator's
			// subtree so the call gets assignedTo set.
			name := nodeFieldText(n, "name")
			if name != "" {
				for _, c := range n.NamedChildren() {
					visit(c, strings.TrimSpace(name))
				}
				return
			}
		case "assignment_expression":
			lhs := n.ChildByFieldName("left")
			rhs := n.ChildByFieldName("right")
			if lhs != nil && rhs != nil && lhs.Type() == "identifier" {
				visit(rhs, strings.TrimSpace(lhs.Text()))
				return
			}
		case "invocation_expression", "object_creation_expression":
			base := csCallBaseName(n)
			if base != "" {
				cs := csharpCallSite{
					line:       int(n.StartRow()) + 1,
					assignedTo: assignTarget,
				}
				if argList := n.ChildByFieldName("arguments"); argList != nil {
					cs.args = extractCSharpCallArgs(argList)
				}
				idx.byBaseName[base] = append(idx.byBaseName[base], cs)
			}
			// Fall through to recurse so calls nested in arguments
			// (`Process.Start(Helper.GetName(req))`) are indexed too.
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return idx
}

// csCallBaseName returns the simple method/constructor name a tree-sitter
// invocation_expression / object_creation_expression resolves to:
// `Foo(...)` → "Foo", `Recv.Bar(...)` → "Bar", `new Foo(...)` → "Foo".
// Mirrors the basename the resolver / walker key call sites by
// (extractBaseName of the callee node name).
func csCallBaseName(call *tsast.Node) string {
	if call.Type() == "object_creation_expression" {
		typ := call.ChildByFieldName("type")
		if typ == nil {
			return ""
		}
		text := strings.TrimSpace(typ.Text())
		if i := strings.IndexByte(text, '<'); i >= 0 {
			text = text[:i]
		}
		if dot := strings.LastIndexByte(text, '.'); dot >= 0 {
			text = text[dot+1:]
		}
		return strings.TrimSpace(text)
	}
	name := csCallText(call)
	if name == "" {
		return ""
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// extractCSharpCallArgs returns positional argument text from a
// tree-sitter `argument_list` node. Each named child is an `argument`
// wrapping the actual expression; we return the argument's text.
func extractCSharpCallArgs(argList *tsast.Node) []string {
	var args []string
	for _, child := range argList.NamedChildren() {
		if child.Type() != "argument" {
			continue
		}
		args = append(args, strings.TrimSpace(child.Text()))
	}
	return args
}

// findCSharpCallSites parses callerContent and returns every call to a
// function whose simple basename equals extractBaseName(calleeName),
// within the caller node's line range.
func findCSharpCallSites(callerContent string, callerNode *FuncNode, calleeName string) []csharpCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	idx := buildCSharpCallIndex(callerContent)
	return idx.lookup(callerNode, baseName)
}

// findCSharpCallSitesIndexed is the cache-aware variant of
// findCSharpCallSites. When cache is nil the behaviour matches the
// uncached path: parse from scratch and walk.
func findCSharpCallSitesIndexed(cache *csharpCallIndexCache, callerContent string, callerNode *FuncNode, calleeName string) []csharpCallSite {
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}
	if cache == nil {
		return findCSharpCallSites(callerContent, callerNode, calleeName)
	}
	idx := cache.get(callerContent)
	return idx.lookup(callerNode, baseName)
}
