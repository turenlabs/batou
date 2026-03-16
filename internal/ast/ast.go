// Package ast provides tree-sitter based AST parsing for multi-language
// security analysis.  It exposes a thin abstraction over tree-sitter so
// that the rest of the codebase (rules, scanner) never imports tree-sitter
// directly.
//
// All operations are best-effort: if parsing fails the caller receives a
// nil *Tree and must fall back to regex-only analysis.
package ast

// Tree wraps a parsed tree-sitter AST for a single file.  It is the only
// type exposed to rule authors and the scanner pipeline.
type Tree struct {
	root     *Node
	content  []byte
	language string // rules.Language value used to parse

	// Cached analysis results, computed lazily on first access.
	lineOffsets   []int          // byte offset of each line start
	commentRanges []commentRange // sorted, non-overlapping comment byte ranges
}

// Root returns the root node of the AST, or nil if the tree is empty.
func (t *Tree) Root() *Node {
	if t == nil {
		return nil
	}
	return t.root
}

// Content returns the original source bytes used to parse the tree.
func (t *Tree) Content() []byte {
	if t == nil {
		return nil
	}
	return t.content
}

// Language returns the language string that was used to parse this tree.
func (t *Tree) Language() string {
	if t == nil {
		return ""
	}
	return t.language
}

// Node wraps a single tree-sitter node with convenience methods.
// It intentionally hides the underlying C pointer type so that callers
// never need to import tree-sitter.
type Node struct {
	nodeType   string
	startByte  uint32
	endByte    uint32
	startRow   uint32
	startCol   uint32
	endRow     uint32
	endCol     uint32
	children   []*Node
	parent     *Node
	isNamed    bool
	content    []byte // reference to source bytes
	fieldName  string // field name in parent, if any
}

// Type returns the grammar node type (e.g. "comment", "string",
// "function_definition").
func (n *Node) Type() string {
	if n == nil {
		return ""
	}
	return n.nodeType
}

// StartByte returns the byte offset where this node starts.
func (n *Node) StartByte() uint32 {
	if n == nil {
		return 0
	}
	return n.startByte
}

// EndByte returns the byte offset where this node ends.
func (n *Node) EndByte() uint32 {
	if n == nil {
		return 0
	}
	return n.endByte
}

// StartRow returns the 0-based line number where this node starts.
func (n *Node) StartRow() uint32 {
	if n == nil {
		return 0
	}
	return n.startRow
}

// StartCol returns the 0-based column where this node starts.
func (n *Node) StartCol() uint32 {
	if n == nil {
		return 0
	}
	return n.startCol
}

// EndRow returns the 0-based line number where this node ends.
func (n *Node) EndRow() uint32 {
	if n == nil {
		return 0
	}
	return n.endRow
}

// EndCol returns the 0-based column where this node ends.
func (n *Node) EndCol() uint32 {
	if n == nil {
		return 0
	}
	return n.endCol
}

// IsNamed returns true if this is a named node in the grammar (not anonymous
// punctuation/keywords).
func (n *Node) IsNamed() bool {
	if n == nil {
		return false
	}
	return n.isNamed
}

// Text returns the source text covered by this node.
func (n *Node) Text() string {
	if n == nil || n.content == nil {
		return ""
	}
	s := n.startByte
	e := n.endByte
	if s > e || int(e) > len(n.content) {
		return ""
	}
	return string(n.content[s:e])
}

// Parent returns this node's parent, or nil for the root.
func (n *Node) Parent() *Node {
	if n == nil {
		return nil
	}
	return n.parent
}

// ChildCount returns the number of children.
func (n *Node) ChildCount() int {
	if n == nil {
		return 0
	}
	return len(n.children)
}

// Child returns the i-th child, or nil if out of range.
func (n *Node) Child(i int) *Node {
	if n == nil || i < 0 || i >= len(n.children) {
		return nil
	}
	return n.children[i]
}

// NamedChildren returns only named child nodes (filtering out anonymous
// punctuation/keyword nodes).
func (n *Node) NamedChildren() []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, c := range n.children {
		if c.isNamed {
			out = append(out, c)
		}
	}
	return out
}

// FieldName returns the field name this node occupies in its parent, or "".
func (n *Node) FieldName() string {
	if n == nil {
		return ""
	}
	return n.fieldName
}

// ChildByFieldName returns the first child with the given field name, or nil.
func (n *Node) ChildByFieldName(name string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.children {
		if c.fieldName == name {
			return c
		}
	}
	return nil
}

// Walk calls fn for every node in the subtree rooted at n (pre-order DFS).
// If fn returns false, the walk does not descend into that node's children.
func (n *Node) Walk(fn func(*Node) bool) {
	if n == nil {
		return
	}
	if !fn(n) {
		return
	}
	for _, c := range n.children {
		c.Walk(fn)
	}
}

// ContainsOffset returns true if byteOffset falls within [StartByte, EndByte).
func (n *Node) ContainsOffset(byteOffset uint32) bool {
	if n == nil {
		return false
	}
	return byteOffset >= n.startByte && byteOffset < n.endByte
}

// Ancestors returns the chain of parent nodes from this node up to the root
// (not including this node itself).
func (n *Node) Ancestors() []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	cur := n.parent
	for cur != nil {
		out = append(out, cur)
		cur = cur.parent
	}
	return out
}

// --- Cached analysis helpers on Tree ---

// commentRange represents a byte range [start, end) that is a comment.
type commentRange struct {
	start uint32
	end   uint32
}

// LineOffsets returns a cached slice where lineOffsets[i] is the byte offset
// of the start of the (i+1)-th line (0-indexed internally). Computed lazily
// on first call.
func (t *Tree) LineOffsets() []int {
	if t == nil {
		return nil
	}
	if t.lineOffsets == nil {
		t.lineOffsets = buildLineOffsets(t.content)
	}
	return t.lineOffsets
}

// buildLineOffsets returns a slice where result[i] is the byte offset of
// the start of line i+1 (0-indexed).
func buildLineOffsets(content []byte) []int {
	offsets := []int{0}
	for i, b := range content {
		if b == '\n' && i+1 < len(content) {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// CommentRanges returns a cached sorted slice of comment byte ranges.
// Built by walking the AST once on first call.
func (t *Tree) CommentRanges() []commentRange {
	if t == nil {
		return nil
	}
	if t.commentRanges == nil {
		t.commentRanges = buildCommentRanges(t.root)
	}
	return t.commentRanges
}

// buildCommentRanges walks the AST and collects all comment node byte ranges.
func buildCommentRanges(root *Node) []commentRange {
	if root == nil {
		return nil
	}
	var ranges []commentRange
	root.Walk(func(n *Node) bool {
		if commentTypes[n.nodeType] {
			ranges = append(ranges, commentRange{start: n.startByte, end: n.endByte})
			return false // don't descend into comment children
		}
		return true
	})
	return ranges
}

// IsOffsetInComment uses binary search over cached comment ranges to check
// if a byte offset falls within a comment. Much faster than NodeAtOffset +
// parent walk when called repeatedly.
func (t *Tree) IsOffsetInComment(offset uint32) bool {
	ranges := t.CommentRanges()
	// Binary search: find the last range where start <= offset.
	lo, hi := 0, len(ranges)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if ranges[mid].start <= offset {
			if offset < ranges[mid].end {
				return true
			}
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return false
}
