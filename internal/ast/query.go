package ast

// FindByType returns all nodes in the subtree rooted at n whose Type()
// matches nodeType.  The search is depth-first pre-order.
func FindByType(n *Node, nodeType string) []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	n.Walk(func(child *Node) bool {
		if child.Type() == nodeType {
			out = append(out, child)
		}
		return true
	})
	return out
}

// FindByTypes returns all nodes whose Type() is in the provided set.
func FindByTypes(n *Node, types map[string]bool) []*Node {
	if n == nil || len(types) == 0 {
		return nil
	}
	var out []*Node
	n.Walk(func(child *Node) bool {
		if types[child.Type()] {
			out = append(out, child)
		}
		return true
	})
	return out
}

// NodeAtOffset returns the deepest (most specific) node that contains
// the given byte offset, or nil if none found.
func NodeAtOffset(root *Node, offset uint32) *Node {
	if root == nil || !root.ContainsOffset(offset) {
		return nil
	}
	best := root
	for _, c := range root.children {
		if c.ContainsOffset(offset) {
			if deeper := NodeAtOffset(c, offset); deeper != nil {
				best = deeper
			}
			break
		}
	}
	return best
}

// NodeAtLine returns the first named node that starts on the given
// 0-based line number, or nil if none found.
func NodeAtLine(root *Node, line uint32) *Node {
	if root == nil {
		return nil
	}
	var result *Node
	root.Walk(func(n *Node) bool {
		if result != nil {
			return false
		}
		if n.IsNamed() && n.StartRow() == line {
			result = n
			return false
		}
		// If this node ends before the target line, skip its children.
		if n.EndRow() < line {
			return false
		}
		return true
	})
	return result
}

// commentTypes is the set of tree-sitter node types that represent comments
// across all supported languages.
var commentTypes = map[string]bool{
	"comment":       true,
	"line_comment":  true,
	"block_comment": true,
	// HTML/XML
	"comment_content": true,
	// Python docstrings are expression_statement > string nodes,
	// handled separately in IsInDocstring.
}

// stringTypes is the set of tree-sitter node types that represent string
// literals across all supported languages.
var stringTypes = map[string]bool{
	"string":                 true,
	"string_literal":         true,
	"interpreted_string_literal": true,
	"raw_string_literal":     true,
	"template_string":        true,
	"string_content":         true,
	"string_fragment":        true,
	"heredoc_body":           true,
	"heredoc_content":        true,
	// Ruby
	"string_array": true,
	// Rust
	"char_literal": true,
}

// IsComment returns true if the given node is a comment node.
func IsComment(n *Node) bool {
	if n == nil {
		return false
	}
	return commentTypes[n.nodeType]
}

// IsString returns true if the given node is a string literal node.
func IsString(n *Node) bool {
	if n == nil {
		return false
	}
	return stringTypes[n.nodeType]
}

// IsInComment returns true if the byte offset falls inside a comment node.
func IsInComment(tree *Tree, offset uint32) bool {
	if tree == nil {
		return false
	}
	node := NodeAtOffset(tree.Root(), offset)
	if node == nil {
		return false
	}
	// Check the node itself and all ancestors.
	for cur := node; cur != nil; cur = cur.parent {
		if commentTypes[cur.nodeType] {
			return true
		}
	}
	return false
}

// IsInString returns true if the byte offset falls inside a string literal.
func IsInString(tree *Tree, offset uint32) bool {
	if tree == nil {
		return false
	}
	node := NodeAtOffset(tree.Root(), offset)
	if node == nil {
		return false
	}
	for cur := node; cur != nil; cur = cur.parent {
		if stringTypes[cur.nodeType] {
			return true
		}
	}
	return false
}

// IsNonCodeContext returns true if the byte offset falls inside a comment,
// string literal, or other non-executable context.
func IsNonCodeContext(tree *Tree, offset uint32) bool {
	return IsInComment(tree, offset) || IsInString(tree, offset)
}
