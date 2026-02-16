package ast

import (
	"context"
	"time"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/turenlabs/batou/internal/rules"
)

// parseTimeout is the maximum time allowed for a single tree-sitter parse.
// Parsing is typically sub-millisecond but we cap it to protect against
// pathological inputs.
const parseTimeout = 2 * time.Second

// Parse parses content as the given language and returns the AST tree.
// Returns nil if the language has no grammar or parsing fails.
// This function is safe to call concurrently; it creates a fresh parser
// each time (tree-sitter parsers are lightweight).
func Parse(content []byte, lang rules.Language) *Tree {
	tsLang := lookupLanguage(lang)
	if tsLang == nil {
		return nil
	}

	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(tsLang)

	ctx, cancel := context.WithTimeout(context.Background(), parseTimeout)
	defer cancel()

	tsTree, err := parser.ParseCtx(ctx, nil, content)
	if err != nil || tsTree == nil {
		return nil
	}

	root := tsTree.RootNode()
	if root == nil {
		return nil
	}

	tree := &Tree{
		content:  content,
		language: string(lang),
	}
	tree.root = convertNode(root, content, nil)
	return tree
}

// convertNode recursively converts a tree-sitter Node into our internal
// Node type, severing the dependency on tree-sitter's C types.
func convertNode(tsNode *sitter.Node, content []byte, parent *Node) *Node {
	if tsNode == nil {
		return nil
	}

	n := &Node{
		nodeType:  tsNode.Type(),
		startByte: tsNode.StartByte(),
		endByte:   tsNode.EndByte(),
		startRow:  tsNode.StartPoint().Row,
		startCol:  tsNode.StartPoint().Column,
		endRow:    tsNode.EndPoint().Row,
		endCol:    tsNode.EndPoint().Column,
		isNamed:   tsNode.IsNamed(),
		content:   content,
		parent:    parent,
	}

	count := int(tsNode.ChildCount())
	if count > 0 {
		n.children = make([]*Node, count)
		for i := 0; i < count; i++ {
			child := tsNode.Child(i)
			n.children[i] = convertNode(child, content, n)
			n.children[i].fieldName = tsNode.FieldNameForChild(i)
		}
	}

	return n
}
