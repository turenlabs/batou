package tsflow

import "github.com/turenio/gtss/internal/ast"

// nodeIsTainted checks whether a tree-sitter node references any tainted variable.
// Walks into identifiers, attribute accesses, binary expressions, call arguments,
// and subscript expressions.
func nodeIsTainted(n *ast.Node, tm *taintMap, cfg *langConfig) (*taintState, bool) {
	if n == nil {
		return nil, false
	}

	nodeType := n.Type()

	// Identifier — direct variable lookup
	if nodeType == cfg.identType {
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return ts, true
		}
		return nil, false
	}

	// PHP variable_name nodes contain the $ prefix
	if nodeType == "variable_name" || nodeType == "name" {
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return ts, true
		}
		return nil, false
	}

	// Attribute/member access — check the base object
	if cfg.attrTypes[nodeType] {
		recv := cfg.extractAttrReceiver(n)
		if recv != "" {
			if ts := tm.get(recv); ts != nil && ts.source != nil {
				return ts, true
			}
		}
		// Also check the full expression text as a variable (e.g., "request.args" stored as-is)
		fullText := n.Text()
		if ts := tm.get(fullText); ts != nil && ts.source != nil {
			return ts, true
		}
		return nil, false
	}

	// Binary expression — check both sides
	if nodeType == "binary_operator" || nodeType == "binary_expression" ||
		nodeType == "concatenated_string" || nodeType == "string_binary_expression" {
		left := n.ChildByFieldName("left")
		if ts, ok := nodeIsTainted(left, tm, cfg); ok {
			return ts, true
		}
		right := n.ChildByFieldName("right")
		return nodeIsTainted(right, tm, cfg)
	}

	// String interpolation — check embedded expressions
	if nodeType == "interpolation" || nodeType == "template_substitution" ||
		nodeType == "string_interpolation" || nodeType == "encapsed_string" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if ts, ok := nodeIsTainted(c, tm, cfg); ok {
				return ts, true
			}
		}
		return nil, false
	}

	// Template string / f-string — check children for interpolations
	if nodeType == "template_string" || nodeType == "string" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if ts, ok := nodeIsTainted(c, tm, cfg); ok {
				return ts, true
			}
		}
		return nil, false
	}

	// Call expression — check receiver and arguments
	if cfg.callTypes[nodeType] {
		// Check if receiver is tainted (e.g., taintedObj.method())
		receiver := cfg.extractCallReceiver(n)
		if receiver != "" {
			if ts := tm.get(receiver); ts != nil && ts.source != nil {
				return ts, true
			}
		}
		// Check arguments
		args := cfg.extractCallArgs(n)
		for _, arg := range args {
			if ts, ok := nodeIsTainted(arg, tm, cfg); ok {
				return ts, true
			}
		}
		return nil, false
	}

	// Subscript / index expression — check the base
	if nodeType == "subscript" || nodeType == "subscript_expression" || nodeType == "element_reference" {
		obj := n.ChildByFieldName("object")
		if obj == nil {
			obj = n.ChildByFieldName("value")
		}
		if obj == nil && n.ChildCount() > 0 {
			obj = n.Child(0)
		}
		return nodeIsTainted(obj, tm, cfg)
	}

	// Parenthesized expression
	if nodeType == "parenthesized_expression" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return nodeIsTainted(c, tm, cfg)
			}
		}
		return nil, false
	}

	// Conditional / ternary expression — check both branches
	if nodeType == "conditional_expression" || nodeType == "ternary_expression" {
		cons := n.ChildByFieldName("consequence")
		if ts, ok := nodeIsTainted(cons, tm, cfg); ok {
			return ts, true
		}
		alt := n.ChildByFieldName("alternative")
		return nodeIsTainted(alt, tm, cfg)
	}

	// Await expression — unwrap
	if nodeType == "await_expression" || nodeType == "await" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return nodeIsTainted(c, tm, cfg)
			}
		}
		return nil, false
	}

	// Array/list literal — check elements
	if nodeType == "list" || nodeType == "array" || nodeType == "array_creation_expression" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				if ts, ok := nodeIsTainted(c, tm, cfg); ok {
					return ts, true
				}
			}
		}
		return nil, false
	}

	// Fallback: for named children, recursively check the first named child
	// to handle language-specific wrapper nodes we haven't explicitly handled.
	named := n.NamedChildren()
	if len(named) == 1 {
		return nodeIsTainted(named[0], tm, cfg)
	}

	return nil, false
}

// propagationConfidence returns the confidence decay factor for taint
// propagating through a given node type.
func propagationConfidence(n *ast.Node) float64 {
	if n == nil {
		return 1.0
	}
	switch n.Type() {
	case "binary_operator", "binary_expression":
		return 0.95 // string concatenation
	case "call", "call_expression", "method_invocation", "function_call_expression", "member_call_expression":
		return 0.85 // unknown function call
	case "subscript", "subscript_expression", "element_reference":
		return 0.9 // indexing
	case "template_string", "interpolation", "template_substitution":
		return 0.95 // string interpolation
	default:
		return 1.0
	}
}
