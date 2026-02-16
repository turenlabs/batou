package tsflow

import "github.com/turenlabs/batou/internal/ast"

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

	// String interpolation — check embedded expressions.
	// Handles interpolation wrapper nodes across languages:
	//   Python: interpolation (inside f-string)
	//   JS/TS:  template_substitution (inside template_string)
	//   Ruby:   interpolation (inside string)
	//   PHP:    encapsed_string (contains variable_name children directly)
	//   C#:     interpolation (inside interpolated_string_expression)
	//   Kotlin: interpolated_expression (inside string_literal, for ${expr})
	//   Perl:   string_content (inside interpolated_string_literal, contains scalar)
	if nodeType == "interpolation" || nodeType == "template_substitution" ||
		nodeType == "string_interpolation" || nodeType == "encapsed_string" ||
		nodeType == "interpolated_expression" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if ts, ok := nodeIsTainted(c, tm, cfg); ok {
				return ts, true
			}
		}
		return nil, false
	}

	// Kotlin interpolated_identifier: "$var" produces an interpolated_identifier
	// node whose text is the bare variable name (without $).
	if nodeType == "interpolated_identifier" {
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return ts, true
		}
		return nil, false
	}

	// Perl scalar/array/hash nodes inside interpolated strings: "$var" produces
	// a scalar node containing a varname child with the bare name.
	if nodeType == "scalar" || nodeType == "array_variable" || nodeType == "hash_variable" {
		name := perlVarName(n)
		if name != "" {
			if ts := tm.get(name); ts != nil && ts.source != nil {
				return ts, true
			}
		}
		return nil, false
	}

	// Template string / f-string / interpolated string containers — walk all
	// children looking for interpolation nodes or embedded variables.
	// Handles:
	//   JS/TS:  template_string
	//   Python: string (f-strings)
	//   Ruby:   string (with #{} interpolation)
	//   Kotlin: string_literal (with $var or ${expr})
	//   C#:     interpolated_string_expression ($"...{expr}...")
	//   Perl:   interpolated_string_literal ("...$var...")
	if nodeType == "template_string" || nodeType == "string" ||
		nodeType == "string_literal" || nodeType == "interpolated_string_expression" ||
		nodeType == "interpolated_string_literal" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if ts, ok := nodeIsTainted(c, tm, cfg); ok {
				return ts, true
			}
		}
		return nil, false
	}

	// Perl string_content nodes may contain embedded scalar/array children
	// (e.g., "Hello $name" has string_content with a scalar child inside).
	if nodeType == "string_content" && n.ChildCount() > 0 {
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

	// Object/dictionary/hash literal — check if any value field is tainted.
	// Handles: JS {username: username}, JS shorthand {username}, Python {"k": v}, Ruby {k: v}.
	if nodeType == "object" || nodeType == "dictionary" || nodeType == "hash" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() {
				continue
			}
			ct := c.Type()
			// pair / dictionary_element: key-value entry — check the value child
			if ct == "pair" {
				val := c.ChildByFieldName("value")
				if val != nil {
					if ts, ok := nodeIsTainted(val, tm, cfg); ok {
						return ts, true
					}
				}
				continue
			}
			// JS/TS shorthand property: {username} means {username: username}
			if ct == "shorthand_property_identifier" || ct == "shorthand_property_identifier_pattern" {
				name := c.Text()
				if ts := tm.get(name); ts != nil && ts.source != nil {
					return ts, true
				}
				continue
			}
			// Fallback: recurse into any other named child
			if ts, ok := nodeIsTainted(c, tm, cfg); ok {
				return ts, true
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
	case "template_string", "interpolation", "template_substitution",
		"interpolated_string_expression", "interpolated_string_literal",
		"string_literal", "interpolated_expression", "interpolated_identifier",
		"encapsed_string":
		return 0.95 // string interpolation
	case "object", "dictionary", "hash":
		return 0.95 // object/dict/hash literal wrapping tainted value
	default:
		return 1.0
	}
}
