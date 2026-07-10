package tsflow

import (
	"strconv"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// nodeIsTainted checks whether a tree-sitter node references any tainted variable.
// Walks into identifiers, attribute accesses, binary expressions, call arguments,
// and subscript expressions.
func nodeIsTainted(n *ast.Node, tm *taintMap, cfg *langConfig) (*taintState, bool) {
	if n == nil {
		return nil, false
	}

	nodeType := n.Type()

	// Identifier — direct variable lookup. If the bare identifier itself
	// is not tracked, fall back to shallow field-sensitive lookup: any
	// `<name>.<field>` entry in the taint map taints a bare-object read at
	// a sink, since the sink may internally read any field. This is a
	// conservative over-approximation that mirrors astflow's exprIsTainted.
	if nodeType == cfg.identType {
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return ts, true
		}
		if ts := tm.anyFieldTainted(name); ts != nil {
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
		if ts := tm.anyFieldTainted(name); ts != nil {
			return ts, true
		}
		return nil, false
	}

	// Ruby instance/class/global variables. Tree-sitter exposes `@q`,
	// `@@cache`, and `$g` as distinct node types (instance_variable,
	// class_variable, global_variable) whose Text() is the full sigil'd
	// name — exactly the key extractAssignLHS seeds. A read of `@q` at a
	// sink (`system(@q)`) resolves the taint assigned to `@q = params[:q]`.
	// Gated to Ruby so no other language's node handling changes.
	if cfg != nil && cfg.language == rules.LangRuby &&
		(nodeType == "instance_variable" || nodeType == "class_variable" || nodeType == "global_variable") {
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return ts, true
		}
		if ts := tm.anyFieldTainted(name); ts != nil {
			return ts, true
		}
		return nil, false
	}

	// Attribute/member access. Bounded multi-level field-sensitive read order:
	//   1. Walk bounded dotted PREFIXES of the path
	//      (req.body.user.id → req.body.user → req.body → req) and taint if any
	//      prefix is a tracked tainted access path. This matches the exact path
	//      (`req.body.user.id`) AND taints sub-paths of a tainted path
	//      (`req.body.user` taints `req.body.user.id`), while a SIBLING field
	//      whose prefix was never tainted (`req.body.other` when only
	//      `req.body.user` is tainted) stays clean — the multi-level precision
	//      gain. Read keys are bounded to maxAccessPathDepth so a deep read
	//      matches a collapsed seeded prefix.
	//   2. Fall back to the grammar-extracted immediate receiver's bare taint
	//      (`tm.get(recv)`). This is the long-standing whole-object fallback:
	//      `msg` in C `msg->payload` (where `msg` is a tainted bare variable),
	//      `b` in `b = req.body; sink(b.x)`. It is path-grammar-agnostic, so it
	//      also covers `->`-style accesses that the dotted prefix walk does not
	//      split. Because processAttr now seeds the precise maximal path rather
	//      than the bare source receiver, this no longer over-taints siblings
	//      (`tm.get("req.body")` is nil when only `req.body.a` was seeded).
	if cfg.attrTypes[nodeType] {
		fullText := n.Text()
		if ts := tm.prefixTainted(boundAccessPath(fullText)); ts != nil {
			return ts, true
		}
		recv := cfg.extractAttrReceiver(n)
		if recv != "" {
			if ts := tm.get(recv); ts != nil && ts.source != nil {
				return ts, true
			}
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

	// Bash variable expansion (Shell only): `$var` is a simple_expansion node and
	// `${var}` is an expansion node; both contain a `variable_name` child whose
	// text is the bare name (e.g. "url", "1", "HOME"). Resolve it against the
	// taint map so a `"$url"` argument at a sink picks up the taint assigned to
	// `url`. `concatenation` (e.g. /tmp/$name) wraps multiple words/expansions.
	// Gated to Shell so the other languages' taint behaviour is byte-identical.
	if cfg != nil && cfg.language == rules.LangShell {
		if nodeType == "simple_expansion" || nodeType == "expansion" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "variable_name" {
					name := c.Text()
					if ts := tm.get(name); ts != nil && ts.source != nil {
						return ts, true
					}
					if ts := tm.anyFieldTainted(name); ts != nil {
						return ts, true
					}
				}
			}
			return nil, false
		}
		if nodeType == "concatenation" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if ts, ok := nodeIsTainted(c, tm, cfg); ok {
					return ts, true
				}
			}
			return nil, false
		}
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
		nodeType == "interpolated_string_literal" ||
		// Ruby: backtick `cmd #{x}` and %x{cmd #{x}} both parse as a `subshell`
		// node holding string_content/interpolation children — same shape as a
		// string, walked here so an embedded tainted interpolation is seen.
		nodeType == "subshell" ||
		// Swift: "...\(expr)..." is a line_string_literal whose interpolation
		// children are `interpolated_expression` nodes (already handled above).
		// Multi-line `"""..."""` is multi_line_string_literal.
		nodeType == "line_string_literal" || nodeType == "multi_line_string_literal" {
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
		// Ruby attribute READ (`obj.cmd`). Tree-sitter models a bare
		// attribute getter as a `call` node with a receiver and a method
		// name but NO argument list. The matching attribute SETTER
		// (`obj.cmd = ...`) seeds a shallow field key "obj.cmd" via
		// extractAssignLHS, so consult prefixTainted for that exact path
		// here. Only fires when the receiver is a plain identifier and
		// there is no argument list, so real method calls (`obj.run(x)`)
		// fall through to the generic receiver/args checks below. Gated to
		// Ruby so other languages' `call` handling is byte-identical, and
		// purely additive: a non-seeded `obj.cmd` returns nil and proceeds.
		if cfg.language == rules.LangRuby && n.ChildByFieldName("arguments") == nil {
			if recv := n.ChildByFieldName("receiver"); recv != nil && recv.Type() == "identifier" {
				if m := n.ChildByFieldName("method"); m != nil {
					fullText := recv.Text() + "." + m.Text()
					if ts := tm.prefixTainted(boundAccessPath(fullText)); ts != nil {
						return ts, true
					}
				}
			}
		}
		// Check if receiver is tainted (e.g., taintedObj.method())
		receiver := cfg.extractCallReceiver(n)
		if receiver != "" {
			if ts := tm.get(receiver); ts != nil && ts.source != nil {
				return ts, true
			}
		}
		// For chained calls like base64.b64decode(tmp).decode('utf-8'),
		// the receiver text is the full inner expression which won't be
		// in the taint map. Recursively check the receiver AST node.
		fn := n.ChildByFieldName("function")
		if fn == nil {
			fn = n.ChildByFieldName("name")
		}
		if fn != nil {
			obj := fn.ChildByFieldName("object")
			if obj == nil {
				obj = fn.ChildByFieldName("value")
			}
			if obj != nil {
				if ts, ok := nodeIsTainted(obj, tm, cfg); ok {
					return ts, true
				}
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

	// Subscript / index expression — check full text first (per-key taint),
	// then per-index list taint, then fall back to checking the base object.
	// element_access_expression is C#'s indexer node (Request.Form["x"], arr[i]);
	// no other grammar produces it, so adding it here only affects C# parses and
	// gives indexing-through-a-tainted-collection the same propagation other
	// languages already get from subscript.
	if nodeType == "subscript" || nodeType == "subscript_expression" || nodeType == "element_reference" || nodeType == "element_access_expression" {
		// Per-key lookup: d['keyB'] stored as full text in taint map.
		fullText := n.Text()
		if ts := tm.get(fullText); ts != nil && ts.source != nil {
			return ts, true
		}
		obj := n.ChildByFieldName("object")
		if obj == nil {
			obj = n.ChildByFieldName("value")
		}
		if obj == nil {
			obj = n.ChildByFieldName("expression") // C# element_access_expression
		}
		if obj == nil && n.ChildCount() > 0 {
			obj = n.Child(0)
		}
		// Per-index list taint: lst[N] with N an integer literal — consult
		// the per-index map populated by .append() / .pop() / etc. so that a
		// list whose tainted element was shifted out by pop(0) reads as
		// untainted at the now-safe index.
		if obj != nil {
			recv := obj.Text()
			if _, ok := tm.lists[recv]; ok {
				// Extract the subscript expression. Tree-sitter exposes it
				// as field "subscript" (Python) or as the second named child.
				idxNode := n.ChildByFieldName("subscript")
				if idxNode == nil {
					named := n.NamedChildren()
					if len(named) >= 2 {
						idxNode = named[1]
					}
				}
				if idxNode != nil {
					idxText := strings.TrimSpace(idxNode.Text())
					if idx, err := strconv.Atoi(idxText); err == nil {
						elemTs := tm.listGet(recv, idx)
						if elemTs != nil && elemTs.source != nil {
							return elemTs, true
						}
						// Integer-literal index that resolved to a non-tainted
						// slot (or out-of-range): treat the subscript as
						// untainted regardless of the receiver's whole-list
						// taint flag. This is what makes the OWASP list-shuffle
						// `bar = lst[1]` after pop(0) read as safe.
						return nil, false
					}
				}
			}
		}
		return nodeIsTainted(obj, tm, cfg)
	}

	// Tuple expression — check all elements (Rust: ("Location", param.as_str()))
	if nodeType == "tuple_expression" {
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

	// Python walrus `x := expr` (named_expression): the whole expression
	// evaluates to its assigned value, so it carries that value's taint. This
	// covers the value appearing directly at a sink, e.g.
	// `os.system(cmd := input())`. The "value" field holds the assigned
	// expression. (The target `x` is separately seeded by processAssignInterproc
	// via assignTypes.) The node type is Python-unique, so no language gate is
	// needed.
	if nodeType == "named_expression" {
		if val := n.ChildByFieldName("value"); val != nil {
			return nodeIsTainted(val, tm, cfg)
		}
		return nil, false
	}

	// Cast expression — unwrap to the casted value (e.g., (String) expr)
	if nodeType == "cast_expression" {
		// The casted value is typically the "value" field or the last named child.
		val := n.ChildByFieldName("value")
		if val != nil {
			return nodeIsTainted(val, tm, cfg)
		}
		// Fallback: check all named children (type + value).
		named := n.NamedChildren()
		for i := len(named) - 1; i >= 0; i-- {
			if ts, ok := nodeIsTainted(named[i], tm, cfg); ok {
				return ts, true
			}
		}
		return nil, false
	}

	// Conditional / ternary expression — check branches.
	// If the condition is a constant expression that can be evaluated,
	// only check the branch that would actually execute (reduces FPs
	// from patterns like: (7*18)+num > 200 ? "safe" : param).
	if nodeType == "conditional_expression" || nodeType == "ternary_expression" {
		cond := n.ChildByFieldName("condition")
		cons := n.ChildByFieldName("consequence")
		alt := n.ChildByFieldName("alternative")

		// Python's conditional_expression (`cons if cond else alt`) has no field
		// names — fall back to positional named children in source order.
		if cond == nil && cons == nil && alt == nil {
			named := n.NamedChildren()
			if len(named) >= 3 {
				cons = named[0]
				cond = named[1]
				alt = named[2]
			}
		}

		if cond != nil {
			if val, ok := evalConstExpr(cond, tm); ok {
				if val != 0 {
					// Condition is true — only consequence executes.
					return nodeIsTainted(cons, tm, cfg)
				}
				// Condition is false — only alternative executes.
				return nodeIsTainted(alt, tm, cfg)
			}
		}

		// Cannot evaluate condition — check both branches (conservative).
		if ts, ok := nodeIsTainted(cons, tm, cfg); ok {
			return ts, true
		}
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
	if nodeType == "list" || nodeType == "array" || nodeType == "array_creation_expression" || nodeType == "array_initializer" {
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

	// Fallback: for named children, recursively check named children
	// to handle language-specific wrapper nodes we haven't explicitly handled.
	named := n.NamedChildren()
	if len(named) == 1 {
		return nodeIsTainted(named[0], tm, cfg)
	}
	// For wrapper nodes with multiple children (e.g., cast_expression, type+value),
	// check each named child for taint.
	if len(named) > 1 {
		for _, c := range named {
			if ts, ok := nodeIsTainted(c, tm, cfg); ok {
				return ts, true
			}
		}
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
	case "subscript", "subscript_expression", "element_reference", "element_access_expression":
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
