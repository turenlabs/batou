package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// argShapeGateOK reports whether a candidate sink that opted into an
// argument-shape constraint (SinkDef.RequiresArgShape) satisfies it. It is a
// POST-MATCH precision filter: matchSinkCall calls it only after the structural
// method match, and only for sinks whose RequiresArgShape != ArgShapeAny. A
// false result DROPS the candidate (the sink does not fire); it never loosens
// matching.
//
// Returns true (KEEP) when the constraint is satisfied OR the relevant
// argument's shape cannot be proven to violate it (recall-preserving). Returns
// false (DROP) only when the argument is unambiguously the wrong shape.
//
// Today only ArgShapeContainer is consumed, and only for PHP (the MongoDB
// find()/findOne() vs Eloquent primary-key collision). Every other shape /
// language is a no-op (keep).
func argShapeGateOK(callNode *ast.Node, sink *taint.SinkDef, cfg *langConfig) bool {
	if sink == nil || cfg == nil || sink.RequiresArgShape == taint.ArgShapeAny {
		return true
	}
	arg := argShapeRelevantArg(callNode, sink, cfg)
	if arg == nil {
		// No inspectable argument (variadic spread, parse gap, missing arg) →
		// keep, matching the conservative "unknown ⇒ keep" default.
		return true
	}
	switch sink.RequiresArgShape {
	case taint.ArgShapeContainer:
		switch cfg.language {
		case rules.LangPHP:
			// KEEP only when the filter argument is (or resolves to) a
			// container; the Eloquent scalar-PK form drops out.
			return phpArgIsContainerShape(arg, callNode, cfg)
		case rules.LangJavaScript, rules.LangTypeScript:
			// KEEP only when the filter argument is a genuine MongoDB query
			// document — an object literal carrying a `$`-operator key, or a
			// whole tainted object/variable. The pervasive parameterized
			// equality form (`find({_id: req.params.id})`), an idiomatic
			// locally-built filter (`find(cond)` where `cond = q ? {f:{$regex}} :
			// {}`), and the Array.prototype.find callback (`arr.find(x => …)`)
			// drop out.
			return jsArgIsNoSQLContainerShape(arg, callNode, cfg)
		}
		// Other languages have not opted in / been validated → no-op.
		return true
	default:
		// ArgShapeScalarLiteral / ArgShapeStringInterp are reserved and not
		// yet consumed by the matcher; treat as no-ops so an accidental
		// opt-in can never silently suppress findings.
		return true
	}
}

// argShapeRelevantArg returns the call argument the shape gate should inspect:
// the first entry of DangerousArgs (default index 0), unwrapped from a PHP
// `argument` wrapper node to the inner expression. Returns nil when the index
// is out of range or the argument cannot be located.
func argShapeRelevantArg(callNode *ast.Node, sink *taint.SinkDef, cfg *langConfig) *ast.Node {
	if callNode == nil || cfg == nil {
		return nil
	}
	idx := 0
	if len(sink.DangerousArgs) > 0 && sink.DangerousArgs[0] >= 0 {
		idx = sink.DangerousArgs[0]
	}
	args := cfg.extractCallArgs(callNode)
	if idx < 0 || idx >= len(args) {
		return nil
	}
	arg := args[idx]
	if arg == nil {
		return nil
	}
	if arg.Type() == "argument" {
		if kids := arg.NamedChildren(); len(kids) > 0 {
			arg = kids[0]
		}
	}
	return arg
}

// phpArgIsContainerShape reports whether a PHP expression passed as a MongoDB
// find()/findOne() filter is (or resolves to) a CONTAINER — an array / query
// document, the shape of a genuine NoSQL-injection filter
// (`find(['$where' => $tainted])`).
//
// It returns false for the Laravel Eloquent primary-key form, whose argument is
// a SCALAR: a literal, a bare ID variable / parameter, a property or
// array-element access, or a scalar-returning helper call (request('id'),
// config(...), a model attribute, …). Dropping that candidate removes the
// bare-keyed `->find($id)` block-tier false positives without receiver-type
// discrimination, which PHP does not give us.
//
// Recall is preserved for the dominant real NoSQL-injection shapes: an inline
// array literal, a variable assigned an array literal, a variable assigned an
// array-producing call (json_decode, $request->all(), array_*), and an
// array/iterable-typed parameter. The residual — a filter held in a variable
// whose array origin is opaque, or iterated out of an opaque collection — is
// intentionally not fired at this block-eligible tier; it is a rare shape that
// appears in no test corpus, and the precision win on real Eloquent code (where
// `->find($scalarId)` is pervasive) is large. This is a deliberate
// precision/recall trade for the bare-`find` collision, not a general default.
func phpArgIsContainerShape(arg, callNode *ast.Node, cfg *langConfig) bool {
	return phpResolvesToContainer(arg, callNode, cfg, 0)
}

// jsArgIsNoSQLContainerShape reports whether a JS/TS expression passed as the
// filter argument of a MongoDB collection method (find/findOne/updateMany/…) is
// a genuine NoSQL query document — the shape a NoSQL-injection finding requires.
// It is the JS counterpart of phpArgIsContainerShape, but deliberately TIGHTER:
// in Mongo the parameterized equality form `find({_id: req.params.id})` is
// pervasive and SAFE (the value is matched as an opaque equality operand, not
// interpreted), so an object literal whose keys are all plain field names must
// NOT fire. Returns true = KEEP (let the sink fire if the arg is tainted),
// false = DROP.
func jsArgIsNoSQLContainerShape(arg, callNode *ast.Node, cfg *langConfig) bool {
	return jsResolvesToNoSQLContainer(arg, callNode, cfg, 0)
}

// jsResolvesToNoSQLContainer classifies a JS/TS filter expression as a genuine
// NoSQL query document (KEEP) or not (DROP), following a bounded number of
// local variable / ternary hops — the JS analogue of phpResolvesToContainer:
//
//   - object literal → KEEP only if it carries a top-level `$`-operator key
//     ($where/$function/$accumulator/$ne/$gt/$regex/…). The canonical
//     code-execution vectors ($where/$function/$accumulator) and operator
//     injection surface as a literal `$`-prefixed key; a plain `{field: value}`
//     equality map (the safe form) has none and drops out. A locally-built
//     filter such as `{title: {$regex: new RegExp(q)}}` is also dropped — its
//     top-level key is the plain field name, so it is treated as the idiomatic
//     per-field search rather than operator/code injection.
//   - arrow/function expression → DROP. An Array.prototype.find/filter callback
//     (`arr.find(x => x === q)`), never a query document — the exact historical
//     false-positive class that got the bare `.find(` sink removed.
//   - ternary → KEEP iff either branch resolves to a container (so
//     `cond ? {$where: t} : {}` keeps, `cond ? {f: t} : {}` drops).
//   - bare identifier → resolve to its nearest preceding local assignment and
//     re-classify the RHS. `filter = req.body` resolves to a member access
//     (KEEP, whole untrusted object); `cond = q ? {f:{$regex}} : {}` resolves to
//     a ternary of plain-key object literals (DROP). An augmented assignment
//     (`+= …`, a string scalar) drops; an unresolved bare identifier (parameter
//     / cross-scope) keeps, since taint still gates the fire.
//   - anything else (`req.body`, a call, a subscript) → KEEP: an opaque object
//     that may carry `$`-operators at runtime (`find(req.body)`); taint decides.
func jsResolvesToNoSQLContainer(expr, callNode *ast.Node, cfg *langConfig, depth int) bool {
	if expr == nil || depth > 4 {
		// Unresolved / runaway → KEEP (conservative; taint still gates).
		return true
	}
	switch expr.Type() {
	case "object":
		return jsObjectHasOperatorKey(expr)
	case "arrow_function", "function", "function_expression":
		return false
	case "parenthesized_expression":
		if kids := expr.NamedChildren(); len(kids) > 0 {
			return jsResolvesToNoSQLContainer(kids[0], callNode, cfg, depth+1)
		}
		return false
	case "ternary_expression":
		cons := expr.ChildByFieldName("consequence")
		alt := expr.ChildByFieldName("alternative")
		return jsResolvesToNoSQLContainer(cons, callNode, cfg, depth+1) ||
			jsResolvesToNoSQLContainer(alt, callNode, cfg, depth+1)
	case "identifier":
		rhs, found := jsNearestAssignmentRHS(expr.Text(), callNode, cfg)
		if found {
			if rhs == nil {
				// Augmented assignment (`x += …`) → string scalar, not a
				// query document.
				return false
			}
			return jsResolvesToNoSQLContainer(rhs, callNode, cfg, depth+1)
		}
		// Bare parameter / cross-scope variable → KEEP; taint gates.
		return true
	default:
		// Member access (`req.body`), call, subscript, etc.: an opaque object
		// that could carry `$`-operators. KEEP; taint gates the actual fire.
		return true
	}
}

// jsNearestAssignmentRHS returns the right-hand side of the nearest local
// binding of `name` that lexically precedes callNode within the enclosing
// function (or program) scope, plus whether any binding was found. It mirrors
// phpVarResolvesToContainer's nearest-assignment scan. A `const/let/var name =
// RHS` declarator and a plain `name = RHS` assignment both bind; an augmented
// `name += …` binds with a nil RHS (a string scalar). Bindings at or after the
// call site are ignored.
func jsNearestAssignmentRHS(name string, callNode *ast.Node, cfg *langConfig) (*ast.Node, bool) {
	scope := jsEnclosingScope(callNode, cfg)
	if scope == nil {
		return nil, false
	}
	callStart := callNode.StartByte()
	var bestRHS *ast.Node
	var bestStart uint32
	found := false
	var walk func(n *ast.Node)
	walk = func(n *ast.Node) {
		if n == nil || n.StartByte() >= callStart {
			return
		}
		switch n.Type() {
		case "variable_declarator":
			nm := n.ChildByFieldName("name")
			if nm != nil && nm.Type() == "identifier" &&
				strings.TrimSpace(nm.Text()) == name {
				if v := n.ChildByFieldName("value"); v != nil {
					if !found || n.StartByte() >= bestStart {
						found = true
						bestStart = n.StartByte()
						bestRHS = v
					}
				}
			}
		case "assignment_expression", "augmented_assignment_expression":
			l := n.ChildByFieldName("left")
			if l != nil && l.Type() == "identifier" &&
				strings.TrimSpace(l.Text()) == name {
				if !found || n.StartByte() >= bestStart {
					found = true
					bestStart = n.StartByte()
					if n.Type() == "augmented_assignment_expression" {
						bestRHS = nil
					} else {
						bestRHS = n.ChildByFieldName("right")
					}
				}
			}
		}
		for i := 0; i < n.ChildCount(); i++ {
			walk(n.Child(i))
		}
	}
	walk(scope)
	return bestRHS, found
}

// jsEnclosingScope returns the body of the nearest enclosing function (the scope
// to scan for a variable binding), falling back to the program root for
// top-level code.
func jsEnclosingScope(n *ast.Node, cfg *langConfig) *ast.Node {
	ancestors := n.Ancestors()
	for _, anc := range ancestors {
		if cfg.funcTypes[anc.Type()] {
			if b := anc.ChildByFieldName("body"); b != nil {
				return b
			}
			return anc
		}
	}
	if len(ancestors) > 0 {
		return ancestors[len(ancestors)-1]
	}
	return nil
}

// jsObjectHasOperatorKey reports whether a JS/TS object-literal node has at
// least one top-level property whose key is a MongoDB `$`-operator (a name
// beginning with `$`, e.g. `$where`, `$function`, `$ne`). Only top-level keys
// are inspected: a nested `{field: {$gt: scalar}}` keeps `field` (plain) at the
// top, so it drops out — matching the deliberate precision trade where a
// per-field comparison against a user scalar is treated as the safe equality
// form, while a top-level `{$where: …}` / a whole tainted filter object is not.
func jsObjectHasOperatorKey(obj *ast.Node) bool {
	if obj == nil {
		return false
	}
	for _, child := range obj.NamedChildren() {
		if child.Type() != "pair" {
			continue
		}
		key := child.ChildByFieldName("key")
		if key == nil {
			continue
		}
		if jsKeyText(key) != "" && strings.HasPrefix(jsKeyText(key), "$") {
			return true
		}
	}
	return false
}

// jsKeyText returns the textual name of a JS/TS object-literal property key,
// stripping the surrounding quotes for string keys so `{"$where": …}` and
// `{$where: …}` both resolve to `$where`. A computed key (`{[k]: …}`) returns
// the empty string (its name is not statically known).
func jsKeyText(key *ast.Node) string {
	switch key.Type() {
	case "property_identifier", "identifier", "private_property_identifier":
		return key.Text()
	case "string":
		// `string` node text includes the quotes (and a `string_fragment`
		// child holds the inner text); trim quotes from the raw text.
		return strings.Trim(key.Text(), "'\"`")
	}
	return ""
}

// phpResolvesToContainer classifies a PHP expression as a container (true) or
// not (false), following at most a couple of variable-binding hops. Anything it
// cannot prove to be a container returns false (drop), which for the
// find()/findOne() gate means "treat as the scalar Eloquent form".
func phpResolvesToContainer(expr, callNode *ast.Node, cfg *langConfig, depth int) bool {
	if expr == nil || depth > 3 {
		return false
	}
	switch expr.Type() {
	case "array_creation_expression":
		// `[...]` / `array(...)` literal — the canonical filter document.
		return true
	case "parenthesized_expression":
		if kids := expr.NamedChildren(); len(kids) > 0 {
			return phpResolvesToContainer(kids[0], callNode, cfg, depth+1)
		}
		return false
	case "cast_expression":
		// `(array) $x` coerces to an array.
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(expr.Text())), "(array)")
	case "subscript_expression":
		// `$x['k']` / `$_POST['filter']`. PHP element access is untyped and
		// can itself yield an array (a request superglobal commonly carries a
		// nested array, e.g. `filter[$where]=…`). This is the canonical
		// whole-value NoSQL-injection filter shape, so it is kept. This is the
		// recall side of the gate; the Eloquent FP cluster never reaches
		// find() through a subscript (it uses bare PK vars / properties).
		return true
	case "variable_name":
		return phpVarResolvesToContainer(expr, callNode, cfg, depth)
	case "function_call_expression", "member_call_expression",
		"scoped_call_expression", "nullsafe_member_call_expression":
		return phpCallProducesContainer(expr)
	}
	// Scalar literals, member/property access (`$model->id`), string
	// concatenation, conditional/ternary, etc. → not a container (the Eloquent
	// scalar primary-key form).
	return false
}

// phpVarResolvesToContainer resolves a `$var` used as the find() filter to a
// container/scalar verdict by scanning its enclosing function body for the
// nearest binding that lexically precedes callNode. A binding to an array
// literal / array-producing call ⇒ container (keep). A binding to a scalar, a
// foreach value element, a scalar/opaque call, or no binding at all (bare
// parameter or unresolved) ⇒ not a container (drop) — except an array/iterable
// type-hinted parameter, which is kept.
func phpVarResolvesToContainer(varNode, callNode *ast.Node, cfg *langConfig, depth int) bool {
	if varNode == nil || callNode == nil {
		return false
	}
	name := strings.TrimSpace(varNode.Text())
	if name == "" {
		return false
	}
	fnNode := phpEnclosingFunction(callNode, cfg)
	// Scan the enclosing function body when inside a function/method; otherwise
	// fall back to the top-level program scope (script-style PHP files).
	scope := phpFunctionBody(fnNode)
	if scope == nil {
		scope = phpProgramRoot(callNode)
	}
	if scope == nil {
		return false
	}
	callStart := callNode.StartByte()

	// Find the nearest assignment to `name` that precedes the call.
	var bestRHS *ast.Node
	var bestStart uint32
	var found bool
	var foreachBound bool
	var walk func(n *ast.Node)
	walk = func(n *ast.Node) {
		if n == nil {
			return
		}
		// Don't look at anything at/after the call site.
		if n.StartByte() >= callStart {
			return
		}
		switch n.Type() {
		case "assignment_expression", "augmented_assignment_expression":
			left := n.ChildByFieldName("left")
			if left != nil && left.Type() == "variable_name" &&
				strings.TrimSpace(left.Text()) == name {
				if !found || n.StartByte() >= bestStart {
					found = true
					bestStart = n.StartByte()
					if n.Type() == "augmented_assignment_expression" {
						// `.=` / `+=` etc. produce scalars.
						bestRHS = nil
					} else {
						bestRHS = n.ChildByFieldName("right")
					}
				}
			}
		case "foreach_statement":
			// A value bound by `foreach (... as $name)` / `as $k => $name`.
			if phpForeachBindsValue(n, name) {
				if !found || n.StartByte() >= bestStart {
					found = true
					foreachBound = true
					bestStart = n.StartByte()
					bestRHS = nil
				}
			}
		}
		for i := 0; i < n.ChildCount(); i++ {
			walk(n.Child(i))
		}
	}
	walk(scope)

	if found {
		if foreachBound {
			// A scalar element iterated out of a collection — the Eloquent
			// `foreach ($ids as $id) { ->find($id) }` shape.
			return false
		}
		return phpResolvesToContainer(bestRHS, callNode, cfg, depth+1)
	}

	// No in-body binding: treat as a parameter (or an unresolved local). Only
	// an array/iterable type-hinted parameter is a container.
	if phpParamHasContainerType(fnNode, name) {
		return true
	}
	return false
}

// phpForeachBindsValue reports whether a foreach_statement binds its VALUE
// variable to `name` (e.g. `foreach ($xs as $name)` or
// `foreach ($xs as $k => $name)`). Only the value binding counts.
func phpForeachBindsValue(foreachNode *ast.Node, name string) bool {
	if foreachNode == nil {
		return false
	}
	// The grammar exposes the value as a `value` field on some versions; fall
	// back to the last variable_name appearing before the body.
	if v := foreachNode.ChildByFieldName("value"); v != nil {
		return v.Type() == "variable_name" && strings.TrimSpace(v.Text()) == name
	}
	body := foreachNode.ChildByFieldName("body")
	bodyStart := ^uint32(0)
	if body != nil {
		bodyStart = body.StartByte()
	}
	var lastVar *ast.Node
	for _, c := range foreachNode.NamedChildren() {
		if c.StartByte() >= bodyStart {
			break
		}
		if c.Type() == "variable_name" {
			lastVar = c
		}
		if c.Type() == "pair" || c.Type() == "by_ref" || c.Type() == "list_literal" {
			// `$k => $v` / `&$v` — the value is the last variable_name within.
			for _, gc := range c.NamedChildren() {
				if gc.Type() == "variable_name" {
					lastVar = gc
				}
			}
		}
	}
	return lastVar != nil && strings.TrimSpace(lastVar.Text()) == name
}

// phpCallProducesContainer reports whether a PHP call unambiguously returns an
// array/collection. Conservative: a scalar-returning helper (request('id'),
// config('k'), intval(...)) or any unrecognised call returns false, so it does
// not keep the Eloquent scalar form alive. The list is the array-producing
// standard library plus the common Laravel request array accessors.
func phpCallProducesContainer(call *ast.Node) bool {
	name := strings.ToLower(phpCalleeBaseName(call))
	if name == "" {
		return false
	}
	switch name {
	case "json_decode", // decoded JSON document (assoc array or object)
		"array", "compact", "get_object_vars", "iterator_to_array",
		"array_merge", "array_merge_recursive", "array_combine",
		"array_filter", "array_map", "array_values", "array_keys",
		"array_column", "array_diff", "array_intersect", "array_replace",
		"array_fill", "array_fill_keys", "array_pad", "array_slice",
		"array_splice", "array_chunk", "array_flip", "array_reverse",
		"array_unique", "range", "explode", "preg_split", "str_split",
		// Laravel request/collection array accessors.
		"all", "only", "except", "toarray":
		return true
	}
	return false
}

// phpCalleeBaseName returns the callee's method/function name for a PHP call
// node: the `name` field for member/scoped calls, or the leading name for a
// plain function call. Returns "" if it cannot be determined.
func phpCalleeBaseName(call *ast.Node) string {
	if call == nil {
		return ""
	}
	if nm := call.ChildByFieldName("name"); nm != nil {
		return strings.TrimSpace(nm.Text())
	}
	return phpCallBaseName(call)
}

// phpEnclosingFunction returns the nearest function_definition / method_declaration
// (or anonymous function / arrow function) ancestor of n, or nil.
func phpEnclosingFunction(n *ast.Node, cfg *langConfig) *ast.Node {
	for _, anc := range n.Ancestors() {
		t := anc.Type()
		if cfg.funcTypes[t] ||
			t == "anonymous_function_creation_expression" ||
			t == "arrow_function" {
			return anc
		}
	}
	return nil
}

// phpProgramRoot returns the top-most ancestor of n (the `program` root), used
// as the scan scope for find() calls in script-style PHP outside any function.
func phpProgramRoot(n *ast.Node) *ast.Node {
	anc := n.Ancestors()
	if len(anc) == 0 {
		return nil
	}
	return anc[len(anc)-1]
}

// phpFunctionBody returns the body (compound_statement) of a PHP function node.
func phpFunctionBody(fnNode *ast.Node) *ast.Node {
	if fnNode == nil {
		return nil
	}
	if b := fnNode.ChildByFieldName("body"); b != nil {
		return b
	}
	for _, c := range fnNode.NamedChildren() {
		if c.Type() == "compound_statement" {
			return c
		}
	}
	return nil
}

// phpParamHasContainerType reports whether `name` is a parameter of fnNode that
// carries an `array` or `iterable` type hint (a variadic `...$name` also binds
// an array of the remaining arguments).
func phpParamHasContainerType(fnNode *ast.Node, name string) bool {
	if fnNode == nil {
		return false
	}
	params := fnNode.ChildByFieldName("parameters")
	if params == nil {
		return false
	}
	for _, p := range params.NamedChildren() {
		switch p.Type() {
		case "variadic_parameter":
			if nm := p.ChildByFieldName("name"); nm != nil &&
				strings.TrimSpace(nm.Text()) == name {
				return true
			}
		case "simple_parameter", "property_promotion_parameter":
			nm := p.ChildByFieldName("name")
			if nm == nil || strings.TrimSpace(nm.Text()) != name {
				continue
			}
			ty := p.ChildByFieldName("type")
			if ty == nil {
				return false
			}
			tt := strings.ToLower(strings.TrimSpace(ty.Text()))
			tt = strings.TrimPrefix(tt, "?")
			return tt == "array" || tt == "iterable"
		}
	}
	return false
}
