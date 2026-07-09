package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// constrained_name.go implements the CONSTRAINED-NAME recogniser that backs
// SinkDef.RejectConstrainedName (Python reflective sinks getattr/setattr —
// CWE-470 / CWE-915). A reflective sink whose dangerous payload is an
// attribute/method NAME is dangerous only when the name is an OPEN
// attacker-controlled value (getattr(obj, request.args['x'])). It must NOT fire
// on the two pervasive SAFE framework idioms whose name is drawn from a BOUNDED
// domain — these are exactly the false positives that previously NO-GO'd adding
// a Python getattr sink:
//
//	(1) Flask/Django HTTP-verb dispatch:
//	      getattr(self, request.method.lower())
//	    The name traces to request.method, whose value set is the fixed,
//	    framework-validated HTTP-verb list (get/post/put/delete/...).
//	(2) Model-metadata iteration:
//	      for field in Model._meta.fields: getattr(obj, field.name)
//	      getattr(obj, column.name)
//	    The name is a schema-bounded model field/column name, never a request
//	    value.
//
// plus the trivially-bounded cases: a STRING-LITERAL name, or a key drawn from
// a LITERAL dispatch table (`ACTIONS = {...}; getattr(self, ACTIONS[a])`).
//
// DESIGN PRINCIPLES (mirrors barrier_guards.go — recall preservation is
// paramount):
//   - SUPPRESS-ONLY. The recogniser never adds a finding; it only drops a fire
//     whose name is PROVABLY bounded. It is consulted only from the fire path,
//     and only when the sink opted in via the default-false RejectConstrainedName
//     field — so every other sink is byte-identical.
//   - CONSERVATIVE DEFAULT. Anything the recogniser cannot prove bounded returns
//     false (NOT constrained ⇒ the sink still fires ⇒ recall-safe). It would
//     rather miss an FP suppression than silence a genuine reflection injection.
//   - TIGHTLY SCOPED to the exact bounded shapes above; gated to Python (the
//     only language whose catalog opts in today). The heuristic is intentionally
//     narrow so a real attacker-controlled name (a request subscript, a tainted
//     variable, an unprovable expression) is never mistaken for bounded.

// caseTransformMethods are string case/whitespace transforms that preserve the
// BOUNDED-ness of their receiver: `request.method.lower()` is still drawn from
// the fixed HTTP-verb set, `"GET".upper()` is still a literal. Peeling such a
// wrapper and re-checking the receiver lets the verb-dispatch idiom be
// recognised through its canonical `.lower()` / `.upper()` normalisation.
var caseTransformMethods = map[string]bool{
	"lower": true, "upper": true, "casefold": true,
	"title": true, "capitalize": true, "swapcase": true,
	"strip": true, "lstrip": true, "rstrip": true,
}

// fieldColumnVarNames are the canonical loop/element variable names for model
// metadata iteration: `field.name`, `column.name`, `col.name`, and the
// plural collection forms. `<one of these>.name` is a schema-bounded field name.
var fieldColumnVarNames = map[string]bool{
	"field": true, "column": true, "col": true,
	"fields": true, "columns": true,
}

// metadataIterableMarkers are substrings that identify a model-metadata
// COLLECTION being iterated (Django `Model._meta.fields` / `_meta.get_fields()`,
// SQLAlchemy `Model.__table__.columns`, generic `.fields` / `.columns`). When a
// `<x>.name` access uses a loop variable `x` bound by `for x in <iterable>` and
// the iterable text contains one of these, the name is schema-bounded.
var metadataIterableMarkers = []string{
	"_meta.fields", "_meta.get_fields", "_meta.concrete_fields",
	"_meta.local_fields", "_meta.many_to_many", "_meta.",
	"__table__.columns", ".get_fields(", "iter_fields(",
	".columns", ".fields",
}

// literalContainerTypes are Python literal-container node types. A name drawn by
// subscript from a variable bound to one of these (a dispatch table) is bounded.
var literalContainerTypes = map[string]bool{
	"dictionary": true, "list": true, "set": true, "tuple": true,
}

// nameArgIsFrameworkConstrained reports whether the NAME argument of a
// reflective sink (getattr/setattr) is provably drawn from a BOUNDED domain,
// making the call a safe framework idiom rather than attacker-controlled
// reflection. Returns true ⇒ the caller SUPPRESSES the fire. Returns false for
// anything it cannot prove bounded (the recall-safe default) and for every
// non-Python language (only Python opts in today).
func nameArgIsFrameworkConstrained(nameArg *ast.Node, tm *taintMap, cfg *langConfig) bool {
	if nameArg == nil || cfg == nil || cfg.language != rules.LangPython {
		return false
	}
	return constrainedNameRec(nameArg, tm, cfg, 0)
}

// constrainedNameRec is the recursive worker. depth bounds runaway recursion on
// pathological wrapper chains.
func constrainedNameRec(n *ast.Node, tm *taintMap, cfg *langConfig, depth int) bool {
	if n == nil || depth > 6 {
		return false
	}
	switch n.Type() {
	case "string", "concatenated_string":
		// A string literal name (getattr(obj, "field")) is fixed. An f-string
		// with interpolation is NOT a literal — reject it (fail closed).
		return isStaticStringLiteral(n)
	case "parenthesized_expression":
		if inner := firstNamedChild(n); inner != nil {
			return constrainedNameRec(inner, tm, cfg, depth+1)
		}
		return false
	case "call":
		// Case-transform wrapper around a bounded value: request.method.lower(),
		// "GET".upper(). Peel the .lower()/.upper()/... method and re-check the
		// receiver for bounded-ness.
		if recv := caseTransformCallReceiver(n, cfg); recv != nil {
			return constrainedNameRec(recv, tm, cfg, depth+1)
		}
		return false
	case "attribute":
		return attrNameIsBounded(n, tm, cfg)
	case "subscript":
		return subscriptIsDispatchTable(n, tm)
	}
	return false
}

// isStaticStringLiteral reports whether a Python `string` / `concatenated_string`
// node is a STATIC literal with no interpolation. An f-string carrying an
// `interpolation` child (`f"{x}"`) embeds a runtime value and is NOT bounded.
func isStaticStringLiteral(n *ast.Node) bool {
	var hasInterp func(*ast.Node) bool
	hasInterp = func(x *ast.Node) bool {
		if x == nil {
			return false
		}
		if x.Type() == "interpolation" {
			return true
		}
		for i := 0; i < x.ChildCount(); i++ {
			if hasInterp(x.Child(i)) {
				return true
			}
		}
		return false
	}
	return !hasInterp(n)
}

// caseTransformCallReceiver returns the receiver of a string case/whitespace
// transform call (`<recv>.lower()`, `<recv>.upper()`, ...) — the value whose
// bounded-ness should be re-checked — or nil when the call is not such a
// transform. A transform with arguments (e.g. a custom `.lower(x)`) is not the
// builtin str method and is declined.
func caseTransformCallReceiver(call *ast.Node, cfg *langConfig) *ast.Node {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return nil
	}
	attr := fn.ChildByFieldName("attribute")
	if attr == nil || !caseTransformMethods[strings.TrimSpace(attr.Text())] {
		return nil
	}
	// The str case transforms take no positional argument; if any are present
	// this is some other method by the same name — decline (fail closed).
	if args := cfg.extractCallArgs(call); len(args) > 0 {
		return nil
	}
	return fn.ChildByFieldName("object")
}

// attrNameIsBounded recognises the two attribute-access bounded shapes:
//   - HTTP-verb: <request>.method  (the verb set is fixed/validated)
//   - model-metadata: field.name / column.name / col.name, or <x>.name where
//     <x> is a loop variable iterating a model-metadata collection.
func attrNameIsBounded(n *ast.Node, tm *taintMap, cfg *langConfig) bool {
	attr := n.ChildByFieldName("attribute")
	obj := n.ChildByFieldName("object")
	if attr == nil || obj == nil {
		return false
	}
	switch strings.TrimSpace(attr.Text()) {
	case "method":
		// HTTP-verb-bounded: request.method (Flask/Django dispatch). Require the
		// receiver to be a request object so an unrelated `x.method` is not
		// over-suppressed.
		return objIsRequestObject(obj)
	case "name":
		// model-metadata-bounded.
		return objIsFieldOrColumnVar(obj, n)
	}
	return false
}

// objIsRequestObject reports whether an attribute-access object is the HTTP
// request object: a bare `request` / `req`, or a chain ending in `.request` /
// `.req` (e.g. `self.request`). Case-insensitive on the identifier text.
func objIsRequestObject(obj *ast.Node) bool {
	t := strings.ToLower(strings.TrimSpace(obj.Text()))
	return t == "request" || t == "req" ||
		strings.HasSuffix(t, ".request") || strings.HasSuffix(t, ".req")
}

// objIsFieldOrColumnVar reports whether the object of a `.name` access is a
// model field/column variable: a canonical bare name (field/column/col/...), or
// a loop variable bound by `for <x> in <model-metadata collection>`.
func objIsFieldOrColumnVar(obj, attrNode *ast.Node) bool {
	if obj.Type() != "identifier" {
		return false
	}
	name := strings.TrimSpace(obj.Text())
	if name == "" {
		return false
	}
	if fieldColumnVarNames[strings.ToLower(name)] {
		return true
	}
	return identBoundByMetadataLoop(attrNode, name)
}

// identBoundByMetadataLoop reports whether `name` is the loop variable of an
// enclosing `for <name> in <iterable>` whose iterable text identifies a model-
// metadata collection (see metadataIterableMarkers). Walks the ancestor chain
// (bounded by tree depth) so `for f in Model._meta.fields: getattr(o, f.name)`
// is recognised.
func identBoundByMetadataLoop(node *ast.Node, name string) bool {
	for _, anc := range node.Ancestors() {
		if anc.Type() != "for_statement" {
			continue
		}
		left := anc.ChildByFieldName("left")
		right := anc.ChildByFieldName("right")
		if left == nil || right == nil {
			continue
		}
		if strings.TrimSpace(left.Text()) != name {
			continue
		}
		rt := right.Text()
		for _, m := range metadataIterableMarkers {
			if strings.Contains(rt, m) {
				return true
			}
		}
	}
	return false
}

// subscriptIsDispatchTable reports whether a subscript name argument indexes a
// LITERAL dispatch table: `D[k]` where `D` is a BARE identifier bound to a
// dict/list/tuple/set literal in scope (a hand-written method-name table). The
// bare-identifier requirement excludes the attacker shape `request.args['x']`
// (whose object is the attribute `request.args`, not a bare identifier), and a
// tainted base is rejected outright.
func subscriptIsDispatchTable(n *ast.Node, tm *taintMap) bool {
	obj := n.ChildByFieldName("value")
	if obj == nil {
		obj = n.ChildByFieldName("object")
	}
	if obj == nil || obj.Type() != "identifier" {
		return false
	}
	name := strings.TrimSpace(obj.Text())
	if name == "" {
		return false
	}
	// A tainted dict variable is attacker data, not a fixed dispatch table.
	if ts := tm.get(name); ts != nil && ts.source != nil {
		return false
	}
	return identBoundToLiteralContainer(n, name)
}

// identBoundToLiteralContainer reports whether `name` is assigned a literal
// container (dict/list/tuple/set) somewhere in the enclosing function/module
// scope. Conservative: it confirms a literal binding exists; combined with the
// subscriptIsDispatchTable not-tainted check, this proves the indexed table is a
// hand-written dispatch map whose values are fixed method names.
func identBoundToLiteralContainer(node *ast.Node, name string) bool {
	var scope *ast.Node
	for _, anc := range node.Ancestors() {
		if anc.Type() == "function_definition" || anc.Type() == "module" {
			scope = anc
			break
		}
	}
	if scope == nil {
		return false
	}
	found := false
	var walk func(*ast.Node)
	walk = func(x *ast.Node) {
		if x == nil || found {
			return
		}
		if x.Type() == "assignment" {
			left := x.ChildByFieldName("left")
			right := x.ChildByFieldName("right")
			if left != nil && right != nil &&
				left.Type() == "identifier" &&
				strings.TrimSpace(left.Text()) == name &&
				literalContainerTypes[right.Type()] {
				found = true
				return
			}
		}
		for i := 0; i < x.ChildCount(); i++ {
			walk(x.Child(i))
		}
	}
	walk(scope)
	return found
}
