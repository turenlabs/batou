package jsast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// This file implements two AST-grounded structural checks that the catalog's
// function/method-name taint model cannot express, because the dangerous
// element is a COMPUTED PROPERTY KEY (or a computed method selector) rather
// than a named call:
//
//   BATOU-JSAST-007 — prototype-polluting / remote-property-injection
//                      assignment: obj[<tainted key>] = v   (CWE-1321 / CWE-471)
//   BATOU-JSAST-008 — unsafe dynamic method/function dispatch:
//                      obj[<tainted key>](...)               (CWE-94 / CWE-749)
//
// Both fire ONLY when the computed key is (a) NOT a string literal and (b)
// structurally derived from request input — either a member-access chain into
// a known request object (req.query.field, req.body.k) or a for-in loop
// variable iterating over such an object (`for (const k in req.body) obj[k]=…`).
// A constant key (obj.foo, obj["const"]), an array index from a numeric for
// loop (arr[i]=data[i]), or a key from a non-request variable never matches.
// This is deliberately conservative — it has no taint engine, so it recognises
// only request-derived key shapes that are attacker-controlled by construction.

// jsRequestRootIdents are identifiers whose member-access chains carry request
// (attacker-controlled) data in the dominant Node/Express idioms. Root-anchored
// so an arbitrary `foo.bar` does not match. Deliberately limited to the
// unambiguous HTTP-request roots `req`/`request`: `ctx`/`context` are heavily
// overloaded (React/Vue context, generic handler params, typed DTOs) and
// matching them as a request root produced false positives on internal typed
// parameters (e.g. `scopesById[context.projectId]=[]` where `context` is a
// `{ projectId: string }` arg). Request data carried under a generic root is
// still caught by the request-SEGMENT check below (req.body / .query / etc).
var jsRequestRootIdents = map[string]bool{
	"req":     true,
	"request": true,
}

// jsRequestSegments are property names that, appearing anywhere in a member
// chain, denote a request-data container. A chain like `req.body.x`,
// `ctx.query.y`, or a destructured `body.k` / `query.field` matches. These are
// the standard request sub-objects across Express/Koa/Fastify/Next.
var jsRequestSegments = map[string]bool{
	"body":    true,
	"query":   true,
	"params":  true,
	"headers": true,
	"cookies": true,
	"payload": true,
}

// jsExprFromRequestSource reports whether the expression node is a member-access
// chain that reads request (attacker-controlled) data. True when:
//   - the chain's ROOT identifier is a known HTTP-request object (req/request),
//     e.g. `req.query.field`, `request.params.id`; OR
//   - ANY property segment of the chain is a request container
//     (body/query/params/headers/cookies/payload), covering destructured forms
//     like `query.field` and deeper chains under a generic root such as
//     `event.payload.id` or `data.body.x`.
//
// A bare identifier, a literal, or a chain with neither a request root nor a
// request segment returns false.
func jsExprFromRequestSource(n *ast.Node) bool {
	if n == nil {
		return false
	}
	if n.Type() != "member_expression" {
		return false
	}
	root := jsMemberRootIdent(n)
	if root != "" && jsRequestRootIdents[strings.ToLower(root)] {
		return true
	}
	// Walk the property segments of the chain.
	cur := n
	for cur != nil && cur.Type() == "member_expression" {
		if prop := memberProperty(cur); prop != "" && jsRequestSegments[strings.ToLower(prop)] {
			return true
		}
		cur = firstNamedChild(cur)
	}
	return false
}

// jsMemberRootIdent returns the leftmost identifier of a member-access chain
// (the receiver root), or "" if the chain does not bottom out in a plain
// identifier (e.g. it starts with a call or subscript).
func jsMemberRootIdent(n *ast.Node) string {
	cur := n
	for cur != nil {
		switch cur.Type() {
		case "identifier":
			return cur.Text()
		case "member_expression":
			cur = firstNamedChild(cur)
		default:
			return ""
		}
	}
	return ""
}

// subscriptParts returns the base and key nodes of a subscript_expression
// (`base[key]`). Tree-sitter exposes them as named children 0 and 1 with no
// field names. Returns (nil, nil) when the node is not a 2-child subscript.
func subscriptParts(n *ast.Node) (base *ast.Node, key *ast.Node) {
	if n == nil || n.Type() != "subscript_expression" {
		return nil, nil
	}
	named := n.NamedChildren()
	if len(named) < 2 {
		return nil, nil
	}
	return named[0], named[1]
}

// jsKeyIsTaintedKey reports whether a subscript KEY expression is attacker
// controlled by construction. forInKeys holds loop-variable names bound by an
// enclosing `for…in` over a request source. The key is tainted when it is a
// member-access into a request source (`obj[req.query.f]`) or a bare identifier
// that is one of those for-in keys (`for (const k in req.body) obj[k]=…`).
// A string literal, number, or any other identifier is NOT tainted.
func jsKeyIsTaintedKey(key *ast.Node, forInKeys map[string]bool) bool {
	if key == nil {
		return false
	}
	switch key.Type() {
	case "string", "number", "true", "false", "null", "undefined":
		return false
	case "identifier":
		return forInKeys[key.Text()]
	case "member_expression":
		return jsExprFromRequestSource(key)
	}
	return false
}

// jsBaseIsPlainObject reports whether the subscript base is a write target that
// is plausibly a plain object whose prototype can be polluted / whose arbitrary
// property is a security-relevant write. We accept a bare identifier or a
// member-access (obj, this.cfg, opts.data) and reject array literals, calls,
// and subscripts (which are typically array/collection element writes, not
// plain-object key writes).
func jsBaseIsPlainObject(base *ast.Node) bool {
	if base == nil {
		return false
	}
	switch base.Type() {
	case "identifier", "member_expression", "this":
		return true
	}
	return false
}

// collectForInRequestKeys walks the subtree rooted at fn and returns the set of
// loop-variable names bound by a `for…in` (or `for…of`) over a request source.
// `for (const k in req.body)` yields {k}. These names are attacker-controlled
// keys when used as a computed property.
func collectForInRequestKeys(root *ast.Node) map[string]bool {
	keys := map[string]bool{}
	if root == nil {
		return keys
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() != "for_in_statement" {
			return true
		}
		named := n.NamedChildren()
		if len(named) < 2 {
			return true
		}
		loopVar := named[0]
		iterable := named[1]
		// loopVar may be a plain identifier (`for (k in …)`) or a declaration
		// (`for (const k in …)`); pull the bound identifier either way.
		varName := ""
		switch loopVar.Type() {
		case "identifier":
			varName = loopVar.Text()
		default:
			if id := firstIdentDescendant(loopVar); id != nil {
				varName = id.Text()
			}
		}
		if varName == "" {
			return true
		}
		if jsExprFromRequestSource(iterable) {
			keys[varName] = true
		}
		return true
	})
	return keys
}

// firstIdentDescendant returns the first identifier node found in a small
// declaration subtree (used to pull `k` out of `const k`).
func firstIdentDescendant(n *ast.Node) *ast.Node {
	if n == nil {
		return nil
	}
	if n.Type() == "identifier" {
		return n
	}
	for _, c := range n.NamedChildren() {
		if id := firstIdentDescendant(c); id != nil {
			return id
		}
	}
	return nil
}

// checkDynamicProperty runs the two computed-key checks over the whole tree.
// It is called once per file from the checker walk.
func (c *jsChecker) checkDynamicProperty() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	forInKeys := collectForInRequestKeys(root)

	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "assignment_expression":
			c.checkProtoPollutingAssign(n, forInKeys)
		case "call_expression":
			c.checkDynamicDispatch(n, forInKeys)
		}
		return true
	})
}

// checkProtoPollutingAssign flags `base[<tainted key>] = value` where the key
// is request-derived and non-literal — the prototype-polluting /
// remote-property-injection shape (CWE-1321 / CWE-471).
func (c *jsChecker) checkProtoPollutingAssign(n *ast.Node, forInKeys map[string]bool) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	lhs := named[0]
	if lhs.Type() != "subscript_expression" {
		return
	}
	base, key := subscriptParts(lhs)
	if !jsBaseIsPlainObject(base) {
		return
	}
	if !jsKeyIsTaintedKey(key, forInKeys) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JSAST-007",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Prototype pollution via computed property assignment",
		Description:   "An object property is written using a computed key (obj[key] = value) where the key is derived from request input. An attacker who controls the key can set __proto__/constructor/prototype, polluting Object.prototype and corrupting unrelated objects across the application.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Reject keys equal to __proto__/constructor/prototype, use a null-prototype object (Object.create(null)) or a Map, or copy only an allowlist of known property names.",
		CWEID:         "CWE-1321",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"prototype-pollution", "injection", "ast"},
	})
}

// checkDynamicDispatch flags `base[<tainted key>](...)` where the method/function
// selector is request-derived and non-literal — unsafe dynamic dispatch
// (CWE-94 / CWE-749).
func (c *jsChecker) checkDynamicDispatch(n *ast.Node, forInKeys map[string]bool) {
	named := n.NamedChildren()
	if len(named) == 0 {
		return
	}
	callee := named[0]
	if callee.Type() != "subscript_expression" {
		return
	}
	base, key := subscriptParts(callee)
	if base == nil {
		return
	}
	if !jsKeyIsTaintedKey(key, forInKeys) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JSAST-008",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Unsafe dynamic method dispatch from request input",
		Description:   "A method/function is selected and invoked using a computed key (obj[name](...)) where the selector is derived from request input. An attacker who controls the selector can reach unintended methods (including inherited Object/Function methods), turning a dispatch table into arbitrary behaviour or code execution.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the selector against an explicit allowlist (e.g. `if (name in ALLOWED)` / a switch over known actions) and call own methods only — Object.prototype.hasOwnProperty.call(handlers, name) before handlers[name]().",
		CWEID:         "CWE-94",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"dynamic-dispatch", "injection", "ast"},
	})
}
