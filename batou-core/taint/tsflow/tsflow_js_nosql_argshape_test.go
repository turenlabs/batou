package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"

	// Register taint catalogs (JS sinks/sources/sanitizers).
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestArgShapeGate_JSMongoFind is the load-bearing end-to-end assertion for the
// JS/TS MongoDB find()/findOne()/... container gate (the JS counterpart of
// TestArgShapeGate_PHPMongoFind). The genuine NoSQL-injection container forms
// (a `$`-operator object literal, or a whole tainted filter object) fire
// CWE-943; the pervasive SAFE parameterized-equality form and the
// Array.prototype.find callback do not — even when a tainted value is in scope.
//
// hasNoSQLFlow is defined in tsflow_argshape_test.go (same package).
func TestArgShapeGate_JSMongoFind(t *testing.T) {
	// ── RECALL: container forms MUST fire ──────────────────────────────────

	t.Run("dollar_where_object_literal_fires", func(t *testing.T) {
		// Object literal carrying a `$where` operator key whose value is tainted
		// — server-side JS execution, the canonical Mongo NoSQL-injection shape.
		code := `
app.post('/x', (req, res) => {
    const q = req.query.q;
    db.collection('allocations').find({$where: q});
});`
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if !hasNoSQLFlow(flows) {
			t.Fatalf("expected CWE-943 NoSQL flow for find({$where: tainted}); got none: %+v", flows)
		}
	})

	t.Run("dollar_where_template_literal_fires", func(t *testing.T) {
		// The NodeGoat allocations-dao shape: `{$where: ` + template with a
		// tainted interpolation.
		code := "\napp.post('/x', (req, res) => {\n" +
			"    const threshold = req.query.threshold;\n" +
			"    db.collection('allocations').find({$where: `this.stocks > '${threshold}'`});\n" +
			"});"
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if !hasNoSQLFlow(flows) {
			t.Fatalf("expected CWE-943 NoSQL flow for find({$where: `...${tainted}`}); got none: %+v", flows)
		}
	})

	t.Run("whole_tainted_object_var_fires", func(t *testing.T) {
		// The whole filter argument is a tainted request object — operator
		// injection (`{$ne: null}` auth bypass), the dominant Express+Mongo
		// vector. A bare variable is not an object literal, so the gate KEEPs it
		// and taint decides the fire.
		code := `
app.post('/login', (req, res) => {
    const filter = req.body;
    db.collection('users').findOne(filter);
});`
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if !hasNoSQLFlow(flows) {
			t.Fatalf("expected CWE-943 NoSQL flow for findOne(taintedReqObject); got none: %+v", flows)
		}
	})

	// ── PRECISION: each negative carries a genuinely TAINTED value in scope,
	// so the gate is what SUPPRESSES the fire (not an absent source). ────────

	t.Run("array_prototype_find_callback_does_not_fire", func(t *testing.T) {
		// Array.prototype.find(callback) — the arg is an arrow function, not a
		// query document. Must NOT fire even though `q` is tainted.
		code := `
app.get('/x', (req, res) => {
    const q = req.query.q;
    const hit = [1, 2, 3].find(x => x === q);
    res.send(hit);
});`
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for [].find(x => x === tainted); got: %+v", flows)
		}
	})

	t.Run("parameterized_equality_scalar_does_not_fire", func(t *testing.T) {
		// `find({_id: req.params.id})` — parameterized equality on a plain field
		// key. Pervasive and SAFE in Mongo (the value is an opaque equality
		// operand). The object literal has no `$`-operator key, so the gate
		// DROPS it even though `id` is tainted.
		code := `
app.get('/users/:id', (req, res) => {
    const id = req.params.id;
    db.collection('users').find({_id: id});
});`
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for find({_id: tainted scalar}); got: %+v", flows)
		}
	})

	t.Run("multi_field_equality_scalar_does_not_fire", func(t *testing.T) {
		// A multi-field equality filter (all plain keys) — still the safe form.
		code := `
app.post('/search', (req, res) => {
    const name = req.body.name;
    const city = req.body.city;
    db.collection('people').find({name: name, city: city});
});`
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for find({name: t, city: t}); got: %+v", flows)
		}
	})

	t.Run("ternary_locally_built_regex_filter_does_not_fire", func(t *testing.T) {
		// The idiomatic Mongoose search (bezkoder node-express-mongodb): a
		// locally-built filter assigned via a ternary of plain-key object
		// literals — `cond = title ? {title: {$regex: ...}} : {}` — then
		// `find(cond)`. The top-level key is the plain field name, so this is the
		// per-field regex-search form, not operator/code injection. The variable
		// resolver classifies `cond` through the ternary branches (both plain
		// keys) and DROPs it, even though `cond` is tainted via `new RegExp(q)`.
		code := `
app.get('/tutorials', (req, res) => {
    const title = req.query.title;
    var condition = title ? { title: { $regex: new RegExp(title), $options: "i" } } : {};
    db.collection('tutorials').find(condition);
});`
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for find(localTernaryFilter); got: %+v", flows)
		}
	})

	t.Run("var_assigned_dollar_where_object_fires", func(t *testing.T) {
		// Recall through the resolver: a variable assigned an object literal
		// carrying `$where` still fires (`q = {$where: t}; find(q)`).
		code := `
app.post('/x', (req, res) => {
    const t = req.query.t;
    const q = {$where: t};
    db.collection('c').find(q);
});`
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if !hasNoSQLFlow(flows) {
			t.Fatalf("expected CWE-943 NoSQL flow for q={$where:t}; find(q); got none: %+v", flows)
		}
	})

	t.Run("string_coerced_value_does_not_fire", func(t *testing.T) {
		// `String(...)` coercion defeats operator injection (an object coerces
		// to "[object Object]"); the SnkNoSQL sanitizer neutralizes the flow.
		code := `
app.post('/login', (req, res) => {
    db.collection('users').findOne({$where: String(req.body.q)});
});`
		flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
		if hasNoSQLFlow(flows) {
			t.Fatalf("did NOT expect CWE-943 NoSQL flow for findOne({$where: String(tainted)}); got: %+v", flows)
		}
	})
}
