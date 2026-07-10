package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"

	"github.com/turenlabs/batou-rules/rules"

	"github.com/turenlabs/batou-core/taint"
)

// Inline ATTRIBUTE/subscript source spliced into a RAW SQL string at the sink —
// via template-literal interpolation OR string concatenation — must fire the
// SQL-injection flow at the dataflow tier (CWE-89).
//
// This is the flagship OWASP Juice Shop SQLi shape (routes/login.ts:34):
//
//	models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' ...`)
//
// Before this fix it was dataflow-INVISIBLE (regex-hint-only, hidden by default
// in `bin/batou scan`): findSourceInExpr deliberately excludes attribute/
// subscript sources from its binary/interpolation recursion to keep the
// field-sensitive access-path map authoritative (so `x=req.body.a;
// db.query("..."+req.body.b)` does not collapse a sibling field). The fix wires
// the category-scoped inline-concat resolver (findInlineConcatSource) for
// SnkSQLQuery the same way it already runs for SnkCommand / SnkRedirect — gated
// on no SIBLING field of the same request source being tracked in scope, so the
// field-sensitivity contract (TestMultiLevelField_*) is preserved.
func TestSQLInlineTemplateSource_Positive(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// template-literal interpolation, attribute source, generic .query
			name: "js-query-template-attr",
			code: "function h(req, db){\n  db.query(`SELECT * FROM u WHERE id = '${req.body.id}'`);\n}",
		},
		{
			// the exact Juice Shop login shape: sequelize.query + template + req.body
			name: "js-sequelize-query-template",
			code: "function login(req, models){\n  models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' AND deletedAt IS NULL`);\n}",
		},
		{
			// string concatenation, attribute source, inline at sink
			name: "js-query-concat-attr",
			code: "function h(req, db){\n  db.query(\"SELECT * FROM u WHERE id = '\" + req.body.id + \"'\");\n}",
		},
		{
			// subscript source in template
			name: "js-query-template-subscript",
			code: "function h(req, db){\n  db.query(`SELECT * FROM u WHERE name = '${req.query['name']}'`);\n}",
		},
		{
			// knex.raw with template + attribute source
			name: "js-knex-raw-template",
			code: "function h(req, knex){\n  knex.raw(`SELECT * FROM u WHERE id = ${req.params.id}`);\n}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !concatFlow(t, rules.LangJavaScript, "/app/h.js", tc.code, taint.SnkSQLQuery) {
				t.Errorf("expected CWE-89 SQL flow for inline source in %s, got none", tc.name)
			}
		})
	}
}

// Field-sensitivity contract guard (the FP this fix must NOT introduce): when a
// SIBLING field of the same request source was read into a local earlier, an
// inline read of a different field at the SQL sink must stay clean. This is the
// scenario the SnkSQLQuery gate (sourceFieldTrackedInScope) preserves; without
// the gate, enabling the inline-concat resolver for SQL would collapse the
// sibling field and reintroduce the TestMultiLevelField_* false positives.
func TestSQLInlineTemplateSource_SiblingExcluded(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// sibling via concat (mirrors TestConcatSourceAtSink_AttributeSiblingExcluded)
			name: "js-sibling-concat",
			code: "function h(req, db){\n  const x = req.body.a;\n  db.query(\"SELECT * FROM t WHERE c = \" + req.body.b);\n}",
		},
		{
			// sibling via template literal
			name: "js-sibling-template",
			code: "function h(req, db){\n  const x = req.body.a;\n  db.query(`SELECT * FROM t WHERE c = '${req.body.b}'`);\n}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if concatFlow(t, rules.LangJavaScript, "/app/h.js", tc.code, taint.SnkSQLQuery) {
				t.Errorf("FP: sibling field flagged in %s — field-sensitivity contract broken", tc.name)
			}
		})
	}
}

// Safe-form negatives: parameterized queries and constant SQL must NOT fire.
// The user value travels in the params array (`?` / `$1` placeholder), so the
// SQL TEMPLATE itself carries no taint; a pure-literal query has no source.
func TestSQLInlineTemplateSource_SafeForms(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// parameterized: user value in the values array, constant template
			name: "js-parameterized-placeholder",
			code: "function h(req, db){\n  db.query(\"SELECT * FROM u WHERE id = ?\", [req.body.id]);\n}",
		},
		{
			// pure-literal query, no taint
			name: "js-constant-query",
			code: "function h(db){\n  db.query(\"SELECT * FROM users WHERE active = 1\");\n}",
		},
		{
			// sequelize parameterized replacements — constant template
			name: "js-sequelize-replacements",
			code: "function h(req, models){\n  models.sequelize.query(\"SELECT * FROM u WHERE id = :id\", { replacements: { id: req.body.id } });\n}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if concatFlow(t, rules.LangJavaScript, "/app/h.js", tc.code, taint.SnkSQLQuery) {
				t.Errorf("expected NO SQL flow for safe form %s, but a flow was reported", tc.name)
			}
		})
	}
}
