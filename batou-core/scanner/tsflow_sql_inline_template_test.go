package scanner_test

// Scanner-level integration test for the inline-template/concat SQL-injection
// recall fix (CWE-89). It exercises the full scan pipeline (parse -> tsflow
// taint -> findings) so it pins the end-to-end behaviour `bin/batou scan`
// produces — the dataflow (BATOU-TAINT-*) tier, NOT the regex-tier BATOU-INJ-*
// rule which fires syntactically and is hidden by default.
//
// Ground truth: OWASP Juice Shop routes/login.ts:34
//
//	models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}' ...`)
//
// Before the fix this produced 0 dataflow CWE-89 findings (regex-hint-only,
// conf=medium, hidden by `bin/batou scan`); after, it fires
// BATOU-TAINT-sql_query at conf=high.

import (
	"strings"
	"testing"

	_ "github.com/turenlabs/batou-core/taintrule"
	"github.com/turenlabs/batou-core/testutil"
)

// firesDataflowSQLi reports whether the scan produced a dataflow-confirmed
// CWE-89 finding (BATOU-TAINT-* / BATOU-INTERPROC-*), not the regex-tier
// BATOU-INJ-* rule. Mirrors firesSQLi in tsflow_multilevel_field_test.go.
func firesDataflowSQLi(t *testing.T, path, src string) bool {
	t.Helper()
	res := testutil.ScanContent(t, path, src)
	for _, f := range res.Findings {
		if f.CWEID != "CWE-89" {
			continue
		}
		if strings.HasPrefix(f.RuleID, "BATOU-TAINT-") ||
			strings.HasPrefix(f.RuleID, "BATOU-INTERPROC-") {
			return true
		}
	}
	return false
}

// TestSQLInlineTemplate_JuiceShopLoginShape is the headline recall case: the
// exact Juice Shop login SQLi — a req.body field interpolated into a raw
// sequelize.query template literal with no intervening variable — must fire at
// the dataflow tier.
func TestSQLInlineTemplate_JuiceShopLoginShape(t *testing.T) {
	src := `function login(req, models) {
  return models.sequelize.query(` + "`SELECT * FROM Users WHERE email = '${req.body.email}' AND deletedAt IS NULL`" + `, { plain: true });
}`
	if !firesDataflowSQLi(t, "/app/routes/login.ts", src) {
		t.Error("recall loss: inline req.body.email in a raw sequelize.query template " +
			"must produce a dataflow CWE-89 finding (Juice Shop login SQLi shape)")
	}
}

// TestSQLInlineTemplate_GenericQueryConcat covers the concatenation form into a
// generic .query sink.
func TestSQLInlineTemplate_GenericQueryConcat(t *testing.T) {
	src := `function handle(req, db) {
  db.query("SELECT * FROM u WHERE id = '" + req.body.id + "'");
}`
	if !firesDataflowSQLi(t, "/app/handler.js", src) {
		t.Error("recall loss: inline req.body.id concatenated into db.query must fire dataflow CWE-89")
	}
}

// TestSQLInlineTemplate_SiblingStaysClean is the field-sensitivity guard: when a
// SIBLING field was read into a local earlier, an inline read of a different
// field at the SQL sink must NOT fire (TestMultiLevelField_* contract). This is
// the FP the fix's sourceFieldTrackedInScope gate must keep suppressed.
func TestSQLInlineTemplate_SiblingStaysClean(t *testing.T) {
	src := `function handle(req, db) {
  const x = req.body.a;
  db.query(` + "`SELECT * FROM t WHERE c = '${req.body.b}'`" + `);
}`
	if firesDataflowSQLi(t, "/app/handler.js", src) {
		t.Error("FP: sibling field req.body.b flagged when only req.body.a was read " +
			"(inline-template SQL gate must preserve field-sensitivity)")
	}
}

// TestSQLInlineTemplate_ParameterizedStaysClean: the safe parameterized form
// (user value in the values array, constant SQL template) must stay clean.
func TestSQLInlineTemplate_ParameterizedStaysClean(t *testing.T) {
	src := `function handle(req, db) {
  db.query("SELECT * FROM u WHERE id = ?", [req.body.id]);
}`
	if firesDataflowSQLi(t, "/app/handler.js", src) {
		t.Error("FP: parameterized query (constant template, value in params array) must stay clean")
	}
}
