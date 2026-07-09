package scanner_test

// Recall + precision contract for CONCAT-/TEMPLATE-THEN-ASSIGN taint with an
// ATTRIBUTE/SUBSCRIPT source operand. The flagship shape is the single most
// common injection idiom (DVNA userSearch):
//
//	var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";
//	db.sequelize.query(query);   // <- SQL injection (CWE-89)
//
// Before the fix, findSourceInExpr deliberately excluded attribute/subscript
// sources from its binary/interpolation recursion (to keep the field-sensitive
// access-path map authoritative for INLINE-at-sink reads), so a concat ASSIGNED
// to a local never tainted that local — the flow was dataflow-invisible (only
// the regex/AST tier saw it). The fix taints the LHS local when a concat/template
// RHS contains an attribute/subscript source, keyed under the LHS NAME so the
// field-sensitivity sibling contract (TestMultiLevelField_*) is preserved.
//
// firesSQLi is shared with tsflow_multilevel_field_test.go (same package).

import "testing"

// TestConcatAttrAssign_JS_Fires is the headline recall case: an attribute source
// concatenated into a SQL string, assigned to a local, then handed to a query
// sink, must now produce a dataflow-confirmed CWE-89 finding.
func TestConcatAttrAssign_JS_Fires(t *testing.T) {
	src := `function handle(req, res) {
  var q = "SELECT * FROM Users WHERE login='" + req.body.login + "'";
  db.query(q);
}`
	if !firesSQLi(t, "/app/handler.js", src) {
		t.Error("recall loss: concat-then-assign req.body.login -> db.query(q) " +
			"must flag (the canonical DVNA Sequelize SQLi shape)")
	}
}

// TestConcatAttrAssign_JS_TemplateFires covers the template-literal form of the
// same shape (`var q = ` + "`...${req.body.login}...`" + `; db.query(q)`).
func TestConcatAttrAssign_JS_TemplateFires(t *testing.T) {
	src := "function handle(req, res) {\n" +
		"  var q = `SELECT * FROM Users WHERE login='${req.body.login}'`;\n" +
		"  db.query(q);\n" +
		"}"
	if !firesSQLi(t, "/app/handler.js", src) {
		t.Error("recall loss: template-literal-then-assign req.body.login -> " +
			"db.query(q) must flag")
	}
}

// TestConcatAttrAssign_JS_SiblingInlineAfterConcatNotTainted is the precision
// guard proving the INLINE-at-sink path was NOT loosened: a concat-assign of one
// field (req.body.a) must not cause a SIBLING field (req.body.b) read INLINE at
// the sink to fire. If this regresses, the fix leaked into the inline resolver
// or collapsed the access path to the bare source prefix.
func TestConcatAttrAssign_JS_SiblingInlineAfterConcatNotTainted(t *testing.T) {
	src := `function handle(req, res) {
  const x = "prefix " + req.body.a;
  db.query("SELECT * FROM t WHERE c = " + req.body.b);
}`
	if firesSQLi(t, "/app/handler.js", src) {
		t.Error("FP: inline sibling req.body.b flagged after a concat-assign of " +
			"req.body.a (inline-at-sink path must stay field-sensitive)")
	}
}

// TestConcatAttrAssign_JS_SiblingObjectReadNotTainted: tainting `q` from a concat
// of req.body.a must NOT taint a later inline read of the sibling req.body.other
// at a different sink — the LHS taint must be keyed under the local name, never
// the bare `req.body` prefix.
func TestConcatAttrAssign_JS_SiblingObjectReadNotTainted(t *testing.T) {
	src := `function handle(req, res) {
  const q = "id=" + req.body.a;
  db.query("SELECT * FROM t WHERE o = " + req.body.other);
}`
	if firesSQLi(t, "/app/handler.js", src) {
		t.Error("FP: sibling req.body.other flagged when only req.body.a was " +
			"concat-assigned to a local (taint must not collapse to req.body)")
	}
}

// TestConcatAttrAssign_Python_SubscriptFires confirms the mechanism is
// language-agnostic: a subscript source concatenated into a SQL string and
// assigned, then executed, must flag.
func TestConcatAttrAssign_Python_SubscriptFires(t *testing.T) {
	src := `from flask import request

def handler():
    q = "SELECT * FROM t WHERE c = '" + request.args['name'] + "'"
    cursor.execute(q)
`
	if !firesSQLi(t, "/app/handler.py", src) {
		t.Error("recall loss: Python concat-then-assign request.args['name'] -> " +
			"cursor.execute(q) must flag")
	}
}

// TestConcatAttrAssign_Python_SafeConstNotTainted is the precision guard: a
// concat of only literals/constants (no source operand) must not taint the local.
func TestConcatAttrAssign_Python_SafeConstNotTainted(t *testing.T) {
	src := `def handler():
    col = "name"
    q = "SELECT * FROM t WHERE c = '" + col + "'"
    cursor.execute(q)
`
	if firesSQLi(t, "/app/handler.py", src) {
		t.Error("FP: literal/constant-only concat assigned to q flagged as SQLi")
	}
}
