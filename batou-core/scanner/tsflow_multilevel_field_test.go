package scanner_test

// Scanner-level integration tests for tsflow's BOUNDED MULTI-LEVEL access-path
// field sensitivity. These exercise the full scan pipeline (parse -> tsflow
// taint -> findings) rather than the tsflow engine in isolation, so they pin
// the end-to-end behaviour that `bin/batou scan` produces.
//
// The precision contract under test: tainting one multi-level access path
// (`req.body.a`, `req.body.user.id`) must NOT taint a SIBLING path
// (`req.body.b`, `req.body.user.name`) read at a sink, while the SAME path
// (and deeper sub-paths of a tainted prefix) must still be detected. A
// 1-level/receiver-collapsing engine flags the sibling — the FP this change
// eliminates. Recall for the same-path flow is preserved.

import (
	"strings"
	"testing"

	_ "github.com/turenlabs/batou-core/taintrule"
	"github.com/turenlabs/batou-core/testutil"
)

// firesSQLi reports whether the scan produced a dataflow-confirmed SQL-injection
// finding for the given source. We key on the TAINT/interproc rule families
// (BATOU-TAINT-*, BATOU-INTERPROC-*) — NOT the regex-tier BATOU-INJ-* rule,
// which flags string-concat-into-query syntactically regardless of taint and
// is hidden by default in `bin/batou scan`. This is the layer that the bounded
// multi-level access-path change governs, so it is the layer the precision and
// recall assertions must observe.
func firesSQLi(t *testing.T, path, src string) bool {
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

// TestMultiLevelField_JS_SiblingNotTainted is the headline precision case:
// only `req.body.a` is read into a local; the sink reads the sibling
// `req.body.b`. A bounded access-path engine must NOT flag this.
func TestMultiLevelField_JS_SiblingNotTainted(t *testing.T) {
	src := `function handle(req, res) {
  const x = req.body.a;
  db.query("SELECT * FROM t WHERE c = " + req.body.b);
}`
	if firesSQLi(t, "/app/handler.js", src) {
		t.Error("FP: sibling field req.body.b flagged when only req.body.a was read " +
			"(bounded multi-level access path should keep siblings distinct)")
	}
}

// TestMultiLevelField_JS_SamePathTainted is the recall guard for the headline
// case: reading the SAME path at the sink must still flag.
func TestMultiLevelField_JS_SamePathTainted(t *testing.T) {
	src := `function handle(req, res) {
  const x = req.body.a;
  db.query("SELECT * FROM t WHERE c = " + req.body.a);
}`
	if !firesSQLi(t, "/app/handler.js", src) {
		t.Error("recall loss: same path req.body.a -> db.query must flag")
	}
}

// TestMultiLevelField_JS_Depth3SiblingNotTainted exercises the depth-3
// distinction that a 1-level engine cannot make: req.body.user.id tainted,
// req.body.user.name read at sink — sibling, must not flag.
func TestMultiLevelField_JS_Depth3SiblingNotTainted(t *testing.T) {
	src := `function handle(req, res) {
  const id = req.body.user.id;
  db.query("SELECT * FROM t WHERE n = " + req.body.user.name);
}`
	if firesSQLi(t, "/app/handler.js", src) {
		t.Error("FP: depth-3 sibling req.body.user.name flagged when only " +
			"req.body.user.id was read")
	}
}

// TestMultiLevelField_JS_Depth3SamePathTainted is the depth-3 recall guard.
func TestMultiLevelField_JS_Depth3SamePathTainted(t *testing.T) {
	src := `function handle(req, res) {
  const id = req.body.user.id;
  db.query("SELECT * FROM t WHERE i = " + req.body.user.id);
}`
	if !firesSQLi(t, "/app/handler.js", src) {
		t.Error("recall loss: same depth-3 path req.body.user.id must flag")
	}
}

// TestMultiLevelField_JS_SubPathOfTaintedPrefixTainted verifies the prefix
// rule: tainting `req.body.user` must taint a deeper read `req.body.user.id`
// (a sub-path of the tainted prefix). This is the conservative direction that
// preserves recall — narrowing must never lose a real flow.
func TestMultiLevelField_JS_SubPathOfTaintedPrefixTainted(t *testing.T) {
	src := `function handle(req, res) {
  const u = req.body.user;
  db.query("SELECT * FROM t WHERE i = " + req.body.user.id);
}`
	if !firesSQLi(t, "/app/handler.js", src) {
		t.Error("recall loss: sub-path req.body.user.id of tainted prefix " +
			"req.body.user must flag")
	}
}

// TestMultiLevelField_JS_SiblingUnderTaintedPrefixNotTainted: tainting
// `req.body.user` must NOT taint the sibling `req.body.other`.
func TestMultiLevelField_JS_SiblingUnderTaintedPrefixNotTainted(t *testing.T) {
	src := `function handle(req, res) {
  const u = req.body.user;
  db.query("SELECT * FROM t WHERE o = " + req.body.other);
}`
	if firesSQLi(t, "/app/handler.js", src) {
		t.Error("FP: sibling req.body.other flagged when only req.body.user was read")
	}
}

// TestMultiLevelField_Python_SiblingNotTainted confirms the mechanism is
// language-agnostic: the same precision applies to Python attribute access.
func TestMultiLevelField_Python_SiblingNotTainted(t *testing.T) {
	src := `from flask import request

def handler():
    x = request.args.a
    cursor.execute("SELECT * FROM t WHERE c = " + request.args.b)
`
	if firesSQLi(t, "/app/handler.py", src) {
		t.Error("FP: Python sibling request.args.b flagged when only request.args.a was read")
	}
}

// TestMultiLevelField_Python_SamePathTainted is the Python recall guard.
func TestMultiLevelField_Python_SamePathTainted(t *testing.T) {
	src := `from flask import request

def handler():
    x = request.args.a
    cursor.execute("SELECT * FROM t WHERE c = " + request.args.a)
`
	if !firesSQLi(t, "/app/handler.py", src) {
		t.Error("recall loss: Python same path request.args.a must flag")
	}
}
