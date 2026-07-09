package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Augmented-assignment (`q += tainted`) taint propagation for JS/TS.
//
// `+=` is the dominant string-building idiom in JavaScript/TypeScript
// (assembling SQL, HTML, shell commands, URLs). tree-sitter parses it as an
// `augmented_assignment_expression`, a distinct node from `assignment_expression`.
// Before the langconfig fix, that node type was absent from the JS config's
// assignTypes set, so a clean variable accumulating a tainted operand via `+=`
// was a silent false negative — even though the desugared `q = q + tainted`
// form was already detected.

// FN that the fix closes: untainted base accumulates a tainted operand via +=.
func TestJS_AugmentedAssign_TaintedRHS_SQLi(t *testing.T) {
	code := `
function handler(req, res) {
    let name = req.query.name;
    let q = "SELECT * FROM users WHERE name = ";
    q += name;
    db.query(q);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for req.query -> q += name -> db.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Command-injection variant of the same += accumulation.
func TestJS_AugmentedAssign_TaintedRHS_CmdInjection(t *testing.T) {
	code := `
function handler(req, res) {
    let name = req.query.name;
    let cmd = "ls ";
    cmd += name;
    child_process.exec(cmd);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for req.query -> cmd += name -> exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Taint introduced directly on the RHS of += (no intermediate variable).
func TestJS_AugmentedAssign_DirectSourceRHS(t *testing.T) {
	code := `
function handler(req, res) {
    let q = "SELECT ";
    q += req.query.name;
    db.query(q);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for q += req.query.name -> db.query")
	}
}

// TypeScript shares the JS config, so the same idiom must be detected.
func TestTS_AugmentedAssign_TaintedRHS_SQLi(t *testing.T) {
	code := `
function handler(req: any, res: any) {
    let name = req.query.name;
    let q = "SELECT * FROM users WHERE name = ";
    q += name;
    db.query(q);
}
`
	flows := Analyze(code, "/app/handler.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow (TS) for req.query -> q += name -> db.query")
	}
}

// Regression guard: a base that is ALREADY tainted, then `+=` of an untainted
// literal, must keep its accumulated taint. `+=` reads the prior value, so the
// untainted RHS must not clear it. (This case passed before the fix only
// because the node was ignored entirely; it must keep passing now that the
// node is processed as an assignment.)
func TestJS_AugmentedAssign_TaintedBase_KeepsTaint(t *testing.T) {
	code := `
function handler(req, res) {
    let q = req.query.name;
    q += " ORDER BY id";
    db.query(q);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected accumulated taint to survive `q += <literal>` after q = req.query.name")
	}
}

// Negative control: an entirely constant += chain must NOT produce a flow.
func TestJS_AugmentedAssign_AllConstant_NoFlow(t *testing.T) {
	code := `
function handler(req, res) {
    let q = "SELECT ";
    q += " FROM users";
    db.query(q);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("constant += chain must not produce a SQL injection flow (false positive)")
	}
}

// Negative control: a numeric-coerced (sanitized) operand added via += must
// NOT flow — parseInt strips the SQL-injection taint.
func TestJS_AugmentedAssign_SanitizedRHS_NoFlow(t *testing.T) {
	code := `
function handler(req, res) {
    let id = parseInt(req.query.id, 10);
    let q = "SELECT * FROM users WHERE id = ";
    q += id;
    db.query(q);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("parseInt-sanitized operand added via += must not produce a SQL injection flow")
	}
}
