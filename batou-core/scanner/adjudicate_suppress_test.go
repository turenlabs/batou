package scanner_test

// adjudicate_suppress_test.go — scanner-level (full-pipeline) coverage for
// Write-time adjudicated suppression. These tests drive
// scanner.Scan() end-to-end (the same entry point `bin/batou scan` uses), NOT
// the suppress package in isolation, so the lever cannot silently regress to
// unit-test-only.
//
// The contract: when a `// batou:ignore RULE -- <reason>` suppresses a taint
// finding and the stated reason is contradicted by the suppressed finding's own
// dataflow, scanner.Scan emits a BATOU-SUPPRESS-UNJUSTIFIED finding. A truthful
// reason (or an unverifiable one) produces no such finding.

import (
	"testing"

	"github.com/turenlabs/batou-core/testutil"
	"github.com/turenlabs/batou-rules/rules"
)

const unjustifiedRuleID = "BATOU-SUPPRESS-UNJUSTIFIED"

// hasUnjustified reports whether the scan surfaced a BATOU-SUPPRESS-UNJUSTIFIED
// finding, returning the first such finding for further assertions.
func hasUnjustified(result *testutil.ScanResult) (rules.Finding, bool) {
	for _, f := range result.Findings {
		if f.RuleID == unjustifiedRuleID {
			return f, true
		}
	}
	return rules.Finding{}, false
}

// hasRule reports whether any finding has the given rule ID (used to confirm the
// ORIGINAL taint finding was suppressed, i.e. is absent from result.Findings).
func hasRule(result *testutil.ScanResult, ruleID string) bool {
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// TestAdjudicate_ParameterizedClaim_Concat_Flags is the headline positive case:
// a SQL-injection taint flow with a string-concatenated sink, suppressed with
// `-- parameterized query`. The query is demonstrably NOT parameterized, so the
// rationale is contradicted and BATOU-SUPPRESS-UNJUSTIFIED must fire.
func TestAdjudicate_ParameterizedClaim_Concat_Flags(t *testing.T) {
	code := `import sqlite3


def lookup_user(request, conn):
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + uid + "'"
    cur = conn.cursor()
    # batou:ignore BATOU-TAINT-sql_query -- parameterized query
    cur.execute(query)
    return cur.fetchall()
`
	result := testutil.ScanContent(t, "/app/handler.py", code)

	f, ok := hasUnjustified(result)
	if !ok {
		t.Fatalf("expected %s for a concatenated SQL flow suppressed as 'parameterized'; got findings: %v",
			unjustifiedRuleID, adjRuleIDs(result))
	}
	// The original taint finding must stay suppressed (only the adjudication
	// finding surfaces).
	if hasRule(result, "BATOU-TAINT-sql_query") {
		t.Errorf("original BATOU-TAINT-sql_query should remain suppressed; it leaked into findings")
	}
	// Evidence must be carried for the reader.
	if f.SourceCategory != "user_input" || f.SinkCategory != "sql_query" {
		t.Errorf("adjudication finding lost flow evidence: source=%q sink=%q", f.SourceCategory, f.SinkCategory)
	}
	if len(f.TaintPath) == 0 {
		t.Errorf("adjudication finding should carry the suppressed flow's taint path")
	}
	// It must point at the sink line where the suppressed finding lived.
	if f.LineNumber == 0 {
		t.Errorf("adjudication finding should have a concrete line number")
	}
	// It must block (High × high-confidence >= 0.7) so it is not lost in dirscan's
	// default data-flow-confirmed view.
	if !f.ShouldBlock() {
		t.Errorf("adjudication finding should block (RiskScore=%.2f)", f.RiskScore)
	}
}

// TestAdjudicate_SanitizedClaim_Flags covers the "sanitized" claim family on a
// command-injection flow with no sanitizer in the path.
func TestAdjudicate_SanitizedClaim_Flags(t *testing.T) {
	code := `import os


def run(request):
    name = request.args.get("name")
    cmd = "ping -c 1 " + name
    # batou:ignore BATOU-TAINT-command_exec -- input is sanitized before use
    os.system(cmd)
`
	result := testutil.ScanContent(t, "/app/cmd.py", code)
	if _, ok := hasUnjustified(result); !ok {
		t.Fatalf("expected %s for an unsanitized command flow suppressed as 'sanitized'; got: %v",
			unjustifiedRuleID, adjRuleIDs(result))
	}
}

// TestAdjudicate_TrustedClaim_Flags covers the "not user input / hardcoded"
// claim family: a user_input source claimed to be trusted.
func TestAdjudicate_TrustedClaim_Flags(t *testing.T) {
	code := `from flask import request, render_template_string


def show(request):
    name = request.args.get("name")
    page = "<h1>Hello " + name + "</h1>"
    # batou:ignore BATOU-TAINT-template_render -- value is hardcoded, not user input
    return render_template_string(page)
`
	result := testutil.ScanContent(t, "/app/render.py", code)
	if _, ok := hasUnjustified(result); !ok {
		t.Fatalf("expected %s for a user_input flow suppressed as 'hardcoded'; got: %v",
			unjustifiedRuleID, adjRuleIDs(result))
	}
}

// TestAdjudicate_CategoryTarget_Flags confirms a category-target suppression
// (`# batou:ignore sql_query -- ...`) is adjudicated, not just exact rule IDs.
func TestAdjudicate_CategoryTarget_Flags(t *testing.T) {
	code := `import sqlite3


def lookup(request, conn):
    uid = request.args.get("id")
    q = "SELECT * FROM t WHERE id = '" + uid + "'"
    cur = conn.cursor()
    # batou:ignore sql_query -- uses prepared statement with bound parameters
    cur.execute(q)
    return cur.fetchall()
`
	result := testutil.ScanContent(t, "/app/dao.py", code)
	if _, ok := hasUnjustified(result); !ok {
		t.Fatalf("expected %s for a category-target suppression of a concat SQL flow; got: %v",
			unjustifiedRuleID, adjRuleIDs(result))
	}
}

// TestAdjudicate_TruthfulParameterized_NoFlag is the headline NEGATIVE: a
// genuinely parameterized query produces NO taint flow, so there is nothing to
// suppress and nothing to adjudicate. The "parameterized" reason is truthful.
func TestAdjudicate_TruthfulParameterized_NoFlag(t *testing.T) {
	code := `import sqlite3


def lookup_user(request, conn):
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = ?"
    cur = conn.cursor()
    # batou:ignore BATOU-TAINT-sql_query -- parameterized query
    cur.execute(query, (uid,))
    return cur.fetchall()
`
	result := testutil.ScanContent(t, "/app/safe_handler.py", code)
	if f, ok := hasUnjustified(result); ok {
		t.Fatalf("genuinely parameterized query must NOT be flagged as unjustified; got %s at line %d",
			f.RuleID, f.LineNumber)
	}
}

// TestAdjudicate_UnverifiableReason_NoFlag is the second NEGATIVE: a real
// concatenated SQL flow IS suppressed, but the reason ("false positive") is not
// machine-verifiable against the flow, so the adjudicator must stay silent.
func TestAdjudicate_UnverifiableReason_NoFlag(t *testing.T) {
	code := `import sqlite3


def lookup_user(request, conn):
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + uid + "'"
    cur = conn.cursor()
    # batou:ignore BATOU-TAINT-sql_query -- false positive, uid is validated upstream
    cur.execute(query)
    return cur.fetchall()
`
	result := testutil.ScanContent(t, "/app/handler2.py", code)
	if f, ok := hasUnjustified(result); ok {
		t.Fatalf("unverifiable reason ('false positive') must NOT be flagged; got %s at line %d",
			f.RuleID, f.LineNumber)
	}
}

// TestAdjudicate_ReasonlessDirective_NoFlag confirms a directive with no
// `-- reason` is not adjudicated (there is no claim to refute). The separate
// SUPPRESS-REVIEW nudge handles reasonless directives in hook mode.
func TestAdjudicate_ReasonlessDirective_NoFlag(t *testing.T) {
	code := `import sqlite3


def lookup(request, conn):
    uid = request.args.get("id")
    q = "SELECT * FROM t WHERE id = '" + uid + "'"
    cur = conn.cursor()
    # batou:ignore BATOU-TAINT-sql_query
    cur.execute(q)
    return cur.fetchall()
`
	result := testutil.ScanContent(t, "/app/dao2.py", code)
	if f, ok := hasUnjustified(result); ok {
		t.Fatalf("reasonless directive must NOT be adjudicated; got %s at line %d", f.RuleID, f.LineNumber)
	}
}

// ruleIDs is a small debugging helper for failure messages.
func adjRuleIDs(result *testutil.ScanResult) []string {
	var ids []string
	for _, f := range result.Findings {
		ids = append(ids, f.RuleID)
	}
	if len(ids) == 0 {
		return []string{"(none)"}
	}
	return ids
}
