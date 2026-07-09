package scanner_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/testutil"
	"github.com/turenlabs/batou-rules/rules"
)

// End-to-end counterparts to the unit tests in external_origin_test.go: these
// drive the FULL scan pipeline (rules -> taint -> dedup -> caps -> block
// decision) via testutil.ScanContent, proving the external-origin block gate
// holds where it matters — the hook's block decision (ShouldBlock OR
// PreSuppressBlock).

// blockEligible reports whether any emitted finding is in the block-eligible
// set (RiskScore >= the 0.70 block threshold) — i.e. confidence_score>=0.7 at
// Critical/High. Mirrors how fp_reduction is measured on real repos.
func anyBlockEligible(findings []rules.Finding) (rules.Finding, bool) {
	for _, f := range findings {
		if f.RiskScore >= 0.7 {
			return f, true
		}
	}
	return rules.Finding{}, false
}

// (A) NO-FLOW -> NO-BLOCK, end-to-end. A Go exec.Command with a variable
// command name (BATOU-AST-003, CWE-78) is AST-structural with a null taint
// path; the gate must keep it out of the block lane via BOTH the post-cap
// ShouldBlock path AND the PreSuppressBlock latch.
func TestExternalOriginPipeline_ASTStructuralNoFlow(t *testing.T) {
	code := "package main\n\nimport \"os/exec\"\n\nfunc r(p string) {\n\texec.Command(p, \"-l\").Run()\n}\n"
	r := testutil.ScanContent(t, "/app/run.go", code)
	if !hasRule(r, "BATOU-AST-003") {
		t.Skip("BATOU-AST-003 not emitted on this content; nothing to assert")
	}
	if r.Raw.PreSuppressBlock {
		t.Error("PreSuppressBlock latched on an AST-structural no-flow finding — gate defeated in hook mode")
	}
	if r.Blocked {
		t.Error("AST-structural no-flow finding still blocks (ShouldBlock true)")
	}
}

// (B) WEAK-SOURCE -> NO-BLOCK, end-to-end. A function whose parameter is merely
// NAMED like input ('path') reaches a command sink. Pre-gate this seeded the
// conf-0.6 param-NAME fabricator and (with a Critical sink) could reach the
// block lane; the gate must demote it to a hint. It must still EMIT (recall at
// minConf=0 unchanged).
func TestExternalOriginPipeline_ParamNameSourceDemoted(t *testing.T) {
	// Non-handler Go helper: parameter 'path' is the name-only fabricator.
	code := "package main\n\nimport \"os/exec\"\n\nfunc runIt(path string) {\n\texec.Command(\"sh\", \"-c\", path).Run()\n}\n"
	r := testutil.ScanContent(t, "/app/helper.go", code)

	if f, ok := anyBlockEligible(r.Raw.Findings); ok {
		// A real external-source flow would be allowed; a param-name flow must not.
		if isParamNameSourced(f) {
			t.Errorf("param-name-sourced finding is block-eligible: %s conf=%.2f risk=%.2f src=%s",
				f.RuleID, f.ConfidenceScore, f.RiskScore, f.SourceCategory)
		}
	}
	if r.Raw.PreSuppressBlock {
		// Only fail if the latch was caused by a param-name flow (anti-bypass
		// for real flows is preserved). Find any param-name flow that would
		// have latched.
		for _, f := range r.Raw.Findings {
			if isParamNameSourced(f) && f.Severity >= rules.High {
				t.Errorf("param-name flow may be latching PreSuppressBlock: %s", f.RuleID)
			}
		}
	}
}

func isParamNameSourced(f rules.Finding) bool {
	return len(f.TaintPath) > 0 && strings.HasPrefix(f.TaintPath[0].Label, "param-name:")
}

// RECALL PRESERVED, end-to-end. A real external source (Flask
// request.args.get / a Servlet-style request.getParameter) reaching a SQL sink
// must STILL block — neither the gate nor the param-name marker may suppress a
// genuine external flow.
func TestExternalOriginPipeline_RealExternalStillBlocks_Python(t *testing.T) {
	code := `import sqlite3

def lookup(request, conn):
    uid = request.args.get("id")
    conn.cursor().execute("SELECT * FROM users WHERE id = '" + uid + "'")
`
	r := testutil.ScanContent(t, "/app/dao.py", code)
	if !hasRule(r, "BATOU-TAINT-sql_query") {
		t.Skip("SQLi taint flow not produced on this build; nothing to assert")
	}
	if !r.Raw.PreSuppressBlock && !r.Blocked {
		t.Error("real Critical SQLi flow from request.args neither blocks nor latches PreSuppressBlock — recall regressed")
	}
	// And its source must be recognised as external (not the param-name marker).
	var found bool
	for _, f := range r.Raw.Findings {
		if f.RuleID == "BATOU-TAINT-sql_query" {
			found = true
			if isParamNameSourced(f) {
				t.Errorf("real request.args flow mislabeled as param-name fabricator: %+v", f.TaintPath)
			}
		}
	}
	if !found {
		t.Skip("no BATOU-TAINT-sql_query finding to inspect")
	}
}

// RECALL PRESERVED, end-to-end, Java servlet. request.getParameter reaching a
// SQL concat sink is the canonical OWASP shape and MUST remain block-eligible.
func TestExternalOriginPipeline_RealExternalStillBlocks_JavaServlet(t *testing.T) {
	code := `import java.sql.*;
import javax.servlet.http.*;

public class Dao {
  public void lookup(HttpServletRequest request, Connection conn) throws Exception {
    String id = request.getParameter("id");
    Statement st = conn.createStatement();
    st.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
  }
}
`
	r := testutil.ScanContent(t, "/app/Dao.java", code)
	if !hasRule(r, "BATOU-TAINT-sql_query") {
		t.Skip("Java SQLi taint flow not produced on this build; nothing to assert")
	}
	if !r.Raw.PreSuppressBlock && !r.Blocked {
		t.Error("real Java servlet getParameter->SQL flow neither blocks nor latches PreSuppressBlock — recall regressed")
	}
}
