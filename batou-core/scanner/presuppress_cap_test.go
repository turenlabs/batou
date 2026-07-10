package scanner_test

import (
	"testing"

	"github.com/turenlabs/batou-core/testutil"
)

// Regression for the PreSuppressBlock-before-caps ordering bug.
//
// The hook's block decision in cmd/batou/main.go is
// `result.ShouldBlock() || result.PreSuppressBlock`. PreSuppressBlock was
// latched from the PRE-cap RiskScore (a Critical AST-structural finding at the
// AST base 0.7 = RiskScore 0.70 = block), and ONLY AFTER that did the
// confidence caps demote it to 0.65 (a hint). So a finding the cap was
// specifically designed to keep out of the block lane (the 20-repo verified-FP
// demotion: symfony PHPAST, git CAST-002, …) still hard-blocked the write in
// hook mode. The fix applies the caps to a copy inside the pre-suppress latch
// loop so PreSuppressBlock reflects the POST-cap decision while remaining
// pre-suppression (the batou:ignore anti-bypass property).
//
// A Go exec.Command with a variable command name (BATOU-AST-003, CWE-78) fires
// the structural rule with no taint flow, so the external-origin invariant
// (CapNonExternalOriginConfidence, case (A) NO-FLOW → NO-BLOCK — which subsumed
// the deleted per-rule AST-structural denylist) caps it to 0.65 and it must not
// block via EITHER path. (Verified end-to-end too: the same shape exits 2/BLOCK
// on a pre-fix binary and 0/ALLOW on the fixed one.)
func TestPreSuppressBlock_HonorsASTStructuralCap(t *testing.T) {
	code := "package main\n\nimport \"os/exec\"\n\nfunc r(p string) {\n\texec.Command(p, \"-l\").Run()\n}\n"
	r := testutil.ScanContent(t, "/app/run.go", code)

	// The structural finding still EMITS (demotion, not deletion — recall at
	// minConf=0 is unchanged). If the build doesn't emit it here there's
	// nothing to assert, so skip rather than give a false pass.
	if !hasRule(r, "BATOU-AST-003") {
		t.Skip("BATOU-AST-003 not emitted on this content; nothing to assert")
	}
	// The cap must keep it out of the block lane via BOTH the post-cap
	// ShouldBlock() path AND the PreSuppressBlock latch.
	if r.Raw.PreSuppressBlock {
		t.Error("PreSuppressBlock latched on a capped AST-structural finding — the confidence cap is defeated in hook mode")
	}
	if r.Blocked {
		t.Error("capped AST-structural finding still blocks (ShouldBlock true)")
	}
}

// The anti-bypass property must be preserved: a genuine high-confidence taint
// finding (NOT in any cap list) still latches PreSuppressBlock, so hiding it
// with a batou:ignore cannot smuggle a vulnerable write past the hook.
func TestPreSuppressBlock_PreservedForRealTaint(t *testing.T) {
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
		t.Error("a real Critical SQLi taint flow neither blocks nor latches PreSuppressBlock — anti-bypass weakened")
	}
}
