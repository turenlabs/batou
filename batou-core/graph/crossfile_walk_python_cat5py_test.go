// PR-CAT5py: residual cross-file FP shapes from the Sentry rescan
// that survived PR-CAT3py. Three concrete shapes, six tests.
//
//   1. `del request.session[k]` / `.session.pop(k)` / `.session.clear()` —
//      removals, NOT trust-boundary writes. The catalog regex matches
//      the subscript shape; the walker now filters delete/pop/clear ops
//      explicitly.
//   2. Multi-line structured logger calls — `logger.info(\n  "event",\n
//      extra=ctx)` split across physical lines escaped
//      pythonLogFirstArgIsStaticLiteral. scanPythonBodyForSinks now
//      joins parenthesised continuations before scanning.
//   3. Prev-line RHS sanitizer — the sink line has a bare-identifier RHS
//      (`session[k] = token`) whose value was assigned on the previous
//      line via a known sanitizer (`token = get_random_string(...)`).
//      The walker now performs a 1-3 line backward lookback.
//
// Positive tests preserved by these fixes:
//   - TestPythonCrossFile_TrustBoundary_RawNextUrl_Flagged (CAT3py)
//   - TestPythonCrossFile_LogOutput_FStringTaint_Flagged   (CAT3py)
// Both still flag because the new suppressions are gated on syntactic
// shapes (leading-del, balanced parens, bare-ident RHS).

package graph

import "testing"

// --- Fix 1: del / pop / clear on request.session ---------------------------

// Negative: `del request.session[k]` removes a key — the catalog regex
// matches the subscript shape but this is not a write at all.
func TestPythonCrossFile_TrustBoundary_DelSession_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `def logout(request, k):
    del request.session[k]
`,
		"app.py": `from flask import Request
from sess import logout

def handle(request: Request):
    logout(request, request.args.get("k"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("del request.session[k] should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// Negative: `.session.pop(k)` is a removal helper, not a write.
func TestPythonCrossFile_TrustBoundary_SessionPop_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `def drop_key(request, k):
    request.session.pop(k, None)
`,
		"app.py": `from flask import Request
from sess import drop_key

def handle(request: Request):
    drop_key(request, request.args.get("k"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("request.session.pop(...) should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// Negative: `.session.clear()` wipes the session entirely.
func TestPythonCrossFile_TrustBoundary_SessionClear_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `def reset_session(request):
    request.session.clear()
`,
		"app.py": `from flask import Request
from sess import reset_session

def handle(request: Request):
    reset_session(request)
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("request.session.clear() should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// --- Fix 2: multi-line structured logger call ------------------------------

// Negative: `logger.info(` opens on one physical line but the literal
// format string + kwargs are on subsequent lines. Without the
// paren-balance join in scanPythonBodyForSinks the helper would only
// see `logger.info(` and conclude "no literal" → log injection.
// The Sentry shape (get_similarity_data_from_seer:81).
func TestPythonCrossFile_LogOutput_MultiLineStructured_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"logger_util.py": `import logging
logger = logging.getLogger(__name__)

def log_event(ctx):
    logger.info(
        "event.similar-issues",
        extra=ctx,
    )
`,
		"app.py": `from flask import Request
from logger_util import log_event

def handle(request: Request):
    log_event({"data": request.args.get("data")})
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-LOG_OUTPUT"); len(got) != 0 {
		t.Errorf("multi-line structured logger.info(\"...\", extra=ctx) should NOT produce LOG_OUTPUT; got %d: %+v",
			len(got), got)
	}
}

// --- Fix 3: prev-line RHS sanitizer ---------------------------------------

// Negative: token generated on the previous line via get_random_string,
// then assigned into the session. The Sentry grant_sudo_privileges
// shape (sudo/utils.py).
func TestPythonCrossFile_TrustBoundary_PrevLineSanitizer_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `from django.utils.crypto import get_random_string

def grant_sudo_privileges(request):
    token = get_random_string(12)
    request.session["_sudo"] = token
`,
		"app.py": `from flask import Request
from sess import grant_sudo_privileges

def handle(request: Request):
    grant_sudo_privileges(request)
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("prev-line get_random_string() RHS should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// Positive (correctness boundary): when the sanitizer is more than 3
// lines back, OR when an intermediate reassignment shadows it, the sink
// STILL fires. The lookback must be narrow — going further risks
// missing real reassignment-from-user-input shapes.
func TestPythonCrossFile_TrustBoundary_PrevLineFar_StillFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `from django.utils.crypto import get_random_string

def grant_sudo_privileges(request, next_url):
    token = get_random_string(12)
    token = next_url
    request.session["_sudo"] = token
`,
		"app.py": `from flask import Request
from sess import grant_sudo_privileges

def handle(request: Request):
    grant_sudo_privileges(request, request.args.get("next"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) == 0 {
		t.Errorf("intermediate reassignment of token from user input SHOULD still produce TRUST_BOUNDARY; got rules=%v",
			findingRuleIDs(findings))
	}
}
