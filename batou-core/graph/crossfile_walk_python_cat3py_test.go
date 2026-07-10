// PR-CAT3py: cross-file scanner FP filters for SnkTrustBoundary
// (session writes of server-generated tokens / validated URLs) and
// SnkLog (structured logger calls whose format string is a literal).
//
// Motivating Sentry production scan FPs:
//
//   - sudo/utils.py:50  -> request.session[k] = get_random_string(12)
//   - auth.py:165       -> request.session["_next"] = next_url   # is_valid_redirect()-validated
//   - auth.py:434       -> request.session["activeorg"] = org_slug
//   - jira/utils/api.py -> logger.info("event.assignee-not-found", extra=ctx)
//   - snuba/utils.py    -> logger.warning("query.deprecated.%s", dataset_label)
//
// Each negative test below recreates the FP shape; positive tests
// preserve the real-TP behaviour (f-string interpolation, plain
// tainted args, unsanitised session writes).

package graph

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// --- SnkTrustBoundary -----------------------------------------------------

// Positive: an unsanitised session write of raw user input SHOULD
// still produce a BATOU-INTERPROC-TRUST_BOUNDARY finding.
func TestPythonCrossFile_TrustBoundary_RawNextUrl_Flagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `def store_next(request, next_url):
    request.session["_next"] = next_url
`,
		"app.py": `from flask import Request
from sess import store_next

def handle(request: Request):
    store_next(request, request.args.get("next"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY")) == 0 {
		t.Fatalf("expected BATOU-INTERPROC-TRUST_BOUNDARY for raw next_url; got rules=%v",
			findingRuleIDs(findings))
	}
}

// Negative: server-generated secrets.token_hex() RHS is not a trust-
// boundary violation; the value never came from the user.
func TestPythonCrossFile_TrustBoundary_SecretsTokenHex_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `import secrets

def grant_token(request):
    request.session["csrf_token"] = secrets.token_hex(32)
`,
		"app.py": `from flask import Request
from sess import grant_token

def handle(request: Request):
    grant_token(request)
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("secrets.token_hex() RHS should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// Negative: server-generated uuid.uuid4() RHS is not a trust-boundary
// violation.
func TestPythonCrossFile_TrustBoundary_UuidUuid4_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `import uuid

def assign_sid(request):
    request.session["sid"] = str(uuid.uuid4())
`,
		"app.py": `from flask import Request
from sess import assign_sid

def handle(request: Request):
    assign_sid(request)
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("uuid.uuid4() RHS should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// Negative: Django's get_random_string is the literal Sentry sudo/utils
// shape. Must not be flagged.
func TestPythonCrossFile_TrustBoundary_GetRandomString_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `from django.utils.crypto import get_random_string

def grant_sudo(request):
    request.session["_sudo"] = get_random_string(12)
`,
		"app.py": `from flask import Request
from sess import grant_sudo

def handle(request: Request):
    grant_sudo(request)
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("get_random_string() RHS should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// Negative: is_valid_redirect-gated next_url is the literal Sentry
// auth.py shape. The validator's presence on the assignment line
// suppresses the trust-boundary finding.
func TestPythonCrossFile_TrustBoundary_IsValidRedirect_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"sess.py": `def initiate_login(request, next_url):
    request.session["_next"] = is_valid_redirect(next_url, allowed_hosts={"example.com"})
`,
		"app.py": `from flask import Request
from sess import initiate_login

def handle(request: Request):
    initiate_login(request, request.args.get("next"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("is_valid_redirect-validated next_url should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// --- SnkLog ---------------------------------------------------------------

// Positive: f-string interpolation of tainted data into the format
// string IS a log-injection sink (the format string itself contains
// adversary content, before the logging library's escape pass).
func TestPythonCrossFile_LogOutput_FStringTaint_Flagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"logger_util.py": `import logging
logger = logging.getLogger(__name__)

def log_event(user_id):
    logger.info(f"User {user_id} performed action")
`,
		"app.py": `from flask import Request
from logger_util import log_event

def handle(request: Request):
    log_event(request.args.get("user_id"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-LOG_OUTPUT")) == 0 {
		t.Fatalf("f-string with tainted interpolation should produce LOG_OUTPUT; got rules=%v",
			findingRuleIDs(findings))
	}
}

// Positive: directly passing a tainted variable as the format string
// (no literal at all) is a log-injection sink.
func TestPythonCrossFile_LogOutput_TaintedFormatString_Flagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"logger_util.py": `import logging
logger = logging.getLogger(__name__)

def log_event(msg):
    logger.info(msg)
`,
		"app.py": `from flask import Request
from logger_util import log_event

def handle(request: Request):
    log_event(request.args.get("msg"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-LOG_OUTPUT")) == 0 {
		t.Fatalf("tainted variable as logger format string should produce LOG_OUTPUT; got rules=%v",
			findingRuleIDs(findings))
	}
}

// Negative: structured logger call with literal event-name and
// `extra=` kwargs. The format string is constant; the logging library
// %-substitutes the rest server-side. This is the dominant Sentry
// FP shape (jira webhooks, identities, similar_issues, snuba/utils).
func TestPythonCrossFile_LogOutput_StructuredWithExtra_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"logger_util.py": `import logging
logger = logging.getLogger(__name__)

def log_event(ctx):
    logger.info("jira.assignee-not-in-changelog", extra=ctx)
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
		t.Errorf("structured logger with constant format string should NOT produce LOG_OUTPUT; got %d: %+v",
			len(got), got)
	}
}

// Negative: %-style structured logger call. `logger.warning("query.%s",
// dataset_label)` — the Python logging stdlib performs `__mod__`
// substitution server-side, escaping control characters. The format
// string itself is constant.
func TestPythonCrossFile_LogOutput_StructuredPercentS_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"logger_util.py": `import logging
logger = logging.getLogger(__name__)

def log_event(dataset_label):
    logger.warning("query.deprecated_dataset.%s", dataset_label)
`,
		"app.py": `from flask import Request
from logger_util import log_event

def handle(request: Request):
    log_event(request.args.get("dataset"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-LOG_OUTPUT"); len(got) != 0 {
		t.Errorf(`logger.warning("...%%s", x) should NOT produce LOG_OUTPUT; got %d: %+v`,
			len(got), got)
	}
}

// --- Unit test for the helper -------------------------------------------

// TestPythonLogFirstArgIsStaticLiteral pins the helper that decides
// whether a log call's first positional argument is a constant string
// literal. Exhaustive coverage of the static / dynamic split lives here.
func TestPythonLogFirstArgIsStaticLiteral(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		static bool
	}{
		// Static literals — safe.
		{"plain double-quote", `logger.info("event.foo")`, true},
		{"plain single-quote", `logger.info('event.foo')`, true},
		{"with extra kwarg", `logger.info("event.foo", extra=ctx)`, true},
		{"with %s args", `logger.warning("query.%s", id)`, true},
		{"indented", `        logger.info("nested")`, true},
		// Dynamic / unsafe — must NOT be static.
		{"f-string", `logger.info(f"User {user_id} acted")`, false},
		{"capital F-string", `logger.info(F"User {user_id} acted")`, false},
		{"rf-string", `logger.info(rf"User {user_id} acted")`, false},
		{"fr-string", `logger.info(fr"User {user_id} acted")`, false},
		{".format() on literal", `logger.info("user {0}".format(name))`, false},
		{"% interpolation outside literal", `logger.info("user %s" % name)`, false},
		{"bare identifier (tainted format)", `logger.info(msg)`, false},
		{"concatenation", `logger.info("user " + name)`, false},
		// Edge case: no parens (e.g. bad input) — conservatively dynamic.
		{"no parens", `logger.info`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pythonLogFirstArgIsStaticLiteral(tc.line)
			if got != tc.static {
				t.Errorf("pythonLogFirstArgIsStaticLiteral(%q) = %v, want %v",
					tc.line, got, tc.static)
			}
		})
	}
}

// Reference the rules package to ensure the cross-file filter still
// emits valid Finding shapes for assertion in callers (no orphan test
// drift if a future refactor renames rules.Finding's RuleID field).
var _ = rules.Finding{}
