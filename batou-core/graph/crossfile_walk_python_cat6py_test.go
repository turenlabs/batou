// PR-CAT6py: two residual Sentry cross-file FP shapes that survived
// PR-CAT5py.
//
//   Fix A — `request.session[<lit>] = <param>` over-flagged
//
//     The callee writes a function PARAMETER into a literal-keyed
//     session slot. The walker treated `request` (arg 0) as the taint
//     source and fired whenever ANY tainted arg was passed at the
//     callsite, even when the actual VALUE-side param (e.g. `org_slug`)
//     came from a literal / constant. ~10 Sentry production findings
//     (sentry/utils/auth.py:170, :337, :434).
//
//     Fix: when the sink line is a session subscript-write with a
//     bare-identifier RHS that matches a callee parameter, set the
//     sink's ArgFromParam to the RHS param's index — not the
//     request-typed param. The cross-file positional check then only
//     fires when the caller passes a tainted arg at that specific
//     position.
//
//   Fix B — parse_* functions mis-categorised
//
//     B1: `re.match(constPattern, taintedValue)` — DangerousArgs=[0]
//     in the catalog, but findPythonParamFlowToSink didn't honour it
//     and bound ArgFromParam to the haystack param. Findings now use
//     the filtered variant so only arg 0 (the pattern) can pin the
//     sink to a source param.
//
//     B2: elasticsearch-py's SnkSQLQuery pattern `sql_query\s*\(`
//     matched the bare `sql_query(` substring inside
//     `parse_sql_query(...)` (a Parsimonious search-query grammar
//     parser, NOT a database executor). The pattern now requires a
//     dot-receiver prefix (`.sql.query(` or `.sql_query(`), since the
//     real ES client always invokes this as a method on a client
//     object.

package graph

import "testing"

// --- Fix A: trust-boundary RHS-is-callee-param ----------------------------

// Negative: `setActive(request, "literal_str")` — the second arg is
// a hardcoded literal, so the session write `session["activeorg"] =
// org` puts a constant into the slot. The walker should NOT fire even
// though the request itself is a tainted source param.
func TestPythonCrossFile_TrustBoundary_ParamRHSNotPassed_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"org.py": `def setActive(request, org):
    request.session["activeorg"] = org
`,
		"app.py": `from flask import Request
from org import setActive

def handle(request: Request):
    setActive(request, "literal_str")
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY"); len(got) != 0 {
		t.Errorf("setActive(request, \"literal_str\") should NOT produce TRUST_BOUNDARY; got %d: %+v",
			len(got), got)
	}
}

// Positive: same callee shape but the caller passes a tainted value
// for the RHS-bound param (`org`). MUST still fire — the literal-vs-
// tainted distinction is the entire point of fix A.
func TestPythonCrossFile_TrustBoundary_ParamRHSTainted_StillFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"org.py": `def setActive(request, org):
    request.session["activeorg"] = org
`,
		"app.py": `from flask import Request
from org import setActive

def handle(request: Request):
    setActive(request, request.args.get("x"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-TRUST_BOUNDARY")) == 0 {
		t.Fatalf("setActive(request, request.args.get(\"x\")) MUST produce TRUST_BOUNDARY; got rules=%v",
			findingRuleIDs(findings))
	}
}

// --- Fix B1: regex_dos honors DangerousArgs=[0] ---------------------------

// Negative: `re.match(r"^...$", tainted_value)` — pattern is a
// hardcoded constant (DangerousArgs=[0]); the subject being tainted is
// the entire point of regex validation. Sentry parse_stats_period shape.
func TestPythonCrossFile_RegexDoS_PatternConst_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"parse.py": `import re

def parse_stats_period(value):
    m = re.match(r"^(\d+)([hdmsw]?)$", value)
    return m
`,
		"app.py": `from flask import Request
from parse import parse_stats_period

def handle(request: Request):
    parse_stats_period(request.args.get("p"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-REGEX_DOS"); len(got) != 0 {
		t.Errorf("re.match(constPattern, taintedValue) should NOT produce REGEX_DOS; got %d: %+v",
			len(got), got)
	}
}

// Positive: tainted PATTERN (arg 0) — this IS the ReDoS surface and
// MUST still fire even with the filtered ArgFromParam.
func TestPythonCrossFile_RegexDoS_PatternTainted_StillFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"parse.py": `import re

def match_against(pattern):
    return re.match(pattern, "ok")
`,
		"app.py": `from flask import Request
from parse import match_against

def handle(request: Request):
    match_against(request.args.get("p"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if len(filterFindingsByRule(findings, "BATOU-INTERPROC-REGEX_DOS")) == 0 {
		t.Fatalf("re.match(taintedPattern, \"ok\") MUST produce REGEX_DOS; got rules=%v",
			findingRuleIDs(findings))
	}
}

// --- Fix B2: elasticsearch sql.query parser-name collision ----------------

// Negative: `parse_sql_query` is a Parsimonious grammar parser, NOT a
// database executor. The prior pattern `sql_query\s*\(` matched the
// `sql_query(` substring even though it's preceded by `parse_`. Sentry
// search_filter / parse_search_query shape.
func TestPythonCrossFile_SQLQuery_ParseGrammar_NotFlagged(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"grammar.py": `def parse_sql_query(query):
    return grammar.parse(query)
`,
		"app.py": `from flask import Request
from grammar import parse_sql_query

def handle(request: Request):
    parse_sql_query(request.args.get("q"))
`,
	})
	primePythonSigs(t, cg, paths)
	findings := WalkCrossFileTaintFlows(cg, nil)
	if got := filterFindingsByRule(findings, "BATOU-INTERPROC-SQL_QUERY"); len(got) != 0 {
		t.Errorf("parse_sql_query() grammar parser should NOT produce SQL_QUERY; got %d: %+v",
			len(got), got)
	}
}
