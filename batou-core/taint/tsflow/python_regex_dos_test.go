package tsflow

// Tests for Python regex DoS (CWE-1333) classification and the negative
// fixture for the historically over-broad `text()` SQL pattern.
//
// Context: Sentry rescan surfaced two Python catalog precision bugs.
//
//  1. `text(...)` in a Django template/config dict (returned by helpers
//     like get_client_config / generate_context) was matching the bare
//     `text\(` SQLAlchemy pattern and producing
//     BATOU-INTERPROC-SQL_QUERY findings. The catalog now requires an
//     explicit `sqlalchemy.` / `sa.` / `sqla.` qualifier on the call
//     site.
//
//  2. `re.compile/match/search/findall` were categorised as SnkEval
//     (BATOU-INTERPROC-CODE_EVAL, CWE-94), but regex execution on
//     attacker-controlled input is Regular Expression Denial of Service
//     (CWE-1333 / CWE-400), not dynamic code injection. The sink now
//     belongs to the new SnkRegexDoS category and produces
//     BATOU-INTERPROC-REGEX_DOS findings at Medium severity.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// TestPython_RegexDoS_Vulnerable_ReCompile is the positive baseline for
// SnkRegexDoS: a request-derived pattern flowing into re.compile() must
// fire a regex_dos flow (NOT a code_eval / SnkEval flow).
func TestPython_RegexDoS_Vulnerable_ReCompile(t *testing.T) {
	code := `
import re
from flask import request

def parse():
    q = request.args.get('q')
    return re.compile(q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Fatalf("expected SnkRegexDoS flow for request.args.get('q') -> re.compile(q); got %d flows", len(flows))
	}
	// Defensive: must NOT classify regex execution as code injection.
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Errorf("re.compile(tainted) must NOT be classified as SnkEval (CWE-94); regex DoS is CWE-1333")
	}
}

// TestPython_RegexDoS_Vulnerable_ReMatch_ReSearch verifies the other
// re.* sinks also classify as SnkRegexDoS, not SnkEval.
func TestPython_RegexDoS_Vulnerable_ReMatch_ReSearch(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"re.match", "re.match(q, 'haystack')"},
		{"re.search", "re.search(q, 'haystack')"},
		{"re.findall", "re.findall(q, 'haystack')"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
import re
from flask import request

def parse():
    q = request.args.get('q')
    return ` + tc.call + `
`
			flows := Analyze(code, "/app/handler.py", rules.LangPython)
			if !hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("expected SnkRegexDoS flow for %s; got %d flows", tc.call, len(flows))
			}
			if hasTaintFlow(flows, taint.SnkEval) {
				t.Errorf("%s with tainted pattern must NOT be classified as SnkEval; regex DoS is CWE-1333", tc.call)
			}
		})
	}
}

// TestPython_TextSqlPattern_Negative_GetClientConfig verifies the
// `text` SQL false-positive fix. A helper that returns a config/template
// dict whose `.text` field is then called must NOT trigger a SQL flow —
// this is the exact Sentry pattern (get_client_config / generate_context
// → context.text(...)).
func TestPython_TextSqlPattern_Negative_GetClientConfig(t *testing.T) {
	code := `
from flask import request

def get_client_config():
    return {"text": lambda key: "rendered template for " + key}

def handler():
    raw = request.args.get('section')
    config = get_client_config()
    rendered = config.text(raw)
    return rendered
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("config.text(...) is not a SQLAlchemy call; must not fire SnkSQLQuery; got flows=%+v", flows)
	}
}

// TestPython_TextSqlPattern_Negative_BareTextCall verifies that a bare
// `text(...)` call (no SQLAlchemy module qualifier in scope) does NOT
// fire the SQL sink. The catalog now requires an explicit
// `sqlalchemy.` / `sa.` / `sqla.` prefix to avoid bare-name collisions.
func TestPython_TextSqlPattern_Negative_BareTextCall(t *testing.T) {
	code := `
from flask import request

def text(s):
    return "wrapped: " + s

def handler():
    raw = request.args.get('q')
    return text(raw)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("bare user-defined text(...) must not fire SnkSQLQuery; got flows=%+v", flows)
	}
}

// TestPython_TextSqlPattern_Positive_QualifiedSqlalchemyText verifies
// that an explicit `sqlalchemy.text(...)` call still fires SnkSQLQuery
// when the argument is tainted. This is the SQLAlchemy true-positive
// path we must preserve while removing the bare-`text(` false positive.
func TestPython_TextSqlPattern_Positive_QualifiedSqlalchemyText(t *testing.T) {
	code := `
import sqlalchemy
from flask import request

def handler(engine):
    raw = request.args.get('q')
    stmt = sqlalchemy.text("SELECT * FROM users WHERE name = '" + raw + "'")
    return engine.execute(stmt)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("sqlalchemy.text(tainted) must fire SnkSQLQuery; got flows=%+v", flows)
	}
}

// --- Third-party `regex` module (PyPI) ReDoS, py.regex.compile ---
//
// The `regex` module is a drop-in re replacement with the same backtracking
// engine; a request-derived pattern flowing into regex.compile()/match()/etc.
// is just as ReDoS-exploitable as with stdlib re. The pre-existing
// `py.re.compile` entry is scoped to Module "re" and never fires on
// `regex.<fn>(...)`, so these are the coverage cases for the new entry.

// TestPython_RegexModule_RegexDoS_Vulnerable_Compile is the positive baseline
// for the third-party regex module: a tainted pattern into regex.compile()
// must fire a SnkRegexDoS flow (and never a SnkEval flow).
func TestPython_RegexModule_RegexDoS_Vulnerable_Compile(t *testing.T) {
	code := `
import regex
from flask import request

def parse():
    q = request.args.get('q')
    return regex.compile(q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Fatalf("expected SnkRegexDoS flow for request.args.get('q') -> regex.compile(q); got %d flows", len(flows))
	}
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Errorf("regex.compile(tainted) must NOT be classified as SnkEval (CWE-94); regex DoS is CWE-1333")
	}
}

// TestPython_RegexModule_RegexDoS_TaintedPattern verifies the other top-level
// regex.* functions also classify a tainted pattern (arg 0) as SnkRegexDoS.
func TestPython_RegexModule_RegexDoS_TaintedPattern(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"regex.match", "regex.match(p, 'haystack')"},
		{"regex.search", "regex.search(p, 'haystack')"},
		{"regex.findall", "regex.findall(p, 'haystack')"},
		{"regex.fullmatch", "regex.fullmatch(p, 'haystack')"},
		{"regex.finditer", "regex.finditer(p, 'haystack')"},
		{"regex.sub", "regex.sub(p, 'y', 'haystack')"},
		{"regex.subn", "regex.subn(p, 'y', 'haystack')"},
		{"regex.split", "regex.split(p, 'haystack')"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
import regex
from flask import request

def parse():
    p = request.args.get('pattern')
    return ` + tc.call + `
`
			flows := Analyze(code, "/app/handler.py", rules.LangPython)
			if !hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("expected SnkRegexDoS flow for %s; got %d flows", tc.call, len(flows))
			}
			if hasTaintFlow(flows, taint.SnkEval) {
				t.Errorf("%s with tainted pattern must NOT be classified as SnkEval; regex DoS is CWE-1333", tc.call)
			}
		})
	}
}

// TestPython_RegexModule_HardcodedPattern_NotRegexDoS is the FP-safety control:
// a hardcoded pattern with a tainted HAYSTACK (arg 1) must NOT fire SnkRegexDoS,
// because only the pattern (arg 0) is the dangerous argument.
func TestPython_RegexModule_HardcodedPattern_NotRegexDoS(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"regex.match", `regex.match(r"^\d+$", q)`},
		{"regex.search", `regex.search(r"foo", q)`},
		{"regex.sub", `regex.sub(r"x", "y", q)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
import regex
from flask import request

def handler():
    q = request.args.get("q")
    return ` + tc.call + `
`
			flows := Analyze(code, "/app/handler.py", rules.LangPython)
			if hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("%s with hardcoded pattern and tainted haystack must NOT fire SnkRegexDoS; got flows=%+v", tc.call, flows)
			}
		})
	}
}
