package tsflow

// Tests for the third-party PyPI `regex` package ReDoS sink (py.regex.compile,
// CWE-1333). The `regex` module is a backtracking drop-in replacement for the
// stdlib `re`. Before this entry existed, `regex.compile(tainted)` fell through
// to the generic empty-ObjectType `py.compile` sink and was MIS-classified as a
// Critical SnkEval / CWE-94 RCE. The dedicated ObjectType "regex" entry is a
// strong receiver match, so the matcher now returns it ahead of the wildcard
// `py.compile` and reports the flow as a Medium ReDoS instead.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Positive baseline: request-derived pattern flowing into regex.compile() must
// fire a SnkRegexDoS flow and must NOT be reported as SnkEval (the bug fix).
func TestPython_RegexPkg_Compile_Vulnerable(t *testing.T) {
	code := `
import regex
from flask import request

def parse():
    q = request.args.get('q')
    return regex.compile(q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Fatalf("expected SnkRegexDoS for request.args.get('q') -> regex.compile(q); got %d flows", len(flows))
	}
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Errorf("regex.compile(tainted) must NOT be classified as SnkEval (CWE-94 RCE); regex DoS is CWE-1333")
	}
}

// The other module-level regex.* execution functions take the pattern at arg 0
// and must classify as SnkRegexDoS, not SnkEval.
func TestPython_RegexPkg_Methods_Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"regex.match", "regex.match(q, 'haystack')"},
		{"regex.search", "regex.search(q, 'haystack')"},
		{"regex.fullmatch", "regex.fullmatch(q, 'haystack')"},
		{"regex.findall", "regex.findall(q, 'haystack')"},
		{"regex.finditer", "regex.finditer(q, 'haystack')"},
		{"regex.sub", "regex.sub(q, 'repl', 'haystack')"},
		{"regex.subn", "regex.subn(q, 'repl', 'haystack')"},
		{"regex.split", "regex.split(q, 'haystack')"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
import regex
from flask import request

def parse():
    q = request.args.get('q')
    return ` + tc.call + `
`
			flows := Analyze(code, "/app/handler.py", rules.LangPython)
			if !hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("expected SnkRegexDoS for %s; got %d flows", tc.call, len(flows))
			}
			if hasTaintFlow(flows, taint.SnkEval) {
				t.Errorf("%s with tainted pattern must NOT be SnkEval; ReDoS is CWE-1333", tc.call)
			}
		})
	}
}

// Negative: a constant (non-tainted) pattern must not fire any flow — the
// haystack being a literal is the whole point and proves we don't blanket-flag
// every regex.compile call.
func TestPython_RegexPkg_ConstantPattern_NoFlow(t *testing.T) {
	code := `
import regex
from flask import request

def parse():
    user = request.args.get('q')
    pat = regex.compile(r'^[a-z]+$')
    return pat.match(user)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Errorf("constant regex pattern must not fire SnkRegexDoS; got %d flows", len(flows))
	}
}

// Regression: stdlib re.compile(tainted) is unaffected — it must still classify
// as SnkRegexDoS (via the ObjectType "re" entry), never SnkEval, and the new
// ObjectType "regex" entry must not interfere.
func TestPython_RegexPkg_StdlibReUnaffected(t *testing.T) {
	code := `
import re
from flask import request

def parse():
    q = request.args.get('q')
    return re.compile(q)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Fatalf("stdlib re.compile(tainted) must still fire SnkRegexDoS; got %d flows", len(flows))
	}
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Errorf("stdlib re.compile(tainted) must NOT be SnkEval")
	}
}

// Regression: the genuine builtin compile() (source -> code object -> exec) is
// still a Critical SnkEval / CWE-94 RCE — the new regex entry must not have
// shadowed the wildcard py.compile sink for non-regex receivers.
func TestPython_BuiltinCompile_StillEval(t *testing.T) {
	code := `
from flask import request

def run():
    src = request.args.get('code')
    obj = compile(src, '<string>', 'exec')
    exec(obj)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Errorf("builtin compile(tainted) must remain a SnkEval / CWE-94 sink; got %d flows", len(flows))
	}
}
