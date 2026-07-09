package pyast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"testing"
)

func scanPython(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangPython)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  code,
		Language: rules.LangPython,
		Tree:     tree,
	}
	a := &PythonASTAnalyzer{}
	return a.Scan(ctx)
}

func findByRule(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestEvalExec(t *testing.T) {
	code := `
def handler(request):
    name = request.args.get('name')
    eval(name)
    exec(name)
`
	findings := scanPython(code)
	count := 0
	for _, f := range findings {
		if f.RuleID == "BATOU-PYAST-001" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 eval/exec findings, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestEvalLiteralSafe(t *testing.T) {
	code := `
eval("1 + 2")
exec("print('hello')")
`
	findings := scanPython(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-PYAST-001" {
			t.Errorf("should not flag literal eval/exec: %s", f.Title)
		}
	}
}

func TestOsSystem(t *testing.T) {
	code := `
import os
def handler(name):
    os.system("rm " + name)
`
	findings := scanPython(code)
	f := findByRule(findings, "BATOU-PYAST-001")
	if f == nil {
		t.Error("expected finding for os.system with variable")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestSubprocessShellTrue(t *testing.T) {
	code := `
import subprocess
def handler(cmd):
    subprocess.call(cmd, shell=True)
    subprocess.run(cmd, shell=True)
`
	findings := scanPython(code)
	count := 0
	for _, f := range findings {
		if f.RuleID == "BATOU-PYAST-002" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 subprocess shell=True findings, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSubprocessNoShellSafe(t *testing.T) {
	code := `
import subprocess
subprocess.call(["ls", "-la"])
subprocess.run(cmd, shell=False)
`
	findings := scanPython(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-PYAST-002" {
			t.Errorf("should not flag subprocess without shell=True: %s", f.Title)
		}
	}
}

func TestPickleLoads(t *testing.T) {
	code := `
import pickle
data = pickle.loads(request.data)
`
	findings := scanPython(code)
	f := findByRule(findings, "BATOU-PYAST-003")
	if f == nil {
		t.Error("expected finding for pickle.loads with variable")
	}
}

func TestOpenVariable(t *testing.T) {
	code := `
def handler(path):
    f = open(path)
`
	findings := scanPython(code)
	f := findByRule(findings, "BATOU-PYAST-004")
	if f == nil {
		t.Error("expected finding for open() with variable path")
	}
}

func TestOpenLiteralSafe(t *testing.T) {
	code := `
f = open("/etc/config.yaml")
`
	findings := scanPython(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-PYAST-004" {
			t.Errorf("should not flag open() with literal path: %s", f.Title)
		}
	}
}

// TestOpenVariableSuppressedByTraversalGuard covers the false-positive
// suppression added to BATOU-PYAST-004: when the file already contains a
// path-traversal denylist / sanitizer / resolve-and-startswith containment
// check, the blind AST signal is silenced to avoid double-flagging safe
// cases (the taint pipeline still inspects the same path with flow
// awareness). Matches the OWASP BenchmarkPython pathtraver SAFE pattern.
func TestOpenVariableSuppressedByTraversalGuard(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			name: "dotdot-denylist-guard",
			code: `
def handler(request):
    bar = request.args.get('name')
    if '../' in bar:
        return 'rejected'
    f = open('/srv/' + bar, 'rb')
`,
		},
		{
			name: "secure_filename",
			code: `
from werkzeug.utils import secure_filename

def handler(request):
    bar = request.args.get('name')
    bar = secure_filename(bar)
    f = open('/srv/' + bar, 'rb')
`,
		},
		{
			name: "resolve-and-startswith",
			code: `
import pathlib

def handler(request):
    bar = request.args.get('name')
    root = pathlib.Path('/srv')
    p = (root / bar).resolve()
    if not str(p).startswith(str(root)):
        return 'rejected'
    f = open(str(p), 'rb')
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanPython(tc.code)
			if f := findByRule(findings, "BATOU-PYAST-004"); f != nil {
				t.Errorf("expected BATOU-PYAST-004 to be suppressed when traversal guard is present, got: %s", f.Title)
			}
		})
	}
}

// TestOpenVariableSuppressedBySafeAssignment covers PR-PATHpy: BATOU-PYAST-004
// also suppresses when the path variable (or any f-string interpolation
// variable that feeds it) was overwritten by a safe last assignment — a
// known sanitizer source, a constant default, or an OWASP Benchmark
// "always case B" match statement. The taint pipeline still inspects the
// flow precisely; the AST signal is the one being silenced.
func TestOpenVariableSuppressedBySafeAssignment(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			name: "fstring-prefix-always-case-B",
			code: `
def handler(request):
    param = request.args.get('name')
    possible = "ABC"
    guess = possible[1]
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = 'fallback'
    fileName = '/srv/' + bar
    fd = open(fileName, 'rb')
`,
		},
		{
			name: "fstring-prefix-get_safe_value",
			code: `
def handler(scr):
    param = scr.get_safe_value('name')
    fileName = '/srv/' + param
    fd = open(fileName, 'wb')
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanPython(tc.code)
			if f := findByRule(findings, "BATOU-PYAST-004"); f != nil {
				t.Errorf("expected BATOU-PYAST-004 to be suppressed; got: %s", f.Title)
			}
		})
	}
}

// TestOpenVariableSuppressedByContainmentGuard covers pyast-fpr: BATOU-PYAST-004
// also suppresses when the path variable feeding open() is validated by a
// containment / allowlist / startswith guard near the sink — extending the same
// guard reasoning the taint layer already applies to the path sinks. The match
// is pinned to the sink variable so a guard on an unrelated variable cannot
// over-suppress (covered by TestOpenContainmentGuardOnOtherVarStillFires).
func TestOpenVariableSuppressedByContainmentGuard(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			name: "in-allowlist-membership",
			code: `
def handler(request):
    p = request.args.get('f')
    if p in ALLOWED:
        with open(p) as fh:
            return fh.read()
`,
		},
		{
			name: "not-in-denylist-early-return",
			code: `
def handler(request):
    p = request.args.get('f')
    if p not in ALLOWED:
        return 'denied'
    return open(p).read()
`,
		},
		{
			name: "startswith-prefix-containment",
			code: `
def handler(request):
    p = request.args.get('f')
    if p.startswith(BASE):
        return open(p).read()
    return 'denied'
`,
		},
		{
			name: "concat-path-with-member-guard",
			code: `
def handler(request):
    bar = request.args.get('name')
    if bar in ALLOWED:
        f = open('/srv/' + bar, 'rb')
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanPython(tc.code)
			if f := findByRule(findings, "BATOU-PYAST-004"); f != nil {
				t.Errorf("expected BATOU-PYAST-004 to be suppressed by containment guard; got: %s", f.Title)
			}
		})
	}
}

// TestOpenContainmentGuardOnOtherVarStillFires guards over-suppression: a
// containment guard on a DIFFERENT variable than the one passed to open() must
// not silence the finding.
func TestOpenContainmentGuardOnOtherVarStillFires(t *testing.T) {
	code := `
def handler(request):
    q = request.args.get('q')
    p = request.args.get('f')
    if q in ALLOWED:
        pass
    with open(p) as fh:
        return fh.read()
`
	findings := scanPython(code)
	if findByRule(findings, "BATOU-PYAST-004") == nil {
		t.Error("containment guard on unrelated variable (q) must NOT suppress open(p)")
	}
}

// TestOpenVariableStillFiresWithoutGuard ensures the suppression heuristic
// remains specific: a file with a variable open() and no recognised guard
// still produces BATOU-PYAST-004.
func TestOpenVariableStillFiresWithoutGuard(t *testing.T) {
	code := `
def handler(request):
    bar = request.args.get('name')
    f = open('/srv/' + bar, 'rb')
`
	findings := scanPython(code)
	if findByRule(findings, "BATOU-PYAST-004") == nil {
		t.Error("expected BATOU-PYAST-004 to fire when no traversal guard is present")
	}
}

// TestOpenArgparseAttributeIsNotFlagged covers the argparse CLI idiom that
// dominated the scan_harness Python sample: shadowsocks-android, magisk,
// and bannedbook all use `open(args.input, ...)` / `open(opts.path)` in
// their build scripts. The path IS user input — but the user is the
// developer running the CLI, not a remote attacker.
func TestOpenArgparseAttributeIsNotFlagged(t *testing.T) {
	cases := map[string]string{
		"args.input": `
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--input')
args = parser.parse_args()
f = open(args.input, 'rb')
`,
		"opts.output write": `
opts = parser.parse_args()
f = open(opts.output, 'wb')
`,
		"options.path": `
options = parse_options()
with open(options.path) as f:
    pass
`,
		"flags.config": `
flags = parser.parse_args()
config = open(flags.config, 'r')
`,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			findings := scanPython(code)
			for _, f := range findings {
				if f.RuleID == "BATOU-PYAST-004" {
					t.Errorf("argparse-shaped open(%s) should not fire PYAST-004: %s",
						name, f.MatchedText)
				}
			}
		})
	}
}

// TestOpenNonArgparseAttributeStillFires guards over-suppression: an
// attribute access on a non-argparse receiver (e.g. request.body.path)
// still represents a real flow from external input.
func TestOpenNonArgparseAttributeStillFires(t *testing.T) {
	code := `
def handler(request):
    f = open(request.path, 'rb')
`
	findings := scanPython(code)
	if findByRule(findings, "BATOU-PYAST-004") == nil {
		t.Error("attribute access on non-argparse receiver (request.path) should still fire")
	}
}

func TestSQLPercentFormat(t *testing.T) {
	code := `
def handler(name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
`
	findings := scanPython(code)
	f := findByRule(findings, "BATOU-PYAST-005")
	if f == nil {
		t.Error("expected finding for SQL % formatting")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestSQLFString(t *testing.T) {
	code := `
def handler(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
`
	findings := scanPython(code)
	f := findByRule(findings, "BATOU-PYAST-005")
	if f == nil {
		t.Error("expected finding for SQL f-string injection")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "eval(x)",
		Language: rules.LangPython,
		Tree:     nil,
	}
	a := &PythonASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.go",
		Content:  "eval(x)",
		Language: rules.LangGo,
	}
	a := &PythonASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
# comment
def handler(x):
    eval(x)
`
	findings := scanPython(code)
	f := findByRule(findings, "BATOU-PYAST-001")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}
