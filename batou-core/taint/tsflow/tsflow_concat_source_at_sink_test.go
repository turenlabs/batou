package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Inline source-CALL inside a concatenation at a sink — recall FN (cross-language).
//
// The two-step concat form — `cmd = source(); sink(cmd + " --flag")` — already
// works because nodeIsTainted recurses binary operands for tracked variables.
// But a source CALL used inline and never bound to a local, reaching a sink (or
// an assignment RHS) WRAPPED in a binary concatenation —
// `os.system(request.args.get("c") + " --flag")`,
// `Runtime.exec(request.getParameter("c") + " x")` — was silently missed:
// findSourceInExpr (the inline fallback that resolves a source directly inside a
// sink argument) had no binary_expression case, so it returned nil for any
// concatenation. "source + literal" (appending a flag, extension, or suffix to
// user input) is one of the most common real-world injection shapes, so this was
// a high-value false negative.
//
// SCOPE NOTE — this fix is intentionally restricted to CALL-shaped sources
// (request.args.get(...), getenv(...), getParameter(...)). Attribute / subscript
// sources (req.body.b, $_GET['c']) are NOT resolved through the binary recursion:
// those access paths are governed by the field-sensitive taint map, and
// synthesising taint for them inline would collapse a specific field path to its
// bare source and break sibling distinctness (see TestMultiLevelField_* in the
// scanner package, and TestConcatSourceAtSink_AttributeSiblingExcluded below).
// Call sources return fresh tainted values and lie outside the access-path
// system, so resolving them inline is FP-safe.

func concatFlow(t *testing.T, lang rules.Language, fp, code string, cat taint.SinkCategory) bool {
	t.Helper()
	return hasTaintFlow(Analyze(code, fp, lang), cat)
}

func TestConcatSourceAtSink_Positive(t *testing.T) {
	cases := []struct {
		name string
		lang rules.Language
		fp   string
		code string
		cat  taint.SinkCategory
	}{
		{
			// source CALL on the LEFT of the concatenation
			name: "python-os-system-left",
			lang: rules.LangPython,
			fp:   "/app/h.py",
			code: "def h():\n    os.system(request.args.get(\"c\") + \" --flag\")\n",
			cat:  taint.SnkCommand,
		},
		{
			// source CALL on the RIGHT of the concatenation
			name: "python-os-system-right",
			lang: rules.LangPython,
			fp:   "/app/h.py",
			code: "def h():\n    os.system(\"echo \" + request.args.get(\"c\"))\n",
			cat:  taint.SnkCommand,
		},
		{
			// nested concatenation — source CALL in the middle
			name: "python-os-system-nested",
			lang: rules.LangPython,
			fp:   "/app/h.py",
			code: "def h():\n    os.system(\"echo \" + request.args.get(\"c\") + \" done\")\n",
			cat:  taint.SnkCommand,
		},
		{
			name: "java-runtime-exec-concat",
			lang: rules.LangJava,
			fp:   "/app/A.java",
			code: "public class A { void h(HttpServletRequest request) {\n  Runtime.getRuntime().exec(request.getParameter(\"c\") + \" x\");\n} }\n",
			cat:  taint.SnkCommand,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !concatFlow(t, tc.lang, tc.fp, tc.code, tc.cat) {
				t.Errorf("expected inline-concat-at-sink flow for %s, got none", tc.name)
			}
		})
	}
}

// The two-step concat form must keep working (regression guard for the path that
// already functioned via nodeIsTainted's binary recursion).
func TestConcatSourceAtSink_TwoStepRegression(t *testing.T) {
	code := "def h():\n    cmd = request.args.get(\"c\")\n    os.system(cmd + \" --flag\")\n"
	if !concatFlow(t, rules.LangPython, "/app/h.py", code, taint.SnkCommand) {
		t.Errorf("two-step concat regression: expected command flow, got none")
	}
}

// Negative controls: the binary recursion must NOT manufacture taint where there
// is no source, and an inline sanitizer wrapping the source operand must still
// suppress the flow.
func TestConcatSourceAtSink_NegativeControls(t *testing.T) {
	cases := []struct {
		name string
		lang rules.Language
		fp   string
		code string
		cat  taint.SinkCategory
	}{
		{
			// shlex.quote neutralizes the operand → no command flow
			name: "python-sanitized-operand",
			lang: rules.LangPython,
			fp:   "/app/h.py",
			code: "def h():\n    os.system(shlex.quote(request.args.get(\"c\")) + \" x\")\n",
			cat:  taint.SnkCommand,
		},
		{
			// both operands are constants
			name: "python-constant-concat",
			lang: rules.LangPython,
			fp:   "/app/h.py",
			code: "def h():\n    os.system(\"a\" + \"b\")\n",
			cat:  taint.SnkCommand,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if concatFlow(t, tc.lang, tc.fp, tc.code, tc.cat) {
				t.Errorf("expected NO flow for %s, but a flow was reported", tc.name)
			}
		})
	}
}

// Field-sensitivity guard: an ATTRIBUTE source concatenated at a sink, when a
// SIBLING field was read into a local earlier, must NOT fire. The binary
// recursion is deliberately restricted to call-shaped sources so it does not
// collapse `req.body.b` to its bare `req.body` source and defeat the
// field-sensitive access-path precision. This pins the scope decision so a
// future broadening of the binary case does not silently reintroduce the
// TestMultiLevelField_* false positives. (The same code WITHOUT the prior
// sibling read is a genuine vulnerability; this test only fixes the
// sibling-distinctness contract.)
func TestConcatSourceAtSink_AttributeSiblingExcluded(t *testing.T) {
	// JS: read req.body.a; concat the sibling req.body.b into a SQL sink.
	js := "function handle(req){\n  const x = req.body.a;\n  db.query(\"SELECT * FROM t WHERE c = \" + req.body.b);\n}"
	if concatFlow(t, rules.LangJavaScript, "/app/h.js", js, taint.SnkSQLQuery) {
		t.Errorf("attribute sibling req.body.b should not be resolved inline through the binary recursion")
	}
}

// TestCommandConcatAttributeSource is the load-bearing test for the Node.js
// shell command-injection (CWE-78) recall fix: an inline ATTRIBUTE/subscript
// source spliced into the single command string of a shell-exec sink — via
// concatenation OR template-literal interpolation — must fire at the dataflow
// tier. This is the canonical dvna `exec('ping -c 2 ' + req.body.address)`
// shape and the equally-common `exec(`ping ${req.params.target}`)` shape. The
// generic binary recursion in findSourceInExpr resolves only CALL-shaped
// sources (to protect the SQL/eval field-sensitive sibling contract), so before
// this fix the command-string concat/template forms with an attribute source
// were regex-hint-only (conf 0.5, no dataflow). The fix is command-sink-scoped
// so the SQL/eval sibling-distinctness contract above is untouched.
func TestCommandConcatAttributeSource(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// concatenation, attribute source, bare-destructured exec
			name: "js-exec-concat-attr",
			code: "const { exec } = require('child_process');\nfunction run(req, res) {\n  exec('ping -c 2 ' + req.body.address);\n}\n",
		},
		{
			// concatenation, attribute source, child_process.exec full form
			name: "js-child_process-exec-concat-attr",
			code: "const child_process = require('child_process');\nfunction run(req, res) {\n  child_process.exec('ping ' + req.body.address);\n}\n",
		},
		{
			// template-literal interpolation, attribute source
			name: "js-exec-template-attr",
			code: "const cp = require('child_process');\nfunction run(req, res) {\n  cp.exec(`ping -c 2 ${req.body.address}`);\n}\n",
		},
		{
			// subscript source in concat
			name: "js-exec-concat-subscript",
			code: "const cp = require('child_process');\nfunction run(req, res) {\n  cp.exec('ls ' + req.query['dir']);\n}\n",
		},
		{
			// execSync concat, attribute source
			name: "js-execsync-concat-attr",
			code: "const cp = require('child_process');\nfunction run(req, res) {\n  cp.execSync('cat ' + req.body.file);\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !concatFlow(t, rules.LangJavaScript, "/app/h.js", tc.code, taint.SnkCommand) {
				t.Errorf("expected CWE-78 command flow for inline attribute source in %s, got none", tc.name)
			}
		})
	}
}

// TestCommandConcatAttributeSource_SafeForms pins the precision boundary: the
// no-shell argv-array forms (execFile/spawn with an args ARRAY and no
// shell:true), a pure-literal command, and a shell-escaped operand must NOT
// fire. An interpolation-free arg in an execFile/spawn array runs without a
// shell, so a tainted array element is not command injection.
func TestCommandConcatAttributeSource_SafeForms(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// execFile with args array, no shell — tainted array element is safe
			name: "js-execfile-array",
			code: "const cp = require('child_process');\nfunction run(req, res) {\n  cp.execFile('ping', ['-c', '2', req.body.address]);\n}\n",
		},
		{
			// spawn with args array, no shell
			name: "js-spawn-array",
			code: "const cp = require('child_process');\nfunction run(req, res) {\n  cp.spawn('ping', ['-c', req.body.address]);\n}\n",
		},
		{
			// pure literal command, no taint
			name: "js-exec-literal",
			code: "const cp = require('child_process');\nfunction run() {\n  cp.exec('ls -la');\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if concatFlow(t, rules.LangJavaScript, "/app/h.js", tc.code, taint.SnkCommand) {
				t.Errorf("expected NO command flow for safe form %s, but a flow was reported", tc.name)
			}
		})
	}
}
