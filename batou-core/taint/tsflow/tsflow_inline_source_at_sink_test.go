package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Inline-source-at-sink recall FN (cross-language).
//
// A user-input source passed DIRECTLY into a sink argument with no intervening
// variable assignment — `os.system(request.args.get("c"))`,
// `Runtime.exec(request.getParameter("c"))`, `fs.readFile(req.params.name)` — is
// one of the most common real-world vulnerability shapes. Before this fix the
// walker's argument-taint check (nodeIsTainted) only resolved variables already
// seeded in the taint map, so it caught the two-step form
// (`x = source(); sink(x)`) but silently missed the inline form. The inline
// fallback (findSourceInExpr on the raw argument expression) was gated to PHP
// only (added with the PHP flat-script work). This test pins the generalization
// to all tsflow languages, and pins that the inline-sanitizer guard still
// suppresses sanitized inline forms.

func inlineFlow(t *testing.T, lang rules.Language, fp, code string, cat taint.SinkCategory) bool {
	t.Helper()
	return hasTaintFlow(Analyze(code, fp, lang), cat)
}

func TestInlineSourceAtSink_Positive(t *testing.T) {
	cases := []struct {
		name string
		lang rules.Language
		fp   string
		code string
		cat  taint.SinkCategory
	}{
		{
			name: "javascript-readfile",
			lang: rules.LangJavaScript,
			fp:   "/app/h.js",
			code: "function h(req){ fs.readFile(req.params.name); }",
			cat:  taint.SnkFileWrite,
		},
		{
			name: "python-os-system",
			lang: rules.LangPython,
			fp:   "/app/h.py",
			code: "def h():\n    os.system(request.args.get(\"c\"))\n",
			cat:  taint.SnkCommand,
		},
		{
			name: "ruby-system",
			lang: rules.LangRuby,
			fp:   "/app/h.rb",
			code: "def h\n  system(params[:c])\nend\n",
			cat:  taint.SnkCommand,
		},
		{
			name: "java-runtime-exec",
			lang: rules.LangJava,
			fp:   "/app/A.java",
			code: "public class A { void h(HttpServletRequest request) {\n  Runtime.getRuntime().exec(request.getParameter(\"c\"));\n} }\n",
			cat:  taint.SnkCommand,
		},
		{
			name: "kotlin-runtime-exec",
			lang: rules.LangKotlin,
			fp:   "/app/A.kt",
			code: "fun h(request: HttpServletRequest) {\n  Runtime.getRuntime().exec(request.getParameter(\"c\"))\n}\n",
			cat:  taint.SnkCommand,
		},
		{
			name: "perl-system",
			lang: rules.LangPerl,
			fp:   "/app/a.pl",
			code: "sub h {\n  my $q = CGI->new;\n  system($q->param('c'));\n}\n",
			cat:  taint.SnkCommand,
		},
		{
			name: "c-system-getenv",
			lang: rules.LangC,
			fp:   "/app/a.c",
			code: "void h(void) {\n  system(getenv(\"C\"));\n}\n",
			cat:  taint.SnkCommand,
		},
		{
			name: "cpp-system-getenv",
			lang: rules.LangCPP,
			fp:   "/app/a.cpp",
			code: "void h() {\n  system(std::getenv(\"C\"));\n}\n",
			cat:  taint.SnkCommand,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !inlineFlow(t, tc.lang, tc.fp, tc.code, tc.cat) {
				t.Errorf("expected inline-source-at-sink flow for %s, got none", tc.name)
			}
		})
	}
}

// PHP was the only language that resolved inline-source-at-sink before this
// change (it was added alongside the PHP flat-script work). Pin that it still
// fires after the gate was generalized.
func TestInlineSourceAtSink_PHPRegression(t *testing.T) {
	code := "<?php\nsystem($_GET['c']);\n"
	if !inlineFlow(t, rules.LangPHP, "/app/a.php", code, taint.SnkCommand) {
		t.Errorf("PHP regression: expected inline-source-at-sink command flow, got none")
	}
}

// The inline-sanitizer guard (containsInlineSanitizer) must still suppress an
// inline source that is wrapped in a recognized neutralizer for the sink
// category. These are NEGATIVE controls: a flow here would mean the
// generalization bypassed the sanitizer check.
func TestInlineSourceAtSink_SanitizedNegativeControls(t *testing.T) {
	cases := []struct {
		name string
		lang rules.Language
		fp   string
		code string
		cat  taint.SinkCategory
	}{
		{
			// shlex.quote neutralizes SnkCommand
			name: "python-shlex-quote",
			lang: rules.LangPython,
			fp:   "/app/h.py",
			code: "def h():\n    os.system(shlex.quote(request.args.get(\"c\")))\n",
			cat:  taint.SnkCommand,
		},
		{
			// path.basename neutralizes SnkFileWrite/SnkFileRead
			name: "javascript-path-basename",
			lang: rules.LangJavaScript,
			fp:   "/app/h.js",
			code: "function h(req){ fs.readFile(path.basename(req.params.name)); }",
			cat:  taint.SnkFileWrite,
		},
		{
			// Shellwords.escape neutralizes SnkCommand
			name: "ruby-shellwords-escape",
			lang: rules.LangRuby,
			fp:   "/app/h.rb",
			code: "def h\n  system(Shellwords.escape(params[:c]))\nend\n",
			cat:  taint.SnkCommand,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if inlineFlow(t, tc.lang, tc.fp, tc.code, tc.cat) {
				t.Errorf("expected NO flow (inline sanitizer present) for %s, but a flow was reported", tc.name)
			}
		})
	}
}

// Trust-boundary sinks (CWE-501) are deliberately EXCLUDED from the inline
// synthesis: a value passed directly into a session/env/queue sink is
// idiomatically preceded by a validation guard tsflow cannot model, so
// synthesising a fresh inline source there is FP-prone. The two-step path still
// reports trust-boundary flows — this only pins that the BARE inline form does
// not. (Mirror of the Rust rdkafka FutureProducer / Perl FormValidator cases
// this scoping protects.)
func TestInlineSourceAtSink_TrustBoundaryExcluded(t *testing.T) {
	// Perl: raw CGI param stored directly into the session inline
	// ($session->param('name', $cgi->param('name'))). This is a genuine
	// trust-boundary call-sink that WOULD fire under the inline synthesis; the
	// exclusion pins that it does not (it is the de-validator form of the
	// FormValidator::Simple test).
	code := "use CGI;\nsub h {\n  my $cgi = CGI->new;\n  $session->param('name', $cgi->param('name'));\n}\n"
	if inlineFlow(t, rules.LangPerl, "/app/h.pl", code, taint.SnkTrustBoundary) {
		t.Errorf("inline trust-boundary synthesis should be skipped, but a flow was reported")
	}
}

// Constant / non-source inline arguments must NOT produce a flow — guards
// against the generalization treating any inline expression as tainted.
func TestInlineSourceAtSink_ConstantNoFlow(t *testing.T) {
	cases := []struct {
		name string
		lang rules.Language
		fp   string
		code string
		cat  taint.SinkCategory
	}{
		{
			name: "python-constant",
			lang: rules.LangPython,
			fp:   "/app/h.py",
			code: "def h():\n    os.system(\"ls -la\")\n",
			cat:  taint.SnkCommand,
		},
		{
			name: "java-constant",
			lang: rules.LangJava,
			fp:   "/app/A.java",
			code: "public class A { void h() {\n  Runtime.getRuntime().exec(\"ls -la\");\n} }\n",
			cat:  taint.SnkCommand,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if inlineFlow(t, tc.lang, tc.fp, tc.code, tc.cat) {
				t.Errorf("expected NO flow for constant arg %s, but a flow was reported", tc.name)
			}
		})
	}
}
