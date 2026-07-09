package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Go's stdlib `regexp` uses RE2 and is not vulnerable to catastrophic
// backtracking. The real ReDoS exposure (CWE-1333) comes from third-party
// backtracking engines — dlclark/regexp2 and the go-pcre cgo bindings — that
// accept the *pattern* (arg 0) from the caller. A tainted pattern reaching any
// of their Compile/MustCompile entry points is a ReDoS sink. These tests
// verify the new go_sinks.go SnkRegexDoS entries fire via astflow's
// package-level call matching.

// regexDoSCase is one taint fixture: a request source flowing (or not) into a
// backtracking regex-compile sink.
type regexDoSCase struct {
	name   string
	import_ string
	body   string // statements inside handler(); has access to w, r
}

func buildRegexDoS(imp, body string) string {
	return `package main

import (
	"net/http"
` + imp + `
)

func handler(w http.ResponseWriter, r *http.Request) {
` + body + `
}
`
}

func TestAnalyzeGo_BacktrackingRegex_ReDoS(t *testing.T) {
	cases := []regexDoSCase{
		{
			"regexp2.Compile",
			"\t\"github.com/dlclark/regexp2\"",
			`	pat := r.URL.Query().Get("pat")
	_, _ = regexp2.Compile(pat, regexp2.None)`,
		},
		{
			"pcre.Compile",
			"\tpcre \"github.com/GRbit/go-pcre\"",
			`	pat := r.URL.Query().Get("pat")
	_, _ = pcre.Compile(pat, 0)`,
		},
		{
			"pcre.CompileJIT",
			"\tpcre \"github.com/GRbit/go-pcre\"",
			`	pat := r.URL.Query().Get("pat")
	_, _ = pcre.CompileJIT(pat, 0, 0)`,
		},
		{
			"pcre.MustCompileJIT",
			"\tpcre \"github.com/GRbit/go-pcre\"",
			`	pat := r.FormValue("pat")
	_ = pcre.MustCompileJIT(pat, 0, 0)`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := AnalyzeGo(buildRegexDoS(tc.import_, tc.body), "/app/handler.go")
			if !hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("%s: expected SnkRegexDoS flow, got %d flows", tc.name, len(flows))
			}
		})
	}
}

// Negative control: a constant (non-tainted) pattern must NOT produce a ReDoS
// flow, even with a backtracking engine.
func TestAnalyzeGo_BacktrackingRegex_ConstantPattern_NoFlow(t *testing.T) {
	code := buildRegexDoS("\t\"github.com/dlclark/regexp2\"",
		`	_ = r.URL.Query().Get("ignored")
	_ = regexp2.MustCompile("^[a-z]+$", regexp2.None)`)
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Errorf("constant regex pattern should not produce a ReDoS flow, got %d flows", len(flows))
	}
}
