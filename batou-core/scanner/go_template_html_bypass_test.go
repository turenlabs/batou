package scanner_test

// go_template_html_bypass_test.go — load-bearing coverage for the Go
// html/template escaping-BYPASS XSS recall fix (go_fpfilter.go).
//
// CONTRACT: `template.HTML(tainted)` / `template.JS(tainted)` /
// `template.CSS(tainted)` / `template.HTMLAttr(tainted)` are the explicit
// escaping-BYPASS conversions — a tainted value flowing into them is reflected
// XSS (CWE-79) and MUST surface at dataflow tier. The astflow engine already
// produces this flow (the sinks are alive in go_sinks.go); the bug was a
// scanner-level FP filter (goScanHasXSSGuard) that treated the mere presence of
// a `template.HTML(...)` call OR an `html/template` import in the look-back
// window as a safety signal, suppressing both the bypass sink itself AND any
// unrelated CWE-79 finding within 15 lines of it.
//
// These tests drive scanner.Scan() end-to-end (the same path `bin/batou scan`
// uses), so the fix cannot silently regress. With the buggy guard restored,
// the positive cases below produce zero CWE-79 findings (verified by copy-file
// revert during development).

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/testutil"
	"github.com/turenlabs/batou-rules/rules"
)

// hasCWE reports whether any finding carries the given CWE id (e.g. "CWE-79").
func hasCWE(result *testutil.ScanResult, cwe string) (rules.Finding, bool) {
	for _, f := range result.Findings {
		if f.CWEID == cwe {
			return f, true
		}
	}
	return rules.Finding{}, false
}

// TestGoTemplateHTMLBypass_TaintedVar is the headline positive case: a
// request-sourced string flows into template.HTML(), the canonical
// auto-escaping bypass. CWE-79 must fire at taint tier.
func TestGoTemplateHTMLBypass_TaintedVar(t *testing.T) {
	code := `package handler

import (
	"html/template"
	"net/http"
)

func Profile(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	out := template.HTML(name)
	_ = out
}
`
	result := testutil.ScanContent(t, "/app/profile.go", code)
	f, ok := hasCWE(result, "CWE-79")
	if !ok {
		t.Fatalf("template.HTML(tainted) must produce a CWE-79 XSS finding; got rules: %v", ruleIDsOf(result))
	}
	if !strings.HasPrefix(f.RuleID, "BATOU-TAINT-") {
		t.Errorf("expected a dataflow-tier (BATOU-TAINT-*) finding, got %s", f.RuleID)
	}
}

// TestGoTemplateJSBypass_TaintedVar covers the sibling template.JS() bypass.
func TestGoTemplateJSBypass_TaintedVar(t *testing.T) {
	code := `package handler

import (
	"html/template"
	"net/http"
)

func Widget(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	out := template.JS(name)
	_ = out
}
`
	result := testutil.ScanContent(t, "/app/widget.go", code)
	if _, ok := hasCWE(result, "CWE-79"); !ok {
		t.Fatalf("template.JS(tainted) must produce a CWE-79 finding; got rules: %v", ruleIDsOf(result))
	}
}

// TestGoTemplateHTMLBypass_InlineSource covers the direct inline-source form
// template.HTML(r.URL.Query().Get("x")) with no intermediate variable.
func TestGoTemplateHTMLBypass_InlineSource(t *testing.T) {
	code := `package handler

import (
	"html/template"
	"net/http"
)

func Inline(w http.ResponseWriter, r *http.Request) {
	out := template.HTML(r.URL.Query().Get("name"))
	_ = out
}
`
	result := testutil.ScanContent(t, "/app/inline.go", code)
	if _, ok := hasCWE(result, "CWE-79"); !ok {
		t.Fatalf("template.HTML(inline source) must produce a CWE-79 finding; got rules: %v", ruleIDsOf(result))
	}
}

// TestGoXSS_CollateralNotSuppressed is the collateral-damage case the buggy
// guard caused: a genuine reflected-XSS sink (w.Write of concatenated tainted
// HTML) sits a few lines below a *safe constant* template.HTML(...) call. The
// constant-arg template.HTML carries no taint and is correctly NOT flagged, but
// it must not silence the real XSS below it.
func TestGoXSS_CollateralNotSuppressed(t *testing.T) {
	code := `package handler

import (
	"html/template"
	"net/http"
)

func Page(w http.ResponseWriter, r *http.Request) {
	banner := template.HTML("<b>Welcome</b>")
	_ = banner
	name := r.FormValue("name")
	w.Write([]byte("<h1>" + name + "</h1>"))
}
`
	result := testutil.ScanContent(t, "/app/page.go", code)
	f, ok := hasCWE(result, "CWE-79")
	if !ok {
		t.Fatalf("a real w.Write XSS near a safe constant template.HTML must still fire CWE-79; got rules: %v", ruleIDsOf(result))
	}
	// The finding must be the real w.Write sink (line 12), not the safe const.
	if f.LineNumber != 12 {
		t.Errorf("expected the CWE-79 finding on the w.Write line (12); got line %d", f.LineNumber)
	}
}

// --- NEGATIVES: genuine safe forms must stay clean ---

// TestGoTemplateExecute_AutoEscapeStillClean confirms the legitimate
// auto-escaping render path (tmpl.Execute(w, structData) on an html/template)
// remains free of CWE-79 — this safety comes from the astflow layer's
// isHTMLTemplateExecute, independent of the removed fpfilter heuristic.
func TestGoTemplateExecute_AutoEscapeStillClean(t *testing.T) {
	code := `package handler

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("p").Parse("<h1>{{.Name}}</h1>"))

type data struct{ Name string }

func Render(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data{Name: r.FormValue("name")})
}
`
	result := testutil.ScanContent(t, "/app/render.go", code)
	if f, ok := hasCWE(result, "CWE-79"); ok {
		t.Errorf("auto-escaping html/template Execute must not produce CWE-79; got %s on line %d", f.RuleID, f.LineNumber)
	}
}

// TestGoXSS_HTMLEscapeStringSanitizerStillClean confirms the genuine escaping
// sanitizers (template.HTMLEscapeString / html.EscapeString) still neutralize
// the flow — the taint engine recognizes them as sanitizers.
func TestGoXSS_HTMLEscapeStringSanitizerStillClean(t *testing.T) {
	code := `package handler

import (
	"html/template"
	"net/http"
)

func Safe(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	esc := template.HTMLEscapeString(name)
	w.Write([]byte("<h1>" + esc + "</h1>"))
}
`
	result := testutil.ScanContent(t, "/app/safe.go", code)
	if f, ok := hasCWE(result, "CWE-79"); ok {
		t.Errorf("HTMLEscapeString-sanitized output must not produce CWE-79; got %s on line %d", f.RuleID, f.LineNumber)
	}
}

// ruleIDsOf returns the distinct rule IDs in a result, for failure messages.
func ruleIDsOf(result *testutil.ScanResult) []string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range result.Findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ids = append(ids, f.RuleID)
		}
	}
	return ids
}
