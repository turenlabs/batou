// Cross-file Python HTML-sanitizer drift regression (#1262).
//
// Continuation of #1261 (cross-file parameterized-SQL FP). The
// cross-file walk carries its OWN sanitizer-detection regex
// (`pythonSanitizerRe`) that had drifted from the single-file
// SnkHTMLOutput catalog (taint/languages/python_sanitizers.go). The
// catalog lists `strip_tags`, the nh3/lxml `clean` family, and the
// Django `conditional_escape` / `force_escape` escapers as HTML
// sanitizers, but the cross-file regex's `escape` catch-all missed
// them (word-boundary on `conditional_escape`; no shared substring for
// strip/clean). A value wrapped in one of these and passed across a
// function boundary into an HTML sink was wrongly flagged as a
// cross-file XSS flow.
//
// These tests are LOAD-BEARING: revert the regex addition in
// crossfile_walk_python.go and the sanitized subtests FAIL (the FP
// returns). The unsanitized subtest must fire BOTH before and after
// the fix (the fix must not over-suppress real flows).
package graph

import (
	"testing"
)

// TestPythonCrossFile_HTMLSanitizerDrift_NotFlagged asserts that a
// handler wrapping user input in an HTML sanitizer the single-file
// catalog recognizes — and then handing the value to a separate-file
// helper that emits it via HttpResponse — produces NO cross-file
// HTML_OUTPUT finding. Covers both the inline-wrap form
// (`show(strip_tags(req)))`) and the prev-line-assignment form
// (`v = strip_tags(req); show(v)`).
func TestPythonCrossFile_HTMLSanitizerDrift_NotFlagged(t *testing.T) {
	// Each case names a sanitizer the catalog lists as SnkHTMLOutput
	// but that pythonSanitizerRe missed before #1262.
	cases := []struct {
		name string
		call string // the sanitizer-wrapped argument expression
	}{
		{"strip_tags", `strip_tags(request.GET.get("q"))`},
		{"nh3.clean", `nh3.clean(request.GET.get("q"))`},
		{"clean_html", `clean_html(request.GET.get("q"))`},
		{"conditional_escape", `conditional_escape(request.GET.get("q"))`},
		{"force_escape", `force_escape(request.GET.get("q"))`},
	}

	for _, tc := range cases {
		t.Run(tc.name+"_inline", func(t *testing.T) {
			cg, paths := pythonScanFixture(t, map[string]string{
				"render.py": `from django.http import HttpResponse

def show(content):
    return HttpResponse(content)
`,
				"views.py": `from django.utils.html import strip_tags, conditional_escape, force_escape
from render import show

def page(request):
    return show(` + tc.call + `)
`,
			})
			primePythonSigs(t, cg, paths)

			findings := WalkCrossFileTaintFlows(cg, nil)
			html := filterFindingsByRule(findings, "BATOU-INTERPROC-HTML_OUTPUT")
			if len(html) != 0 {
				t.Errorf("%s-wrapped arg crossing into HttpResponse must not produce an HTML_OUTPUT finding; got %d: %v",
					tc.name, len(html), findingRuleIDs(findings))
			}
		})

		t.Run(tc.name+"_prevline", func(t *testing.T) {
			cg, paths := pythonScanFixture(t, map[string]string{
				"render.py": `from django.http import HttpResponse

def show(content):
    return HttpResponse(content)
`,
				"views.py": `from django.utils.html import strip_tags, conditional_escape, force_escape
from render import show

def page(request):
    cleaned = ` + tc.call + `
    return show(cleaned)
`,
			})
			primePythonSigs(t, cg, paths)

			findings := WalkCrossFileTaintFlows(cg, nil)
			html := filterFindingsByRule(findings, "BATOU-INTERPROC-HTML_OUTPUT")
			if len(html) != 0 {
				t.Errorf("%s-assigned var crossing into HttpResponse must not produce an HTML_OUTPUT finding; got %d: %v",
					tc.name, len(html), findingRuleIDs(findings))
			}
		})
	}
}

// TestPythonCrossFile_HTMLSanitizerDrift_UnsanitizedStillFires is the
// recall guard: the SAME two-file shape WITHOUT a sanitizer must still
// emit a cross-file HTML_OUTPUT finding. This must pass both before and
// after the #1262 regex change — proving the fix did not over-suppress.
func TestPythonCrossFile_HTMLSanitizerDrift_UnsanitizedStillFires(t *testing.T) {
	cg, paths := pythonScanFixture(t, map[string]string{
		"render.py": `from django.http import HttpResponse

def show(content):
    return HttpResponse(content)
`,
		"views.py": `from render import show

def page(request):
    return show(request.GET.get("q"))
`,
	})
	primePythonSigs(t, cg, paths)

	findings := WalkCrossFileTaintFlows(cg, nil)
	html := filterFindingsByRule(findings, "BATOU-INTERPROC-HTML_OUTPUT")
	if len(html) == 0 {
		t.Fatalf("unsanitized user input crossing into HttpResponse must produce an HTML_OUTPUT finding; got none (emitted: %v)",
			findingRuleIDs(findings))
	}
}
