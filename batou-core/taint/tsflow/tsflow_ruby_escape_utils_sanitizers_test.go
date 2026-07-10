package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — escape_utils gem output encoders neutralize XSS (CWE-79)
//
// The escape_utils gem (brianmario/escape_utils) provides fast C-extension
// HTML/JavaScript/URL escapers used by html-pipeline and others. Code that
// routes user input through EscapeUtils.escape_html / escape_javascript /
// escape_url before writing it to an HTML-output sink (safe_concat) should
// NOT be flagged as an HTML-output (XSS) flow.
//
// safe_concat is used as the sink because it is a free-function sink
// (ObjectType "") that tsflow matches by method name alone, giving a real
// baseline flow (see the Unsanitized negative control below).
// =========================================================================

func TestRuby_EscapeUtils_EscapeHtml_SanitizesHTMLOutput(t *testing.T) {
	code := `
require 'escape_utils'
def handler(params)
    name = params[:name]
    safe = EscapeUtils.escape_html(name)
    safe_concat(safe)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("EscapeUtils.escape_html should neutralize HTML-output (XSS) taint flow")
	}
}

func TestRuby_EscapeUtils_EscapeJavascript_SanitizesHTMLOutput(t *testing.T) {
	code := `
require 'escape_utils'
def handler(params)
    name = params[:name]
    safe = EscapeUtils.escape_javascript(name)
    safe_concat(safe)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("EscapeUtils.escape_javascript should neutralize HTML-output (XSS) taint flow")
	}
}

func TestRuby_EscapeUtils_EscapeUrl_SanitizesHTMLOutput(t *testing.T) {
	code := `
require 'escape_utils'
def handler(params)
    target = params[:url]
    safe = EscapeUtils.escape_url(target)
    safe_concat(safe)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("EscapeUtils.escape_url should neutralize HTML-output taint flow (CGI.escape equivalent)")
	}
}

// Negative control: identical shape WITHOUT the escape_utils call must still
// produce the HTML-output flow (proves the sink fires and the sanitizer above
// is what removes the flow, not an absent baseline).
func TestRuby_EscapeUtils_Unsanitized_HTMLOutputFlow(t *testing.T) {
	code := `
def handler(params)
    name = params[:name]
    safe_concat(name)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML-output flow for unsanitized params[:name] -> safe_concat()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
