package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// hasRubyHTMLSinkID reports whether any flow lands on the named HTML-output
// sink with CWE-79. Used to pin the revived raw()/.html_safe sinks precisely
// (a generic SnkHTMLOutput assertion could be satisfied by a sibling sink).
func hasRubyHTMLSinkID(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.CWEID == "CWE-79" &&
			f.Sink.Category == taint.SnkHTMLOutput {
			return true
		}
	}
	return false
}

// TestRuby_XSS_RawHelperRevived covers the dead-mechanism revival of the
// `ruby.rails.raw` sink. raw() is a BARE ActionView helper, so the call
// `raw(x)` carries no `ActionView` receiver — the old receiver-typed
// ObjectType ("ActionView") never matched and the sink was DEAD. Setting
// ObjectType "" routes it through tsflow's weak-sink path (re-validated
// against the `\braw\s*\(` Pattern). This is the load-bearing assertion: it
// FAILS on the baseline catalog (ObjectType "ActionView") and PASSES after.
func TestRuby_XSS_RawHelperRevived(t *testing.T) {
	code := `
def show(params)
  x = params[:x]
  raw(x)
end
`
	flows := Analyze(code, "/app/controllers/posts_controller.rb", rules.LangRuby)
	if !hasRubyHTMLSinkID(flows, "ruby.rails.raw") {
		t.Error("expected CWE-79 SnkHTMLOutput flow for params -> raw() (ruby.rails.raw)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// TestRuby_XSS_HtmlSafeRevived covers the dead-mechanism revival of the
// `ruby.rails.html_safe` sink. The receiver of `x.html_safe` is an arbitrary
// expression (here a tainted `params[:x]`), never literally a `String`-typed
// receiver — so the old ObjectType ("String") never matched and the sink was
// DEAD. ObjectType "" + the `\.html_safe` Pattern fires on any-receiver
// `.html_safe`. Load-bearing: FAILS on baseline, PASSES after the edit.
func TestRuby_XSS_HtmlSafeRevived(t *testing.T) {
	code := `
def show(params)
  x = params[:x]
  x.html_safe
end
`
	flows := Analyze(code, "/app/controllers/posts_controller.rb", rules.LangRuby)
	if !hasRubyHTMLSinkID(flows, "ruby.rails.html_safe") {
		t.Error("expected CWE-79 SnkHTMLOutput flow for params -> .html_safe (ruby.rails.html_safe)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// TestRuby_XSS_RawSanitizedNoFlow is the PRECISION guard for the revived
// raw() sink: an inline `raw(sanitize(params[:x]))` must NOT fire, because
// the existing Rails `sanitize` HTML-output sanitizer neutralizes the flow.
// This proves the revival did not regress sanitizer-aware suppression.
func TestRuby_XSS_RawSanitizedNoFlow(t *testing.T) {
	code := `
def show(params)
  raw(sanitize(params[:x]))
end
`
	flows := Analyze(code, "/app/controllers/posts_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO HTML output flow — sanitize() should neutralize raw()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// TestRuby_XSS_HEscapedHtmlSafeNoFlow is the PRECISION guard for the revived
// .html_safe sink: `h(params[:x]).html_safe` must NOT fire, because the value
// has been HTML-escaped via the Rails `h()` helper before being marked safe.
func TestRuby_XSS_HEscapedHtmlSafeNoFlow(t *testing.T) {
	code := `
def show(params)
  h(params[:x]).html_safe
end
`
	flows := Analyze(code, "/app/controllers/posts_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO HTML output flow — h() escaping should neutralize .html_safe")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
