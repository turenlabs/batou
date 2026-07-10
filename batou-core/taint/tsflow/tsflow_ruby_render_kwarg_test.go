package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// renderKwargFlow reports whether any flow reaches the given Rails render
// keyword-arg sink with the expected CWE at >= the required confidence. The CWE
// assertion matters because the OWASP-style harness matches by CWE number.
func renderKwargFlow(flows []taint.TaintFlow, sinkID, cwe string, minConf float64) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.CWEID == cwe && f.Confidence >= minConf {
			return true
		}
	}
	return false
}

func anyRenderKwargSink(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		switch f.Sink.ID {
		case "ruby.rails.render.html", "ruby.rails.render.inline",
			"ruby.rails.render.file", "ruby.rails.render.text":
			return true
		}
	}
	return false
}

// TestRuby_RenderKwarg_FiresOnTaintedValue is the load-bearing RECALL test for
// the revived Rails keyword-arg render sinks (render html:/inline:/file:/text:).
// They were dead: keyed MethodName "render html:"/etc. + ObjectType
// "ActionController", but extractMethodNames("render html:") mangles the
// space+colon to an empty final component, so the sink was registered under NO
// key in sinksByMethod and was never a candidate for a `render` call. Re-keyed
// bare (ObjectType:"" + MethodName:"render"), the empty-ObjectType wildcard
// branch re-validates the call text against the tight Pattern (weakSinkPatternOK)
// and the dataflow flow fires. Covers the two-step variable form AND the
// tracked-variable interpolation form. render file: is the CVE-2019-5418
// arbitrary-file-read shape (CWE-22).
func TestRuby_RenderKwarg_FiresOnTaintedValue(t *testing.T) {
	vuln := []struct {
		name   string
		code   string
		sinkID string
		cwe    string
	}{
		{
			name:   "inline_two_step",
			code:   "\nclass C < ApplicationController\n  def a\n    x = params[:y]\n    render inline: x\n  end\nend\n",
			sinkID: "ruby.rails.render.inline",
			cwe:    "CWE-79",
		},
		{
			name:   "inline_interpolation_tracked_var",
			code:   "\nclass C < ApplicationController\n  def a\n    x = params[:y]\n    render inline: \"Hello #{x}\"\n  end\nend\n",
			sinkID: "ruby.rails.render.inline",
			cwe:    "CWE-79",
		},
		{
			name:   "html_two_step",
			code:   "\nclass C < ApplicationController\n  def a\n    h = params[:h]\n    render html: h\n  end\nend\n",
			sinkID: "ruby.rails.render.html",
			cwe:    "CWE-79",
		},
		{
			// CVE-2019-5418: tainted path to render file: → arbitrary file read.
			name:   "file_two_step",
			code:   "\nclass C < ApplicationController\n  def a\n    p = params[:path]\n    render file: p\n  end\nend\n",
			sinkID: "ruby.rails.render.file",
			cwe:    "CWE-22",
		},
		{
			name:   "text_two_step",
			code:   "\nclass C < ApplicationController\n  def a\n    t = params[:t]\n    render text: t\n  end\nend\n",
			sinkID: "ruby.rails.render.text",
			cwe:    "CWE-79",
		},
	}
	for _, tc := range vuln {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/controllers/c.rb", rules.LangRuby)
			if !renderKwargFlow(flows, tc.sinkID, tc.cwe, 0.9) {
				t.Errorf("expected %s (%s) flow conf>=0.9 for %s; got %d flows", tc.sinkID, tc.cwe, tc.name, len(flows))
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (id=%s, cwe=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.Confidence)
				}
			}
		})
	}
}

// TestRuby_RenderKwarg_SafeFormsDoNotFire is THE false-positive gate. The
// bare-keyed render sink must not collide with the pervasive SAFE render forms:
// a template/action symbol (`render :index`), a JSON/partial render whose value
// is benign for XSS, a constant string, and — critically — a value wrapped in an
// HTML sanitizer (`render html: sanitize(x)`). The sanitize case exercises the
// kwarg-pair sanitizer recursion in containsInlineSanitizer (the dangerous arg
// is a `pair` node whose VALUE carries the sanitizer).
func TestRuby_RenderKwarg_SafeFormsDoNotFire(t *testing.T) {
	safe := []struct {
		name string
		code string
	}{
		{"render_action_symbol", "\nclass C < ApplicationController\n  def a\n    render :index\n  end\nend\n"},
		{"render_json", "\nclass C < ApplicationController\n  def a\n    data = params[:d]\n    render json: data\n  end\nend\n"},
		{"render_partial", "\nclass C < ApplicationController\n  def a\n    render partial: \"x\"\n  end\nend\n"},
		{"render_html_constant", "\nclass C < ApplicationController\n  def a\n    render html: \"<b>const</b>\"\n  end\nend\n"},
		{"render_html_sanitized", "\nclass C < ApplicationController\n  def a\n    h = params[:h]\n    render html: sanitize(h)\n  end\nend\n"},
		{"render_html_escaped", "\nclass C < ApplicationController\n  def a\n    h = params[:h]\n    render html: ERB::Util.html_escape(h)\n  end\nend\n"},
		{"render_html_strip_tags_two_step", "\nclass C < ApplicationController\n  def a\n    h = params[:h]\n    safe = strip_tags(h)\n    render html: safe\n  end\nend\n"},
	}
	for _, tc := range safe {
		t.Run(tc.name, func(t *testing.T) {
			flows := Analyze(tc.code, "/app/controllers/c.rb", rules.LangRuby)
			if anyRenderKwargSink(flows) {
				t.Errorf("FALSE POSITIVE: render kwarg sink flagged on safe %s", tc.name)
				for _, f := range flows {
					t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
				}
			}
		})
	}
}
