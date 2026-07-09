package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — web_sanitize (leafo) whitelist HTML/CSS sanitizer.
//
// web_sanitize is a production-grade Lua library for sanitizing untrusted
// HTML by parsing it and stripping dangerous elements/attributes via a
// whitelist (distinct from the entity-escapers already catalogued). Each
// function returns a sanitized value, so a tainted user-input -> sanitizer
// -> HTML-output flow must NOT fire.
//
// Per-feature file (not appended to tsflow_test.go) — the taint-research
// loop contends heavily on tsflow_test.go.
//
// Every positive test is paired with a negative control proving the same
// source/sink pair WOULD flow without the sanitizer, guarding against the
// silent-pass failure mode (sanitizer "passes" only because the sink never
// fired). The HTMLOutput sink used is ngx.say.
// =========================================================================

// --- web_sanitize.sanitize_html (SnkHTMLOutput) ---

func TestLua_WebSanitizeSanitizeHTML_SanitizesHTMLOutput(t *testing.T) {
	code := `
local web_sanitize = require("web_sanitize")
function handler()
    local args = ngx.req.get_uri_args()
    local body = args["body"]
    local safe = web_sanitize.sanitize_html(body)
    ngx.say(safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.7 {
			t.Errorf("expected web_sanitize.sanitize_html to sanitize HTML output flow, got conf %.2f", f.Confidence)
		}
	}
}

func TestLua_WebSanitizeSanitizeHTML_NegativeControl(t *testing.T) {
	code := `
function handler()
    local args = ngx.req.get_uri_args()
    local body = args["body"]
    ngx.say(body)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML-output flow without sanitizer (control); none of the configured sinks fired")
	}
}

// --- web_sanitize.extract_text (SnkHTMLOutput) ---

func TestLua_WebSanitizeExtractText_SanitizesHTMLOutput(t *testing.T) {
	code := `
local web_sanitize = require("web_sanitize")
function handler()
    local args = ngx.req.get_uri_args()
    local comment = args["comment"]
    local plain = web_sanitize.extract_text(comment)
    ngx.say(plain)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.7 {
			t.Errorf("expected web_sanitize.extract_text to sanitize HTML output flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- web_sanitize.sanitize_style (SnkHTMLOutput) ---

func TestLua_WebSanitizeSanitizeStyle_SanitizesHTMLOutput(t *testing.T) {
	code := `
local web_sanitize = require("web_sanitize")
function handler()
    local args = ngx.req.get_uri_args()
    local style = args["style"]
    local safe = web_sanitize.sanitize_style(style)
    ngx.say(safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.7 {
			t.Errorf("expected web_sanitize.sanitize_style to sanitize HTML output flow, got conf %.2f", f.Confidence)
		}
	}
}

// --- registration sanity: the three entries are present in the catalog ---

func TestLua_WebSanitize_Registered(t *testing.T) {
	want := map[string]bool{
		"lua.web_sanitize.sanitize_html":  false,
		"lua.web_sanitize.extract_text":   false,
		"lua.web_sanitize.sanitize_style": false,
	}
	for _, s := range taint.SanitizersForLanguage(rules.LangLua) {
		if _, ok := want[s.ID]; ok {
			want[s.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("sanitizer %q not registered for Lua", id)
		}
	}
}
