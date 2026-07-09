package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for the Rust XSS output-encoder sanitizer completions added in this
// cycle:
//
//   rust.ammonia.clean_text              (ammonia plain-text HTML escaper)
//   rust.html_escape.encode_script_style (html-escape <script>/<style> context encoders)
//
// Each sanitizer has a paired "Vulnerable" test (asserting the source -> sink
// flow IS detected without the sanitizer) and a "Safe" test (asserting the
// flow is neutralized when the sanitizer wraps the tainted value inline).
//
// The sink used throughout is rust.rocket.rawhtml (SnkHTMLOutput): RawHtml(x)
// renders x as raw markup, so a tainted x is reflected XSS. ammonia::clean_text
// and html_escape::encode_script/encode_style all return a String directly, so
// the walker's inline-sanitizer pass recognizes them inside the sink argument.

func rustHasRawHtmlXSS(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Sink.ID == "rust.rocket.rawhtml" {
			return true
		}
	}
	return false
}

// --- Baseline: tainted value reaches RawHtml unsanitized ---

func TestRust_HtmlEncoder_Vulnerable_RawHtml(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let resp = RawHtml(name);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !rustHasRawHtmlXSS(flows) {
		t.Error("expected XSS flow for env::var -> RawHtml without a sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// --- ammonia::clean_text (plain-text HTML escaper) ---

func TestRust_AmmoniaCleanText_Safe(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let resp = RawHtml(ammonia::clean_text(&name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if rustHasRawHtmlXSS(flows) {
		t.Error("ammonia::clean_text should neutralize the XSS flow into RawHtml")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// --- html_escape::encode_script (<script> JS-text context) ---

func TestRust_HtmlEscapeScript_Safe(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let resp = RawHtml(html_escape::encode_script(&name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if rustHasRawHtmlXSS(flows) {
		t.Error("html_escape::encode_script should neutralize the XSS flow into RawHtml")
	}
}

// --- html_escape::encode_style (<style> CSS-text context) ---

func TestRust_HtmlEscapeStyle_Safe(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let resp = RawHtml(html_escape::encode_style(&name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if rustHasRawHtmlXSS(flows) {
		t.Error("html_escape::encode_style should neutralize the XSS flow into RawHtml")
	}
}

// --- Negative control: an unrelated encode_* name is NOT treated as the new
// script/style sanitizer (guards against the entry being over-broad). A
// fabricated `html_escape::encode_bogus` is not a real crate function and must
// not suppress the flow. ---

func TestRust_HtmlEscape_UnknownFn_StillVulnerable(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let resp = RawHtml(html_escape::encode_bogus(&name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !rustHasRawHtmlXSS(flows) {
		t.Error("a non-existent html_escape::encode_bogus must not be treated as a sanitizer")
	}
}
