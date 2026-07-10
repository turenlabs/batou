package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"

	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for the binary-to-text encoding sanitizers added in cycle #1115:
//
//   rust.hex.encode         (hex crate, lowercase [0-9a-f])
//   rust.hex.encode_upper   (hex crate, uppercase [0-9A-F])
//   rust.base64.encode      (base64 crate free fn, [A-Za-z0-9+/=])
//
// These mirror the existing C (c.openssl.buf2hexstr, c.encoding.glib_base64_encode)
// and Zig (zig.fmt.fmtSliceHexLower, zig.base64.encode) precedents: hex/base64
// encoding produces an alphabet with no HTML/log/header injection metacharacters,
// so the result is safe to embed in those output contexts.
//
// The HTML output sink used for the baseline is rocket's RawHtml (rust.rocket.rawhtml),
// which is a real call_expression (not a macro) and is proven to fire by
// TestRust_RocketRawHtmlXSS. Each sanitizer has a paired "Safe" test that wraps the
// tainted value in the encoder inside the sink's argument list, which the walker's
// containsInlineSanitizer pass detects.
//
// NOTE: Rust log sinks (log::info!/error!) are macro_invocation nodes, which tsflow
// cannot trace through (see TestRust_UnsanitizedLogInjection) — so the SnkLog /
// SnkHeader neutralizations these entries also declare are exercised at the catalog
// level, not via a tsflow flow test.

// --- Baseline: tainted value reaching RawHtml IS detected (control for the Safe tests) ---

func TestRust_HexBase64_Vulnerable_HtmlOutput(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let _resp = RawHtml(name);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasHTMLFlow(flows) {
		t.Error("expected HTML output flow for env::var -> RawHtml (baseline must fire for Safe tests to be meaningful)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- hex::encode neutralizes the HTML-output flow ---

func TestRust_HexEncode_Safe_HtmlOutput(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let _resp = RawHtml(hex::encode(name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("hex::encode should neutralize HTML output flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- hex::encode_upper neutralizes the HTML-output flow ---

func TestRust_HexEncodeUpper_Safe_HtmlOutput(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let _resp = RawHtml(hex::encode_upper(name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("hex::encode_upper should neutralize HTML output flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- base64::encode neutralizes the HTML-output flow ---

func TestRust_Base64Encode_Safe_HtmlOutput(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let _resp = RawHtml(base64::encode(name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("base64::encode should neutralize HTML output flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Negative control: an unrelated .encode() must NOT be treated as the
// hex/base64 sanitizer (ObjectType scoping prevents the join-bomb). ---

func TestRust_HexBase64_NegativeControl_UnrelatedEncode(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let _resp = RawHtml(myserializer.encode(name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasHTMLFlow(flows) {
		t.Error("expected HTML output flow to survive: myserializer.encode is NOT the hex/base64 sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func hasHTMLFlow(flows []taint.TaintFlow) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			return true
		}
	}
	return false
}
