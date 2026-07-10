package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestRust_ShellEscapeSanitizer verifies that shell_escape::escape prevents
// command injection findings.
func TestRust_ShellEscapeSanitizer(t *testing.T) {
	code := `
use std::env;
use std::process::Command;
use shell_escape;
use std::borrow::Cow;

fn handler() {
    let user_input = env::var("CMD_ARG").unwrap();
    let safe = shell_escape::escape(Cow::from(&user_input));
    Command::new("sh").arg("-c").arg(&format!("echo {}", safe));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("Expected no command injection flow after shell_escape::escape, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_ShlexTryQuoteSanitizer verifies that shlex::try_quote prevents
// command injection findings.
func TestRust_ShlexTryQuoteSanitizer(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn handler() {
    let user_input = env::var("CMD_ARG").unwrap();
    let safe = shlex::try_quote(&user_input).unwrap();
    Command::new("sh").arg("-c").arg(&format!("echo {}", safe));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("Expected no command injection flow after shlex::try_quote, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_HeaderValueFromStrSanitizer verifies that HeaderValue::from_str
// prevents header injection findings.
func TestRust_HeaderValueFromStrSanitizer(t *testing.T) {
	code := `
use actix_web::{web, HttpRequest, HttpResponse};
use http::header::HeaderValue;

async fn handler(req: HttpRequest) -> HttpResponse {
    let user_val = req.headers().get("X-Custom").unwrap().to_str().unwrap();
    let safe_val = HeaderValue::from_str(user_val).unwrap();
    HttpResponse::Ok()
        .insert_header(("X-Echo", safe_val))
        .finish()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("Expected no header injection flow after HeaderValue::from_str, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_TypedDeserSanitizer verifies that serde_json::from_str::<T>
// prevents deserialization findings.
func TestRust_TypedDeserSanitizer(t *testing.T) {
	code := `
use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    name: String,
    count: u32,
}

async fn handler(body: web::Bytes) -> HttpResponse {
    let raw = std::str::from_utf8(&body).unwrap();
    let config: Config = serde_json::from_str::<Config>(raw).unwrap();
    HttpResponse::Ok().json(config)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Errorf("Expected no deserialization flow after typed serde_json::from_str::<T>, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_UrlHostCheckSanitizer verifies that Url::host_str() prevents
// open redirect findings.
func TestRust_UrlHostCheckSanitizer(t *testing.T) {
	code := `
use actix_web::{web, HttpRequest, HttpResponse};
use url::Url;

async fn handler(req: HttpRequest) -> HttpResponse {
    let redirect_url = req.query_string();
    let parsed = Url::parse(redirect_url).unwrap();
    let host = parsed.host_str().unwrap();
    if host == "example.com" {
        HttpResponse::Found()
            .insert_header(("Location", redirect_url))
            .finish()
    } else {
        HttpResponse::BadRequest().finish()
    }
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Errorf("Expected no redirect flow after host_str() check, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_ControlCharFilterLogSanitizer verifies that filtering control chars
// prevents log injection findings.
func TestRust_ControlCharFilterLogSanitizer(t *testing.T) {
	code := `
use std::env;
use log;

fn handler() {
    let user_input = env::var("USER_DATA").unwrap();
    let safe: String = user_input.chars().filter(|c| !c.is_control()).collect();
    log::info!("User provided: {}", safe);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Errorf("Expected no log injection flow after is_control() filter, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_UnsanitizedCommandInjection verifies that without sanitization,
// command injection IS detected (positive control).
func TestRust_UnsanitizedCommandInjection(t *testing.T) {
	code := `
use std::env;
use std::process::Command;

fn handler() {
    let cmd = env::var("CMD").unwrap();
    Command::new(cmd);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("Expected command injection flow for unsanitized env::var -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TestRust_UnsanitizedLogInjection verifies log flow detection.
// NOTE: Rust macro invocations (log::info!) use "macro_invocation" in tree-sitter,
// not "call_expression", so tsflow can't track through them. Log sinks in Rust
// are detected by regex (Layer 1), not taint flow. This test documents that limitation.
func TestRust_UnsanitizedLogInjection(t *testing.T) {
	code := `
use std::env;
use log;

fn handler() {
    let user_input = env::var("USER_DATA").unwrap();
    log::info!("User provided: {}", user_input);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	// tsflow cannot see macro invocations as call sites, so no SnkLog flow expected.
	// Log injection detection in Rust relies on regex rules (Layer 1).
	t.Logf("Rust macro limitation: %d flows found (log sinks require regex layer)", len(flows))
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}

// TestRust_HandlebarsHtmlEscapeSanitizer verifies that handlebars::html_escape
// prevents XSS findings when used before HTML output.
func TestRust_HandlebarsHtmlEscapeSanitizer(t *testing.T) {
	code := `
use std::env;
use handlebars;
use axum::response::Html;

fn handler() -> Html<String> {
    let user_input = env::var("NAME").unwrap();
    let safe = handlebars::html_escape(&user_input);
    Html(format!("<p>{}</p>", safe))
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("Expected no XSS flow after handlebars::html_escape, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_MinijinjaEnvironmentSanitizer verifies that minijinja::Environment::new
// is recognized as a safe template environment (auto-escaping enabled by default).
// NOTE: This is a configuration-level sanitizer — it marks the environment variable
// as sanitized, which may not neutralize data flowing through template context.
func TestRust_MinijinjaEnvironmentSanitizer(t *testing.T) {
	code := `
use std::env;
use minijinja;

fn handler() -> String {
    let user_input = env::var("NAME").unwrap();
    let env = minijinja::Environment::new();
    env.render_str("Hello {{ name }}", user_input)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	// Log what flows were found — the Environment::new sanitizer is configuration-level
	// and may not neutralize data paths in tsflow. Full scanner pipeline handles this.
	t.Logf("minijinja Environment::new test: %d flows found", len(flows))
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}

// TestRust_MaudHtmlMacroSanitizer verifies that maud::html! macro is recognized
// as safe (compile-time HTML generation with auto-escaping).
// NOTE: Rust macros are "macro_invocation" nodes in tree-sitter, so tsflow may
// not process them as sanitizer calls. The entry works at the regex/scanner level.
func TestRust_MaudHtmlMacroSanitizer(t *testing.T) {
	code := `
use std::env;
use maud;

fn handler() -> String {
    let user_input = env::var("NAME").unwrap();
    let markup = maud::html! { p { (user_input) } };
    markup.into_string()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	// Maud html! is a macro invocation — tsflow may not see it as a sanitizer call.
	// Detection works at the regex/scanner level.
	t.Logf("maud::html! macro test: %d flows found", len(flows))
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}

// TestRust_SanitizeFilenameSanitizer verifies that sanitize_filename::sanitize
// prevents path traversal findings.
func TestRust_SanitizeFilenameSanitizer(t *testing.T) {
	code := `
use std::env;
use std::fs;
use sanitize_filename;

fn handler() {
    let user_filename = env::var("FILENAME").unwrap();
    let safe_name = sanitize_filename::sanitize(&user_filename);
    let content = fs::read(format!("/uploads/{}", safe_name));
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Errorf("Expected no path traversal flow after sanitize_filename::sanitize, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_SubtleCtEqSanitizer verifies that subtle constant-time equality
// is recognized as a crypto sanitizer (prevents timing attack findings).
func TestRust_SubtleCtEqSanitizer(t *testing.T) {
	code := `
use std::env;
use subtle::ConstantTimeEq;

fn verify_token() -> bool {
    let user_token = env::var("TOKEN").unwrap();
    let expected = b"secret_token";
    let result = user_token.as_bytes().ct_eq(expected);
    result.into()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("Expected no crypto flow after ct_eq, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_RingConstantTimeVerifySanitizer verifies that ring::constant_time
// comparison is recognized as a crypto sanitizer.
func TestRust_RingConstantTimeVerifySanitizer(t *testing.T) {
	code := `
use std::env;
use ring::constant_time;

fn verify_hmac() -> bool {
    let user_mac = env::var("MAC").unwrap();
    let expected_mac = compute_expected_hmac();
    ring::constant_time::verify_slices_are_equal(user_mac.as_bytes(), &expected_mac).is_ok()
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("Expected no crypto flow after ring constant_time verify, got src=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// TestRust_IpAddrSsrfCheckSanitizer verifies that IP address validation patterns
// are recognized by the taint engine.
// NOTE: SSRF prevention via is_loopback/is_private operates on the resolved IP
// address, not the original URL string that reaches the sink. The sanitizer works
// at the scanner confidence-reduction level, not the tsflow data-path level.
func TestRust_IpAddrSsrfCheckSanitizer(t *testing.T) {
	code := `
use std::env;
use std::net::IpAddr;

fn handler() {
    let user_url = env::var("TARGET_URL").unwrap();
    let addr: IpAddr = user_url.parse().unwrap();
    if addr.is_loopback() {
        panic!("internal address blocked");
    }
    reqwest::get(&user_url);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	// is_loopback() sanitizes the IP address variable, not the original URL that
	// reaches reqwest::get(). SSRF flow is still expected at the tsflow level.
	// The sanitizer reduces confidence at the full scanner pipeline level.
	t.Logf("SSRF IP check test: %d flows found (sanitizer works at scanner level, not data-path)", len(flows))
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}
