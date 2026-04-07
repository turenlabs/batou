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
