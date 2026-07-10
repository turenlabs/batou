package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestRust_UreqGetSSRF verifies that ureq::get with tainted URL is detected.
func TestRust_UreqGetSSRF(t *testing.T) {
	code := `
use std::env;

fn fetch_url() {
    let url = env::var("TARGET_URL").unwrap();
    let resp = ureq::get(&url).call().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.ureq.get" {
			found = true
		}
	}
	if !found {
		t.Error("Expected SSRF finding for ureq::get with tainted URL")
	}
}

// TestRust_UreqPostSSRF verifies that ureq::post with tainted URL is detected.
func TestRust_UreqPostSSRF(t *testing.T) {
	code := `
use std::env;

fn post_data() {
    let url = env::var("TARGET_URL").unwrap();
    let resp = ureq::post(&url).send_string("body").unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.ureq.post" {
			found = true
		}
	}
	if !found {
		t.Error("Expected SSRF finding for ureq::post with tainted URL")
	}
}

// TestRust_IsahcGetSSRF verifies that isahc::get with tainted URL is detected.
func TestRust_IsahcGetSSRF(t *testing.T) {
	code := `
use std::env;

fn fetch() {
    let url = env::var("API_ENDPOINT").unwrap();
    let resp = isahc::get(&url).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.isahc.get" {
			found = true
		}
	}
	if !found {
		t.Error("Expected SSRF finding for isahc::get with tainted URL")
	}
}

// TestRust_SurfGetSSRF verifies that surf::get with tainted URL is detected.
func TestRust_SurfGetSSRF(t *testing.T) {
	code := `
use std::env;

async fn fetch() {
    let url = env::var("REMOTE_URL").unwrap();
    let resp = surf::get(&url).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.surf.request" {
			found = true
		}
	}
	if !found {
		t.Error("Expected SSRF finding for surf::get with tainted URL")
	}
}

// TestRust_RocketRawHtmlXSS verifies that RawHtml with tainted content is detected.
func TestRust_RocketRawHtmlXSS(t *testing.T) {
	code := `
use std::env;

fn index() {
    let name = env::var("USER_INPUT").unwrap();
    let resp = RawHtml(name);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Sink.ID == "rust.rocket.rawhtml" {
			found = true
		}
	}
	if !found {
		t.Error("Expected XSS finding for RawHtml with tainted content")
	}
}

// TestRust_WarpReplyHtmlXSS verifies that warp::reply::html with tainted content is detected.
func TestRust_WarpReplyHtmlXSS(t *testing.T) {
	code := `
use warp::reply;
use std::env;

fn handler() -> impl warp::Reply {
    let name = env::var("USER_INPUT").unwrap();
    reply::html(format!("<h1>Hello {}</h1>", name))
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Sink.ID == "rust.warp.reply.html" {
			found = true
		}
	}
	if !found {
		t.Error("Expected XSS finding for warp::reply::html with tainted content")
	}
}

// TestRust_SafeUreqHardcodedURL verifies no SSRF finding for hardcoded URL.
func TestRust_SafeUreqHardcodedURL(t *testing.T) {
	code := `
fn fetch() {
    let resp = ureq::get("https://api.example.com/data").call().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Sink.ID == "rust.ureq.get" {
			t.Errorf("Expected no SSRF finding for hardcoded URL, got src=%s", f.Source.ID)
		}
	}
}
