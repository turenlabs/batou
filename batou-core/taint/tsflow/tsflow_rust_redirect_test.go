package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func hasRustRedirectSinkID(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.Category == taint.SnkRedirect {
			return true
		}
	}
	return false
}

// Rocket Redirect::found (302)
func TestRust_RocketRedirectFound_Tainted(t *testing.T) {
	code := `
use std::env;
use rocket::response::Redirect;

fn handler() -> Redirect {
    let url = env::var("REDIRECT_URL").unwrap();
    Redirect::found(url)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustRedirectSinkID(flows, "rust.redirect.found") {
		t.Error("expected open redirect flow for env::var -> Redirect::found")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Rocket Redirect::moved (301)
func TestRust_RocketRedirectMoved_Tainted(t *testing.T) {
	code := `
use std::env;
use rocket::response::Redirect;

fn handler() -> Redirect {
    let url = env::var("REDIRECT_URL").unwrap();
    Redirect::moved(url)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustRedirectSinkID(flows, "rust.redirect.moved") {
		t.Error("expected open redirect flow for env::var -> Redirect::moved")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Warp warp::redirect (301)
func TestRust_WarpRedirect_Tainted(t *testing.T) {
	code := `
use std::env;
use warp::http::Uri;

fn handler() -> impl warp::Reply {
    let dest = env::var("DEST").unwrap();
    let uri: Uri = dest.parse().unwrap();
    warp::redirect(uri)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustRedirectSinkID(flows, "rust.warp.redirect") {
		t.Error("expected open redirect flow for env::var -> warp::redirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Warp warp::redirect::permanent (308)
func TestRust_WarpRedirectPermanent_Tainted(t *testing.T) {
	code := `
use std::env;
use warp::http::Uri;

fn handler() -> impl warp::Reply {
    let dest = env::var("DEST").unwrap();
    let uri: Uri = dest.parse().unwrap();
    warp::redirect::permanent(uri)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustRedirectSinkID(flows, "rust.warp.redirect.permanent") {
		t.Error("expected open redirect flow for env::var -> warp::redirect::permanent")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Warp warp::redirect::temporary (307)
func TestRust_WarpRedirectTemporary_Tainted(t *testing.T) {
	code := `
use std::env;
use warp::http::Uri;

fn handler() -> impl warp::Reply {
    let dest = env::var("DEST").unwrap();
    let uri: Uri = dest.parse().unwrap();
    warp::redirect::temporary(uri)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustRedirectSinkID(flows, "rust.warp.redirect.temporary") {
		t.Error("expected open redirect flow for env::var -> warp::redirect::temporary")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Warp warp::redirect::see_other (303)
func TestRust_WarpRedirectSeeOther_Tainted(t *testing.T) {
	code := `
use std::env;
use warp::http::Uri;

fn handler() -> impl warp::Reply {
    let dest = env::var("DEST").unwrap();
    let uri: Uri = dest.parse().unwrap();
    warp::redirect::see_other(uri)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustRedirectSinkID(flows, "rust.warp.redirect.see_other") {
		t.Error("expected open redirect flow for env::var -> warp::redirect::see_other")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Warp warp::redirect::found (302)
func TestRust_WarpRedirectFound_Tainted(t *testing.T) {
	code := `
use std::env;
use warp::http::Uri;

fn handler() -> impl warp::Reply {
    let dest = env::var("DEST").unwrap();
    let uri: Uri = dest.parse().unwrap();
    warp::redirect::found(uri)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustRedirectSinkID(flows, "rust.warp.redirect.found") {
		t.Error("expected open redirect flow for env::var -> warp::redirect::found")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Safe: hardcoded URL in Rocket Redirect::found should NOT produce a redirect flow.
func TestRust_RocketRedirectFound_Safe(t *testing.T) {
	code := `
use rocket::response::Redirect;

fn handler() -> Redirect {
    Redirect::found("/home")
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Errorf("hardcoded URL in Redirect::found should not produce redirect flow, got sink=%s", f.Sink.ID)
		}
	}
}

// Safe: hardcoded URI in Warp redirect should NOT produce a redirect flow.
func TestRust_WarpRedirect_Safe(t *testing.T) {
	code := `
use warp::http::Uri;

fn handler() -> impl warp::Reply {
    let uri: Uri = "/home".parse().unwrap();
    warp::redirect::permanent(uri)
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Errorf("hardcoded URI in warp::redirect::permanent should not produce redirect flow, got sink=%s", f.Sink.ID)
		}
	}
}
