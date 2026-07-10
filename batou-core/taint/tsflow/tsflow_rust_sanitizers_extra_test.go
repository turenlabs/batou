package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for the Rust sanitizer entries added in cycle #743:
//
//   rust.v_htmlescape.escape           (Actix-web HTML escape, SIMD)
//   rust.askama_escape.escape          (Askama template HTML escape)
//   rust.urlencoding.encode            (urlencoding crate, distinct from percent-encoding)
//   rust.urlencoding.encode_binary     (urlencoding bytes variant)
//   rust.uuid.parse_str                (Uuid::parse_str input validation)
//   rust.path_clean.clean              (path-clean crate Plan 9-style normalization)
//   rust.tokio_fs.canonicalize         (tokio::fs::canonicalize async)
//
// Each sanitizer has a paired "Vulnerable" test (asserting the source -> sink
// flow IS detected without the sanitizer) and a "Safe" test (asserting the
// flow is neutralized when the sanitizer is applied inline at the sink call
// site — same convention as tsflow_rust_modern_sanitizers_test.go).

// --- v_htmlescape (CWE-79 XSS) ---

func TestRust_VHtmlescape_Vulnerable_WarpReplyHtml(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let user = env::var("USERNAME").unwrap();
    let body = format!("<div>Welcome {}</div>", user);
    let _ = warp::reply::html(body);
}
`
	flows := Analyze(code, "/app/web.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML-output flow for env::var -> warp::reply::html")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_VHtmlescape_Safe_Escape(t *testing.T) {
	code := `
use std::env;
use v_htmlescape::escape;

fn handler() {
    let user = env::var("USERNAME").unwrap();
    let _ = warp::reply::html(v_htmlescape::escape(&user));
}
`
	flows := Analyze(code, "/app/web.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("v_htmlescape::escape should sanitize before warp::reply::html: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- askama_escape (CWE-79 XSS) ---

func TestRust_AskamaEscape_Vulnerable_AxumHtml(t *testing.T) {
	code := `
use std::env;

fn handler() {
    let user = env::var("USERNAME").unwrap();
    let body = format!("<p>Hello {}</p>", user);
    let _ = axum::response::Html(body);
}
`
	flows := Analyze(code, "/app/web.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML-output flow for env::var -> axum::response::Html")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_AskamaEscape_Safe_Escape(t *testing.T) {
	// Note: in real code .to_string() is chained on the MarkupDisplay return,
	// but the inline-sanitizer detector requires the sanitizer call to be the
	// direct argument of the sink (matches percent_encoding test convention).
	code := `
use std::env;
use askama_escape::{escape, Html};

fn handler() {
    let user = env::var("USERNAME").unwrap();
    let _ = axum::response::Html(askama_escape::escape(&user, Html));
}
`
	flows := Analyze(code, "/app/web.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("askama_escape::escape should sanitize before axum::response::Html: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- urlencoding crate (CWE-918 SSRF / CWE-601 redirect) ---

func TestRust_Urlencoding_Vulnerable_ReqwestQuery(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let q = env::var("QUERY").unwrap();
    let url = format!("https://api.example.com/search?q={}", q);
    let _ = reqwest::get(&url).await;
}
`
	flows := Analyze(code, "/app/search.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected URL-fetch flow for env::var -> reqwest::get with format!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Urlencoding_Safe_Encode(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let q = env::var("QUERY").unwrap();
    let _ = reqwest::get(urlencoding::encode(&q)).await;
}
`
	flows := Analyze(code, "/app/search.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("urlencoding::encode should sanitize query before reqwest::get: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Urlencoding_Safe_EncodeBinary(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let q = env::var("QUERY").unwrap();
    let _ = reqwest::get(urlencoding::encode_binary(q.as_bytes())).await;
}
`
	flows := Analyze(code, "/app/search.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("urlencoding::encode_binary should sanitize query before reqwest::get: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Uuid::parse_str (CWE-89 SQLi via UUID column) ---

func TestRust_UuidParseStr_Vulnerable_SqlxQueryDirect(t *testing.T) {
	code := `
use std::env;

async fn handler(pool: sqlx::PgPool) {
    let id = env::var("USER_ID").unwrap();
    let _ = sqlx::query(&id).fetch_one(&pool).await;
}
`
	flows := Analyze(code, "/app/users.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for env::var -> sqlx::query with format!")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_UuidParseStr_Safe_Validation(t *testing.T) {
	// Direct inline sanitizer at the sink call site (format! macro nesting
	// would defeat the inline-sanitizer detector — same convention as the
	// existing percent_encoding sanitizer test).
	code := `
use std::env;
use uuid::Uuid;

async fn handler(pool: sqlx::PgPool) {
    let id = env::var("USER_ID").unwrap();
    let _ = sqlx::query(Uuid::parse_str(&id)).fetch_one(&pool).await;
}
`
	flows := Analyze(code, "/app/users.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("Uuid::parse_str should validate id before SQL: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- path_clean::clean (CWE-22 path traversal) ---

func TestRust_PathClean_Vulnerable_FsRead(t *testing.T) {
	code := `
use std::env;
use std::fs;

fn handler() {
    let path = env::var("FILE_PATH").unwrap();
    let _ = fs::read_to_string(&path);
}
`
	flows := Analyze(code, "/app/files.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow for env::var -> fs::read_to_string")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_PathClean_Safe_Clean(t *testing.T) {
	code := `
use std::env;
use std::fs;

fn handler() {
    let path = env::var("FILE_PATH").unwrap();
    let _ = fs::read_to_string(path_clean::clean(&path));
}
`
	flows := Analyze(code, "/app/files.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Errorf("path_clean::clean should sanitize path before fs::read_to_string: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- tokio::fs::canonicalize (CWE-22 path traversal, async) ---

func TestRust_TokioFsCanonicalize_Vulnerable_TokioRead(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let path = env::var("FILE_PATH").unwrap();
    let _ = tokio::fs::read_to_string(&path).await;
}
`
	flows := Analyze(code, "/app/files.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow for env::var -> tokio::fs::read_to_string")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TokioFsCanonicalize_Safe_Canonicalize(t *testing.T) {
	// Direct inline sanitizer (.await.unwrap() chain would defeat the
	// inline-sanitizer detector).
	code := `
use std::env;

async fn handler() {
    let path = env::var("FILE_PATH").unwrap();
    let _ = tokio::fs::read_to_string(tokio::fs::canonicalize(&path)).await;
}
`
	flows := Analyze(code, "/app/files.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Errorf("tokio::fs::canonicalize should sanitize path before tokio::fs::read_to_string: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
