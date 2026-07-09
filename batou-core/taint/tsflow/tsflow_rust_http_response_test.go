package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust external source tests — HTTP client response bodies
//
// reqwest / ureq response bodies are SrcExternal: data fetched from a
// remote URL is attacker-controlled when the URL is user-supplied (SSRF
// chain) or the upstream is untrusted (link unfurl, OAuth callback, proxy).
// Without these sources, downstream usage in shell/SQL/template/file sinks
// produces zero flows.
// =========================================================================

// --- reqwest async client ---

func TestRust_Reqwest_Response_Text_CommandInjection(t *testing.T) {
	code := `
use reqwest::Client;
use std::process::Command;

async fn unfurl(client: Client, url: &str) {
    let response = client.get(url).send().await.unwrap();
    let body = response.text().await.unwrap();
    Command::new(&body).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for reqwest response.text() -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Reqwest_Response_TextWithCharset_SQLInjection(t *testing.T) {
	code := `
use reqwest::Client;
use sqlx::PgPool;

async fn fetch_and_log(client: Client, pool: &PgPool, url: &str) {
    let response = client.get(url).send().await.unwrap();
    let body = response.text_with_charset("utf-8").await.unwrap();
    sqlx::query(&format!("INSERT INTO upstream_log VALUES ('{}')", body)).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for reqwest response.text_with_charset() -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Reqwest_Response_Json_CommandInjection(t *testing.T) {
	code := `
use reqwest::Client;
use std::process::Command;

async fn run_remote_cmd(client: Client, url: &str) {
    let response = client.get(url).send().await.unwrap();
    let payload: String = response.json().await.unwrap();
    Command::new(&payload).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for reqwest response.json() -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Reqwest_Response_Bytes_FileWrite(t *testing.T) {
	code := `
use reqwest::Client;
use std::fs;

async fn cache_remote(client: Client, url: &str) {
    let response = client.get(url).send().await.unwrap();
    let data = response.bytes().await.unwrap();
    fs::write("/tmp/cache", &data).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	// Either SnkFileWrite (path-traversal-style) or any file-related sink should trigger.
	// We just want at least one flow originating from the new source.
	found := false
	for _, f := range flows {
		if f.Source.Category == taint.SrcExternal {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SrcExternal flow for reqwest response.bytes() -> fs::write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Reqwest_Response_BytesStream_CommandInjection(t *testing.T) {
	code := `
use reqwest::Client;
use std::process::Command;

async fn stream_handler(client: Client, url: &str) {
    let response = client.get(url).send().await.unwrap();
    let stream = response.bytes_stream();
    Command::new(&format!("{:?}", stream)).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for reqwest response.bytes_stream() -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Reqwest_Response_Chunk_SQLInjection(t *testing.T) {
	code := `
use reqwest::Client;
use sqlx::PgPool;

async fn stream_to_db(client: Client, pool: &PgPool, url: &str) {
    let mut response = client.get(url).send().await.unwrap();
    let chunk = response.chunk().await.unwrap().unwrap();
    sqlx::query(&format!("INSERT INTO chunks VALUES ('{:?}')", chunk)).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for reqwest response.chunk() -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- ureq sync client ---

func TestRust_Ureq_Response_IntoString_CommandInjection(t *testing.T) {
	code := `
use std::process::Command;

fn fetch_and_run(url: &str) {
    let response = ureq::get(url).call().unwrap();
    let body = response.into_string().unwrap();
    Command::new(&body).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ureq response.into_string() -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Ureq_Response_IntoReader_CommandInjection(t *testing.T) {
	code := `
use std::process::Command;

fn fetch_reader(url: &str) {
    let response = ureq::get(url).call().unwrap();
    let reader = response.into_reader();
    Command::new(&format!("{:?}", reader)).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ureq response.into_reader() -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative test: hardcoded string into Command::new should NOT trigger an
// SrcExternal flow. Guards against the new sources being too broad and seeding
// taint on receivers unrelated to HTTP responses.

func TestRust_Reqwest_Response_NegativeNoExternalForLocalString(t *testing.T) {
	code := `
use std::process::Command;

fn run_local() {
    let body = String::from("ls -la");
    let _bytes = body.bytes();
    Command::new("sh").arg("-c").arg(&body).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Source.Category == taint.SrcExternal {
			t.Errorf("unexpected SrcExternal flow for String::bytes() (not a Response method): %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
