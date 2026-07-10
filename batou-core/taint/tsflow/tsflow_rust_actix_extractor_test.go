package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Actix-web's dominant input sources are typed parameter EXTRACTORS: a handler
// `async fn h(info: web::Query<Params>)` then reads `info.field`. The extractor
// types web::Query<T> / web::Path<T> / web::Json<T> / web::Form<T> ARE the user
// input. seedParams seeds such typed parameters as user_input sources so the
// field read flows to a sink. web::Data<T> is application state (NOT input) and
// must never be seeded.

// CWE-78: web::Query extractor field reaches Command::new (via local binding).
func TestRust_ActixQueryExtractor_CommandInjection(t *testing.T) {
	code := `
use actix_web::web;
use std::process::Command;

async fn handler(info: web::Query<Params>) {
    let s = info.cmd;
    Command::new(&s).output().expect("failed");
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for web::Query extractor field -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// CWE-78: web::Query extractor field used inline at the sink.
func TestRust_ActixQueryExtractor_CommandInjection_Inline(t *testing.T) {
	code := `
use actix_web::web;
use std::process::Command;

async fn handler(info: web::Query<Params>) {
    Command::new(&info.cmd).output().expect("failed");
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for inline web::Query extractor field -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// CWE-22: web::Path extractor field reaches std::fs::read_to_string.
func TestRust_ActixPathExtractor_PathTraversal(t *testing.T) {
	code := `
use actix_web::web;

async fn handler(info: web::Path<String>) {
    let contents = std::fs::read_to_string(&info.f).unwrap();
    println!("{}", contents);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected path-traversal (file_read) flow for web::Path extractor field -> fs::read_to_string")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// CWE-89: web::Json extractor field reaches a formatted SQL query.
// The parameter name `item` is deliberately NOT an input-shaped name
// (isInputParamName is false for it), so this flow exists ONLY because the
// extractor TYPE web::Json<T> is seeded — making the test load-bearing for the
// lever rather than relying on the generic name-based seed.
func TestRust_ActixJsonExtractor_SqlInjection(t *testing.T) {
	code := `
use actix_web::web;

async fn handler(item: web::Json<Params>) {
    let q = format!("SELECT * FROM users WHERE name = '{}'", item.name);
    sqlx::query(&q).fetch_all(&pool);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for web::Json extractor field -> sqlx::query(format!)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Fully-qualified `actix_web::web::Query<T>` is also recognized.
func TestRust_ActixQueryExtractor_FullyQualified(t *testing.T) {
	code := `
use std::process::Command;

async fn handler(info: actix_web::web::Query<Params>) {
    Command::new(&info.cmd).output().expect("failed");
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for fully-qualified actix_web::web::Query extractor")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// PRECISION: web::Data<T> is shared application state, NOT user input. A field
// read of a web::Data parameter reaching a command sink must NOT produce a flow.
func TestRust_ActixDataExtractor_Precision_NoFlow(t *testing.T) {
	code := `
use actix_web::web;
use std::process::Command;

async fn handler(d: web::Data<AppState>) {
    Command::new(&d.cmd).output().expect("failed");
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("web::Data is application state, not user input: must not produce a command flow (src=%s)", f.Source.ID)
		}
	}
}
