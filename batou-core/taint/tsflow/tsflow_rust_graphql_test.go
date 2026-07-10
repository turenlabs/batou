// batou:ignore-start all -- intentional vulnerable patterns embedded in inline Rust strings for taint-flow unit tests
package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust GraphQL resolver sources — async-graphql Context + juniper Executor
// =========================================================================

func TestRust_GraphQLSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangRust)
	if cat == nil {
		t.Fatal("Rust catalog not loaded")
	}
	ids := map[string]bool{}
	for _, s := range cat.Sources() {
		ids[s.ID] = true
	}
	want := []string{
		"rust.async_graphql.ctx.param_value",
		"rust.async_graphql.ctx.oneof_param_value",
		"rust.graphql.look_ahead",
		"rust.juniper.executor.variables",
	}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("missing expected source: %s", id)
		}
	}
}

// async-graphql resolver pulls a named field argument via ctx.param_value
// and concatenates it into a raw SQL query — classic SQLi via GraphQL.
// Uses non-turbofish call form so tsflow's Rust walker extracts the method.
func TestRust_AsyncGraphQL_ParamValue_SQLi(t *testing.T) {
	code := `
use async_graphql::{Context, Object};
use sqlx::Row;

struct Query;

impl Query {
    async fn user(&self, ctx: &Context) -> String {
        let id = ctx.param_value("id", None);
        let q = format!("SELECT * FROM users WHERE id = '{}'", id);
        sqlx::query(&q).fetch_one(pool).await.unwrap();
        id
    }
}
`
	flows := Analyze(code, "/app/schema.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from ctx.param_value -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// async-graphql resolver uses OneofObject param and writes it to a URL fetch — SSRF.
func TestRust_AsyncGraphQL_OneofParam_SSRF(t *testing.T) {
	code := `
use async_graphql::{Context, Object};

struct Query;

impl Query {
    async fn fetch(&self, ctx: &Context) -> String {
        let target = ctx.oneof_param_value();
        let body = reqwest::get(&target).await.unwrap().text().await.unwrap();
        body
    }
}
`
	flows := Analyze(code, "/app/schema.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow from ctx.oneof_param_value -> reqwest::get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// async-graphql resolver reads ctx.look_ahead() and passes selection info
// into a file-read path — path traversal via GraphQL query shape.
func TestRust_AsyncGraphQL_LookAhead_PathTraversal(t *testing.T) {
	code := `
use async_graphql::{Context, Object};
use std::fs;

struct Query;

impl Query {
    async fn page(&self, ctx: &Context) -> String {
        let sel = ctx.look_ahead();
        let path = format!("{:?}", sel);
        let content = fs::read_to_string(&path).unwrap();
        content
    }
}
`
	flows := Analyze(code, "/app/schema.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected path traversal flow from ctx.look_ahead() -> fs::read_to_string")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// juniper resolver reads the raw operation variables via executor.variables()
// and uses them in a SQL query — SQLi through GraphQL.
func TestRust_Juniper_ExecutorVariables_SQLi(t *testing.T) {
	code := `
use juniper::Executor;

fn resolve_run(executor: &Executor) -> String {
    let vars = executor.variables();
    let q = format!("SELECT * FROM logs WHERE tag = '{:?}'", vars);
    sqlx::query(&q).fetch_one(pool).await.unwrap();
    q
}
`
	flows := Analyze(code, "/app/resolver.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from executor.variables() -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// juniper resolver reads executor.look_ahead() and passes selection info
// into a file-read path — path traversal via GraphQL query shape.
func TestRust_Juniper_ExecutorLookAhead_PathTraversal(t *testing.T) {
	code := `
use juniper::Executor;
use std::fs;

fn resolve_page(executor: &Executor) -> String {
    let sel = executor.look_ahead();
    let path = format!("{:?}", sel);
    let content = fs::read_to_string(&path).unwrap();
    content
}
`
	flows := Analyze(code, "/app/resolver.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected path traversal flow from executor.look_ahead() -> fs::read_to_string")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe baseline: hardcoded constant into sqlx — must NOT flag.
func TestRust_AsyncGraphQL_Safe_Hardcoded(t *testing.T) {
	code := `
use async_graphql::{Context, Object};
use sqlx::Row;

struct Query;

impl Query {
    async fn admin(&self, _ctx: &Context) -> String {
        let q = "SELECT * FROM users WHERE id = 'admin'";
        sqlx::query(q).fetch_one(pool).await.unwrap();
        "ok".to_string()
    }
}
`
	flows := Analyze(code, "/app/schema.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("hardcoded SQL should not produce SQL flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// batou:ignore-end
