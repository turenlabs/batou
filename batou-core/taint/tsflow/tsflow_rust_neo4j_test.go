package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Rust Neo4j Cypher Injection (CWE-943) — neo4rs driver tests
// =========================================================================
//
// neo4rs is the official Rust Neo4j driver (neo4j-labs/neo4rs). The top-level
// `neo4rs::query(&str)` is the only public API that takes a Cypher string
// directly — Graph::run/execute and Txn::run/execute all accept
// `impl Into<Query>` and can only build a Query from a `&str` via this function.
// Concatenating user input into that string allows Cypher injection.
// See https://neo4j.com/developer/kb/protecting-against-cypher-injection/

func hasRustCypherSinkID(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.Category == taint.SnkNoSQL {
			return true
		}
	}
	return false
}

// Cypher concatenated from an env-var source. Inline call — query() arg 0 is
// the format!() result, which carries taint from `name`.
func TestRust_Neo4rs_Query_EnvVar_FormatConcat_CypherInjection(t *testing.T) {
	code := `
use std::env;
use neo4rs::Graph;

async fn handler(graph: Graph) {
    let name = env::var("USER_NAME").unwrap();
    let cypher = format!("MATCH (u:User {{name: '{}'}}) RETURN u", name);
    let q = neo4rs::query(&cypher);
    graph.execute(q).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustCypherSinkID(flows, "rust.neo4rs.query") {
		t.Error("expected Cypher injection flow for env::var -> format! -> neo4rs::query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Inline `neo4rs::query(format!(...))` passed straight into Graph::run — the
// outer call doesn't matter; the inner query() call still sees a tainted arg.
func TestRust_Neo4rs_Query_Inline_GraphRun_CypherInjection(t *testing.T) {
	code := `
use std::env;
use neo4rs::Graph;

async fn handler(graph: Graph) {
    let label = env::var("LABEL").unwrap();
    graph.run(neo4rs::query(&format!("MATCH (n:{}) RETURN n", label))).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustCypherSinkID(flows, "rust.neo4rs.query") {
		t.Error("expected Cypher injection flow for env::var -> inline neo4rs::query() inside Graph::run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// File-read source flowing into the Cypher string — covers the second-order
// case where untrusted input arrives via filesystem rather than a request.
func TestRust_Neo4rs_Query_FileRead_CypherInjection(t *testing.T) {
	code := `
use std::fs;
use neo4rs::{Graph, Txn};

async fn handler(txn: Txn) {
    let id = fs::read_to_string("/etc/userid").unwrap();
    let cypher = format!("MATCH (u:User {{id: {}}}) DETACH DELETE u", id);
    txn.execute(neo4rs::query(&cypher)).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustCypherSinkID(flows, "rust.neo4rs.query") {
		t.Error("expected Cypher injection flow for fs::read_to_string -> neo4rs::query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Safe pattern: parameterised query — user input is bound via .param() rather
// than concatenated, so the Cypher string passed to neo4rs::query() is a
// hardcoded literal and carries no taint. No injection finding should fire.
func TestRust_Neo4rs_Query_Parameterised_Safe(t *testing.T) {
	code := `
use std::env;
use neo4rs::Graph;

async fn handler(graph: Graph) {
    let name = env::var("USER_NAME").unwrap();
    let q = neo4rs::query("MATCH (u:User {name: $name}) RETURN u").param("name", name);
    graph.execute(q).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.neo4rs.query" {
			t.Errorf("expected no rust.neo4rs.query finding for parameterised Cypher, got src=%s",
				f.Source.ID)
		}
	}
}
