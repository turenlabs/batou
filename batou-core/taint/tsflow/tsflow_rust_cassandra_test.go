package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust Cassandra / ScyllaDB CQL-injection sinks (CWE-943)
//
// Covers two drivers:
//   - scylla crate (https://docs.rs/scylla)
//   - cdrs-tokio crate (https://docs.rs/cdrs-tokio)
//
// Safe usage: `session.query_unpaged("SELECT ... WHERE id = ?", (id,))` —
// hardcoded CQL with `?` placeholders. Vulnerable usage: any string-formatted
// CQL passed as the first argument.
// =========================================================================

// ---------- scylla::Session::query_unpaged (CWE-943) ----------

func TestRust_Scylla_Session_QueryUnpaged_Injection(t *testing.T) {
	code := `
use scylla::Session;

async fn get_user(session: Session, input: String) {
    let cql = format!("SELECT * FROM users WHERE name = '{}'", input);
    session.query_unpaged(cql, &[]).await.unwrap();
}
`
	flows := Analyze(code, "/app/dao.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "rust.scylla.session.query_unpaged" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for Session::query_unpaged; got flows: %+v", flows)
	}
}

// ---------- scylla::Session::query_iter (CWE-943) ----------

func TestRust_Scylla_Session_QueryIter_Injection(t *testing.T) {
	code := `
use scylla::Session;

async fn list_orders(session: Session, input: String) {
    let cql = format!("SELECT * FROM {}", input);
    session.query_iter(cql, &[]).await.unwrap();
}
`
	flows := Analyze(code, "/app/orders.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "rust.scylla.session.query_iter" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for Session::query_iter; got flows: %+v", flows)
	}
}

// ---------- scylla::Session::query_single_page (CWE-943) ----------

func TestRust_Scylla_Session_QuerySinglePage_Injection(t *testing.T) {
	code := `
use scylla::Session;

async fn search(session: Session, input: String) {
    let cql = format!("SELECT id FROM posts WHERE body LIKE '%{}%'", input);
    session.query_single_page(cql, &[], None).await.unwrap();
}
`
	flows := Analyze(code, "/app/search.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "rust.scylla.session.query_single_page" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for Session::query_single_page; got flows: %+v", flows)
	}
}

// ---------- cdrs_tokio::Session::query (CWE-943) ----------

func TestRust_CdrsTokio_Session_Query_Injection(t *testing.T) {
	code := `
use cdrs_tokio::cluster::session::Session;

async fn count_rows(session: Session, input: String) {
    let cql = format!("SELECT count(*) FROM {}", input);
    session.query(cql).await.unwrap();
}
`
	flows := Analyze(code, "/app/metrics.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "rust.cdrs_tokio.session.query" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for cdrs-tokio Session::query; got flows: %+v", flows)
	}
}

// ---------- cdrs_tokio::Session::query_with_values (CWE-943) ----------

func TestRust_CdrsTokio_Session_QueryWithValues_Injection(t *testing.T) {
	code := `
use cdrs_tokio::cluster::session::Session;

async fn delete_log(session: Session, name: String) {
    let cql = format!("DELETE FROM logs WHERE name = '{}'", name);
    session.query_with_values(cql, ()).await.unwrap();
}
`
	flows := Analyze(code, "/app/logs.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "rust.cdrs_tokio.session.query_with_values" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for cdrs-tokio Session::query_with_values; got flows: %+v", flows)
	}
}

// ---------- cdrs_tokio::Session::query_with_params (CWE-943) ----------

func TestRust_CdrsTokio_Session_QueryWithParams_Injection(t *testing.T) {
	code := `
use cdrs_tokio::cluster::session::Session;

async fn lookup(session: Session, input: String) {
    let cql = format!("SELECT * FROM users WHERE id = {}", input);
    session.query_with_params(cql, params).await.unwrap();
}
`
	flows := Analyze(code, "/app/lookup.rs", rules.LangRust)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkNoSQL && f.Sink.ID == "rust.cdrs_tokio.session.query_with_params" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected CQL injection finding for cdrs-tokio Session::query_with_params; got flows: %+v", flows)
	}
}

// ---------- Safe: parameterized scylla query ----------
// First arg is a hardcoded literal with `?` placeholders — not tainted —
// so the catalog entry must NOT fire.
func TestRust_Scylla_ParameterizedQuery_Safe(t *testing.T) {
	code := `
use scylla::Session;

async fn get_user(session: Session, user_id: String) {
    session.query_unpaged("SELECT * FROM users WHERE id = ?", (user_id,)).await.unwrap();
}
`
	flows := Analyze(code, "/app/dao.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.scylla.session.query_unpaged" ||
			f.Sink.ID == "rust.scylla.session.query_iter" ||
			f.Sink.ID == "rust.scylla.session.query_single_page" {
			t.Errorf("Unexpected CQL injection finding on parameterized query: %+v", f)
		}
	}
}

// ---------- Safe: tokio_postgres client.query is NOT a Cassandra sink ----------
// Verifies the cdrs-tokio `(?:session|sess)\.query` regex doesn't FP on
// tokio-postgres's idiomatic `client.query(...)` usage.
func TestRust_CdrsTokio_TokioPostgresClient_NotCassandraSink(t *testing.T) {
	code := `
use tokio_postgres::Client;

async fn list(client: Client, name: String) {
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    client.query(&sql, &[]).await.unwrap();
}
`
	flows := Analyze(code, "/app/pg.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.cdrs_tokio.session.query" {
			t.Errorf("Cassandra cdrs-tokio sink should not fire on tokio-postgres client.query: %+v", f)
		}
	}
}
