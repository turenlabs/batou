package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust — tokio-postgres extended Client/Transaction methods + sqlx top-level
// query family. Exercises the new SQL-injection sinks added alongside the
// existing rust.tokio.postgres.query and rust.sql.sqlx_query entries.
// All tests source taint from std::env::var (known SrcEnvironment source) to
// avoid relying on framework-extractor parameter heuristics.
// =========================================================================

// --- tokio-postgres Client extended methods ----------------------------

func TestRust_TokioPostgres_ClientQueryOne_SQLi(t *testing.T) {
	code := `
use std::env;
use tokio_postgres::Client;

async fn handler(client: &Client) {
    let name = env::var("USER_NAME").unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    let row = client.query_one(&sql, &[]).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for tokio-postgres client.query_one with concatenated SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TokioPostgres_ClientQueryOpt_SQLi(t *testing.T) {
	code := `
use std::env;
use tokio_postgres::Client;

async fn handler(client: &Client) {
    let id = env::var("USER_ID").unwrap();
    let sql = format!("SELECT * FROM users WHERE id = {}", id);
    let row = client.query_opt(&sql, &[]).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for tokio-postgres client.query_opt with concatenated SQL")
	}
}

func TestRust_TokioPostgres_ClientQueryRaw_SQLi(t *testing.T) {
	code := `
use std::env;
use tokio_postgres::Client;

async fn handler(client: &Client) {
    let table = env::var("TABLE").unwrap();
    let sql = format!("SELECT * FROM {}", table);
    let stream = client.query_raw(&sql, std::iter::empty::<i32>()).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for tokio-postgres client.query_raw with format!() SQL")
	}
}

func TestRust_TokioPostgres_ClientExecuteRaw_SQLi(t *testing.T) {
	code := `
use std::env;
use tokio_postgres::Client;

async fn handler(client: &Client) {
    let where_clause = env::var("WHERE").unwrap();
    let sql = format!("DELETE FROM users WHERE {}", where_clause);
    let n = client.execute_raw(&sql, std::iter::empty::<i32>()).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for tokio-postgres client.execute_raw with format!() SQL")
	}
}

// --- tokio-postgres Transaction methods --------------------------------

func TestRust_TokioPostgres_TransactionQuery_SQLi(t *testing.T) {
	code := `
use std::env;
use tokio_postgres::Transaction;

async fn handler(transaction: &Transaction<'_>) {
    let name = env::var("NAME").unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    let rows = transaction.query(&sql, &[]).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for tokio-postgres tx.query with concatenated SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TokioPostgres_TransactionSimpleQuery_StackedSQLi(t *testing.T) {
	code := `
use std::env;
use tokio_postgres::Transaction;

async fn handler(transaction: &Transaction<'_>) {
    let payload = env::var("PAYLOAD").unwrap();
    let sql = format!("SELECT 1; {}", payload);
    let _ = transaction.simple_query(&sql).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected stacked-SQLi flow for tokio-postgres txn.simple_query (multi-statement)")
	}
}

func TestRust_TokioPostgres_TransactionBatchExecute_StackedSQLi(t *testing.T) {
	code := `
use std::env;
use tokio_postgres::Transaction;

async fn handler(transaction: &Transaction<'_>) {
    let ddl = env::var("DDL").unwrap();
    let sql = format!("CREATE TABLE t (a int); {}", ddl);
    transaction.batch_execute(&sql).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected stacked-SQLi flow for tokio-postgres transaction.batch_execute")
	}
}

// --- sqlx top-level query functions ------------------------------------

func TestRust_Sqlx_QueryAs_SQLi(t *testing.T) {
	code := `
use std::env;
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let name = env::var("NAME").unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    let users: Vec<User> = sqlx::query_as(&sql).fetch_all(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for sqlx::query_as with format!() SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Sqlx_QueryWith_SQLi(t *testing.T) {
	code := `
use std::env;
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let table = env::var("TABLE").unwrap();
    let sql = format!("SELECT * FROM {} WHERE id = $1", table);
    let q = sqlx::query_with(&sql, args).fetch_all(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for sqlx::query_with with format!() SQL (table-name injection)")
	}
}

func TestRust_Sqlx_RawSql_SQLi(t *testing.T) {
	code := `
use std::env;
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let ddl = env::var("DDL").unwrap();
    let sql = format!("CREATE TABLE {} (id int)", ddl);
    sqlx::raw_sql(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for sqlx::raw_sql with format!() SQL")
	}
}

// --- Negative tests: hardcoded SQL must not trigger --------------------

func TestRust_TokioPostgres_ClientQueryOne_HardcodedSQL_NoFlow(t *testing.T) {
	code := `
use std::env;
use tokio_postgres::Client;

async fn handler(client: &Client) {
    let _ = env::var("UNUSED").unwrap();
    let row = client.query_one("SELECT name FROM users WHERE id = $1", &[&42i32]).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQLi flow on hardcoded SQL with bound parameters")
	}
}

func TestRust_Sqlx_QueryAs_HardcodedSQL_NoFlow(t *testing.T) {
	code := `
use std::env;
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let _ = env::var("UNUSED").unwrap();
    let users: Vec<User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(42)
        .fetch_all(pool)
        .await
        .unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQLi flow on sqlx::query_as with hardcoded SQL + .bind()")
	}
}
