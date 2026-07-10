package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Rust Tiberius (Microsoft SQL Server) + rust-oracle SQL Injection (CWE-89)
// =========================================================================
//
// tiberius (https://github.com/prisma/tiberius) is the canonical async TDS 7.x
// driver for SQL Server. The `oracle` crate (kubo/rust-oracle) is the canonical
// Oracle Database driver. Both expose query/execute APIs that accept SQL as
// arg 0 with bind values supplied separately. Concatenating user input into
// the SQL string (rather than using @P1 / :name placeholders) allows SQL
// injection.

func hasRustSQLSinkID(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID && f.Sink.Category == taint.SnkSQLQuery {
			return true
		}
	}
	return false
}

// ---------- Tiberius (Microsoft SQL Server) ----------

func TestRust_Tiberius_SimpleQuery_EnvVar_SQLInjection(t *testing.T) {
	code := `
use std::env;
use tiberius::Client;

async fn handler(client: &mut Client) {
    let name = env::var("USER").unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    client.simple_query(sql).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustSQLSinkID(flows, "rust.tiberius.client.simple_query") {
		t.Error("expected SQL injection flow for env::var -> format! -> tiberius simple_query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestRust_Tiberius_BulkInsert_EnvVar_SQLInjection(t *testing.T) {
	code := `
use std::env;
use tiberius::Client;

async fn handler(client: &mut Client) {
    let table = env::var("TABLE_NAME").unwrap();
    client.bulk_insert(&table).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustSQLSinkID(flows, "rust.tiberius.client.bulk_insert") {
		t.Error("expected SQL injection flow for env::var -> tiberius bulk_insert")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---------- rust-oracle ----------

func TestRust_Oracle_ExecuteNamed_EnvVar_SQLInjection(t *testing.T) {
	code := `
use std::env;
use oracle::Connection;

fn handler(conn: &Connection) {
    let dept = env::var("DEPT").unwrap();
    let sql = format!("UPDATE emp SET sal = sal * 1.1 WHERE deptno = {}", dept);
    conn.execute_named(&sql, &[]).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustSQLSinkID(flows, "rust.oracle.connection.execute_named") {
		t.Error("expected SQL injection flow for env::var -> format! -> oracle Connection::execute_named")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestRust_Oracle_QueryNamed_EnvVar_SQLInjection(t *testing.T) {
	code := `
use std::env;
use oracle::Connection;

fn handler(conn: &Connection) {
    let name = env::var("NAME").unwrap();
    let sql = format!("SELECT ename, sal FROM emp WHERE ename = '{}'", name);
    let rows = conn.query_named(&sql, &[]).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustSQLSinkID(flows, "rust.oracle.connection.query_named") {
		t.Error("expected SQL injection flow for env::var -> format! -> oracle Connection::query_named")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestRust_Oracle_QueryRowAsNamed_FileRead_SQLInjection(t *testing.T) {
	code := `
use std::fs;
use oracle::Connection;

fn handler(conn: &Connection) {
    let id = fs::read_to_string("/etc/userid").unwrap();
    let sql = format!("SELECT ename FROM emp WHERE empno = {}", id);
    let row: (String,) = conn.query_row_as_named(&sql, &[]).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustSQLSinkID(flows, "rust.oracle.connection.query_row_as_named") {
		t.Error("expected SQL injection flow for fs::read_to_string -> oracle Connection::query_row_as_named")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestRust_Oracle_QueryAs_EnvVar_SQLInjection(t *testing.T) {
	code := `
use std::env;
use oracle::Connection;

fn handler(conn: &Connection) {
    let order = env::var("ORDER_BY").unwrap();
    let sql = format!("SELECT ename, sal FROM emp ORDER BY {}", order);
    let rows = conn.query_as(&sql, &[]).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustSQLSinkID(flows, "rust.oracle.connection.query_as") {
		t.Error("expected SQL injection flow for env::var -> format! -> oracle Connection::query_as")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestRust_Oracle_Batch_EnvVar_SQLInjection(t *testing.T) {
	code := `
use std::env;
use oracle::Connection;

fn handler(conn: &Connection) {
    let table = env::var("TARGET_TABLE").unwrap();
    let sql = format!("INSERT INTO {} (id) VALUES (:1)", table);
    let mut batch = conn.batch(&sql, 100).build().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasRustSQLSinkID(flows, "rust.oracle.connection.batch") {
		t.Error("expected SQL injection flow for env::var -> format! -> oracle Connection::batch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Safe: oracle execute_named with `:name` bind variables and values supplied
// separately — the SQL string is a literal and carries no taint.
func TestRust_Oracle_ExecuteNamed_Parameterised_Safe(t *testing.T) {
	code := `
use std::env;
use oracle::Connection;

fn handler(conn: &Connection) {
    let dept = env::var("DEPT").unwrap();
    conn.execute_named(
        "UPDATE emp SET sal = sal * 1.1 WHERE deptno = :dept",
        &[("dept", &dept)],
    ).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.ID == "rust.oracle.connection.execute_named" {
			t.Errorf("expected no rust.oracle.connection.execute_named finding for parameterised SQL, got src=%s", f.Source.ID)
		}
	}
}
