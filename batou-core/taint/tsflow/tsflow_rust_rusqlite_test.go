package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Rust — rusqlite (the canonical Rust SQLite driver) Connection methods that
// accept a raw SQL string at argument 0. Prior to these entries only
// Connection::execute was modeled; prepare / prepare_cached / query_row /
// query_row_and_then / query_one / execute_batch were all unmodeled despite
// taking tainted SQL as their first argument (CWE-89).
//
// All positive tests source taint from std::env::var (a known SrcEnvironment
// source) and build the SQL with format!() so the flow does not rely on
// framework parameter-extraction heuristics. The rusqlite Connection handle
// is conventionally named `conn`, which matches ObjectType
// "rusqlite::Connection" via the matcher's "connection" receiver heuristic.
// =========================================================================

func TestRust_Rusqlite_Prepare_SQLi(t *testing.T) {
	code := `
use std::env;
use rusqlite::Connection;

fn handler(conn: &Connection) {
    let table = env::var("TABLE").unwrap();
    let sql = format!("SELECT * FROM {}", table);
    let mut stmt = conn.prepare(&sql).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for rusqlite conn.prepare with format!() SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Rusqlite_PrepareCached_SQLi(t *testing.T) {
	code := `
use std::env;
use rusqlite::Connection;

fn handler(conn: &Connection) {
    let name = env::var("NAME").unwrap();
    let sql = format!("SELECT id FROM users WHERE name = '{}'", name);
    let mut stmt = conn.prepare_cached(&sql).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for rusqlite conn.prepare_cached with format!() SQL")
	}
}

func TestRust_Rusqlite_QueryRow_SQLi(t *testing.T) {
	code := `
use std::env;
use rusqlite::Connection;

fn handler(conn: &Connection) {
    let id = env::var("USER_ID").unwrap();
    let sql = format!("SELECT name FROM users WHERE id = {}", id);
    let name: String = conn.query_row(&sql, [], |row| row.get(0)).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for rusqlite conn.query_row with format!() SQL")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_Rusqlite_QueryRowAndThen_SQLi(t *testing.T) {
	code := `
use std::env;
use rusqlite::Connection;

fn handler(conn: &Connection) {
    let col = env::var("COL").unwrap();
    let sql = format!("SELECT {} FROM users WHERE id = 1", col);
    let val: String = conn.query_row_and_then(&sql, [], |row| row.get(0)).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for rusqlite conn.query_row_and_then with format!() SQL")
	}
}

func TestRust_Rusqlite_QueryOne_SQLi(t *testing.T) {
	code := `
use std::env;
use rusqlite::Connection;

fn handler(conn: &Connection) {
    let name = env::var("NAME").unwrap();
    let sql = format!("SELECT id FROM users WHERE name = '{}'", name);
    let id: i64 = conn.query_one(&sql, [], |row| row.get(0)).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for rusqlite conn.query_one with format!() SQL")
	}
}

func TestRust_Rusqlite_ExecuteBatch_StackedSQLi(t *testing.T) {
	code := `
use std::env;
use rusqlite::Connection;

fn handler(conn: &Connection) {
    let ddl = env::var("DDL").unwrap();
    let sql = format!("CREATE TABLE t (a int); {}", ddl);
    conn.execute_batch(&sql).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected stacked-SQLi flow for rusqlite conn.execute_batch with format!() SQL")
	}
}

// --- Negative tests: hardcoded SQL with bound params must not trigger ----

func TestRust_Rusqlite_QueryRow_HardcodedSQL_NoFlow(t *testing.T) {
	code := `
use std::env;
use rusqlite::Connection;

fn handler(conn: &Connection) {
    let _ = env::var("UNUSED").unwrap();
    let name: String = conn.query_row("SELECT name FROM users WHERE id = ?1", [&42i32], |row| row.get(0)).unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQLi flow on rusqlite query_row with hardcoded SQL + bound params")
	}
}

func TestRust_Rusqlite_Prepare_HardcodedSQL_NoFlow(t *testing.T) {
	code := `
use std::env;
use rusqlite::Connection;

fn handler(conn: &Connection) {
    let _ = env::var("UNUSED").unwrap();
    let mut stmt = conn.prepare("SELECT name FROM users WHERE id = ?1").unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQLi flow on rusqlite prepare with hardcoded SQL")
	}
}
