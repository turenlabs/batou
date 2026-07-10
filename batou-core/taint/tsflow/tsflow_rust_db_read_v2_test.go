package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Second-order injection sources added in cycle #915:
//   - mongodb: Collection/Database::aggregate, Collection::distinct
//   - mysql / mysql_async (Queryable trait): exec_iter, exec_map, query_fold, exec_fold
//
// All use sqlx::query(&sql).execute(pool) as the SQL-injection sink because
// sqlx::query has ObjectType "sqlx" which matches the scoped_identifier
// receiver, giving reliable sink detection regardless of which source feeds it.

// --- MongoDB aggregation / distinct read sources ---

func TestRust_SrcDB_MongoDB_Aggregate_To_SQLInjection(t *testing.T) {
	code := `
use mongodb::Collection;
use bson::Document;
use sqlx::PgPool;

async fn handler(coll: &Collection<Document>, pool: &PgPool) {
    let results = coll.aggregate(vec![]).await.unwrap();
    let name: String = results.get("name");
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mongodb aggregate -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_MongoDB_Distinct_To_SQLInjection(t *testing.T) {
	code := `
use mongodb::Collection;
use bson::{doc, Document};
use sqlx::PgPool;

async fn handler(coll: &Collection<Document>, pool: &PgPool) {
    let values = coll.distinct("category", doc! {}).await.unwrap();
    let category: String = values.get("0");
    let sql = format!("SELECT * FROM products WHERE category = '{}'", category);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mongodb distinct -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- mysql / mysql_async prepared-statement read sources ---

func TestRust_SrcDB_MySQL_ExecIter_To_SQLInjection(t *testing.T) {
	code := `
use mysql_async::Conn;
use sqlx::PgPool;

async fn handler(conn: &mut Conn, pool: &PgPool) {
    let rows = conn.exec_iter("SELECT bio FROM profiles WHERE active = ?", (true,)).await.unwrap();
    let bio: String = rows.get("bio");
    let sql = format!("INSERT INTO search_index (text) VALUES ('{}')", bio);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mysql exec_iter -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_MySQL_ExecMap_To_SQLInjection(t *testing.T) {
	code := `
use mysql::Conn;
use sqlx::PgPool;

async fn handler(conn: &mut Conn, pool: &PgPool) {
    let names = conn.exec_map("SELECT name FROM users WHERE id = ?", (1,), |row| row.get("name")).await.unwrap();
    let name: String = names.get("name");
    let sql = format!("SELECT * FROM orders WHERE customer = '{}'", name);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mysql exec_map -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_MySQL_QueryFold_To_SQLInjection(t *testing.T) {
	code := `
use mysql_async::Conn;
use sqlx::PgPool;

async fn handler(conn: &mut Conn, pool: &PgPool) {
    let acc = conn.query_fold("SELECT note FROM audit", String::new(), |a, row| a + &row.get::<String, _>("note").unwrap()).await.unwrap();
    let note: String = acc;
    let sql = format!("INSERT INTO audit_archive (note) VALUES ('{}')", note);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mysql query_fold -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_MySQL_ExecFold_To_SQLInjection(t *testing.T) {
	code := `
use mysql_async::Conn;
use sqlx::PgPool;

async fn handler(conn: &mut Conn, pool: &PgPool) {
    let acc = conn.exec_fold("SELECT tag FROM tags WHERE owner = ?", (5,), Vec::new(), |mut v, row| { v.push(row.get::<String, _>("tag").unwrap()); v }).await.unwrap();
    let tag: String = acc.get("tag");
    let sql = format!("DELETE FROM tags WHERE tag = '{}'", tag);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mysql exec_fold -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe case: parameterized downstream query must not flag ---

func TestRust_SrcDB_V2_Safe_Sqlx_Parameterized(t *testing.T) {
	code := `
use mongodb::Collection;
use bson::Document;
use sqlx::PgPool;

async fn handler(coll: &Collection<Document>, pool: &PgPool) {
    let results = coll.aggregate(vec![]).await.unwrap();
    let name: String = results.get("name");
    sqlx::query("SELECT * FROM orders WHERE customer = $1")
        .bind(&name)
        .fetch_all(pool)
        .await
        .unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("parameterized .bind() query should not flag SQL injection from a database source")
		}
	}
}
