package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// MongoDB find_one_and_* compound operations (find_one_and_update,
// find_one_and_replace, find_one_and_delete) return the matched document
// (by default the pre-modification version). That document may hold
// attacker-stored data, making it a second-order taint source. These methods
// are already NoSQL-injection sinks on the filter argument; the constant
// filters below keep the sink role silent so only the source role drives the
// downstream sqlx::query SQL-injection sink (same harness as
// tsflow_rust_db_read_v2_test.go).

func TestRust_SrcDB_MongoDB_FindOneAndUpdate_To_SQLInjection(t *testing.T) {
	code := `
use mongodb::Collection;
use bson::{doc, Document};
use sqlx::PgPool;

async fn handler(coll: &Collection<Document>, pool: &PgPool) {
    let prev = coll.find_one_and_update(doc! {"id": 1}, doc! {"$set": {"seen": true}}).await.unwrap();
    let name: String = prev.get("name");
    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mongodb find_one_and_update -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_MongoDB_FindOneAndReplace_To_SQLInjection(t *testing.T) {
	code := `
use mongodb::Collection;
use bson::{doc, Document};
use sqlx::PgPool;

async fn handler(coll: &Collection<Document>, pool: &PgPool) {
    let prev = coll.find_one_and_replace(doc! {"id": 1}, doc! {"x": 1}).await.unwrap();
    let bio: String = prev.get("bio");
    let sql = format!("INSERT INTO search_index (text) VALUES ('{}')", bio);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mongodb find_one_and_replace -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_MongoDB_FindOneAndDelete_To_SQLInjection(t *testing.T) {
	code := `
use mongodb::Collection;
use bson::{doc, Document};
use sqlx::PgPool;

async fn handler(coll: &Collection<Document>, pool: &PgPool) {
    let removed = coll.find_one_and_delete(doc! {"id": 1}).await.unwrap();
    let tag: String = removed.get("tag");
    let sql = format!("DELETE FROM tags WHERE tag = '{}'", tag);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: mongodb find_one_and_delete -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe case: the document read from find_one_and_delete flows into a
// parameterized .bind() query, which must not flag SQL injection.
func TestRust_SrcDB_MongoDB_Compound_Safe_Parameterized(t *testing.T) {
	code := `
use mongodb::Collection;
use bson::{doc, Document};
use sqlx::PgPool;

async fn handler(coll: &Collection<Document>, pool: &PgPool) {
    let removed = coll.find_one_and_delete(doc! {"id": 1}).await.unwrap();
    let tag: String = removed.get("tag");
    sqlx::query("DELETE FROM tags WHERE tag = $1")
        .bind(&tag)
        .execute(pool)
        .await
        .unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("parameterized .bind() query should not flag SQL injection from a mongodb compound source")
		}
	}
}
