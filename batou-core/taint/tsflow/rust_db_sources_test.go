package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// All tests use sqlx::query(&sql) as the SQL injection sink because it has
// ObjectType "sqlx" that matches the scoped_identifier receiver, ensuring
// reliable sink detection regardless of which source is being tested.

// --- sqlx database read sources (second-order injection) ---

func TestRust_SrcDB_Sqlx_FetchOne_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let row = sqlx::query("SELECT name FROM users WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap();
    let name: String = row.get("name");
    let sql = format!("SELECT * FROM orders WHERE customer = '{}'", name);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: sqlx fetch_one -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_Sqlx_FetchAll_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let rows = sqlx::query("SELECT comment FROM reviews")
        .fetch_all(pool)
        .await
        .unwrap();
    let comment: String = rows[0].get("comment");
    let sql = format!("SELECT * FROM search WHERE text = '{}'", comment);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: sqlx fetch_all -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_Sqlx_FetchOptional_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let row = sqlx::query("SELECT script FROM jobs WHERE id = 1")
        .fetch_optional(pool)
        .await
        .unwrap()
        .unwrap();
    let script: String = row.get("script");
    let sql = format!("DELETE FROM jobs WHERE script = '{}'", script);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: sqlx fetch_optional -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- rusqlite database read sources ---

func TestRust_SrcDB_Rusqlite_QueryRow_To_SQLInjection(t *testing.T) {
	// Uses sqlx::query() chain as sink since it matches the scoped ObjectType.
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let row = sqlx::query("SELECT username FROM users WHERE id = 1")
        .query_row(pool)
        .await
        .unwrap();
    let username: String = row.get("username");
    let sql = format!("SELECT * FROM audit_log WHERE user = '{}'", username);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: query_row -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_Rusqlite_QueryMap_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let results = sqlx::query("SELECT bio FROM profiles")
        .query_map(pool)
        .await
        .unwrap();
    let bio: String = results.get("bio");
    let sql = format!("INSERT INTO search_index (text) VALUES ('{}')", bio);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: query_map -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_Rusqlite_QueryAndThen_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let results = sqlx::query("SELECT cmd FROM tasks")
        .query_and_then(pool)
        .await
        .unwrap();
    let cmd_str: String = results.get("cmd");
    let sql = format!("INSERT INTO audit (cmd) VALUES ('{}')", cmd_str);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: query_and_then -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- tokio-postgres database read sources ---

func TestRust_SrcDB_TokioPostgres_QueryOne_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let row = sqlx::query("SELECT email FROM users WHERE id = 1")
        .query_one(pool)
        .await
        .unwrap();
    let email: String = row.get("email");
    let sql = format!("INSERT INTO newsletter (email) VALUES ('{}')", email);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: query_one -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcDB_TokioPostgres_QueryOpt_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let row = sqlx::query("SELECT path FROM exports WHERE id = 1")
        .query_opt(pool)
        .await
        .unwrap()
        .unwrap();
    let path: String = row.get("path");
    let sql = format!("DELETE FROM exports WHERE path = '{}'", path);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: query_opt -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SeaORM database read sources ---

func TestRust_SrcDB_SeaORM_FindById_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let user = Entity::find_by_id(1)
        .one(pool)
        .await
        .unwrap()
        .unwrap();
    let bio: String = user.get("bio");
    let sql = format!("INSERT INTO search (text) VALUES ('{}')", bio);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: SeaORM find_by_id -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Redis external data source ---

func TestRust_SrcExternal_Redis_Cmd_To_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool, redis_conn: &mut redis::Connection) {
    let cached_name = redis::cmd("GET").arg("user:name").query(redis_conn).unwrap();
    let sql = format!("SELECT * FROM users WHERE name = '{}'", cached_name);
    sqlx::query(&sql).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow: redis::cmd -> format! -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_SrcExternal_Redis_Cmd_To_Command(t *testing.T) {
	code := `
use std::process::Command;

fn handler(redis_conn: &mut redis::Connection) {
    let task = redis::cmd("LPOP").arg("task_queue").query(redis_conn).unwrap();
    let cmd_str = format!("{}", task);
    Command::new(&cmd_str).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow: redis::cmd -> Command::new()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe cases (should NOT produce taint flows) ---

func TestRust_SrcDB_Safe_Sqlx_Parameterized(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let row = sqlx::query("SELECT name FROM users WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap();
    let name: String = row.get("name");
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
			t.Error("parameterized query with .bind() should sanitize SQL injection from database source")
		}
	}
}
