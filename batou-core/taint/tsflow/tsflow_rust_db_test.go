package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Rust database source tests — second-order injection detection
// =========================================================================

func TestRust_DB_SqlxFetchOne_CommandInjection(t *testing.T) {
	code := `
use sqlx::PgPool;
use std::process::Command;

async fn handler(pool: &PgPool) {
    let name: String = sqlx::query_scalar("SELECT cmd FROM jobs LIMIT 1").fetch_one(pool).await.unwrap();
    Command::new(&name).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for sqlx fetch_one -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_SqlxFetchAll_CommandInjection(t *testing.T) {
	code := `
use sqlx::PgPool;
use std::process::Command;

async fn handler(pool: &PgPool) {
    let cmd = sqlx::query("SELECT cmd FROM jobs").fetch_all(pool).await.unwrap();
    Command::new(&cmd).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for sqlx fetch_all -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_SqlxFetchOptional_CommandInjection(t *testing.T) {
	code := `
use sqlx::PgPool;
use std::process::Command;

async fn handler(pool: &PgPool) {
    let name = sqlx::query_scalar("SELECT cmd FROM jobs").fetch_optional(pool).await.unwrap().unwrap();
    Command::new(&name).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for sqlx fetch_optional -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_SqlxQueryScalar_CommandInjection(t *testing.T) {
	code := `
use sqlx::PgPool;
use std::process::Command;

async fn handler(pool: &PgPool) {
    let name: String = sqlx::query_scalar("SELECT name FROM users LIMIT 1").fetch_one(pool).await.unwrap();
    Command::new(&name).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for sqlx query_scalar -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_DieselGetResult_CommandInjection(t *testing.T) {
	code := `
use diesel::prelude::*;
use std::process::Command;

fn handler(conn: &mut PgConnection) {
    let name = diesel::insert_into(users).values(&new_user).get_result(conn).unwrap();
    Command::new(&name).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for diesel get_result -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_DieselGetResults_CommandInjection(t *testing.T) {
	code := `
use diesel::prelude::*;
use std::process::Command;

fn handler(conn: &mut PgConnection) {
    let users = diesel::insert_into(users).values(&batch).get_results(conn).unwrap();
    Command::new(&users).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for diesel get_results -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_RusqliteQueryRow_CommandInjection(t *testing.T) {
	code := `
use rusqlite::Connection;
use std::process::Command;

fn handler(conn: &Connection) {
    let name: String = conn.query_row("SELECT name FROM users WHERE id=1", [], |row| row.get(0)).unwrap();
    Command::new(&name).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for rusqlite query_row -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_RusqliteQueryMap_CommandInjection(t *testing.T) {
	code := `
use rusqlite::Connection;
use std::process::Command;

fn handler(conn: &Connection) {
    let names = stmt.query_map([], |row| row.get(0)).unwrap();
    Command::new(&names).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for rusqlite query_map -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_TokioPostgresQueryOne_CommandInjection(t *testing.T) {
	code := `
use tokio_postgres::Client;
use std::process::Command;

async fn handler(client: &Client) {
    let name = client.query_one("SELECT name FROM users WHERE id=$1", &[&1]).await.unwrap();
    Command::new(&name).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for tokio-postgres query_one -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_TokioPostgresQueryOpt_CommandInjection(t *testing.T) {
	code := `
use tokio_postgres::Client;
use std::process::Command;

async fn handler(client: &Client) {
    let name = client.query_opt("SELECT name FROM users WHERE id=$1", &[&1]).await.unwrap().unwrap();
    Command::new(&name).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for tokio-postgres query_opt -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_DB_MongoDBFindOne_CommandInjection(t *testing.T) {
	code := `
use mongodb::Collection;
use std::process::Command;

async fn handler(collection: &Collection) {
    let doc = collection.find_one(None).await.unwrap().unwrap();
    Command::new(&doc).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for mongodb find_one -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Rust external/cloud source tests
// =========================================================================

func TestRust_External_LambdaEvent_CommandInjection(t *testing.T) {
	// LambdaEvent<T> is a type annotation, not a function call.
	// tsflow detects it via parameter seeding: "payload" is in isInputParamName.
	code := `
use lambda_runtime::LambdaEvent;
use std::process::Command;

async fn handler(payload: LambdaEvent<String>) {
    let cmd = payload.payload;
    Command::new(&cmd).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Lambda payload -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_External_SQSReceive_CommandInjection(t *testing.T) {
	code := `
use aws_sdk_sqs::Client;
use std::process::Command;

async fn handler(sqs: &Client) {
    let output = sqs.receive_message().send().await.unwrap();
    Command::new(&output).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for SQS receive_message -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_External_S3GetObject_CommandInjection(t *testing.T) {
	code := `
use aws_sdk_s3::Client;
use std::process::Command;

async fn handler(s3: &Client) {
    let resp = s3.get_object().send().await.unwrap();
    Command::new(&resp).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for S3 get_object -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe tests — sanitized paths should NOT produce flows
// =========================================================================

func TestRust_DB_SqlxFetchOne_Safe_Parameterized(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn handler(pool: &PgPool) {
    let name: String = sqlx::query_scalar("SELECT name FROM users LIMIT 1").fetch_one(pool).await.unwrap();
    sqlx::query("INSERT INTO log (msg) VALUES ($1)").bind(&name).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected no SQL injection flow when parameterized query (.bind) is used")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
