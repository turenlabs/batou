package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Rust external source tests — messaging & RPC frameworks
// =========================================================================

// --- rdkafka (Kafka) ---

func TestRust_External_Rdkafka_ConsumerRecv_CommandInjection(t *testing.T) {
	code := `
use rdkafka::consumer::StreamConsumer;
use std::process::Command;

async fn handler(consumer: &StreamConsumer) {
    let msg = consumer.recv().await.unwrap();
    Command::new(&format!("{:?}", msg)).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for rdkafka consumer.recv -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_External_Rdkafka_Payload_SQLInjection(t *testing.T) {
	code := `
use sqlx::PgPool;

async fn process(pool: &PgPool) {
    let text = msg.payload();
    sqlx::query(&format!("INSERT INTO log VALUES ('{:?}')", text)).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for rdkafka .payload() -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- lapin (RabbitMQ) ---

func TestRust_External_Lapin_BasicConsume_CommandInjection(t *testing.T) {
	code := `
use lapin::Channel;
use std::process::Command;

async fn handler(channel: &Channel) {
    let consumer = channel.basic_consume("queue", "tag", Default::default(), Default::default()).await.unwrap();
    Command::new(&format!("{:?}", consumer)).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for lapin basic_consume -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_External_Lapin_DeliveryData_SQLInjection(t *testing.T) {
	code := `
use lapin::Delivery;
use sqlx::PgPool;

async fn process(delivery: Delivery, pool: &PgPool) {
    let msg = delivery.data;
    sqlx::query(&format!("INSERT INTO events VALUES ('{:?}')", msg)).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for lapin delivery.data -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- tonic (gRPC) ---

func TestRust_External_Tonic_IntoInner_CommandInjection(t *testing.T) {
	code := `
use tonic::{Request, Response, Status};
use std::process::Command;

async fn run_job(request: Request<JobRequest>) -> Result<Response<JobReply>, Status> {
    let req = request.into_inner();
    let cmd = req.command;
    Command::new(&cmd).output().unwrap();
    Ok(Response::new(JobReply {}))
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for tonic request.into_inner -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_External_Tonic_GetRef_SQLInjection(t *testing.T) {
	code := `
use tonic::{Request, Response, Status};
use sqlx::PgPool;

async fn search(request: Request<SearchRequest>, pool: &PgPool) -> Result<Response<SearchReply>, Status> {
    let q = request.get_ref();
    let query_str = &q.term;
    sqlx::query(&format!("SELECT * FROM items WHERE name = '{}'", query_str)).fetch_all(pool).await.unwrap();
    Ok(Response::new(SearchReply {}))
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for tonic request.get_ref -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_External_Tonic_Metadata_CommandInjection(t *testing.T) {
	code := `
use tonic::{Request, Response, Status};
use std::process::Command;

async fn handler(request: Request<MyReq>) -> Result<Response<MyResp>, Status> {
    let meta = request.metadata();
    let token = meta.get("x-api-key").unwrap().to_str().unwrap();
    Command::new(token).output().unwrap();
    Ok(Response::new(MyResp {}))
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for tonic request.metadata -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- async-nats (NATS) ---

func TestRust_External_Nats_Subscribe_CommandInjection(t *testing.T) {
	code := `
use async_nats;
use std::process::Command;

async fn handler(client: async_nats::Client) {
    let subscriber = client.subscribe("jobs.>").await.unwrap();
    Command::new(&format!("{:?}", subscriber)).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for NATS client.subscribe -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- rumqttc (MQTT) ---

func TestRust_External_Rumqttc_Poll_CommandInjection(t *testing.T) {
	code := `
use rumqttc::{AsyncClient, EventLoop, Event, Incoming};
use std::process::Command;

async fn handler(mut eventloop: EventLoop) {
    let event = eventloop.poll().await.unwrap();
    Command::new(&format!("{:?}", event)).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for rumqttc eventloop.poll -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_External_Rumqttc_Poll_SQLInjection(t *testing.T) {
	code := `
use rumqttc::EventLoop;
use sqlx::PgPool;

async fn process(mut eventloop: EventLoop, pool: &PgPool) {
    let event = eventloop.poll().await.unwrap();
    sqlx::query(&format!("INSERT INTO mqtt_log VALUES ('{:?}')", event)).execute(pool).await.unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for rumqttc eventloop.poll -> sqlx::query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Pulsar ---

func TestRust_External_Pulsar_TryNext_CommandInjection(t *testing.T) {
	code := `
use pulsar::Consumer;
use std::process::Command;
use futures::TryStreamExt;

async fn handler(mut consumer: Consumer<String, _>) {
    let msg = consumer.try_next().await.unwrap().unwrap();
    let data = msg.deserialize().unwrap();
    Command::new(&data).output().unwrap();
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Pulsar consumer.try_next -> Command::new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe tests — external data properly sanitized before use
// =========================================================================

func TestRust_External_Rdkafka_Safe_ParsedInt(t *testing.T) {
	code := `
use rdkafka::consumer::StreamConsumer;

async fn handler(consumer: &StreamConsumer) {
    let msg = consumer.recv().await.unwrap();
    let payload = msg.payload().unwrap();
    let text = String::from_utf8_lossy(payload);
    let count: i64 = text.parse().unwrap();
    println!("processed {} messages", count);
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected no command injection flow when Kafka payload is parsed to integer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_External_Tonic_Safe_Parameterized(t *testing.T) {
	code := `
use tonic::{Request, Response, Status};
use sqlx::PgPool;

async fn search(request: Request<SearchRequest>, pool: &PgPool) -> Result<Response<SearchReply>, Status> {
    let req = request.into_inner();
    sqlx::query("INSERT INTO searches (term) VALUES ($1)").bind(&req.term).execute(pool).await.unwrap();
    Ok(Response::new(SearchReply {}))
}
`
	flows := Analyze(code, "/app/handler.rs", rules.LangRust)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected no SQL injection when tonic request data used with parameterized query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
