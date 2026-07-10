package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Rust — Message broker / task queue producer trust boundary (CWE-501)
// =========================================================================
//
// Producers push tainted user data into a broker (Kafka / RabbitMQ / NATS /
// Pulsar / Redis-backed queues). Consumers deserialize and process those
// payloads in a privileged context, across a trust boundary. Rust already
// had the consumer-side *sources* for these brokers; these tests cover the
// producer-side sinks added in rust_sinks.go.

// --- rdkafka FutureProducer (async) ---

func TestRust_TaskQueue_RdkafkaFutureProducer(t *testing.T) {
	code := `
use axum::extract::Query;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

async fn handler(Query(params): Query<SendParams>, producer: FutureProducer) {
    let body = &params.body;
    let _ = producer.send(
        FutureRecord::to("events").payload(body).key("k"),
        Duration::from_secs(5),
    ).await;
}
`
	flows := Analyze(code, "/app/kafka_producer.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for axum Query -> rdkafka FutureProducer.send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TaskQueue_RdkafkaFutureProducer_Hardcoded_Safe(t *testing.T) {
	code := `
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

async fn handler(producer: FutureProducer) {
    let _ = producer.send(
        FutureRecord::to("events").payload("hardcoded-event").key("k"),
        Duration::from_secs(5),
    ).await;
}
`
	flows := Analyze(code, "/app/kafka_producer.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Errorf("hardcoded rdkafka FutureProducer.send should not produce trust-boundary flow: %s", f.Sink.ID)
		}
	}
}

// --- rdkafka BaseProducer (sync) ---

func TestRust_TaskQueue_RdkafkaBaseProducer(t *testing.T) {
	code := `
use axum::extract::Query;
use rdkafka::producer::{BaseProducer, BaseRecord};

fn handler(Query(params): Query<SendParams>, producer: BaseProducer) {
    let body = &params.body;
    let _ = producer.send(
        BaseRecord::to("events").payload(body).key("k"),
    );
}
`
	flows := Analyze(code, "/app/kafka_sync_producer.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for axum Query -> rdkafka BaseProducer.send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- lapin (AMQP/RabbitMQ) ---

func TestRust_TaskQueue_LapinBasicPublish(t *testing.T) {
	code := `
use axum::extract::Query;
use lapin::{Channel, options::BasicPublishOptions, BasicProperties};

async fn handler(Query(params): Query<PublishParams>, channel: Channel) {
    let body = params.body.as_bytes();
    let _ = channel.basic_publish(
        "",
        "events",
        BasicPublishOptions::default(),
        body,
        BasicProperties::default(),
    ).await;
}
`
	flows := Analyze(code, "/app/rabbit_producer.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for axum Query -> lapin Channel.basic_publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- async-nats ---

func TestRust_TaskQueue_NatsClientPublish(t *testing.T) {
	code := `
use axum::extract::Query;
use async_nats::Client;

async fn handler(Query(params): Query<NatsParams>, client: Client) {
    let payload = params.data.clone();
    let _ = client.publish("events", payload.into()).await;
}
`
	flows := Analyze(code, "/app/nats_producer.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for axum Query -> async_nats Client.publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TaskQueue_NatsPublishWithReply(t *testing.T) {
	code := `
use axum::extract::Query;
use async_nats::Client;

async fn handler(Query(params): Query<NatsParams>, client: Client) {
    let payload = params.data.clone();
    let _ = client.publish_with_reply("events", "reply.inbox", payload.into()).await;
}
`
	flows := Analyze(code, "/app/nats_reply_producer.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for axum Query -> async_nats publish_with_reply")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- pulsar ---

func TestRust_TaskQueue_PulsarProducerSend(t *testing.T) {
	code := `
use axum::extract::Query;
use pulsar::Producer;

async fn handler(Query(params): Query<PulsarParams>, producer: Producer) {
    let body = params.payload.clone();
    let _ = producer.send(body).await;
}
`
	flows := Analyze(code, "/app/pulsar_producer.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for axum Query -> pulsar Producer.send")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRust_TaskQueue_PulsarSendNonBlocking(t *testing.T) {
	code := `
use axum::extract::Query;
use pulsar::Producer;

async fn handler(Query(params): Query<PulsarParams>, producer: Producer) {
    let body = params.payload.clone();
    let _ = producer.send_non_blocking(body).await;
}
`
	flows := Analyze(code, "/app/pulsar_nb_producer.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for axum Query -> pulsar send_non_blocking")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- apalis (Rust task queue over Redis/SQS/Postgres) ---

func TestRust_TaskQueue_ApalisStoragePush(t *testing.T) {
	code := `
use axum::extract::Query;
use apalis::prelude::*;

async fn handler(Query(params): Query<JobParams>, mut storage: RedisStorage<EmailJob>) {
    let email = params.email.clone();
    let job = EmailJob { to: email };
    let _ = storage.push(job).await;
}
`
	flows := Analyze(code, "/app/apalis_producer.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust-boundary flow for axum Query -> apalis Storage.push")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
