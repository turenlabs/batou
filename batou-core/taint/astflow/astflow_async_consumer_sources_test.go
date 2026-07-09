package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Go — async-task / message-broker consumer trust-boundary sources (CWE-501)
// =========================================================================
//
// Mirrors the existing producer-side trust-boundary sinks
// (go.asynq.client.enqueue, go.amqp.channel.publish, go.nats.conn.publish,
// go.gcp.pubsub.topic.publish, go.sarama.syncproducer.sendmessage) by
// tainting consumer-side message accessors that haven't been covered yet:
//
//   - Asynq         (hibiken/asynq):                 *asynq.Task.Payload
//   - Paho MQTT     (eclipse/paho.mqtt.golang):      mqtt.Message.Payload, .Topic
//   - NATS JetStream (nats-io/nats.go/jetstream):    jetstream.Msg.Data, .Subject, .Headers
//
// The legacy NATS Subscription.NextMsg, GCP Pub/Sub Receive, AMQP Consume,
// and Kafka Consumer.ReadMessage handler-side sources were already in the
// catalog; this file covers the modern siblings.

// --- Catalog registration test ---

func TestCatalogMatcher_AsyncConsumerSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sources := cat.Sources()
	matcher := NewCatalogMatcher(sources, nil, nil, nil)

	checks := []struct {
		method string
		id     string
	}{
		{"Payload", "go.asynq.task.payload"},
		{"Payload", "go.paho.mqtt.message.payload"},
		{"Topic", "go.paho.mqtt.message.topic"},
		{"Data", "go.jetstream.msg.data"},
		{"Subject", "go.jetstream.msg.subject"},
		{"Headers", "go.jetstream.msg.headers"},
	}

	for _, c := range checks {
		found := false
		for _, src := range matcher.sourcesByMethod[c.method] {
			if src.ID == c.id && src.Category == taint.SrcExternal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected source %q (method=%q) to be registered as SrcExternal", c.id, c.method)
		}
	}
}

// --- Asynq end-to-end flow tests ---

func TestAnalyzeGo_AsyncConsumer_AsynqTaskPayload_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"

	"github.com/hibiken/asynq"
)

var db *sql.DB

func ProcessUserTask(ctx context.Context, t *asynq.Task) error {
	body := t.Payload()
	db.Query("SELECT * FROM users WHERE name = '" + string(body) + "'")
	return nil
}
`
	flows := AnalyzeGo(code, "/app/worker.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for asynq.Task.Payload -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_AsyncConsumer_AsynqTaskPayload_CmdInj(t *testing.T) {
	code := `package main

import (
	"context"
	"os/exec"

	"github.com/hibiken/asynq"
)

func ProcessShellTask(ctx context.Context, t *asynq.Task) error {
	body := t.Payload()
	exec.Command("sh", "-c", string(body)).Run()
	return nil
}
`
	flows := AnalyzeGo(code, "/app/worker.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for asynq.Task.Payload -> exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Paho MQTT end-to-end flow tests ---

func TestAnalyzeGo_AsyncConsumer_PahoMqttPayload_CmdInj(t *testing.T) {
	code := `package main

import (
	"os/exec"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func handler(client mqtt.Client, msg mqtt.Message) {
	body := msg.Payload()
	exec.Command("sh", "-c", string(body)).Run()
}
`
	flows := AnalyzeGo(code, "/app/iot.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for mqtt.Message.Payload -> exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_AsyncConsumer_PahoMqttTopic_Log(t *testing.T) {
	code := `package main

import (
	"log"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func handler(client mqtt.Client, msg mqtt.Message) {
	topic := msg.Topic()
	log.Printf("received on topic: %s", topic)
}
`
	flows := AnalyzeGo(code, "/app/iot.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for mqtt.Message.Topic -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- NATS JetStream end-to-end flow tests ---

func TestAnalyzeGo_AsyncConsumer_JetStreamData_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/nats-io/nats.go/jetstream"
)

var db *sql.DB

func handle(msg jetstream.Msg) {
	body := msg.Data()
	db.Query("SELECT * FROM events WHERE name = '" + string(body) + "'")
}
`
	flows := AnalyzeGo(code, "/app/stream.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for jetstream.Msg.Data -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_AsyncConsumer_JetStreamSubject_Log(t *testing.T) {
	code := `package main

import (
	"log"

	"github.com/nats-io/nats.go/jetstream"
)

func handle(msg jetstream.Msg) {
	subj := msg.Subject()
	log.Printf("got subject: %s", subj)
}
`
	flows := AnalyzeGo(code, "/app/stream.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for jetstream.Msg.Subject -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Negative tests (no flow expected) ---

// Hardcoded payloads must not produce flows — guards against
// "any *.Payload() call" overmatch.
func TestAnalyzeGo_AsyncConsumer_HardcodedAsynqPayload_NoFlow(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
)

var db *sql.DB

func process(ctx context.Context) error {
	payload := "hardcoded constant"
	db.Query("SELECT * FROM users WHERE name = '" + payload + "'")
	return nil
}
`
	flows := AnalyzeGo(code, "/app/worker.go")
	for _, f := range flows {
		if f.Source.ID == "go.asynq.task.payload" {
			t.Errorf("unexpected asynq taint flow without *asynq.Task receiver: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// Wrong receiver type — `*asynq.Client` (the publisher) has no Payload(),
// but if someone names a different variable .Payload() this guards against
// matching it as a tainted source.
func TestAnalyzeGo_AsyncConsumer_WrongReceiver_NoFlow(t *testing.T) {
	code := `package main

import (
	"database/sql"
)

type localStruct struct{}

func (l *localStruct) Payload() []byte { return []byte("safe") }

var db *sql.DB

func handler(local *localStruct) {
	body := string(local.Payload())
	db.Query("SELECT * FROM events WHERE name = '" + body + "'")
}
`
	flows := AnalyzeGo(code, "/app/worker.go")
	for _, f := range flows {
		if f.Source.ID == "go.asynq.task.payload" ||
			f.Source.ID == "go.paho.mqtt.message.payload" {
			t.Errorf("unexpected async-consumer taint on unrelated *localStruct.Payload(): %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
