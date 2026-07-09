package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Go — Message broker / task queue producer trust boundary (CWE-501)
// =========================================================================
//
// Producers push tainted user data into a broker (RabbitMQ / NATS / GCP
// Pub/Sub / Sarama-Kafka) or a task queue (Asynq). Consumers deserialize
// and process those payloads in a privileged context, across a trust
// boundary. Go already had the consumer-side *sources* for these brokers
// (go.amqp.channel.consume, go.nats.subscription.nextmsg, go.gcp.pubsub.receive,
// etc.) but no producer-side trust-boundary sinks. Mirrors Java PR #426,
// Rust PR #424, and the existing Python/Ruby/JS/Kotlin trust-boundary sinks.

// --- Catalog registration test ---

func TestCatalogMatcher_TaskQueueSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sinks := cat.Sinks()
	matcher := NewCatalogMatcher(nil, sinks, nil, nil)

	checks := []struct {
		method string
		id     string
	}{
		{"Publish", "go.amqp.channel.publish"},
		{"PublishWithContext", "go.amqp.channel.publishwithcontext"},
		{"Publish", "go.nats.conn.publish"},
		{"PublishMsg", "go.nats.conn.publishmsg"},
		{"Publish", "go.gcp.pubsub.topic.publish"},
		{"Enqueue", "go.asynq.client.enqueue"},
		{"SendMessage", "go.sarama.syncproducer.sendmessage"},
	}

	for _, c := range checks {
		found := false
		for _, sink := range matcher.sinksByMethod[c.method] {
			if sink.ID == c.id && sink.Category == taint.SnkTrustBoundary {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected sink %q (method=%q) to be registered as SnkTrustBoundary", c.id, c.method)
		}
	}
}

// --- End-to-end flow tests ---

func TestAnalyzeGo_TaskQueue_AmqpChannelPublish(t *testing.T) {
	code := `package main

import (
	"net/http"

	amqp "github.com/rabbitmq/amqp091-go"
)

func handler(w http.ResponseWriter, r *http.Request, ch *amqp.Channel) {
	payload := r.FormValue("body")
	ch.Publish("ex", "rk", false, false, amqp.Publishing{
		ContentType: "text/plain",
		Body:        []byte(payload),
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for r.FormValue → ch.Publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_TaskQueue_AmqpChannelPublishWithContext(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	amqp "github.com/rabbitmq/amqp091-go"
)

func handler(w http.ResponseWriter, r *http.Request, ch *amqp.Channel) {
	ctx := context.Background()
	body := r.URL.Query().Get("data")
	ch.PublishWithContext(ctx, "ex", "rk", false, false, amqp.Publishing{
		Body: []byte(body),
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for r.URL.Query().Get → ch.PublishWithContext")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_TaskQueue_NatsConnPublish(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/nats-io/nats.go"
)

func handler(w http.ResponseWriter, r *http.Request, nc *nats.Conn) {
	subject := "events.user"
	data := r.FormValue("payload")
	nc.Publish(subject, []byte(data))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for r.FormValue → nc.Publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_TaskQueue_NatsConnPublishMsg(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/nats-io/nats.go"
)

func handler(w http.ResponseWriter, r *http.Request, nc *nats.Conn) {
	body := r.FormValue("data")
	msg := &nats.Msg{
		Subject: "events.user",
		Data:    []byte(body),
	}
	nc.PublishMsg(msg)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for r.FormValue → nc.PublishMsg")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_TaskQueue_GcpPubsubTopicPublish(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"cloud.google.com/go/pubsub"
)

func handler(w http.ResponseWriter, r *http.Request, topic *pubsub.Topic) {
	ctx := context.Background()
	data := r.FormValue("payload")
	topic.Publish(ctx, &pubsub.Message{
		Data: []byte(data),
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for r.FormValue → topic.Publish")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_TaskQueue_AsynqClientEnqueue(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/hibiken/asynq"
)

func handler(w http.ResponseWriter, r *http.Request, client *asynq.Client) {
	payload := r.FormValue("data")
	task := asynq.NewTask("email:send", []byte(payload))
	client.Enqueue(task)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for r.FormValue → client.Enqueue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_TaskQueue_SaramaSyncProducerSendMessage(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/IBM/sarama"
)

func handler(w http.ResponseWriter, r *http.Request, producer sarama.SyncProducer) {
	value := r.FormValue("body")
	msg := &sarama.ProducerMessage{
		Topic: "events",
		Value: sarama.StringEncoder(value),
	}
	producer.SendMessage(msg)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected SnkTrustBoundary flow for r.FormValue → producer.SendMessage")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- Negative test: hardcoded constant payload must NOT fire ---

func TestAnalyzeGo_TaskQueue_HardcodedPayload_NoFlow(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	amqp "github.com/rabbitmq/amqp091-go"
)

func handler(w http.ResponseWriter, r *http.Request, ch *amqp.Channel) {
	_ = r.FormValue("ignored")
	ctx := context.Background()
	ch.PublishWithContext(ctx, "ex", "rk", false, false, amqp.Publishing{
		Body: []byte("static-internal-event"),
	})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected NO SnkTrustBoundary flow for hardcoded payload")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
