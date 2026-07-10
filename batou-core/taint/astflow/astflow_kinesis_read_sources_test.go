package astflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Go — AWS Kinesis Data Streams second-order stream-consumer sources
// =========================================================================
//
// Closes the single gap in Go's stream/queue consumer source coverage: GCP
// Pub/Sub, Kafka, RabbitMQ, NATS, NATS JetStream and Redis Pub/Sub consumers
// were already modeled, but AWS Kinesis was not. An attacker who can publish
// records onto a stream controls the bytes a consumer later reads via
// GetRecords; those payloads then flow into SQL/command/etc. sinks.
//
// Covers aws-sdk-go-v2 (*kinesis.Client.GetRecords) and the legacy
// aws-sdk-go v1 (*kinesis.Kinesis.GetRecordsWithContext). The receiver-name
// heuristic added in astflow/matcher.go resolves untyped `:=` clients
// (svc/kc/kinesis/...) so detection works on idiomatic real-world code, not
// only statically-typed function parameters.

// --- Catalog registration ---

func TestCatalogMatcher_KinesisReadSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	matcher := NewCatalogMatcher(cat.Sources(), nil, nil, nil)

	checks := []struct {
		method string
		id     string
	}{
		{"GetRecords", "go.kinesis.getrecords"},
		{"GetRecordsWithContext", "go.kinesis.getrecordswithcontext"},
	}
	for _, c := range checks {
		found := false
		for _, src := range matcher.sourcesByMethod[c.method] {
			if src.ID == c.id && src.Category == taint.SrcDatabase {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected source %q (method=%q) to be registered as SrcDatabase", c.id, c.method)
		}
	}
}

// --- v2: typed *kinesis.Client receiver (TypeEnv resolution) ---

func TestAnalyzeGo_KinesisGetRecords_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

func handler(client *kinesis.Client, db *sql.DB) {
	out := client.GetRecords(nil, nil)
	db.Query("SELECT * FROM events WHERE actor = '" + out + "'")
}
`
	flows := AnalyzeGo(code, "/app/consumer.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Kinesis GetRecords → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDatabase) {
		t.Error("expected source category SrcDatabase")
	}
}

func TestAnalyzeGo_KinesisGetRecords_SecondOrderCommand(t *testing.T) {
	code := `package main

import (
	"os/exec"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

func handler(client *kinesis.Client) {
	out := client.GetRecords(nil, nil)
	exec.Command("sh", "-c", "echo "+out)
}
`
	flows := AnalyzeGo(code, "/app/consumer.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected second-order command injection: Kinesis GetRecords → exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- v2: untyped `:=` client (receiver-name heuristic, no TypeEnv) ---

func TestAnalyzeGo_KinesisGetRecords_UntypedLocal_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

func handler(db *sql.DB) {
	cfg, _ := config.LoadDefaultConfig(context.TODO())
	kc := kinesis.NewFromConfig(cfg)
	out := kc.GetRecords(nil, nil)
	db.Query("SELECT * FROM events WHERE actor = '" + out + "'")
}
`
	flows := AnalyzeGo(code, "/app/consumer.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: untyped kc.GetRecords → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- v1 (legacy aws-sdk-go): typed *kinesis.Kinesis receiver ---

func TestAnalyzeGo_KinesisGetRecordsWithContext_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go/service/kinesis"
)

func handler(svc *kinesis.Kinesis, db *sql.DB) {
	out := svc.GetRecordsWithContext(nil, nil)
	db.Query("SELECT * FROM events WHERE actor = '" + out + "'")
}
`
	flows := AnalyzeGo(code, "/app/consumer.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: Kinesis GetRecordsWithContext → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative control: constant record data, no taint source ---

func TestAnalyzeGo_KinesisGetRecords_ConstantData_NoFlow(t *testing.T) {
	code := `package main

import "database/sql"

func handler(db *sql.DB) {
	actor := "system"
	db.Query("SELECT * FROM events WHERE actor = '" + actor + "'")
}
`
	flows := AnalyzeGo(code, "/app/consumer.go")
	for _, f := range flows {
		if strings.HasPrefix(f.Source.ID, "go.kinesis.") {
			t.Errorf("did not expect a Kinesis-sourced flow for constant data, got %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
