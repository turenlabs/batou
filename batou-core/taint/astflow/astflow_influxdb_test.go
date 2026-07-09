package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// InfluxDB query-language injection (CWE-943) tests
//
// v2 client (github.com/influxdata/influxdb-client-go/v2):
//   api.QueryAPI.Query(ctx, flux)  — Flux query string (arg 1)
//   api.QueryAPI.QueryRaw(ctx, flux, dialect) — Flux query string (arg 1)
//
// v1 client (github.com/influxdata/influxdb1-client/v2):
//   client.NewQuery(command, db, precision) — InfluxQL command (arg 0)
//
// Both Flux and InfluxQL accept multi-pipeline / `;`-separated statements,
// so a single string concatenation is enough to break out of the intended
// query and read arbitrary buckets / measurements.
// =========================================================================

func TestCatalogMatcher_InfluxDBSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sinks := cat.Sinks()
	matcher := NewCatalogMatcher(nil, sinks, nil, nil)

	expected := map[string]string{
		"go.influxdb2.queryapi.query":    "Query",
		"go.influxdb2.queryapi.queryraw": "QueryRaw",
		"go.influxdb1.client.newquery":   "NewQuery",
	}

	for id, method := range expected {
		found := false
		for _, s := range matcher.sinksByMethod[method] {
			if s.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected sink %q to be indexed under method name %q", id, method)
		}
	}
}

func TestAnalyzeGo_InfluxDB2QueryAPI_Query_FluxInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/influxdata/influxdb-client-go/v2/api"
)

func handler(ctx context.Context, queryAPI api.QueryAPI, r *http.Request) {
	bucket := r.URL.Query().Get("bucket")
	flux := ` + "`" + `from(bucket: "` + "`" + ` + bucket + ` + "`" + `") |> range(start: -1h)` + "`" + `
	queryAPI.Query(ctx, flux)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.influxdb2.queryapi.query" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Flux injection flow for query param -> api.QueryAPI.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_InfluxDB2QueryAPI_QueryRaw_FluxInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/domain"
)

func handler(ctx context.Context, queryAPI api.QueryAPI, r *http.Request) {
	measurement := r.URL.Query().Get("m")
	flux := ` + "`" + `from(bucket: "data") |> filter(fn: (r) => r._measurement == "` + "`" + ` + measurement + ` + "`" + `")` + "`" + `
	var dialect *domain.Dialect
	queryAPI.QueryRaw(ctx, flux, dialect)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.influxdb2.queryapi.queryraw" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Flux injection flow for query param -> api.QueryAPI.QueryRaw")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_InfluxDB1ClientNewQuery_InfluxQLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	client "github.com/influxdata/influxdb1-client/v2"
)

func handler(c client.Client, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := "SELECT * FROM cpu WHERE host = '" + host + "'"
	q := client.NewQuery(cmd, "mydb", "ns")
	c.Query(q)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.influxdb1.client.newquery" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected InfluxQL injection flow for query param -> client.NewQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative test: parameterized v2 QueryWithParams should NOT be flagged because
// it is the safe, parameter-bound API. (We don't catalog QueryWithParams as a
// sink — this test exercises the absence-of-finding contract.)
func TestAnalyzeGo_InfluxDB2QueryAPI_QueryWithParams_Safe(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/influxdata/influxdb-client-go/v2/api"
)

func handler(ctx context.Context, queryAPI api.QueryAPI, r *http.Request) {
	bucket := r.URL.Query().Get("bucket")
	flux := ` + "`" + `from(bucket: params.b) |> range(start: -1h)` + "`" + `
	params := map[string]interface{}{"b": bucket}
	queryAPI.QueryWithParams(ctx, flux, params)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.influxdb2.queryapi.query" || f.Sink.ID == "go.influxdb2.queryapi.queryraw" {
			t.Errorf("unexpected Flux injection flow on parameterized QueryWithParams call: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}
