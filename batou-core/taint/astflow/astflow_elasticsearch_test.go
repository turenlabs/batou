package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Catalog registration tests ---

func TestCatalogMatcher_OlivereElasticSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sinks := cat.Sinks()
	matcher := NewCatalogMatcher(nil, sinks, nil, nil)

	expectedMethods := []string{
		"NewQueryStringQuery",
		"NewSimpleQueryStringQuery",
		"NewRawStringQuery",
		"NewScriptInline",
	}

	for _, method := range expectedMethods {
		if len(matcher.sinksByMethod[method]) == 0 {
			t.Errorf("expected %q to be indexed as a sink", method)
		}
	}
}

func TestCatalogMatcher_OlivereElasticSanitizersRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sanitizers := cat.Sanitizers()
	matcher := NewCatalogMatcher(nil, nil, sanitizers, nil)

	expectedMethods := []string{
		"NewTermQuery",
		"NewMatchQuery",
		"NewRangeQuery",
	}

	for _, method := range expectedMethods {
		if len(matcher.sanitizersByMethod[method]) == 0 {
			t.Errorf("expected %q to be indexed as a sanitizer", method)
		}
	}
}

// --- End-to-end taint flow tests ---

func TestAnalyzeGo_OlivereElastic_QueryStringQueryInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/olivere/elastic/v7"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("q")
	_ = elastic.NewQueryStringQuery(userInput)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL/Lucene injection: r.URL.Query().Get → elastic.NewQueryStringQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_OlivereElastic_SimpleQueryStringQueryInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/olivere/elastic/v7"
)

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
	_ = elastic.NewSimpleQueryStringQuery(q)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL/Lucene injection via simple_query_string")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_OlivereElastic_RawStringQueryInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/olivere/elastic/v7"
)

func handler(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	_ = elastic.NewRawStringQuery(body)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection via raw JSON query body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_OlivereElastic_ScriptInlineInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/olivere/elastic/v7"
)

func handler(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("script")
	_ = elastic.NewScriptInline(src)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected server-side script injection via Painless inline script")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_OlivereElastic_TermQuerySanitized(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/olivere/elastic/v7"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userValue := r.URL.Query().Get("user")
	// Safe: structured term query isolates value from query structure.
	q := elastic.NewTermQuery("username", userValue)
	_ = elastic.NewRawStringQuery(q.Source)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	// The tainted value is first neutralized by NewTermQuery before being
	// observed near the raw-string-query sink. We should not report a
	// SnkSQLQuery flow from r.URL.Query() to this sink in the sanitized path.
	for _, f := range flows {
		if f.Sink.ID == "go.olivere.elastic.newtermquery" {
			t.Errorf("term query builder should not itself be reported as a sink: %+v", f)
		}
	}
}

// =========================================================================
// Elasticsearch v8 (github.com/elastic/go-elasticsearch/v8) and
// OpenSearch (github.com/opensearch-project/opensearch-go) — modern client
// query-DSL + Painless script injection sinks.
// CWE-943 (NoSQL/DSL injection) and CWE-94 (Painless RCE on the cluster).
// =========================================================================

// --- Catalog registration: the new sinks must be indexed by method name ---

func TestCatalogMatcher_ElasticsearchV8SinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sinks := cat.Sinks()
	matcher := NewCatalogMatcher(nil, sinks, nil, nil)

	expectedMethods := []string{
		"Bulk",
		"Msearch",
		"DeleteByQuery",
		"Reindex",
		"PutScript",
	}

	for _, method := range expectedMethods {
		if len(matcher.sinksByMethod[method]) == 0 {
			t.Errorf("expected %q to be indexed as a sink (elasticsearch v8 / opensearch)", method)
		}
	}
}

// --- elasticsearch v8: Bulk(body, ...) — NDJSON body DSL injection ---

func TestAnalyzeGo_ElasticsearchV8_Bulk_DSLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
)

func handler(es *elasticsearch.Client, w http.ResponseWriter, r *http.Request) {
	idLine := r.FormValue("id")
	body := "{\"index\":{\"_id\":\"" + idLine + "\"}}\n{\"name\":\"x\"}\n"
	es.Bulk(strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for FormValue -> es.Bulk")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- elasticsearch v8: Msearch(body, ...) — multi-search NDJSON injection ---

func TestAnalyzeGo_ElasticsearchV8_Msearch_DSLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
)

func handler(es *elasticsearch.Client, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	body := "{\"index\":\"logs\"}\n{\"query\":{\"query_string\":{\"query\":\"" + q + "\"}}}\n"
	es.Msearch(strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected per-shard DSL-injection flow for URL.Query -> es.Msearch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- elasticsearch v8: DeleteByQuery(idx, body, ...) — destructive DSL injection ---

func TestAnalyzeGo_ElasticsearchV8_DeleteByQuery_DSLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
)

func handler(es *elasticsearch.Client, w http.ResponseWriter, r *http.Request) {
	tenant := r.FormValue("tenant")
	body := "{\"query\":{\"term\":{\"tenant\":\"" + tenant + "\"}}}"
	es.DeleteByQuery([]string{"records"}, strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected destructive DSL-injection flow for FormValue -> es.DeleteByQuery body arg")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- elasticsearch v8: Reindex(body, ...) — body may carry Painless script.source (RCE) ---

func TestAnalyzeGo_ElasticsearchV8_Reindex_PainlessRCE(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
)

func handler(es *elasticsearch.Client, w http.ResponseWriter, r *http.Request) {
	src := r.FormValue("transform")
	body := "{\"source\":{\"index\":\"a\"},\"dest\":{\"index\":\"b\"},\"script\":{\"lang\":\"painless\",\"source\":\"" + src + "\"}}"
	es.Reindex(strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless RCE flow for FormValue -> es.Reindex (script.source)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- elasticsearch v8: PutScript(id, body, ...) — persistent stored Painless RCE ---

func TestAnalyzeGo_ElasticsearchV8_PutScript_PersistentRCE(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
)

func handler(es *elasticsearch.Client, w http.ResponseWriter, r *http.Request) {
	src := r.FormValue("painless")
	body := "{\"script\":{\"lang\":\"painless\",\"source\":\"" + src + "\"}}"
	es.PutScript("daily-rollup", strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected persistent-RCE flow for FormValue -> es.PutScript body arg")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- opensearch-go: Bulk(body, ...) ---

func TestAnalyzeGo_OpenSearch_Bulk_DSLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/opensearch-project/opensearch-go/opensearch"
)

func handler(client *opensearch.Client, w http.ResponseWriter, r *http.Request) {
	idLine := r.FormValue("id")
	body := "{\"index\":{\"_id\":\"" + idLine + "\"}}\n{\"name\":\"x\"}\n"
	client.Bulk(strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL-injection flow for FormValue -> opensearch client.Bulk")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- opensearch-go: DeleteByQuery(idx, body, ...) ---

func TestAnalyzeGo_OpenSearch_DeleteByQuery_DSLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/opensearch-project/opensearch-go/opensearch"
)

func handler(client *opensearch.Client, w http.ResponseWriter, r *http.Request) {
	tenant := r.FormValue("tenant")
	body := "{\"query\":{\"term\":{\"tenant\":\"" + tenant + "\"}}}"
	client.DeleteByQuery([]string{"records"}, strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected destructive DSL-injection flow for FormValue -> opensearch DeleteByQuery body arg")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- opensearch-go: PutScript(id, body, ...) — persistent Painless RCE ---

func TestAnalyzeGo_OpenSearch_PutScript_PersistentRCE(t *testing.T) {
	code := `package main

import (
	"net/http"
	"strings"

	"github.com/opensearch-project/opensearch-go/opensearch"
)

func handler(client *opensearch.Client, w http.ResponseWriter, r *http.Request) {
	src := r.FormValue("painless")
	body := "{\"script\":{\"lang\":\"painless\",\"source\":\"" + src + "\"}}"
	client.PutScript("daily-rollup", strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected persistent-RCE flow for FormValue -> opensearch PutScript body arg")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative test: hardcoded literal body produces no flow ---

func TestAnalyzeGo_ElasticsearchV8_Bulk_HardcodedSafe(t *testing.T) {
	code := `package main

import (
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
)

func reindexAll(es *elasticsearch.Client) {
	body := "{\"index\":{\"_index\":\"records\"}}\n{\"name\":\"static\"}\n"
	es.Bulk(strings.NewReader(body))
}
`
	flows := AnalyzeGo(code, "/app/admin.go")
	for _, f := range flows {
		if f.Sink.ID == "go.elasticsearch.bulk" {
			t.Errorf("unexpected DSL flow on hardcoded literal: %+v", f)
		}
	}
}

// --- Negative test: same method name on a non-ES type must not match ---

func TestAnalyzeGo_BulkOnUnrelatedType_NoFlow(t *testing.T) {
	code := `package main

import "net/http"

type fakeBatcher struct{}

func (b *fakeBatcher) Bulk(body string) {}

func handler(b *fakeBatcher, w http.ResponseWriter, r *http.Request) {
	v := r.FormValue("v")
	b.Bulk(v)
}
`
	flows := AnalyzeGo(code, "/app/unrelated.go")
	for _, f := range flows {
		if f.Sink.ID == "go.elasticsearch.bulk" || f.Sink.ID == "go.opensearch.bulk" {
			t.Errorf("ES Bulk sink incorrectly matched a non-ES type: %+v", f)
		}
	}
}
