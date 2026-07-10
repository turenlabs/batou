package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Couchbase gocb v2 N1QL / SQL++ injection (CWE-943) tests
//
// Couchbase's N1QL (now SQL++) is a SQL-like query language. The gocb v2
// driver (github.com/couchbase/gocb/v2) accepts a statement string as the
// first positional argument; user input must be passed via QueryOptions
// NamedParameters or PositionalParameters. Concatenating user input into
// the statement string is injectable. Real incidents include
// CVE-2019-9039 (Couchbase Sync Gateway) and GHSA-jfwg-rxf3-p7r9
// (authorizerdev's fmt.Sprintf-based N1QL/CQL builder).
// =========================================================================

func TestCatalogMatcher_CouchbaseSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sinks := cat.Sinks()
	matcher := NewCatalogMatcher(nil, sinks, nil, nil)

	expectedIDs := []string{
		"go.gocb.cluster.query",
		"go.gocb.cluster.analyticsquery",
		"go.gocb.scope.query",
		"go.gocb.scope.analyticsquery",
	}

	found := map[string]bool{}
	for _, method := range []string{"Query", "AnalyticsQuery"} {
		for _, s := range matcher.sinksByMethod[method] {
			found[s.ID] = true
		}
	}
	for _, id := range expectedIDs {
		if !found[id] {
			t.Errorf("expected sink %q to be indexed by method name", id)
		}
	}
}

func TestAnalyzeGo_CouchbaseClusterQuery_N1QLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/couchbase/gocb/v2"
)

func handler(cluster *gocb.Cluster, r *http.Request) {
	bucket := r.URL.Query().Get("bucket")
	stmt := "SELECT * FROM ` + "`" + `" + bucket + "` + "`" + ` WHERE active = true"
	cluster.Query(stmt, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.gocb.cluster.query" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected N1QL injection flow for query param -> *gocb.Cluster.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_CouchbaseClusterAnalyticsQuery_SQLppInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/couchbase/gocb/v2"
)

func handler(cluster *gocb.Cluster, r *http.Request) {
	dataset := r.FormValue("dataset")
	stmt := "SELECT count(*) FROM " + dataset
	cluster.AnalyticsQuery(stmt, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.gocb.cluster.analyticsquery" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL++ injection flow for FormValue -> *gocb.Cluster.AnalyticsQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_CouchbaseScopeQuery_N1QLInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/couchbase/gocb/v2"
)

func handler(scope *gocb.Scope, r *http.Request) {
	user := r.URL.Query().Get("user")
	stmt := "SELECT * FROM users WHERE name = '" + user + "'"
	scope.Query(stmt, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.gocb.scope.query" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected N1QL injection flow for query param -> *gocb.Scope.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_CouchbaseScopeAnalyticsQuery_SQLppInjection(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/couchbase/gocb/v2"
)

func handler(scope *gocb.Scope, r *http.Request) {
	filter := r.FormValue("filter")
	stmt := "SELECT * FROM events WHERE type = '" + filter + "'"
	scope.AnalyticsQuery(stmt, nil)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.gocb.scope.analyticsquery" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL++ injection flow for FormValue -> *gocb.Scope.AnalyticsQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_CouchbaseClusterQuery_Safe_Parameterized(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/couchbase/gocb/v2"
)

func handler(cluster *gocb.Cluster, r *http.Request) {
	user := r.URL.Query().Get("user")
	// Safe: statement is a literal; user input flows only through
	// QueryOptions.NamedParameters.
	cluster.Query("SELECT * FROM users WHERE name = $name",
		&gocb.QueryOptions{NamedParameters: map[string]interface{}{"name": user}})
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.gocb.cluster.query" {
			t.Errorf("expected no N1QL injection for parameterized query, got src=%s", f.Source.ID)
		}
	}
}
