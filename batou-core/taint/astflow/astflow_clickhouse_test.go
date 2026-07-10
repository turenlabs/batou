package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// ClickHouse-go v2 native interface SQL injection (CWE-89) tests
//
// The v2 driver exposes a clickhouse.Conn (= driver.Conn) interface that
// is NOT routed through database/sql. Query-accepting methods take the
// SQL string directly, so string-concatenated user input is injectable.
// =========================================================================

func TestCatalogMatcher_ClickHouseSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sinks := cat.Sinks()
	matcher := NewCatalogMatcher(nil, sinks, nil, nil)

	expectedIDs := []string{
		"go.clickhouse.conn.query",
		"go.clickhouse.conn.queryrow",
		"go.clickhouse.conn.exec",
		"go.clickhouse.conn.select",
		"go.clickhouse.conn.preparebatch",
		"go.clickhouse.conn.asyncinsert",
	}

	found := map[string]bool{}
	for _, method := range []string{"Query", "QueryRow", "Exec", "Select", "PrepareBatch", "AsyncInsert"} {
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

func TestAnalyzeGo_ClickHouseConnQuery_SQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func handler(conn clickhouse.Conn, r *http.Request) {
	ctx := context.Background()
	userID := r.URL.Query().Get("id")
	stmt := "SELECT * FROM events WHERE user_id = '" + userID + "'"
	conn.Query(ctx, stmt)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.clickhouse.conn.query" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection flow for query param -> clickhouse.Conn.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_ClickHouseConnQueryRow_SQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func handler(conn clickhouse.Conn, r *http.Request) {
	ctx := context.Background()
	name := r.FormValue("name")
	stmt := "SELECT count() FROM users WHERE name = '" + name + "'"
	conn.QueryRow(ctx, stmt)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.clickhouse.conn.queryrow" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection flow for FormValue -> clickhouse.Conn.QueryRow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_ClickHouseConnExec_SQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func handler(conn clickhouse.Conn, r *http.Request) {
	ctx := context.Background()
	table := r.URL.Query().Get("table")
	stmt := "DROP TABLE " + table
	conn.Exec(ctx, stmt)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.clickhouse.conn.exec" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection flow for query param -> clickhouse.Conn.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_ClickHouseConnSelect_SQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/ClickHouse/clickhouse-go/v2"
)

type Row struct {
	ID   int
	Name string
}

func handler(conn clickhouse.Conn, r *http.Request) {
	ctx := context.Background()
	filter := r.URL.Query().Get("filter")
	var dest []Row
	stmt := "SELECT id, name FROM users WHERE name LIKE '%" + filter + "%'"
	conn.Select(ctx, &dest, stmt)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.clickhouse.conn.select" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection flow for query param -> clickhouse.Conn.Select")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_ClickHouseConnPrepareBatch_SQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func handler(conn clickhouse.Conn, r *http.Request) {
	ctx := context.Background()
	table := r.FormValue("table")
	stmt := "INSERT INTO " + table + " (id, name) VALUES"
	conn.PrepareBatch(ctx, stmt)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.clickhouse.conn.preparebatch" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection flow for FormValue -> clickhouse.Conn.PrepareBatch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_ClickHouseConnAsyncInsert_SQLInjection(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func handler(conn clickhouse.Conn, r *http.Request) {
	ctx := context.Background()
	name := r.URL.Query().Get("name")
	stmt := "INSERT INTO events VALUES ('" + name + "', now())"
	conn.AsyncInsert(ctx, stmt, false)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	found := false
	for _, f := range flows {
		if f.Sink.ID == "go.clickhouse.conn.asyncinsert" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection flow for query param -> clickhouse.Conn.AsyncInsert")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

func TestAnalyzeGo_ClickHouseConnQuery_Safe_Parameterized(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func handler(conn clickhouse.Conn, r *http.Request) {
	ctx := context.Background()
	userID := r.URL.Query().Get("id")
	// Safe: the query string is a compile-time constant; user input
	// flows only through the parameterized positional arg.
	conn.Query(ctx, "SELECT * FROM events WHERE user_id = $1", userID)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.ID == "go.clickhouse.conn.query" {
			t.Errorf("expected no SQL injection for parameterized query, got src=%s", f.Source.ID)
		}
	}
}
