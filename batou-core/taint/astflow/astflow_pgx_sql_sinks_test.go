package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Catalog registration: each new pgx raw-SQL sink is indexed under its method
// name as a SnkSQLQuery sink.
func TestCatalogMatcher_PgxSQLSinksRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	matcher := NewCatalogMatcher(nil, cat.Sinks(), nil, nil)

	// method -> at least one pgx ObjectType expected for that method.
	want := map[string][]string{
		"Exec":     {"*pgx.Conn", "*pgxpool.Pool", "pgx.Tx"},
		"Query":    {"*pgx.Conn", "*pgxpool.Pool", "pgx.Tx"},
		"QueryRow": {"*pgx.Conn", "*pgxpool.Pool", "pgx.Tx"},
		"Prepare":  {"*pgx.Conn", "pgx.Tx"},
		"Queue":    {"*pgx.Batch"},
	}
	for method, objTypes := range want {
		for _, ot := range objTypes {
			found := false
			for _, snk := range matcher.sinksByMethod[method] {
				if snk.Category == taint.SnkSQLQuery && snk.ObjectType == ot {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected pgx sink for method %q ObjectType %q to be registered", method, ot)
			}
		}
	}
}

// --- Positive flows: user input concatenated into the SQL string argument. ---

func TestAnalyzeGo_PgxConnQuery_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func handler(conn *pgx.Conn, r *http.Request) {
	name := r.FormValue("name")
	conn.Query(context.Background(), "SELECT * FROM users WHERE name = '"+name+"'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: r.FormValue -> pgx Conn.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PgxConnExec_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func handler(conn *pgx.Conn, r *http.Request) {
	id := r.URL.Query().Get("id")
	conn.Exec(context.Background(), "DELETE FROM users WHERE id = "+id)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: request query -> pgx Conn.Exec")
	}
}

func TestAnalyzeGo_PgxConnQueryRow_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func handler(conn *pgx.Conn, r *http.Request) {
	name := r.FormValue("name")
	conn.QueryRow(context.Background(), "SELECT id FROM users WHERE name = '"+name+"'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: r.FormValue -> pgx Conn.QueryRow")
	}
}

func TestAnalyzeGo_PgxConnPrepare_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func handler(conn *pgx.Conn, r *http.Request) {
	col := r.FormValue("col")
	conn.Prepare(context.Background(), "stmt1", "SELECT "+col+" FROM users")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: r.FormValue -> pgx Conn.Prepare (sql at arg 2)")
	}
}

func TestAnalyzeGo_PgxpoolPoolQuery_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

func handler(pool *pgxpool.Pool, r *http.Request) {
	name := r.FormValue("name")
	pool.Query(context.Background(), "SELECT * FROM users WHERE name = '"+name+"'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: r.FormValue -> pgxpool Pool.Query")
	}
}

func TestAnalyzeGo_PgxpoolPoolExec_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

func handler(pool *pgxpool.Pool, r *http.Request) {
	id := r.FormValue("id")
	pool.Exec(context.Background(), "DELETE FROM logs WHERE id = "+id)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: r.FormValue -> pgxpool Pool.Exec")
	}
}

func TestAnalyzeGo_PgxTxQuery_SQLi(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func handler(tx pgx.Tx, r *http.Request) {
	name := r.FormValue("name")
	tx.Query(context.Background(), "SELECT * FROM users WHERE name = '"+name+"'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: r.FormValue -> pgx Tx.Query")
	}
}

func TestAnalyzeGo_PgxBatchQueue_SQLi(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/jackc/pgx/v5"
)

func handler(batch *pgx.Batch, r *http.Request) {
	name := r.FormValue("name")
	batch.Queue("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: r.FormValue -> pgx Batch.Queue (sql at arg 0)")
	}
}

// --- Negative control: parameterized query keeps the SQL string constant, so
// user input flows only into a separate query parameter (arg 2) and must NOT be
// flagged. The dangerous arg for Conn/Pool/Tx methods is index 1 (the SQL text).
func TestAnalyzeGo_PgxParameterized_NoFlow(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func handler(conn *pgx.Conn, r *http.Request) {
	name := r.FormValue("name")
	conn.Query(context.Background(), "SELECT * FROM users WHERE name = $1", name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("parameterized pgx query (constant SQL, user input as $1 arg) must not be flagged")
	}
}
