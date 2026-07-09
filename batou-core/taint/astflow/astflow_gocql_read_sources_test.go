package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Catalog registration: each new gocql (Cassandra/ScyllaDB) read source is
// indexed under its method name as a SrcDatabase second-order read.
func TestCatalogMatcher_GocqlReadSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	matcher := NewCatalogMatcher(cat.Sources(), nil, nil, nil)

	for _, id := range []string{
		"go.gocql.iter.scan",
		"go.gocql.iter.mapscan",
		"go.gocql.iter.slicemap",
		"go.gocql.query.scan",
		"go.gocql.query.mapscan",
	} {
		found := false
		for _, srcs := range matcher.sourcesByMethod {
			for _, src := range srcs {
				if src.ID == id && src.Category == taint.SrcDatabase {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("expected %q to be indexed as a SrcDatabase (gocql read) source", id)
		}
	}
}

// End-to-end second-order flow tests: gocql read → SQL query.
// Reads are captured as return values (matching the database/sql rows.Scan
// catalog convention) and flow into a separate SQL sink.

func TestAnalyzeGo_GocqlIterScan_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/gocql/gocql"
)

func handler(session *gocql.Session, db *sql.DB) {
	iter := session.Query("SELECT name FROM users").Iter()
	name := iter.Scan()
	db.Query("SELECT * FROM logs WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: gocql Iter.Scan → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDatabase) {
		t.Error("expected source category to be SrcDatabase")
	}
}

func TestAnalyzeGo_GocqlIterMapScan_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/gocql/gocql"
)

func handler(session *gocql.Session, db *sql.DB) {
	iter := session.Query("SELECT * FROM users").Iter()
	row := iter.MapScan()
	db.Query("SELECT * FROM logs WHERE name = '" + row + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: gocql Iter.MapScan → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_GocqlIterSliceMap_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/gocql/gocql"
)

func handler(session *gocql.Session, db *sql.DB) {
	iter := session.Query("SELECT * FROM users").Iter()
	rows := iter.SliceMap()
	db.Query("SELECT * FROM logs WHERE name = '" + rows + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: gocql Iter.SliceMap → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_GocqlQueryScan_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/gocql/gocql"
)

func handler(session *gocql.Session, db *sql.DB) {
	query := session.Query("SELECT name FROM users WHERE id = ?", 1)
	name := query.Scan()
	db.Query("SELECT * FROM logs WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: gocql Query.Scan → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_GocqlQueryMapScan_SecondOrderSQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/gocql/gocql"
)

func handler(session *gocql.Session, db *sql.DB) {
	query := session.Query("SELECT * FROM users WHERE id = ?", 1)
	row := query.MapScan()
	db.Query("SELECT * FROM logs WHERE name = '" + row + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected second-order SQL injection: gocql Query.MapScan → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative test: a hardcoded literal must NOT produce a SrcDatabase flow.
// Guards against the new gocql entries being too broad.
func TestAnalyzeGo_GocqlRead_Safe_Literal(t *testing.T) {
	code := `package main

import "database/sql"

func handler(db *sql.DB) {
	name := "hardcoded_value"
	db.Query("SELECT * FROM logs WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Source.Category == taint.SrcDatabase {
			t.Errorf("should not detect SrcDatabase source on literal-only code; got %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative test: receiver-name scoping — a Scan() on an unrelated receiver name
// (not iter/it/query/q and not a known DB receiver) must NOT match gocql.
func TestAnalyzeGo_GocqlRead_ReceiverScope(t *testing.T) {
	code := `package main

import "database/sql"

func handler(other *something, db *sql.DB) {
	name := other.Scan()
	db.Query("SELECT * FROM logs WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Source.ID == "go.gocql.iter.scan" || f.Source.ID == "go.gocql.query.scan" {
			t.Errorf("gocql Scan source should not fire on unrelated receiver name; got %s", f.Source.ID)
		}
	}
}
