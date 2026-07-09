package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks/sanitizers are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestAnalyzeGo_FieldSensitive_TaintThroughStructField verifies that taint
// flowing through a struct field reaches a sink. Without shallow field-
// sensitive tracking the engine would not see `s.QueryStr` as a distinct
// taint key — this is the FN this PR closes.
//
//	s.QueryStr = r.FormValue("x")  // taint -> "s.QueryStr"
//	db.Exec(s.QueryStr)            // sink reads "s.QueryStr" -> report
func TestAnalyzeGo_FieldSensitive_TaintThroughStructField(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

type State struct {
	QueryStr string
}

func handler(w http.ResponseWriter, r *http.Request) {
	var s State
	s.QueryStr = r.FormValue("x")
	db.Exec(s.QueryStr)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for FormValue -> s.QueryStr -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.Category, f.Sink.Category, f.SinkLine)
		}
	}
}

// TestAnalyzeGo_FieldSensitive_SafeField verifies that assigning a hardcoded
// literal to a struct field does not produce a taint flow when that field is
// later passed to a sink.
//
//	s.SafeStr = "hardcoded"   // no taint
//	db.Exec(s.SafeStr)        // no taint -> no report
func TestAnalyzeGo_FieldSensitive_SafeField(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

type State struct {
	SafeStr string
}

func handler(w http.ResponseWriter, r *http.Request) {
	var s State
	s.SafeStr = "hardcoded"
	db.Exec(s.SafeStr)
	_ = r
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SQL injection flow for hardcoded literal -> s.SafeStr -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.Category, f.Sink.Category, f.SinkLine)
		}
	}
}

// TestAnalyzeGo_FieldSensitive_PlainIdentRegression guards against a
// regression of the existing whole-variable behaviour. Direct assignment
// of a tainted source to a plain identifier (no field) must still be
// detected as it was before this PR.
//
//	s := r.FormValue("x")
//	db.Exec(s)
func TestAnalyzeGo_FieldSensitive_PlainIdentRegression(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	s := r.FormValue("x")
	db.Exec(s)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for FormValue -> s -> db.Exec (no-field regression)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.Category, f.Sink.Category, f.SinkLine)
		}
	}
}

// TestAnalyzeGo_FieldSensitive_DifferentFieldNoReport verifies that taint on
// one struct's field does NOT leak across to a different object reading a
// different (safe) field.
//
//	s.QueryStr = r.FormValue("x")   // taint -> "s.QueryStr"
//	other.Field = ""                // no taint on "other.Field"
//	db.Exec(other.Field)            // read "other.Field" -> no taint -> no report
//
// Note: AnyFieldTainted for a bare ident read would conservatively flag the
// whole object, but here the sink read is `other.Field` (a specific field).
// The lookup is "other.Field" (clean) -> falls back to "other" (clean).
// `s.QueryStr` belongs to a different object, so no report.
func TestAnalyzeGo_FieldSensitive_DifferentFieldNoReport(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

type State struct {
	QueryStr string
}

type Other struct {
	Field string
}

func handler(w http.ResponseWriter, r *http.Request) {
	var s State
	var other Other
	s.QueryStr = r.FormValue("x")
	other.Field = ""
	db.Exec(other.Field)
	_ = s
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SQL injection flow — taint is on s.QueryStr but sink reads other.Field")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.Category, f.Sink.Category, f.SinkLine)
		}
	}
}
