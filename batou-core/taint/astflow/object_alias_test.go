package astflow

// Intra-function MUST-alias tests for the Go astflow engine.
//
// A straight `b := a` copy of a struct/pointer reference makes the two names
// interchangeable for shallow field reads/writes within the same function, so
// a field written through one name (`b.Field = src`) is observed through a
// field read on the other (`db.Exec(a.Field)`). The alias is MUST-alias:
// reassigning a name breaks its edge, and sibling fields stay clean.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func sqlFlowCountGo(flows []taint.TaintFlow) int {
	n := 0
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			n++
		}
	}
	return n
}

// Positive (the FN this fix closes): b := a; b.Q = src; db.Exec(a.Q).
func TestAnalyzeGo_ObjectAlias_FieldWriteThroughAlias_Detected(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

type State struct{ Q string }

func handler(w http.ResponseWriter, r *http.Request) {
	a := &State{}
	b := a
	b.Q = r.FormValue("x")
	db.Exec(a.Q)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for b:=a; b.Q=FormValue; db.Exec(a.Q) (object aliasing)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.Category, f.Sink.Category, f.SinkLine)
		}
	}
}

// Negative (must-alias precision): reassigning b breaks the alias, so a later
// b.Q write does not reflect on a.Q.
func TestAnalyzeGo_ObjectAlias_BrokenByReassignment_NoFlow(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

type State struct{ Q string }

func handler(w http.ResponseWriter, r *http.Request) {
	a := &State{}
	b := a
	b = other
	b.Q = r.FormValue("x")
	db.Exec(a.Q)
}

var other *State
var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if n := sqlFlowCountGo(flows); n != 0 {
		t.Errorf("did not expect SQL flow after `b = other` breaks the alias; got %d", n)
	}
}

// Negative (sibling precision): tainting b.Q must not taint a.Other.
func TestAnalyzeGo_ObjectAlias_SiblingField_NoFlow(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

type State struct {
	Q     string
	Other string
}

func handler(w http.ResponseWriter, r *http.Request) {
	a := &State{}
	b := a
	b.Q = r.FormValue("x")
	db.Exec(a.Other)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if n := sqlFlowCountGo(flows); n != 0 {
		t.Errorf("did not expect SQL flow on sibling field a.Other; got %d", n)
	}
}

// Over-clear soundness preserved: a := src; b := a; a = "safe"; db.Exec(b)
// still fires — breaking a's alias must not clear b's own copied taint.
func TestAnalyzeGo_ObjectAlias_OverClearStillFires(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	a := r.FormValue("x")
	b := a
	a = "safe"
	_ = a
	db.Exec(b)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL flow for a:=src; b:=a; a=safe; db.Exec(b) (over-clear must stay sound)")
	}
}
