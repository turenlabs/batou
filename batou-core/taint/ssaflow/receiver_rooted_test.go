package ssaflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Register Go language catalog so source/sink lookups resolve.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestReceiverRooted_ConstructionFieldToSink is the headline companion case:
// a struct field is tainted at construction (h := &Handler{Q: r.FormValue})
// and a method (h.Process) reaches a sink through that exact field (h.Q).
// Before the receiver-rooted lane this emitted NOTHING — methods were never
// summarised and the receiver field was never tracked across the call.
func TestReceiverRooted_ConstructionFieldToSink(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

type Handler struct {
	Other string
	Q     string
}

func (h *Handler) Process() {
	db.Query(h.Q)
}

func Serve(r *http.Request) {
	h := &Handler{Q: r.FormValue("x")}
	h.Process()
}
`
	flows := AnalyzeGo(code, "/app/recv.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input → sql_query receiver-rooted flow, got %d flows: %+v", len(flows), flows)
	}
}

// TestReceiverRooted_FieldDiscrimination is the canonical no-FP sibling: the
// TAINTED value is stored into a DIFFERENT field than the one the sink reads.
// The match is field-sensitive, so this must NOT fire.
func TestReceiverRooted_FieldDiscrimination(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

type Handler struct {
	Tainted string
	Safe    string
}

func (h *Handler) Process() {
	db.Query(h.Safe)
}

func Serve(r *http.Request) {
	h := &Handler{Tainted: r.FormValue("x"), Safe: "constant"}
	h.Process()
}
`
	flows := AnalyzeGo(code, "/app/recv.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Fatalf("field discrimination failed: sink reads h.Safe (constant) but a SQL flow was emitted: %+v", f)
		}
	}
}

// TestReceiverRooted_NoSourceNoFlow: when the field is assigned a constant
// (no caller source flows into it), the lane must stay silent even though the
// method reaches a sink through that field.
func TestReceiverRooted_NoSourceNoFlow(t *testing.T) {
	code := `package main

import "database/sql"

var db *sql.DB

type Handler struct {
	Q string
}

func (h *Handler) Process() {
	db.Query(h.Q)
}

func Serve() {
	h := &Handler{Q: "select 1"}
	h.Process()
}
`
	flows := AnalyzeGo(code, "/app/recv.go")
	if hasAnyFlow(flows) {
		t.Fatalf("expected no flow for constant-assigned field, got %d: %+v", len(flows), flows)
	}
}

// TestReceiverRooted_SanitizerPrunes: a SQL-category sanitizer between the
// source and the stored field breaks the chain — no flow. regexp.QuoteMeta is
// catalogued as neutralizing SnkSQLQuery and returns a single string, so the
// construction-site walk's reaches() prune should cut the chain.
func TestReceiverRooted_SanitizerPrunes(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
	"regexp"
)

var db *sql.DB

type Handler struct {
	Q string
}

func (h *Handler) Process() {
	db.Query(h.Q)
}

func Serve(r *http.Request) {
	h := &Handler{Q: regexp.QuoteMeta(r.FormValue("x"))}
	h.Process()
}
`
	flows := AnalyzeGo(code, "/app/recv.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Fatalf("sanitizer prune failed: QuoteMeta'd value still produced a SQL flow: %+v", f)
		}
	}
}
