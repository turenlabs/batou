package ssaflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// field_forward_test.go is the permanent regression suite for store-to-load
// forwarding through local aggregates and same-function globals
// (field_forward.go). The SSA lifter cannot promote address-taken aggregates
// to registers (go/ssa lift.go:liftAlloc bails on any FieldAddr/IndexAddr
// referrer), so without this forwarding the def-use walkers silently drop all
// memory-resident taint. Each test pins a construct that used to be UNSOUND
// (FN: a real flow was dropped) alongside its clean sibling that must stay
// silent (no FP introduced by the over-approximation).

// TestFieldForward_StructFieldTaintFlows: o.F = src ; sink(o.F) must fire.
// This is the canonical field-sensitivity FN that motivated the fix.
func TestFieldForward_StructFieldTaintFlows(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

type O struct {
	F string
	G string
}

func H(r *http.Request) {
	var o O
	o.F = r.URL.Query().Get("q")
	o.G = "safe"
	db.Exec(o.F)
}
`
	flows := AnalyzeGo(code, "/app/field.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input -> sql_query through tainted struct field o.F, got %d flows: %+v", len(flows), flows)
	}
}

// TestFieldForward_CleanFieldSiblingNoFP: o.G = src ; o.F = "safe" ; sink(o.F).
// The sink reads the CLEAN field. Field discrimination must keep this silent —
// the taint on o.G must not bleed into o.F. This is the precision sibling that
// proves the forwarding is field-sensitive, not whole-struct.
func TestFieldForward_CleanFieldSiblingNoFP(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

type O struct {
	F string
	G string
}

func H(r *http.Request) {
	var o O
	o.G = r.URL.Query().Get("q")
	o.F = "safe"
	db.Exec(o.F)
}
`
	flows := AnalyzeGo(code, "/app/clean.go")
	if hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("FALSE POSITIVE: o.G tainted but sink reads clean field o.F; got flows: %+v", flows)
	}
}

// TestFieldForward_ArrayElementTaintFlows: a[0] = src ; sink(a[0]) must fire.
// Index access is index-INSENSITIVE (whole-container), matching the
// documented whole-pointee model in pointer_arg.go.
func TestFieldForward_ArrayElementTaintFlows(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func H(r *http.Request) {
	var a [2]string
	a[0] = r.URL.Query().Get("q")
	db.Exec(a[0])
}
`
	flows := AnalyzeGo(code, "/app/arr.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input -> sql_query through tainted array element a[0], got %d flows: %+v", len(flows), flows)
	}
}

// TestFieldForward_SameFunctionGlobalFlows: a package-level global written
// from a source and read into a sink within the SAME function must fire.
// (Cross-function global flow is a separate, summary-driven concern and is
// intentionally NOT covered here — see TestFieldForward_CrossFnGlobalNoIntra.)
func TestFieldForward_SameFunctionGlobalFlows(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB
var stash string

func H(r *http.Request) {
	stash = r.URL.Query().Get("q")
	db.Exec(stash)
}
`
	flows := AnalyzeGo(code, "/app/glob.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input -> sql_query through same-function global stash, got %d flows: %+v", len(flows), flows)
	}
}

// TestFieldForward_ConstFieldNoFP: a struct field assigned ONLY a constant and
// read into a sink must stay silent. Confirms the forwarding does not invent
// taint where none exists (the stored value is an untaintable const and the
// walker terminates).
func TestFieldForward_ConstFieldNoFP(t *testing.T) {
	code := `package main

import "database/sql"

var db *sql.DB

type O struct {
	F string
}

func H() {
	var o O
	o.F = "literal"
	db.Exec(o.F)
}
`
	flows := AnalyzeGo(code, "/app/const.go")
	if hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("FALSE POSITIVE: const-only struct field surfaced as taint; got flows: %+v", flows)
	}
}

// TestFieldForward_RegisterOnlyStillFires guards against a regression where
// store-forwarding accidentally short-circuits the original register-resident
// def-use walk. The canonical r.URL.Query().Get(...) -> db.Exec(...) flow has
// no aggregate memory at all; it must keep firing exactly as before.
func TestFieldForward_RegisterOnlyStillFires(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func H(r *http.Request) {
	db.Exec(r.URL.Query().Get("q"))
}
`
	flows := AnalyzeGo(code, "/app/reg.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("REGRESSION: register-only flow no longer fires; got %d flows: %+v", len(flows), flows)
	}
}

// TestFieldForward_DistinctLocalsNoFP: taint stored into one local struct must
// not forward into a load off a DIFFERENT local struct of the same type. Root
// identity (the Alloc) discriminates them.
func TestFieldForward_DistinctLocalsNoFP(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

type O struct {
	F string
}

func H(r *http.Request) {
	var a O
	var b O
	a.F = r.URL.Query().Get("q")
	b.F = "safe"
	db.Exec(b.F)
}
`
	flows := AnalyzeGo(code, "/app/two.go")
	if hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("FALSE POSITIVE: taint on local a.F bled into distinct local b.F; got flows: %+v", flows)
	}
}
