package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
)

// Regression: an inline source call used directly as a sink argument, never
// bound to a variable, must propagate taint — exactly as the bound-variable
// sibling does. exprIsTainted's CallExpr case only inspected the call's own
// arguments and consulted the taint map; it never matched the call itself as a
// source, so `db.Query(r.FormValue("x"))` yielded zero flows while
// `x := r.FormValue("x"); db.Query(x)` fired.
func TestInlineSourceArg_DirectSink(t *testing.T) {
	code := `package main

import "net/http"
import "database/sql"

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	db.Query(r.FormValue("x"))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for db.Query(r.FormValue(x)); got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Bound-variable sibling (already worked pre-fix) — guards the canonical path
// the inline case mirrors.
func TestBoundSourceArg_DirectSink(t *testing.T) {
	code := `package main

import "net/http"
import "database/sql"

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	x := r.FormValue("x")
	db.Query(x)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for bound x := r.FormValue(x); db.Query(x); got %d flows", len(flows))
	}
}

// Inline source inside a struct-literal field, then the struct flows to a sink.
// Resolving the inline source here is what exposed (and required fixing) the
// validator-guard sanitizer gap covered by
// TestInlineValidatorGuard_TrustBoundary_Sanitized below.
func TestInlineSourceArg_StructLiteralField(t *testing.T) {
	code := `package main

import "net/http"
import "database/sql"

type Q struct{ Raw string }

func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	q := Q{Raw: r.FormValue("x")}
	db.Query(q.Raw)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQLi flow for Q{Raw: r.FormValue(x)} -> db.Query(q.Raw); got %d flows", len(flows))
	}
}

// Clean negative sibling: a constant argument must not produce a flow, so the
// inline-source resolution is not blanket-tainting every call argument.
func TestConstantArg_DirectSink_NoFlow(t *testing.T) {
	code := `package main

import "database/sql"

func handler(db *sql.DB) {
	db.Query("SELECT 1")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("constant arg should not produce a SQLi flow")
	}
}

// Validator-guard sanitizer in an if-init clause clears the validated value's
// taint. `if err := validate.Struct(input); err != nil { return }` fail-closes,
// so `input` is validated for all code after the guard. Before the inline-source
// fix, this passed for the WRONG reason (the struct field was never tainted);
// the fix makes `input` tainted, requiring the guard to genuinely sanitize it.
func TestInlineValidatorGuard_TrustBoundary_Sanitized(t *testing.T) {
	code := `package main

import (
	"context"
	"net/http"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

type UserInput struct {
	Name string
}

func handler(w http.ResponseWriter, r *http.Request) {
	input := UserInput{Name: r.FormValue("name")}
	if err := validate.Struct(input); err != nil {
		return
	}
	ctx := context.WithValue(r.Context(), "input", input)
	_ = ctx
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust_boundary flow: validate.Struct guard sanitizes input before context.WithValue")
		}
	}
}
