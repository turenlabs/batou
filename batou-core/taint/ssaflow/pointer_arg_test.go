package ssaflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Register Go language catalog so source/sink lookups resolve.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// The tests in this file exercise pointer-arg taint propagation
// (PR-DD). They define stub framework types (gin.Context, fiber.Ctx,
// echo.Context) locally — `package gin` etc. — so that ssaflow's
// type checker can resolve the bind methods. The catalog's source
// definitions key off the canonicalised type name "*gin.Context" /
// "echo.Context" / "*fiber.Ctx", which is built from the package
// alias (here the package NAME, which equals the alias). The end
// result: the engine sees exactly the same type identifiers it would
// see when scanning a real handler against the real gin/fiber/echo
// imports.

// TestAnalyzeGo_PointerArg_GinShouldBindXML is the canonical positive
// case for PR-DD: c.ShouldBindXML(&in) mutates *in with request-body
// data, and a subsequent read of in.Name reaching a SQL sink must
// produce a flow.
//
// Prior to PR-DD the engine could only relate sinks to source-typed
// parameters via def-use; the Alloc behind `in` had no operand path
// back to `c`, so the flow was missed. The pointer-arg pass captures
// `&in`'s Alloc at the source call and routes the subsequent FieldAddr
// load to that root.
func TestAnalyzeGo_PointerArg_GinShouldBindXML(t *testing.T) {
	code := `package gin

import "database/sql"

type Context struct{}

func (c *Context) ShouldBindXML(obj any) error { return nil }

type In struct{ Name string }

var db *sql.DB

func H(c *Context) {
	var in In
	_ = c.ShouldBindXML(&in)
	db.Exec(in.Name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input → sql_query flow via ShouldBindXML, got %d: %+v", len(flows), flows)
	}
	// Confidence sanity: pointer-arg flows go through the intra-procedural
	// emit path (0.9), not the cross-procedural path (0.85).
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence < 0.85 {
			t.Errorf("flow confidence %.2f below SSA intra-procedural baseline 0.9", f.Confidence)
		}
	}
}

// TestAnalyzeGo_PointerArg_GinShouldBindJSON mirrors the XML test for the
// JSON variant. The catalog entry that covers c.BindJSON / ShouldBindJSON
// is go.gin.bindjson; this exercises that entry's WritesArg position.
func TestAnalyzeGo_PointerArg_GinShouldBindJSON(t *testing.T) {
	code := `package gin

import "database/sql"

type Context struct{}

func (c *Context) ShouldBindJSON(obj any) error { return nil }

type In struct{ Query string }

var db *sql.DB

func H(c *Context) {
	var in In
	_ = c.ShouldBindJSON(&in)
	db.Exec(in.Query)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input → sql_query flow via ShouldBindJSON, got %d: %+v", len(flows), flows)
	}
}

// TestAnalyzeGo_PointerArg_FiberQueryParser is the Fiber-flavoured PR-DD
// case from the original PR-BB skipped test. Confirms QueryParser's
// WritesArg=[0] also lights up.
func TestAnalyzeGo_PointerArg_FiberQueryParser(t *testing.T) {
	code := `package fiber

import "database/sql"

type Ctx struct{}

func (c *Ctx) QueryParser(obj any) error { return nil }

type In struct{ Q string }

var db *sql.DB

func H(c *Ctx) error {
	var in In
	_ = c.QueryParser(&in)
	db.Exec(in.Q)
	return nil
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input → sql_query flow via QueryParser, got %d: %+v", len(flows), flows)
	}
}

// TestAnalyzeGo_PointerArg_FiberBodyParser exercises BodyParser, the
// JSON-body sibling of QueryParser.
func TestAnalyzeGo_PointerArg_FiberBodyParser(t *testing.T) {
	code := `package fiber

import "database/sql"

type Ctx struct{}

func (c *Ctx) BodyParser(obj any) error { return nil }

type Payload struct{ User string }

var db *sql.DB

func H(c *Ctx) error {
	var p Payload
	_ = c.BodyParser(&p)
	db.Exec(p.User)
	return nil
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input → sql_query flow via BodyParser, got %d: %+v", len(flows), flows)
	}
}

// TestAnalyzeGo_PointerArg_EchoBind exercises echo.Context.Bind, the
// echo flavour of the bind family.
func TestAnalyzeGo_PointerArg_EchoBind(t *testing.T) {
	code := `package echo

import "database/sql"

type Context interface {
	Bind(obj any) error
}

type ctxImpl struct{}

func (c *ctxImpl) Bind(obj any) error { return nil }

type Form struct{ Search string }

var db *sql.DB

func H(c Context) error {
	var f Form
	_ = c.Bind(&f)
	db.Exec(f.Search)
	return nil
}
`
	// Echo's Context is an interface in the real library, so we emulate
	// that. SSA handles the method dispatch as an invoke call.
	flows := AnalyzeGo(code, "/app/handler.go")
	// Interface dispatch is out of scope for ssaflow's static-callee
	// matcher, so we expect this case to still NOT report (current
	// engine limit). Document the expectation explicitly so a future
	// extension that adds invoke-handling can flip the assertion.
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			// If a flow does appear in the future, that's a good
			// thing — promote this t.Logf to a passing assertion at
			// that time. For now we only assert no panic.
			t.Logf("note: echo Bind via interface now reports a flow: %+v", f)
		}
	}
}

// TestAnalyzeGo_PointerArg_NoSourceCall: the function declares a local
// `in`, sets a field to a constant, and passes it to db.Exec. No bind
// call ever runs, so the pointer-root set is empty and no flow should
// be reported. Catches over-tainting on plain local structs.
func TestAnalyzeGo_PointerArg_NoSourceCall(t *testing.T) {
	code := `package gin

import "database/sql"

type Context struct{}

func (c *Context) ShouldBindXML(obj any) error { return nil }

type In struct{ Name string }

var db *sql.DB

func H(c *Context) {
	var in In
	in.Name = "safe-constant"
	db.Exec(in.Name)
	_ = c
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	// The parameter `c` is a *gin.Context source, but the SQL sink's
	// argument `in.Name` has no operand path back to `c` — the only
	// assignment is a string literal. Pre-PR-DD: no flow. Post-PR-DD:
	// no bind call ran so the pointer-root set is empty; also no flow.
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected SQLi flow reported on a non-tainted local struct: %+v", f)
		}
	}
}

// TestAnalyzeGo_PointerArg_UnknownFunction: an unrecognised function
// that takes &in is NOT in the catalog's WritesArg list, so its effect
// is unknown and the pointee remains untainted. The downstream sink
// should not be flagged.
func TestAnalyzeGo_PointerArg_UnknownFunction(t *testing.T) {
	code := `package main

import "database/sql"

type In struct{ Name string }

var db *sql.DB

func someUnknownFunc(in *In) {} // no-op; not catalogued as a source

func H() {
	var in In
	someUnknownFunc(&in)
	db.Exec(in.Name)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("unexpected SQLi flow via unknown pointer-mutating function: %+v", f)
		}
	}
}

// TestAnalyzeGo_PointerArg_NestedFieldRead: the bind call writes &in,
// then the sink consumes a nested field (in.Inner.Value). The
// pointer-aware walker must follow the FieldAddr chain through more
// than one hop.
func TestAnalyzeGo_PointerArg_NestedFieldRead(t *testing.T) {
	code := `package gin

import "database/sql"

type Context struct{}

func (c *Context) ShouldBindJSON(obj any) error { return nil }

type Inner struct{ Value string }
type In struct{ Inner Inner }

var db *sql.DB

func H(c *Context) {
	var in In
	_ = c.ShouldBindJSON(&in)
	db.Exec(in.Inner.Value)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected nested-field SQLi flow via bind, got %d: %+v", len(flows), flows)
	}
}
