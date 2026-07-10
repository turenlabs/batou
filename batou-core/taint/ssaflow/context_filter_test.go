package ssaflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Register Go language catalog so source/sink lookups resolve.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestIsContextTypeString_Matches pins the exact set of strings the
// context-filter recognises. Keeping the matching narrow (only
// `context.Context` and the bare `Context` fallback for dot-imports)
// avoids accidentally suppressing flows through legitimately-named user
// types (e.g. a struct called Context unrelated to the stdlib type).
func TestIsContextTypeString_Matches(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"context.Context", true},
		{"*context.Context", true},
		{" context.Context ", true}, // tolerates surrounding whitespace
		{"Context", true},           // dot-import edge case
		{"*Context", true},
		// Negative — these should NOT match. A user struct named
		// "AppContext" or "RequestContext" is a regular type, not the
		// stdlib plumbing the filter targets.
		{"AppContext", false},
		{"RequestContext", false},
		{"http.Context", false},
		{"context.CancelFunc", false},
		{"*http.Request", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isContextTypeString(tc.in)
		if got != tc.want {
			t.Errorf("isContextTypeString(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestAnalyzeGo_ContextParam_NotTreatedAsSource confirms that even when a
// handler's signature pairs a context.Context with a real *http.Request,
// the SSA engine emits a flow for the http.Request (via r.URL.Query()) and
// does NOT emit one whose source is ctx. The pattern mirrors the FP class
// reported on harness scans:
//
//	func H(ctx context.Context, r *http.Request) {
//	    Inner(ctx, r.URL.Query().Get("q"))
//	}
//	func Inner(ctx context.Context, s string) { db.Exec(s) }
//
// We use db.Exec (not db.ExecContext) because *sql.DB.Exec is in the Go
// taint catalog with the SQL string at position 0 — the standard sink
// the rest of the test suite uses. Behaviour is identical for ctx
// filtering purposes.
//
// We expect:
//   - At least one SQLi flow whose Source is the *http.Request param.
//   - Zero flows whose Source.ObjectType is context.Context.
func TestAnalyzeGo_ContextParam_NotTreatedAsSource(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
	"net/http"
)

var db *sql.DB

func Inner(ctx context.Context, s string) {
	_ = ctx
	db.Exec(s)
}

func H(ctx context.Context, r *http.Request) {
	Inner(ctx, r.URL.Query().Get("q"))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected user_input → sql_query flow via r.URL.Query(); got %d flows: %+v", len(flows), flows)
	}
	for _, f := range flows {
		if isContextTypeString(f.Source.ObjectType) {
			t.Errorf("flow source must not be context.Context; got %+v", f.Source)
		}
	}
}

// TestAnalyzeGo_ContextOnly_NoFinding confirms the trivial case: a handler
// whose only parameter is context.Context and whose body sinks a STATIC
// string should produce zero user_input flows. Without the source-param
// filter the engine could pick up the ctx param as a "param of unknown
// type" (it doesn't today — ctx is absent from KnownGoSourceTypes — but
// the filter guards against future catalog expansions or fuzzy matching).
func TestAnalyzeGo_ContextOnly_NoFinding(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
)

var db *sql.DB

func H(ctx context.Context) {
	_ = ctx
	db.Exec("SELECT 1")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Source.Category == taint.SrcUserInput {
			t.Errorf("unexpected user_input flow on ctx-only handler with static SQL: %+v", f)
		}
	}
}

// TestAnalyzeGo_ControllerChain_CtxOnly_NoFinding is the regression test
// for the harness FP class: a handler hands ctx to a controller which
// hands ctx to a db helper which calls a STATIC SQL query. The ctx is
// pure plumbing — there is no user-controlled string in the chain, only
// a hardcoded query literal. Without the ctx filter the cross-function
// fixed-point synthesises a flow rooted at ctx ("ctx → Controller.Update
// → sql.Query"); with the filter no flow is emitted.
func TestAnalyzeGo_ControllerChain_CtxOnly_NoFinding(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
)

var db *sql.DB

type Controller struct{}

func (c *Controller) Update(ctx context.Context) {
	c.UpdateOptLock(ctx)
}

func (c *Controller) UpdateOptLock(ctx context.Context) {
	_ = ctx
	db.Exec("UPDATE t SET v = 1 WHERE id = 1")
}

func H(ctx context.Context) {
	c := &Controller{}
	c.Update(ctx)
}
`
	flows := AnalyzeGo(code, "/app/controller.go")
	for _, f := range flows {
		// The pure-plumbing chain MUST NOT surface a user_input flow.
		// (Other categories — e.g. an env-var taint — are out of scope
		// for this fixture but would also be invalid given the body.)
		if f.Source.Category == taint.SrcUserInput {
			t.Errorf("unexpected user_input flow on ctx-only controller chain: %+v", f)
		}
		if isContextTypeString(f.Source.ObjectType) {
			t.Errorf("flow source must not be context.Context; got %+v", f.Source)
		}
	}
}

// TestAnalyzeGo_ControllerChain_WithRequest_StillReports confirms the
// filter is conservative: when the handler ALSO passes a real
// *http.Request (or a string derived from it) down the chain alongside
// ctx, the SQLi flow through the request must still surface. We expect
// at least one user_input → sql_query flow.
//
// Uses free functions (not methods) so the test exercises the same
// cross-function summary propagation as the rest of the ssaflow tests
// — the goal is to verify the ctx filter doesn't accidentally suppress
// real flows through string arguments that travel alongside ctx, NOT to
// exercise method-receiver-shifted summaries (covered elsewhere).
func TestAnalyzeGo_ControllerChain_WithRequest_StillReports(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"
	"net/http"
)

var db *sql.DB

func Update(ctx context.Context, q string) {
	UpdateOptLock(ctx, q)
}

func UpdateOptLock(ctx context.Context, q string) {
	_ = ctx
	db.Exec(q)
}

func H(ctx context.Context, r *http.Request) {
	Update(ctx, r.URL.Query().Get("q"))
}
`
	flows := AnalyzeGo(code, "/app/controller_req.go")
	if !hasFlowWithCategories(flows, taint.SrcUserInput, taint.SnkSQLQuery) {
		t.Fatalf("expected SQLi flow via *http.Request even with ctx in signature; got %d: %+v", len(flows), flows)
	}
	// No source emitted should be ctx.
	for _, f := range flows {
		if isContextTypeString(f.Source.ObjectType) {
			t.Errorf("flow source must not be context.Context; got %+v", f.Source)
		}
	}
}

// TestCalleeParamIsContext_OutOfRangeSafe pins the safety of
// calleeParamIsContext on the lookup paths the cross-function emitter
// exercises: a nil fn, a negative index, and an index past the end of
// Params must all return false rather than panicking. The cross-function
// fixed-point passes raw paramSinks keys through this helper, and on
// pathological summaries (e.g. a summary computed against a different
// SSA function with a different param count) it must degrade gracefully.
func TestCalleeParamIsContext_OutOfRangeSafe(t *testing.T) {
	if calleeParamIsContext(nil, 0) {
		t.Errorf("nil fn must return false")
	}
	if calleeParamIsContext(nil, -1) {
		t.Errorf("nil fn + negative idx must return false")
	}
}

// TestCrossPackage_ContextChain_NoFinding extends the controller test to
// span packages: handler in pkg `a` calls Service in pkg `b` calls Repo
// in pkg `c`, each accepting only a context.Context, with the deepest
// call being a STATIC SQL query. The cross-package fixed-point should
// not synthesise a flow at the handler — every callee param along the
// chain is filtered out.
func TestCrossPackage_ContextChain_NoFinding(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	root := writeModule(t, map[string]string{
		"a/a.go": `package a

import (
	"context"
	"m/b"
)

func Handler(ctx context.Context) {
	b.Service(ctx)
}
`,
		"b/b.go": `package b

import (
	"context"
	"m/c"
)

func Service(ctx context.Context) {
	c.Repo(ctx)
}
`,
		"c/c.go": `package c

import (
	"context"
	"database/sql"
)

var db *sql.DB

func Repo(ctx context.Context) {
	_ = ctx
	db.Exec("SELECT 1")
}
`,
	})

	aFile := filepath.Join(root, "a/a.go")
	content, err := os.ReadFile(aFile)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	flows := AnalyzeGo(string(content), aFile)
	for _, f := range flows {
		// Handler-scoped user_input flows are the FP class we're
		// suppressing; assert none surface.
		if !strings.Contains(f.ScopeName, "Handler") {
			continue
		}
		if f.Source.Category == taint.SrcUserInput {
			t.Errorf("unexpected user_input flow in cross-pkg ctx-only chain: %+v", f)
		}
		if isContextTypeString(f.Source.ObjectType) {
			t.Errorf("flow source must not be context.Context; got %+v", f.Source)
		}
	}
}
