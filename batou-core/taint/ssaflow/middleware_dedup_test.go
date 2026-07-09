package ssaflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Register Go language catalog so source/sink lookups resolve.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestMiddlewareChain_SameSourceDedupes is the Bug 2 fixture, refined
// in PR-OO. The original PR-NN test asserted "5 middleware layers → 1
// cross-flow" by collapsing on (sink, sourceCategory). That was too
// aggressive: each layer has its own *http.Request parameter (a
// genuinely distinct entry point at a distinct file:line), so each is
// independently meaningful and the recall-loss it caused on real
// repos (env-ON sig-propagation dropped from 14612 sinks lifted to
// ~78) showed up across the harness scan.
//
// Under PR-OO the dedup keys on (deepSink, sinkCategory, sinkMethod,
// sourceFile, sourceLine, sourceCategory). So a single layer that
// calls the next layer TWICE (same source param, same downstream
// sink) still collapses to one finding, but distinct entry-point
// functions don't.
//
// We use the single-package, same-file shape so the test runs against
// analyzePackageCrossFunction (not the module-wide path) — both code
// paths share the same dedup helper (seenDeep + newCrossSinkKey), so
// a contract pinned here also covers crosspackage.
func TestMiddlewareChain_SameSourceDedupes(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

// Bottom of the chain — the catalog sink.
func Handler(r *http.Request) {
	db.Exec(r.URL.Query().Get("q"))
}

// Single middleware that calls Handler twice from the SAME source param.
// Both call sites share (sourceFile, sourceLine), so the dedup MUST
// collapse them to one cross-flow.
func Middleware(r *http.Request) {
	Handler(r)
	Handler(r)
}
`
	flows := AnalyzeGo(code, "/app/middleware.go")

	// Count cross-function flows whose scope is Middleware. Two calls
	// to Handler from the same param ought to collapse to one.
	crossCount := 0
	for _, f := range flows {
		if !strings.Contains(f.ScopeName, "Middleware") {
			continue
		}
		for _, st := range f.Steps {
			if strings.HasPrefix(st.Description, "calls ") {
				crossCount++
				break
			}
		}
	}
	if crossCount != 1 {
		t.Errorf("expected exactly 1 cross-function flow from Middleware (same source, same sink), got %d. flows=%+v",
			crossCount, flows)
	}

	// Sanity: the intra-procedural flow inside Handler is still emitted.
	var sawIntra bool
	for _, f := range flows {
		if !strings.Contains(f.ScopeName, "Handler") {
			continue
		}
		hasCallsStep := false
		for _, st := range f.Steps {
			if strings.HasPrefix(st.Description, "calls ") {
				hasCallsStep = true
				break
			}
		}
		if !hasCallsStep && f.Source.Category == taint.SrcUserInput && f.Sink.Category == taint.SnkSQLQuery {
			sawIntra = true
			break
		}
	}
	if !sawIntra {
		t.Errorf("expected intra-procedural SQLi flow inside Handler to remain; flows=%+v", flows)
	}
}

// TestMiddlewareChain_DistinctSourcesKeepAllFlows pins the recall side
// of PR-OO's fix. Each middleware function has its own
// *http.Request parameter at a distinct source line, so the new wider
// dedup key (which includes sourceFile + sourceLine) MUST keep each
// layer's cross-flow separate. PR-NN collapsed them all to one,
// causing the env-ON sig-propagation regression this PR addresses.
func TestMiddlewareChain_DistinctSourcesKeepAllFlows(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func Handler(r *http.Request) {
	db.Exec(r.URL.Query().Get("q"))
}

// 5 layers of transparent middleware. Each layer's r is a distinct
// source param (distinct line) — distinct entry points that may be
// independently exposed by a router. Each must produce its own
// cross-flow.
func M1(r *http.Request) { M2(r) }
func M2(r *http.Request) { M3(r) }
func M3(r *http.Request) { M4(r) }
func M4(r *http.Request) { M5(r) }
func M5(r *http.Request) { Handler(r) }
`
	flows := AnalyzeGo(code, "/app/middleware.go")

	crossCount := 0
	for _, f := range flows {
		for _, st := range f.Steps {
			if strings.HasPrefix(st.Description, "calls ") {
				crossCount++
				break
			}
		}
	}
	// Expect at least one cross-flow per middleware layer (5). The
	// emitter may also produce a transitive flow at M1 etc.; we use >=
	// to keep the assertion focused on "no collapse", not on the exact
	// rendering shape.
	if crossCount < 5 {
		t.Errorf("expected >=5 cross-function flows across 5 distinct middleware sources, got %d. flows=%+v",
			crossCount, flows)
	}
}

// TestMiddlewareChain_DifferentDeepSinksKeepBothFlows confirms the
// dedup is SCOPED to the same leaf sink — two genuinely distinct sinks
// reached from the same source via different paths still produce
// separate findings. This guards against an over-zealous dedup that
// would hide real second-class vulnerabilities.
func TestMiddlewareChain_DifferentDeepSinksKeepBothFlows(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

var db *sql.DB

func Sink1(r *http.Request) {
	db.Exec(r.URL.Query().Get("q"))
}

func Sink2(r *http.Request) {
	_ = exec.Command(r.URL.Query().Get("q"))
}

func HandlerA(r *http.Request) { Sink1(r) }
func HandlerB(r *http.Request) { Sink2(r) }
`
	flows := AnalyzeGo(code, "/app/handlers.go")

	// We expect at least one cross-flow per distinct leaf sink — i.e.
	// the dedup must NOT collapse Sink1 vs Sink2 into one finding.
	var sawSQL, sawCmd bool
	for _, f := range flows {
		// Restrict to cross-flows (rendered with a "calls" step).
		hasCallsStep := false
		for _, st := range f.Steps {
			if strings.HasPrefix(st.Description, "calls ") {
				hasCallsStep = true
				break
			}
		}
		if !hasCallsStep {
			continue
		}
		switch f.Sink.Category {
		case taint.SnkSQLQuery:
			sawSQL = true
		case taint.SnkCommand:
			sawCmd = true
		}
	}
	if !sawSQL {
		t.Errorf("expected cross-flow for SQLi sink; flows=%+v", flows)
	}
	if !sawCmd {
		t.Errorf("expected cross-flow for command-injection sink; flows=%+v", flows)
	}
}
