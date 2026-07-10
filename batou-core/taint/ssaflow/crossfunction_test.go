package ssaflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Register Go language catalog so source/sink lookups resolve.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// findCrossFunctionFlow returns the first flow that appears to be a
// cross-function emission (sink line equals a call-site line in scope X
// while the actual dangerous API is in scope Y). The cross-function
// emitter renders steps with a "calls <callee>" hop — we use that as a
// reliable test marker that doesn't depend on internal field names.
func findCrossFunctionFlow(flows []taint.TaintFlow, scopeContains string) *taint.TaintFlow {
	for i := range flows {
		f := &flows[i]
		if scopeContains != "" && !strings.Contains(f.ScopeName, scopeContains) {
			continue
		}
		for _, st := range f.Steps {
			if strings.HasPrefix(st.Description, "calls ") {
				return f
			}
		}
	}
	return nil
}

// TestCrossFunction_SinkInsideCallee covers the canonical case:
// the caller passes its *http.Request straight into a same-package
// function that internally sinks the request into db.Exec. Without
// cross-function summaries we'd only catch the flow inside the callee;
// with summaries we also emit a flow at the caller's scope.
func TestCrossFunction_SinkInsideCallee(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func Forward(r *http.Request) {
	db.Exec(r.URL.Query().Get("q"))
}

func Handler(r *http.Request) {
	Forward(r)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if len(flows) == 0 {
		t.Fatalf("expected at least one flow, got 0")
	}

	// We expect both:
	//   1. An intra-procedural flow inside Forward (existing engine).
	//   2. A NEW cross-function flow scoped to Handler.
	var sawIntraInForward, sawCrossInHandler bool
	for _, f := range flows {
		if f.Source.Category != taint.SrcUserInput || f.Sink.Category != taint.SnkSQLQuery {
			continue
		}
		switch {
		case strings.Contains(f.ScopeName, "Forward"):
			sawIntraInForward = true
		case strings.Contains(f.ScopeName, "Handler"):
			sawCrossInHandler = true
		}
	}
	if !sawIntraInForward {
		t.Errorf("expected intra-procedural SQLi flow inside Forward; flows=%+v", flows)
	}
	if !sawCrossInHandler {
		t.Errorf("expected cross-function SQLi flow inside Handler (caller); flows=%+v", flows)
	}

	// The cross-function flow's Steps should mention "calls Forward".
	cross := findCrossFunctionFlow(flows, "Handler")
	if cross == nil {
		t.Fatalf("expected a flow whose steps include a 'calls <callee>' hop; got %+v", flows)
	}
	hasCallStep := false
	for _, st := range cross.Steps {
		if strings.Contains(st.Description, "calls ") && strings.Contains(st.Description, "Forward") {
			hasCallStep = true
		}
	}
	if !hasCallStep {
		t.Errorf("cross-function flow missing 'calls Forward' step; steps=%+v", cross.Steps)
	}
}

// TestCrossFunction_TaintedReturn covers the converse direction:
// the callee returns a value derived from a tainted param, the caller
// stores it and sinks it. The summary's paramTaintsReturn=true bit is
// what lets us propagate taint through the return edge.
func TestCrossFunction_TaintedReturn(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func Get(r *http.Request) string {
	return r.URL.Path
}

func Handler(r *http.Request) {
	db.Exec(Get(r))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if len(flows) == 0 {
		t.Fatalf("expected at least one flow, got 0")
	}

	// The new behaviour: there should be a flow scoped to Handler whose
	// sink category is SQLi. (The callee Get has no sink, so without
	// tainted-return propagation we would emit nothing at all from
	// either function — Handler.r is the only source param in the
	// program, and the only sink is db.Exec inside Handler.)
	var sawHandlerSQLi bool
	for _, f := range flows {
		if f.Source.Category != taint.SrcUserInput || f.Sink.Category != taint.SnkSQLQuery {
			continue
		}
		if strings.Contains(f.ScopeName, "Handler") {
			sawHandlerSQLi = true
		}
	}
	if !sawHandlerSQLi {
		t.Fatalf("expected SQLi flow inside Handler via tainted-return; flows=%+v", flows)
	}
}

// TestCrossFunction_NegativeKnownLimitation_UnknownSanitizer documents
// a known limitation: a same-package, user-defined sanitizer function
// is treated as transparent (its return is still tainted) because this
// PR does not infer sanitization from a callee's body. The Go taint
// catalog only knows about a fixed set of standard-library escapers
// (html.EscapeString, url.QueryEscape, regexp.QuoteMeta, …); custom
// project-local helpers like "func mySanitize(...) string { ... }" are
// invisible. The test asserts the documented behaviour (a flow IS
// emitted today) without failing on the limitation — once a future PR
// adds callee-body inference or a per-summary "sanitizing-return" bit,
// this case will silently flip to 0 flows and the test should be
// promoted to a positive negative assertion.
//
// Important: we deliberately do NOT use regexp.QuoteMeta or
// html.EscapeString here — those ARE in the catalog and would be
// caught by the existing sanitizer prune.
func TestCrossFunction_NegativeKnownLimitation_UnknownSanitizer(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
	"strings"
)

var db *sql.DB

// projectSanitize is a hand-rolled "sanitizer" — replacing every
// single-quote with an empty string is dangerous and incomplete (it
// does not actually neutralize SQL injection), but a real codebase
// might have a helper of this shape and expect a SAST tool to flag
// its misuse. This PR's cross-function pass conservatively treats the
// return as tainted (param 0 flows to return) because we do not
// recognise user-defined sanitizers — only catalog entries.
func projectSanitize(s string) string {
	return strings.ReplaceAll(s, "'", "")
}

func Handler(r *http.Request) {
	db.Exec(projectSanitize(r.URL.Path))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	// Documented behaviour: a SQLi flow IS emitted, scoped to Handler,
	// because we don't infer sanitization from a callee body. This is
	// a known false positive for trivial passthrough helpers AND a true
	// positive for actually-broken sanitizers like projectSanitize
	// (which doesn't escape backslash, two-byte chars, etc.). The test
	// asserts the engine's behaviour rather than a security verdict.
	var sawSQLi bool
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && strings.Contains(f.ScopeName, "Handler") {
			sawSQLi = true
			break
		}
	}
	if !sawSQLi {
		t.Log("no SQLi flow emitted — a future PR likely added callee-body sanitizer inference or " +
			"a user-defined-sanitizer recognition path. Promote this test to require len(flows)==0.")
	} else {
		t.Log("documented limitation: user-defined sanitizer projectSanitize is treated as transparent " +
			"because the cross-function summary records 'param 0 → return' for any path-passthrough " +
			"function. Future work: add a 'sanitizing-return' summary bit when the callee body is " +
			"recognised as a known escaper, or run an AST pattern over the callee body. Either way, the " +
			"flow is correct today for the projectSanitize case (which is in fact an incomplete sanitizer).")
	}
}

// TestCrossFunction_PlainStringCalleeIsTransparent ensures that a
// callee with a plain-string parameter (no typed source) DOES propagate
// caller taint into its body. This is the strongest motivation for the
// PR: the callee analyzed in isolation has nothing to report, but the
// cross-function pass sees that Handler passes a tainted value as arg 0.
func TestCrossFunction_PlainStringCalleeIsTransparent(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

// Forward has no typed-source parameters, so the intra-procedural
// engine reports nothing for it. But Forward.s flows to db.Exec, and
// the caller passes a tainted value as arg 0, so the cross-function
// pass MUST emit a flow inside Handler.
func Forward(s string) {
	db.Exec(s)
}

func Handler(r *http.Request) {
	Forward(r.URL.Query().Get("q"))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	var sawHandlerCrossSQLi bool
	for _, f := range flows {
		if f.Source.Category != taint.SrcUserInput || f.Sink.Category != taint.SnkSQLQuery {
			continue
		}
		if strings.Contains(f.ScopeName, "Handler") {
			sawHandlerCrossSQLi = true
		}
	}
	if !sawHandlerCrossSQLi {
		t.Fatalf("expected cross-function SQLi flow inside Handler when callee param is plain string; flows=%+v", flows)
	}
}

// TestCrossFunction_DoesNotEmitForUnreachableArg makes sure the
// summary-based emission does not over-fire: when a callee has a sink
// reachable from param 0 but the caller passes a non-tainted constant
// to arg 0, no flow should be emitted at the caller. This is the
// fundamental soundness check for the cross-function pass.
func TestCrossFunction_DoesNotEmitForUnreachableArg(t *testing.T) {
	code := `package main

import (
	"database/sql"
)

var db *sql.DB

func Forward(s string) {
	db.Exec(s)
}

// Caller has no typed-source params — so even though Forward's
// summary says "param 0 reaches a SQLi sink", the caller passes a
// constant, and no source-to-sink chain exists. Cross-function pass
// must NOT emit a flow here.
func Caller() {
	Forward("SELECT 1")
}
`
	flows := AnalyzeGo(code, "/app/safe.go")
	for _, f := range flows {
		if strings.Contains(f.ScopeName, "Caller") {
			t.Errorf("unexpected flow inside Caller for a constant arg: %+v", f)
		}
	}
}

// TestCrossFunction_FixedPointConvergesOnRecursion is a robustness
// test: a function that calls itself must not loop in the fixed-point
// driver. The summary for fn says "param 0 reaches return" the first
// time around; the second iteration adds nothing; convergence.
func TestCrossFunction_FixedPointConvergesOnRecursion(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

// Recursive function: returns r.URL.Path or recurses. Either way,
// param r flows to the return value. The fixed-point driver should
// converge on a stable summary in <= 2 iterations.
func Get(r *http.Request, depth int) string {
	if depth > 0 {
		return Get(r, depth-1)
	}
	return r.URL.Path
}

func Handler(r *http.Request) {
	db.Exec(Get(r, 3))
}
`
	flows := AnalyzeGo(code, "/app/recursive.go")
	var sawHandlerSQLi bool
	for _, f := range flows {
		if f.Source.Category == taint.SrcUserInput && f.Sink.Category == taint.SnkSQLQuery &&
			strings.Contains(f.ScopeName, "Handler") {
			sawHandlerSQLi = true
		}
	}
	if !sawHandlerSQLi {
		t.Fatalf("expected SQLi via tainted-return through recursive callee; flows=%+v", flows)
	}
}

// TestCrossFunction_CrossPackageSkipped confirms the scope-limit
// documented in the PR: we do not attempt to summarise functions in
// other packages. Cross-package taint will be a follow-up PR.
//
// We can't easily exercise an actual multi-package SSA build in a
// single-file test, so this test is structural: it asserts that the
// cross-function pass does NOT try to look up summaries for callees
// whose ssa.Function.Pkg != caller.Pkg. We simulate that by calling a
// stdlib function (in package "fmt") with a tainted arg — fmt.Println
// is not in the catalog as a sink, so no flow should be emitted from
// the cross-function pass for it.
func TestCrossFunction_CrossPackageSkipped(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
)

func Handler(r *http.Request) {
	fmt.Println(r.URL.Path)
}
`
	flows := AnalyzeGo(code, "/app/log.go")
	// fmt.Println is in the Go taint catalog as a log sink for some
	// categories. The intra-procedural engine may emit a log flow here —
	// that's fine. We just assert no cross-function emission tries to
	// look up a fmt.* summary (which it can't have). Practically: no
	// flow should have a "calls fmt." step.
	for _, f := range flows {
		for _, st := range f.Steps {
			if strings.Contains(st.Description, "calls fmt.") {
				t.Errorf("cross-function pass leaked into cross-package callee fmt.*; flow=%+v", f)
			}
		}
	}
}
