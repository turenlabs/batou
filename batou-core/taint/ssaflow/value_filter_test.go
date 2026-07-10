package ssaflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Register Go language catalog so source/sink lookups resolve.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestAnalyzeGo_NoFlowForConstStatusCode is the canonical Bug 1 fixture.
// os.Link takes BOTH of its args as dangerous (catalog DangerousArgs:
// [0, 1]). Calling it with one taint-bearing arg (r.URL.Path) plus a
// hardcoded string-constant arg ("/tmp/lock") must produce exactly one
// flow rooted at the request — not two, where the second is rooted at
// the literal "/tmp/lock". analyzeFunction's break after the first hit
// already collapses multiple hits per call site to a single flow, so
// the contract here is "no flow whose source steps reference the
// literal arg's identifier".
func TestAnalyzeGo_NoFlowForConstStatusCode(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
)

func H(r *http.Request) {
	_ = os.Link("/tmp/lock", r.URL.Path)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasAnyFlow(flows) {
		t.Fatalf("expected at least one flow for r.URL.Path → os.Link, got 0: %+v", flows)
	}
	// Exactly one flow per sink-arg pair: analyzeFunction breaks after
	// the first param hit. A constant arg cannot add a second flow even
	// when it precedes the real arg in the position list. This guard
	// pins the contract so a future regression in the walker gets caught.
	if len(flows) != 1 {
		t.Fatalf("expected exactly 1 flow (request → os.Link); got %d: %+v", len(flows), flows)
	}
	for _, f := range flows {
		for _, st := range f.Steps {
			if strings.Contains(st.VarName, `"/tmp/lock"`) {
				t.Errorf("flow step references string-literal constant: step=%+v flow=%+v", st, f)
			}
		}
		if f.Source.Category != taint.SrcUserInput {
			t.Errorf("expected SrcUserInput, got %q: %+v", f.Source.Category, f)
		}
	}
}

// TestIsUntaintableSSAValue_NilSafe documents the nil-input contract:
// every walker passes the value it just dereferenced — sometimes nil —
// so the helper must return false (not panic) on nil so the walker
// continues to the visited/operand checks below.
func TestIsUntaintableSSAValue_NilSafe(t *testing.T) {
	if isUntaintableSSAValue(nil) {
		t.Fatal("isUntaintableSSAValue(nil) returned true; expected false")
	}
}

// TestAnalyzeGo_StdlibGlobalArgDoesNotProduceFlow verifies that an arg
// like os.Stdout passed alongside a real request value does not
// surface as a separate "source" in cross-flow rendering. The flow
// from the *http.Request param to fmt.Fprintln is still emitted; the
// io.Writer arg is just inert.
func TestAnalyzeGo_StdlibGlobalArgDoesNotProduceFlow(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
	"os"
)

func H(r *http.Request) {
	fmt.Fprintln(os.Stderr, r.URL.Path)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		// Source MethodName should be the param name "r", not a global.
		if strings.HasPrefix(strings.ToLower(f.Source.MethodName), "stderr") ||
			strings.HasPrefix(strings.ToLower(f.Source.MethodName), "stdout") ||
			strings.HasPrefix(strings.ToLower(f.Source.MethodName), "stdin") {
			t.Errorf("flow appears rooted at a stdlib io stream: %+v", f)
		}
		// Confirm we still recognise the source category for the legit
		// request flow when one is emitted.
		if f.Source.Category != taint.SrcUserInput && f.Source.Category != "" {
			t.Logf("non-user-input flow emitted (acceptable): %+v", f)
		}
	}
}
