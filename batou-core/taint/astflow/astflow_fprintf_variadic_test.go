package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
)

// Regression for the printf-family variadic dangerous-arg bug. The catalog gives
// fmt.Fprintf DangerousArgs=[1] (the FORMAT slot), so a tainted value at the
// variadic tail — fmt.Fprintf(w, "%s", q) with q at index 2 — produced no flow,
// missing the idiomatic Go reflected-XSS shape. The matcher now treats every arg
// after the io.Writer as dangerous for fmt-write sinks; the taint check still
// gates on an actually-tainted arg, so no new false positive.
func TestAnalyzeGo_FprintfVariadic_ReflectedXSS(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, "<div>%s</div>", q)
}
`
	flows := AnalyzeGo(code, "/app/h.go")
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected SnkHTMLOutput for a tainted fmt.Fprintf variadic value (index 2), not the format slot")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

// A constant variadic value must NOT flag — the widening only matters when an
// arg is actually tainted.
func TestAnalyzeGo_FprintfVariadic_ConstantSafe(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	_ = r
	fmt.Fprintf(w, "<div>%s</div>", "static")
}
`
	flows := AnalyzeGo(code, "/app/safe.go")
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("fmt.Fprintf with a constant variadic value must not flag XSS")
	}
}
