package ssaflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint/astflow"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// benchHandler is a representative single-file Go program: a handler with a
// typed source param, a deep variable chain, and a sink. Sized to be
// non-trivial but small enough that astflow and ssaflow can both be timed
// many times without dominating the suite duration.
func benchHandler() string {
	var b strings.Builder
	b.WriteString(`package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func H(r *http.Request) {
`)
	b.WriteString("\tv0 := r.URL.Query().Get(\"q\")\n")
	for i := 1; i < 12; i++ {
		b.WriteString("\tv")
		b.WriteString(itoaSmall(i))
		b.WriteString(" := v")
		b.WriteString(itoaSmall(i - 1))
		b.WriteString(" + \"x\"\n")
	}
	b.WriteString("\tdb.Exec(v11)\n}\n")
	return b.String()
}

func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

// BenchmarkAstflow_Handler establishes the baseline cost of the existing
// astflow engine on a representative file. Used together with
// BenchmarkSSAflow_Handler to compute the SSA overhead documented in the PR.
func BenchmarkAstflow_Handler(b *testing.B) {
	code := benchHandler()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = astflow.AnalyzeGo(code, "/app/handler.go")
	}
}

// BenchmarkSSAflow_Handler measures the cost of the SSA engine on the same
// input. The expected outcome is a real (>=1.5x) slowdown because SSA forces
// full type-checking and IR construction, while astflow walks go/ast directly.
func BenchmarkSSAflow_Handler(b *testing.B) {
	code := benchHandler()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeGo(code, "/app/handler.go")
	}
}

// BenchmarkBoth_Handler measures the combined cost when both engines run
// (BATOU_SSAFLOW=1 production path). This is the number the perf-note in the
// PR body cites.
func BenchmarkBoth_Handler(b *testing.B) {
	code := benchHandler()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = astflow.AnalyzeGo(code, "/app/handler.go")
		_ = AnalyzeGo(code, "/app/handler.go")
	}
}

// benchCrossFunction returns a multi-function file that stresses the
// cross-function summary engine: a chain of N=10 same-package functions
// each forwarding their *http.Request to the next, terminating in a
// SQLi sink. The fixed-point driver must propagate the param-taints-
// return bit through the chain and then emit a cross-function flow at
// every caller site. Used in BenchmarkSSAflow_CrossFunction to
// quantify the PR's overhead on inputs that actually exercise it.
func benchCrossFunction() string {
	var b strings.Builder
	b.WriteString(`package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func leaf(r *http.Request) {
	db.Exec(r.URL.Query().Get("q"))
}

`)
	for i := 0; i < 10; i++ {
		b.WriteString("func f")
		b.WriteString(itoaSmall(i))
		b.WriteString("(r *http.Request) { ")
		if i == 0 {
			b.WriteString("leaf(r)")
		} else {
			b.WriteString("f")
			b.WriteString(itoaSmall(i - 1))
			b.WriteString("(r)")
		}
		b.WriteString(" }\n")
	}
	return b.String()
}

// BenchmarkSSAflow_CrossFunction measures the cost of the SSA engine on
// a file that meaningfully exercises the cross-function pass: 10
// forwarding functions plus a leaf sink. The pre-PR baseline (intra-
// procedural only) and post-PR number are recorded in the PR body so
// reviewers can see the overhead introduced by summaries + fixed-point.
func BenchmarkSSAflow_CrossFunction(b *testing.B) {
	code := benchCrossFunction()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeGo(code, "/app/chain.go")
	}
}

// benchCrossPackageModule writes a temporary 3-package module (a → b → c)
// with a tainted handler in a, a transparent forwarder in b, and a sink
// in c — the canonical cross-package shape that PR-CC's summary table is
// designed to detect. Returns the absolute path to a/a.go which the
// benchmark uses as AnalyzeGo's entry point.
//
// This benchmark intentionally pays the packages.Load cost on EVERY
// iteration: the module cache is reset at the start of each call so we
// measure the worst-case "first scan" latency. Production scans of
// multiple files in the same module amortise the load (subsequent calls
// hit the cache and take microseconds), so the steady-state cost is
// much lower than what this benchmark reports.
func benchCrossPackageModule(b *testing.B) (entryFile, content string) {
	b.Helper()
	dir := b.TempDir()
	files := map[string]string{
		"go.mod": "module bench\n\ngo 1.22\n",
		"a/a.go": `package a

import (
	"net/http"
	"bench/b"
)

func Handler(r *http.Request) {
	b.Forward(r.URL.Query().Get("q"))
}
`,
		"b/b.go": `package b

import "bench/c"

func Forward(s string) {
	c.Sink(s)
}
`,
		"c/c.go": `package c

import "database/sql"

var db *sql.DB

func Sink(s string) {
	db.Exec(s)
}
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			b.Fatalf("write %s: %v", name, err)
		}
	}
	entryFile = filepath.Join(dir, "a/a.go")
	bytes, err := os.ReadFile(entryFile)
	if err != nil {
		b.Fatalf("read entry: %v", err)
	}
	return entryFile, string(bytes)
}

// BenchmarkSSAflow_CrossPackage measures the cost of the cross-package
// SSA engine on a multi-module 3-hop chain. The reported number bounds
// the worst-case overhead introduced by PR-CC: each iteration pays a
// fresh packages.Load and a fresh fixed-point. The PR body's perf
// budget is "≤ 3x the intra-package benchmark" — see
// BenchmarkSSAflow_CrossFunction for the comparison point.
func BenchmarkSSAflow_CrossPackage(b *testing.B) {
	entryFile, code := benchCrossPackageModule(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resetModuleCacheForBench()
		_ = AnalyzeGo(code, entryFile)
	}
}

// BenchmarkSSAflow_CrossPackage_Cached measures the steady-state cost
// after the module cache is warm. This is the number that matters for
// any scan after the first file in a module — every subsequent file in
// the same module reuses the cached SSA program and pays only the
// per-file emission cost, which is dominated by func-body walks rather
// than packages.Load. Comparing this number with the per-file
// BenchmarkSSAflow_Handler gives reviewers a precise read on the
// amortised steady-state overhead.
func BenchmarkSSAflow_CrossPackage_Cached(b *testing.B) {
	entryFile, code := benchCrossPackageModule(b)
	// Prime the cache once outside the timed loop so the measurement
	// reflects the cache-hit path only.
	_ = AnalyzeGo(code, entryFile)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeGo(code, entryFile)
	}
}

// resetModuleCacheForBench wipes the cross-package cache; lifted out
// rather than calling the test-only helper to avoid coupling.
func resetModuleCacheForBench() {
	moduleSlotsMu.Lock()
	defer moduleSlotsMu.Unlock()
	moduleSlots = make(map[string]*moduleSlot)
}
