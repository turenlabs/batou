package ssaflow

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Register Go language catalog so source/sink lookups resolve.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// writeModule materialises a temporary Go module on disk with the given
// files (relative path → contents) and returns the module root path. We
// have to use a real temp directory because packages.Load shells out to
// the `go` command — there's no in-memory equivalent. The module path
// `m` is short and stable so test fixtures import as `m/a`, `m/b`, etc.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = "module m\n\ngo 1.22\n"
	}
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return dir
}

// resetModuleCache wipes the cross-package summary cache so successive
// subtests don't see each other's analyses. The cache is keyed by
// module root (temp dir paths differ per t.TempDir) so collisions are
// rare, but tests that re-use the same directory could leak — better
// to be explicit.
func resetModuleCache() {
	moduleSlotsMu.Lock()
	defer moduleSlotsMu.Unlock()
	moduleSlots = make(map[string]*moduleSlot)
}

// hasFlowMatching is a more selective version of the existing
// hasFlowWithCategories: it also matches a substring of the caller-side
// scope name so cross-package tests can assert "the flow was emitted in
// package a's handler" (rather than the deep callee).
func hasFlowMatching(flows []taint.TaintFlow, src taint.SourceCategory, snk taint.SinkCategory, scopeContains string) bool {
	for _, f := range flows {
		if f.Source.Category != src || f.Sink.Category != snk {
			continue
		}
		if scopeContains != "" && !strings.Contains(f.ScopeName, scopeContains) {
			continue
		}
		return true
	}
	return false
}

// TestCrossPackage_TwoPackageSinkInCallee is the canonical positive case:
// package `a` defines a handler that passes its *http.Request straight
// into a same-module sink helper in package `b`. The intra-procedural
// engine only sees the sink in b; with cross-package summaries we ALSO
// emit a flow at the caller site in a.
func TestCrossPackage_TwoPackageSinkInCallee(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	root := writeModule(t, map[string]string{
		"a/a.go": `package a

import (
	"net/http"
	"m/b"
)

func Handler(r *http.Request) {
	b.Sink(r.URL.Query().Get("q"))
}
`,
		"b/b.go": `package b

import "database/sql"

var db *sql.DB

func Sink(s string) {
	db.Exec(s)
}
`,
	})

	aFile := filepath.Join(root, "a/a.go")
	content, err := os.ReadFile(aFile)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	flows := AnalyzeGo(string(content), aFile)
	if len(flows) == 0 {
		t.Fatalf("expected at least one cross-package SQLi flow, got 0")
	}

	if !hasFlowMatching(flows, taint.SrcUserInput, taint.SnkSQLQuery, "Handler") {
		t.Errorf("expected SQLi flow scoped to Handler (cross-package into b.Sink); flows=%+v", flows)
	}

	// Confirm the cross-function step rendering includes a 'calls b.Sink'
	// marker. We don't depend on the exact qualifier ('m/b.Sink' vs 'b.Sink')
	// — RelString depends on the from-package; just check the callee short
	// name appears somewhere in the steps.
	var cross *taint.TaintFlow
	for i := range flows {
		f := &flows[i]
		if !strings.Contains(f.ScopeName, "Handler") {
			continue
		}
		for _, st := range f.Steps {
			if strings.HasPrefix(st.Description, "calls ") && strings.Contains(st.Description, "Sink") {
				cross = f
				break
			}
		}
		if cross != nil {
			break
		}
	}
	if cross == nil {
		t.Fatalf("expected cross-package flow with a 'calls ...Sink' step; flows=%+v", flows)
	}
}

// TestCrossPackage_ThreeHopChain stresses the fixed-point: a (handler)
// calls b which calls c which sinks. Each package contributes one
// paramTaintsReturn / paramSinks bit; the module-wide driver must
// propagate both forward (a→b→c sinks) and reflect the result at the
// outermost caller. Both intra-procedural emission and cross-package
// emission produce flows; we only require that at least one is scoped
// to package a's Handler.
func TestCrossPackage_ThreeHopChain(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	root := writeModule(t, map[string]string{
		"a/a.go": `package a

import (
	"net/http"
	"m/b"
)

func Handler(r *http.Request) {
	b.Forward(r.URL.Query().Get("q"))
}
`,
		"b/b.go": `package b

import "m/c"

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
	})

	aFile := filepath.Join(root, "a/a.go")
	content, err := os.ReadFile(aFile)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	flows := AnalyzeGo(string(content), aFile)
	if !hasFlowMatching(flows, taint.SrcUserInput, taint.SnkSQLQuery, "Handler") {
		t.Fatalf("expected 3-hop cross-package SQLi flow scoped to Handler; flows=%+v", flows)
	}
}

// TestCrossPackage_NegativePureCallee confirms the cross-package pass
// does not over-fire: when the callee has NO sink (just a pure
// passthrough or constant return), passing a tainted value into it
// must NOT emit a flow at the caller. This is the soundness check for
// the new code path.
func TestCrossPackage_NegativePureCallee(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	root := writeModule(t, map[string]string{
		"a/a.go": `package a

import (
	"net/http"
	"m/b"
)

func Handler(r *http.Request) {
	b.Pure(r.URL.Query().Get("q"))
}
`,
		"b/b.go": `package b

// Pure has no sink. The cross-package summary for Pure should have
// empty paramSinks and (because it takes a value and returns nothing)
// no paramTaintsReturn entries either. No flow must be emitted at
// the caller for this call.
func Pure(s string) {
	_ = len(s)
}
`,
	})

	aFile := filepath.Join(root, "a/a.go")
	content, err := os.ReadFile(aFile)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	flows := AnalyzeGo(string(content), aFile)
	// We accept any non-SQLi flows (e.g. catalog matches on URL parsing
	// returning user-input) but no SQLi flow should appear in Handler —
	// no SQL sink is reachable from Handler in any callee.
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && strings.Contains(f.ScopeName, "Handler") {
			t.Errorf("unexpected SQLi flow at Handler when callee is pure: %+v", f)
		}
	}
}

// TestCrossPackage_TaintedReturnAcrossPackages exercises the converse
// direction: package b exposes a getter that returns a tainted-by-arg
// string; the caller in package a stores the result and sinks it
// locally. The module-wide summary must mark b.Get's param-0 as
// flowing to return so the caller's reachability walker can descend
// through the call site.
func TestCrossPackage_TaintedReturnAcrossPackages(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	root := writeModule(t, map[string]string{
		"a/a.go": `package a

import (
	"database/sql"
	"net/http"
	"m/b"
)

var db *sql.DB

func Handler(r *http.Request) {
	// b.Pluck returns its tainted arg; the caller sinks that result.
	db.Exec(b.Pluck(r.URL.Path))
}
`,
		"b/b.go": `package b

func Pluck(s string) string {
	return s
}
`,
	})

	aFile := filepath.Join(root, "a/a.go")
	content, err := os.ReadFile(aFile)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	flows := AnalyzeGo(string(content), aFile)
	if !hasFlowMatching(flows, taint.SrcUserInput, taint.SnkSQLQuery, "Handler") {
		t.Fatalf("expected SQLi flow via cross-package tainted-return; flows=%+v", flows)
	}
}

// TestCrossPackage_StdlibCalleeStaysOpaque is the negative companion
// to the positive cases: a tainted value flowing into a stdlib
// function (which has no SSA summary in the module) must NOT produce
// a cross-package emission. Stdlib functions remain catalog-only —
// this is the explicit boundary documented in crosspackage.go.
func TestCrossPackage_StdlibCalleeStaysOpaque(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	root := writeModule(t, map[string]string{
		"a/a.go": `package a

import (
	"fmt"
	"net/http"
)

func Handler(r *http.Request) {
	// fmt.Println is not in our taint catalog as an injection sink;
	// it has no module-level summary either. No cross-package flow
	// should be emitted with a 'calls fmt.Println' step.
	fmt.Println(r.URL.Path)
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
		for _, st := range f.Steps {
			if strings.Contains(st.Description, "calls ") && strings.Contains(st.Description, "fmt.") {
				t.Errorf("cross-package emission leaked into stdlib: %+v", f)
			}
		}
	}
}

// TestCrossPackage_FallbackOnNoModule confirms graceful degradation:
// when the file path doesn't live under a go.mod, AnalyzeGo must
// silently fall back to the single-file SSA build. We exercise that
// here with the synthetic /app/handler.go path used by the legacy
// tests — same content, same expected flow, just no module load.
func TestCrossPackage_FallbackOnNoModule(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

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
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasFlowMatching(flows, taint.SrcUserInput, taint.SnkSQLQuery, "H") {
		t.Fatalf("expected single-file SQLi flow on synthetic path (fallback); flows=%+v", flows)
	}
}

// TestCrossPackage_CacheReusesAnalysis is a behavioural test for the
// module cache: two AnalyzeGo calls on different files of the same
// module should share the same *moduleAnalysis pointer. We can't
// observe that pointer directly through the public API, but we CAN
// observe a side effect: the second call returns much faster than the
// first because the SSA program is reused. To avoid flakiness on slow
// CI machines we just assert that both calls succeed and produce
// consistent flow sets — and we verify the cache map has a single
// entry for the shared module root afterwards.
func TestCrossPackage_CacheReusesAnalysis(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	root := writeModule(t, map[string]string{
		"a/a.go": `package a

import (
	"net/http"
	"m/b"
)

func HandlerA(r *http.Request) {
	b.Sink(r.URL.Path)
}
`,
		"a/a2.go": `package a

import (
	"net/http"
	"m/b"
)

func HandlerA2(r *http.Request) {
	b.Sink(r.URL.RawQuery)
}
`,
		"b/b.go": `package b

import "database/sql"

var db *sql.DB

func Sink(s string) {
	db.Exec(s)
}
`,
	})

	aFile1 := filepath.Join(root, "a/a.go")
	aFile2 := filepath.Join(root, "a/a2.go")
	c1, _ := os.ReadFile(aFile1)
	c2, _ := os.ReadFile(aFile2)

	flows1 := AnalyzeGo(string(c1), aFile1)
	flows2 := AnalyzeGo(string(c2), aFile2)
	if !hasFlowMatching(flows1, taint.SrcUserInput, taint.SnkSQLQuery, "HandlerA") {
		t.Errorf("expected SQLi flow from first scan; flows=%+v", flows1)
	}
	if !hasFlowMatching(flows2, taint.SrcUserInput, taint.SnkSQLQuery, "HandlerA2") {
		t.Errorf("expected SQLi flow from second scan; flows=%+v", flows2)
	}

	moduleSlotsMu.Lock()
	defer moduleSlotsMu.Unlock()
	// Find the entry by suffix matching the temp dir we wrote.
	rootAbs, _ := filepath.Abs(root)
	if slot := moduleSlots[rootAbs]; slot == nil || slot.entry == nil {
		t.Errorf("expected cache entry for module root %q, got none. cache=%v", rootAbs, moduleCacheKeys())
	}
}

// moduleCacheKeys returns a snapshot of the cache's keys for diagnostic
// output. Must be called with moduleSlotsMu held.
func moduleCacheKeys() []string {
	keys := make([]string, 0, len(moduleSlots))
	for k := range moduleSlots {
		keys = append(keys, k)
	}
	return keys
}

// TestCrossPackage_ConcurrentLoadIsSafe drives multiple AnalyzeGo calls
// in parallel against the same module. The cache mutex protects entry
// creation; we just need to confirm no race detector failures and
// consistent results. (`go test -race` is the actual assertion; this
// test is its driver.)
func TestCrossPackage_ConcurrentLoadIsSafe(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	root := writeModule(t, map[string]string{
		"a/a.go": `package a

import (
	"net/http"
	"m/b"
)

func H(r *http.Request) {
	b.Sink(r.URL.Path)
}
`,
		"b/b.go": `package b

import "database/sql"

var db *sql.DB

func Sink(s string) {
	db.Exec(s)
}
`,
	})

	aFile := filepath.Join(root, "a/a.go")
	content, _ := os.ReadFile(aFile)
	src := string(content)

	const goroutines = 4
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			flows := AnalyzeGo(src, aFile)
			if !hasFlowMatching(flows, taint.SrcUserInput, taint.SnkSQLQuery, "H") {
				t.Errorf("goroutine %d: missing expected flow; flows=%+v", idx, flows)
			}
		}(i)
	}
	wg.Wait()
}

// TestCrossPackage_PackageLoadFailureFallsBack writes a module whose
// go.mod is intentionally broken (unknown directive). packages.Load
// will fail; we expect AnalyzeGo to silently fall back to the
// single-file SSA build for the file we passed and still produce a
// reasonable result on whatever it can parse alone. This is the
// "fail open" branch of crosspackage.go's defensive policy.
func TestCrossPackage_PackageLoadFailureFallsBack(t *testing.T) {
	resetModuleCache()
	defer resetModuleCache()

	// Broken go.mod (missing module path; `go list` will error).
	root := writeModule(t, map[string]string{
		"go.mod": "module\n",
		"a/a.go": `package a

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func H(r *http.Request) {
	db.Exec(r.URL.Query().Get("q"))
}
`,
	})

	aFile := filepath.Join(root, "a/a.go")
	content, _ := os.ReadFile(aFile)
	flows := AnalyzeGo(string(content), aFile)
	// Single-file build sees the same source/sink within H itself.
	if !hasFlowMatching(flows, taint.SrcUserInput, taint.SnkSQLQuery, "H") {
		t.Errorf("expected fallback single-file SQLi flow when module load fails; flows=%+v", flows)
	}
}

