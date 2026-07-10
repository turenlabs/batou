package graph

// Tests for the cross-file cap-truncation diagnostics: Reset/Snapshot
// semantics, the String format the dirscan summary line prints, and
// per-cap increment behavior when a bound genuinely truncates work.
// Internal package tests because the counters and several instrumented
// helpers (matchDerivedParamName, deriveParamIndex) are unexported.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func TestCapHits_ResetAndSnapshot(t *testing.T) {
	ResetCapHits()
	if s := SnapshotCapHits(); s.Any() {
		t.Fatalf("after Reset, Any() = true, snapshot = %+v", s)
	}

	capHits.deriv.Add(3)
	capHits.stale.Add(1)
	s := SnapshotCapHits()
	if !s.Any() {
		t.Fatal("Any() = false after increments")
	}
	if s.Deriv != 3 || s.Stale != 1 {
		t.Fatalf("snapshot = %+v, want Deriv=3 Stale=1", s)
	}
	if s.Fixpoint != 0 || s.Depth != 0 || s.Callers != 0 || s.Pairs != 0 ||
		s.SecondHop != 0 || s.Lookback != 0 || s.Oversize != 0 {
		t.Fatalf("untouched counters nonzero: %+v", s)
	}

	ResetCapHits()
	if s := SnapshotCapHits(); s.Any() {
		t.Fatalf("second Reset did not zero counters: %+v", s)
	}
}

func TestCapHits_StringFormat(t *testing.T) {
	s := CapHitStats{Fixpoint: 1, Deriv: 12, Lookback: 3, Stale: 2}
	want := "fixpoint=1 depth=0 callers=0 pairs=0 secondhop=0 deriv=12 lookback=3 oversize=0 stale=2"
	if got := s.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	// The zero value renders all-zero (the caller gates on Any(), but the
	// format must stay stable either way).
	if got := (CapHitStats{}).String(); !strings.Contains(got, "fixpoint=0") || !strings.Contains(got, "stale=0") {
		t.Fatalf("zero-value String() = %q", got)
	}
}

// TestCapHits_IncrementalCallersCap builds a hub file called from more
// files than maxIncrementalCallers and asserts the callers counter
// increments exactly once (one truncation event) while the returned
// slice is capped.
func TestCapHits_IncrementalCallersCap(t *testing.T) {
	ResetCapHits()
	cg := NewCallGraph("/proj", "s")
	hub := "/proj/hub.go"
	cg.AddNode(&FuncNode{ID: FuncID(hub, "Util"), FilePath: hub, Name: "Util", Language: rules.LangGo})
	for i := 0; i < maxIncrementalCallers+5; i++ {
		fp := fmt.Sprintf("/proj/caller%03d.go", i)
		id := FuncID(fp, "F")
		cg.AddNode(&FuncNode{ID: id, FilePath: fp, Name: "F", Language: rules.LangGo})
		cg.AddEdge(id, FuncID(hub, "Util"))
	}

	out := CallersOfFileFromOtherFiles(cg, hub)
	if len(out) != maxIncrementalCallers {
		t.Fatalf("len(out) = %d, want %d", len(out), maxIncrementalCallers)
	}
	if s := SnapshotCapHits(); s.Callers != 1 {
		t.Fatalf("Callers counter = %d, want 1 (snapshot %+v)", s.Callers, s)
	}

	// Under the cap: no truncation, no increment.
	ResetCapHits()
	cg2 := NewCallGraph("/proj", "s")
	cg2.AddNode(&FuncNode{ID: FuncID(hub, "Util"), FilePath: hub, Name: "Util", Language: rules.LangGo})
	cg2.AddNode(&FuncNode{ID: "/proj/a.go:F", FilePath: "/proj/a.go", Name: "F", Language: rules.LangGo})
	cg2.AddEdge("/proj/a.go:F", FuncID(hub, "Util"))
	_ = CallersOfFileFromOtherFiles(cg2, hub)
	if s := SnapshotCapHits(); s.Callers != 0 {
		t.Fatalf("Callers counter = %d after under-cap query, want 0", s.Callers)
	}
}

// TestCapHits_TransitiveDepthCap builds a caller chain deeper than the
// requested BFS depth and asserts the depth counter fires — and does NOT
// fire when the chain ends exactly at the cap (no genuine truncation).
func TestCapHits_TransitiveDepthCap(t *testing.T) {
	chain := func(n int) *CallGraph {
		cg := NewCallGraph("/proj", "s")
		for i := 0; i <= n; i++ {
			fp := fmt.Sprintf("/proj/f%d.go", i)
			cg.AddNode(&FuncNode{ID: FuncID(fp, "F"), FilePath: fp, Name: "F", Language: rules.LangGo})
		}
		for i := 1; i <= n; i++ {
			// f{i} calls f{i-1}: callers stack upward from f0.
			cg.AddEdge(fmt.Sprintf("/proj/f%d.go:F", i), fmt.Sprintf("/proj/f%d.go:F", i-1))
		}
		return cg
	}

	// Chain of 8 callers above f0, walked to depth 5: truncated.
	ResetCapHits()
	cg := chain(8)
	got := cg.GetTransitiveCallers("/proj/f0.go:F", maxTraversalDepth)
	if len(got) != maxTraversalDepth {
		t.Fatalf("callers returned = %d, want %d", len(got), maxTraversalDepth)
	}
	if s := SnapshotCapHits(); s.Depth != 1 {
		t.Fatalf("Depth counter = %d, want 1 (snapshot %+v)", s.Depth, s)
	}

	// Chain ending exactly AT the cap: frontier has no unvisited callers,
	// so nothing was truncated and the counter must stay zero.
	ResetCapHits()
	cg = chain(maxTraversalDepth)
	_ = cg.GetTransitiveCallers("/proj/f0.go:F", maxTraversalDepth)
	if s := SnapshotCapHits(); s.Depth != 0 {
		t.Fatalf("Depth counter = %d for exactly-at-cap chain, want 0", s.Depth)
	}
}

// TestCapHits_DerivDepthCap feeds matchDerivedParamName an expression
// nested deeper than maxDerivDepth and asserts the deriv counter fires.
func TestCapHits_DerivDepthCap(t *testing.T) {
	ResetCapHits()
	// Nest one level deeper than the cap so the recursion bails.
	expr := "p"
	for i := 0; i <= maxDerivDepth+1; i++ {
		expr = fmt.Sprintf("wrap%d(%s)", i, expr)
	}
	if idx := matchDerivedParamName(expr, []string{"p"}, taint.SnkSQLQuery, nil, 0); idx != -1 {
		t.Fatalf("over-deep expression derived to %d, want -1 (fail closed)", idx)
	}
	if s := SnapshotCapHits(); s.Deriv == 0 {
		t.Fatalf("Deriv counter = 0 after over-deep unwrap, want > 0")
	}

	// Within the cap: derives fine, no increment.
	ResetCapHits()
	if idx := matchDerivedParamName("parse(p)", []string{"p"}, taint.SnkSQLQuery, nil, 0); idx != 0 {
		t.Fatalf("parse(p) derived to %d, want 0", idx)
	}
	if s := SnapshotCapHits(); s.Deriv != 0 {
		t.Fatalf("Deriv counter = %d for in-cap expression, want 0", s.Deriv)
	}
}

// TestCapHits_AssignLookbackClipped places the only binding for a local
// above the lookback window and asserts the lookback counter fires; a
// binding inside the window (same body size) must not count.
func TestCapHits_AssignLookbackClipped(t *testing.T) {
	ResetCapHits()
	body := make([]string, maxAssignLookback+20)
	for i := range body {
		body[i] = "\tnoop()"
	}
	body[0] = "\tq := build(p)" // binding beyond the clipped window
	callLineIdx := len(body) - 1
	if idx := matchDerivedParamName("q", []string{"p"}, taint.SnkSQLQuery, body, callLineIdx); idx != -1 {
		t.Fatalf("out-of-window binding derived to %d, want -1", idx)
	}
	if s := SnapshotCapHits(); s.Lookback != 1 {
		t.Fatalf("Lookback counter = %d, want 1 (snapshot %+v)", s.Lookback, s)
	}

	// Binding INSIDE the window: found, no increment even though the
	// window is still clipped (the cap did not change the answer).
	ResetCapHits()
	body[0] = "\tnoop()"
	body[callLineIdx-2] = "\tq := build(p)"
	if idx := matchDerivedParamName("q", []string{"p"}, taint.SnkSQLQuery, body, callLineIdx); idx != 0 {
		t.Fatalf("in-window binding derived to %d, want 0", idx)
	}
	if s := SnapshotCapHits(); s.Lookback != 0 {
		t.Fatalf("Lookback counter = %d after successful lookback, want 0", s.Lookback)
	}
}
