package tsflow

// Load-bearing tests for CH4-access-path-depth: the bounded access-path depth
// cap raised 3 -> 5.
//
// These drive the EXACT production mechanism the cap participates in:
//   - write side: a source value reaching a deep field path is seeded under
//     boundAccessPath(maximalPath) (see processAttr / maximalSourceAccessPath).
//   - read side : a sink reading a field path resolves via
//     prefixTainted(boundAccessPath(readPath)) (see nodeIsTainted in
//     propagation.go).
//
// The cap collapses any path deeper than root + maxAccessPathDepth to that
// bounded prefix. The behavioural consequence of the cap height shows up at the
// boundary between depth-3 and depth-5 access paths: at cap=3 two distinct
// sibling leaves four levels deep (a.b.c.d.X and a.b.c.d.Y) both collapse to the
// SAME key a.b.c.d, so tainting one over-taints the other; at cap=5 they stay
// distinct, so the clean sibling is not spuriously tainted.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
)

// seedTaintedPath records `path` (after the production bound) as a tainted
// access-path key, mirroring how processAttr seeds maximalSourceAccessPath.
func seedTaintedPath(tm *taintMap, path string) {
	key := boundAccessPath(path)
	tm.set(key, &taintState{
		varName:    key,
		source:     &taint.SourceDef{Category: taint.SrcUserInput},
		sourceLine: 1,
		confidence: 0.9,
	})
}

// readPathTainted answers the sink-side question "does reading `path` resolve to
// tainted?" exactly as nodeIsTainted does for an attribute read.
func readPathTainted(tm *taintMap, path string) bool {
	return tm.prefixTainted(boundAccessPath(path)) != nil
}

// TestAccessPathDepth_DeepSiblingStaysDistinct is the load-bearing assertion.
//
// A tainted leaf at depth 4 (root a + b.c.d.tainted) reaches the map; a SIBLING
// leaf at the same depth (a.b.c.d.clean) is read at a sink. The two paths differ
// only in their 4th field segment.
//
//   - WITH the fix (cap=5): both paths exceed neither bound, stay distinct, and
//     the clean sibling reads UNTAINTED (correct — precision preserved at depth 4).
//   - WITHOUT the fix (cap=3): both collapse to a.b.c.d, so the clean sibling
//     reads TAINTED (a false positive). This test then FAILS — proving it is
//     load-bearing on the cap height.
func TestAccessPathDepth_DeepSiblingStaysDistinct(t *testing.T) {
	tm := newTaintMap()
	seedTaintedPath(tm, "a.b.c.d.tainted")

	// Recall: the genuinely tainted deep leaf must still resolve (a depth-4 leaf
	// is within the cap at 5; at 3 it collapses to a.b.c.d but still resolves,
	// so this half holds either way — it guards against the fix dropping a flow).
	if !readPathTainted(tm, "a.b.c.d.tainted") {
		t.Fatalf("recall regression: tainted deep leaf a.b.c.d.tainted must resolve as tainted")
	}

	// Precision (LOAD-BEARING): the clean sibling four levels deep must NOT be
	// tainted. Passes only when the cap is high enough (>=4) to keep the 4th
	// field segment distinct. At cap=3 both collapse to a.b.c.d and this fails.
	if readPathTainted(tm, "a.b.c.d.clean") {
		t.Errorf("over-taint: clean sibling a.b.c.d.clean must NOT be tainted when only a.b.c.d.tainted is seeded "+
			"(seeded key %q, read key %q) — depth cap too low collapses distinct siblings",
			boundAccessPath("a.b.c.d.tainted"), boundAccessPath("a.b.c.d.clean"))
	}
}

// TestAccessPathDepth_BoundExactValues pins the boundAccessPath collapse
// behaviour at the raised cap so a future cap change is caught here too. With
// maxAccessPathDepth=5, root + 5 fields (6 segments) is kept verbatim, and a
// 7-segment path collapses to its 6-segment prefix.
func TestAccessPathDepth_BoundExactValues(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// root + 4 fields (5 segments): within cap, unchanged.
		{"a.b.c.d.e", "a.b.c.d.e"},
		// root + 5 fields (6 segments): exactly at cap, unchanged.
		{"a.b.c.d.e.f", "a.b.c.d.e.f"},
		// root + 6 fields (7 segments): over cap, collapses to root + 5.
		{"a.b.c.d.e.f.g", "a.b.c.d.e.f"},
		// shallow paths untouched.
		{"req.body", "req.body"},
		{"x", "x"},
	}
	for _, c := range cases {
		if got := boundAccessPath(c.in); got != c.want {
			t.Errorf("boundAccessPath(%q) = %q, want %q (cap=%d)", c.in, got, c.want, maxAccessPathDepth)
		}
	}
}

// TestAccessPathDepth_DeepLeafTrackedToDepth5 asserts the recall direction the
// change advertises: a tainted leaf at depth 5 (a.b.c.d.e) is tracked at its
// FULL path (not collapsed) and a sibling at depth 5 (a.b.c.d.x) stays clean.
// At cap=3 the depth-5 leaf collapses to a.b.c.d, the sibling collapses to the
// same a.b.c.d, and the sibling over-taints — so the no-flow assertion fails.
func TestAccessPathDepth_DeepLeafTrackedToDepth5(t *testing.T) {
	tm := newTaintMap()
	seedTaintedPath(tm, "a.b.c.d.e")

	if got := boundAccessPath("a.b.c.d.e"); got != "a.b.c.d.e" {
		t.Fatalf("depth-5 leaf must be tracked at full path; boundAccessPath = %q (cap=%d)", got, maxAccessPathDepth)
	}
	if !readPathTainted(tm, "a.b.c.d.e") {
		t.Fatalf("recall: depth-5 tainted leaf a.b.c.d.e must resolve as tainted")
	}
	// LOAD-BEARING: distinct depth-5 sibling stays clean only when cap>=4.
	if readPathTainted(tm, "a.b.c.d.x") {
		t.Errorf("over-taint: depth-5 sibling a.b.c.d.x must NOT be tainted when only a.b.c.d.e is seeded")
	}
}
