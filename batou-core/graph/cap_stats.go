// Cross-file cap-truncation diagnostics.
//
// Every cross-file analysis bound in this package (fixpoint iteration
// ceilings, BFS depth limits, caller/pair/callee fan-out caps, expression
// unwrap depth, assignment lookback windows, caller-file size limits, and
// the staleness gate) historically truncated SILENTLY — "no finding" was
// indistinguishable from "hit a cap". This file adds package-level hit
// counters, incremented at the exact moment a bound truncates work, plus
// a Reset/Snapshot API so `batou scan` can surface a one-line diagnostic
// in its summary output.
//
// The counters are OUTPUT-ONLY: no control flow, threshold, or finding
// emission depends on them. Increments use atomics because cap sites run
// from concurrent dirscan workers (per-file PropagateInterproc) as well
// as the single-threaded finalize pass.
package graph

import (
	"fmt"
	"sync/atomic"
)

// capHitCounters holds one atomic counter per cross-file bound. A counter
// increments once per truncation EVENT (e.g. one early-returned pair walk,
// one skipped oversize file), not per unit of work dropped.
type capHitCounters struct {
	fixpoint  atomic.Int64 // sigPropagationMaxIters: fixpoint exited the iteration ceiling while still changing
	depth     atomic.Int64 // maxTraversalDepth-shaped BFS truncated with frontier remaining
	callers   atomic.Int64 // maxIncrementalCallers: inbound callers dropped in the hook lane
	pairs     atomic.Int64 // maxHookCrossFilePairs: hook pair walk returned early
	secondHop atomic.Int64 // maxSecondHopCallees: two-hop lift bounded its intermediates
	deriv     atomic.Int64 // maxDerivDepth: expression-unwrap recursion bailed
	lookback  atomic.Int64 // maxAssignLookback: assignment lookback window was clipped and found no binding
	oversize  atomic.Int64 // maxCallerFileSize: loadCallerFile declined an oversize file
	stale     atomic.Int64 // staleness gate: loadCallerFile skipped a file changed since the graph baseline
}

// capHits is the package-wide counter instance. Callers that want a
// per-run view call ResetCapHits() at the start of the run and
// SnapshotCapHits() at the end (what dirscan's finalize does).
var capHits capHitCounters

// frontierHasUnvisitedCallers reports whether any node in a BFS frontier
// still has an unvisited caller — i.e. a depth cap genuinely truncated the
// upward walk rather than merely coinciding with its natural end. Used by
// the depth-cap diagnostics so a chain that ends exactly at the cap does
// not count as a truncation.
func frontierHasUnvisitedCallers(cg *CallGraph, frontier []string, visited map[string]bool) bool {
	for _, id := range frontier {
		node := cg.Nodes[id]
		if node == nil {
			continue
		}
		for _, callerID := range node.CalledBy {
			if !visited[callerID] {
				return true
			}
		}
	}
	return false
}

// CapHitStats is an immutable snapshot of the cap-hit counters, safe to
// read field-by-field without synchronization.
type CapHitStats struct {
	Fixpoint  int64
	Depth     int64
	Callers   int64
	Pairs     int64
	SecondHop int64
	Deriv     int64
	Lookback  int64
	Oversize  int64
	Stale     int64
}

// ResetCapHits zeroes every cap-hit counter. Call at the start of a scan
// (or test) so the subsequent snapshot reflects only that run.
func ResetCapHits() {
	capHits.fixpoint.Store(0)
	capHits.depth.Store(0)
	capHits.callers.Store(0)
	capHits.pairs.Store(0)
	capHits.secondHop.Store(0)
	capHits.deriv.Store(0)
	capHits.lookback.Store(0)
	capHits.oversize.Store(0)
	capHits.stale.Store(0)
}

// SnapshotCapHits returns the current counter values. Each field is read
// atomically; the snapshot as a whole is not a single atomic cut, which
// is fine for diagnostics read after concurrent work has drained.
func SnapshotCapHits() CapHitStats {
	return CapHitStats{
		Fixpoint:  capHits.fixpoint.Load(),
		Depth:     capHits.depth.Load(),
		Callers:   capHits.callers.Load(),
		Pairs:     capHits.pairs.Load(),
		SecondHop: capHits.secondHop.Load(),
		Deriv:     capHits.deriv.Load(),
		Lookback:  capHits.lookback.Load(),
		Oversize:  capHits.oversize.Load(),
		Stale:     capHits.stale.Load(),
	}
}

// Any reports whether at least one cap was hit — the gate for emitting
// the diagnostic line, so quiet scans stay quiet.
func (s CapHitStats) Any() bool {
	return s.Fixpoint != 0 || s.Depth != 0 || s.Callers != 0 || s.Pairs != 0 ||
		s.SecondHop != 0 || s.Deriv != 0 || s.Lookback != 0 || s.Oversize != 0 ||
		s.Stale != 0
}

// String renders the snapshot in the fixed key=value order used by the
// `batou scan` summary line.
func (s CapHitStats) String() string {
	return fmt.Sprintf(
		"fixpoint=%d depth=%d callers=%d pairs=%d secondhop=%d deriv=%d lookback=%d oversize=%d stale=%d",
		s.Fixpoint, s.Depth, s.Callers, s.Pairs, s.SecondHop, s.Deriv, s.Lookback, s.Oversize, s.Stale,
	)
}
