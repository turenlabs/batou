package ssaflow

import (
	"go/token"

	"github.com/turenlabs/batou-core/taint"
	"golang.org/x/tools/go/ssa"
)

// funcSummary captures the cross-function-relevant taint signature of a
// single ssa.Function. Summaries are computed intra-procedurally first
// (pass 1) and then iteratively refined as callee summaries become known
// (pass 2). Two facts are recorded for each parameter index i:
//
//  1. paramSinks[i] — every (sink call, sinkDef) pair inside fn that is
//     reachable from parameter i via SSA def-use. This is what callers use
//     to know "if I pass a tainted value as arg i, it will end up in this
//     sink inside the callee".
//  2. paramTaintsReturn[i] — true if parameter i flows to at least one
//     Return instruction's result. This is what callers use to know "if I
//     pass a tainted value as arg i, the call's return value is tainted
//     and must be treated as a fresh taint root for further analysis".
//
// Both maps are keyed by source-level parameter index (receiver excluded),
// matching the catalog's DangerousArgs convention.
type funcSummary struct {
	fn                *ssa.Function
	paramSinks        map[int][]paramSinkRecord
	paramTaintsReturn map[int]bool
	// recvFieldSinks records, for a METHOD, every catalog sink reachable
	// from the receiver through a specific struct-field access path
	// (e.g. `db.Query(h.Q)` → field path [#1]). It is the field-sensitive
	// receiver analogue of paramSinks and drives the construction-site
	// emission lane in receiver_rooted.go. Empty for non-methods.
	recvFieldSinks []recvFieldSink
}

// paramSinkRecord describes a single sink reachable from a parameter
// inside the function the summary belongs to. It is stored on the summary
// so that when a caller propagates a tainted argument into this function,
// the caller can render a TaintFlow that names the callee-side sink
// without re-running the callee's analysis.
type paramSinkRecord struct {
	sink     taint.SinkDef
	sinkLine int
	// sinkCallSiteName is the short name of the sink callee
	// (e.g. "Exec", "Command") — used for human-readable flow steps when
	// the caller emits a cross-function TaintFlow.
	sinkCallSiteName string
	// deepSinkFile / deepSinkLine record the file and line of the
	// CATALOG-MATCHED call (the actual sink call) at the leaf of the
	// summary chain. They are populated in the direct match case
	// (sink == catalog entry) and PRESERVED across forwarding hops so
	// every middleware layer that propagates a tainted arg still
	// carries the deepest sink's stable position. Used by the cross-
	// function/cross-package emitters to dedup multiple layers that
	// all funnel the same source to the same leaf sink — without this
	// the emitter would render N findings (one per layer) for what is
	// really a single vulnerable call site.
	deepSinkFile string
	deepSinkLine int
}

// newSummary builds an empty summary tied to fn. Maps are nil until
// populated by computeSummary.
func newSummary(fn *ssa.Function) *funcSummary {
	return &funcSummary{
		fn:                fn,
		paramSinks:        make(map[int][]paramSinkRecord),
		paramTaintsReturn: make(map[int]bool),
	}
}

// equal returns true when two summaries record the same set of facts.
// Used by the fixed-point driver to decide when iteration has converged.
// Sink records are compared by (sinkID, sinkLine) — sufficient because
// every (function, parameter, sink call) triple is unique within an SSA
// build.
//
// Note: deepSinkFile/deepSinkLine are intentionally NOT part of the
// equality. Those fields are emission-time metadata used for cross-flow
// dedup at the leaf; participating in summary equality would change
// propagation semantics (records that share (sinkID, sinkLine) but
// differ in deep position would prevent convergence and could exceed
// maxSummaryIterations, causing legitimate downstream sinks to never
// land in the per-node TaintSig). See PR-OO for the regression report.
func (s *funcSummary) equal(other *funcSummary) bool {
	if s == nil || other == nil {
		return s == other
	}
	if len(s.paramSinks) != len(other.paramSinks) {
		return false
	}
	for i, recs := range s.paramSinks {
		otherRecs, ok := other.paramSinks[i]
		if !ok || len(otherRecs) != len(recs) {
			return false
		}
		// O(n^2) but n is tiny (params × sinks per func is small in practice).
		for _, r := range recs {
			found := false
			for _, or := range otherRecs {
				if r.sink.ID == or.sink.ID &&
					r.sinkLine == or.sinkLine {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	if len(s.paramTaintsReturn) != len(other.paramTaintsReturn) {
		return false
	}
	for i, v := range s.paramTaintsReturn {
		if other.paramTaintsReturn[i] != v {
			return false
		}
	}
	// recvFieldSinks is derived purely intra-procedurally (the receiver's
	// own field path to a local sink), so it is stable across fixed-point
	// iterations; comparing by (sinkID, sinkLine, field-path) is enough to
	// keep convergence sound if a future change makes it summary-dependent.
	if len(s.recvFieldSinks) != len(other.recvFieldSinks) {
		return false
	}
	for _, r := range s.recvFieldSinks {
		found := false
		for _, or := range other.recvFieldSinks {
			if r.rec.sink.ID == or.rec.sink.ID &&
				r.rec.sinkLine == or.rec.sinkLine &&
				fieldPathsEqual(r.path, or.path) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// fieldPathsEqual reports whether two receiver field-access paths are
// identical (same length, same selector at each step).
func fieldPathsEqual(a, b []fieldSelector) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].isIndex != b[i].isIndex || a[i].field != b[i].field {
			return false
		}
	}
	return true
}

// positionLineOrZero is a panic-safe wrapper around fset.Position(pos).Line.
// Some SSA-synthesised values carry NoPos; the original engine relies on
// this returning 0 in that case (positionLine already does).
func positionLineOrZero(fset *token.FileSet, pos token.Pos) int {
	return positionLine(fset, pos)
}
