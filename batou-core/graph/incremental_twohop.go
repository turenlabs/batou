// Two-hop incremental cross-file resolution for the write-time hook lane.
//
// The one-hop hook walk (WalkCrossFileTaintFlowsForCaller) analyzes the
// edited file's DIRECT cross-file callees: edited file A -> callee B in
// another file, where B's persisted signature carries a sink (direct, or
// one lifted from a deeper callee by the scan's
// PropagateSignaturesAcrossCallgraph pass). That lift is what lets the
// one-hop walk surface A -> B -> C(sink) chains — but ONLY when the
// persisted lift is present and current.
//
// The lift can be absent in the hook lane:
//   - B is a pure forwarder whose persisted signature never gained C's
//     sink (the lift was capped, or B/C were edited after the last scan
//     so the persisted lift is stale), OR
//   - C's leaf sink is one the per-leaf ensure*CalleeSinks helpers
//     populate lazily but the scan's fixpoint didn't propagate up to B.
//
// In those cases the one-hop walk skips the A->B pair (B has no sink
// signature) and the genuine A->B->C flow is missed at write time. The
// full `batou scan` catches it via PropagateSignaturesAcrossCallgraph's
// whole-graph fixpoint, but that doesn't run in the hook.
//
// LiftSecondHopSinksForFile closes that gap with a BOUNDED, single-level
// re-lift: for each direct cross-file callee B of the edited file, it
// runs the SAME proven per-caller lift used by the scan
// (propagateOneCaller) so B inherits its own cross-file callees' (C's)
// sinks in-memory. The subsequent one-hop walk then surfaces the full
// chain — the lifted SinkRef carries OriginFile/OriginLine pointing at
// C's leaf sink, so the rendered finding spans A -> ... -> C exactly as
// the scan-mode finding would.
//
// This reuses the existing lift machinery rather than reinventing a
// second-hop walker, so it inherits the lift's soundness (a sink is only
// lifted into B when B actually passes its parameter to C's sink
// position) and its per-language coverage.
package graph

import (
	"sort"

	"github.com/turenlabs/batou-rules/rules"
)

// maxSecondHopCallees bounds how many distinct intermediate (B) nodes the
// two-hop lift processes per hook invocation. Combined with
// maxHookCrossFilePairs (the one-hop pair cap of the walk that consumes
// the lifts) this keeps the write-time worst case bounded: the second
// hop adds at most this many per-caller lift passes, each touching one
// intermediate file. Files whose edit reaches more than this many
// distinct cross-file callees keep the first N in sorted order; the next
// full `batou scan` heals the rest. Deliberately HALF the one-hop caller
// cap (maxIncrementalCallers = 64) — the second hop is a deepening, not
// a fan-out, and the tighter cap keeps the added latency well inside the
// one-hop budget.
const maxSecondHopCallees = 32

// propagateOneCaller runs a single-node sink/return lift for caller,
// dispatching by language exactly as PropagateSignaturesAcrossCallgraph's
// fixpoint inner loop does. Returns the number of SinkRef/return entries
// newly lifted into caller.TaintSig.
//
// passes/pyIdx/jsIdx are the per-pass parse caches; the caller builds
// them once and reuses them across every node so the parse-once-per-file
// contract holds. Unlike the fixpoint, this runs the lift for ONE node a
// SINGLE time (no iterate-to-fixed-point) — the hook two-hop deepens by
// exactly one level, by design.
func propagateOneCaller(
	cg *CallGraph,
	caller *FuncNode,
	fileContents map[string]string,
	passes map[rules.Language]genericPropagatorPass,
	pyIdx *pythonCallIndexCache,
	jsIdx *javascriptCallIndexCache,
) int {
	if caller == nil || len(caller.Calls) == 0 {
		return 0
	}
	switch caller.Language {
	case rules.LangGo:
		return propagateForCaller(cg, caller, fileContents)
	case rules.LangPython:
		return propagateForPythonCallerCached(cg, caller, fileContents, pyIdx)
	case rules.LangJavaScript, rules.LangTypeScript:
		return propagateForJavaScriptCallerCached(cg, caller, fileContents, jsIdx)
	default:
		gp, ok := passes[caller.Language]
		if !ok {
			return 0
		}
		return gp.run(cg, caller, fileContents)
	}
}

// SecondHopStats reports what the two-hop lift did, for diagnostics and
// for the load-bearing test to assert the lift actually fired.
type SecondHopStats struct {
	Intermediates int  // distinct cross-file callee (B) nodes processed
	SinksLifted   int  // SinkRef/return entries lifted into B nodes
	Capped        bool // true if maxSecondHopCallees bounded the work
}

// LiftSecondHopSinksForFile performs the bounded one-level second-hop
// sink lift for the file being written in the hook lane. It collects the
// edited file's DIRECT cross-file callees (the B nodes), and for each B
// that has no directly-consumable sink/return signature, runs
// propagateOneCaller so B inherits its own cross-file callees' (C's)
// sinks in-memory. The subsequent WalkCrossFileTaintFlowsForCaller then
// surfaces the A->B->C flow.
//
// Bounded by maxSecondHopCallees intermediates. The lift is gated to B
// nodes WITHOUT an existing usable signature so already-lifted (or
// directly-sinking) intermediates — which the one-hop walk already
// covers — cost nothing extra. ensureCalleeSignatures is run first on
// each B so the "has a usable signature" check reflects lazily-populated
// leaf sinks, not just whatever the scan persisted.
//
// Returns SecondHopStats; the lifts are written into cg.Nodes[*].TaintSig
// in place (the same mutation the scan's fixpoint performs), so the walk
// that runs immediately after sees them.
func LiftSecondHopSinksForFile(cg *CallGraph, editedFile string, fileContents map[string]string) SecondHopStats {
	stats := SecondHopStats{}
	if cg == nil || editedFile == "" {
		return stats
	}
	if fileContents == nil {
		fileContents = map[string]string{}
	}

	callers := cg.NodesInFile(editedFile)
	if len(callers) == 0 {
		return stats
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i].ID < callers[j].ID })

	// Collect the distinct cross-file callee (B) IDs the edited file
	// reaches directly, in deterministic order.
	seen := make(map[string]bool)
	var bIDs []string
	for _, caller := range callers {
		calleeIDs := append([]string(nil), caller.Calls...)
		sort.Strings(calleeIDs)
		for _, id := range calleeIDs {
			b := cg.GetNode(id)
			if b == nil || b.FilePath == editedFile {
				continue // same-file callees are PropagateInterproc's job
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			bIDs = append(bIDs, id)
		}
	}
	if len(bIDs) == 0 {
		return stats
	}

	// Per-pass parse caches are allocated lazily on the first genuine
	// lift candidate so the common case — an edited file whose direct
	// cross-file callees are all true leaves or already carry a usable
	// signature (the one-hop walk's job) — pays nothing beyond the
	// candidate scan. Building the 11-language pass registry + py/js
	// caches costs ~1us + ~50 allocs; skipping it keeps the no-op two-hop
	// path as cheap as the one-hop walk.
	var passes map[rules.Language]genericPropagatorPass
	var pyIdx *pythonCallIndexCache
	var jsIdx *javascriptCallIndexCache

	for _, id := range bIDs {
		if stats.Intermediates >= maxSecondHopCallees {
			stats.Capped = true
			capHits.secondHop.Add(1) // diagnostics only: remaining intermediates were not lifted
			break
		}
		b := cg.GetNode(id)
		if b == nil {
			continue
		}
		// B can only forward a second hop if it itself calls into other
		// files. A B with no outbound cross-file edge is a true leaf —
		// the one-hop walk already covers it.
		if !hasCrossFileCallee(cg, b) {
			continue
		}
		// Ensure B's own leaf sinks are populated (lazy per-language) so
		// a B that directly sinks isn't needlessly re-lifted, and so the
		// "usable signature" gate below is accurate.
		ensureCalleeSignatures(cg, b)
		if calleeHasUsableSignature(b) {
			// One-hop walk already surfaces A->B (direct or
			// already-lifted sink). No second hop needed.
			continue
		}
		if passes == nil {
			passes = newGenericPropagatorPasses()
			pyIdx = newPythonCallIndexCache()
			jsIdx = newJavaScriptCallIndexCache()
		}
		stats.Intermediates++
		added := propagateOneCaller(cg, b, fileContents, passes, pyIdx, jsIdx)
		stats.SinksLifted += added
	}
	return stats
}

// hasCrossFileCallee reports whether node calls into at least one
// function defined in a different file. Cheap guard so we only pay the
// second-hop lift for genuine forwarders.
func hasCrossFileCallee(cg *CallGraph, node *FuncNode) bool {
	for _, calleeID := range node.Calls {
		c := cg.GetNode(calleeID)
		if c != nil && c.FilePath != node.FilePath {
			return true
		}
	}
	return false
}

// calleeHasUsableSignature reports whether node already carries a
// sink/return signature the one-hop walk can fire on. Mirrors the
// fast-skip predicate used by WalkCrossFileTaintFlowsForCaller and
// AnalyzeCallerImpact.
func calleeHasUsableSignature(node *FuncNode) bool {
	return len(node.TaintSig.SinkCalls) > 0 ||
		len(node.TaintSig.TaintedReturns) > 0 ||
		len(node.TaintSig.TaintedReturnPaths) > 0
}
