package ssaflow

import (
	"go/token"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/languages"
	"golang.org/x/tools/go/ssa"
)

// maxSummaryIterations bounds the fixed-point pass that propagates
// summaries across call edges. Each iteration re-runs intra-procedural
// reachability per function using the previous round's summary table,
// so mutually-recursive (or pathologically deep) call graphs cannot loop
// forever. Real Go packages converge in 2–4 iterations in practice; the
// cap is conservative.
const maxSummaryIterations = 10

// confidenceSSACrossProc is the confidence emitted for cross-function
// flows. Set slightly below the intra-procedural baseline (0.9) because
// each call edge we cross introduces an additional approximation step
// (alias unsoundness, no field sensitivity in the summary), but still
// well above the regex/AST tiers. Downstream dedup will boost
// multi-tier agreement back up to >= 0.95.
const confidenceSSACrossProc = 0.85

// analyzePackageCrossFunction is the cross-function entry point. It
// builds summaries for every function in ssaPkg, iterates until the
// summary table converges (or maxSummaryIterations), and then performs
// a final per-function flow-emission pass that mixes intra-procedural
// sinks with cross-function sinks (via callee summaries).
//
// Returns the combined list of TaintFlow records. Callers are
// responsible for downstream dedup; this function does NOT dedup against
// the intra-procedural pass — both lists are concatenated and trusted to
// be deduplicated later by the scanner's (line, CWE) grouping.
func analyzePackageCrossFunction(
	ssaPkg *ssa.Package,
	fset *token.FileSet,
	filePath string,
	matcher *catalogMatcher,
) []taint.TaintFlow {
	if ssaPkg == nil {
		return nil
	}

	// Collect every analyzable function in the package, including nested
	// anonymous functions (closures), so summaries are available for
	// closure-mediated propagation too.
	funcs := collectFunctions(ssaPkg)
	if len(funcs) == 0 {
		return nil
	}

	// summaryFuncs is the set we build SUMMARIES for. It is a superset of
	// `funcs`: it also includes named-type METHODS (materialised via
	// packageMethods) so that a method CALLEE can be summarised — the
	// receiver-rooted lane needs a method's recvFieldSinks, and any
	// cross-function flow whose callee is a method needs its paramSinks.
	//
	// Methods are deliberately NOT added to `funcs` (the EMISSION set):
	// emitting from a method as its own caller-scope would let the existing
	// index-based lane treat a source-typed receiver (e.g. *gin.Context) as
	// a whole-receiver taint root and surface field-blind cross-function
	// FPs (config-field → sink chains). The receiver-rooted lane is the
	// field-sensitive path that consumes these method summaries safely.
	summaryFuncs := summaryFunctions(ssaPkg, funcs)

	// summaries is the cross-function fixed-point table. Keys are
	// ssa.Function pointers (each *ssa.Function is unique per build, so
	// pointer identity is safe). Values are the current best summary.
	summaries := make(map[*ssa.Function]*funcSummary, len(summaryFuncs))
	for _, fn := range summaryFuncs {
		summaries[fn] = newSummary(fn)
	}

	// Fixed point: re-derive every summary using the previous round's
	// summaries as context, until nothing changes. Convergence is
	// guaranteed because each iteration can only add facts to a summary
	// (paramSinks gains records; paramTaintsReturn flips false→true) —
	// the lattice is monotonic and finite, so the iteration is bounded
	// even without the maxSummaryIterations cap. The cap exists purely
	// as a defensive guard for pathological inputs.
	for iter := 0; iter < maxSummaryIterations; iter++ {
		changed := false
		for _, fn := range summaryFuncs {
			prev := summaries[fn]
			next := computeSummary(fn, summaries, matcher, fset)
			if !prev.equal(next) {
				summaries[fn] = next
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	// Final emission pass: walk every function's body once more and
	// produce TaintFlow records for cross-function sinks reachable from
	// the caller's source params. Intra-procedural flows are intentionally
	// not re-emitted here — the caller (AnalyzeGo) already invoked
	// analyzeFunction for that, and we want to keep the two paths
	// independently testable.
	var flows []taint.TaintFlow
	// Shared dedup across every fn in this package — middleware-chain
	// emissions (5 layers each emitting for the same leaf sink) collapse
	// to a single finding. See crossSinkKey docstring.
	seenDeep := make(map[crossSinkKey]bool)
	for _, fn := range funcs {
		flows = append(flows, emitCrossFunctionFlows(fn, summaries, matcher, fset, filePath, seenDeep)...)
		// Receiver-rooted (construction-site) lane: emit flows where a
		// struct field is tainted at construction and a method reaches a
		// sink through that field. Shares seenDeep so a receiver-rooted
		// flow dedups against an index-rooted flow to the same leaf sink.
		flows = append(flows, emitReceiverRootedFlows(fn, summaries, matcher, fset, filePath, seenDeep)...)
	}
	return flows
}

// collectFunctions returns every ssa.Function exposed by ssaPkg, walking
// into AnonFuncs recursively. This matches the iteration order used by
// AnalyzeGo so the fixed point converges on the same set of functions.
func collectFunctions(ssaPkg *ssa.Package) []*ssa.Function {
	var out []*ssa.Function
	var visit func(fn *ssa.Function)
	visit = func(fn *ssa.Function) {
		if fn == nil || fn.Blocks == nil {
			return
		}
		out = append(out, fn)
		for _, anon := range fn.AnonFuncs {
			visit(anon)
		}
	}
	for _, member := range ssaPkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			visit(fn)
		}
	}
	return out
}

// computeSummary rebuilds fn's summary using the current `summaries`
// table for context. The body is walked once: for each ssa.Call we look
// up a sink in the catalog, and walk its dangerous args backward through
// def-use chains looking for fn's own parameters; for each ssa.Return
// we walk each result operand the same way. Both walks respect callee
// summaries via reachesWithSummaries — i.e. a tainted-return call result
// is treated as a fresh taint root contributed by whatever upstream
// parameter the call's relevant arg traces back to.
func computeSummary(
	fn *ssa.Function,
	summaries map[*ssa.Function]*funcSummary,
	matcher *catalogMatcher,
	fset *token.FileSet,
) *funcSummary {
	out := newSummary(fn)
	if fn == nil || fn.Blocks == nil || len(fn.Params) == 0 {
		return out
	}

	// Build a lookup of (param value → source-level index) used by the
	// reachability walker to record which parameter the data came from.
	paramIndex := make(map[ssa.Value]int, len(fn.Params))
	offset := 0
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		offset = 1 // skip receiver — receivers are addressed via index -1
	}
	for i, p := range fn.Params {
		if i < offset {
			continue
		}
		paramIndex[p] = i - offset
	}

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			switch n := instr.(type) {
			case ssa.CallInstruction:
				// ssa.CallInstruction covers *ssa.Call plus `go f(x)`
				// (*ssa.Go) and `defer f(x)` (*ssa.Defer), so a function's
				// summary records params reaching a sink invoked in a
				// goroutine or deferred call, and the cross-summary hop below
				// forwards through them.
				// Intra-procedural sink reachability for this fn.
				sink, dangerous := matcher.matchSink(n.Common())
				if sink != nil {
					args := n.Common().Args
					for _, pos := range dangerous {
						if pos < 0 || pos >= len(args) {
							continue
						}
						arg := args[pos]
						visited := make(map[ssa.Value]bool)
						hits := reachesAnyParam(arg, paramIndex, visited, 0, matcher, *sink, summaries)
						for _, idx := range hits {
							// Direct catalog match: this IS the leaf sink. Record
							// the deep file/line so forwarding hops upstream
							// preserve a stable identity for cross-emitter dedup.
							deepPos := fset.Position(n.Pos())
							rec := paramSinkRecord{
								sink:             *sink,
								sinkLine:         positionLineOrZero(fset, n.Pos()),
								sinkCallSiteName: callShortName(n),
								deepSinkFile:     deepPos.Filename,
								deepSinkLine:     deepPos.Line,
							}
							out.paramSinks[idx] = append(out.paramSinks[idx], rec)
						}
					}
				}

				// PR-CC: cross-summary sink propagation. When fn calls a
				// statically-known callee whose summary already records
				// "param j reaches sink S", and the call's arg j traces
				// back to fn's own param i via def-use, then fn's param i
				// also reaches sink S. Without this hop, three-or-more
				// deep call chains (a→b→c where c is the sink, b is
				// transparent) would not propagate — b's summary would
				// stay empty because b never directly calls a catalog
				// sink, and so a's emission pass would see "b has no
				// sinks reachable from any param" and skip.
				//
				// This is independent of paramTaintsReturn (which only
				// handles RETURN-value taint). The two facts together
				// give us: "tainted arg → callee sink" (this hop) and
				// "tainted arg → return → caller-side sink" (the
				// reachesAnyParam hop). Together they cover the common
				// shapes of cross-function dataflow.
				if callee := n.Common().StaticCallee(); callee != nil {
					if calleeSum := summaries[callee]; calleeSum != nil && len(calleeSum.paramSinks) > 0 {
						args := n.Common().Args
						callOffset := 0
						if !n.Common().IsInvoke() && n.Common().Signature() != nil &&
							n.Common().Signature().Recv() != nil {
							callOffset = 1
						}
						for calleeParamIdx, recs := range calleeSum.paramSinks {
							// context.Context plumbing: even if the callee's
							// summary records a sink reachable from this
							// param, the param itself carries cancellation /
							// deadline metadata, not user data. Skip so we
							// don't propagate taint through ctx and create
							// "ctx flows into db.Exec" false positives. See
							// context_filter.go for the rationale.
							if calleeParamIsContext(callee, calleeParamIdx) {
								continue
							}
							argPos := calleeParamIdx + callOffset
							if argPos < 0 || argPos >= len(args) {
								continue
							}
							arg := args[argPos]
							visited := make(map[ssa.Value]bool)
							// Use the first rec's sink for sanitizer pruning;
							// records sharing a paramIdx all have the same
							// downstream sink semantics.
							hits := reachesAnyParam(arg, paramIndex, visited, 0, matcher, recs[0].sink, summaries)
							for _, idx := range hits {
								// Forward the callee-side records so the
								// rendered flow at the eventual caller
								// still names the deepest catalog sink
								// (not the intermediate callee). The line
								// recorded is the local call-site so error
								// reports point at THIS function's code,
								// matching the contract used by the
								// caller's emission pass.
								for _, rec := range recs {
									// PRESERVE the upstream rec's deep
									// sink position so middleware-chain
									// dedup at the emitter sees a stable
									// (deepSinkFile, deepSinkLine) across
									// every forwarding hop. sinkLine
									// continues to be overwritten with
									// THIS function's call-site line, so
									// the rendered flow still points at
									// the local caller.
									forwarded := paramSinkRecord{
										sink:             rec.sink,
										sinkLine:         positionLineOrZero(fset, n.Pos()),
										sinkCallSiteName: callShortName(n),
										deepSinkFile:     rec.deepSinkFile,
										deepSinkLine:     rec.deepSinkLine,
									}
									out.paramSinks[idx] = append(out.paramSinks[idx], forwarded)
								}
							}
						}
					}
				}
			case *ssa.Return:
				for _, r := range n.Results {
					if r == nil {
						continue
					}
					visited := make(map[ssa.Value]bool)
					// Tainted-return reachability shares the same walker
					// as sink reachability — the only difference is that
					// we record "param i flows out via return" rather
					// than "param i flows into a sink".
					hits := reachesAnyParam(r, paramIndex, visited, 0, matcher, taint.SinkDef{}, summaries)
					for _, idx := range hits {
						out.paramTaintsReturn[idx] = true
					}
				}
			}
		}
	}
	// Dedup paramSinks records by (sink.ID, sinkLine, sinkCallSiteName).
	// Both the direct catalog-match path and the cross-summary
	// propagation path can append a record for the same call site (e.g.
	// when fn directly calls a catalog sink AND a same-package wrapper
	// that re-exposes the same sink shape). Leaving duplicates would
	// break funcSummary.equal — that comparator checks list length —
	// causing the fixed-point driver to oscillate forever.
	for idx, recs := range out.paramSinks {
		out.paramSinks[idx] = dedupParamSinkRecords(recs)
	}
	// Receiver-rooted, field-sensitive sinks (methods only). This is the
	// companion fact to the receiver-offset realignment: a method that
	// reaches a sink through a specific receiver field (db.Query(h.Q))
	// records that field path so a construction-site caller can match it
	// (see receiver_rooted.go). Derived purely from fn's own body, so it
	// does not depend on the summaries table and is stable across the
	// fixed point.
	out.recvFieldSinks = computeReceiverFieldSinks(fn, matcher, fset)
	return out
}

// dedupParamSinkRecords removes records with identical (sink ID, local
// line, callee short name) tuples while preserving the first
// occurrence's order. O(n^2) by intent — the slice is always tiny (a
// function's param-to-sink edge count is bounded by its call sites
// times its params, both single-digit in practice). Lifted into a
// helper so the crossfunction and crosspackage paths can share it
// without each re-implementing the dedup.
//
// The deep-sink position is intentionally NOT part of the dedup key:
// during the fixed-point pass, a single (callsite, sink) tuple is one
// fact regardless of which downstream leaf the chain eventually ends
// at. Including deep position here would prevent multi-hop merges and
// leave the summary smaller than needed for accurate propagation —
// exactly the regression PR-OO fixes. The leaf-sink dedup that PR-NN
// originally introduced lives in the emitter (seenDeep + crossSinkKey),
// not here. The first-kept record's deepSinkFile/deepSinkLine flow
// through to the emitter for that purpose.
func dedupParamSinkRecords(recs []paramSinkRecord) []paramSinkRecord {
	if len(recs) <= 1 {
		return recs
	}
	out := recs[:0]
	for _, r := range recs {
		dup := false
		for _, kept := range out {
			if kept.sink.ID == r.sink.ID &&
				kept.sinkLine == r.sinkLine &&
				kept.sinkCallSiteName == r.sinkCallSiteName {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, r)
		}
	}
	return out
}

// reachesAnyParam walks backward from v through SSA def-use chains and
// returns every source-level parameter index that is reachable. Unlike
// the original reaches(), which returned a single hit, this collects ALL
// reaching params — needed because a sink arg might be a phi merge of
// two different parameters (or a binop on them), and the summary must
// record all of them.
//
// When v is a *ssa.Call to a function with a known summary entry for
// paramTaintsReturn, the walker descends into the corresponding caller
// arg (as if the call returned that arg directly). This is the
// mechanism by which cross-function tainted-return propagation works.
//
// sink may be zero-valued when the caller is computing return-taint
// reachability (rather than sink reachability). In that case the
// sanitizer prune is still active but matches against an empty category,
// which never neutralizes anything — safe behaviour.
func reachesAnyParam(
	v ssa.Value,
	params map[ssa.Value]int,
	visited map[ssa.Value]bool,
	depth int,
	matcher *catalogMatcher,
	sink taint.SinkDef,
	summaries map[*ssa.Function]*funcSummary,
) []int {
	if v == nil || depth > maxDefUseDepth {
		return nil
	}
	// Skip SSA constants and stdlib globals — they can't be parameters and
	// they can't carry user data, so they can't extend the def-use chain
	// in any useful direction. Filtering here also prevents the caller's
	// summary from being polluted with sinks whose only "tainted" arg was
	// a status-code literal or os.Stderr.
	if isUntaintableSSAValue(v) {
		return nil
	}
	if idx, ok := params[v]; ok {
		return []int{idx}
	}
	if visited[v] {
		return nil
	}
	visited[v] = true

	// Sanitizer prune: identical to reaches() in analyze.go.
	if call, ok := v.(*ssa.Call); ok {
		if sink.Category != "" && matcher.callIsSanitizerFor(call, sink.Category) {
			return nil
		}
		// Cross-function tainted-return: if v is the result of a call
		// whose callee summary says "param i taints return", recurse
		// into the call's arg i (source-level index, so receiver-shifted
		// if necessary) and union those hits in.
		if hits := traverseCalleeReturn(call, params, visited, depth, matcher, sink, summaries); len(hits) > 0 {
			// We DO NOT also recurse into other operands of the call
			// when the callee summary says "param i taints return" — the
			// summary is authoritative for cross-function propagation.
			// (Other operands like the function expression and unrelated
			// args are not data dependencies for taint.)
			return uniqueInts(hits)
		}
	}

	var out []int
	for _, op := range operands(v) {
		if op == nil || *op == nil {
			continue
		}
		if more := reachesAnyParam(*op, params, visited, depth+1, matcher, sink, summaries); len(more) > 0 {
			out = append(out, more...)
		}
	}
	// Store-to-load forwarding through local aggregates (see
	// field_forward.go): values stored into the cell this load reads are
	// extra param-reachability sources the operand walk cannot see.
	for _, sv := range storeForwardedValues(v) {
		if more := reachesAnyParam(sv, params, visited, depth+1, matcher, sink, summaries); len(more) > 0 {
			out = append(out, more...)
		}
	}
	return uniqueInts(out)
}

// traverseCalleeReturn handles the "tainted-return propagation" hop. For
// every parameter index i that the callee's summary marks as flowing to
// its return, we recurse into the call's source-level arg i (offset for
// receiver) and collect reaching params in the caller. This is the
// mechanism that lets `result := Get(r); db.Exec(result)` resolve as a
// flow even though Get's body is in a different function.
func traverseCalleeReturn(
	call *ssa.Call,
	params map[ssa.Value]int,
	visited map[ssa.Value]bool,
	depth int,
	matcher *catalogMatcher,
	sink taint.SinkDef,
	summaries map[*ssa.Function]*funcSummary,
) []int {
	callee := call.Common().StaticCallee()
	if callee == nil {
		return nil
	}
	sum, ok := summaries[callee]
	if !ok || sum == nil || len(sum.paramTaintsReturn) == 0 {
		return nil
	}
	args := call.Common().Args
	offset := 0
	if !call.Common().IsInvoke() && call.Common().Signature() != nil &&
		call.Common().Signature().Recv() != nil {
		offset = 1
	}
	var out []int
	for paramIdx, taints := range sum.paramTaintsReturn {
		if !taints {
			continue
		}
		// Skip context.Context params — they're plumbing, not data.
		// See context_filter.go.
		if calleeParamIsContext(callee, paramIdx) {
			continue
		}
		argPos := paramIdx + offset
		if argPos < 0 || argPos >= len(args) {
			continue
		}
		more := reachesAnyParam(args[argPos], params, visited, depth+1, matcher, sink, summaries)
		out = append(out, more...)
	}
	return out
}

// emitCrossFunctionFlows is the final pass: for each call site inside
// fn, look up the callee's summary and emit a TaintFlow per
// (caller-param → callee-sink) pair whose argument is reachable from a
// caller-side source param. The flow's scope is set to fn (the caller),
// the source line is the caller's parameter declaration, and the sink
// line is the caller-side call (NOT the deeper callee-side sink line) —
// callers want to know where in their code the bad value was
// introduced into the call chain, not the precise instruction inside an
// external function.
//
// We deliberately exclude intra-procedural flows from this pass; they
// are reported by analyzeFunction in analyze.go. The two passes are
// kept separate so cross-function flows can be turned off (or scored
// differently) without disturbing the existing intra-procedural
// behaviour.
func emitCrossFunctionFlows(
	fn *ssa.Function,
	summaries map[*ssa.Function]*funcSummary,
	matcher *catalogMatcher,
	fset *token.FileSet,
	filePath string,
	seenDeep map[crossSinkKey]bool,
) []taint.TaintFlow {
	if fn == nil || fn.Blocks == nil {
		return nil
	}
	paramSources := make(map[ssa.Value]*taint.SourceDef, len(fn.Params))
	for _, p := range fn.Params {
		if src := paramSource(p); src != nil {
			paramSources[p] = src
		}
	}
	if len(paramSources) == 0 {
		return nil
	}

	scopeName := fn.Name()
	if recv := fn.Signature.Recv(); recv != nil {
		scopeName = receiverTypeString(recv.Type()) + "." + scopeName
	}

	// Same-package gate: cross-package calls are out of scope for this
	// PR. We compare ssa.Package pointers — the SSA build groups every
	// function from a single source-level package into one ssa.Package,
	// so this is a precise check.
	thisPkg := fn.Pkg

	var flows []taint.TaintFlow
	seen := make(map[crossFlowKey]bool)

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			callee := call.Common().StaticCallee()
			if callee == nil {
				continue // static-target only (see scope-limits docstring)
			}
			if callee.Pkg != thisPkg {
				continue // cross-package skipped for this PR
			}
			sum := summaries[callee]
			if sum == nil || len(sum.paramSinks) == 0 {
				continue
			}
			args := call.Common().Args
			offset := 0
			if !call.Common().IsInvoke() && call.Common().Signature() != nil &&
				call.Common().Signature().Recv() != nil {
				offset = 1
			}
			for paramIdx, recs := range sum.paramSinks {
				// context.Context plumbing: see context_filter.go.
				if calleeParamIsContext(callee, paramIdx) {
					continue
				}
				argPos := paramIdx + offset
				if argPos < 0 || argPos >= len(args) {
					continue
				}
				arg := args[argPos]
				// Find which caller source param the arg traces to.
				visited := make(map[ssa.Value]bool)
				reached, path := reachesAnyParamSource(arg, paramSources, visited, 0, matcher, recs[0].sink, summaries)
				if reached == nil {
					continue
				}
				src := paramSources[reached]
				// Source position: where the tainted param enters the
				// caller. Included in the leaf-sink dedup key so two
				// distinct handlers each forwarding a same-category
				// source into the same downstream sink stay separate
				// findings (see crossSinkKey doc).
				sourceLine := positionLineOrZero(fset, reached.Pos())
				for _, rec := range recs {
					key := crossFlowKey{
						callerFn: fn,
						calleeFn: callee,
						sinkID:   rec.sink.ID,
						paramIdx: paramIdx,
					}
					if seen[key] {
						continue
					}
					seen[key] = true
					// Module-wide / package-wide dedup keyed by the LEAF
					// sink + SOURCE: when several middleware layers each
					// have their own (callerFn, calleeFn, sinkID,
					// paramIdx) tuple but all funnel the SAME source into
					// the same deep sink, only the first emitter wins.
					// Different sources (distinct file+line) are kept.
					if rec.deepSinkFile != "" && seenDeep != nil {
						deepKey := newCrossSinkKey(rec, *src, filePath, sourceLine)
						if seenDeep[deepKey] {
							continue
						}
						seenDeep[deepKey] = true
					}
					flow := buildCrossFlow(fn, call, callee, *src, rec, reached, path, fset, filePath, scopeName)
					flows = append(flows, flow)
				}
			}
		}
	}
	return flows
}

// crossFlowKey de-dups multiple identical (caller, callee, sink, param)
// emissions that can arise when the same callee is called from two
// blocks within the same caller — only one flow per unique tuple is
// useful for the user.
type crossFlowKey struct {
	callerFn *ssa.Function
	calleeFn *ssa.Function
	sinkID   string
	paramIdx int
}

// crossSinkKey identifies the LEAF sink (the deepest catalog match in a
// summary chain) plus the SOURCE that flowed into it. Used by the
// module-wide and package-wide emitters to dedup middleware-chain
// pathologies: when 5 middleware layers each propagate the same source
// shape into the same deep sink, every layer's emitter produces an
// otherwise-distinct flow (different scopes, different local sinkLines).
// The deep sink position is preserved through summary forwarding (see
// paramSinkRecord.deepSinkFile / deepSinkLine in summary.go), so this
// key is identical across all 5 layers and the first finding wins.
//
// The source identity includes both file+line AND category so distinct
// SOURCES reaching the same sink stay separate findings — two handlers
// each accepting an *http.Request and forwarding to the same downstream
// sink are independently meaningful even though both are
// SrcUserInput. PR-NN's original key used sourceCategory alone, which
// collapsed sibling handlers in the same file/module; PR-OO widened
// the key to fix that recall regression.
type crossSinkKey struct {
	deepSinkFile   string
	deepSinkLine   int
	sinkCategory   taint.SinkCategory
	sinkMethod     string
	sourceFile     string
	sourceLine     int
	sourceCategory taint.SourceCategory
}

// newCrossSinkKey extracts the dedup key from a flow about to be emitted.
// Centralised so all emitters (single-file, same-package, cross-package)
// can share the same dedup invariant — keeping a single source of truth
// for what "the same finding" means across the module pass.
//
// sourceFile/sourceLine identify WHERE the source enters the chain (the
// caller-side source parameter) so two handlers in the same file/module
// each forwarding to the same downstream sink remain distinct findings.
func newCrossSinkKey(rec paramSinkRecord, src taint.SourceDef, sourceFile string, sourceLine int) crossSinkKey {
	return crossSinkKey{
		deepSinkFile:   rec.deepSinkFile,
		deepSinkLine:   rec.deepSinkLine,
		sinkCategory:   rec.sink.Category,
		sinkMethod:     rec.sink.MethodName,
		sourceFile:     sourceFile,
		sourceLine:     sourceLine,
		sourceCategory: src.Category,
	}
}

// reachesAnyParamSource is the existing reaches() pattern adapted to
// return BOTH the reaching root AND the operand path, while ALSO
// honoring tainted-return propagation through summaries. It is used in
// the cross-function emission pass to render readable flow steps.
func reachesAnyParamSource(
	v ssa.Value,
	roots map[ssa.Value]*taint.SourceDef,
	visited map[ssa.Value]bool,
	depth int,
	matcher *catalogMatcher,
	sink taint.SinkDef,
	summaries map[*ssa.Function]*funcSummary,
) (ssa.Value, []ssa.Value) {
	if v == nil || depth > maxDefUseDepth {
		return nil, nil
	}
	// Skip SSA constants and stdlib globals — see isUntaintableSSAValue.
	// Without this guard the cross-package emitter walks into literals
	// like http.StatusBadRequest and synthesises "source" arrows from
	// them in the rendered flow.
	if isUntaintableSSAValue(v) {
		return nil, nil
	}
	if _, ok := roots[v]; ok {
		return v, []ssa.Value{v}
	}
	if visited[v] {
		return nil, nil
	}
	visited[v] = true

	if call, ok := v.(*ssa.Call); ok {
		if matcher.callIsSanitizerFor(call, sink.Category) {
			return nil, nil
		}
		// Tainted-return: descend through the relevant arg of the call.
		if hit, path := traverseReturnForFlow(call, roots, visited, depth, matcher, sink, summaries); hit != nil {
			return hit, append(path, v)
		}
	}

	for _, op := range operands(v) {
		if op == nil || *op == nil {
			continue
		}
		if hit, path := reachesAnyParamSource(*op, roots, visited, depth+1, matcher, sink, summaries); hit != nil {
			return hit, append(path, v)
		}
	}
	// Store-to-load forwarding through local aggregates — see
	// field_forward.go. Keeps the cross-function flow-emission walker in
	// lockstep with reaches()/reachesAnyParam().
	for _, sv := range storeForwardedValues(v) {
		if hit, path := reachesAnyParamSource(sv, roots, visited, depth+1, matcher, sink, summaries); hit != nil {
			return hit, append(path, v)
		}
	}
	return nil, nil
}

// traverseReturnForFlow is the flow-emission analogue of
// traverseCalleeReturn: it descends through tainted-return args of a
// call site, returning the first reaching root and its path.
func traverseReturnForFlow(
	call *ssa.Call,
	roots map[ssa.Value]*taint.SourceDef,
	visited map[ssa.Value]bool,
	depth int,
	matcher *catalogMatcher,
	sink taint.SinkDef,
	summaries map[*ssa.Function]*funcSummary,
) (ssa.Value, []ssa.Value) {
	callee := call.Common().StaticCallee()
	if callee == nil {
		return nil, nil
	}
	sum, ok := summaries[callee]
	if !ok || sum == nil || len(sum.paramTaintsReturn) == 0 {
		return nil, nil
	}
	args := call.Common().Args
	offset := 0
	if !call.Common().IsInvoke() && call.Common().Signature() != nil &&
		call.Common().Signature().Recv() != nil {
		offset = 1
	}
	for paramIdx, taints := range sum.paramTaintsReturn {
		if !taints {
			continue
		}
		// Skip context.Context params — see context_filter.go.
		if calleeParamIsContext(callee, paramIdx) {
			continue
		}
		argPos := paramIdx + offset
		if argPos < 0 || argPos >= len(args) {
			continue
		}
		if hit, path := reachesAnyParamSource(args[argPos], roots, visited, depth+1, matcher, sink, summaries); hit != nil {
			return hit, path
		}
	}
	return nil, nil
}

// buildCrossFlow constructs a TaintFlow record describing a single
// cross-function emission. The flow's scope is the caller; the sink
// description is the callee-side sink (so the user knows which
// dangerous API is ultimately invoked); the sink line is the
// caller-side call expression.
func buildCrossFlow(
	fn *ssa.Function,
	callSite *ssa.Call,
	callee *ssa.Function,
	src taint.SourceDef,
	rec paramSinkRecord,
	param ssa.Value,
	path []ssa.Value,
	fset *token.FileSet,
	filePath string,
	scopeName string,
) taint.TaintFlow {
	srcLine := positionLineOrZero(fset, fn.Pos())
	if p, ok := param.(*ssa.Parameter); ok {
		srcLine = positionLineOrZero(fset, p.Pos())
	}
	callerCallLine := positionLineOrZero(fset, callSite.Pos())

	// Steps: render the caller-side operand path, then add a synthetic
	// "calls <callee>" hop, then a callee-side sink step. This gives the
	// reader a single linear trace covering both functions.
	steps := make([]taint.FlowStep, 0, len(path)+2)
	for i := len(path) - 1; i >= 0; i-- {
		v := path[i]
		steps = append(steps, taint.FlowStep{
			Line:        positionLineOrZero(fset, v.Pos()),
			Description: ssaStepDescription(v),
			VarName:     ssaValueName(v),
		})
	}
	calleeName := callee.RelString(nil)
	steps = append(steps, taint.FlowStep{
		Line:        callerCallLine,
		Description: "calls " + calleeName,
		VarName:     calleeName,
	})
	steps = append(steps, taint.FlowStep{
		Line:        rec.sinkLine,
		Description: "tainted argument reaches sink inside " + calleeName,
		VarName:     rec.sinkCallSiteName,
	})

	return taint.TaintFlow{
		Source:     src,
		Sink:       rec.sink,
		SourceLine: srcLine,
		SinkLine:   callerCallLine,
		Steps:      steps,
		FilePath:   filePath,
		ScopeName:  scopeName,
		Confidence: confidenceSSACrossProc,
	}
}

// callShortName returns the human-readable name of the function being
// called at this call site, or "" for indirect/dynamic dispatch. Used
// to label sink steps in cross-function flows.
func callShortName(ci ssa.CallInstruction) string {
	if ci == nil {
		return ""
	}
	if callee := ci.Common().StaticCallee(); callee != nil {
		return callee.Name()
	}
	return ""
}

// uniqueInts removes duplicate entries from a small int slice while
// preserving order. Used by reachesAnyParam to avoid recording the same
// parameter twice when it is reached through multiple operand paths.
func uniqueInts(xs []int) []int {
	if len(xs) <= 1 {
		return xs
	}
	seen := make(map[int]bool, len(xs))
	out := xs[:0]
	for _, x := range xs {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// Ensure the languages catalog import is referenced — the catalog is
// loaded transitively by analyze.go via taint.GetCatalog, but go vet
// will flag unused imports in a fresh file otherwise. (Kept for
// symmetry with analyze.go which also imports it.)
var _ = languages.LookupGoSourceType
