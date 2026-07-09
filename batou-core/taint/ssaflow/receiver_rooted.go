package ssaflow

import (
	"go/token"
	"go/types"

	"github.com/turenlabs/batou-core/taint"
	"golang.org/x/tools/go/ssa"
)

// summaryFunctions returns the set of functions to build SUMMARIES for: the
// emission set `funcs` plus every named-type method in ssaPkg. Methods must be
// summarised (so a method callee's paramSinks / recvFieldSinks are known) but
// are intentionally kept out of the emission set — see analyzePackageCrossFunction.
func summaryFunctions(ssaPkg *ssa.Package, funcs []*ssa.Function) []*ssa.Function {
	methods := packageMethods(ssaPkg)
	if len(methods) == 0 {
		return funcs
	}
	seen := make(map[*ssa.Function]bool, len(funcs))
	out := make([]*ssa.Function, 0, len(funcs)+len(methods))
	for _, fn := range funcs {
		seen[fn] = true
		out = append(out, fn)
	}
	for _, m := range methods {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// packageMethods returns every concrete method declared on a named type in
// ssaPkg, materialised as an *ssa.Function with a body. Methods live under
// *ssa.Type members (not as top-level *ssa.Function members), so the
// function-collection passes miss them entirely unless we walk the method
// sets here.
//
// We enumerate the pointer method set of each named type (a superset of the
// value method set, so both value- and pointer-receiver methods are covered),
// materialise each via prog.MethodValue, and filter to functions actually
// declared in ssaPkg with a body. Results are deduped by pointer identity —
// the same *ssa.Function can appear under multiple selections.
func packageMethods(ssaPkg *ssa.Package) []*ssa.Function {
	if ssaPkg == nil || ssaPkg.Prog == nil {
		return nil
	}
	var out []*ssa.Function
	seen := make(map[*ssa.Function]bool)
	for _, member := range ssaPkg.Members {
		typeMem, ok := member.(*ssa.Type)
		if !ok {
			continue
		}
		mset := ssaPkg.Prog.MethodSets.MethodSet(types.NewPointer(typeMem.Type()))
		for i, n := 0, mset.Len(); i < n; i++ {
			fn := ssaPkg.Prog.MethodValue(mset.At(i))
			if fn == nil || fn.Blocks == nil || fn.Pkg != ssaPkg {
				continue
			}
			if seen[fn] {
				continue
			}
			seen[fn] = true
			out = append(out, fn)
		}
	}
	return out
}

// receiver_rooted.go implements field-sensitive RECEIVER-rooted cross-function
// taint: the construction-site companion to the receiver-offset realignment.
//
// The shape it catches
// --------------------
//
//	type Handler struct{ Q string }
//	func (h *Handler) Process()        { db.Query(h.Q) }   // sink reads recv.Q
//	func Serve(r *http.Request) {
//	    h := &Handler{Q: r.FormValue("x")}                 // tainted field at construction
//	    h.Process()                                        // method call
//	}
//
// The index-based cross-function machinery in crossfunction.go is blind to
// this for two reasons that this file fixes together:
//
//  1. Method bodies were never summarized at all — collectFunctions() only
//     walked top-level *ssa.Function package members + their AnonFuncs.
//     `(*Handler).Process` lives under an *ssa.Type member, so its summary
//     was empty. (See addPackageMethods in crossfunction.go.)
//  2. Even once summarized, the receiver is parameter 0 of a method but the
//     value that carries user data is a *field* of the receiver struct, not
//     the whole receiver. A bare "param 0 reaches sink" fact would taint the
//     entire receiver on every method call — far too coarse. We instead
//     record the exact field ACCESS PATH from the receiver to the sink
//     (recvFieldSink.path) so the construction-site match is field-precise:
//     storing into a DIFFERENT field of the same struct does not fire.
//
// At the call site we reuse the field_forward.go aliasing primitives
// (addrPath / pathsAlias) to ask, in the CALLER: "was the receiver's field at
// this exact path assigned a value that traces back to a caller source?"  If
// yes, we emit a flow whose source is the caller param and whose sink is the
// callee-side sink the receiver field reaches.
//
// Precision discipline (mirrors field_forward.go):
//   - The receiver field path must match step-for-step (field index sensitive;
//     index-insensitive on collection elements). `o.Other = src; recv.Q sink`
//     does NOT fire.
//   - The construction-site receiver must resolve to a LOCAL Alloc whose
//     aliasing stores we can see in the caller; receivers obtained from
//     params/globals/returns are out of scope here (no over-reach).
//   - The stored value must trace to a caller SOURCE param (or pointer-root)
//     via the same reaches() walk every other lane uses — sanitizers prune it.

// recvFieldSink records that a method reaches a catalog sink through a
// specific field-access path rooted at its receiver. `path` is the field
// selector chain from the receiver to the value that flows into the sink
// (root-first, the same orientation field_forward.go uses).
type recvFieldSink struct {
	path []fieldSelector
	rec  paramSinkRecord
}

// computeReceiverFieldSinks walks fn (a method) and records, for every sink
// call inside it, the field-access path from the receiver to the sink's
// dangerous argument. Returns nil for non-methods or methods that reach no
// sink through the receiver.
//
// This is the receiver analogue of computeSummary's paramSinks loop, but it
// resolves the dangerous arg to a (receiver, field-path) pair instead of a
// source-level parameter index — making the eventual construction-site match
// field-sensitive.
func computeReceiverFieldSinks(
	fn *ssa.Function,
	matcher *catalogMatcher,
	fset *token.FileSet,
) []recvFieldSink {
	if fn == nil || fn.Blocks == nil || fn.Signature == nil || fn.Signature.Recv() == nil {
		return nil
	}
	if len(fn.Params) == 0 {
		return nil
	}
	recv := fn.Params[0] // SSA places the receiver at param index 0.

	var out []recvFieldSink
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			// ssa.CallInstruction also matches `go f(x)` / `defer f(x)`, so a
			// receiver-field value reaching a goroutine or deferred sink is
			// recorded like any other.
			ci, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			common := ci.Common()
			sink, dangerous := matcher.matchSink(common)
			if sink == nil {
				continue
			}
			args := common.Args
			for _, pos := range dangerous {
				if pos < 0 || pos >= len(args) {
					continue
				}
				visited := make(map[ssa.Value]bool)
				if path, found := reachesReceiverField(args[pos], recv, visited, 0, matcher, *sink); found {
					deepPos := fset.Position(ci.Pos())
					out = append(out, recvFieldSink{
						path: path,
						rec: paramSinkRecord{
							sink:             *sink,
							sinkLine:         positionLineOrZero(fset, ci.Pos()),
							sinkCallSiteName: callShortName(ci),
							deepSinkFile:     deepPos.Filename,
							deepSinkLine:     deepPos.Line,
						},
					})
				}
			}
		}
	}
	return out
}

// reachesReceiverField walks v backward through def-use chains looking for a
// load off the receiver via a field-access path (`*(&recv.F...)`). On a hit it
// returns the field path (root-first) from the receiver to v.
//
// It deliberately ONLY follows the field-load shape — it does not chase
// general operand chains the way reaches() does — because the construction-
// site match needs the precise field path, and a hit on the whole receiver
// (path == nil, i.e. the sink consumes `recv` itself) is intentionally NOT a
// receiver-FIELD flow and is left to the existing index lanes. This keeps the
// new lane purely additive and field-precise.
func reachesReceiverField(
	v ssa.Value,
	recv ssa.Value,
	visited map[ssa.Value]bool,
	depth int,
	matcher *catalogMatcher,
	sink taint.SinkDef,
) ([]fieldSelector, bool) {
	if v == nil || depth > maxDefUseDepth {
		return nil, false
	}
	if isUntaintableSSAValue(v) {
		return nil, false
	}
	if visited[v] {
		return nil, false
	}
	visited[v] = true

	// Sanitizer prune: a sanitizer call result breaks the chain (same rule
	// every other walker applies).
	if call, ok := v.(*ssa.Call); ok {
		if sink.Category != "" && matcher.callIsSanitizerFor(call, sink.Category) {
			return nil, false
		}
	}

	// Direct hit: v is a load off a receiver-rooted field-address chain.
	// addrPath only bottoms out at Alloc/Global roots, but the receiver is
	// an *ssa.Parameter, so we use the receiver-aware resolver here.
	if load, ok := v.(*ssa.UnOp); ok && load.Op == token.MUL {
		if path, ok := receiverAddrPath(load.X, recv); ok && len(path) > 0 {
			return path, true
		}
	}

	// Otherwise recurse through operands so intermediate copies (phi, binop
	// on a single field, conversions) still resolve to the receiver field.
	for _, op := range operands(v) {
		if op == nil || *op == nil {
			continue
		}
		if path, found := reachesReceiverField(*op, recv, visited, depth+1, matcher, sink); found {
			return path, true
		}
	}
	return nil, false
}

// receiverAddrPath resolves a field-address chain (`&recv.F.G…`) that bottoms
// out at the given receiver value, returning the field-selector path root-
// first. Unlike addrPath (which only accepts Alloc/Global roots), it bottoms
// out at `recv` by pointer identity — the receiver is an *ssa.Parameter. The
// returned path uses the SAME fieldSelector orientation as addrPath so
// pathsAlias can compare a receiver-side path against a construction-site
// (Alloc-rooted) path directly.
func receiverAddrPath(addr ssa.Value, recv ssa.Value) ([]fieldSelector, bool) {
	cur := addr
	var rev []fieldSelector
	for hops := 0; hops < 32; hops++ {
		if cur == recv {
			path := make([]fieldSelector, len(rev))
			for i := range rev {
				path[len(rev)-1-i] = rev[i]
			}
			return path, true
		}
		switch n := cur.(type) {
		case *ssa.FieldAddr:
			rev = append(rev, fieldSelector{isIndex: false, field: n.Field})
			cur = n.X
		case *ssa.IndexAddr:
			rev = append(rev, fieldSelector{isIndex: true})
			cur = n.X
		default:
			return nil, false
		}
	}
	return nil, false
}

// emitReceiverRootedFlows is the construction-site emission lane. For each
// call site inside fn, if the static callee is a method whose summary records
// a receiver-field sink, and the call's receiver argument is a local Alloc
// whose matching field was assigned a value tracing to a caller source, emit a
// cross-function TaintFlow.
//
// This lane is additive and orthogonal to emitCrossFunctionFlows: it keys on
// recvFieldSinks (receiver-rooted) where that one keys on paramSinks
// (positional-arg-rooted). The shared seenDeep map dedups a receiver-rooted
// flow against an index-rooted flow that happens to reach the same leaf sink
// with the same source.
func emitReceiverRootedFlows(
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

	// Caller-side source params (typed sources) — the same source surface
	// analyzeFunction and emitCrossFunctionFlows use. (Pointer-root /
	// bind-into-field-at-construction is intentionally out of scope for this
	// lane; the typed-source-param case is the demonstrated shape.)
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

	var flows []taint.TaintFlow
	seen := make(map[recvFlowKey]bool)

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			callee := call.Common().StaticCallee()
			if callee == nil {
				continue
			}
			sum := summaries[callee]
			if sum == nil || len(sum.recvFieldSinks) == 0 {
				continue
			}
			// The receiver argument is source-level arg 0 of a method call.
			args := call.Common().Args
			if len(args) == 0 {
				continue
			}
			recvArg := args[0]
			// Only local Allocs let us see the construction-site stores; a
			// receiver from a param/global/return is out of scope (no over-
			// reach). addrPath bottoms out at the Alloc with an empty path.
			recvRoot, recvBase, ok := addrPath(recvArg)
			if !ok || len(recvBase) != 0 {
				continue
			}
			if _, isAlloc := recvRoot.(*ssa.Alloc); !isAlloc {
				continue
			}

			for _, rfs := range sum.recvFieldSinks {
				// Find aliasing stores into the receiver's field at the
				// callee-recorded path, and check whether any stored value
				// traces to a caller source.
				reached, path := storedValueReachesSource(
					fn, recvRoot, rfs.path, paramSources, matcher, rfs.rec.sink)
				if reached == nil {
					continue
				}
				src := paramSources[reached]
				if src == nil {
					continue
				}
				key := recvFlowKey{
					callerFn: fn,
					calleeFn: callee,
					sinkID:   rfs.rec.sink.ID,
				}
				if seen[key] {
					continue
				}
				seen[key] = true

				sourceLine := positionLineOrZero(fset, reached.Pos())
				if rfs.rec.deepSinkFile != "" && seenDeep != nil {
					deepKey := newCrossSinkKey(rfs.rec, *src, filePath, sourceLine)
					if seenDeep[deepKey] {
						continue
					}
					seenDeep[deepKey] = true
				}
				flow := buildCrossFlow(fn, call, callee, *src, rfs.rec, reached, path, fset, filePath, scopeName)
				flows = append(flows, flow)
			}
		}
	}
	return flows
}

// recvFlowKey dedups receiver-rooted emissions within a single caller.
type recvFlowKey struct {
	callerFn *ssa.Function
	calleeFn *ssa.Function
	sinkID   string
}

// storedValueReachesSource scans fn for Store instructions whose address
// aliases the receiver Alloc's field at fieldPath, and for each such store
// checks whether the stored value traces back to a caller source param (or
// pointer-root). Returns the reaching source value and the operand path for
// flow rendering, or (nil, nil).
//
// This reuses the field_forward.go aliasing primitives (addrPath/pathsAlias)
// to resolve "&construction.Field" against "&receiverArg.Field" by Alloc
// identity + field path, then the standard reaches walk for source tracing.
func storedValueReachesSource(
	fn *ssa.Function,
	recvRoot ssa.Value,
	fieldPath []fieldSelector,
	paramSources map[ssa.Value]*taint.SourceDef,
	matcher *catalogMatcher,
	sink taint.SinkDef,
) (ssa.Value, []ssa.Value) {
	if fn == nil || fn.Blocks == nil {
		return nil, nil
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			st, ok := instr.(*ssa.Store)
			if !ok || st.Val == nil {
				continue
			}
			sRoot, sPath, ok := addrPath(st.Addr)
			if !ok {
				continue
			}
			if !pathsAlias(recvRoot, fieldPath, sRoot, sPath) {
				continue
			}
			// The stored value is the construction-site RHS. Trace it to a
			// caller source via the standard backward walk (sanitizers prune).
			visited := make(map[ssa.Value]bool)
			if reachedParam, path := reaches(st.Val, paramSources, visited, 0, matcher, sink); reachedParam != nil {
				return reachedParam, path
			}
		}
	}
	return nil, nil
}
