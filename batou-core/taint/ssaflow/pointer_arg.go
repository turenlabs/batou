package ssaflow

import (
	"go/token"

	"github.com/turenlabs/batou-core/taint"
	"golang.org/x/tools/go/ssa"
)

// pointerArg.go implements PR-DD: pointer-arg taint propagation.
//
// Many request-binding APIs do not return the parsed payload — they
// decode it into a destination pointer the caller supplies:
//
//	var in In
//	_ = c.ShouldBindXML(&in)    // gin
//	_ = c.QueryParser(&in)      // fiber
//	_ = c.Bind(&in)             // echo
//
// The base SSA engine in analyze.go walks BACK from each sink-call's
// dangerous argument and looks for source-typed parameters or call
// returns. A read like `in.Name` materialises in SSA as a FieldAddr+Load
// off the local Alloc of `in`. There is no operand path from that load
// back to the request context, so the base engine misses the flow.
//
// This file adds a forward pass executed once per function before the
// backward walk: for each ssa.Call that matches a SourceDef with a
// non-empty WritesArg, we capture the SSA value passed at each WritesArg
// position. That value's pointee (the address the call mutates) is then
// recorded in a per-function tainted-pointer set, along with the original
// source and the call site. The backward walker treats any read that
// dereferences a tainted pointer (UnOp '*' over a tainted address, or a
// FieldAddr/IndexAddr/Field/Index whose base resolves to a tainted
// address) as a synthetic root contributed by that source.
//
// Scope limits documented in CLAUDE.md / the PR description:
//   - Only direct ssa.Call sites with a statically resolvable callee
//     participate. Interface dispatch and closures returning the bind
//     method are out of scope.
//   - The pointer-arg taint is whole-pointee — we do not distinguish
//     which field of the struct was decoded. This matches reality for
//     bind/parser methods which populate the whole destination.
//   - Receiver-mutating methods (r.ParseForm() — populates r.Form,
//     which is a field of the receiver) are NOT modelled here; the
//     receiver is already a typed source so subsequent r.Form reads
//     are already tainted via the parameter mechanism.
//   - Decoder-chain idioms (`json.NewDecoder(r.Body).Decode(&in)`) are
//     not handled: the chained call is not in the catalog as a single
//     source. The user is expected to use the framework Bind methods
//     for the common case.

// pointerRoot describes one tainted pointee captured at a source call.
type pointerRoot struct {
	// ptr is the SSA value that holds the address whose pointee is
	// tainted (typically a *ssa.Alloc from a local var declaration, or
	// a *ssa.FieldAddr when the destination is a struct field).
	ptr ssa.Value
	// src is the SourceDef that owns the WritesArg position. The flow
	// emitted for any sink consuming the pointee names this source.
	src taint.SourceDef
	// callLine is the line of the source call (e.g. the line where
	// c.ShouldBindXML(&in) appears). Used as SourceLine on the flow.
	callLine int
	// callValue is the actual ssa.Call so flow-step rendering can
	// reference the method's short name.
	callValue *ssa.Call
}

// collectPointerRoots performs the forward pass: scan every call in fn
// and record pointer-roots for any source with WritesArg. Returns an
// empty map (not nil) when fn has no such calls; callers can range over
// it unconditionally.
func collectPointerRoots(
	fn *ssa.Function,
	matcher *catalogMatcher,
	fset *token.FileSet,
) map[ssa.Value]*pointerRoot {
	roots := make(map[ssa.Value]*pointerRoot)
	if fn == nil || fn.Blocks == nil || matcher == nil || len(matcher.writeSources) == 0 {
		return roots
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			src, positions := matcher.matchWriteSource(call)
			if src == nil {
				continue
			}
			args := call.Common().Args
			line := positionLine(fset, call.Pos())
			for _, pos := range positions {
				if pos < 0 || pos >= len(args) {
					continue
				}
				ptr := normalizePointerArg(args[pos])
				if ptr == nil {
					continue
				}
				// Multiple bind calls into the same pointee are fine;
				// keep the first one for stable SourceLine reporting,
				// since downstream dedup will collapse duplicate flows.
				if _, exists := roots[ptr]; exists {
					continue
				}
				roots[ptr] = &pointerRoot{
					ptr:       ptr,
					src:       *src,
					callLine:  line,
					callValue: call,
				}
			}
		}
	}
	return roots
}

// normalizePointerArg unwraps SSA conversions that wrap a pointer
// argument without losing its identity (e.g. MakeInterface for a method
// that takes `any`). Returns nil when the argument cannot be reduced to
// a pointer-shaped SSA value — in that case the writer's effect cannot
// be tracked precisely so we skip it (graceful loss of recall rather
// than a false positive).
//
// For the typical `c.ShouldBindXML(&in)` idiom, SSA generates
// `args[0] = MakeInterface(local *In)` because Bind* takes `any`. We
// peel that interface boxing off and return the underlying Alloc so
// later FieldAddr operations off the Alloc match the tainted-pointer
// set by identity.
func normalizePointerArg(v ssa.Value) ssa.Value {
	for i := 0; i < 8; i++ { // bounded peel — pathological chains can't blow up
		switch n := v.(type) {
		case *ssa.MakeInterface:
			v = n.X
		case *ssa.ChangeType:
			v = n.X
		case *ssa.Convert:
			v = n.X
		default:
			return v
		}
	}
	return v
}

// pointerRootForValue tests whether v (or a chain of FieldAddr / IndexAddr
// / Field / Index operations rooted at v) corresponds to one of the
// tainted-pointer roots. Returns the root and the operand path collected
// during the walk (newest-first, matching the convention of reaches()).
//
// We unwrap FieldAddr/IndexAddr because a load like `in.Name` is a chain:
//
//	t0 = local In         (Alloc, address of `in`)
//	t1 = &t0.Name [#0]    (FieldAddr off t0)
//	t2 = *t1              (UnOp '*' load)
//
// When we are walking backward from a sink-arg and reach t2 (a load),
// the existing reaches() walks into t1 (FieldAddr) and would walk into
// t0 (Alloc) but t0 is not a source param, so the chain dies. With this
// helper we look at the chain of FieldAddr/IndexAddr operands; if the
// base is in `roots`, the load is treated as a synthetic root.
func pointerRootForValue(v ssa.Value, roots map[ssa.Value]*pointerRoot) (*pointerRoot, []ssa.Value) {
	if len(roots) == 0 {
		return nil, nil
	}
	path := []ssa.Value{}
	cur := v
	for hops := 0; hops < 16; hops++ {
		if cur == nil {
			return nil, nil
		}
		if r, ok := roots[cur]; ok {
			return r, path
		}
		// Also try the normalised form: callers sometimes pass us a
		// ChangeType/Convert wrapping the same Alloc.
		if nv := normalizePointerArg(cur); nv != cur {
			if r, ok := roots[nv]; ok {
				return r, path
			}
		}
		switch n := cur.(type) {
		case *ssa.FieldAddr:
			// &x.f off a tainted pointee yields another tainted pointee.
			path = append(path, cur)
			cur = n.X
		case *ssa.IndexAddr:
			// &a[i] off a tainted array/slice base is similarly tainted.
			path = append(path, cur)
			cur = n.X
		case *ssa.UnOp:
			// Dereference: *ptr loads the value behind ptr. When ptr is
			// itself a chain off a tainted pointee (e.g. `*(&in.Inner)`),
			// peel the dereference and keep walking. Other UnOps (neg,
			// receive, etc.) are not pointer-shaped — stop the walk.
			if n.Op != token.MUL {
				return nil, nil
			}
			path = append(path, cur)
			cur = n.X
		default:
			return nil, nil
		}
	}
	return nil, nil
}

// reachesWithPointer is the pointer-aware variant of reaches() used when
// the function has at least one pointer-root. It mirrors the existing
// def-use walk but, at each step, also checks whether v is a load that
// dereferences a tainted pointee — if so, the search succeeds at that
// load and the flow is rooted at the pointer's source.
//
// The function returns either a parameter hit (matching the existing
// reaches() contract) OR a synthetic pointer-root hit. Callers
// distinguish via the second return: when it is non-nil, the flow's
// source is the pointer-root's SourceDef (a bind/parser call); when it
// is nil and the first return is non-nil, the flow's source is the
// parameter's SourceDef (the existing behaviour).
func reachesWithPointer(
	v ssa.Value,
	paramRoots map[ssa.Value]*taint.SourceDef,
	ptrRoots map[ssa.Value]*pointerRoot,
	visited map[ssa.Value]bool,
	depth int,
	matcher *catalogMatcher,
	sink taint.SinkDef,
) (ssa.Value, *pointerRoot, []ssa.Value) {
	if v == nil || depth > maxDefUseDepth {
		return nil, nil, nil
	}
	// Filter SSA constants and stdlib globals so the pointer-aware walker
	// matches the constant-filtering applied by reaches/reachesAnyParam.
	if isUntaintableSSAValue(v) {
		return nil, nil, nil
	}
	if _, ok := paramRoots[v]; ok {
		return v, nil, []ssa.Value{v}
	}
	// Pointer-root check: if v dereferences a tainted pointee, we have
	// found a flow rooted at the source-of-mutation call. The returned
	// path captures every operand we peeled from v down to the
	// root-pointer Alloc, including v itself.
	if r, p := pointerRootForValue(v, ptrRoots); r != nil {
		return nil, r, p
	}
	if visited[v] {
		return nil, nil, nil
	}
	visited[v] = true

	// Sanitizer prune: identical to reaches() in analyze.go.
	if call, ok := v.(*ssa.Call); ok {
		if matcher.callIsSanitizerFor(call, sink.Category) {
			return nil, nil, nil
		}
	}

	for _, op := range operands(v) {
		if op == nil || *op == nil {
			continue
		}
		if hitParam, hitPtr, path := reachesWithPointer(*op, paramRoots, ptrRoots, visited, depth+1, matcher, sink); hitParam != nil || hitPtr != nil {
			return hitParam, hitPtr, append(path, v)
		}
	}
	// Store-to-load forwarding through local aggregates — same rationale as
	// reaches() in analyze.go. This lets a tainted value stored into a local
	// struct/array field reach a sink that loads the same field even in
	// functions that also carry pointer-roots from bind methods.
	for _, sv := range storeForwardedValues(v) {
		if hitParam, hitPtr, path := reachesWithPointer(sv, paramRoots, ptrRoots, visited, depth+1, matcher, sink); hitParam != nil || hitPtr != nil {
			return hitParam, hitPtr, append(path, v)
		}
	}
	return nil, nil, nil
}

// buildPointerFlow constructs a TaintFlow for a sink whose argument
// reaches back to a tainted pointee. The Source field is the
// pointer-root's SourceDef (the bind/parser method), SourceLine is the
// line of that call, and Steps render the operand chain we walked plus
// a synthetic "tainted via pointer-arg of <method>" lead-in step.
func buildPointerFlow(
	fn *ssa.Function,
	call ssa.CallInstruction,
	root *pointerRoot,
	sink taint.SinkDef,
	path []ssa.Value,
	fset *token.FileSet,
	filePath string,
	scopeName string,
) taint.TaintFlow {
	sinkLine := positionLine(fset, call.Pos())
	steps := make([]taint.FlowStep, 0, len(path)+1)
	// Synthetic lead-in: this step makes it obvious in the rendered
	// trace that the taint originates from a pointer-arg mutation
	// rather than an ordinary return value.
	srcName := root.src.MethodName
	if srcName == "" {
		srcName = root.src.ID
	}
	steps = append(steps, taint.FlowStep{
		Line:        root.callLine,
		Description: "pointer-arg mutated by " + srcName,
		VarName:     ssaValueName(root.ptr),
	})
	// The path collected by reachesWithPointer is sink-first / load-last;
	// reverse to source→sink order, matching buildFlow's convention.
	for i := len(path) - 1; i >= 0; i-- {
		v := path[i]
		steps = append(steps, taint.FlowStep{
			Line:        positionLine(fset, v.Pos()),
			Description: ssaStepDescription(v),
			VarName:     ssaValueName(v),
		})
	}

	return taint.TaintFlow{
		Source:     root.src,
		Sink:       sink,
		SourceLine: root.callLine,
		SinkLine:   sinkLine,
		Steps:      steps,
		FilePath:   filePath,
		ScopeName:  scopeName,
		Confidence: confidenceSSAIntraProc,
	}
}
