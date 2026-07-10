package ssaflow

import (
	"go/token"
	"go/types"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/languages"
	"golang.org/x/tools/go/ssa"
)

// analyzeFunction is the per-function intra-procedural pass.
//
// For each ssa.Call in the function:
//  1. match the static callee against the sink catalog (by package + method);
//  2. for each dangerous arg position, walk operands backward through
//     def-use chains, halting at parameters, free variables, sanitizer
//     returns, and a depth cap;
//  3. if any reached value is a function parameter whose canonical type is in
//     the Go source catalog, emit a TaintFlow.
func analyzeFunction(fn *ssa.Function, fset *token.FileSet, filePath string, matcher *catalogMatcher) []taint.TaintFlow {
	if fn == nil || fn.Blocks == nil {
		return nil
	}

	// Identify source parameters (typed as a known Go source type).
	paramSources := make(map[ssa.Value]*taint.SourceDef, len(fn.Params))
	for _, p := range fn.Params {
		if src := paramSource(p); src != nil {
			paramSources[p] = src
		}
	}

	// Forward pass: capture pointer-roots produced by sources with a
	// non-empty WritesArg (bind/parser methods that mutate `&out`).
	// This pass runs even when paramSources is empty — a helper that
	// receives no typed source but still invokes a bind method on a
	// passed-in context still produces a tainted pointee. The pointer
	// roots are keyed by the underlying address (Alloc), so subsequent
	// loads off that Alloc resolve to the bind call as the source.
	pointerRoots := collectPointerRoots(fn, matcher, fset)

	if len(paramSources) == 0 && len(pointerRoots) == 0 {
		return nil // No tainted entry point in this function — nothing intra-procedural to find.
	}

	scopeName := fn.Name()
	if recv := fn.Signature.Recv(); recv != nil {
		scopeName = receiverTypeString(recv.Type()) + "." + scopeName
	}

	var flows []taint.TaintFlow

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			// ssa.CallInstruction matches regular calls (*ssa.Call) as well as
			// `go f(x)` (*ssa.Go) and `defer f(x)` (*ssa.Defer) — a sink
			// invoked in a goroutine or deferred call is just as reachable
			// from a tainted argument as a direct call.
			ci, isCall := instr.(ssa.CallInstruction)
			if !isCall {
				continue
			}
			common := ci.Common()
			sink, dangerousPositions := matcher.matchSink(common)
			if sink == nil {
				continue
			}
			args := common.Args
			for _, pos := range dangerousPositions {
				if pos < 0 || pos >= len(args) {
					continue
				}
				arg := args[pos]
				// When the function has pointer-roots, walk with the
				// pointer-aware variant so loads off tainted pointees
				// can short-circuit the search. Otherwise fall back to
				// the parameter-only reaches() to keep the behaviour
				// identical for handlers without bind calls.
				if len(pointerRoots) > 0 {
					visited := make(map[ssa.Value]bool)
					reachedParam, ptrRoot, path := reachesWithPointer(arg, paramSources, pointerRoots, visited, 0, matcher, *sink)
					if ptrRoot != nil {
						flow := buildPointerFlow(fn, ci, ptrRoot, *sink, path, fset, filePath, scopeName)
						flows = append(flows, flow)
						break
					}
					if reachedParam != nil {
						src := paramSources[reachedParam]
						flow := buildFlow(fn, ci, *src, *sink, reachedParam, path, fset, filePath, scopeName)
						flows = append(flows, flow)
						break
					}
					continue
				}
				visited := make(map[ssa.Value]bool)
				if reachedParam, path := reaches(arg, paramSources, visited, 0, matcher, *sink); reachedParam != nil {
					src := paramSources[reachedParam]
					flow := buildFlow(fn, ci, *src, *sink, reachedParam, path, fset, filePath, scopeName)
					flows = append(flows, flow)
					// One flow per (sink, arg) pair is enough; further hops
					// through the same operand chain would duplicate.
					break
				}
			}
		}
	}

	return flows
}

// paramSource returns the SourceDef for a function parameter whose declared
// type matches a Go source-type catalog entry, or nil. Receiver parameters
// are also checked — handlers attached to a frameworks router context can
// arrive as receivers in some idioms (e.g. (c *gin.Context).Bind), but the
// common case is positional params.
//
// context.Context parameters are filtered out unconditionally — see
// isContextParamType. Even though KnownGoSourceTypes does not currently
// list context.Context, this guard protects against future catalog
// expansions or fuzzy type-matching from accidentally promoting ctx to a
// taint source.
func paramSource(p *ssa.Parameter) *taint.SourceDef {
	if isContextParamType(p.Type()) {
		return nil
	}
	canon := canonicalGoTypeString(p.Type())
	cat, ok := languages.LookupGoSourceType(canon)
	if !ok {
		return nil
	}
	return &taint.SourceDef{
		ID:          "go.param.type." + canon,
		Category:    cat,
		Pattern:     canon,
		ObjectType:  canon,
		MethodName:  p.Name(),
		Description: "function parameter of type " + canon,
		Assigns:     "return",
	}
}

// reaches walks backward through SSA def-use chains starting from v, looking
// for any value in roots. The path slice (operand → operand) is returned so
// callers can render flow steps. Stops at sanitizer returns: when the value
// being examined is the result of a call to a sanitizer applicable to the
// sink category, the search is pruned (sanitizer breaks the chain).
func reaches(
	v ssa.Value,
	roots map[ssa.Value]*taint.SourceDef,
	visited map[ssa.Value]bool,
	depth int,
	matcher *catalogMatcher,
	sink taint.SinkDef,
) (ssa.Value, []ssa.Value) {
	if v == nil || depth > maxDefUseDepth {
		return nil, nil
	}
	// Filter SSA constants and stdlib globals up front: they cannot carry
	// user-controlled data, so reaching one terminates the walk without a
	// hit. Skipping them also prevents the walker from synthesising flows
	// rooted at literals like http.StatusBadRequest.
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

	// Sanitizer prune: if v is the return of a sanitizer call that
	// neutralizes our sink category, do not look further inside its operands.
	if call, ok := v.(*ssa.Call); ok {
		if matcher.callIsSanitizerFor(call, sink.Category) {
			return nil, nil
		}
	}

	for _, op := range operands(v) {
		if op == nil || *op == nil {
			continue
		}
		if hit, path := reaches(*op, roots, visited, depth+1, matcher, sink); hit != nil {
			return hit, append(path, v)
		}
	}
	// Store-to-load forwarding: when v is a load off a local aggregate
	// (struct/array) that the SSA lifter could not promote to registers,
	// the values stored into the aliasing cell are extra data dependencies
	// the operand walk above cannot see (load and store share an address,
	// not an SSA operand edge). See field_forward.go.
	for _, sv := range storeForwardedValues(v) {
		if hit, path := reaches(sv, roots, visited, depth+1, matcher, sink); hit != nil {
			return hit, append(path, v)
		}
	}
	return nil, nil
}

// operands returns the operand pointers of an SSA value/instruction we want
// to recurse into. For most instructions we use the SSA framework's Operands
// helper, but a handful of values (e.g. *ssa.Phi, *ssa.Extract) need their
// edges treated as operand sources too.
func operands(v ssa.Value) []*ssa.Value {
	if instr, ok := v.(ssa.Instruction); ok {
		// instr.Operands(nil) returns the operand pointers (excluding receiver
		// in BinOp etc., but those are still data dependencies for taint).
		return instr.Operands(nil)
	}
	return nil
}

// buildFlow constructs a taint.TaintFlow describing a source→sink path.
//
// The Steps slice is summarised — one step per hop in the SSA chain we
// traversed, capped at a short head/tail rendering — so the reporter can
// show the path without an unbounded sequence of synthetic SSA names.
func buildFlow(
	fn *ssa.Function,
	call ssa.CallInstruction,
	src taint.SourceDef,
	sink taint.SinkDef,
	param ssa.Value,
	path []ssa.Value,
	fset *token.FileSet,
	filePath string,
	scopeName string,
) taint.TaintFlow {
	srcLine := positionLine(fset, fn.Pos())
	if p, ok := param.(*ssa.Parameter); ok {
		srcLine = positionLine(fset, p.Pos())
	}
	sinkLine := positionLine(fset, call.Pos())

	steps := make([]taint.FlowStep, 0, len(path))
	// path is sink-first, source-last. Reverse to source→sink for readability.
	for i := len(path) - 1; i >= 0; i-- {
		v := path[i]
		line := positionLine(fset, v.Pos())
		steps = append(steps, taint.FlowStep{
			Line:        line,
			Description: ssaStepDescription(v),
			VarName:     ssaValueName(v),
		})
	}

	return taint.TaintFlow{
		Source:     src,
		Sink:       sink,
		SourceLine: srcLine,
		SinkLine:   sinkLine,
		Steps:      steps,
		FilePath:   filePath,
		ScopeName:  scopeName,
		Confidence: confidenceSSAIntraProc,
	}
}

// ssaStepDescription renders a short, human-readable label for an SSA value
// used in a flow step. Specialised for the common cases (parameter, field
// load, call result, phi, binop) so the resulting TaintPath reads like a
// normal taint trace rather than dumping SSA print form.
func ssaStepDescription(v ssa.Value) string {
	switch n := v.(type) {
	case *ssa.Parameter:
		return "parameter " + n.Name() + " of type " + canonicalGoTypeString(n.Type())
	case *ssa.FreeVar:
		return "free variable " + n.Name()
	case *ssa.Call:
		if cal := n.Common().StaticCallee(); cal != nil {
			return "return value of " + cal.RelString(nil)
		}
		return "return value of indirect call"
	case *ssa.FieldAddr:
		return "field access " + fieldName(n.X.Type(), n.Field)
	case *ssa.Field:
		return "field access " + fieldName(n.X.Type(), n.Field)
	case *ssa.IndexAddr, *ssa.Index:
		return "index access"
	case *ssa.UnOp:
		return "unary op " + n.Op.String()
	case *ssa.BinOp:
		return "binary op " + n.Op.String()
	case *ssa.Phi:
		return "phi merge"
	case *ssa.Convert:
		return "type conversion"
	case *ssa.MakeInterface:
		return "interface boxing"
	}
	return "ssa value"
}

// ssaValueName returns the short name an SSA value carries in its Name()
// method (e.g. "t3", "x", or empty for constants). The caller uses this as
// a stable identifier for the reporter's variable column.
func ssaValueName(v ssa.Value) string {
	if v == nil {
		return ""
	}
	return v.Name()
}

// receiverTypeString renders the receiver type of a method as a short string
// suitable for scope names ("*MyType" or "MyType").
func receiverTypeString(t types.Type) string {
	return canonicalGoTypeString(t)
}

// fieldName returns the Go-level name of the i'th field of t (after pointer
// indirection), or "" when t is not a struct.
func fieldName(t types.Type, i int) string {
	t = derefAll(t)
	st, ok := t.Underlying().(*types.Struct)
	if !ok || i < 0 || i >= st.NumFields() {
		return ""
	}
	return st.Field(i).Name()
}

func derefAll(t types.Type) types.Type {
	for {
		p, ok := t.(*types.Pointer)
		if !ok {
			return t
		}
		t = p.Elem()
	}
}

func positionLine(fset *token.FileSet, pos token.Pos) int {
	if !pos.IsValid() {
		return 0
	}
	return fset.Position(pos).Line
}

// canonicalGoTypeString renders a types.Type into the canonical string used
// by KnownGoSourceTypes ("*http.Request", "*gin.Context", "io.Reader" …).
// types.TypeString already produces this form when the qualifier returns
// just the package name (Pkg.Name()) — exactly the convention astflow's
// catalog uses.
func canonicalGoTypeString(t types.Type) string {
	if t == nil {
		return ""
	}
	qual := func(p *types.Package) string {
		if p == nil {
			return ""
		}
		return p.Name()
	}
	s := types.TypeString(t, qual)
	// Some SSA-generated types come back with leading whitespace or
	// surrounding parens (rare; defensive normalisation).
	s = strings.TrimSpace(s)
	return s
}
