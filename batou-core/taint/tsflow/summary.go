package tsflow

import "github.com/turenlabs/batou-core/taint"

// paramSinkSite records a sink a parameter reaches inside its function body,
// captured during the pass-1 per-parameter summary walk. The sink def carries
// the CWE / category / rule metadata; sinkLine is the line within the callee
// where the sink fires (used for the interprocedural flow's sink step). The
// captured taint steps describe the in-callee path (param -> ... -> sink) so
// the emitted finding shows the full chain.
type paramSinkSite struct {
	sink     *taint.SinkDef
	sinkLine int
	steps    []taint.FlowStep
}

// returnsSourceInfo captures a catalog taint SOURCE whose value reaches a
// return statement of a local function with no parameter seeding — e.g.
//
//	def get_q(): return request.args.get('q')
//
// Such a function manufactures taint from nothing, so its call sites must be
// tainted even when no tainted argument is passed (the param-indexed fields of
// TaintSummary cannot express this — they only model taint entering via
// parameters). Without it, a local source-returning function is strictly WORSE
// than an unknown external one: the local-summary early return suppresses even
// the conservative arg-propagation fallback, yielding zero flows.
type returnsSourceInfo struct {
	// source is the catalog source matched inside the callee body.
	source *taint.SourceDef
	// sourceLine is the callee-local line where the source was read.
	sourceLine int
	// confidence is the in-callee confidence of the returned value, decayed
	// by branchSingleWeight when only some return paths carry the source.
	confidence float64
	// sanitized holds sink categories neutralized on EVERY source-carrying
	// return path (intersection, mirroring returnSanitizedCategories) — so
	// `return escape(request.args.get('q'))` stays tainted for SQL but not
	// for HTML output.
	sanitized map[taint.SinkCategory]bool
	// steps is a representative in-callee step trail (source → return).
	steps []taint.FlowStep
}

// taintStateFor materializes a caller-side taint state for an assignment
// `lhs = callee()` from the callee's returns-source summary. The in-callee
// steps are preserved and a call-site hop step is appended; confidence takes
// the standard 0.85 interprocedural hop decay (mirroring the param-propagation
// path in propagateCallResultInterproc). The sanitized map and steps are
// copied so per-call-site mutation never aliases the shared summary.
func (rs *returnsSourceInfo) taintStateFor(lhsName string, line int, callName string) *taintState {
	san := make(map[taint.SinkCategory]bool, len(rs.sanitized))
	for k, v := range rs.sanitized {
		san[k] = v
	}
	steps := make([]taint.FlowStep, len(rs.steps), len(rs.steps)+1)
	copy(steps, rs.steps)
	steps = append(steps, taint.FlowStep{
		Line:        line,
		Description: "returned by " + callName + "()",
		VarName:     lhsName,
	})
	return &taintState{
		varName:    lhsName,
		source:     rs.source,
		sourceLine: rs.sourceLine,
		sanitized:  san,
		confidence: rs.confidence * 0.85,
		steps:      steps,
	}
}

// TaintSummary captures rich dataflow information for a local function:
// which parameters propagate to the return value, and which sink categories
// each parameter can reach. This enables context-sensitive interprocedural
// analysis — only tainted arguments at call sites propagate taint, not all
// arguments indiscriminately.
type TaintSummary struct {
	FuncName string

	// ReturnsSource is non-nil when the function body reads a catalog taint
	// source and that value reaches a return statement WITHOUT any parameter
	// seeding (`def get_q(): return request.args.get('q')`). Call sites seed
	// the assignment LHS from it even when no tainted argument is passed.
	ReturnsSource *returnsSourceInfo

	// ParamFlows[i] maps sink categories reachable from parameter i.
	// nil means parameter i does not propagate taint to any return or sink.
	ParamFlows []map[taint.SinkCategory]bool

	// ParamSinks[i] maps each sink category reachable from parameter i to a
	// representative sink site (sink def + callee-local line + in-callee taint
	// steps). This lets a caller emit an interprocedural finding at the call
	// site — callee(tainted_arg) — when the corresponding parameter reaches a
	// dangerous sink inside the callee. nil/empty when parameter i reaches no
	// sink. Populated only for sinks the per-parameter pass-1 walk actually
	// confirmed (so inline sanitizers / safe-form gates already pruned it),
	// which keeps the call-site emission free of false positives.
	ParamSinks []map[taint.SinkCategory]paramSinkSite

	// ReturnTaint maps parameter index → true when that parameter's taint
	// flows to a return statement.
	ReturnTaint map[int]bool

	// Sanitizes maps parameter index → set of sink categories that the
	// function sanitizes for that parameter before returning.
	Sanitizes map[int]map[taint.SinkCategory]bool

	// IsPure means no parameter reaches any sink (function has no side effects
	// from a taint perspective).
	IsPure bool
}

// paramPropagates returns true if the given parameter index propagates taint
// to the return value.
func (s *TaintSummary) paramPropagates(paramIdx int) bool {
	if s.ReturnTaint == nil {
		return false
	}
	return s.ReturnTaint[paramIdx]
}

// sanitizedCategories returns the set of sink categories sanitized for the
// given parameter index. Returns nil if no sanitization is recorded.
func (s *TaintSummary) sanitizedCategories(paramIdx int) map[taint.SinkCategory]bool {
	if s.Sanitizes == nil {
		return nil
	}
	return s.Sanitizes[paramIdx]
}

// paramSinkSites returns the sink sites reachable from the given parameter
// index (category → representative sink). Returns nil when the parameter
// reaches no sink. Used to emit interprocedural findings at a call site when a
// tainted argument flows into a parameter that reaches a dangerous sink inside
// the callee.
func (s *TaintSummary) paramSinkSites(paramIdx int) map[taint.SinkCategory]paramSinkSite {
	if paramIdx < 0 || paramIdx >= len(s.ParamSinks) {
		return nil
	}
	return s.ParamSinks[paramIdx]
}

// anyParamPropagates returns true if any parameter propagates to return.
// This is the backwards-compatible check equivalent to the old boolean map.
func (s *TaintSummary) anyParamPropagates() bool {
	for _, v := range s.ReturnTaint {
		if v {
			return true
		}
	}
	return false
}
