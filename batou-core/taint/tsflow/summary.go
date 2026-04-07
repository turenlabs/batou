package tsflow

import "github.com/turenlabs/batou-core/taint"

// TaintSummary captures rich dataflow information for a local function:
// which parameters propagate to the return value, and which sink categories
// each parameter can reach. This enables context-sensitive interprocedural
// analysis — only tainted arguments at call sites propagate taint, not all
// arguments indiscriminately.
type TaintSummary struct {
	FuncName string

	// ParamFlows[i] maps sink categories reachable from parameter i.
	// nil means parameter i does not propagate taint to any return or sink.
	ParamFlows []map[taint.SinkCategory]bool

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
