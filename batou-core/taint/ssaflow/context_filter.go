package ssaflow

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// isContextParamType reports whether t is `context.Context` (or, defensively,
// a pointer to it). Such parameters are plumbing — they carry cancellation /
// deadline metadata, never user-controlled string data — and must not be
// treated as taint sources by the SSA engine. Without this filter the
// cross-function fixed-point can trace data through a ctx parameter (because
// every non-receiver param is indexed for reachability) and synthesise
// "ctx (arg 0) → Controller.Update → sql.Query" style false positives on
// handler → controller → db chains, which is the dominant FP class observed
// on harness scans run with BATOU_SSAFLOW=1 BATOU_GOTYPES_RESOLVER=1.
//
// This mirrors graph/interprocedural.go's isContextParamType (introduced in
// PR-M for the regex/AST interproc path). The SSA engine needs its own copy
// because it inspects go/types.Type values, not source-level parameter
// strings.
func isContextParamType(t types.Type) bool {
	if t == nil {
		return false
	}
	s := canonicalGoTypeString(t)
	return isContextTypeString(s)
}

// isContextTypeString is the string-comparison core of isContextParamType,
// pulled out so tests can pin the matched strings without constructing a
// go/types.Type. Accepts the canonical form produced by
// canonicalGoTypeString — i.e. short package name, leading `*` preserved
// for pointer types. The bare "Context" form is matched too because
// imports that dot-import "context" (uncommon but legal) drop the package
// qualifier from the canonical type string.
func isContextTypeString(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "*")
	return s == "context.Context" || s == "Context"
}

// calleeParamIsContext reports whether the source-level parameter at
// position paramIdx of fn is typed context.Context. paramIdx is the
// receiver-excluded index used throughout the cross-function propagator —
// matching the catalog's DangerousArgs convention and funcSummary.paramSinks
// key semantics. Returns false on any out-of-range lookup so callers can
// use the result unconditionally as a "skip this callee param" guard.
//
// This is the call-site equivalent of the source-param filter: even if a
// callee's summary records `paramSinks[i]` for some reason, when the i-th
// source-level parameter of the callee is context.Context the caller must
// not surface a flow through arg i. Same plumbing-not-data rationale as
// isContextParamType.
func calleeParamIsContext(fn *ssa.Function, paramIdx int) bool {
	if fn == nil || paramIdx < 0 {
		return false
	}
	offset := 0
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		offset = 1
	}
	ssaIdx := paramIdx + offset
	if ssaIdx >= len(fn.Params) {
		return false
	}
	p := fn.Params[ssaIdx]
	if p == nil {
		return false
	}
	return isContextParamType(p.Type())
}
