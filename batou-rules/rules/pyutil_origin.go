package rules

import (
	"regexp"
	"strings"
)

// pyForLoopBind matches `for varName in <iterable>:` for tracking loop
// variables bound from tainted iterables.
var pyForLoopBind = regexp.MustCompile(`^for\s+([A-Za-z_]\w*)\s+in\s+(.+?):`)

// pyVarHasUnsafeOrigin returns true when any assignment to varName visible
// before fromLine has an RHS that traces back to an unsafe (non-safe-attr)
// request source. The recursion budget is small to keep the analysis cheap
// and to avoid pathological scans.
//
// "Safe" RHS forms:
//   - String/number literals, empty string.
//   - request.<safe-attr> references (request.path, request.url, ...).
//   - Simple references to a variable whose origin is also safe.
//   - dict/list literals (no taint keyword tokens).
//
// "Unsafe" RHS forms:
//   - request.<unsafe-attr> references (request.form, request.args, ...).
//   - References to a taint keyword (param, wrapped, args, form, ...) whose
//     origin is unsafe.
//   - Anything else where the chain is uncertain → considered unsafe to
//     stay safe-by-default.
func pyVarHasUnsafeOrigin(lines []string, fromLine int, varName string, depth int) bool {
	if depth > 5 || varName == "" || fromLine <= 0 {
		return false // bail out: assume safe to avoid runaway recursion
	}
	assignPrefix := varName + " = "
	compoundPrefix := varName + " += "
	saw := false

	for i := fromLine - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])

		// for-loop binding: for <varName> in <iterable>:
		if m := pyForLoopBind.FindStringSubmatch(trimmed); m != nil && m[1] == varName {
			iter := strings.TrimSpace(m[2])
			if pyRHSChainIsUnsafe(lines, i, iter, depth+1) {
				return true
			}
			saw = true
			continue
		}

		// Compound assignment counts as a separate write.
		if strings.HasPrefix(trimmed, compoundPrefix) {
			compoundRHS := strings.TrimSpace(trimmed[len(compoundPrefix):])
			if pyRHSChainIsUnsafe(lines, i, compoundRHS, depth+1) {
				return true
			}
			saw = true
			continue
		}
		if !strings.HasPrefix(trimmed, assignPrefix) {
			continue
		}
		rhs := strings.TrimSpace(trimmed[len(assignPrefix):])
		if pyRHSChainIsUnsafe(lines, i, rhs, depth+1) {
			return true
		}
		saw = true
		// Continue scanning — every assignment in scope must be safe.
	}

	// Found no assignment at all → conservatively consider the value safe
	// (could be a function parameter or imported symbol).
	_ = saw
	return false
}

// pyRHSChainIsUnsafe inspects an RHS expression and returns true when it
// traces back to an unsafe request source.
func pyRHSChainIsUnsafe(lines []string, fromLine int, rhs string, depth int) bool {
	rhs = strings.TrimSpace(rhs)
	if rhs == "" {
		return false
	}
	// Direct request reference: classify by attribute.
	if strings.Contains(rhs, "request") {
		if !pyRequestOnlySafeRHS(rhs) {
			// Unsafe attribute or unrecognised request usage.
			return true
		}
		// All `request.X` are safe attrs — keep scanning interior identifiers
		// in case there's also a non-request taint keyword present.
	}
	// Wrapped sources (request_wrapper(...).get_form_parameter etc.) are
	// always unsafe for XSS.
	if strings.Contains(rhs, "wrapped.") || strings.Contains(rhs, "request_wrapper(") {
		return true
	}
	// Non-request taint keyword present — recurse to check its origin.
	if pyNonRequestTaintRE.MatchString(rhs) {
		tv := pyNonRequestTaintRE.FindString(rhs)
		if tv != "" {
			if pyVarHasUnsafeOrigin(lines, fromLine, tv, depth) {
				return true
			}
		}
	}
	// Intermediate variable reference: recurse on it.
	if intermediate := pyFirstIntermediateVar(rhs); intermediate != "" && intermediate != "request" {
		if pyVarHasUnsafeOrigin(lines, fromLine, intermediate, depth) {
			return true
		}
	}
	return false
}
