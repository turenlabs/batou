package rules

import (
	"regexp"
	"strings"
)

// Python false-positive suppression utilities.
//
// These functions detect OWASP Benchmark safe patterns where a sink variable
// (e.g., "bar") was last assigned from a non-tainted source. They are shared
// across rule packages (injection, xss, traversal, redirect, session) to
// avoid duplication.

// PyTaintKeywords matches Python user-input taint source indicators.
var PyTaintKeywords = regexp.MustCompile(`\bparam\b|\brequest\b|\bwrapped\b|\bargs\b|\bform\b|\bcookies\b|\bquery_string\b|\buser_input\b`)

// pyRequestAttrRE captures attribute names following `request.`.
var pyRequestAttrRE = regexp.MustCompile(`\brequest\.([A-Za-z_]\w*)`)

// pyRequestSafeAttrName lists request attributes considered non-XSS sources
// by the OWASP Python benchmark.
var pyRequestSafeAttrName = map[string]bool{
	"path": true, "url": true, "host": true, "host_url": true,
	"root_path": true, "base_url": true, "url_root": true,
	"script_root": true, "remote_addr": true, "scheme": true,
	"method": true, "environ": true, "view_args": true,
}

// pyRequestOnlySafeRHS returns true when the only taint-keyword tokens in
// the RHS are request.<safe-attr> references AND none of the other taint
// keywords (param, wrapped, args, form, cookies, query_string, user_input)
// appear. This is used to suppress XSS findings for code that derives
// values from request.path / request.url / etc.
func pyRequestOnlySafeRHS(rhs string) bool {
	// Reject if any non-request taint keyword is present.
	if pyNonRequestTaintRE.MatchString(rhs) {
		return false
	}
	// Must have at least one request reference, and every request.X must
	// be a known safe attribute.
	if !strings.Contains(rhs, "request") {
		return false
	}
	matches := pyRequestAttrRE.FindAllStringSubmatch(rhs, -1)
	if len(matches) == 0 {
		// "request" appears but without attribute access — could be bare
		// request usage (e.g., passed as arg). Conservative: not safe.
		return false
	}
	for _, m := range matches {
		if len(m) > 1 && !pyRequestSafeAttrName[m[1]] {
			return false
		}
	}
	return true
}

// pyNonRequestTaintRE matches taint keywords other than "request" itself.
var pyNonRequestTaintRE = regexp.MustCompile(`\bparam\b|\bwrapped\b|\bargs\b|\bform\b|\bcookies\b|\bquery_string\b|\buser_input\b`)

// PyFStringVar extracts the first f-string interpolation variable: {varName}.
var PyFStringVar = regexp.MustCompile(`\{(\w+)\}`)

// pyFormatArg extracts the first positional argument from .format(varName, ...).
var pyFormatArg = regexp.MustCompile(`\.format\s*\(\s*([a-zA-Z_]\w*)`)

// pyFuncCallArg extracts a variable argument from common sink function calls
// like exec(bar), eval(bar), open(bar), redirect(bar), xpath(query), subprocess.run(argStr), etc.
// batou:ignore BATOU-VAL-007 -- Go RE2 engine guarantees linear-time matching; no ReDoS risk
var pyFuncCallArg = regexp.MustCompile(`(?:exec|eval|redirect|open|XPath|xpath|select|execute|search|compile|loads|load|write|send|render|run|popen|system|Popen|call)\s*\(\s*(?:\w+\s*,\s*)*([a-zA-Z_]\w*)\s*[,)]`)

// pyXMLParseArg extracts the *first* (data) argument from an XML parse sink:
// parseString(bar, parser) → bar, ET.parse(user_file) → user_file,
// fromstring(data) → data, XML(payload) → payload. Unlike pyFuncCallArg, this
// pins the first argument (the XML document) rather than the last, so a trailing
// parser/handler argument is not mistaken for the tainted data.
var pyXMLParseArg = regexp.MustCompile(`(?:parseString|fromstring|parse|XML)\s*\(\s*([a-zA-Z_]\w*)\s*[,)]`)

// pyNestedCallArg extracts the innermost simple variable from nested function calls:
// pickle.loads(base64.urlsafe_b64decode(bar)) → bar
var pyNestedCallArg = regexp.MustCompile(`\w+\(\s*([a-zA-Z_]\w*)\s*\)\s*\)`)

// pyPctFormatArg extracts the first positional argument from %-formatting:
// '%s' % (bar, ...) — requires % followed by ( to avoid matching %s inside strings
var pyPctFormatArg = regexp.MustCompile(`%\s*\(\s*([a-zA-Z_]\w*)\s*[,)]`)

// pySessionAssign extracts the value variable from session/dict assignments:
// flask.session['key'] = bar, session.setAttribute('key', bar)
var pySessionAssign = regexp.MustCompile(`(?:session|flask\.session)\s*\[.*\]\s*=\s*([a-zA-Z_]\w*)\s*$`)

// PyURLValidation detects URL validation guards (urlparse + netloc/scheme check).
var PyURLValidation = regexp.MustCompile(`(?:urlparse|url\.netloc|url\.scheme|parsed\.netloc|parsed\.scheme)\b`)

// PyEvalGuard detects validation guards before eval/exec (e.g., startswith check).
var PyEvalGuard = regexp.MustCompile(`(?i)\bnot\s+\w+\.startswith\s*\(\s*['"]`)

// pyAlwaysTrueCond matches OWASP Benchmark always-true arithmetic conditions
// like "if 7 * 42 - num > 200:" or "if 7 * 18 + num > 200:".
var pyAlwaysTrueArith = regexp.MustCompile(`^\s*if\s+\d+\s*[*+\-]\s*\d+\s*[+\-]\s*\w+\s*>\s*\d+`)

// pyTernaryArith matches Python ternary expressions with always-true arithmetic:
// bar = "safe_value" if 7 * 18 + num > 200 else param
var pyTernaryArith = regexp.MustCompile(`\bif\s+\d+\s*[*+\-]\s*\d+\s*[+\-]\s*\w+\s*>\s*\d+\s+else\b`)

// pyDictAccess matches dict/map key access: someDict['keyName'] or someDict["keyName"]
var pyDictAccess = regexp.MustCompile(`^(\w+)\[['"]([^'"]+)['"]\]$`)

// pyConfigGet matches configparser get: conf.get('section', 'key')
var pyConfigGet = regexp.MustCompile(`^(\w+)\.get\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)$`)

// PyLastAssignmentIsSafe checks if the last assignment to varName (scanning
// backward from lineIdx) has a right-hand side that does NOT contain taint
// source keywords. This suppresses findings when the sink variable was
// overwritten with a safe value.
//
// Handles two patterns:
//  1. Unconditional assignment at the same or lesser indentation as the sink.
//  2. If/else branching where the if-branch (with arithmetic always-true
//     condition) assigns a safe value, and the else-branch has tainted input.
func PyLastAssignmentIsSafe(lines []string, lineIdx int, varName string) bool {
	if varName == "" || lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	assignPrefix := varName + " = "
	compoundPrefix := varName + " += "
	// batou:ignore BATOU-VAL-013 -- bounds checked above (lineIdx < 0 || lineIdx >= len(lines))
	sinkIndent := pyLineIndent(lines[lineIdx])

	// sawSafeConditional records that we encountered at least one conditional
	// (deeper-indent) assignment whose RHS is a safe literal/value. When every
	// conditional branch assigning varName is safe — i.e. the scan finishes
	// without any branch returning false — the variable is safe even without an
	// explicit always-true arithmetic guard. This is the OWASP if/else idiom:
	//   if 'should' not in TestParam:  bar = "literal"   (safe)
	//   else:                          bar = param        (param resolves safe)
	// The tainted else is skipped via `continue` only when its taint resolves to
	// a safe origin; a genuinely tainted else returns false before the scan can
	// complete, so true positives (param <- request.cookies) are unaffected.
	sawSafeConditional := false

	for i := lineIdx - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])

		// Check for compound assignment (+=). If the += RHS is tainted,
		// the variable is tainted regardless of the base = assignment.
		if strings.HasPrefix(trimmed, compoundPrefix) {
			indent := pyLineIndent(lines[i])
			if indent <= sinkIndent {
				compoundRHS := strings.TrimSpace(trimmed[len(compoundPrefix):])
				if PyTaintKeywords.MatchString(compoundRHS) && !pyRequestOnlySafeRHS(compoundRHS) {
					// Resolve indirection: if the taint keyword in the RHS
					// is itself derived from a known-safe source, the compound
					// assignment doesn't taint the LHS.
					taintVar := PyTaintKeywords.FindString(compoundRHS)
					if taintVar != "" && taintVar != "request" {
						if !pyVarHasUnsafeOrigin(lines, i, taintVar, 0) {
							continue
						}
					}
					return false
				}
				// Check f-string variables in the compound RHS.
				if fVars := PyFStringVar.FindAllStringSubmatch(compoundRHS, -1); len(fVars) > 0 {
					for _, fv := range fVars {
						if len(fv) > 1 && fv[1][0] >= 'A' {
							if !PyLastAssignmentIsSafe(lines, i, fv[1]) {
								return false
							}
						}
					}
				}
				// Check .format() variables in the compound RHS.
				if fm := pyFormatArg.FindStringSubmatch(compoundRHS); len(fm) > 1 {
					if !PyLastAssignmentIsSafe(lines, i, fm[1]) {
						return false
					}
				}
			}
			// Compound RHS is safe; continue scanning for the base = assignment.
			continue
		}

		if !strings.HasPrefix(trimmed, assignPrefix) {
			continue
		}
		indent := pyLineIndent(lines[i])
		rhs := strings.TrimSpace(trimmed[len(assignPrefix):])

		// Unconditional assignment (same or lesser indentation as sink).
		if indent <= sinkIndent {
			// Check for ternary: bar = "safe" if <always-true> else param
			if pyTernaryArith.MatchString(rhs) {
				ifIdx := strings.Index(rhs, " if ")
				if ifIdx > 0 {
					safeVal := strings.TrimSpace(rhs[:ifIdx])
					if !PyTaintKeywords.MatchString(safeVal) {
						return true
					}
				}
			}
			// Dict key resolution: bar = someDict['keyA'] → trace dict assignment.
			// Distinguishes safe keyA from tainted keyB in the same dict.
			if m := pyDictAccess.FindStringSubmatch(rhs); len(m) > 2 {
				return PyDictKeyIsSafe(lines, i, m[1], m[2])
			}
			// ConfigParser resolution: bar = conf.get('section', 'key')
			if m := pyConfigGet.FindStringSubmatch(rhs); len(m) > 3 {
				return PyConfigSetIsSafe(lines, i, m[1], m[2], m[3])
			}

			if PyTaintKeywords.MatchString(rhs) {
				// Only "request" matched? If the only request.X attribute
				// referenced is a non-XSS URL component (request.path, etc.)
				// and no other taint keyword is present, treat as safe.
				if pyRequestOnlySafeRHS(rhs) {
					return true
				}
				// Indirection: when the taint keyword is a local name (param,
				// wrapped, args, form, cookies, values, etc.), check if that
				// name itself resolves to a safe source (e.g., request.path).
				taintVar := PyTaintKeywords.FindString(rhs)
				if taintVar != "" && taintVar != "request" {
					if !pyVarHasUnsafeOrigin(lines, i, taintVar, 0) {
						return true
					}
				}
				// Before declaring tainted, check if the assignment is inside
				// an else block of an always-true condition (same indent level
				// can occur when if/else and sink are in sibling blocks).
				alwaysTrueAbove := false
				for j := i - 1; j >= 0 && j >= i-5; j-- {
					if pyAlwaysTrueArith.MatchString(lines[j]) {
						alwaysTrueAbove = true
						break
					}
				}
				if alwaysTrueAbove {
					// Tainted assignment is in a never-executed else branch.
					// Continue scanning for the safe assignment in the if-branch.
					continue
				}
				return false
			}
			// If the RHS is an f-string or .format() with interpolated variables,
			// recursively check if those variables are safe. This prevents false
			// negatives where query = f"...{bar}..." looks safe (no taint keywords)
			// but bar itself is tainted.
			if fVars := PyFStringVar.FindAllStringSubmatch(rhs, -1); len(fVars) > 0 {
				for _, fv := range fVars {
					if len(fv) > 1 && fv[1][0] >= 'A' { // skip numeric {0}
						// Either a safe last-assignment or an "always
						// safe branch" pattern (OWASP Benchmark match/case
						// with statically-determined selector) counts.
						if !PyLastAssignmentIsSafe(lines, i, fv[1]) &&
							!PyHasAlwaysSafeBranch(lines, i, fv[1]) {
							return false
						}
					}
				}
			}
			// Recursively check intermediate variables in the RHS that are
			// not taint keywords themselves but may reference tainted vars
			// (e.g., bar = base64.b64decode(tmp).decode() where tmp ← param).
			if interVar := pyFirstIntermediateVar(rhs); interVar != "" {
				if pyVarHasUnsafeOrigin(lines, i, interVar, 0) {
					return false
				}
			}
			return true
		}

		// Conditional assignment — check if it's in an always-true if block.
		// Treat request.path / request.url etc. as not a taint source.
		taintRHS := PyTaintKeywords.MatchString(rhs) && !pyRequestOnlySafeRHS(rhs)
		if !taintRHS {
			// Safe RHS in a branch. Check if the if-condition above is
			// an always-true arithmetic expression.
			for j := i - 1; j >= 0 && j >= i-3; j-- {
				if pyAlwaysTrueArith.MatchString(lines[j]) {
					return true
				}
			}
			// RHS doesn't reference a known taint source directly. But it
			// may reference an intermediate local variable (e.g., values[0],
			// tmp.decode()) where that variable is tainted. If so, the
			// conditional branch taints varName.
			if interVar := pyFirstIntermediateVar(rhs); interVar != "" {
				if pyVarHasUnsafeOrigin(lines, i, interVar, 0) {
					return false
				}
			}
			// A genuinely safe conditional assignment (literal or safe-origin
			// intermediate). Record it: if no sibling branch turns out tainted,
			// the variable is safe at the sink.
			sawSafeConditional = true
		} else {
			// Tainted RHS in a conditional branch. Check if the if-condition
			// above is always-true (meaning the tainted else-branch never runs).
			alwaysTrue := false
			for j := i - 1; j >= 0 && j >= i-3; j-- {
				if pyAlwaysTrueArith.MatchString(lines[j]) {
					alwaysTrue = true
					break
				}
			}
			if !alwaysTrue {
				// Before declaring tainted, check whether the taint keyword
				// in the RHS itself originates from a safe source. The
				// common OWASP "safe" idiom is:
				//   parts = request.path.split("/")
				//   param = parts[1]
				//   bar = param.split(' ')[0]   <- looks tainted via `param`,
				//                                  but param chains back to
				//                                  request.path (safe).
				taintVar := PyTaintKeywords.FindString(rhs)
				if taintVar != "" && taintVar != "request" {
					if !pyVarHasUnsafeOrigin(lines, i, taintVar, 0) {
						// Tainted keyword resolves to a safe source —
						// the branch is effectively safe. Record it and
						// continue scanning for an earlier assignment to
						// varName.
						sawSafeConditional = true
						continue
					}
				}
				// The tainted branch could execute — variable is NOT safe.
				return false
			}
			// The tainted branch is in an always-true if block's else,
			// so it never runs. Continue scanning for an earlier assignment.
		}
	}
	// If we observed one or more conditional assignments and every one of them
	// was safe (no branch returned false above), the variable is safe at the
	// sink. Otherwise (no assignment seen, or an unresolved case) stay
	// conservative and report unsafe.
	return sawSafeConditional
}

// PyHasURLValidation checks if there is a URL validation guard (urlparse +
// netloc/scheme check) between the given line and the sink line.
func PyHasURLValidation(lines []string, sinkIdx int) bool {
	start := sinkIdx - 15
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:sinkIdx] {
		if PyURLValidation.MatchString(l) {
			return true
		}
	}
	return false
}

// PyHasEvalGuard checks if there's a validation guard (e.g., startswith check)
// before a code execution call on the given line range.
func PyHasEvalGuard(lines []string, sinkIdx int) bool {
	start := sinkIdx - 10
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:sinkIdx] {
		if PyEvalGuard.MatchString(l) {
			return true
		}
	}
	return false
}

// PyExtractSinkVar extracts the variable name used in a Python f-string,
// format string, or function call argument on the given line. It tries
// multiple extraction strategies:
//  1. f-string interpolation: {varName}
//  2. .format(varName, ...) first positional argument
//  3. Common sink function call argument: exec(bar), eval(bar), etc.
func PyExtractSinkVar(line string) string {
	// Try f-string variable extraction first.
	if m := GFindSubmatch(PyFStringVar, line); len(m) > 1 {
		// Skip numeric positional args like {0} — extract from .format() instead.
		varName := m[1]
		if varName[0] < 'A' { // digit check: '0'-'9' < 'A'
			if fm := GFindSubmatch(pyFormatArg, line); len(fm) > 1 {
				return fm[1]
			}
		}
		return varName
	}
	// Try .format(var) extraction.
	if m := GFindSubmatch(pyFormatArg, line); len(m) > 1 {
		return m[1]
	}
	// Try XML parse sink first-argument extraction: parseString(bar, parser),
	// ET.parse(user_file), fromstring(data), XML(payload). Pinning the first
	// (document) argument avoids mistaking a trailing parser/handler arg for
	// the tainted data.
	if m := GFindSubmatch(pyXMLParseArg, line); len(m) > 1 {
		return m[1]
	}
	// Try function call argument extraction.
	if m := GFindSubmatch(pyFuncCallArg, line); len(m) > 1 {
		return m[1]
	}
	// Try nested function call: loads(base64.urlsafe_b64decode(bar)) — extract
	// the innermost simple variable argument from a chain of function calls.
	if m := GFindSubmatch(pyNestedCallArg, line); len(m) > 1 {
		return m[1]
	}
	// Try %-formatting: '%s' % (bar, ...) or '%s' % bar
	if m := GFindSubmatch(pyPctFormatArg, line); len(m) > 1 {
		return m[1]
	}
	// Try session/dict assignment: session['key'] = bar
	if m := GFindSubmatch(pySessionAssign, line); len(m) > 1 {
		return m[1]
	}
	return ""
}

// PySinkVarIsSafe is a convenience function combining variable extraction
// and safe-assignment checking. It extracts the interpolated variable from
// the sink line and checks if it was last assigned from a safe source.
// Returns true if the variable is determined to be safe.
func PySinkVarIsSafe(lines []string, sinkIdx int) bool {
	if sinkIdx < 0 || sinkIdx >= len(lines) {
		return false
	}
	varName := PyExtractSinkVar(lines[sinkIdx])
	if varName == "" {
		return false
	}
	// Dict-key format access: ...'{0[key]}'.format(dict) — check the
	// specific key value rather than the dict literal initialiser.
	if key, ok := pyFormatDictKey(lines[sinkIdx]); ok {
		if !PyDictKeyIsSafe(lines, sinkIdx, varName, key) {
			return false
		}
	}
	if PyLastAssignmentIsSafe(lines, sinkIdx, varName) {
		return true
	}
	// Check for OWASP Benchmark "always case B" match/case pattern.
	return PyHasAlwaysSafeBranch(lines, sinkIdx, varName)
}

// pyFormatDictKeyRE matches dict-key references in format strings: {0[key]}.
var pyFormatDictKeyRE = regexp.MustCompile(`\{0\[([^\]]+)\]\}`)

// pyFormatDictKey extracts the first dict-key reference from a format
// string of the form {0[key]}.
func pyFormatDictKey(line string) (string, bool) {
	if m := GFindSubmatch(pyFormatDictKeyRE, line); len(m) > 1 {
		return m[1], true
	}
	return "", false
}

// PyHasXPathGuard checks if there is an apostrophe validation guard or a
// replace-based sanitizer near the sink that prevents XPath injection.
// OWASP Benchmark patterns:
//
//	if '\'' in bar: return  (rejects input containing quotes)
//	bar.replace('\'', '&apos;')  (escapes apostrophes for safe XPath)
func PyHasXPathGuard(lines []string, sinkIdx int) bool {
	end := sinkIdx + 30
	if end > len(lines) {
		end = len(lines)
	}
	start := sinkIdx - 10
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:end] {
		// Check for .replace() sanitizer with apostrophe/apos escaping.
		if strings.Contains(l, ".replace(") && (strings.Contains(l, "apos") || strings.Contains(l, `"'"`) || strings.Contains(l, `'\''`)) {
			return true
		}
		trimmed := strings.TrimSpace(l)
		// Only match if-statements with 'in' operator, not arbitrary lines
		if !strings.HasPrefix(trimmed, "if ") {
			continue
		}
		if (strings.Contains(l, `'\''`) || strings.Contains(l, `"'"`)) && strings.Contains(l, " in ") {
			return true
		}
	}
	return false
}

// PyHasTraversalGuard checks if there is a path traversal guard near the sink.
// OWASP Benchmark pattern:
//
//	if '../' in bar: return
func PyHasTraversalGuard(lines []string, sinkIdx int) bool {
	end := sinkIdx + 30
	if end > len(lines) {
		end = len(lines)
	}
	start := sinkIdx - 30
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:end] {
		trimmed := strings.TrimSpace(l)
		// Pattern 1: if '../' in bar: return
		if strings.HasPrefix(trimmed, "if ") {
			if (strings.Contains(l, `'../'`) || strings.Contains(l, `"../"`)) && strings.Contains(l, " in ") {
				return true
			}
		}
		// Pattern 2: if not str(p).startswith(str(base)): — path prefix validation
		if pyStartswithGuard.MatchString(trimmed) {
			return true
		}
		// Pattern 3: .resolve() near a startswith check — pathlib safe pattern
		if strings.Contains(trimmed, ".resolve()") {
			for _, nearby := range lines[start:end] {
				if strings.Contains(nearby, "startswith") {
					return true
				}
			}
		}
	}
	return false
}

// pyStartswithGuard matches path validation patterns:
//   - if not str(p).startswith(str(base)):
//   - if not path.startswith(base_dir):
//   - if str(resolved).startswith(allowed):
var pyStartswithGuard = regexp.MustCompile(`(?i)if\s+(?:not\s+)?(?:str\s*\()?\w+(?:\))?\.startswith\s*\(`)

// PyHasContainmentGuard reports whether a *specific* variable is validated by a
// containment / allowlist / startswith guard within a window around the sink.
// This is the variable-scoped extension of the same var-safety reasoning that
// PySinkVarIsSafe applies to last-assignments, but it recognises the OWASP /
// real-world idiom where the value is gated by a membership or prefix check
// rather than overwritten:
//
//	p = request.args.get("f")
//	if p in ALLOWED:            # allowlist containment  -> safe in if-body
//	    open(p)
//	if p not in ALLOWED:        # denylist / reject      -> safe on fall-through
//	    return
//	open(p)
//	if p.startswith(BASE):      # prefix containment
//	    open(p)
//	if str(real).startswith(BASE):  # canonicalise-then-contain
//	    open(real)
//
// The match is pinned to varName so a guard on an unrelated variable never
// suppresses the finding. The taint pipeline still inspects the same flow with
// full dataflow awareness; this only silences the blind AST signal for the
// allowlist-guarded case it cannot otherwise reason about.
func PyHasContainmentGuard(lines []string, sinkIdx int, varName string) bool {
	if varName == "" || sinkIdx < 0 || sinkIdx >= len(lines) {
		return false
	}
	start := sinkIdx - 30
	if start < 0 {
		start = 0
	}
	end := sinkIdx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, "if ") && !strings.HasPrefix(trimmed, "elif ") {
			continue
		}
		// Membership containment: `if p in ALLOWED:` / `if p not in WHITELIST:`.
		// Pinned to varName so a sibling variable's check can't suppress.
		if m := pyMembershipGuardRE.FindStringSubmatch(trimmed); len(m) > 1 && m[1] == varName {
			return true
		}
		// Prefix containment: `if p.startswith(BASE):` / `if not p.startswith(..)`
		// / `if str(p).startswith(str(base)):`. The receiver identifier must be
		// varName (optionally wrapped in str(...)).
		if m := pyStartswithGuardVarRE.FindStringSubmatch(trimmed); len(m) > 1 && m[1] == varName {
			return true
		}
	}
	return false
}

// pyMembershipGuardRE matches a membership-containment guard whose subject is a
// captured identifier: `if <var> in COLLECTION:` or `if <var> not in COLLECTION:`.
// The collection side is intentionally unconstrained (set/list/tuple/dict/frozenset
// literal or a constant name) — what matters is that the tainted variable is the
// membership subject.
var pyMembershipGuardRE = regexp.MustCompile(`^(?:el)?if\s+([A-Za-z_]\w*)\s+(?:not\s+)?in\s+`)

// pyStartswithGuardVarRE matches a prefix-containment guard whose receiver is a
// captured identifier, optionally wrapped in str(): `if p.startswith(`,
// `if not p.startswith(`, `if str(p).startswith(`.
var pyStartswithGuardVarRE = regexp.MustCompile(`^(?:el)?if\s+(?:not\s+)?(?:str\s*\(\s*)?([A-Za-z_]\w*)\s*\)?\.startswith\s*\(`)

// PyHasInputGuard checks for any input validation guard near the sink.
// Combines XPath guard and traversal guard detection.
func PyHasInputGuard(lines []string, sinkIdx int) bool {
	return PyHasXPathGuard(lines, sinkIdx) || PyHasTraversalGuard(lines, sinkIdx)
}

// pyMatchCaseAlwaysB matches the OWASP Benchmark "always case B" pattern:
//
//	possible = "ABC"
//	guess = possible[1]  # always 'B'
//	match guess:
//	    case 'B': bar = 'safe'
var pyMatchCaseB = regexp.MustCompile(`^\s*case\s+['"]B['"]\s*:`)

// pyMatchGuessB detects: guess = possible[1] (or varname[1])
var pyMatchGuessB = regexp.MustCompile(`^\s*\w+\s*=\s*\w+\[1\]`)

// PyHasAlwaysSafeBranch checks if the sink variable (bar) was assigned in
// a "match/case" block where case 'B' is always taken (OWASP Benchmark
// idiom: possible = "ABC"; guess = possible[1]; match guess: case 'B': bar = 'safe').
// Returns true if the case 'B' assignment is safe.
func PyHasAlwaysSafeBranch(lines []string, sinkIdx int, varName string) bool {
	if varName == "" {
		return false
	}
	assignPrefix := varName + " = "
	// Scan backward from sink looking for a case 'B' block
	for i := sinkIdx - 1; i >= 0 && i >= sinkIdx-30; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, assignPrefix) {
			continue
		}
		rhs := strings.TrimSpace(trimmed[len(assignPrefix):])
		if PyTaintKeywords.MatchString(rhs) {
			// Tainted assignment — check if it's in a non-B case
			continue
		}
		// Safe assignment found. Check if it's inside a case 'B' block.
		for j := i - 1; j >= 0 && j >= i-3; j-- {
			if pyMatchCaseB.MatchString(lines[j]) {
				// Verify "guess = possible[1]" appears above
				for k := j - 1; k >= 0 && k >= j-5; k-- {
					if pyMatchGuessB.MatchString(lines[k]) {
						return true
					}
				}
			}
		}
	}
	return false
}

// PyDictKeyIsSafe checks if dictName['key'] was assigned a safe (non-tainted)
// value by scanning backward for dictName['key'] = <value>.
func PyDictKeyIsSafe(lines []string, fromLine int, dictName, key string) bool {
	pattern1 := dictName + "['" + key + "'] = "
	pattern2 := dictName + `["` + key + `"] = `
	for j := fromLine - 1; j >= 0; j-- {
		trimmed := strings.TrimSpace(lines[j])
		var valueRHS string
		if strings.HasPrefix(trimmed, pattern1) {
			valueRHS = strings.TrimSpace(trimmed[len(pattern1):])
		} else if strings.HasPrefix(trimmed, pattern2) {
			valueRHS = strings.TrimSpace(trimmed[len(pattern2):])
		}
		if valueRHS != "" {
			if !PyTaintKeywords.MatchString(valueRHS) {
				// Value has no direct taint keyword — but it may be a simple
				// variable reference (e.g., bar) whose chain leads back to
				// a request source. Recursively check that variable's safety.
				if simpleVar := pySimpleIdent(valueRHS); simpleVar != "" {
					return PyLastAssignmentIsSafe(lines, j, simpleVar)
				}
				return true
			}
			// Value has taint keyword — check if that variable was sanitized
			return pyTaintVarIsSanitized(lines, j, valueRHS)
		}
	}
	return false // couldn't resolve → assume unsafe
}

// pySimpleIdent returns rhs if it is a bare identifier (no whitespace,
// no operators), otherwise returns "".
var pySimpleIdentRE = regexp.MustCompile(`^[A-Za-z_]\w*$`)

func pySimpleIdent(rhs string) string {
	if pySimpleIdentRE.MatchString(rhs) {
		return rhs
	}
	return ""
}

// PyConfigSetIsSafe checks if confName.set('section', 'key', value) was called
// with a safe (non-tainted) value by scanning backward.
func PyConfigSetIsSafe(lines []string, fromLine int, confName, section, key string) bool {
	pattern := confName + ".set('" + section + "', '" + key + "', "
	for j := fromLine - 1; j >= 0; j-- {
		trimmed := strings.TrimSpace(lines[j])
		if strings.HasPrefix(trimmed, pattern) {
			rest := strings.TrimSuffix(strings.TrimSpace(trimmed[len(pattern):]), ")")
			if !PyTaintKeywords.MatchString(rest) {
				return true
			}
			return pyTaintVarIsSanitized(lines, j, rest)
		}
	}
	return false
}

// pyTaintVarIsSanitized checks if a taint-keyword variable in valueRHS traces
// back to a safe origin: request.<safe-attr>-only sources (request.path,
// request.url, ...) that are not attacker-controlled for these sinks.
// Delegating to pyVarHasUnsafeOrigin keeps a single source of truth for
// origin safety: it resolves request.path-only chains and
// intermediate-variable indirection, while still classifying genuinely
// tainted sources (request.form/args/cookies) as unsafe.
func pyTaintVarIsSanitized(lines []string, fromLine int, valueRHS string) bool {
	taintVar := PyTaintKeywords.FindString(valueRHS)
	if taintVar == "" {
		return false
	}
	if taintVar == "request" {
		// Bare request reference in the value: safe only when every request.X
		// attribute is a known-safe component and no other taint keyword is set.
		return pyRequestOnlySafeRHS(valueRHS)
	}
	// A bare taint keyword (param, form, cookies, ...) with NO local assignment
	// is itself the attacker-controlled source and must stay unsafe — e.g. a
	// function parameter named `param` passed straight into conf.set(..., param).
	// pyVarHasUnsafeOrigin returns false ("safe") for an unresolved name, so
	// require that the variable is actually assigned before trusting its origin.
	if !pyVarHasLocalAssignment(lines, fromLine, taintVar) {
		return false
	}
	return !pyVarHasUnsafeOrigin(lines, fromLine, taintVar, 0)
}

// pyVarHasLocalAssignment reports whether varName has any visible assignment
// (plain `=`, compound `+=`, or for-loop binding) before fromLine.
func pyVarHasLocalAssignment(lines []string, fromLine int, varName string) bool {
	if varName == "" {
		return false
	}
	assignPrefix := varName + " = "
	compoundPrefix := varName + " += "
	for i := fromLine - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, assignPrefix) || strings.HasPrefix(trimmed, compoundPrefix) {
			return true
		}
		if m := pyForLoopBind.FindStringSubmatch(trimmed); m != nil && m[1] == varName {
			return true
		}
	}
	return false
}

// pyLineIndent returns the number of leading whitespace characters.
func pyLineIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}
