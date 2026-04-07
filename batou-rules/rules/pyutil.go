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

// PyFStringVar extracts the first f-string interpolation variable: {varName}.
var PyFStringVar = regexp.MustCompile(`\{(\w+)\}`)

// pyFormatArg extracts the first positional argument from .format(varName, ...).
var pyFormatArg = regexp.MustCompile(`\.format\s*\(\s*([a-zA-Z_]\w*)`)

// pyFuncCallArg extracts a variable argument from common sink function calls
// like exec(bar), eval(bar), open(bar), redirect(bar), xpath(query), subprocess.run(argStr), etc.
// batou:ignore BATOU-VAL-007 -- Go RE2 engine guarantees linear-time matching; no ReDoS risk
var pyFuncCallArg = regexp.MustCompile(`(?:exec|eval|redirect|open|XPath|xpath|select|execute|search|compile|loads|load|write|send|render|run|popen|system|Popen|call)\s*\(\s*(?:\w+\s*,\s*)*([a-zA-Z_]\w*)\s*[,)]`)

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

// PySafeInputSource detects known sanitizer functions that return safe values.
var PySafeInputSource = regexp.MustCompile(`get_safe_value\s*\(`)

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

	for i := lineIdx - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])

		// Check for compound assignment (+=). If the += RHS is tainted,
		// the variable is tainted regardless of the base = assignment.
		if strings.HasPrefix(trimmed, compoundPrefix) {
			indent := pyLineIndent(lines[i])
			if indent <= sinkIndent {
				compoundRHS := strings.TrimSpace(trimmed[len(compoundPrefix):])
				if PyTaintKeywords.MatchString(compoundRHS) {
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
				// Check if the tainted variable was assigned from a known
				// safe source (e.g., get_safe_value()). If so, the taint
				// keyword in the RHS is neutralized.
				taintVar := PyTaintKeywords.FindString(rhs)
				if taintVar != "" {
					taintAssign := taintVar + " = "
					for j := i - 1; j >= 0; j-- {
						tj := strings.TrimSpace(lines[j])
						if strings.HasPrefix(tj, taintAssign) {
							if PySafeInputSource.MatchString(tj[len(taintAssign):]) {
								return true
							}
							break
						}
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
						if !PyLastAssignmentIsSafe(lines, i, fv[1]) {
							return false
						}
					}
				}
			}
			return true
		}

		// Conditional assignment — check if it's in an always-true if block.
		if !PyTaintKeywords.MatchString(rhs) {
			// Safe RHS in a branch. Check if the if-condition above is
			// an always-true arithmetic expression.
			for j := i - 1; j >= 0 && j >= i-3; j-- {
				if pyAlwaysTrueArith.MatchString(lines[j]) {
					return true
				}
			}
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
				// The tainted branch could execute — variable is NOT safe.
				return false
			}
			// The tainted branch is in an always-true if block's else,
			// so it never runs. Continue scanning for an earlier assignment.
		}
	}
	return false
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
	if m := PyFStringVar.FindStringSubmatch(line); len(m) > 1 {
		// Skip numeric positional args like {0} — extract from .format() instead.
		varName := m[1]
		if varName[0] < 'A' { // digit check: '0'-'9' < 'A'
			if fm := pyFormatArg.FindStringSubmatch(line); len(fm) > 1 {
				return fm[1]
			}
		}
		return varName
	}
	// Try .format(var) extraction.
	if m := pyFormatArg.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	// Try function call argument extraction.
	if m := pyFuncCallArg.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	// Try nested function call: loads(base64.urlsafe_b64decode(bar)) — extract
	// the innermost simple variable argument from a chain of function calls.
	if m := pyNestedCallArg.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	// Try %-formatting: '%s' % (bar, ...) or '%s' % bar
	if m := pyPctFormatArg.FindStringSubmatch(line); len(m) > 1 {
		return m[1]
	}
	// Try session/dict assignment: session['key'] = bar
	if m := pySessionAssign.FindStringSubmatch(line); len(m) > 1 {
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
	if PyLastAssignmentIsSafe(lines, sinkIdx, varName) {
		return true
	}
	// Check for OWASP Benchmark "always case B" match/case pattern.
	return PyHasAlwaysSafeBranch(lines, sinkIdx, varName)
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
				return true
			}
			// Value has taint keyword — check if that variable was sanitized
			return pyTaintVarIsSanitized(lines, j, valueRHS)
		}
	}
	return false // couldn't resolve → assume unsafe
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

// pyTaintVarIsSanitized checks if a taint-keyword variable in valueRHS was
// last assigned from a known safe source (e.g., get_safe_value()). This
// handles the OWASP Benchmark pattern where param = scr.get_safe_value(...)
// makes param safe despite matching PyTaintKeywords.
func pyTaintVarIsSanitized(lines []string, fromLine int, valueRHS string) bool {
	taintVar := PyTaintKeywords.FindString(valueRHS)
	if taintVar == "" {
		return false
	}
	assignPrefix := taintVar + " = "
	for j := fromLine - 1; j >= 0; j-- {
		tj := strings.TrimSpace(lines[j])
		if strings.HasPrefix(tj, assignPrefix) {
			return PySafeInputSource.MatchString(tj[len(assignPrefix):])
		}
	}
	return false
}

// pyLineIndent returns the number of leading whitespace characters.
func pyLineIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}
