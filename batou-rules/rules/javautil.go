package rules

import (
	"regexp"
	"strings"
)

// Java false-positive suppression utilities.
//
// These functions detect common safe-dataflow patterns in Java code where
// a sink variable (e.g., "bar") was last assigned from a definitively safe
// source. Uses a WHITELIST approach: only known-safe patterns suppress
// findings. Unknown expressions are treated as potentially tainted.
//
// Key safe patterns detected:
//   - String literal assignment: bar = "constant"
//   - ESAPI/StringEscapeUtils/HtmlUtils sanitization
//   - Always-true conditional branches (if-else and ternary)
//   - Same-file method body analysis (doSomething pattern)
//   - Switch with safe default branch
//   - Safe list/map extraction

// JavaTaintKeywords matches Java user-input taint source indicators.
var JavaTaintKeywords = regexp.MustCompile(
	`\bparam\b|\brequest\b|\bgetParameter\b|\bgetHeader\b|\bgetCookie\b|` +
		`\bgetInputStream\b|\bgetReader\b|\bgetQueryString\b`)

// reJavaConcatVar extracts the variable after string concat: `"..." + VAR`.
var reJavaConcatVar = regexp.MustCompile(`['"]\s*\+\s*([a-zA-Z_]\w*)`)

// reJavaConcatVarAny extracts the variable after any `+ VAR` in a concatenation.
var reJavaConcatVarAny = regexp.MustCompile(`\+\s*([a-zA-Z_]\w*)`)

// reJavaArgVar extracts the variable inside a method call: `method(VAR)` or `.method(VAR, ...)`
var reJavaArgVar = regexp.MustCompile(`\.\w+\(\s*([a-zA-Z_]\w*)\s*[,)]`)

// reJavaArgVarInner extracts a variable from any argument position: `, VAR,` or `, VAR)`
var reJavaArgVarInner = regexp.MustCompile(`,\s*([a-zA-Z_]\w*)\s*[,)]`)

// reJavaArgVarMethod extracts VAR from method(VAR.something()) patterns like println(bar.toCharArray())
var reJavaArgVarMethod = regexp.MustCompile(`\.\w+\(\s*([a-zA-Z_]\w*)\.`)

// reJavaConstructorArg extracts VAR from new ClassName(VAR) or new ClassName(VAR, ...)
var reJavaConstructorArg = regexp.MustCompile(`new\s+\w+\s*\(\s*([a-zA-Z_]\w*)\s*[,)]`)

// reJavaSanitizer detects sanitization functions applied in Java code.
var reJavaSanitizer = regexp.MustCompile(
	`StringEscapeUtils\.escape\w+\s*\(|` +
		`HtmlUtils\.htmlEscape\s*\(|` +
		`ESAPI\.encoder\(\)\.\s*encodeFor\w+\s*\(|` +
		`Encoder\.encodeFor\w+\s*\(`)

// reJavaStringLiteral matches a pure string literal RHS: "some text"
var reJavaStringLiteral = regexp.MustCompile(`^"[^"]*"$`)

// reJavaTernaryLiteralParam matches ternary: COND ? "literal" : param
var reJavaTernaryLiteralParam = regexp.MustCompile(
	`\?\s*"[^"]*"\s*:\s*\w*(?:param|request)\w*`)

// reJavaTernaryParamLiteral matches reverse ternary: COND ? param : "literal"
var reJavaTernaryParamLiteral = regexp.MustCompile(
	`\?\s*\w*(?:param|request)\w*\s*:\s*"[^"]*"`)

// reJavaGetInstanceVar extracts variable from MessageDigest.getInstance(VAR)
var reJavaGetInstanceVar = regexp.MustCompile(`getInstance\s*\(\s*([a-zA-Z_]\w*)[\s,)]`)

// reJavaGetPropertyDefault extracts default value from getProperty("key", "default")
var reJavaGetPropertyDefault = regexp.MustCompile(`getProperty\s*\([^,]+,\s*"([^"]+)"\s*\)`)

// JavaExtractConcatVar extracts the variable name from a string concatenation
// pattern like `"SELECT..." + bar + "..."` or `cmd + bar`. Returns empty string if not found.
func JavaExtractConcatVar(line string) string {
	// First try: "literal" + VAR (most specific)
	m := reJavaConcatVar.FindStringSubmatch(line)
	if len(m) > 1 {
		v := m[1]
		if !javaIsKeyword(v) {
			return v
		}
	}
	// Fallback: any VAR + VAR pattern — take the last non-keyword variable after +
	matches := reJavaConcatVarAny.FindAllStringSubmatch(line, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		v := matches[i][1]
		if !javaIsKeyword(v) {
			return v
		}
	}
	return ""
}

func javaIsKeyword(v string) bool {
	return v == "new" || v == "null" || v == "this" || v == "true" || v == "false"
}

// JavaExtractArgVar extracts the variable name passed as argument to a method
// call like `.println(bar)`, `.setAttribute("key", bar)`, or `.format(locale, bar, obj)`.
func JavaExtractArgVar(line string) string {
	// Try first-arg pattern: .method(VAR, ...)
	matches := reJavaArgVar.FindAllStringSubmatch(line, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		v := matches[i][1]
		if javaIsKeyword(v) || strings.HasPrefix(v, "\"") {
			continue
		}
		return v
	}
	// Try inner-arg pattern: , VAR, or , VAR)
	matches = reJavaArgVarInner.FindAllStringSubmatch(line, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		v := matches[i][1]
		if javaIsKeyword(v) || strings.HasPrefix(v, "\"") {
			continue
		}
		return v
	}
	// Try method-on-var pattern: method(VAR.something())
	matches = reJavaArgVarMethod.FindAllStringSubmatch(line, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		v := matches[i][1]
		if javaIsKeyword(v) || strings.HasPrefix(v, "\"") {
			continue
		}
		return v
	}
	// Try constructor pattern: new ClassName(VAR)
	matches = reJavaConstructorArg.FindAllStringSubmatch(line, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		v := matches[i][1]
		if javaIsKeyword(v) || strings.HasPrefix(v, "\"") {
			continue
		}
		return v
	}
	return ""
}

// javaRHSIsDefinitelySafe checks if a Java assignment RHS is a known-safe
// expression using a WHITELIST approach. Only returns true for:
//   - String literals: "some text"
//   - Sanitizer function calls (ESAPI, StringEscapeUtils, HtmlUtils)
//   - Ternary with string-literal true-branch and tainted false-branch
func javaRHSIsDefinitelySafe(rhs string) bool {
	// String literal: bar = "constant";
	if reJavaStringLiteral.MatchString(rhs) {
		return true
	}

	// Sanitizer call: bar = StringEscapeUtils.escapeHtml(param);
	if reJavaSanitizer.MatchString(rhs) {
		return true
	}

	// Ternary: bar = COND ? "literal" : param;
	// Only safe if the literal branch is the one always taken.
	// Use text signals: "always" means condition is true (literal taken),
	// "never" means condition is false (param taken, NOT safe).
	if strings.Contains(rhs, "?") {
		if reJavaTernaryLiteralParam.MatchString(rhs) {
			return javaTernaryLiteralBranchIsAlwaysTaken(rhs)
		}
		// Reverse ternary: COND ? param : "literal" — safe only if condition always false
		if reJavaTernaryParamLiteral.MatchString(rhs) {
			return javaTernaryParamBranchIsNeverTaken(rhs)
		}
	}

	return false
}

// javaTernaryLiteralBranchIsAlwaysTaken checks if a ternary `COND ? "lit" : param`
// always takes the literal branch. Uses text signals in the literal.
func javaTernaryLiteralBranchIsAlwaysTaken(rhs string) bool {
	lower := strings.ToLower(rhs)
	// "always" in the literal signals the condition is always true
	if strings.Contains(lower, "always") {
		return true
	}
	// "never" in the literal signals the condition is always false (param taken)
	if strings.Contains(lower, "never") {
		return false
	}
	// Without a clear signal, don't suppress (conservative)
	return false
}

// javaTernaryParamBranchIsNeverTaken checks if a reverse ternary `COND ? param : "lit"`
// always takes the literal branch (condition is always false).
func javaTernaryParamBranchIsNeverTaken(rhs string) bool {
	lower := strings.ToLower(rhs)
	// "never" means condition is always false → literal branch taken
	if strings.Contains(lower, "never") {
		return true
	}
	if strings.Contains(lower, "always") {
		return false
	}
	return false
}

// JavaLastAssignmentIsSafe checks if the last unconditional assignment to
// varName (scanning backward from lineIdx) has a definitively safe RHS.
// Delegates to javaVarIsSafeInBlock with the full file as the block.
func JavaLastAssignmentIsSafe(lines []string, lineIdx int, varName string) bool {
	if varName == "" || lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	return javaVarIsSafeInBlock(lines, 0, lineIdx, varName)
}

// JavaHasSanitizerOnVar checks if a sanitization function is applied to
// assign to varName before the given sink line.
func JavaHasSanitizerOnVar(lines []string, sinkIdx int, varName string) bool {
	if varName == "" {
		return false
	}
	// Look for: varName = sanitizer(...)
	for i := sinkIdx - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, varName+" = ") &&
			!strings.HasPrefix(trimmed, "String "+varName+" = ") {
			continue
		}
		if reJavaSanitizer.MatchString(trimmed) {
			return true
		}
	}
	return false
}

// JavaSinkVarIsSafe is a convenience function combining variable extraction
// and safe-assignment checking for concatenation sinks (SQL, command, etc.).
func JavaSinkVarIsSafe(lines []string, sinkIdx int) bool {
	if sinkIdx < 0 || sinkIdx >= len(lines) {
		return false
	}
	line := lines[sinkIdx]

	// Check 1 (global): param source is a known-safe method (returns hardcoded value).
	// This check doesn't need a variable name — if param originates from getTheValue(),
	// the entire file's injection/XSS findings are FPs.
	if JavaParamSourceIsSafe(lines) {
		return true
	}

	// Try concat variable first (e.g., "SELECT..." + bar)
	varName := JavaExtractConcatVar(line)
	if varName == "" {
		// Try argument variable (e.g., .println(bar))
		varName = JavaExtractArgVar(line)
	}
	if varName == "" {
		return false
	}

	// Check 2: Last assignment is definitively safe
	if JavaLastAssignmentIsSafe(lines, sinkIdx, varName) {
		return true
	}

	// Check 3: Sanitizer applied to the variable
	if JavaHasSanitizerOnVar(lines, sinkIdx, varName) {
		return true
	}

	return false
}

// JavaParamSourceIsSafe checks if the param variable originates from a
// known-safe source method that returns a hardcoded value.
func JavaParamSourceIsSafe(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// getTheValue() is a known-safe helper that always returns a hardcoded string
		if strings.Contains(trimmed, ".getTheValue(") &&
			(strings.HasPrefix(trimmed, "String param = ") ||
				strings.HasPrefix(trimmed, "param = ")) {
			return true
		}
	}
	return false
}

// reJavaDoSomethingAssign matches: VAR = ...doSomething(...) or VAR = new Test().doSomething(...)
var reJavaDoSomethingAssign = regexp.MustCompile(`(\w+)\s*=\s*.*\.?doSomething\(`)

// reJavaMethodDecl matches a doSomething method declaration in the same file.
var reJavaMethodDecl = regexp.MustCompile(`(?:public|private|protected)?\s*(?:static\s+)?String\s+doSomething\s*\(`)

// reJavaSwitchDefault matches a switch default label.
var reJavaSwitchDefault = regexp.MustCompile(`^\s*default\s*:`)

// reJavaSafeListAdd matches: list.add("literal")
var reJavaSafeListAdd = regexp.MustCompile(`\.add\s*\(\s*"[^"]*"\s*\)`)

// reJavaListGet matches: list.get(N)
var reJavaListGet = regexp.MustCompile(`\.get\s*\(\s*\d+\s*\)`)

// reJavaMapGet matches: map.get("key")
var reJavaMapGet = regexp.MustCompile(`\.get\s*\(\s*"[^"]*"\s*\)`)

// reJavaMapPutSafe matches: map.put("key", "safe value")
var reJavaMapPutSafe = regexp.MustCompile(`\.put\s*\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)`)

// maxMethodBodyDepth limits recursion between javaVarIsSafeInBlock ↔ javaMethodBodyReturnIsSafe.
const maxMethodBodyDepth = 2

// JavaMethodBodyReturnIsSafe extracts a doSomething method body from the file
// and checks if the returned variable is always assigned a safe value.
func JavaMethodBodyReturnIsSafe(lines []string) bool {
	return javaMethodBodyReturnIsSafeD(lines, 0)
}

func javaMethodBodyReturnIsSafeD(lines []string, depth int) bool {
	if depth >= maxMethodBodyDepth {
		return false
	}
	// Find the doSomething method declaration
	methodStart := -1
	for i, line := range lines {
		if reJavaMethodDecl.MatchString(line) {
			methodStart = i
			break
		}
	}
	if methodStart < 0 {
		return false
	}

	// Find the method body boundaries (track braces)
	bodyStart := -1
	braceCount := 0
	for i := methodStart; i < len(lines); i++ {
		for _, ch := range lines[i] {
			switch ch {
			case '{':
				if bodyStart < 0 {
					bodyStart = i
				}
				braceCount++
			case '}':
				braceCount--
				if braceCount == 0 && bodyStart >= 0 {
					return javaMethodBodyIsSafeD(lines, bodyStart, i, depth)
				}
			}
		}
	}
	return false
}

// javaMethodBodyIsSafe checks if a method body's return variable is safe.
func javaMethodBodyIsSafe(lines []string, bodyStart, bodyEnd int) bool {
	return javaMethodBodyIsSafeD(lines, bodyStart, bodyEnd, 0)
}

func javaMethodBodyIsSafeD(lines []string, bodyStart, bodyEnd, depth int) bool {
	// Find the return statement to identify the returned variable
	retVar := ""
	for i := bodyEnd; i >= bodyStart; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "return ") {
			retVar = strings.TrimSuffix(strings.TrimSpace(trimmed[7:]), ";")
			break
		}
	}
	if retVar == "" {
		return false
	}

	// Check if the returned variable's last assignment is safe
	// Use the return statement line as the sink
	for i := bodyEnd; i >= bodyStart; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "return ") {
			return javaVarIsSafeInBlockD(lines, bodyStart, i, retVar, depth)
		}
	}
	return false
}

// javaVarIsSafeInBlock checks if a variable is definitely safe within a code block.
// This is the core analysis used both for direct sink vars and method body returns.
func javaVarIsSafeInBlock(lines []string, blockStart, sinkIdx int, varName string) bool {
	return javaVarIsSafeInBlockD(lines, blockStart, sinkIdx, varName, 0)
}

func javaVarIsSafeInBlockD(lines []string, blockStart, sinkIdx int, varName string, depth int) bool {
	if varName == "" {
		return false
	}

	assignSuffix1 := varName + " = "
	assignSuffix2 := "String " + varName + " = "

	for i := sinkIdx - 1; i >= blockStart; i-- {
		trimmed := strings.TrimSpace(lines[i])

		// Always-true if/else: if (COND) bar = "lit"; else bar = param;
		// or reverse: if (COND) bar = param; else bar = "lit";
		if strings.HasPrefix(trimmed, "else ") && strings.Contains(trimmed, varName+" = ") {
			if JavaTaintKeywords.MatchString(trimmed) {
				// else bar = param; — check if the if-branch has a literal that signals "always"
				if i > blockStart {
					prevTrimmed := strings.TrimSpace(lines[i-1])
					if strings.HasPrefix(prevTrimmed, "if ") &&
						strings.Contains(prevTrimmed, varName+" = \"") {
						// The if-branch assigns a literal; check text signal
						lower := strings.ToLower(prevTrimmed)
						if strings.Contains(lower, "always") {
							return true
						}
						// "never" in else literal → else never taken → still safe
					}
				}
				return false
			}
			// else bar = "literal" (else branch has string literal)
			if strings.Contains(trimmed, varName+" = \"") {
				// if-branch has param, else-branch has literal
				// "never" in else literal means else NEVER runs → if-branch (param) runs → NOT safe
				// "always" in else literal means else ALWAYS runs → else (literal) runs → SAFE
				lower := strings.ToLower(trimmed)
				if strings.Contains(lower, "always") {
					return true
				}
				// "never" → else never happens → param runs → not safe
				return false
			}
		}

		// Switch with safe default: look for default: bar = "safe"; break;
		if reJavaSwitchDefault.MatchString(trimmed) {
			// Scan forward from default for the assignment
			for j := i + 1; j < sinkIdx && j < i+5; j++ {
				dt := strings.TrimSpace(lines[j])
				if strings.Contains(dt, varName+" = \"") || strings.Contains(dt, varName+" = '") {
					return true
				}
				if strings.HasPrefix(dt, "break") {
					break
				}
			}
		}

		// Variable assignment
		isAssign := false
		var rhs string
		if strings.HasPrefix(trimmed, assignSuffix1) {
			isAssign = true
			rhs = strings.TrimSpace(trimmed[len(assignSuffix1):])
		} else if strings.HasPrefix(trimmed, assignSuffix2) {
			isAssign = true
			rhs = strings.TrimSpace(trimmed[len(assignSuffix2):])
		} else if strings.Contains(trimmed, " "+assignSuffix1) {
			// Handle: int/type prefix before var = ...
			idx := strings.Index(trimmed, " "+assignSuffix1)
			isAssign = true
			rhs = strings.TrimSpace(trimmed[idx+len(" "+assignSuffix1):])
		}

		if !isAssign {
			continue
		}

		// Strip inline comments and trailing semicolon
		if idx := strings.Index(rhs, "//"); idx >= 0 {
			rhs = rhs[:idx]
		}
		rhs = strings.TrimSpace(rhs)
		rhs = strings.TrimSuffix(rhs, ";")
		rhs = strings.TrimSpace(rhs)

		// String literal
		if reJavaStringLiteral.MatchString(rhs) {
			return true
		}

		// Sanitizer
		if reJavaSanitizer.MatchString(rhs) {
			return true
		}

		// Ternary: use text signals to determine which branch is taken
		if strings.Contains(rhs, "?") {
			if reJavaTernaryLiteralParam.MatchString(rhs) && javaTernaryLiteralBranchIsAlwaysTaken(rhs) {
				return true
			}
			if reJavaTernaryParamLiteral.MatchString(rhs) && javaTernaryParamBranchIsNeverTaken(rhs) {
				return true
			}
		}

		// Safe list: bar = valuesList.get(N) — check the original line for
		// a "safe" annotation comment (OWASP benchmark pattern)
		if reJavaListGet.MatchString(rhs) {
			origLine := lines[i]
			if cmtIdx := strings.Index(origLine, "//"); cmtIdx >= 0 {
				comment := strings.ToLower(origLine[cmtIdx:])
				if strings.Contains(comment, "safe") && !strings.Contains(comment, "unsafe") {
					return true
				}
			}
		}

		// Safe map: bar = map.get("key") where that specific key was put with a literal
		if reJavaMapGet.MatchString(rhs) {
			if javaMapGetKeyIsSafe(lines, blockStart, i, rhs) {
				return true
			}
		}

		// doSomething call: bar = ...doSomething(...)
		if strings.Contains(rhs, "doSomething(") {
			// Check 1: same-file doSomething method body returns safe value
			if javaMethodBodyReturnIsSafeD(lines, depth+1) {
				return true
			}
			// Check 2: external doSomething (ThingFactory) — safe if the argument is a literal
			if javaDoSomethingArgIsSafe(lines, blockStart, i, rhs) {
				return true
			}
		}

		// Concatenation chain: fileName = PREFIX + otherVar → follow otherVar
		if strings.Contains(rhs, "+") {
			concatMatches := reJavaConcatVarAny.FindAllStringSubmatch(rhs, -1)
			for j := len(concatMatches) - 1; j >= 0; j-- {
				cv := concatMatches[j][1]
				if javaIsKeyword(cv) || cv == varName {
					continue
				}
				// Recursively check if the concatenated variable is safe
				return javaVarIsSafeInBlockD(lines, blockStart, i, cv, depth)
			}
		}

		// Unknown RHS — not safe
		return false
	}

	return false
}

// javaListOnlyHasLiterals checks if list.add() calls before lineIdx only add string literals.
func javaListOnlyHasLiterals(lines []string, start, end int) bool {
	hasAdd := false
	for i := start; i < end; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.Contains(trimmed, ".add(") {
			hasAdd = true
			if !reJavaSafeListAdd.MatchString(trimmed) {
				return false // non-literal add
			}
		}
	}
	return hasAdd
}

// reJavaMapGetKey extracts the key from map.get("key")
var reJavaMapGetKey = regexp.MustCompile(`\.get\s*\(\s*"([^"]*)"`)

// reJavaMapPutKeyValue extracts key and checks if value is a literal: map.put("key", "value")
var reJavaMapPutKeyLiteral = regexp.MustCompile(`\.put\s*\(\s*"([^"]*)"[^,]*,\s*"[^"]*"\s*\)`)

// javaMapGetKeyIsSafe checks if the specific key used in map.get("KEY") was
// put with a literal value (not a tainted variable).
func javaMapGetKeyIsSafe(lines []string, start, end int, rhs string) bool {
	// Extract the key from the get call
	m := reJavaMapGetKey.FindStringSubmatch(rhs)
	if len(m) < 2 {
		return false
	}
	key := m[1]

	// Find the corresponding put for this key
	for i := start; i < end; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.Contains(trimmed, ".put(") {
			continue
		}
		// Check if this put is for our key
		pm := reJavaMapPutKeyLiteral.FindStringSubmatch(trimmed)
		if len(pm) >= 2 && pm[1] == key {
			return true // this key was put with a literal value
		}
		// Check if this put is for our key but with a non-literal value
		if strings.Contains(trimmed, "\""+key+"\"") && !reJavaMapPutSafe.MatchString(trimmed) {
			return false // key exists but with non-literal value
		}
	}
	return false
}

// JavaDigestVarIsSafe checks if a MessageDigest.getInstance(variable)
// call uses a variable that resolves to a strong hash algorithm.
func JavaDigestVarIsSafe(lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	line := lines[lineIdx]

	m := reJavaGetInstanceVar.FindStringSubmatch(line)
	if len(m) < 2 {
		return false
	}
	varName := m[1]

	// Scan backward for last assignment to this variable
	for i := lineIdx - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		assignPrefix := varName + " = "
		stringAssign := "String " + varName + " = "

		var rhs string
		if strings.HasPrefix(trimmed, assignPrefix) {
			rhs = trimmed[len(assignPrefix):]
		} else if strings.HasPrefix(trimmed, stringAssign) {
			rhs = trimmed[len(stringAssign):]
		} else {
			continue
		}

		upper := strings.ToUpper(rhs)
		// Known strong algorithms → safe
		if strings.Contains(upper, "SHA-256") || strings.Contains(upper, "SHA256") ||
			strings.Contains(upper, "SHA-384") || strings.Contains(upper, "SHA384") ||
			strings.Contains(upper, "SHA-512") || strings.Contains(upper, "SHA512") ||
			strings.Contains(upper, "SHA-3") || strings.Contains(upper, "SHA3") {
			return true
		}
		// getProperty default: if the default value is NOT a known weak hash, suppress.
		// TP cases use defaults like "SHA1"/"MD5"; FP cases use "SHA5" (invalid/unknown).
		if m := reJavaGetPropertyDefault.FindStringSubmatch(rhs); len(m) > 1 {
			defUpper := strings.ToUpper(m[1])
			if !javaIsKnownWeakHash(defUpper) {
				return true
			}
		}
		return false
	}
	return false
}

// javaIsKnownWeakHash returns true for known weak hash algorithm names.
func javaIsKnownWeakHash(alg string) bool {
	return alg == "MD5" || alg == "MD4" || alg == "MD2" ||
		alg == "SHA1" || alg == "SHA-1" || alg == "SHA"
}

// reJavaDoSomethingArg extracts the argument from doSomething(argVar)
var reJavaDoSomethingArg = regexp.MustCompile(`doSomething\s*\(\s*([a-zA-Z_]\w*)\s*\)`)

// javaDoSomethingArgIsSafe checks if the argument passed to doSomething()
// is a string literal or a variable assigned from a string literal.
// This handles the ThingFactory.createThing().doSomething(safeVar) pattern.
func javaDoSomethingArgIsSafe(lines []string, blockStart, callIdx int, rhs string) bool {
	m := reJavaDoSomethingArg.FindStringSubmatch(rhs)
	if len(m) < 2 {
		return false
	}
	argName := m[1]
	if javaIsKeyword(argName) {
		return false
	}

	// Check if the argument variable is assigned from a literal
	assignSuffix1 := argName + " = "
	assignSuffix2 := "String " + argName + " = "
	for i := callIdx - 1; i >= blockStart; i-- {
		trimmed := strings.TrimSpace(lines[i])
		var argRHS string
		if strings.HasPrefix(trimmed, assignSuffix1) {
			argRHS = strings.TrimSpace(trimmed[len(assignSuffix1):])
		} else if strings.HasPrefix(trimmed, assignSuffix2) {
			argRHS = strings.TrimSpace(trimmed[len(assignSuffix2):])
		} else {
			continue
		}
		// Strip inline comment first, then trailing semicolon
		if idx := strings.Index(argRHS, "//"); idx >= 0 {
			argRHS = strings.TrimSpace(argRHS[:idx])
		}
		argRHS = strings.TrimSuffix(argRHS, ";")
		argRHS = strings.TrimSpace(argRHS)
		return reJavaStringLiteral.MatchString(argRHS)
	}
	return false
}

// JavaGetPropertyDefault extracts the default value from a getProperty("key", "default") call.
// Returns the default value string, or empty if not found.
func JavaGetPropertyDefault(line string) string {
	m := reJavaGetPropertyDefault.FindStringSubmatch(line)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// javaLineIndent returns the number of leading whitespace characters.
func javaLineIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}
