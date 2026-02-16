package taint

import (
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou/internal/rules"
)

// LocatedSource represents a taint source found at a specific line in a scope.
type LocatedSource struct {
	Def     SourceDef
	Line    int
	VarName string // The variable that receives the tainted value
}

// LocatedSink represents a taint sink found at a specific line in a scope.
type LocatedSink struct {
	Def      SinkDef
	Line     int
	ArgExprs []string // The expressions passed as arguments
}

// LocatedSanitizer represents a sanitizer found at a specific line in a scope.
type LocatedSanitizer struct {
	Def     SanitizerDef
	Line    int
	VarName string // Variable being sanitized
}

// patternCache caches compiled regexps for catalog patterns.
var (
	patternCacheMu sync.RWMutex
	patternCacheM  = make(map[string]*regexp.Regexp)
)

// compilePattern compiles and caches a regex pattern.
func compilePattern(pattern string) *regexp.Regexp {
	patternCacheMu.RLock()
	re, ok := patternCacheM[pattern]
	patternCacheMu.RUnlock()
	if ok {
		return re
	}

	patternCacheMu.Lock()
	defer patternCacheMu.Unlock()

	// Double-check after acquiring write lock.
	if re, ok := patternCacheM[pattern]; ok {
		return re
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		// Store nil so we don't retry invalid patterns.
		patternCacheM[pattern] = nil
		return nil
	}
	patternCacheM[pattern] = re
	return re
}

// Analyze runs taint analysis on the given source code.
// It detects scopes, identifies sources and sinks in each scope,
// runs the variable tracker, and returns taint flows.
func Analyze(content string, filePath string, lang rules.Language) []TaintFlow {
	cat := GetCatalog(lang)
	if cat == nil {
		return nil
	}

	sources := cat.Sources()
	sinks := cat.Sinks()
	sanitizers := cat.Sanitizers()

	scopes := DetectScopes(content, lang)
	if len(scopes) == 0 {
		return nil
	}

	// Pre-compile all patterns.
	for _, s := range sources {
		compilePattern(s.Pattern)
	}
	for _, s := range sinks {
		compilePattern(s.Pattern)
	}
	for _, s := range sanitizers {
		compilePattern(s.Pattern)
	}

	// Analyze each scope in parallel.
	type scopeResult struct {
		flows []TaintFlow
	}

	results := make([]scopeResult, len(scopes))
	var wg sync.WaitGroup

	for i := range scopes {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scope := &scopes[idx]

			locSources := findSources(scope, sources, lang)
			locSinks := findSinks(scope, sinks)
			locSanitizers := findSanitizers(scope, sanitizers)

			if len(locSources) == 0 || len(locSinks) == 0 {
				return
			}

			flows := TrackTaint(scope, locSources, locSinks, locSanitizers, filePath)
			results[idx] = scopeResult{flows: flows}
		}(i)
	}

	wg.Wait()

	// Aggregate flows.
	var allFlows []TaintFlow
	for _, r := range results {
		allFlows = append(allFlows, r.flows...)
	}

	return allFlows
}

// findSources scans each line of the scope for source patterns and
// extracts the variable name on the LHS of the assignment.
func findSources(scope *Scope, defs []SourceDef, lang rules.Language) []LocatedSource {
	var located []LocatedSource

	for lineIdx, line := range scope.Lines {
		lineNum := scope.StartLine + lineIdx

		for _, def := range defs {
			re := compilePattern(def.Pattern)
			if re == nil {
				continue
			}
			if !re.MatchString(line) {
				continue
			}

			varName := extractAssignmentLHS(line, lang)
			if varName == "" {
				// Try to extract a destructured variable name from the
				// pattern match itself (e.g., "{ query }" -> "query").
				// This handles function parameter destructuring where
				// there is no assignment LHS.
				varName = extractDestructuredName(re, line)
			}
			if varName == "" {
				// If the source assigns to its return value but we can't find
				// an LHS, try to use the pattern's Assigns hint.
				varName = "__tainted__"
			}

			located = append(located, LocatedSource{
				Def:     def,
				Line:    lineNum,
				VarName: varName,
			})
		}
	}

	return located
}

// findSinks scans each line of the scope for sink patterns and
// extracts the argument expressions. For multi-line function calls,
// it joins continuation lines until parentheses are balanced.
func findSinks(scope *Scope, defs []SinkDef) []LocatedSink {
	var located []LocatedSink

	for lineIdx, line := range scope.Lines {
		lineNum := scope.StartLine + lineIdx

		for _, def := range defs {
			re := compilePattern(def.Pattern)
			if re == nil {
				continue
			}
			if !re.MatchString(line) {
				continue
			}

			args := extractCallArgs(line, def.Pattern)

			// If the call spans multiple lines (unbalanced parens), join
			// continuation lines and re-extract args from the combined text.
			// This handles cases like:
			//   .update(
			//     { _id: req.body.id },
			//     { $set: ... }
			//   )
			if strings.Contains(line, "(") && !parenBalanced(line) {
				combined := line
				for j := lineIdx + 1; j < len(scope.Lines); j++ {
					combined += " " + strings.TrimSpace(scope.Lines[j])
					if parenBalanced(combined) {
						break
					}
				}
				combinedArgs := extractCallArgs(combined, def.Pattern)
				if len(combinedArgs) > len(args) {
					args = combinedArgs
				}
			}

			located = append(located, LocatedSink{
				Def:      def,
				Line:     lineNum,
				ArgExprs: args,
			})
		}
	}

	return located
}

// parenBalanced returns true if the parentheses in s are balanced
// (every '(' has a matching ')').
func parenBalanced(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// findSanitizers scans each line of the scope for sanitizer patterns.
func findSanitizers(scope *Scope, defs []SanitizerDef) []LocatedSanitizer {
	var located []LocatedSanitizer

	for lineIdx, line := range scope.Lines {
		lineNum := scope.StartLine + lineIdx

		for _, def := range defs {
			re := compilePattern(def.Pattern)
			if re == nil {
				continue
			}
			if !re.MatchString(line) {
				continue
			}

			// The sanitizer assigns its result to a variable (the sanitized one).
			varName := extractAssignmentLHS(line, "")
			if varName == "" {
				varName = "__sanitized__"
			}

			located = append(located, LocatedSanitizer{
				Def:     def,
				Line:    lineNum,
				VarName: varName,
			})
		}
	}

	return located
}

// extractAssignmentLHS extracts the variable name from the left side of an assignment.
// Handles patterns like:
//
//	x := expr        (Go)
//	x = expr         (any)
//	var x = expr     (JS/Go)
//	let x = expr     (JS/TS)
//	const x = expr   (JS/TS)
//	x, err := expr   (Go multi-return)
//	$x = expr        (PHP)
func extractAssignmentLHS(line string, lang rules.Language) string {
	trimmed := strings.TrimSpace(line)

	// Go short declaration: x := or x, err :=
	if colonIdx := strings.Index(trimmed, ":="); colonIdx >= 0 {
		lhs := strings.TrimSpace(trimmed[:colonIdx])
		return extractFirstIdent(lhs)
	}

	// var/let/const declarations.
	for _, kw := range []string{"var ", "let ", "const "} {
		if strings.HasPrefix(trimmed, kw) {
			rest := trimmed[len(kw):]
			// "var x type = expr" or "var x = expr" or "let x: type = expr"
			eqIdx := strings.Index(rest, "=")
			if eqIdx < 0 {
				// Declaration without assignment; take the first identifier.
				return extractFirstIdent(rest)
			}
			lhs := strings.TrimSpace(rest[:eqIdx])
			// Remove type annotation.
			if colonIdx := strings.Index(lhs, ":"); colonIdx >= 0 {
				lhs = strings.TrimSpace(lhs[:colonIdx])
			}
			return extractFirstIdent(lhs)
		}
	}

	// PHP: $x = expr
	if strings.HasPrefix(trimmed, "$") {
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx > 0 && (eqIdx+1 >= len(trimmed) || trimmed[eqIdx+1] != '=') {
			lhs := strings.TrimSpace(trimmed[:eqIdx])
			lhs = strings.TrimLeft(lhs, "$")
			return extractFirstIdent(lhs)
		}
	}

	// Generic assignment: x = expr (but not ==, !=, <=, >=)
	eqIdx := strings.Index(trimmed, "=")
	if eqIdx > 0 {
		// Make sure it's not ==, !=, <=, >= or :=
		before := trimmed[eqIdx-1]
		if before == '!' || before == '<' || before == '>' || before == ':' || before == '=' {
			return ""
		}
		if eqIdx+1 < len(trimmed) && trimmed[eqIdx+1] == '=' {
			return ""
		}

		lhs := strings.TrimSpace(trimmed[:eqIdx])

		// Handle Go multi-return: x, err = ...
		if commaIdx := strings.Index(lhs, ","); commaIdx >= 0 {
			return extractFirstIdent(strings.TrimSpace(lhs[:commaIdx]))
		}

		// Handle property access: skip "obj.field = ..." but allow direct vars.
		if strings.Contains(lhs, ".") || strings.Contains(lhs, "[") {
			// For object property assignments, extract the root variable.
			dotIdx := strings.Index(lhs, ".")
			bracketIdx := strings.Index(lhs, "[")
			cutIdx := len(lhs)
			if dotIdx >= 0 && dotIdx < cutIdx {
				cutIdx = dotIdx
			}
			if bracketIdx >= 0 && bracketIdx < cutIdx {
				cutIdx = bracketIdx
			}
			return extractFirstIdent(strings.TrimSpace(lhs[:cutIdx]))
		}

		return extractFirstIdent(lhs)
	}

	return ""
}

// extractFirstIdent extracts the first valid identifier from a string.
// Supports unicode identifiers for non-Latin scripts.
func extractFirstIdent(s string) string {
	s = strings.TrimSpace(s)
	// Skip leading keywords like "mut" in Rust.
	s = strings.TrimPrefix(s, "mut ")

	var ident strings.Builder
	started := false
	for _, r := range s {
		if !started {
			if isIdentStartRune(r) {
				started = true
				ident.WriteRune(r)
			}
		} else {
			if isIdentCharRune(r) {
				ident.WriteRune(r)
			} else {
				break
			}
		}
	}
	return ident.String()
}

// extractCallArgs extracts the arguments from a function call on a line.
// funcPattern is used to locate the function call; we then extract args from
// the parenthesized list that follows.
func extractCallArgs(line string, funcPattern string) []string {
	// Find the function call by locating opening paren after the pattern match.
	re := compilePattern(funcPattern)
	if re == nil {
		return extractArgsFromFirstCall(line)
	}

	loc := re.FindStringIndex(line)
	if loc == nil {
		return extractArgsFromFirstCall(line)
	}

	// Starting from the match, find the opening paren.
	searchStart := loc[0]
	rest := line[searchStart:]
	parenIdx := strings.Index(rest, "(")
	if parenIdx < 0 {
		return nil
	}

	return extractArgsFromParen(rest[parenIdx:])
}

// extractArgsFromFirstCall finds the first function call on a line and extracts args.
func extractArgsFromFirstCall(line string) []string {
	parenIdx := strings.Index(line, "(")
	if parenIdx < 0 {
		return nil
	}
	return extractArgsFromParen(line[parenIdx:])
}

// extractArgsFromParen extracts arguments from a string starting with "(".
func extractArgsFromParen(s string) []string {
	if len(s) == 0 || s[0] != '(' {
		return nil
	}

	// Find the matching close paren.
	depth := 0
	end := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				goto found
			}
		}
	}
found:
	if end < 0 {
		// No matching paren; take everything.
		end = len(s)
	}

	inner := s[1:end]
	if strings.TrimSpace(inner) == "" {
		return nil
	}

	parts := splitParams(inner)
	var args []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			args = append(args, p)
		}
	}
	return args
}

// destructuredNameRe extracts the first identifier inside curly braces,
// matching destructuring patterns like "{ query }", "{ params }", "{ body }".
var destructuredNameRe = regexp.MustCompile(`\{\s*(\w+)`)

// extractDestructuredName attempts to extract a variable name from a
// destructuring pattern in the matched text. For example, if the source
// pattern matched "{ query }" on a function parameter line, this returns
// "query". Returns "" if no destructured name is found.
func extractDestructuredName(re *regexp.Regexp, line string) string {
	match := re.FindString(line)
	if match == "" {
		return ""
	}
	m := destructuredNameRe.FindStringSubmatch(match)
	if m == nil {
		return ""
	}
	return m[1]
}
