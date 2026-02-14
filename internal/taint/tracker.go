package taint

import (
	"regexp"
	"strings"
	"sync"

	"github.com/turenio/gtss/internal/rules"
)

// unknownFunctionDecay is the confidence multiplier applied when taint
// propagates through an unknown (non-sanitizer) function call. Slightly
// below 1.0 because the function might sanitize the data.
const unknownFunctionDecay = 0.8

// reJavaCSharpTypedDecl matches Java/C# typed declarations: Type varName = expr;
// Compiled once at package level to avoid re-compiling on every parseAssignment call.
var reJavaCSharpTypedDecl = regexp.MustCompile(`^\s*(?:final\s+)?([A-Z][\w<>,.\s]*?)\s+([a-zA-Z_][\w]*)\s*=\s*(.+?);\s*$`)

// TrackTaint performs intraprocedural taint tracking within a scope.
// It builds a variable taint map, propagates taint through assignments
// and operations, and detects when tainted data reaches a sink.
func TrackTaint(
	scope *Scope,
	sources []LocatedSource,
	sinks []LocatedSink,
	sanitizers []LocatedSanitizer,
	filePath string,
) []TaintFlow {

	// Build indexes by line for fast lookup.
	sourceByLine := make(map[int][]LocatedSource)
	for _, s := range sources {
		sourceByLine[s.Line] = append(sourceByLine[s.Line], s)
	}
	sinkByLine := make(map[int][]LocatedSink)
	for _, s := range sinks {
		sinkByLine[s.Line] = append(sinkByLine[s.Line], s)
	}
	sanitizerByLine := make(map[int][]LocatedSanitizer)
	for _, s := range sanitizers {
		sanitizerByLine[s.Line] = append(sanitizerByLine[s.Line], s)
	}

	// Determine language from sources/sinks for assignment parsing.
	lang := inferLanguage(sources, sinks, sanitizers)

	// taintMap tracks the current taint state of each variable.
	taintMap := make(map[string]*TaintVar)

	// assignChain records which variable was derived from which, for FlowStep tracing.
	assignChain := make(map[string][]assignRecord)

	var flows []TaintFlow

	// Process lines top-to-bottom within the scope.
	for i, line := range scope.Lines {
		absLine := scope.StartLine + i

		// (a) Check for sources on this line.
		if srcs, ok := sourceByLine[absLine]; ok {
			for _, src := range srcs {
				varName := src.VarName
				if varName == "" {
					// If no explicit variable, try to parse LHS from the line.
					if lhs, _, found := parseAssignment(line, lang); found {
						varName = lhs
					}
				}
				if varName != "" {
					taintMap[varName] = &TaintVar{
						Name:       varName,
						Line:       absLine,
						Source:     &src.Def,
						SourceLine: src.Line,
						Confidence: 1.0,
						Sanitized:  make(map[SinkCategory]bool),
					}
				}
			}
		}

		// (b) Check for assignments and propagate taint.
		if lhs, rhs, found := parseAssignment(line, lang); found {
			// Handle multiple LHS variables (e.g., "x, err := func()" in Go).
			lhsVars := splitMultipleAssignment(lhs)

			for _, lv := range lhsVars {
				lv = strings.TrimSpace(lv)
				if lv == "" || lv == "_" {
					continue
				}

				// Check if any tainted variable appears in the RHS.
				for varName, tv := range taintMap {
					if tv.Source == nil {
						continue
					}
					if !rhsReferencesVar(rhs, varName) {
						continue
					}

					// Determine propagation confidence from the operation.
					propagates, propConf, ruleMatched := ApplyPropagationWithMatch(rhs)
					if !propagates {
						// Taint is sticky: if the RHS is a function call
						// wrapping a tainted argument and the function is NOT
						// a known sanitizer, propagate with reduced confidence.
						if isFunctionCall(rhs) && !isKnownSanitizer(rhs, sanitizers) {
							propagates = true
							propConf = unknownFunctionDecay
						}
					} else if !ruleMatched && isFunctionCall(rhs) && !isKnownSanitizer(rhs, sanitizers) {
						// No propagation rule matched but default fallthrough
						// returned (true, 1.0). For unknown function calls,
						// reduce confidence since the function might sanitize.
						propConf = unknownFunctionDecay
					}
					if !propagates {
						continue
					}

					newConf := tv.Confidence * propConf

					// Only update if this gives higher confidence or is a new taint.
					existing, exists := taintMap[lv]
					if exists && existing.Source != nil && existing.Confidence >= newConf {
						continue
					}

					// Propagate taint to the LHS variable.
					sanitized := make(map[SinkCategory]bool)
					for k, v := range tv.Sanitized {
						sanitized[k] = v
					}
					taintMap[lv] = &TaintVar{
						Name:       lv,
						Line:       absLine,
						Source:     tv.Source,
						SourceLine: tv.SourceLine,
						Confidence: newConf,
						Derived:    true,
						Sanitized:  sanitized,
					}

					assignChain[lv] = append(assignChain[lv], assignRecord{
						fromVar: varName,
						line:    absLine,
						rhs:     rhs,
					})
					break // One source per LHS variable per line is sufficient.
				}
			}
		}

		// (c) Check for sanitizers on this line.
		if sans, ok := sanitizerByLine[absLine]; ok {
			for _, san := range sans {
				varName := san.VarName
				if varName == "" {
					// Try to infer from assignment LHS.
					if lhs, _, found := parseAssignment(line, lang); found {
						varName = lhs
					}
				}
				if varName != "" {
					if tv, exists := taintMap[varName]; exists && tv.Source != nil {
						for _, cat := range san.Def.Neutralizes {
							tv.Sanitized[cat] = true
						}
					}
				}
			}
		}

		// (d) Check for sinks on this line.
		if snks, ok := sinkByLine[absLine]; ok {
			for _, sink := range snks {
				foundForSink := false

				// Skip SQL injection flows for parameterized queries.
				// Parameterized queries use bind parameters ($1, ?, :name, %s)
				// instead of string interpolation, making them safe from SQLi.
				if sink.Def.Category == SnkSQLQuery && isParameterizedQuery(line, sink.ArgExprs) {
					continue
				}

				// Determine which args to check based on DangerousArgs.
				dangerousArgs := filterDangerousArgs(sink.ArgExprs, sink.Def.DangerousArgs)

				for _, argExpr := range dangerousArgs {
					// First, check if a known tainted variable appears in this arg.
					for varName, tv := range taintMap {
						if !exprReferencesVar(argExpr, varName) {
							continue
						}
						if !tv.IsTaintedFor(sink.Def.Category) {
							continue
						}
						// Found a taint flow.
						flow := buildFlow(tv, sink, scope, filePath, assignChain)
						flows = append(flows, flow)
						foundForSink = true
					}

					// Second, check for inline sources in the sink arg expression.
					// This catches patterns like: db.update({ _id: req.body.id })
					// where req.body is never assigned to a variable first.
					if !foundForSink {
						for _, src := range sources {
							re := compilePattern(src.Def.Pattern)
							if re == nil {
								continue
							}
							if !re.MatchString(argExpr) {
								continue
							}
							// Create an inline taint flow directly from source to sink.
							inlineTV := &TaintVar{
								Name:       "__inline__",
								Line:       absLine,
								Source:     &src.Def,
								SourceLine: absLine,
								Confidence: 1.0,
								Sanitized:  make(map[SinkCategory]bool),
							}
							if !inlineTV.IsTaintedFor(sink.Def.Category) {
								continue
							}
							flow := buildFlow(inlineTV, sink, scope, filePath, assignChain)
							flows = append(flows, flow)
							foundForSink = true
							break
						}
					}
				}
			}
		}
	}

	return flows
}

// inferLanguage determines the language from the located items.
func inferLanguage(sources []LocatedSource, sinks []LocatedSink, sanitizers []LocatedSanitizer) rules.Language {
	if len(sources) > 0 {
		return sources[0].Def.Language
	}
	if len(sinks) > 0 {
		return sinks[0].Def.Language
	}
	if len(sanitizers) > 0 {
		return sanitizers[0].Def.Language
	}
	return rules.LangAny
}

// --- Assignment Parsing ---

// assignmentPatterns defines regex patterns for assignment detection per language category.
var assignmentPatterns = []struct {
	re   *regexp.Regexp
	lang func(rules.Language) bool // Which languages this pattern applies to
}{
	// Go short variable declaration: x, err := expr
	{
		re:   regexp.MustCompile(`^\s*([a-zA-Z_][\w]*(?:\s*,\s*[a-zA-Z_][\w]*)*)\s*:=\s*(.+)$`),
		lang: func(l rules.Language) bool { return l == rules.LangGo },
	},
	// Go/Java/C#/Rust typed declaration: var x Type = expr, let x: Type = expr
	{
		re:   regexp.MustCompile(`^\s*(?:var|let|const|mut)\s+([a-zA-Z_][\w]*)\s*(?:[:\s]\s*[\w.*\[\]<>,\s]+)?\s*=\s*(.+)$`),
		lang: func(l rules.Language) bool { return true },
	},
	// JS/TS: var/let/const x = expr
	{
		re:   regexp.MustCompile(`^\s*(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*(.+)$`),
		lang: func(l rules.Language) bool { return true },
	},
	// Java/C#: Type x = expr (e.g., String query = ...)
	{
		re:   regexp.MustCompile(`^\s*(?:final\s+)?([A-Z][\w<>,\s]*?)\s+([a-zA-Z_][\w]*)\s*=\s*(.+)$`),
		lang: func(l rules.Language) bool {
			return l == rules.LangJava || l == rules.LangCSharp
		},
	},
	// PHP: $x = expr
	{
		re:   regexp.MustCompile(`^\s*(\$[a-zA-Z_][\w]*)\s*=\s*(.+)$`),
		lang: func(l rules.Language) bool { return l == rules.LangPHP },
	},
	// Ruby/Python: x = expr (also augmented x += expr)
	{
		re:   regexp.MustCompile(`^\s*([a-zA-Z_][\w]*(?:\s*,\s*[a-zA-Z_][\w]*)*)\s*[\+\-\*\/]?=\s*(.+)$`),
		lang: func(l rules.Language) bool { return true },
	},
}

// tsAssertion matches TypeScript `as Type` assertions at the end of an expression,
// including complex types like `as string`, `as Foo.Bar`, `as unknown as string`.
var tsAssertion = regexp.MustCompile(`\s+as\s+[\w.*\[\]]+(?:\s+as\s+[\w.*\[\]]+)*\s*[;,)}\]]?\s*$`)

// stripTSTypeAssertions removes TypeScript `as Type` suffixes from an expression,
// so "query.to as string" becomes "query.to".
func stripTSTypeAssertions(expr string) string {
	// Strip trailing semicolon first so the assertion regex can anchor at end.
	stripped := strings.TrimRight(strings.TrimSpace(expr), ";")
	result := tsAssertion.ReplaceAllString(stripped, "")
	if result == "" {
		return expr // safety: don't return empty
	}
	return result
}

// parseAssignment extracts the LHS variable(s) and RHS expression from an assignment statement.
// Returns empty strings and false if the line is not an assignment.
func parseAssignment(line string, lang rules.Language) (lhs string, rhs string, found bool) {
	trimmed := strings.TrimSpace(line)

	// Skip comment-only lines.
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
		return "", "", false
	}

	// Skip lines that are clearly not assignments (return, if, for, etc.).
	for _, kw := range []string{"return ", "if ", "for ", "while ", "switch ", "case ", "func ", "def ", "class ", "import ", "from ", "package "} {
		if strings.HasPrefix(trimmed, kw) {
			return "", "", false
		}
	}

	// Special handling for Java/C# typed declarations: Type varName = expr
	if lang == rules.LangJava || lang == rules.LangCSharp {
		if m := reJavaCSharpTypedDecl.FindStringSubmatch(trimmed); m != nil {
			return m[2], m[3], true
		}
	}

	// Try each pattern in order.
	for _, ap := range assignmentPatterns {
		if !ap.lang(lang) {
			continue
		}
		m := ap.re.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}

		// Some patterns capture type in group 1 and var in group 2.
		switch len(m) {
		case 4:
			// Pattern: Type var = expr (Java/C#)
			return m[2], cleanRHS(m[3], lang), true
		case 3:
			// Pattern: var = expr
			return m[1], cleanRHS(m[2], lang), true
		}
	}

	return "", "", false
}

// cleanRHS post-processes the RHS of an assignment to remove language-specific
// syntax noise that interferes with taint tracking.
func cleanRHS(rhs string, lang rules.Language) string {
	// Strip TypeScript `as Type` assertions so "query.to as string" becomes "query.to".
	if lang == rules.LangJavaScript || lang == rules.LangTypeScript || lang == rules.LangAny {
		rhs = stripTSTypeAssertions(rhs)
	}
	return rhs
}

// splitMultipleAssignment splits a multi-variable LHS like "x, err" into ["x", "err"].
func splitMultipleAssignment(lhs string) []string {
	parts := strings.Split(lhs, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// --- Function Call Detection ---

// funcCallRe matches a function/method call pattern: identifier(, obj.method(, pkg.Func(
var funcCallRe = regexp.MustCompile(`[a-zA-Z_$][\w$.]*\s*\(`)

// isFunctionCall returns true if the RHS expression looks like a function call.
func isFunctionCall(rhs string) bool {
	return funcCallRe.MatchString(strings.TrimSpace(rhs))
}

// isKnownSanitizer checks whether the RHS matches any sanitizer pattern from
// the located sanitizers in this scope. If it does, the function is a known
// sanitizer and taint should NOT be force-propagated.
func isKnownSanitizer(rhs string, sanitizers []LocatedSanitizer) bool {
	seen := make(map[string]bool)
	for _, san := range sanitizers {
		pat := san.Def.Pattern
		if pat == "" || seen[pat] {
			continue
		}
		seen[pat] = true
		re := compilePattern(pat)
		if re != nil && re.MatchString(rhs) {
			return true
		}
	}
	return false
}

// --- Variable Reference Detection ---

// wordBoundaryCache stores compiled word-boundary regexps keyed by variable name.
// This avoids recompiling O(N*M) regexps during taint tracking.
var (
	wordBoundaryMu    sync.RWMutex
	wordBoundaryCache = make(map[string]*regexp.Regexp)
)

// wordBoundaryPattern creates a regexp that matches a variable name at word boundaries,
// preventing "user" from matching "username".
// For PHP variables starting with $, it uses a non-word-char or start-of-string boundary
// on the left since \b does not work before the non-word character $.
// Results are cached per variable name.
func wordBoundaryPattern(varName string) *regexp.Regexp {
	wordBoundaryMu.RLock()
	if cached, ok := wordBoundaryCache[varName]; ok {
		wordBoundaryMu.RUnlock()
		return cached
	}
	wordBoundaryMu.RUnlock()

	escaped := regexp.QuoteMeta(varName)

	var pattern string
	if strings.HasPrefix(varName, "$") {
		pattern = `(?:^|[^\w])` + escaped + `\b`
	} else {
		pattern = `\b` + escaped + `\b`
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	wordBoundaryMu.Lock()
	wordBoundaryCache[varName] = re
	wordBoundaryMu.Unlock()
	return re
}

// rhsReferencesVar checks if the RHS of an assignment references a variable by name.
// Uses word boundary matching to avoid false matches like "user" in "username".
func rhsReferencesVar(rhs string, varName string) bool {
	re := wordBoundaryPattern(varName)
	if re == nil {
		return false
	}
	return re.MatchString(rhs)
}

// exprReferencesVar checks if an expression (e.g. a sink argument) references
// a variable. Handles direct reference, property access (var.prop),
// method calls (var.method()), and indexing (var[key]).
func exprReferencesVar(expr string, varName string) bool {
	re := wordBoundaryPattern(varName)
	if re == nil {
		return false
	}
	return re.MatchString(expr)
}

// --- Flow Construction ---

// buildFlow constructs a TaintFlow by tracing the assignment chain from
// the tainted variable back to its source, producing FlowStep entries
// for each intermediate assignment.
func buildFlow(
	tv *TaintVar,
	sink LocatedSink,
	scope *Scope,
	filePath string,
	assignChain map[string][]assignRecord,
) TaintFlow {
	steps := traceSteps(tv.Name, assignChain, make(map[string]bool))

	// Add the initial source step.
	sourceStep := FlowStep{
		Line:        tv.SourceLine,
		Description: "tainted by " + tv.Source.MethodName,
		VarName:     tv.Name,
	}

	// If the variable itself is the original source (not derived), the steps will
	// be empty. Add the source step as the first step regardless.
	allSteps := make([]FlowStep, 0, len(steps)+1)

	// Only prepend source step if it's not already the first step.
	if len(steps) == 0 || steps[0].Line != tv.SourceLine {
		allSteps = append(allSteps, sourceStep)
	}
	allSteps = append(allSteps, steps...)

	return TaintFlow{
		Source:     *tv.Source,
		Sink:       sink.Def,
		SourceLine: tv.SourceLine,
		SinkLine:   sink.Line,
		Steps:      allSteps,
		FilePath:   filePath,
		ScopeName:  scope.Name,
		Confidence: tv.Confidence,
	}
}

// traceSteps walks the assignment chain backward to build FlowStep entries.
// It uses a visited set to prevent infinite loops from circular references.
func traceSteps(varName string, chain map[string][]assignRecord, visited map[string]bool) []FlowStep {
	if visited[varName] {
		return nil
	}
	visited[varName] = true

	records, ok := chain[varName]
	if !ok || len(records) == 0 {
		return nil
	}

	// Use the most recent assignment record for this variable.
	rec := records[len(records)-1]

	// Recursively trace the source variable.
	prior := traceSteps(rec.fromVar, chain, visited)

	step := FlowStep{
		Line:        rec.line,
		Description: "assigned from " + rec.fromVar,
		VarName:     varName,
	}

	result := make([]FlowStep, 0, len(prior)+1)
	result = append(result, prior...)
	result = append(result, step)
	return result
}

// assignRecord records a single taint propagation through an assignment,
// used to trace the chain from source to sink for FlowStep construction.
type assignRecord struct {
	fromVar string // Variable that provided the taint
	line    int    // Line where the assignment occurred
	rhs     string // The RHS expression
}

// --- Parameterized Query Detection ---

// parameterizedPlaceholderRe matches SQL parameterized query placeholders:
//   - $1, $2, etc. (PostgreSQL positional)
//   - ? as a placeholder (MySQL, Go database/sql, JDBC)
//   - :name named parameters (Oracle, SQLAlchemy)
//   - %s with separate args (Python DB-API)
var parameterizedPlaceholderRe = regexp.MustCompile(
	`\$\d+` + // $1, $2 (PostgreSQL)
		`|(?:^|[^\\])\?` + // ? placeholder (MySQL, Go, JDBC)  - not preceded by backslash
		`|:\w+` + // :name (Oracle, SQLAlchemy named params)
		`|%s`, // %s (Python DB-API)
)

// knexBuilderRe matches Knex-style query builder method chains that are
// inherently parameterized: .where('col', val) or .where({key: val}).
var knexBuilderRe = regexp.MustCompile(
	`\.where\s*\(\s*['"]` + // .where('column', ...
		`|\.where\s*\(\s*\{` + // .where({key: val})
		`|\.andWhere\s*\(` + // .andWhere(...)
		`|\.orWhere\s*\(`, // .orWhere(...)
)

// isParameterizedQuery checks whether a SQL sink call uses parameterized
// queries (bind parameters) instead of string interpolation. This is used
// to suppress false positives: parameterized queries are safe from SQL
// injection even when tainted data flows to the call.
//
// It checks two signals:
// 1. The first argument (query string) contains placeholders ($1, ?, :name, %s)
// 2. The call has multiple arguments (query string + bind parameters)
// 3. The line uses a query builder pattern (Knex .where('col', val))
func isParameterizedQuery(sinkLine string, allArgs []string) bool {
	// Check for Knex-style query builders on the sink line.
	if knexBuilderRe.MatchString(sinkLine) {
		return true
	}

	// If the first argument (query string) contains placeholders, it's parameterized.
	if len(allArgs) > 0 && parameterizedPlaceholderRe.MatchString(allArgs[0]) {
		return true
	}

	// If there are multiple arguments AND the first looks like a SQL string,
	// the extra arguments are likely bind parameters.
	if len(allArgs) >= 2 {
		first := strings.TrimSpace(allArgs[0])
		if (strings.HasPrefix(first, `"`) || strings.HasPrefix(first, "'") || strings.HasPrefix(first, "`")) &&
			sqlKeywordRe.MatchString(first) {
			return true
		}
	}

	// Check the entire sink line for placeholders (handles multi-line calls
	// where the query string might be on a previous line).
	if parameterizedPlaceholderRe.MatchString(sinkLine) {
		return true
	}

	return false
}

// sqlKeywordRe matches common SQL statement keywords.
var sqlKeywordRe = regexp.MustCompile(`(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE)\b`)

// filterDangerousArgs returns only the argument expressions at the indices
// specified by dangerousArgs. If dangerousArgs contains -1, all args are
// returned (indicating that any argument position is dangerous).
// If dangerousArgs is empty or nil, all args are returned for safety.
func filterDangerousArgs(allArgs []string, dangerousArgs []int) []string {
	if len(dangerousArgs) == 0 {
		return allArgs
	}
	for _, idx := range dangerousArgs {
		if idx == -1 {
			return allArgs
		}
	}
	var filtered []string
	for _, idx := range dangerousArgs {
		if idx >= 0 && idx < len(allArgs) {
			filtered = append(filtered, allArgs[idx])
		}
	}
	if len(filtered) == 0 {
		return allArgs // Fallback: if no valid indices matched, check all
	}
	return filtered
}
