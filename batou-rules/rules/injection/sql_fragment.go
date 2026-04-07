package injection

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// SQL Fragment Injection Detection (BATOU-INJ-027)
//
// Detects SQL injection in code that builds SQL fragments through string
// concatenation or template literal interpolation — even when the fragment
// doesn't contain top-level keywords like SELECT/INSERT/UPDATE/DELETE.
//
// This catches patterns like Ghost CVE-2026-26980:
//   order += `WHEN \`${table}\`.\`slug\` = '${slug}' THEN ${index} `;
//
// The signal is: a string containing SQL syntax markers + variable interpolation.

// sqlSyntaxMarkers are tokens that indicate a string is likely a SQL fragment.
// Each carries a weight — higher weight = stronger signal.
var sqlSyntaxMarkers = []struct {
	pattern *regexp.Regexp
	weight  int
	name    string
}{
	// SQL clause keywords (including fragments not in the top-level keyword list)
	{regexp.MustCompile(`(?i)\b(WHEN|CASE|THEN|ELSE|END|HAVING|GROUP\s+BY|ORDER\s+BY|LIMIT|OFFSET|ASC|DESC|BETWEEN|EXISTS|LIKE|ILIKE|IN\s*\(|NOT\s+NULL|IS\s+NULL|LEFT\s+JOIN|INNER\s+JOIN|RIGHT\s+JOIN|ON\s+\w)\b`), 2, "sql_clause"},
	// Core SQL keywords (already caught by existing rules, but boost score)
	{regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|SET|INTO|VALUES|UNION)\b`), 3, "sql_keyword"},
	// Backtick-quoted identifiers (MySQL style)
	{regexp.MustCompile("`\\w+`\\.`\\w+`"), 3, "backtick_identifier"},
	// Single backtick-quoted identifier
	{regexp.MustCompile("`\\w+`"), 1, "backtick_single"},
	// SQL comparison with placeholder pattern: = ? or = $N
	{regexp.MustCompile(`=\s*\?|=\s*\$\d`), 1, "parameterized"},
	// SQL string literal quotes around interpolation: = '${var}' or = '" + var + "'
	{regexp.MustCompile(`=\s*'`), 1, "sql_string_compare"},
}

// interpolationPatterns detect variable interpolation in different languages.
var interpolationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\$\{[^}]+\}`),   // JS template literals: ${var}
	regexp.MustCompile(`\$\w+`),          // PHP: $var
	regexp.MustCompile(`#\{[^}]+\}`),     // Ruby: #{var}
	regexp.MustCompile(`\{\w+\}`),        // Python f-string: {var} (also C# $"")
	regexp.MustCompile(`"\s*\+\s*\w`),    // String concat: " + var
	regexp.MustCompile(`\w\s*\+\s*"`),    // String concat: var + "
}

// dangerousInterpolation detects variable interpolation INSIDE SQL string values.
// This is the actual injection: '${slug}' or '" + slug + "'
var dangerousInterpolation = []*regexp.Regexp{
	// '${var}' — JS template literal with value in SQL string quotes
	regexp.MustCompile(`'\$\{[^}]+\}'`),
	// ' + var + ' — concat with value between SQL string quotes
	regexp.MustCompile(`'\s*\+\s*\w+\s*\+\s*'`),
	// '#{var}' — Ruby interpolation in SQL string quotes
	regexp.MustCompile(`'#\{[^}]+\}'`),
	// '{var}' — Python f-string in SQL string quotes (if preceded by f or F)
	regexp.MustCompile(`'\{[^}]+\}'`),
	// "$var" in PHP inside SQL
	regexp.MustCompile(`'\$\w+'`),
}

// SQLFragmentInjection detects SQL injection via string building with interpolated fragments.
type SQLFragmentInjection struct{}

func init() {
	rules.Register(&SQLFragmentInjection{})
}

func (r *SQLFragmentInjection) ID() string                     { return "BATOU-INJ-027" }
func (r *SQLFragmentInjection) Name() string                   { return "SQLFragmentInjection" }
func (r *SQLFragmentInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SQLFragmentInjection) Description() string {
	return "String interpolation in a SQL fragment allows SQL injection. Use parameterized queries with placeholders (?) instead of embedding variables in SQL strings."
}
func (r *SQLFragmentInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPHP, rules.LangRuby, rules.LangPython}
}

func (r *SQLFragmentInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Step 1: Does this line have dangerous interpolation inside SQL string quotes?
		hasDangerousInterp := false
		for _, re := range dangerousInterpolation {
			if re.MatchString(line) {
				hasDangerousInterp = true
				break
			}
		}
		if !hasDangerousInterp {
			continue
		}

		// Step 2: Score how SQL-like this line is.
		// The dangerous interpolation itself ('${var}' in SQL quotes) is a strong signal.
		sqlScore := 1 // Base score for having dangerous interpolation at all
		for _, marker := range sqlSyntaxMarkers {
			if marker.pattern.MatchString(line) {
				sqlScore += marker.weight
			}
		}

		// Also check surrounding context (4 lines above and below) for SQL keywords.
		// SQL is often built across multiple lines/statements.
		for j := max(0, i-4); j <= min(len(lines)-1, i+4); j++ {
			if j == i {
				continue
			}
			for _, marker := range sqlSyntaxMarkers {
				if marker.pattern.MatchString(lines[j]) {
					sqlScore += marker.weight / 2 // Half weight for context lines
				}
			}
		}

		// Step 3: If SQL score is high enough, we have a finding
		if sqlScore >= 3 {
			matched := trimmed
			if len(matched) > 200 {
				matched = matched[:200]
			}

			conf := "medium"
			confScore := 0.6
			if sqlScore >= 5 {
				conf = "high"
				confScore = 0.7
			}
			if sqlScore >= 8 {
				confScore = 0.8
			}

			findings = append(findings, rules.Finding{
				RuleID:          r.ID(),
				Title:           "SQL injection via string interpolation in SQL fragment",
				Description:     "Variable values are interpolated directly into a SQL string fragment instead of using parameterized placeholders. An attacker who controls the interpolated value can inject arbitrary SQL.",
				Severity:        rules.Critical,
				SeverityLabel:   "CRITICAL",
				Confidence:      conf,
				ConfidenceScore: confScore,
				FilePath:        ctx.FilePath,
				LineNumber:      lineNum,
				MatchedText:     matched,
				Suggestion:      "Use parameterized queries with ? placeholders and pass values as a separate bindings array. Never embed variables inside SQL string literals.",
				CWEID:           "CWE-89",
				OWASPCategory:   "A03:2021-Injection",
				Language:        ctx.Language,
			})
		}
	}

	return findings
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
