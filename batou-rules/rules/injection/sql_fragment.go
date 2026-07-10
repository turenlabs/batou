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
//
// Tightening note (2026-04-25): bare `EXISTS|LIKE|BETWEEN|WHEN|CASE`
// keywords are common English words. `'already exists'` in error
// templates was firing this marker. Tightened to require their actual
// SQL shapes: `EXISTS(`, `LIKE 'pattern'`, `BETWEEN x AND y`,
// `CASE WHEN ... THEN ...`. Multi-token shapes survive intact.
var sqlSyntaxMarkers = []struct {
	pattern *regexp.Regexp
	weight  int
	name    string
}{
	// SQL clause keywords — multi-token shapes that don't collide with
	// English. Bare keywords like EXISTS/LIKE/BETWEEN need their
	// follow-on token (`(`, quoted string, AND-clause) to count.
	{regexp.MustCompile(`(?i)\b(GROUP\s+BY|ORDER\s+BY|LEFT\s+JOIN|INNER\s+JOIN|RIGHT\s+JOIN|FULL\s+JOIN|CROSS\s+JOIN|HAVING\s+\w|EXISTS\s*\(|LIKE\s+['"$` + "`" + `]|ILIKE\s+['"$` + "`" + `]|BETWEEN\s+\w+\s+AND\s+\w|NOT\s+NULL|IS\s+NULL|IS\s+NOT\s+NULL|IN\s*\(|ON\s+\w+\s*=|CASE\s+WHEN|WHEN\s+\w+\s+THEN|LIMIT\s+\d|OFFSET\s+\d|\bASC\s*[,;)]|\bDESC\s*[,;)])`), 2, "sql_clause"},
	// Core SQL keywords — full strength only when paired with another
	// SQL token (table/column/clause). The previous bare alternation
	// hit identifiers like `update.attribute`, `state.set(...)`,
	// `delete obj.x`, `forceUpdate()` etc. Shape-based forms below
	// stay strong; bare forms drop to weight 1 so they can't push a
	// finding past the threshold by themselves.
	{regexp.MustCompile(`(?i)\b(SELECT\s+(?:\*|DISTINCT|TOP\s+\d|\w+\s*[,)])|INSERT\s+INTO|UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b|ALTER\s+TABLE\b|DROP\s+(?:TABLE|INDEX|DATABASE|VIEW|SCHEMA)\b|CREATE\s+(?:TABLE|INDEX|VIEW|DATABASE|SCHEMA)\b|WHERE\s+\w+\s*(?:=|<|>|LIKE\b|IN\s*\()|FROM\s+\w+\s*(?:WHERE|JOIN|;|$)|UNION\s+(?:ALL\s+)?SELECT\b|VALUES\s*\()`), 3, "sql_keyword_shape"},
	// Bare SQL keywords as a weak signal — only enough to nudge the
	// score when other markers are also present.
	{regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|VALUES|UNION)\b`), 1, "sql_keyword_bare"},
	// Backtick-quoted identifiers (MySQL style)
	{regexp.MustCompile("`\\w+`\\.`\\w+`"), 3, "backtick_identifier"},
	// Single backtick-quoted identifier
	{regexp.MustCompile("`\\w+`"), 1, "backtick_single"},
	// SQL comparison with placeholder pattern: = ? or = $N
	{regexp.MustCompile(`=\s*\?|=\s*\$\d`), 1, "parameterized"},
	// SQL string literal quotes around interpolation: = '${var}' or = '" + var + "'
	{regexp.MustCompile(`=\s*'`), 1, "sql_string_compare"},
}

// dangerousInterpolation is keyed by language so JS/TS files don't match
// PHP-style `'$var'` strings (which collide with Vue DI keys like
// `'$appProviderService'` and every framework's service-token convention).
//
// JS/TS: only template-literal and concat patterns.
// PHP: adds `'$var'` literal interpolation.
// Ruby: adds `'#{var}'`.
// Python: adds `'{var}'` (assumes caller ensures f-string context via prefix — regex cannot see the `f`).
var dangerousInterpolation = map[rules.Language][]*regexp.Regexp{
	rules.LangJavaScript: {
		regexp.MustCompile(`'\$\{[^}]+\}'`),         // '${var}' template literal
		regexp.MustCompile(`'\s*\+\s*\w+\s*\+\s*'`), // ' + var + ' concat
	},
	rules.LangTypeScript: {
		regexp.MustCompile(`'\$\{[^}]+\}'`),
		regexp.MustCompile(`'\s*\+\s*\w+\s*\+\s*'`),
	},
	rules.LangPHP: {
		regexp.MustCompile(`'\$\{[^}]+\}'`),
		regexp.MustCompile(`'\s*\+\s*\w+\s*\+\s*'`),
		regexp.MustCompile(`'\$\w+'`), // PHP $var in quotes (intentional)
	},
	rules.LangRuby: {
		regexp.MustCompile(`'#\{[^}]+\}'`),
	},
	rules.LangPython: {
		regexp.MustCompile(`'\$\{[^}]+\}'`),
		regexp.MustCompile(`'\{[^}]+\}'`),
	},
}

// importOrExportLine matches ES-module import/export lines whose `from` clause
// is NOT SQL but collides with the SQL FROM keyword marker. Used to exclude
// such lines from the SQL-context scoring scan.
var importOrExportLine = regexp.MustCompile(`^\s*(import|export)\b`)

// sqlCoreKeyword matches a core SQL keyword in a *SQL-shaped position* —
// surrounded by whitespace / quotes / parens / operators, NOT as a method
// call (`.join(`, `.values(`, `.set(`, `.update(`) or a substring of a
// longer identifier (`Selected`, `joined`, `setup`). This is the primary
// signal for E6-T4's proximity gate: a template literal / concat must have
// an actual SQL keyword within `sqlKeywordWindow` chars of the
// interpolation point to be considered a SQL fragment — not just any
// backtick string with a `${}` in it (DOM selectors, Vue DI keys, log
// messages all fail this gate).
//
// RE2 has no lookbehind, so the leading delimiter is an alternation
// `(^|[...])`. Both the leading and trailing delimiters are SQL-ish: a
// quote, backtick, whitespace, comma, paren, semicolon, or `+` (for
// concat). `.` and word chars are deliberately excluded so `arr.join(...)`,
// `Object.values(...)`, `map.set(...)`, `forceUpdate()`,
// `latestSelectedIndex`, etc. never match.
var sqlCoreKeyword = regexp.MustCompile(`(?i)(^|[\s,;('` + "`" + `"+])(SELECT|INSERT\s+INTO|INSERT|UPDATE|DELETE|FROM|WHERE|INNER\s+JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|FULL\s+JOIN|CROSS\s+JOIN|JOIN|UNION(\s+ALL)?|ORDER\s+BY|GROUP\s+BY|HAVING|INTO|TRUNCATE)([\s,;)('` + "`" + `"+]|$)`)

// sqlKeywordWindow is how far (in characters) from a dangerous-interpolation
// match we look for SQL evidence. SQL fragments can be long; 200 chars
// comfortably covers `SELECT ... FROM ... WHERE id = '${x}'` while still
// excluding keywords/markers that happen to live elsewhere on a long
// minified line.
const sqlKeywordWindow = 200

// interpMatchPositions returns the [start,end) byte offsets of every
// dangerous-interpolation match on the line, for the given patterns.
func interpMatchPositions(line string, patterns []*regexp.Regexp) [][2]int {
	var out [][2]int
	for _, re := range patterns {
		for _, loc := range rules.GFindAllIndex(re, line, -1) {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	return out
}

// windowAround returns the substring of line within sqlKeywordWindow chars
// on either side of the [p[0],p[1]) span.
func windowAround(line string, p [2]int) string {
	lo := p[0] - sqlKeywordWindow
	if lo < 0 {
		lo = 0
	}
	hi := p[1] + sqlKeywordWindow
	if hi > len(line) {
		hi = len(line)
	}
	return line[lo:hi]
}

// hasSQLEvidenceNearInterp is E6-T4's proximity gate. It reports whether,
// within sqlKeywordWindow chars of any dangerous-interpolation match on the
// line, there is either:
//   - a core SQL keyword (SELECT/INSERT/UPDATE/DELETE/FROM/WHERE/JOIN/...)
//     in a SQL-shaped position, OR
//   - at least 2 points' worth of SQL-syntax markers (the same evidence
//     `sqlSyntaxMarkers` already scores) — this preserves Ghost-CVE-style
//     fragments like “WHEN `tbl`.`slug` = '${slug}' THEN“ that don't
//     contain a top-level keyword.
//
// DOM selectors (`querySelectorAll(`[id='${x}']`)`), Vue DI keys
// (`useService('${name}')`), and log messages all fail this gate: their
// only marker is at most a single `= '` (weight 1), and they have no SQL
// keyword anywhere near the interpolation.
func hasSQLEvidenceNearInterp(line string, positions [][2]int) bool {
	for _, p := range positions {
		w := windowAround(line, p)
		if sqlCoreKeyword.MatchString(w) {
			return true
		}
		markerScore := 0
		for _, marker := range sqlSyntaxMarkers {
			if marker.pattern.MatchString(w) {
				markerScore += marker.weight
			}
		}
		if markerScore >= 2 {
			return true
		}
	}
	return false
}

// SQLFragmentInjection detects SQL injection via string building with interpolated fragments.
type SQLFragmentInjection struct{}

func init() {
	rules.Register(&SQLFragmentInjection{})
}

func (r *SQLFragmentInjection) ID() string                      { return "BATOU-INJ-027" }
func (r *SQLFragmentInjection) Name() string                    { return "SQLFragmentInjection" }
func (r *SQLFragmentInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SQLFragmentInjection) Description() string {
	return "String interpolation in a SQL fragment allows SQL injection. Use parameterized queries with placeholders (?) instead of embedding variables in SQL strings."
}
func (r *SQLFragmentInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPHP, rules.LangRuby, rules.LangPython}
}

func (r *SQLFragmentInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	interpPatterns, ok := dangerousInterpolation[ctx.Language]
	if !ok || len(interpPatterns) == 0 {
		return nil
	}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Step 1: Does this line have language-appropriate dangerous interpolation?
		interpPositions := interpMatchPositions(line, interpPatterns)
		if len(interpPositions) == 0 {
			continue
		}

		// Step 1a (E6-T4): the line must actually look like a SQL fragment.
		// Require a core SQL keyword (SELECT/INSERT/UPDATE/DELETE/FROM/WHERE/
		// JOIN/UNION/ORDER BY/GROUP BY/...) within sqlKeywordWindow chars of
		// the interpolation point. This is what separates a real SQL fragment
		// from a DOM selector (`querySelectorAll(\`[id='${x}']\`)`), a Vue
		// dependency-injection key (`useService('$${name}')`), or a log
		// message (`logger.info(\`done ${x}\`)`) — none of which have a SQL
		// keyword near their interpolation. The keyword must be in a
		// SQL-shaped position (whitespace/quote/paren delimited, not
		// `arr.join(`, `Object.values(`, `map.set(`, or a substring of
		// `latestSelectedIndex`), so this gate is precise. Ghost-CVE-style
		// fragments without a top-level keyword still pass via the marker
		// fallback (see hasSQLEvidenceNearInterp).
		if !hasSQLEvidenceNearInterp(line, interpPositions) {
			continue
		}

		// Step 2: Score how SQL-like this line is. Track same-line score
		// separately so context-only signal can't push a finding over the
		// threshold. Without this, error templates like
		// `throw new Error(\`x with key '${k}' not found\`)` and DOM
		// selectors like `querySelectorAll(\`[id='${x}']\`)` get pushed
		// over by an unrelated `\bset\b` (any .set(...) call) within
		// 4 lines, even though the line itself has no SQL evidence.
		sameLineScore := 0
		for _, marker := range sqlSyntaxMarkers {
			if rules.GMatchLower(marker.pattern, line, lowered[i]) {
				sameLineScore += marker.weight
			}
		}

		// Require same-line evidence beyond the dangerous interpolation
		// itself, AND beyond a bare SQL keyword (which can collide with
		// JS/property names like `update.attribute`, `delete user`,
		// `state.set(...)`). Real SQL fragments produce a multi-token
		// shape match (weight 3); bare keywords (weight 1) alone aren't
		// enough.
		if sameLineScore < 2 {
			continue
		}

		sqlScore := 1 + sameLineScore // 1 base for dangerous interp.

		// Also check surrounding context (4 lines above and below) for
		// SQL keywords. SQL is often built across multiple lines.
		//
		// Skip ES-module import/export lines — their `from '...'` clause
		// is NOT SQL-FROM and was previously causing FPs on every TS/JS
		// file that had any `$`-prefixed string nearby (Vue DI keys).
		for j := max(0, i-4); j <= min(len(lines)-1, i+4); j++ {
			if j == i {
				continue
			}
			if isJSLang(ctx.Language) && importOrExportLine.MatchString(lines[j]) {
				continue
			}
			for _, marker := range sqlSyntaxMarkers {
				if marker.pattern.MatchString(lines[j]) {
					sqlScore += marker.weight / 2 // Half weight for context.
				}
			}
		}

		// Step 3: If SQL score is high enough, we have a finding.
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

func isJSLang(l rules.Language) bool {
	return l == rules.LangJavaScript || l == rules.LangTypeScript
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
