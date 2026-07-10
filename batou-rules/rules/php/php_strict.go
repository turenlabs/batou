// Variable-indirection regex tier for PHP sinks. The existing rules
// (PHP-005 cmdi, PHP-006 sqli) only match when a superglobal is the
// IMMEDIATE arg of a dangerous call. Real PHP code commonly assigns
// `$x = $_GET['k']` and then passes `$x` (possibly inside a concat) to
// the sink — which slipped past the strict patterns. These new rules
// add a small backward-lookback that flags the call when the variable
// is provably tainted from a superglobal within the same function.
//
// Each rule below covers one CWE class the bench-phpcve corpus exercises
// (CWE-78 cmdi, CWE-89 sqli, CWE-22 pathtrav, CWE-611 xxe, CWE-94 eval).
// IDs continue from BATOU-PHP-024 (php_ext.go); new IDs are 025-029.

package php

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// phpTaintedAssignRe captures `$varname = $_(GET|POST|REQUEST|COOKIE|FILES)['...']`
// or `= $request->input(...)` / `->get(...)` / `->query(...)` shapes. Used by
// phpVarLikelyTainted's backward scan.
var phpTaintedAssignRe = regexp.MustCompile(
	`\$(\w+)\s*=\s*` +
		`(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[` +
		`|\$request->(?:input|get|all|query|post|cookie|header|file)\s*\(` +
		`|request\s*\(\s*\)\s*->(?:input|get|all|query|post|cookie|header|file)\s*\(` +
		`|Input::(?:get|post|all|file|cookie|header)\s*\(` +
		`|Request::(?:input|get|all|query|post|cookie|header|file)\s*\(` +
		`|filter_input\s*\(` +
		`|file_get_contents\s*\(\s*['"]php://input` +
		`)`,
)

// phpVarLikelyTainted backward-scans up to 30 lines for an assignment to
// $varName from a superglobal / framework request source. Mirrors the
// pythonLastAssignmentIsSafe lookback pattern used by PR-XSSpy.
func phpVarLikelyTainted(lines []string, lineIdx int, varName string) bool {
	if varName == "" || lineIdx < 0 {
		return false
	}
	start := lineIdx - 30
	if start < 0 {
		start = 0
	}
	for j := lineIdx; j >= start; j-- {
		l := lines[j]
		if isComment(l) {
			continue
		}
		m := rules.GFindSubmatch(phpTaintedAssignRe, l)
		if len(m) >= 2 && m[1] == varName {
			return true
		}
	}
	return false
}

// phpFirstVarInCallRe captures each `$varname` token. Used by
// phpCollectVarsInCall to walk every variable in the argument list so
// the caller can find one that traces back to a superglobal — not just
// the first one, which may be a literal `\$result` inside an eval()
// string or an unrelated `$baseDir` constant.
var phpFirstVarInCallRe = regexp.MustCompile(`\\?\$(\w+)`)

// phpCollectVarsInCall returns every $var token in the call-args slice,
// in source order, with backslash-escaped `\$varname` (string-literal
// content) filtered out.
func phpCollectVarsInCall(callArgs string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, m := range phpFirstVarInCallRe.FindAllStringSubmatch(callArgs, -1) {
		// FindAllStringSubmatch returns the full match in m[0]; if it
		// starts with a backslash the $ was escaped inside a string literal
		// (e.g. `"\$result"` inside eval). Skip those — they're not real
		// PHP variable references.
		if strings.HasPrefix(m[0], `\$`) {
			continue
		}
		v := m[1]
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// phpVarTaintedTransitive runs phpVarLikelyTainted with one extra hop:
// if `$varName = $other . $tainted` (or any concat involving other vars),
// also follow each intermediate. Bounded to 2 hops to keep cost low and
// avoid pathological recursion on real code.
func phpVarTaintedTransitive(lines []string, lineIdx int, varName string, depth int) bool {
	if depth > 2 || varName == "" || lineIdx < 0 {
		return false
	}
	if phpVarLikelyTainted(lines, lineIdx, varName) {
		return true
	}
	// 1-hop: find any assignment to $varName and recurse into vars used on
	// the RHS. We look for `$varName = <rhs>` and pull all $vars out.
	assignRe := regexp.MustCompile(`\$` + regexp.QuoteMeta(varName) + `\s*=\s*(.+)$`)
	start := lineIdx - 30
	if start < 0 {
		start = 0
	}
	for j := lineIdx; j >= start; j-- {
		l := lines[j]
		if isComment(l) {
			continue
		}
		// assignRe is compiled per call (its pattern embeds varName), so the
		// pointer-keyed gate cache would grow unbounded and rarely hit. This
		// lookback also runs only inside the (uncommon) transitive-taint walk
		// over a ≤30-line window, so it is left ungated by design.
		m := assignRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		rhsVars := phpCollectVarsInCall(m[1])
		for _, v := range rhsVars {
			if v == varName {
				continue
			}
			if phpVarTaintedTransitive(lines, j-1, v, depth+1) {
				return true
			}
		}
		// Found an assignment but no transitive taint — stop looking back
		// for *this* var; an earlier assignment was replaced.
		return false
	}
	return false
}

// shellCallRe matches a generic PHP shell-exec call shape with at least
// one $var anywhere in the arguments. The existing PHP-005 rule (in
// php.go) handles the direct-superglobal case; this widens to recognize
// the var-indirected shape.
var phpShellCallIndirectRe = regexp.MustCompile(
	`\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(([^)]*)\)`,
)

// ---------------------------------------------------------------------------
// BATOU-PHP-025: Command injection via variable indirection
// ---------------------------------------------------------------------------

type CommandInjectionIndirect struct{}

func (r *CommandInjectionIndirect) ID() string   { return "BATOU-PHP-025" }
func (r *CommandInjectionIndirect) Name() string { return "PHPCommandInjectionIndirect" }
func (r *CommandInjectionIndirect) Description() string {
	return "Detects PHP shell-exec call whose argument contains a variable that traces back to a superglobal / request source within the same function."
}
func (r *CommandInjectionIndirect) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CommandInjectionIndirect) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *CommandInjectionIndirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindSubmatchLower(phpShellCallIndirectRe, line, lowered[i])
		if m == nil {
			continue
		}
		// Walk every $var in the call args — first tainted one wins.
		var hit string
		for _, v := range phpCollectVarsInCall(m[1]) {
			if strings.HasPrefix(v, "_") || isShellEscapedVarName(v) {
				continue
			}
			if phpVarTaintedTransitive(lines, i, v, 0) {
				hit = v
				break
			}
		}
		if hit == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "PHP command injection via tainted local variable",
			Description:   "A shell-exec function received a variable that traces back to a superglobal or request source within the same function. An attacker can inject shell metachars unless the variable is run through escapeshellarg/escapeshellcmd.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Wrap the user-controlled portion in escapeshellarg() at the assignment site, or rewrite to use a safe API (e.g. Symfony Process with explicit argv array).",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "command-injection", "rce", "indirect"},
		})
	}
	return findings
}

// isShellEscapedVarName flags conventional names that imply prior
// escapeshellarg sanitation (e.g. $safe, $escaped, $quoted).
func isShellEscapedVarName(v string) bool {
	lower := strings.ToLower(v)
	for _, p := range []string{"safe", "escape", "escaped", "quoted", "sanitized"} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-PHP-026: SQL injection via PDO / mysqli variable indirection
// ---------------------------------------------------------------------------

// phpRawSQLIndirectRe matches `$pdo->query("...".$var)` / `->exec(...)` /
// `mysqli_query(...)` shapes with $var in the SQL string. The existing
// PHP-006 only covers `mysqli_query` family.
var phpRawSQLIndirectRe = regexp.MustCompile(
	`(?:->(?:query|exec|prepare)|::query|\b(?:mysqli_query|mysql_query|pg_query|pg_exec))\s*\(([^)]*)\)`,
)

type RawSQLQueryIndirect struct{}

func (r *RawSQLQueryIndirect) ID() string   { return "BATOU-PHP-026" }
func (r *RawSQLQueryIndirect) Name() string { return "PHPSQLInjectionIndirect" }
func (r *RawSQLQueryIndirect) Description() string {
	return "Detects PDO / mysqli / pg raw-SQL call whose argument concatenates a variable traceable to a superglobal/request source."
}
func (r *RawSQLQueryIndirect) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RawSQLQueryIndirect) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *RawSQLQueryIndirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindSubmatchLower(phpRawSQLIndirectRe, line, lowered[i])
		if m == nil {
			continue
		}
		args := m[1]
		// Parameter-binding shape: only `?` placeholders, no $var. Safe.
		hasVar := strings.ContainsRune(args, '$')
		if !hasVar {
			continue
		}
		var hit string
		for _, v := range phpCollectVarsInCall(args) {
			if strings.HasPrefix(v, "_") || isShellEscapedVarName(v) {
				continue
			}
			if phpVarTaintedTransitive(lines, i, v, 0) {
				hit = v
				break
			}
		}
		if hit == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "PHP SQL injection via tainted local variable",
			Description:   "A PDO/mysqli/pg raw-SQL call received a variable that traces back to a superglobal/request source. Concatenating user input into the SQL text bypasses parameter binding.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use prepared statements with positional or named placeholders: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id'); $stmt->execute([':id' => $id]).",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "sql-injection", "indirect"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-027: Path traversal via file-read / file-write with tainted var
// ---------------------------------------------------------------------------

// phpPathSinkRe matches read/write/include calls where a $var is the path arg.
// Note: `file` (the standalone reader) is omitted from the alternation
// because Go's RE2 has no negative lookahead to distinguish it from
// file_get_contents/file_put_contents — those are listed explicitly.
var phpPathSinkRe = regexp.MustCompile(
	`\b(?:readfile|file_get_contents|fopen|file_put_contents|copy|unlink|rename|opendir|scandir|glob)\s*\(([^)]*)\)`,
)

type PathTraversalIndirect struct{}

func (r *PathTraversalIndirect) ID() string   { return "BATOU-PHP-027" }
func (r *PathTraversalIndirect) Name() string { return "PHPPathTraversalIndirect" }
func (r *PathTraversalIndirect) Description() string {
	return "Detects file read/write/listing calls whose path argument traces back to a superglobal/request source."
}
func (r *PathTraversalIndirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *PathTraversalIndirect) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *PathTraversalIndirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindSubmatchLower(phpPathSinkRe, line, lowered[i])
		if m == nil {
			continue
		}
		// Skip URLs (php://input, http://, https://, file:///)
		if strings.Contains(m[0], "php://") || strings.Contains(m[0], "://") {
			continue
		}
		var hit string
		for _, v := range phpCollectVarsInCall(m[1]) {
			if strings.HasPrefix(v, "_") || isShellEscapedVarName(v) {
				continue
			}
			if phpPathLooksSafeNamed(v) {
				continue
			}
			if phpVarTaintedTransitive(lines, i, v, 0) {
				hit = v
				break
			}
		}
		if hit == "" {
			continue
		}
		// Suppress when same line uses basename() or realpath().
		if strings.Contains(line, "basename(") || strings.Contains(line, "realpath(") {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "PHP path traversal via tainted local variable",
			Description:   "A file read/write call received a variable that traces back to a superglobal/request source. Without basename() or a realpath+prefix check, ../ sequences escape the intended directory.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Apply basename() to strip directory components, then verify with realpath()+strpos against an allowlisted base directory.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "path-traversal", "indirect"},
		})
	}
	return findings
}

func phpPathLooksSafeNamed(v string) bool {
	lower := strings.ToLower(v)
	return strings.Contains(lower, "validated") || strings.Contains(lower, "allowed") || strings.Contains(lower, "basename")
}

// ---------------------------------------------------------------------------
// BATOU-PHP-028: XXE via DOMDocument loadXML with LIBXML_NOENT / LIBXML_DTDLOAD
// ---------------------------------------------------------------------------

var phpXMLLoadRe = regexp.MustCompile(`->loadXML\s*\([^)]*\)|simplexml_load_string\s*\([^)]*\)|simplexml_load_file\s*\([^)]*\)`)

type XXELoadXML struct{}

func (r *XXELoadXML) ID() string   { return "BATOU-PHP-028" }
func (r *XXELoadXML) Name() string { return "PHPXXEDangerousFlags" }
func (r *XXELoadXML) Description() string {
	return "Detects DOMDocument::loadXML / simplexml_load_string / simplexml_load_file invocations that pass LIBXML_NOENT or LIBXML_DTDLOAD, enabling external-entity expansion (XXE)."
}
func (r *XXELoadXML) DefaultSeverity() rules.Severity { return rules.High }
func (r *XXELoadXML) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *XXELoadXML) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindLower(phpXMLLoadRe, line, lowered[i])
		if m == "" {
			continue
		}
		dangerous := strings.Contains(m, "LIBXML_NOENT") ||
			strings.Contains(m, "LIBXML_DTDLOAD") ||
			strings.Contains(m, "LIBXML_DTDATTR")
		if !dangerous {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "PHP XXE: dangerous libxml flags on XML loader",
			Description:   "Passing LIBXML_NOENT / LIBXML_DTDLOAD / LIBXML_DTDATTR to DOMDocument::loadXML or simplexml_load_* enables substitution of external entities, allowing XXE attacks (file disclosure, SSRF via <!ENTITY xxe SYSTEM 'file:///etc/passwd'>).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Drop the LIBXML_NOENT / LIBXML_DTDLOAD flags. Use LIBXML_NONET to forbid network entity fetches. Since libxml2 ≥2.9, external entity loading is disabled by default — leave the default in place for untrusted XML.",
			CWEID:         "CWE-611",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "xxe", "xml"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-PHP-029: eval / assert with tainted local variable
// ---------------------------------------------------------------------------

var phpEvalCallRe = regexp.MustCompile(`\b(?:eval|assert|create_function)\s*\(([^)]*)\)`)

type EvalIndirect struct{}

func (r *EvalIndirect) ID() string                      { return "BATOU-PHP-029" }
func (r *EvalIndirect) Name() string                    { return "PHPEvalIndirect" }
func (r *EvalIndirect) Description() string             { return "Detects eval()/assert() with a variable traceable to a superglobal." }
func (r *EvalIndirect) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *EvalIndirect) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *EvalIndirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindSubmatchLower(phpEvalCallRe, line, lowered[i])
		if m == nil {
			continue
		}
		var hit string
		for _, v := range phpCollectVarsInCall(m[1]) {
			if strings.HasPrefix(v, "_") || isShellEscapedVarName(v) {
				continue
			}
			if phpVarTaintedTransitive(lines, i, v, 0) {
				hit = v
				break
			}
		}
		if hit == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "PHP code injection via eval() with tainted variable",
			Description:   "eval/assert/create_function received a variable that traces back to a superglobal/request source. The PHP interpreter will execute attacker-supplied code.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Eliminate eval/assert/create_function. Parse expressions with a real expression library (e.g. symfony/expression-language with explicit allow-list), or rewrite the dispatch as a lookup table keyed on validated input.",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "code-injection", "rce", "eval"},
		})
	}
	return findings
}
