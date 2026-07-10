package kotlin

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Compiled patterns for Kotlin benchmark rules (BATOU-KT-025 .. BATOU-KT-029)
// ---------------------------------------------------------------------------

// KT-025: JDBC SQL injection via executeQuery/createStatement with string concat/template
var (
	// executeQuery("..." + var) or executeQuery("...$var...")
	reExecuteQueryConcat = regexp.MustCompile(`(?:executeQuery|executeUpdate|execute)\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\))`)
	// executeQuery("...${var}...") or executeQuery("...$var...")
	reExecuteQueryTemplate = regexp.MustCompile(`(?:executeQuery|executeUpdate|execute)\s*\(\s*"[^"]*\$`)
	// createStatement().executeQuery with string template/concat nearby
	// String concatenation into SQL variable: val query = "SELECT..." + var
	reSQLStringConcat = regexp.MustCompile(`(?i)(?:val|var)\s+\w+\s*=\s*"(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)[^"]*"\s*\+`)
	// String template with SQL: val query = "SELECT ... $var" or "... ${var}"
	reSQLStringTemplate = regexp.MustCompile(`(?i)(?:val|var)\s+\w+\s*=\s*"(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)[^"]*\$`)
	// prepareStatement used as sanitizer
	rePrepareStatement = regexp.MustCompile(`prepareStatement\s*\(`)
	// Allowlist/validation patterns
	reAllowlistCheck = regexp.MustCompile(`(?i)(?:\bin\s+(?:allowed|valid|safe|whitelist)|(?:allowed|valid|safe|whitelist)\w*\s*\.\s*contains|when\s*\()`)
)

// KT-026: XSS via HTML response
var (
	// call.respondText(... ContentType.Text.Html)
	reRespondTextHTML = regexp.MustCompile(`call\s*\.\s*respondText\s*\(`)
	reContentTypeHTML = regexp.MustCompile(`ContentType\s*\.\s*Text\s*\.\s*Html`)
	// String template or concat with HTML tags
	reHTMLWithVar = regexp.MustCompile(`"<[^"]*\$|"<[^"]*"\s*\+`)
	// Return statement with HTML string containing interpolation
	reReturnHTML = regexp.MustCompile(`return\s+"<[^"]*\$`)
	// Safe: plain text or JSON content type
	reContentTypeSafe = regexp.MustCompile(`ContentType\s*\.\s*(?:Text\s*\.\s*Plain|Application\s*\.\s*Json)`)
	// HTML escaping patterns
	reHTMLEscape = regexp.MustCompile(`(?i)(?:escapeHtml|htmlEscape|HtmlUtils\.htmlEscape|Encode\.forHtml|StringEscapeUtils\.escapeHtml|\.replace\s*\(\s*"<"\s*,\s*"&lt;"|\.replace\s*\(\s*"&"\s*,\s*"&amp;")`)
	// Servlet/Spring user input
	reServletInput = regexp.MustCompile(`request\.getParameter\s*\(|@RequestParam|@PathVariable`)
)

// KT-027: Command injection (broader patterns)
var (
	// Runtime.getRuntime().exec("...$var") - simple $var, not just ${var}
	reRuntimeExecSimple = regexp.MustCompile(`Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(`)
	// Check if exec argument contains string interpolation
	reExecWithInterp = regexp.MustCompile(`\.exec\s*\(\s*"[^"]*\$`)
	reExecWithConcat = regexp.MustCompile(`\.exec\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\))`)
	// ProcessBuilder with /bin/sh -c and user input
	rePBShellExec = regexp.MustCompile(`ProcessBuilder\s*\(\s*"?/bin/(?:sh|bash)"?\s*,\s*"-c"`)
	// ProcessBuilder with list/arrayOf containing interpolation
	rePBWithInterp = regexp.MustCompile(`ProcessBuilder\s*\([^)]*\$`)
)

// KT-028: Path traversal via File operations
var (
	// File(userVar) or File("/path/" + var) or File("/path/$var")
	reFileWithVar    = regexp.MustCompile(`File\s*\(\s*[a-zA-Z_]\w*\s*[!)\]]`)
	reFileWithConcat = regexp.MustCompile(`File\s*\(\s*"[^"]*"\s*\+`)
	reFileWithInterp = regexp.MustCompile(`File\s*\(\s*"[^"]*\$`)
	// FileInputStream with variable
	reFileInputStreamVar = regexp.MustCompile(`FileInputStream\s*\(\s*[a-zA-Z_]\w*`)
	// Paths.get with variable
	rePathsGetVar = regexp.MustCompile(`Paths\.get\s*\([^)]*[a-zA-Z_]\w*`)
	// Files.readAllBytes with variable
	reFilesRead = regexp.MustCompile(`Files\.readAllBytes\s*\(`)
	// Path traversal sanitizers
	rePathSanitizer = regexp.MustCompile(`(?:canonicalPath|canonicalFile|\.normalize\s*\(|startsWith\s*\()`)
	rePathReplace   = regexp.MustCompile(`\.replace\s*\(\s*(?:"\.\."|"/"|"\\\\")`)
)

// KT-029: Open redirect
var (
	// call.respondRedirect(var) — not hardcoded string
	reRespondRedirect = regexp.MustCompile(`call\s*\.\s*respondRedirect\s*\(`)
	// response.sendRedirect(var)
	reSendRedirect = regexp.MustCompile(`(?:response|res)\s*\.\s*sendRedirect\s*\(`)
	// Check if redirect arg is a variable (not hardcoded)
	reRedirectHardcoded = regexp.MustCompile(`(?:respondRedirect|sendRedirect)\s*\(\s*"[^$"]*"\s*\)`)
	// URL validation patterns
	reURLValidation = regexp.MustCompile(`(?i)(?:URI\s*\(|\.host\b|\.isAbsolute|startsWith\s*\(\s*"/"|\.contains\s*\(\s*"://"|parsed\.host|allowed|setOf\s*\()`)
	reIntCoercion   = regexp.MustCompile(`\.toIntOrNull\s*\(|\.toInt\s*\(`)
	reWhenExpr      = regexp.MustCompile(`when\s*\(\s*\w+\s*\)\s*\{`)
)

// Kotlin user-input source patterns
var reKotlinUserInput = regexp.MustCompile(`call\s*\.\s*(?:parameters|request\s*\.\s*(?:queryParameters|cookies|headers))\s*\[|call\s*\.receive|call\s*\.receiveText|call\s*\.receiveParameters|request\s*\.getParameter|receiveMultipart`)

func init() {
	rules.Register(&KotlinJDBCSQLInjection{})
	rules.Register(&KotlinXSSHTMLResponse{})
	rules.Register(&KotlinCommandInjection{})
	rules.Register(&KotlinPathTraversal{})
	rules.Register(&KotlinOpenRedirect{})
}

// ---------------------------------------------------------------------------
// BATOU-KT-025: Kotlin JDBC SQL injection via executeQuery with string concat/template
// ---------------------------------------------------------------------------

type KotlinJDBCSQLInjection struct{}

func (r *KotlinJDBCSQLInjection) ID() string   { return "BATOU-KT-025" }
func (r *KotlinJDBCSQLInjection) Name() string { return "KotlinJDBCSQLInjection" }
func (r *KotlinJDBCSQLInjection) Description() string {
	return "Detects JDBC SQL injection via executeQuery/createStatement with string concatenation or template interpolation."
}
func (r *KotlinJDBCSQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *KotlinJDBCSQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangKotlin}
}

func (r *KotlinJDBCSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail: no SQL-related functions
	if !strings.Contains(ctx.Content, "executeQuery") &&
		!strings.Contains(ctx.Content, "executeUpdate") &&
		!strings.Contains(ctx.Content, "createStatement") {
		return nil
	}

	// Must have user input somewhere
	if !rules.GMatchFile(reKotlinUserInput, ctx) {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		context := surroundingContext(lines, i, 10)

		// Skip if using prepared statements
		if rePrepareStatement.MatchString(context) {
			continue
		}

		// Skip if allowlist/validation is used
		if reAllowlistCheck.MatchString(context) {
			continue
		}

		// Skip if integer coercion is used (toIntOrNull, toInt)
		if reIntCoercion.MatchString(context) {
			continue
		}

		var matched string
		var desc string

		// Check for executeQuery with string template
		if rules.GMatchLower(reExecuteQueryTemplate, line, lowered[i]) {
			matched = rules.GFindLower(reExecuteQueryTemplate, line, lowered[i])
			desc = "executeQuery() with Kotlin string template interpolation"
		} else if rules.GMatchLower(reExecuteQueryConcat, line, lowered[i]) {
			matched = rules.GFindLower(reExecuteQueryConcat, line, lowered[i])
			desc = "executeQuery() with string concatenation"
		} else if rules.GMatchLower(reSQLStringConcat, line, lowered[i]) {
			matched = rules.GFindLower(reSQLStringConcat, line, lowered[i])
			desc = "SQL query built via string concatenation"
		} else if rules.GMatchLower(reSQLStringTemplate, line, lowered[i]) {
			matched = rules.GFindLower(reSQLStringTemplate, line, lowered[i])
			desc = "SQL query built via string template interpolation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Kotlin JDBC SQL injection via " + desc,
				Description:   "SQL query is constructed via string concatenation or Kotlin string templates (${ } or $var) and executed via JDBC Statement.executeQuery(). User-controlled input in the query enables SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use PreparedStatement with parameter binding: connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\").apply { setString(1, userInput) }.executeQuery()",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "jdbc", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-026: Kotlin XSS via HTML response
// ---------------------------------------------------------------------------

type KotlinXSSHTMLResponse struct{}

func (r *KotlinXSSHTMLResponse) ID() string   { return "BATOU-KT-026" }
func (r *KotlinXSSHTMLResponse) Name() string { return "KotlinXSSHTMLResponse" }
func (r *KotlinXSSHTMLResponse) Description() string {
	return "Detects XSS via Ktor respondText with HTML content type containing unescaped user input."
}
func (r *KotlinXSSHTMLResponse) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinXSSHTMLResponse) Languages() []rules.Language {
	return []rules.Language{rules.LangKotlin}
}

func (r *KotlinXSSHTMLResponse) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail: needs HTML response and user input
	hasRespondText := strings.Contains(ctx.Content, "respondText") || strings.Contains(ctx.Content, "respondHtml")
	hasReturnHTML := strings.Contains(ctx.Content, "return \"<")
	if !hasRespondText && !hasReturnHTML {
		return nil
	}
	if !rules.GMatchFile(reKotlinUserInput, ctx) && !rules.GMatchFile(reServletInput, ctx) {
		return nil
	}

	// Check for HTML escaping in the file
	hasEscaping := rules.GMatchFile(reHTMLEscape, ctx)

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		isRespondText := rules.GMatchLower(reRespondTextHTML, line, lowered[i])
		isReturnHTML := rules.GMatchLower(reReturnHTML, line, lowered[i])

		if !isRespondText && !isReturnHTML {
			continue
		}

		context := surroundingContext(lines, i, 5)

		if isRespondText {
			// Skip if content type is plain text or JSON
			if rules.GMatchLower(reContentTypeSafe, line, lowered[i]) || reContentTypeSafe.MatchString(context) {
				if !rules.GMatchLower(reContentTypeHTML, line, lowered[i]) && !reContentTypeHTML.MatchString(context) {
					continue
				}
			}

			// Must have HTML content type on the same line or nearby
			hasHTMLType := rules.GMatchLower(reContentTypeHTML, line, lowered[i]) || reContentTypeHTML.MatchString(context)
			// Or the response contains HTML tags with variables
			hasHTMLVars := rules.GMatchLower(reHTMLWithVar, line, lowered[i]) || reHTMLWithVar.MatchString(context)

			if !hasHTMLType && !hasHTMLVars {
				continue
			}
		}

		// Skip if HTML escaping is used in the function
		if hasEscaping {
			continue
		}

		// Skip if no user input flows to this response
		hasInput := reKotlinUserInput.MatchString(context) || reServletInput.MatchString(context) || hasVariableInterp(context)
		if !hasInput {
			continue
		}

		// Skip if allowlist validation
		if reAllowlistCheck.MatchString(context) {
			continue
		}

		// Skip if integer coercion
		if reIntCoercion.MatchString(context) {
			continue
		}

		// Skip if regex validation
		if strings.Contains(context, ".matches(Regex(") {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Kotlin XSS via HTML response with unescaped user input",
			Description:   "User input is included in an HTML response via Ktor call.respondText() with ContentType.Text.Html without HTML escaping. An attacker can inject JavaScript or HTML to perform cross-site scripting attacks.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(trimmed, 120),
			Suggestion:    "Escape user input before including in HTML responses. Use HtmlUtils.htmlEscape(), OWASP Encode.forHtml(), or Apache Commons StringEscapeUtils.escapeHtml4(). Prefer a templating engine with auto-escaping.",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"kotlin", "ktor", "xss", "html"},
		})
	}
	return findings
}

// hasVariableInterp checks if text contains Kotlin string interpolation ($var or ${expr})
func hasVariableInterp(s string) bool {
	return strings.Contains(s, "$") && (strings.Contains(s, "\"") || strings.Contains(s, "'"))
}

// ---------------------------------------------------------------------------
// BATOU-KT-027: Kotlin command injection (broader patterns)
// ---------------------------------------------------------------------------

type KotlinCommandInjection struct{}

func (r *KotlinCommandInjection) ID() string   { return "BATOU-KT-027" }
func (r *KotlinCommandInjection) Name() string { return "KotlinCommandInjection" }
func (r *KotlinCommandInjection) Description() string {
	return "Detects command injection via Runtime.exec() or ProcessBuilder with user-controlled input."
}
func (r *KotlinCommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *KotlinCommandInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangKotlin}
}

func (r *KotlinCommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail: needs exec or ProcessBuilder
	hasExec := strings.Contains(ctx.Content, ".exec(") || strings.Contains(ctx.Content, "Runtime.getRuntime")
	hasPB := strings.Contains(ctx.Content, "ProcessBuilder")
	if !hasExec && !hasPB {
		return nil
	}

	// Must have user input
	if !rules.GMatchFile(reKotlinUserInput, ctx) {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		context := surroundingContext(lines, i, 10)

		var matched string
		var desc string

		// Runtime.exec with string interpolation or concatenation
		if rules.GMatchLower(reRuntimeExecSimple, line, lowered[i]) {
			if rules.GMatchLower(reExecWithInterp, line, lowered[i]) {
				matched = strings.TrimSpace(line)
				desc = "Runtime.exec() with string template interpolation"
			} else if rules.GMatchLower(reExecWithConcat, line, lowered[i]) {
				matched = strings.TrimSpace(line)
				desc = "Runtime.exec() with string concatenation"
			} else if strings.Contains(line, "arrayOf") && hasVariableInArgs(line) {
				matched = strings.TrimSpace(line)
				desc = "Runtime.exec() with user input in argument array"
			}
		}

		// ProcessBuilder with /bin/sh -c and interpolation
		if matched == "" && hasPB {
			if rules.GMatchLower(rePBShellExec, line, lowered[i]) && hasVariableInterp(line) {
				matched = strings.TrimSpace(line)
				desc = "ProcessBuilder with shell execution and user-controlled input"
			} else if rules.GMatchLower(rePBShellExec, line, lowered[i]) && hasVariableInterp(context) {
				matched = strings.TrimSpace(line)
				desc = "ProcessBuilder with shell execution and user-controlled input"
			} else if rules.GMatchLower(rePBWithInterp, line, lowered[i]) {
				matched = strings.TrimSpace(line)
				desc = "ProcessBuilder with string template interpolation in arguments"
			}
		}

		if matched == "" {
			continue
		}

		// Skip if validation is used nearby
		if reAllowlistCheck.MatchString(context) {
			continue
		}
		if reIntCoercion.MatchString(context) {
			continue
		}
		if strings.Contains(context, ".matches(Regex(") {
			continue
		}
		if strings.Contains(context, ".replace(Regex(") {
			continue
		}

		// Skip hardcoded commands with no user input
		if !reKotlinUserInput.MatchString(context) {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Kotlin command injection via " + desc,
			Description:   "User-controlled input is passed to OS command execution via " + desc + ". An attacker can inject shell metacharacters to execute arbitrary commands.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(matched, 120),
			Suggestion:    "Use ProcessBuilder with separate argument list: ProcessBuilder(\"cmd\", userArg). Never pass user input to /bin/sh -c. Validate input against an allowlist.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"kotlin", "command-injection"},
		})
	}
	return findings
}

// hasVariableInArgs checks if the line has variable references in arrayOf/listOf arguments
func hasVariableInArgs(s string) bool {
	// Look for arrayOf or listOf with a variable that isn't a string literal
	if strings.Contains(s, "arrayOf") || strings.Contains(s, "listOf") {
		// Check for variable names after a comma (not just string literals)
		parts := strings.Split(s, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			// A variable reference (not a string literal)
			if len(p) > 0 && p[0] != '"' && p[0] != '\'' && !strings.HasPrefix(p, "\"") {
				if strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") {
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-KT-028: Kotlin path traversal via File operations
// ---------------------------------------------------------------------------

type KotlinPathTraversal struct{}

func (r *KotlinPathTraversal) ID() string   { return "BATOU-KT-028" }
func (r *KotlinPathTraversal) Name() string { return "KotlinPathTraversal" }
func (r *KotlinPathTraversal) Description() string {
	return "Detects path traversal via File(), FileInputStream, or Paths.get() with user-controlled input."
}
func (r *KotlinPathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinPathTraversal) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinPathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail: needs file operations
	hasFile := strings.Contains(ctx.Content, "File(") || strings.Contains(ctx.Content, "FileInputStream(") || strings.Contains(ctx.Content, "Paths.get(") || strings.Contains(ctx.Content, "Files.readAllBytes(")
	if !hasFile {
		return nil
	}

	// Must have user input
	if !rules.GMatchFile(reKotlinUserInput, ctx) {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		context := surroundingContext(lines, i, 10)

		var matched string
		var desc string

		// File(variable) - direct variable
		if rules.GMatchLower(reFileWithVar, line, lowered[i]) {
			matched = strings.TrimSpace(line)
			desc = "File() constructor with user-controlled path"
		} else if rules.GMatchLower(reFileWithConcat, line, lowered[i]) {
			matched = strings.TrimSpace(line)
			desc = "File() constructor with string concatenation in path"
		} else if rules.GMatchLower(reFileWithInterp, line, lowered[i]) {
			matched = strings.TrimSpace(line)
			desc = "File() constructor with string template in path"
		} else if rules.GMatchLower(reFileInputStreamVar, line, lowered[i]) {
			matched = strings.TrimSpace(line)
			desc = "FileInputStream with user-controlled path"
		} else if rules.GMatchLower(rePathsGetVar, line, lowered[i]) && strings.Contains(context, "readAllBytes") {
			matched = strings.TrimSpace(line)
			desc = "Paths.get() with user-controlled path component"
		} else if rules.GMatchLower(reFilesRead, line, lowered[i]) {
			matched = strings.TrimSpace(line)
			desc = "Files.readAllBytes() with user-controlled path"
		}

		if matched == "" {
			continue
		}

		// Skip if path sanitization is used
		if rePathSanitizer.MatchString(context) {
			continue
		}
		if rePathReplace.MatchString(context) {
			continue
		}

		// Skip if allowlist validation
		if reAllowlistCheck.MatchString(context) {
			continue
		}

		// Skip if integer coercion (safe path)
		if reIntCoercion.MatchString(context) {
			continue
		}

		// Skip if regex validation or replacement (sanitization)
		if strings.Contains(context, ".matches(Regex(") || strings.Contains(context, ".replace(Regex(") {
			continue
		}

		// Skip if map lookup (safe indirection)
		if strings.Contains(context, "mapOf(") || strings.Contains(context, "themes[") || strings.Contains(context, "themes.get(") {
			continue
		}

		// Skip if .take() truncation is used (length limiting)
		if strings.Contains(context, ".take(") {
			continue
		}

		// Skip if no user input flows nearby
		if !reKotlinUserInput.MatchString(context) {
			continue
		}

		// Skip hardcoded file paths
		if isHardcodedFilePath(line) {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Kotlin path traversal via " + desc,
			Description:   "A file operation uses a path derived from user input without traversal protection. An attacker can use ../ sequences to access files outside the intended directory.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(matched, 120),
			Suggestion:    "Validate paths with canonicalPath + startsWith check: val resolved = File(base, userInput).canonicalFile; require(resolved.path.startsWith(base.canonicalPath)). Or strip directory separators from filenames.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"kotlin", "path-traversal", "file"},
		})
	}
	return findings
}

// isHardcodedFilePath checks if a File() call contains only a hardcoded string literal
func isHardcodedFilePath(line string) bool {
	// File("/some/path") with no variables
	idx := strings.Index(line, "File(")
	if idx < 0 {
		idx = strings.Index(line, "File (")
	}
	if idx < 0 {
		return false
	}
	rest := line[idx:]
	// If the File() argument is a pure string literal with no $ interpolation
	if strings.Contains(rest, "\"") && !strings.Contains(rest, "$") && !strings.Contains(rest, "+") {
		// Check if there's only string literals (no variable args)
		// File("/var/data/config.json") -> safe
		parenStart := strings.Index(rest, "(")
		parenEnd := strings.Index(rest, ")")
		if parenStart >= 0 && parenEnd > parenStart {
			arg := rest[parenStart+1 : parenEnd]
			arg = strings.TrimSpace(arg)
			if strings.HasPrefix(arg, "\"") && strings.HasSuffix(arg, "\"") {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-KT-029: Kotlin open redirect
// ---------------------------------------------------------------------------

type KotlinOpenRedirect struct{}

func (r *KotlinOpenRedirect) ID() string   { return "BATOU-KT-029" }
func (r *KotlinOpenRedirect) Name() string { return "KotlinOpenRedirect" }
func (r *KotlinOpenRedirect) Description() string {
	return "Detects open redirect via Ktor respondRedirect or servlet sendRedirect with user-controlled URL."
}
func (r *KotlinOpenRedirect) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *KotlinOpenRedirect) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinOpenRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail: needs redirect
	if !strings.Contains(ctx.Content, "respondRedirect") && !strings.Contains(ctx.Content, "sendRedirect") {
		return nil
	}

	// Must have user input
	if !rules.GMatchFile(reKotlinUserInput, ctx) {
		return nil
	}

	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched bool
		if rules.GMatchLower(reRespondRedirect, line, lowered[i]) {
			matched = true
		} else if rules.GMatchLower(reSendRedirect, line, lowered[i]) {
			matched = true
		}

		if !matched {
			continue
		}

		// Skip hardcoded redirects: respondRedirect("/dashboard")
		if rules.GMatchLower(reRedirectHardcoded, line, lowered[i]) {
			continue
		}

		context := surroundingContext(lines, i, 10)

		// Skip if URL validation is present
		if reURLValidation.MatchString(context) {
			continue
		}

		// Skip if integer coercion (e.g., /items/$id)
		if reIntCoercion.MatchString(context) {
			continue
		}

		// Skip when expression (enum-like mapping)
		if reWhenExpr.MatchString(context) {
			continue
		}

		// Skip if allowlist check
		if reAllowlistCheck.MatchString(context) {
			continue
		}

		// Skip if regex validation
		if strings.Contains(context, ".matches(Regex(") {
			continue
		}

		// Skip if no user input nearby
		if !reKotlinUserInput.MatchString(context) {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Kotlin open redirect with user-controlled URL",
			Description:   "A redirect destination is derived from user input without validation. An attacker can craft a URL that redirects users to a malicious site for phishing or credential theft.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(trimmed, 120),
			Suggestion:    "Validate redirect URLs: check that the URL starts with '/' (relative) and doesn't start with '//' (protocol-relative). For absolute URLs, validate the host against an allowlist. Use a when/map pattern for known destinations.",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"kotlin", "open-redirect"},
		})
	}
	return findings
}
