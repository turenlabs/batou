package validation

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-VAL-001: Direct use of request params in operations without validation
var (
	// Python: request params flow into operations
	reFlaskRequestArgs  = regexp.MustCompile(`request\.(?:args|form|values|json)\s*(?:\.\s*get\s*\(|(?:\[))`)
	reDjangoRequestData = regexp.MustCompile(`request\.(?:GET|POST|data|query_params)\s*(?:\.\s*get\s*\(|(?:\[))`)

	// JS/TS: req.params / req.query / req.body used directly
	reExpressParams = regexp.MustCompile(`req\.(?:params|query|body)\s*(?:\.\s*\w+|\[)`)

	// Go: r.URL.Query().Get or r.FormValue
	reGoHTTPParams = regexp.MustCompile(`(?:r|req|request)\.(?:URL\.Query\(\)\.Get\(|FormValue\(|PostFormValue\(|Form\.Get\()`)

	// Java: request.getParameter
	reJavaServletParam = regexp.MustCompile(`request\.getParameter\s*\(`)

	// PHP: $_GET / $_POST / $_REQUEST
	rePHPSuperglobal = regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`)

	// Ruby: params[] access
	reRubyParams = regexp.MustCompile(`params\s*\[`)

	// Validation/sanitization indicators (if present nearby, suppress finding)
	reValidationPresent = regexp.MustCompile(`(?i)\b(?:validate|sanitize|clean|escape|parseInt|parseFloat|Number\(|int\(|float\(|isinstance|strconv\.|regexp\.|@Valid|@Pattern|Joi\.|zod\.|\.parse\(|\.safeParse\(|yup\.|validator\.|express-validator|filter_var|intval|is_numeric|\.to_i\b|Integer\.parseInt|Long\.parseLong|\.matches\(|pydantic|wtforms|marshmallow|binding\.Bind|ValidationPipe)\b`)

	// Parameterized SQL — only match when actual placeholders are present in
	// a query string (not just the DB function name, which could still use
	// string concatenation).
	reParameterizedSQL = regexp.MustCompile(`(?:` +
		`=\s*\$\d+` + // PostgreSQL-style: = $1, = $2
		`|,\s*\$\d+` + // PostgreSQL-style in list: , $2
		`|LIMIT\s+\$\d+` + // PostgreSQL-style: LIMIT $3
		`|=\s*\?` + // MySQL-style: = ?
		`|,\s*\?` + // MySQL-style in VALUES: , ?
		`|=\s*%s` + // Python DB-API style: = %s
		`|,\s*%s` + // Python DB-API style: , %s
		`)`)

	// ORM / query builder patterns that are inherently safe (auto-parameterized).
	// These only match patterns where string interpolation is NOT being used.
	reORMUsage = regexp.MustCompile(`(?i)(?:` +
		// Django ORM keyword-arg filtering (auto-parameterized)
		`\.objects\.filter\s*\(\s*\w+` +
		`|\.objects\.exclude\s*\(\s*\w+` +
		`|\.objects\.annotate\s*\(` +
		`|\.objects\.aggregate\s*\(` +
		`|\.objects\.create\s*\(\s*\w+` +
		`|\.values\s*\(` + // Django .values()
		// ActiveRecord find_by with hash args (auto-parameterized)
		`|\.find_by\s*\(\s*\w+\s*:` +
		`|\.find_by_\w+` +
		// ActiveRecord where with placeholder: .where('col = ?', val)
		`|\.where\s*\(\s*(?:"|')[^"']*\?\s*(?:"|')` +
		`|\.where\s*\(\s*\w+\s*:` + // .where(id: params[:id]) — hash syntax
		// Knex query builder chain
		`|db\s*\(\s*(?:"|')\w+(?:"|')\s*\)\s*\.` +
		`|\.andWhere\s*\(` +
		// ActiveRecord update_all with placeholder
		`|update_all\s*\(\s*\[` +
		// ActiveRecord Arel (auto-parameterized)
		`|\.arel_table` +
		// Java PreparedStatement (always parameterized)
		`|PreparedStatement` +
		`|\.prepareStatement\s*\(` +
		`)`)

	// Path-safety indicators — path traversal prevented
	rePathSafety = regexp.MustCompile(`(?i)(?:` +
		`path\.resolve\b` + // Node path.resolve
		`|path\.basename\b` + // Node path.basename
		`|path\.join\b` + // Node path.join (often with resolve/startsWith)
		`|filepath\.Clean\b` + // Go filepath.Clean
		`|filepath\.Base\b` + // Go filepath.Base
		`|filepath\.Join\b` + // Go filepath.Join
		`|os\.path\.basename\b` + // Python os.path.basename
		`|os\.path\.realpath\b` + // Python os.path.realpath
		`|\.resolve\(\)` + // Python pathlib .resolve()
		`|File\.realpath\b` + // Ruby File.realpath
		`|File\.basename\b` + // Ruby File.basename
		`|startsWith\s*\(` + // JS startsWith check
		`|\.startswith\s*\(` + // Python startswith check
		`|strings\.HasPrefix\s*\(` + // Go strings.HasPrefix
		`|start_with\?\s*\(` + // Ruby start_with?
		`|realpath\s*\(` + // PHP realpath
		`)`)

	// HTML-safe output indicators — XSS prevention already handled
	reHTMLSafe = regexp.MustCompile(`(?i)(?:` +
		`escapeHtml\b` + // escape-html npm package
		`|DOMPurify\.sanitize\b` + // DOMPurify
		`|CGI\.escapeHTML\b` + // Ruby CGI.escapeHTML
		`|markupsafe\.escape\b` + // Python markupsafe
		`|html\.EscapeString\b` + // Go html.EscapeString
		`|html/template` + // Go html/template (auto-escapes)
		`|render_template\s*\(` + // Flask render_template (Jinja2 auto-escapes)
		`|htmlspecialchars\s*\(` + // PHP htmlspecialchars
		`|res\.json\s*\(` + // Express JSON response (no HTML)
		`|jsonify\s*\(` + // Flask jsonify (no HTML)
		`|JsonResponse\s*\(` + // Django JsonResponse (no HTML)
		`|\.to_json\b` + // Ruby to_json (no HTML)
		`|content_type\s*:\s*:json` + // Sinatra JSON content type
		`|json\.NewEncoder\b` + // Go JSON encoder
		`)`)

	// URL-safety indicators — SSRF/redirect prevention
	reURLSafe = regexp.MustCompile(`(?i)(?:` +
		`new\s+URL\s*\(` + // JS URL parsing
		`|url\.Parse\s*\(` + // Go url.Parse
		`|urlparse\s*\(` + // Python urlparse
		`|URI\.parse\s*\(` + // Ruby URI.parse
		`|ALLOWED_REDIRECT` + // Explicit allowlist variable names
		`|allowedHosts` +
		`|allowed_hosts` +
		`)`)

	// Equality / switch / comparison — value is checked before use.
	reEqualityCheck = regexp.MustCompile(`(?i)(?:` +
		`switch\s*\(` + // switch statement
		`|case\s+(?:"|')` + // case branch with literal
		`|allowedFiles\b` + // explicit allowlist variable names
		`|allowedActions\b` +
		`|allowed\b.*\.includes\s*\(` + // allowed.includes(...)
		`)`)
)

// BATOU-VAL-002: Missing type coercion / bounds checking
var (
	// parseInt without isNaN check (JS)
	reParseIntNoCheck = regexp.MustCompile(`parseInt\s*\(\s*(?:req\.|request\.|params|query|body)\w*`)

	// Array indexing with user input
	reArrayUserIndex = regexp.MustCompile(`\[\s*(?:req\.|request\.|params|query|body)\w*\s*(?:\.\s*\w+\s*)?\]`)

	// NaN check indicators
	reNaNCheck = regexp.MustCompile(`(?i)\b(?:isNaN|Number\.isNaN|Number\.isFinite|isFinite|Number\.isInteger|!==?\s*NaN)\b`)
)

// BATOU-VAL-003: Missing length/size validation
var (
	// User input in DB operations without length check (JS)
	reBodyInDB = regexp.MustCompile(`(?:req\.body\.\w+|request\.body\.\w+)`)
	reDBOp     = regexp.MustCompile(`(?i)\.(?:create|save|insert|update|findOneAndUpdate|query|execute|exec)\s*\(`)

	// File upload without size limit
	reFileUploadNoLimit = regexp.MustCompile(`(?i)(?:multer\s*\(\s*\{[^}]*\}|upload\.(?:single|array|fields)\s*\()`)
	reFileSizeLimit     = regexp.MustCompile(`(?i)(?:limits\s*:|fileSize\s*:|maxFileSize|maxSize|sizeLimit|limitSize)`)

	// Length check indicators
	reLengthCheck = regexp.MustCompile(`(?i)(?:\.length\b|\.trim\(\)|\.size\b|maxlength|maxLength|max_length|strlen|len\()`)
)

// BATOU-VAL-004: Missing enum/allowlist validation
var (
	// Dynamic property access from user input (JS/TS)
	reDynPropAccess = regexp.MustCompile(`\w+\s*\[\s*(?:req\.|request\.|params\.|query\.|body\.)[\w.]+\s*\]`)

	// Dynamic property access from user input (Python)
	reDynAttrAccess = regexp.MustCompile(`(?:getattr\s*\([^)]*(?:request\.|params)|__dict__\s*\[\s*(?:request\.|params))`)

	// Dynamic property access from user input (Go)
	reDynMapAccessGo = regexp.MustCompile(`\w+\s*\[\s*(?:r\.URL\.Query\(\)\.Get|r\.FormValue)\s*\(`)

	// Allowlist check indicators
	reAllowlistCheck = regexp.MustCompile(`(?i)(?:\.includes\s*\(|\.indexOf\s*\(|\.has\s*\(|in\s+\[|switch\s*\(|allowlist|whitelist|allowedValues|validValues|enum\b|OneOf|\.Contains\()`)
)

// ---------------------------------------------------------------------------
// Comment detection (false positive reduction)
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*(?://|#|--|;|%|/\*)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

// truncate ensures matched text doesn't exceed maxLen characters.
func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// scopeHasPattern checks whether any line within a window around the given
// line index contains the given pattern. This approximates "in the same
// function scope" for single-file regex analysis.
func scopeHasPattern(lines []string, lineIdx int, re *regexp.Regexp, window int) bool {
	start := lineIdx - window
	if start < 0 {
		start = 0
	}
	end := lineIdx + window
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		if re.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-VAL-001: Direct use of request params without validation
// ---------------------------------------------------------------------------

type DirectParamUsage struct{}

func (r DirectParamUsage) ID() string              { return "BATOU-VAL-001" }
func (r DirectParamUsage) Name() string            { return "Direct Request Parameter Usage" }
func (r DirectParamUsage) DefaultSeverity() rules.Severity { return rules.High }
func (r DirectParamUsage) Description() string {
	return "Detects request parameters used directly in operations without any validation or sanitization call nearby."
}
func (r DirectParamUsage) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangRuby,
	}
}

// paramUsageSuppressed checks whether the parameter access at lineIdx is
// used in a safe context by scanning surrounding lines for evidence of
// validation, parameterized queries, ORM usage, path safety, HTML escaping,
// URL validation, or equality/allowlist checks.
func paramUsageSuppressed(lines []string, lineIdx int) bool {
	const window = 20

	// Layer 1: Original validation/sanitization keywords
	if scopeHasPattern(lines, lineIdx, reValidationPresent, window) {
		return true
	}

	// Layer 2: Parameterized SQL (the param is bound safely via placeholders)
	if scopeHasPattern(lines, lineIdx, reParameterizedSQL, window) {
		return true
	}

	// Layer 3: ORM / query builder (input goes through safe abstraction)
	if scopeHasPattern(lines, lineIdx, reORMUsage, window) {
		return true
	}

	// Layer 4: Path-safety functions (traversal already handled)
	if scopeHasPattern(lines, lineIdx, rePathSafety, window) {
		return true
	}

	// Layer 5: HTML-safe output (XSS already handled or JSON-only)
	if scopeHasPattern(lines, lineIdx, reHTMLSafe, window) {
		return true
	}

	// Layer 6: URL-safety (SSRF/redirect already handled)
	if scopeHasPattern(lines, lineIdx, reURLSafe, window) {
		return true
	}

	// Layer 7: Equality / switch / comparison checks
	if scopeHasPattern(lines, lineIdx, reEqualityCheck, window) {
		return true
	}

	return false
}

func (r DirectParamUsage) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	var patterns []pattern

	switch ctx.Language {
	case rules.LangPython:
		patterns = []pattern{
			{reFlaskRequestArgs, "high", "Flask request parameter used without validation"},
			{reDjangoRequestData, "high", "Django request data used without validation"},
		}
	case rules.LangJavaScript, rules.LangTypeScript:
		patterns = []pattern{
			{reExpressParams, "high", "Express request parameter used without validation"},
		}
	case rules.LangGo:
		patterns = []pattern{
			{reGoHTTPParams, "high", "HTTP request parameter used without validation"},
		}
	case rules.LangJava:
		patterns = []pattern{
			{reJavaServletParam, "high", "Servlet request parameter used without validation"},
		}
	case rules.LangPHP:
		patterns = []pattern{
			{rePHPSuperglobal, "high", "PHP superglobal used without validation"},
		}
	case rules.LangRuby:
		patterns = []pattern{
			{reRubyParams, "medium", "Rails params used without validation"},
		}
	default:
		return nil
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				// Check if validation/sanitization exists nearby
				if paramUsageSuppressed(lines, i) {
					continue
				}

				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Missing Input Validation: " + p.desc,
					Description:   "User input from request parameters should be validated before use. Missing validation is the #1 weakness in AI-generated code (CWE-20).",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Validate and sanitize all request parameters before use. Use type coercion (parseInt, int()), schema validation (Joi, zod, pydantic), or allowlists as appropriate.",
					CWEID:         "CWE-20",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"validation", "input-validation", "cwe-20"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-002: Missing type coercion / bounds checking
// ---------------------------------------------------------------------------

type MissingTypeCoercion struct{}

func (r MissingTypeCoercion) ID() string              { return "BATOU-VAL-002" }
func (r MissingTypeCoercion) Name() string            { return "Missing Type Coercion" }
func (r MissingTypeCoercion) DefaultSeverity() rules.Severity { return rules.Medium }
func (r MissingTypeCoercion) Description() string {
	return "Detects user input used where a specific type is expected without proper parsing or bounds checking."
}
func (r MissingTypeCoercion) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript,
		rules.LangPython, rules.LangGo, rules.LangJava,
	}
}

func (r MissingTypeCoercion) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// parseInt/parseFloat without isNaN check (JS/TS)
		if ctx.Language == rules.LangJavaScript || ctx.Language == rules.LangTypeScript {
			if loc := reParseIntNoCheck.FindStringIndex(line); loc != nil {
				// Check if NaN check exists nearby
				if !scopeHasPattern(lines, i, reNaNCheck, 5) {
					matched := truncate(line[loc[0]:loc[1]], 120)
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						SeverityLabel: r.DefaultSeverity().String(),
						Title:         "Missing NaN check after parseInt on user input",
						Description:   "parseInt() returns NaN for non-numeric strings. Without an isNaN check, NaN can propagate and cause unexpected behavior.",
						FilePath:      ctx.FilePath,
						LineNumber:    i + 1,
						MatchedText:   matched,
						Suggestion:    "Check for NaN after parsing: const id = parseInt(req.params.id); if (isNaN(id)) return res.status(400).send('Invalid ID');",
						CWEID:         "CWE-20",
						OWASPCategory: "A03:2021-Injection",
						Language:      ctx.Language,
						Confidence:    "medium",
						Tags:          []string{"validation", "type-coercion", "cwe-20"},
					})
				}
			}
		}

		// Array indexing with user input (any language)
		if loc := reArrayUserIndex.FindStringIndex(line); loc != nil {
			matched := truncate(line[loc[0]:loc[1]], 120)
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Array/object indexing with user input without bounds check",
				Description:   "Using user input directly as an array index or object key without validation can lead to out-of-bounds access, prototype pollution, or unexpected behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate that the index is within bounds. For numeric indices, parse and check range. For string keys, use an allowlist.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"validation", "bounds-check", "cwe-20"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-003: Missing length/size validation
// ---------------------------------------------------------------------------

type MissingLengthValidation struct{}

func (r MissingLengthValidation) ID() string              { return "BATOU-VAL-003" }
func (r MissingLengthValidation) Name() string            { return "Missing Length Validation" }
func (r MissingLengthValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r MissingLengthValidation) Description() string {
	return "Detects user input used in database or storage operations without length or size validation, which can lead to DoS or storage abuse."
}
func (r MissingLengthValidation) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript,
		rules.LangPython, rules.LangGo, rules.LangJava, rules.LangRuby, rules.LangPHP,
	}
}

func (r MissingLengthValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for file upload without size limit
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if loc := reFileUploadNoLimit.FindStringIndex(line); loc != nil {
			// Check if size limit exists nearby
			if !scopeHasPattern(lines, i, reFileSizeLimit, 8) {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "File upload without size limit",
					Description:   "File upload handlers should enforce a maximum file size to prevent denial of service through large file uploads.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Add a file size limit: multer({ limits: { fileSize: 5 * 1024 * 1024 } }) or equivalent for your framework.",
					CWEID:         "CWE-20",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"validation", "file-upload", "dos", "cwe-20"},
				})
			}
		}
	}

	// Check for req.body fields used in DB operations without length check (JS/TS)
	if ctx.Language == rules.LangJavaScript || ctx.Language == rules.LangTypeScript {
		hasDBOp := false
		hasBody := false
		for _, line := range lines {
			if reDBOp.MatchString(line) {
				hasDBOp = true
			}
			if reBodyInDB.MatchString(line) {
				hasBody = true
			}
			if hasDBOp && hasBody {
				break
			}
		}

		if hasDBOp && hasBody {
			// Check if there's any length validation in the file
			hasLengthCheck := false
			for _, line := range lines {
				if reLengthCheck.MatchString(line) {
					hasLengthCheck = true
					break
				}
			}
			if !hasLengthCheck {
				// Find the first DB operation line to report
				for i, line := range lines {
					if reDBOp.MatchString(line) {
						matched := truncate(strings.TrimSpace(line), 120)
						findings = append(findings, rules.Finding{
							RuleID:        r.ID(),
							Severity:      r.DefaultSeverity(),
							SeverityLabel: r.DefaultSeverity().String(),
							Title:         "Request body used in DB operation without length validation",
							Description:   "User-supplied strings stored in databases without length validation can lead to storage abuse and potential DoS.",
							FilePath:      ctx.FilePath,
							LineNumber:    i + 1,
							MatchedText:   matched,
							Suggestion:    "Validate string lengths before database operations: if (req.body.name.length > 255) return res.status(400).send('Name too long');",
							CWEID:         "CWE-20",
							OWASPCategory: "A03:2021-Injection",
							Language:      ctx.Language,
							Confidence:    "low",
							Tags:          []string{"validation", "length-check", "dos", "cwe-20"},
						})
						break
					}
				}
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-004: Missing enum/allowlist validation
// ---------------------------------------------------------------------------

type MissingAllowlistValidation struct{}

func (r MissingAllowlistValidation) ID() string              { return "BATOU-VAL-004" }
func (r MissingAllowlistValidation) Name() string            { return "Missing Allowlist Validation" }
func (r MissingAllowlistValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r MissingAllowlistValidation) Description() string {
	return "Detects user input used as object keys or in dynamic property access without allowlist validation, which can lead to prototype pollution or unauthorized access."
}
func (r MissingAllowlistValidation) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript,
		rules.LangPython, rules.LangGo, rules.LangRuby,
	}
}

func (r MissingAllowlistValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string
		found := false

		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reDynPropAccess.FindStringIndex(line); loc != nil {
				if !scopeHasPattern(lines, i, reAllowlistCheck, 10) {
					matched = truncate(line[loc[0]:loc[1]], 120)
					desc = "Dynamic property access with user input without allowlist"
					found = true
				}
			}
		case rules.LangPython:
			if loc := reDynAttrAccess.FindStringIndex(line); loc != nil {
				if !scopeHasPattern(lines, i, reAllowlistCheck, 10) {
					matched = truncate(line[loc[0]:loc[1]], 120)
					desc = "Dynamic attribute access with user input without allowlist"
					found = true
				}
			}
		case rules.LangGo:
			if loc := reDynMapAccessGo.FindStringIndex(line); loc != nil {
				if !scopeHasPattern(lines, i, reAllowlistCheck, 10) {
					matched = truncate(line[loc[0]:loc[1]], 120)
					desc = "Dynamic map access with user input without allowlist"
					found = true
				}
			}
		}

		if found {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing Allowlist: " + desc,
				Description:   "Using user input as an object key or for dynamic property access without an allowlist can lead to prototype pollution (JS), unauthorized data access, or unexpected behavior.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate user input against an explicit allowlist of permitted values before using it as a key: const allowed = ['name', 'email']; if (!allowed.includes(key)) return;",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"validation", "allowlist", "prototype-pollution", "cwe-20"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-VAL-005: File upload without content-type validation (CWE-434)
// ---------------------------------------------------------------------------

// File upload handler patterns
var (
	// Go: multipart form handling
	reGoMultipartForm  = regexp.MustCompile(`\.(?:FormFile|MultipartForm|ParseMultipartForm)\s*\(`)
	reGoContentType    = regexp.MustCompile(`(?i)(?:content[_-]?type|mime|DetectContentType|http\.DetectContentType)`)
	reGoFileExt        = regexp.MustCompile(`(?:filepath\.Ext|path\.Ext|strings\.HasSuffix)\s*\(`)

	// Python: file upload patterns
	rePyFileUpload     = regexp.MustCompile(`(?:request\.(?:files|FILES)|FileField|ImageField|UploadedFile)\b`)
	rePyContentCheck   = regexp.MustCompile(`(?i)(?:content[_-]?type|mimetype|allowed_extensions|ALLOWED_EXTENSIONS|magic\.from_buffer|imghdr|filetype)`)

	// JS/TS: multer / express-fileupload / formidable
	reJSFileUpload     = regexp.MustCompile(`(?:multer|fileUpload|formidable|busboy|multiparty)\s*\(`)
	reJSFileFilter     = regexp.MustCompile(`(?i)(?:fileFilter|mimetype|content[_-]?type|allowedTypes|allowedMimes)`)
	reJSMimeType       = regexp.MustCompile(`(?i)(?:\.mimetype|\.type)\s*(?:===?|!==?|\.includes|\.match|\.test)`)

	// Java: multipart upload
	reJavaMultipart    = regexp.MustCompile(`(?:MultipartFile|@RequestParam.*MultipartFile|Part\s+\w+\s*=|getPart\s*\()`)
	reJavaContentCheck = regexp.MustCompile(`(?i)(?:getContentType|content[_-]?type|MediaType|MimeType)`)

	// PHP: file upload
	rePHPFileUpload    = regexp.MustCompile(`\$_FILES\s*\[`)
	rePHPTypeCheck     = regexp.MustCompile(`(?i)(?:mime_content_type|finfo_file|getimagesize|exif_imagetype|pathinfo.*PATHINFO_EXTENSION)`)

	// Ruby: file upload
	reRubyFileUpload   = regexp.MustCompile(`(?:params\[.*\]\.tempfile|uploaded_file|ActionDispatch::Http::UploadedFile|attach\s*\()`)
	reRubyContentCheck = regexp.MustCompile(`(?i)(?:content[_-]?type|Marcel|MimeMagic|allowed_types)`)

	// Store in web-accessible directory patterns
	reWebAccessibleDir = regexp.MustCompile(`(?i)(?:public/|static/|www/|htdocs/|webroot/|uploads/|media/)\w*\.`)
)

type FileUploadHardening struct{}

func (r FileUploadHardening) ID() string              { return "BATOU-VAL-005" }
func (r FileUploadHardening) Name() string            { return "File Upload Hardening" }
func (r FileUploadHardening) DefaultSeverity() rules.Severity { return rules.High }
func (r FileUploadHardening) Description() string {
	return "Detects file upload handlers missing content-type validation, size limits, or storing files in web-accessible directories."
}
func (r FileUploadHardening) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby,
	}
}

func (r FileUploadHardening) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Determine language-specific upload and validation patterns
	var uploadRE *regexp.Regexp
	var contentCheckRE *regexp.Regexp

	switch ctx.Language {
	case rules.LangGo:
		uploadRE = reGoMultipartForm
		contentCheckRE = reGoContentType
	case rules.LangPython:
		uploadRE = rePyFileUpload
		contentCheckRE = rePyContentCheck
	case rules.LangJavaScript, rules.LangTypeScript:
		uploadRE = reJSFileUpload
		contentCheckRE = reJSFileFilter
	case rules.LangJava:
		uploadRE = reJavaMultipart
		contentCheckRE = reJavaContentCheck
	case rules.LangPHP:
		uploadRE = rePHPFileUpload
		contentCheckRE = rePHPTypeCheck
	case rules.LangRuby:
		uploadRE = reRubyFileUpload
		contentCheckRE = reRubyContentCheck
	default:
		return nil
	}

	// Find upload handlers
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if loc := uploadRE.FindStringIndex(line); loc != nil {
			// Check if content-type validation exists nearby
			hasContentCheck := scopeHasPattern(lines, i, contentCheckRE, 30)

			// For JS/TS, also check inline mime type checks
			if !hasContentCheck && (ctx.Language == rules.LangJavaScript || ctx.Language == rules.LangTypeScript) {
				hasContentCheck = scopeHasPattern(lines, i, reJSMimeType, 30)
			}

			// For Go, also check file extension checking
			if !hasContentCheck && ctx.Language == rules.LangGo {
				hasContentCheck = scopeHasPattern(lines, i, reGoFileExt, 30)
			}

			if !hasContentCheck {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "File upload without content-type validation",
					Description:   "File upload handler does not validate the content type or file extension of uploaded files. Attackers can upload executable files (web shells, scripts) disguised as safe file types.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Validate the file content type using magic bytes (not just the extension or Content-Type header). Maintain an allowlist of permitted MIME types. Use libraries like file-type (Node.js), python-magic, or http.DetectContentType (Go).",
					CWEID:         "CWE-434",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"validation", "file-upload", "content-type", "cwe-434"},
				})
			}
		}

		// Check for storing uploads in web-accessible directories
		if loc := reWebAccessibleDir.FindStringIndex(line); loc != nil {
			// Only flag if there's also an upload handler in the file
			if uploadRE.MatchString(ctx.Content) {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "File upload stored in web-accessible directory",
					Description:   "Uploaded files are stored in a web-accessible directory. If an attacker uploads a web shell or executable file, it can be accessed directly via the web server.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Store uploaded files outside the web root. Serve them through an application handler that validates access permissions and sets safe Content-Type headers.",
					CWEID:         "CWE-434",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"validation", "file-upload", "storage", "cwe-434"},
				})
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(DirectParamUsage{})
	rules.Register(MissingTypeCoercion{})
	rules.Register(MissingLengthValidation{})
	rules.Register(MissingAllowlistValidation{})
	rules.Register(FileUploadHardening{})
}
