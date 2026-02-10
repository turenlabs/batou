package validation

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// GTSS-VAL-001: Direct use of request params in operations without validation
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
)

// GTSS-VAL-002: Missing type coercion / bounds checking
var (
	// parseInt without isNaN check (JS)
	reParseIntNoCheck = regexp.MustCompile(`parseInt\s*\(\s*(?:req\.|request\.|params|query|body)\w*`)

	// Array indexing with user input
	reArrayUserIndex = regexp.MustCompile(`\[\s*(?:req\.|request\.|params|query|body)\w*\s*(?:\.\s*\w+\s*)?\]`)

	// NaN check indicators
	reNaNCheck = regexp.MustCompile(`(?i)\b(?:isNaN|Number\.isNaN|Number\.isFinite|isFinite|Number\.isInteger|!==?\s*NaN)\b`)
)

// GTSS-VAL-003: Missing length/size validation
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

// GTSS-VAL-004: Missing enum/allowlist validation
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
// GTSS-VAL-001: Direct use of request params without validation
// ---------------------------------------------------------------------------

type DirectParamUsage struct{}

func (r DirectParamUsage) ID() string              { return "GTSS-VAL-001" }
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
				// Check if validation/sanitization exists nearby (within 10 lines)
				if scopeHasPattern(lines, i, reValidationPresent, 10) {
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
// GTSS-VAL-002: Missing type coercion / bounds checking
// ---------------------------------------------------------------------------

type MissingTypeCoercion struct{}

func (r MissingTypeCoercion) ID() string              { return "GTSS-VAL-002" }
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
// GTSS-VAL-003: Missing length/size validation
// ---------------------------------------------------------------------------

type MissingLengthValidation struct{}

func (r MissingLengthValidation) ID() string              { return "GTSS-VAL-003" }
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
// GTSS-VAL-004: Missing enum/allowlist validation
// ---------------------------------------------------------------------------

type MissingAllowlistValidation struct{}

func (r MissingAllowlistValidation) ID() string              { return "GTSS-VAL-004" }
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
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(DirectParamUsage{})
	rules.Register(MissingTypeCoercion{})
	rules.Register(MissingLengthValidation{})
	rules.Register(MissingAllowlistValidation{})
}
