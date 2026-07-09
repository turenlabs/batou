package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- FastAPI
// ---------------------------------------------------------------------------

// BATOU-FW-FASTAPI-001: Endpoint without auth dependency
var (
	reFastapiRoute       = regexp.MustCompile(`@app\.(?:get|post|put|delete|patch|options|head)\s*\(`)
	reFastapiDepends     = regexp.MustCompile(`Depends\s*\(`)
	reFastapiAuthKeyword = regexp.MustCompile(`(?i)(?:auth|security|token|current_user|get_current|verify|jwt|oauth|api_key|permission|require_auth)`)
)

// isFastAPIFile gates the FastAPI rule pack to files that actually use
// FastAPI. Without this guard, the `@app.get|post|...` shorthand
// triggers every rule against Flask 2 routes (Flask added the same
// shorthand decorators in 2.0). This was the dominant FP shape on the
// scan-harness Python sample (e.g. pallets/flask itself produced
// dozens of FASTAPI-001 hits in its test suite).
//
// Heuristic: a file is FastAPI iff it imports the FastAPI symbol or
// constructs a FastAPI() app. We don't gate on `from starlette` alone
// because Starlette routes use a different decorator shape.
var (
	reFastapiImport  = regexp.MustCompile(`(?m)^\s*(?:from\s+fastapi\b|import\s+fastapi\b)`)
	reFastapiAppCtor = regexp.MustCompile(`(?:^|=\s*)FastAPI\s*\(`)
)

func isFastAPIFile(content string) bool {
	return reFastapiImport.MatchString(content) || reFastapiAppCtor.MatchString(content)
}

// BATOU-FW-FASTAPI-002: CORS wildcard
var reFastapiCORSWildcard = regexp.MustCompile(`allow_origins\s*=\s*\[\s*["']\*["']\s*\]`)
var reFastapiAllowCredsTrue = regexp.MustCompile(`allow_credentials\s*=\s*True`)

// BATOU-FW-FASTAPI-003: Debug mode
var reFastapiDebug = regexp.MustCompile(`uvicorn\.run\s*\([^)]*debug\s*=\s*True`)

// BATOU-FW-FASTAPI-004: SQL injection via f-string
var reFastapiSQLFString = regexp.MustCompile(`(?:execute|text|raw)\s*\(\s*f["'](?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|MERGE)\b`)

// BATOU-FW-FASTAPI-005: Response model exposing internal fields
var reFastapiResponseInternal = regexp.MustCompile(`(?:response_model\s*=\s*\w+)`)
var reFastapiInternalFields = regexp.MustCompile(`(?:password|hashed_password|secret|token|salt|ssn|credit_card|internal_id|api_key)\s*(?::|=)`)

// BATOU-FW-FASTAPI-006: File upload without validation
var reFastapiFileUpload = regexp.MustCompile(`(?:file|upload)\s*:\s*UploadFile`)
var reFastapiFileValidation = regexp.MustCompile(`(?:content_type|filename|size|\.endswith|allowed_extensions|validate_file|file_extension|ALLOWED_TYPES)`)

// BATOU-FW-FASTAPI-007: OAuth2 without HTTPS
var reFastapiOAuth2HTTP = regexp.MustCompile(`OAuth2PasswordBearer\s*\(\s*tokenUrl\s*=\s*["']http://`)

// BATOU-FW-FASTAPI-008: Depends() without error handling
var reFastapiDependsNaked = regexp.MustCompile(`Depends\s*\(\s*(\w+)\s*\)`)
var reFastapiDependsErrorHandling = regexp.MustCompile(`(?:try\s*:|except\s+|HTTPException|raise\s+)`)

// BATOU-FW-FASTAPI-009: Jinja2 without autoescaping
var reFastapiJinja2NoEscape = regexp.MustCompile(`Jinja2Templates\s*\(`)
var reFastapiAutoescapeFalse = regexp.MustCompile(`autoescape\s*=\s*False`)

// BATOU-FW-FASTAPI-010: Background task with sensitive data
var reFastapiBackgroundTask = regexp.MustCompile(`(?:background_tasks\.add_task|BackgroundTasks)\s*\(`)
var reFastapiSensitiveDataInTask = regexp.MustCompile(`(?:password|secret|token|api_key|credit_card|ssn|private_key)`)

// BATOU-FW-FASTAPI-012: APIKeyQuery (API key in URL query string)
var reFastapiAPIKeyQuery = regexp.MustCompile(`APIKeyQuery\s*\(`)

// BATOU-FW-FASTAPI-013: TrustedHostMiddleware with wildcard
var reFastapiTrustedHost = regexp.MustCompile(`TrustedHostMiddleware`)
var reFastapiTrustedHostWild = regexp.MustCompile(`allowed_hosts\s*=\s*\[\s*["']\*["']\s*\]`)

func init() {
	rules.Register(&FastAPINoAuth{})
	rules.Register(&FastAPICORSWildcard{})
	rules.Register(&FastAPIDebugMode{})
	rules.Register(&FastAPISQLInjection{})
	rules.Register(&FastAPIResponseExposure{})
	rules.Register(&FastAPIFileUpload{})
	rules.Register(&FastAPIOAuth2HTTP{})
	rules.Register(&FastAPIDependsNoError{})
	rules.Register(&FastAPIJinja2NoEscape{})
	rules.Register(&FastAPIBackgroundSensitive{})
	rules.Register(&FastAPIAPIKeyQuery{})
	rules.Register(&FastAPITrustedHostWildcard{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-001: FastAPI endpoint without authentication dependency
// ---------------------------------------------------------------------------

type FastAPINoAuth struct{}

func (r *FastAPINoAuth) ID() string                      { return "BATOU-FW-FASTAPI-001" }
func (r *FastAPINoAuth) Name() string                    { return "FastAPINoAuth" }
func (r *FastAPINoAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FastAPINoAuth) Description() string {
	return "Detects FastAPI route handlers without authentication dependencies."
}
func (r *FastAPINoAuth) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPINoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isFastAPIFile(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		if !rules.GMatchLower(reFastapiRoute, line, lowered[i]) {
			continue
		}

		// Check the route decorator and subsequent lines for Depends with auth
		lookAhead := 10
		if i+lookAhead > len(lines) {
			lookAhead = len(lines) - i
		}
		block := strings.Join(lines[i:i+lookAhead], "\n")

		hasAuth := reFastapiDepends.MatchString(block) && reFastapiAuthKeyword.MatchString(block)
		if hasAuth {
			continue
		}

		// Skip if the route itself has dependencies= in decorator
		if strings.Contains(line, "dependencies=") && rules.GMatchLower(reFastapiAuthKeyword, line, lowered[i]) {
			continue
		}

		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "FastAPI endpoint without authentication dependency",
			Description:   "This FastAPI route handler does not include an authentication dependency (Depends). Without authentication, the endpoint is accessible to unauthenticated users, which may be unintended for sensitive operations.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Add an authentication dependency to the route: @app.get('/path', dependencies=[Depends(get_current_user)]) or include current_user: User = Depends(get_current_user) as a parameter.",
			CWEID:         "CWE-306",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"framework", "fastapi", "authentication"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-002: CORS middleware with allow_origins=["*"]
// ---------------------------------------------------------------------------

type FastAPICORSWildcard struct{}

func (r *FastAPICORSWildcard) ID() string                      { return "BATOU-FW-FASTAPI-002" }
func (r *FastAPICORSWildcard) Name() string                    { return "FastAPICORSWildcard" }
func (r *FastAPICORSWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPICORSWildcard) Description() string {
	return "Detects FastAPI CORSMiddleware configured with allow_origins=['*']."
}
func (r *FastAPICORSWildcard) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPICORSWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		m := rules.GFindLower(reFastapiCORSWildcard, line, lowered[i])
		if m == "" {
			continue
		}

		// Look at the same add_middleware/CORSMiddleware block (this line plus
		// up to ~15 surrounding lines) for an allow_credentials=True flag. The
		// combination is forbidden by Starlette and represents an explicit auth
		// bypass surface — escalate to Critical.
		from := i - 7
		if from < 0 {
			from = 0
		}
		to := i + 8
		if to > len(lines) {
			to = len(lines)
		}
		block := strings.Join(lines[from:to], "\n")
		credsTrue := reFastapiAllowCredsTrue.MatchString(block)

		matched := m
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}
		sev := r.DefaultSeverity()
		title := "FastAPI CORS allows all origins"
		desc := "CORSMiddleware is configured with allow_origins=['*'], allowing any website to make cross-origin requests to this API. This can expose sensitive data and APIs to untrusted domains."
		conf := "high"
		if credsTrue {
			sev = rules.Critical
			title = "FastAPI CORS wildcard with credentials enabled"
			desc = "CORSMiddleware is configured with allow_origins=['*'] AND allow_credentials=True. Starlette/FastAPI forbid this combination because it allows any origin to make authenticated cross-origin requests with cookies/Authorization headers — full session-hijack surface."
			conf = "high"
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      sev,
			SeverityLabel: sev.String(),
			Title:         title,
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Specify explicit trusted origins: allow_origins=['https://example.com', 'https://app.example.com']. Never combine wildcards with allow_credentials=True.",
			CWEID:         "CWE-346",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    conf,
			Tags:          []string{"framework", "fastapi", "cors"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-003: Debug mode enabled
// ---------------------------------------------------------------------------

type FastAPIDebugMode struct{}

func (r *FastAPIDebugMode) ID() string                      { return "BATOU-FW-FASTAPI-003" }
func (r *FastAPIDebugMode) Name() string                    { return "FastAPIDebugMode" }
func (r *FastAPIDebugMode) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPIDebugMode) Description() string {
	return "Detects FastAPI/uvicorn running with debug=True."
}
func (r *FastAPIDebugMode) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPIDebugMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if m := rules.GFindLower(reFastapiDebug, line, lowered[i]); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "FastAPI debug mode enabled in uvicorn",
				Description:   "uvicorn.run() is called with debug=True, which exposes detailed error pages with stack traces and internal state to end users. This must be disabled in production.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove debug=True or set it via environment variable: debug=os.environ.get('DEBUG', 'false').lower() == 'true'. Never enable debug mode in production.",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fastapi", "debug"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-004: SQL injection via f-string
// ---------------------------------------------------------------------------

type FastAPISQLInjection struct{}

func (r *FastAPISQLInjection) ID() string                      { return "BATOU-FW-FASTAPI-004" }
func (r *FastAPISQLInjection) Name() string                    { return "FastAPISQLInjection" }
func (r *FastAPISQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPISQLInjection) Description() string {
	return "Detects SQL injection via f-strings in raw query execution within FastAPI handlers."
}
func (r *FastAPISQLInjection) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPISQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if m := rules.GFindLower(reFastapiSQLFString, line, lowered[i]); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "FastAPI SQL injection via f-string in raw query",
				Description:   "An f-string is used to construct a SQL query passed to execute(), text(), or raw(). This allows SQL injection if any interpolated values come from user input.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use parameterized queries: db.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id}). Never use f-strings for SQL.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fastapi", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-005: Response model exposing internal fields
// ---------------------------------------------------------------------------

type FastAPIResponseExposure struct{}

func (r *FastAPIResponseExposure) ID() string                      { return "BATOU-FW-FASTAPI-005" }
func (r *FastAPIResponseExposure) Name() string                    { return "FastAPIResponseExposure" }
func (r *FastAPIResponseExposure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FastAPIResponseExposure) Description() string {
	return "Detects FastAPI response models that may expose internal or sensitive fields."
}
func (r *FastAPIResponseExposure) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *FastAPIResponseExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isFastAPIFile(ctx.Content) {
		return nil
	}
	var findings []rules.Finding

	// Only check files that define Pydantic models with response_model usage
	if !rules.GMatchFile(reFastapiResponseInternal, ctx) {
		return nil
	}

	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if rules.GMatchLower(reFastapiInternalFields, line, lowered[i]) && strings.Contains(ctx.Content, "BaseModel") {
			// Check that this is inside a Pydantic model class, not just any usage
			if strings.Contains(line, ":") && !strings.Contains(line, "def ") {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "FastAPI response model may expose sensitive fields",
					Description:   "A Pydantic model used as a response_model contains fields that appear to hold sensitive data (password, secret, token, etc.). If this model is returned in API responses, these fields will be exposed to clients.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Create separate response schemas that exclude sensitive fields. Use Field(exclude=True) or define a dedicated response model without internal fields: class UserResponse(BaseModel): id, name, email only.",
					CWEID:         "CWE-200",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"framework", "fastapi", "information-disclosure"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-006: File upload without validation
// ---------------------------------------------------------------------------

type FastAPIFileUpload struct{}

func (r *FastAPIFileUpload) ID() string                      { return "BATOU-FW-FASTAPI-006" }
func (r *FastAPIFileUpload) Name() string                    { return "FastAPIFileUpload" }
func (r *FastAPIFileUpload) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPIFileUpload) Description() string {
	return "Detects FastAPI file upload endpoints without file type or size validation."
}
func (r *FastAPIFileUpload) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPIFileUpload) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !rules.GMatchLower(reFastapiFileUpload, line, lowered[i]) {
			continue
		}

		// Look ahead for validation in the function body
		lookAhead := 20
		if i+lookAhead > len(lines) {
			lookAhead = len(lines) - i
		}
		block := strings.Join(lines[i:i+lookAhead], "\n")

		if reFastapiFileValidation.MatchString(block) {
			continue
		}

		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "FastAPI file upload without type or size validation",
			Description:   "An UploadFile parameter is accepted without validating the file type, size, or content. This allows uploading malicious files such as executables, web shells, or oversized files that cause denial of service.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Validate file.content_type against an allowlist, check file.size against a maximum limit, and validate the file extension: if file.content_type not in ['image/png', 'image/jpeg']: raise HTTPException(400).",
			CWEID:         "CWE-434",
			OWASPCategory: "A04:2021-Insecure Design",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"framework", "fastapi", "file-upload"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-007: OAuth2 without HTTPS
// ---------------------------------------------------------------------------

type FastAPIOAuth2HTTP struct{}

func (r *FastAPIOAuth2HTTP) ID() string                      { return "BATOU-FW-FASTAPI-007" }
func (r *FastAPIOAuth2HTTP) Name() string                    { return "FastAPIOAuth2HTTP" }
func (r *FastAPIOAuth2HTTP) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPIOAuth2HTTP) Description() string {
	return "Detects FastAPI OAuth2PasswordBearer configured with an HTTP (non-HTTPS) token URL."
}
func (r *FastAPIOAuth2HTTP) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPIOAuth2HTTP) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if m := rules.GFindLower(reFastapiOAuth2HTTP, line, lowered[i]); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "FastAPI OAuth2 token URL uses HTTP instead of HTTPS",
				Description:   "OAuth2PasswordBearer is configured with an http:// token URL. OAuth2 tokens sent over unencrypted HTTP are vulnerable to interception, allowing attackers to steal access tokens.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use HTTPS for all OAuth2 token URLs: OAuth2PasswordBearer(tokenUrl='https://api.example.com/token'). Use relative paths in production: tokenUrl='/token'.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fastapi", "oauth2", "cleartext"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-008: Depends() without error handling
// ---------------------------------------------------------------------------

type FastAPIDependsNoError struct{}

func (r *FastAPIDependsNoError) ID() string                      { return "BATOU-FW-FASTAPI-008" }
func (r *FastAPIDependsNoError) Name() string                    { return "FastAPIDependsNoError" }
func (r *FastAPIDependsNoError) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FastAPIDependsNoError) Description() string {
	return "Detects FastAPI dependency injection without proper error handling that could expose internal errors."
}
func (r *FastAPIDependsNoError) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *FastAPIDependsNoError) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()

	// Collect unique dep names referenced via Depends(name) call sites.
	depNames := map[string]bool{}
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, m := range rules.GFindAllSubmatch(reFastapiDependsNaked, line, -1) {
			if len(m) >= 2 && m[1] != "" {
				depNames[m[1]] = true
			}
		}
	}
	if len(depNames) == 0 {
		return findings
	}

	// Already flagged dep functions (avoid duplicates per file).
	flagged := map[string]bool{}

	for i, line := range lines {
		// Match a top-level or nested function definition whose name is a dep.
		name, defIndent, ok := parseFastapiDef(line)
		if !ok {
			continue
		}
		if !depNames[name] || flagged[name] {
			continue
		}

		// Walk the function body until indent <= defIndent on a non-blank,
		// non-comment line.
		bodyEnd := len(lines)
		for j := i + 1; j < len(lines); j++ {
			ln := lines[j]
			trimmed := strings.TrimSpace(ln)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			indent := leadingIndent(ln)
			if indent <= defIndent {
				bodyEnd = j
				break
			}
		}
		body := strings.Join(lines[i:bodyEnd], "\n")
		if reFastapiDependsErrorHandling.MatchString(body) {
			flagged[name] = true
			continue
		}

		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "FastAPI Depends() without error handling",
			Description:   "A FastAPI dependency function is defined without try/except or HTTPException handling. If the dependency fails (database connection error, external service timeout), the unhandled exception may expose internal error details to the client.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Add try/except blocks inside the dependency function and raise HTTPException with appropriate status codes.",
			CWEID:         "CWE-755",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"framework", "fastapi", "error-handling"},
		})
		flagged[name] = true
	}
	return findings
}

// parseFastapiDef returns the function name and the leading indent level if
// `line` is a Python function definition, otherwise ok=false.
func parseFastapiDef(line string) (name string, indent int, ok bool) {
	indent = leadingIndent(line)
	t := strings.TrimLeft(line, " \t")
	t = strings.TrimPrefix(t, "async ")
	if !strings.HasPrefix(t, "def ") {
		return "", 0, false
	}
	rest := strings.TrimPrefix(t, "def ")
	// Function name is up to '(' or whitespace.
	end := strings.IndexAny(rest, "( \t")
	if end <= 0 {
		return "", 0, false
	}
	return rest[:end], indent, true
}

func leadingIndent(line string) int {
	n := 0
	for _, c := range line {
		switch c {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-009: Jinja2 template without autoescaping
// ---------------------------------------------------------------------------

type FastAPIJinja2NoEscape struct{}

func (r *FastAPIJinja2NoEscape) ID() string                      { return "BATOU-FW-FASTAPI-009" }
func (r *FastAPIJinja2NoEscape) Name() string                    { return "FastAPIJinja2NoEscape" }
func (r *FastAPIJinja2NoEscape) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPIJinja2NoEscape) Description() string {
	return "Detects FastAPI Jinja2Templates configured without autoescaping, enabling XSS."
}
func (r *FastAPIJinja2NoEscape) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *FastAPIJinja2NoEscape) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !rules.GMatchLower(reFastapiJinja2NoEscape, line, lowered[i]) {
			continue
		}

		// Check if autoescape is explicitly disabled nearby
		lookAhead := 5
		if i+lookAhead > len(lines) {
			lookAhead = len(lines) - i
		}
		block := strings.Join(lines[i:i+lookAhead], "\n")

		if reFastapiAutoescapeFalse.MatchString(block) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "FastAPI Jinja2 template with autoescaping disabled",
				Description:   "Jinja2Templates is configured with autoescape=False. Without autoescaping, any user input rendered in templates will not be HTML-escaped, creating XSS vulnerabilities.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Enable autoescaping: Jinja2Templates(directory='templates', autoescape=True) or use the default which has autoescaping enabled for .html files.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fastapi", "xss", "template"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-010: Background task with sensitive data in memory
// ---------------------------------------------------------------------------

type FastAPIBackgroundSensitive struct{}

func (r *FastAPIBackgroundSensitive) ID() string { return "BATOU-FW-FASTAPI-010" }
func (r *FastAPIBackgroundSensitive) Name() string {
	return "FastAPIBackgroundSensitive"
}
func (r *FastAPIBackgroundSensitive) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FastAPIBackgroundSensitive) Description() string {
	return "Detects FastAPI background tasks that may retain sensitive data in memory."
}
func (r *FastAPIBackgroundSensitive) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *FastAPIBackgroundSensitive) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !rules.GMatchLower(reFastapiBackgroundTask, line, lowered[i]) {
			continue
		}

		// Check if sensitive data is passed to the background task
		if rules.GMatchLower(reFastapiSensitiveDataInTask, line, lowered[i]) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "FastAPI background task with sensitive data",
				Description:   "A background task is created with what appears to be sensitive data (password, secret, token, API key) passed as an argument. Background tasks retain their arguments in memory until execution completes, increasing the exposure window for sensitive data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Pass only identifiers to background tasks and retrieve sensitive data within the task itself. Clear sensitive variables after use. Consider encrypting data passed to long-running tasks.",
				CWEID:         "CWE-226",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "fastapi", "sensitive-data", "background-task"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-012: APIKeyQuery places API key in URL query string
// ---------------------------------------------------------------------------

type FastAPIAPIKeyQuery struct{}

func (r *FastAPIAPIKeyQuery) ID() string                      { return "BATOU-FW-FASTAPI-012" }
func (r *FastAPIAPIKeyQuery) Name() string                    { return "FastAPIAPIKeyQuery" }
func (r *FastAPIAPIKeyQuery) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPIAPIKeyQuery) Description() string {
	return "Detects use of fastapi.security.APIKeyQuery, which carries the API key in the URL query string."
}
func (r *FastAPIAPIKeyQuery) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *FastAPIAPIKeyQuery) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !rules.GMatchLower(reFastapiAPIKeyQuery, line, lowered[i]) {
			continue
		}
		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "FastAPI APIKeyQuery exposes credentials in URLs",
			Description:   "APIKeyQuery requires clients to send the API key as a URL query parameter. Query strings are written to web-server access logs, browser history, proxy logs, and Referer headers — exposing the credential to anyone with log access.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Switch to APIKeyHeader (e.g. X-API-Key) or APIKeyCookie. Headers and cookies are not logged in access logs by default and don't leak via Referer.",
			CWEID:         "CWE-598",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"framework", "fastapi", "credential-exposure"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-013: TrustedHostMiddleware allowed_hosts=["*"] (wildcard)
// ---------------------------------------------------------------------------

type FastAPITrustedHostWildcard struct{}

func (r *FastAPITrustedHostWildcard) ID() string   { return "BATOU-FW-FASTAPI-013" }
func (r *FastAPITrustedHostWildcard) Name() string { return "FastAPITrustedHostWildcard" }
func (r *FastAPITrustedHostWildcard) DefaultSeverity() rules.Severity {
	return rules.Medium
}
func (r *FastAPITrustedHostWildcard) Description() string {
	return "Detects TrustedHostMiddleware configured with allowed_hosts=['*'], which disables host-header validation."
}
func (r *FastAPITrustedHostWildcard) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *FastAPITrustedHostWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !rules.GMatchLower(reFastapiTrustedHostWild, line, lowered[i]) {
			continue
		}
		// Confirm the wildcard belongs to a TrustedHost configuration — look
		// at this line and ~10 lines above for the middleware reference. This
		// avoids colliding with allowed_hosts in unrelated configs.
		from := i - 10
		if from < 0 {
			from = 0
		}
		block := strings.Join(lines[from:i+1], "\n")
		if !reFastapiTrustedHost.MatchString(block) {
			continue
		}
		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "FastAPI TrustedHostMiddleware accepts any Host header",
			Description:   "TrustedHostMiddleware is configured with allowed_hosts=['*'], which disables Host-header validation entirely. The middleware exists specifically to mitigate Host-header injection (cache poisoning, password-reset poisoning, SSRF) — wildcard makes it a no-op.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "List the actual production hostnames: allowed_hosts=['example.com', '*.example.com']. Use environment variables to vary by deployment.",
			CWEID:         "CWE-20",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"framework", "fastapi", "host-header"},
		})
	}
	return findings
}
