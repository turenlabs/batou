package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- FastAPI
// ---------------------------------------------------------------------------

// GTSS-FW-FASTAPI-001: Endpoint without auth dependency
var (
	reFastapiRoute       = regexp.MustCompile(`@app\.(?:get|post|put|delete|patch|options|head)\s*\(`)
	reFastapiDepends     = regexp.MustCompile(`Depends\s*\(`)
	reFastapiAuthKeyword = regexp.MustCompile(`(?i)(?:auth|security|token|current_user|get_current|verify|jwt|oauth|api_key|permission|require_auth)`)
)

// GTSS-FW-FASTAPI-002: CORS wildcard
var reFastapiCORSWildcard = regexp.MustCompile(`allow_origins\s*=\s*\[\s*["']\*["']\s*\]`)

// GTSS-FW-FASTAPI-003: Debug mode
var reFastapiDebug = regexp.MustCompile(`uvicorn\.run\s*\([^)]*debug\s*=\s*True`)

// GTSS-FW-FASTAPI-004: SQL injection via f-string
var reFastapiSQLFString = regexp.MustCompile(`(?:execute|text|raw)\s*\(\s*f["'](?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|MERGE)\b`)

// GTSS-FW-FASTAPI-005: Response model exposing internal fields
var reFastapiResponseInternal = regexp.MustCompile(`(?:response_model\s*=\s*\w+)`)
var reFastapiInternalFields = regexp.MustCompile(`(?:password|hashed_password|secret|token|salt|ssn|credit_card|internal_id|api_key)\s*(?::|=)`)

// GTSS-FW-FASTAPI-006: File upload without validation
var reFastapiFileUpload = regexp.MustCompile(`(?:file|upload)\s*:\s*UploadFile`)
var reFastapiFileValidation = regexp.MustCompile(`(?:content_type|filename|size|\.endswith|allowed_extensions|validate_file|file_extension|ALLOWED_TYPES)`)

// GTSS-FW-FASTAPI-007: OAuth2 without HTTPS
var reFastapiOAuth2HTTP = regexp.MustCompile(`OAuth2PasswordBearer\s*\(\s*tokenUrl\s*=\s*["']http://`)

// GTSS-FW-FASTAPI-008: Depends() without error handling
var reFastapiDependsNaked = regexp.MustCompile(`Depends\s*\(\s*\w+\s*\)`)
var reFastapiDependsErrorHandling = regexp.MustCompile(`(?:try\s*:|except\s+|HTTPException|raise\s+)`)

// GTSS-FW-FASTAPI-009: Jinja2 without autoescaping
var reFastapiJinja2NoEscape = regexp.MustCompile(`Jinja2Templates\s*\(`)
var reFastapiAutoescapeFalse = regexp.MustCompile(`autoescape\s*=\s*False`)

// GTSS-FW-FASTAPI-010: Background task with sensitive data
var reFastapiBackgroundTask = regexp.MustCompile(`(?:background_tasks\.add_task|BackgroundTasks)\s*\(`)
var reFastapiSensitiveDataInTask = regexp.MustCompile(`(?:password|secret|token|api_key|credit_card|ssn|private_key)`)

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
}

// ---------------------------------------------------------------------------
// GTSS-FW-FASTAPI-001: FastAPI endpoint without authentication dependency
// ---------------------------------------------------------------------------

type FastAPINoAuth struct{}

func (r *FastAPINoAuth) ID() string                      { return "GTSS-FW-FASTAPI-001" }
func (r *FastAPINoAuth) Name() string                    { return "FastAPINoAuth" }
func (r *FastAPINoAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FastAPINoAuth) Description() string {
	return "Detects FastAPI route handlers without authentication dependencies."
}
func (r *FastAPINoAuth) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPINoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		if !reFastapiRoute.MatchString(line) {
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
		if strings.Contains(line, "dependencies=") && reFastapiAuthKeyword.MatchString(line) {
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
// GTSS-FW-FASTAPI-002: CORS middleware with allow_origins=["*"]
// ---------------------------------------------------------------------------

type FastAPICORSWildcard struct{}

func (r *FastAPICORSWildcard) ID() string                      { return "GTSS-FW-FASTAPI-002" }
func (r *FastAPICORSWildcard) Name() string                    { return "FastAPICORSWildcard" }
func (r *FastAPICORSWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPICORSWildcard) Description() string {
	return "Detects FastAPI CORSMiddleware configured with allow_origins=['*']."
}
func (r *FastAPICORSWildcard) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPICORSWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if m := reFastapiCORSWildcard.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "FastAPI CORS allows all origins",
				Description:   "CORSMiddleware is configured with allow_origins=['*'], allowing any website to make cross-origin requests to this API. This can expose sensitive data and APIs to untrusted domains.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Specify explicit trusted origins: allow_origins=['https://example.com', 'https://app.example.com']. Avoid wildcards in production.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fastapi", "cors"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-FASTAPI-003: Debug mode enabled
// ---------------------------------------------------------------------------

type FastAPIDebugMode struct{}

func (r *FastAPIDebugMode) ID() string                      { return "GTSS-FW-FASTAPI-003" }
func (r *FastAPIDebugMode) Name() string                    { return "FastAPIDebugMode" }
func (r *FastAPIDebugMode) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPIDebugMode) Description() string {
	return "Detects FastAPI/uvicorn running with debug=True."
}
func (r *FastAPIDebugMode) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPIDebugMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if m := reFastapiDebug.FindString(line); m != "" {
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
// GTSS-FW-FASTAPI-004: SQL injection via f-string
// ---------------------------------------------------------------------------

type FastAPISQLInjection struct{}

func (r *FastAPISQLInjection) ID() string                      { return "GTSS-FW-FASTAPI-004" }
func (r *FastAPISQLInjection) Name() string                    { return "FastAPISQLInjection" }
func (r *FastAPISQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPISQLInjection) Description() string {
	return "Detects SQL injection via f-strings in raw query execution within FastAPI handlers."
}
func (r *FastAPISQLInjection) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPISQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if m := reFastapiSQLFString.FindString(line); m != "" {
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
// GTSS-FW-FASTAPI-005: Response model exposing internal fields
// ---------------------------------------------------------------------------

type FastAPIResponseExposure struct{}

func (r *FastAPIResponseExposure) ID() string                      { return "GTSS-FW-FASTAPI-005" }
func (r *FastAPIResponseExposure) Name() string                    { return "FastAPIResponseExposure" }
func (r *FastAPIResponseExposure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FastAPIResponseExposure) Description() string {
	return "Detects FastAPI response models that may expose internal or sensitive fields."
}
func (r *FastAPIResponseExposure) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *FastAPIResponseExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only check files that define Pydantic models with response_model usage
	if !reFastapiResponseInternal.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reFastapiInternalFields.MatchString(line) && strings.Contains(ctx.Content, "BaseModel") {
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
// GTSS-FW-FASTAPI-006: File upload without validation
// ---------------------------------------------------------------------------

type FastAPIFileUpload struct{}

func (r *FastAPIFileUpload) ID() string                      { return "GTSS-FW-FASTAPI-006" }
func (r *FastAPIFileUpload) Name() string                    { return "FastAPIFileUpload" }
func (r *FastAPIFileUpload) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPIFileUpload) Description() string {
	return "Detects FastAPI file upload endpoints without file type or size validation."
}
func (r *FastAPIFileUpload) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPIFileUpload) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !reFastapiFileUpload.MatchString(line) {
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
// GTSS-FW-FASTAPI-007: OAuth2 without HTTPS
// ---------------------------------------------------------------------------

type FastAPIOAuth2HTTP struct{}

func (r *FastAPIOAuth2HTTP) ID() string                      { return "GTSS-FW-FASTAPI-007" }
func (r *FastAPIOAuth2HTTP) Name() string                    { return "FastAPIOAuth2HTTP" }
func (r *FastAPIOAuth2HTTP) DefaultSeverity() rules.Severity { return rules.High }
func (r *FastAPIOAuth2HTTP) Description() string {
	return "Detects FastAPI OAuth2PasswordBearer configured with an HTTP (non-HTTPS) token URL."
}
func (r *FastAPIOAuth2HTTP) Languages() []rules.Language { return []rules.Language{rules.LangPython} }

func (r *FastAPIOAuth2HTTP) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if m := reFastapiOAuth2HTTP.FindString(line); m != "" {
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
// GTSS-FW-FASTAPI-008: Depends() without error handling
// ---------------------------------------------------------------------------

type FastAPIDependsNoError struct{}

func (r *FastAPIDependsNoError) ID() string                      { return "GTSS-FW-FASTAPI-008" }
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
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !reFastapiDependsNaked.MatchString(line) {
			continue
		}

		// Check surrounding context for error handling
		lookAhead := 15
		if i+lookAhead > len(lines) {
			lookAhead = len(lines) - i
		}
		block := strings.Join(lines[i:i+lookAhead], "\n")

		if reFastapiDependsErrorHandling.MatchString(block) {
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
			Description:   "A FastAPI dependency is injected without proper error handling. If the dependency function fails (database connection error, external service timeout), unhandled exceptions may expose internal error details to the client.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Add try/except blocks in dependency functions and raise HTTPException with appropriate status codes. Use exception handlers to prevent internal error details from reaching clients.",
			CWEID:         "CWE-755",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"framework", "fastapi", "error-handling"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-FASTAPI-009: Jinja2 template without autoescaping
// ---------------------------------------------------------------------------

type FastAPIJinja2NoEscape struct{}

func (r *FastAPIJinja2NoEscape) ID() string                      { return "GTSS-FW-FASTAPI-009" }
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
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !reFastapiJinja2NoEscape.MatchString(line) {
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
// GTSS-FW-FASTAPI-010: Background task with sensitive data in memory
// ---------------------------------------------------------------------------

type FastAPIBackgroundSensitive struct{}

func (r *FastAPIBackgroundSensitive) ID() string { return "GTSS-FW-FASTAPI-010" }
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
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if !reFastapiBackgroundTask.MatchString(line) {
			continue
		}

		// Check if sensitive data is passed to the background task
		if reFastapiSensitiveDataInTask.MatchString(line) {
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
