package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Actix-web (Rust) framework security rule patterns
// ---------------------------------------------------------------------------

var (
	// BATOU-FW-ACTIX-001: CORS permissive configuration
	reActixCorsPermissiveOrigin  = regexp.MustCompile(`Cors::permissive\s*\(`)
	reActixCorsAllowAnyOrigin    = regexp.MustCompile(`\.allow_any_origin\s*\(`)
	reActixCorsAllowAnyMethod    = regexp.MustCompile(`\.allow_any_method\s*\(`)

	// BATOU-FW-ACTIX-002: Serving static files with user-controlled path
	reActixNamedFile     = regexp.MustCompile(`NamedFile::open\s*\(\s*(?:format!\s*\(|&format!\s*\(|path\.|req\.|info\.)`)
	reActixFilesService  = regexp.MustCompile(`Files::new\s*\(\s*"[^"]*"\s*,\s*(?:&?\w+|format!\s*\()`)

	// BATOU-FW-ACTIX-003: SQL injection via format! in query
	reActixSQLFormat     = regexp.MustCompile(`(?:query|execute|query_as|query_scalar)\s*[!(]\s*(?:&\s*)?format!\s*\(`)
	reActixSQLFormatStr  = regexp.MustCompile(`(?:query|execute)\s*\(\s*&format!\s*\(`)

	// BATOU-FW-ACTIX-004: Session without secure cookie settings
	reActixCookieSession   = regexp.MustCompile(`CookieSession::(?:signed|private)\s*\(`)
	reActixSessionSecure   = regexp.MustCompile(`\.secure\s*\(\s*true\s*\)`)
	reActixSessionHttpOnly = regexp.MustCompile(`\.http_only\s*\(\s*true\s*\)`)

	// BATOU-FW-ACTIX-005: Missing authentication extractor
	reActixHandler        = regexp.MustCompile(`(?:\.route|\.resource|web::(?:get|post|put|delete|patch))\s*\(`)
	reActixAuthExtractor  = regexp.MustCompile(`(?:Identity|Claims|Auth|Token|Session|User)\s*:`)

	// BATOU-FW-ACTIX-006: Error response exposing internal details
	reActixErrorDisplay   = regexp.MustCompile(`HttpResponse::(?:InternalServerError|BadRequest)\s*\(\s*\)\s*\.(?:body|json)\s*\(\s*(?:format!\s*\(|err\.|e\.|error\.)`)
	reActixErrorDbg       = regexp.MustCompile(`HttpResponse::.*\.body\s*\(\s*format!\s*\(\s*"[^"]*\{:?\?\}`)
)

func init() {
	rules.Register(&ActixCorsPermissive{})
	rules.Register(&ActixStaticPath{})
	rules.Register(&ActixSQLFormat{})
	rules.Register(&ActixInsecureSession{})
	rules.Register(&ActixMissingAuth{})
	rules.Register(&ActixErrorExposure{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-ACTIX-001: CORS permissive configuration
// ---------------------------------------------------------------------------

type ActixCorsPermissive struct{}

func (r *ActixCorsPermissive) ID() string                      { return "BATOU-FW-ACTIX-001" }
func (r *ActixCorsPermissive) Name() string                    { return "ActixCorsPermissive" }
func (r *ActixCorsPermissive) DefaultSeverity() rules.Severity { return rules.High }
func (r *ActixCorsPermissive) Description() string {
	return "Detects actix-web CORS configuration with permissive origins or methods, allowing cross-origin attacks."
}
func (r *ActixCorsPermissive) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r *ActixCorsPermissive) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		var title string
		if m := reActixCorsPermissiveOrigin.FindString(line); m != "" {
			matched = m
			title = "Actix-web Cors::permissive() allows all origins and methods"
		} else if m := reActixCorsAllowAnyOrigin.FindString(line); m != "" {
			matched = m
			title = "Actix-web CORS allows any origin"
		} else if m := reActixCorsAllowAnyMethod.FindString(line); m != "" {
			matched = m
			title = "Actix-web CORS allows any HTTP method"
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "The actix-web CORS configuration is overly permissive, allowing any origin or any HTTP method. This enables cross-origin attacks where malicious websites can make authenticated requests to your API.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Specify allowed origins explicitly with .allowed_origin(\"https://trusted.com\"). Restrict methods with .allowed_methods(vec![\"GET\", \"POST\"]). Avoid Cors::permissive() in production.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "actix", "rust", "cors"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ACTIX-002: Static file serving with user-controlled path
// ---------------------------------------------------------------------------

type ActixStaticPath struct{}

func (r *ActixStaticPath) ID() string                      { return "BATOU-FW-ACTIX-002" }
func (r *ActixStaticPath) Name() string                    { return "ActixStaticPath" }
func (r *ActixStaticPath) DefaultSeverity() rules.Severity { return rules.High }
func (r *ActixStaticPath) Description() string {
	return "Detects actix-web NamedFile::open with user-controlled paths, which can lead to path traversal and arbitrary file read."
}
func (r *ActixStaticPath) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r *ActixStaticPath) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reActixNamedFile.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Actix-web NamedFile::open with user-controlled path (path traversal)",
				Description:   "NamedFile::open is called with a path that appears to be constructed from user input (request parameters, format! macro). An attacker can use path traversal sequences (../) to read arbitrary files on the server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate and sanitize the file path. Use canonicalize() and verify the resolved path is within the intended directory. Reject paths containing '..' or absolute paths.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "actix", "rust", "path-traversal"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ACTIX-003: SQL injection via format! in query
// ---------------------------------------------------------------------------

type ActixSQLFormat struct{}

func (r *ActixSQLFormat) ID() string                      { return "BATOU-FW-ACTIX-003" }
func (r *ActixSQLFormat) Name() string                    { return "ActixSQLFormat" }
func (r *ActixSQLFormat) DefaultSeverity() rules.Severity { return rules.High }
func (r *ActixSQLFormat) Description() string {
	return "Detects SQL queries built with Rust's format! macro instead of parameterized queries, enabling SQL injection."
}
func (r *ActixSQLFormat) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r *ActixSQLFormat) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reActixSQLFormat.FindString(line); m != "" {
			matched = m
		} else if m := reActixSQLFormatStr.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SQL query built with format! macro (SQL injection risk)",
				Description:   "A SQL query is constructed using Rust's format! macro, which embeds values directly into the SQL string. This bypasses query parameterization and enables SQL injection attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use parameterized queries with bind parameters: sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(user_id). Never use format! to build SQL queries.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "actix", "rust", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ACTIX-004: Session without secure cookie settings
// ---------------------------------------------------------------------------

type ActixInsecureSession struct{}

func (r *ActixInsecureSession) ID() string                      { return "BATOU-FW-ACTIX-004" }
func (r *ActixInsecureSession) Name() string                    { return "ActixInsecureSession" }
func (r *ActixInsecureSession) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ActixInsecureSession) Description() string {
	return "Detects actix-web session cookies without secure or httponly flags, exposing sessions to interception or XSS."
}
func (r *ActixInsecureSession) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r *ActixInsecureSession) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if !reActixCookieSession.MatchString(line) {
			continue
		}

		// Look forward for .secure(true) and .http_only(true)
		end := i + 15
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		hasSecure := reActixSessionSecure.MatchString(block)
		hasHttpOnly := reActixSessionHttpOnly.MatchString(block)

		if !hasSecure || !hasHttpOnly {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			desc := "Actix-web CookieSession is configured without "
			if !hasSecure && !hasHttpOnly {
				desc += "the secure and http_only flags"
			} else if !hasSecure {
				desc += "the secure flag (cookie sent over HTTP)"
			} else {
				desc += "the http_only flag (cookie accessible to JavaScript)"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Actix-web session cookie missing secure settings",
				Description:   desc + ". This exposes the session to interception or XSS-based theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add .secure(true) and .http_only(true) to the CookieSession builder. Also set .same_site(SameSite::Strict) for CSRF protection.",
				CWEID:         "CWE-614",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "actix", "rust", "session", "cookie"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ACTIX-005: Missing authentication extractor
// ---------------------------------------------------------------------------

type ActixMissingAuth struct{}

func (r *ActixMissingAuth) ID() string                      { return "BATOU-FW-ACTIX-005" }
func (r *ActixMissingAuth) Name() string                    { return "ActixMissingAuth" }
func (r *ActixMissingAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ActixMissingAuth) Description() string {
	return "Detects actix-web route handlers that do not use authentication extractors, potentially serving unauthenticated requests."
}
func (r *ActixMissingAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r *ActixMissingAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only flag if the project uses auth extractors somewhere
	if !reActixAuthExtractor.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if !reActixHandler.MatchString(line) {
			continue
		}
		// Look at the handler function signature for auth extractors
		end := i + 5
		if end > len(lines) {
			end = len(lines)
		}
		context := strings.Join(lines[i:end], "\n")
		if !reActixAuthExtractor.MatchString(context) {
			// Check if handler name suggests it should be public
			lower := strings.ToLower(line)
			if strings.Contains(lower, "health") || strings.Contains(lower, "public") ||
				strings.Contains(lower, "login") || strings.Contains(lower, "register") ||
				strings.Contains(lower, "signup") {
				continue
			}
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Actix-web route handler without authentication extractor",
				Description:   "A route handler does not use an authentication extractor (Identity, Auth, Token, etc.) while other handlers in the same file do. This endpoint may be unintentionally accessible without authentication.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add an authentication extractor to the handler parameters, or use middleware-level authentication with wrap(). If the endpoint is intentionally public, document it.",
				CWEID:         "CWE-306",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "actix", "rust", "authentication"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ACTIX-006: Error response exposing internal details
// ---------------------------------------------------------------------------

type ActixErrorExposure struct{}

func (r *ActixErrorExposure) ID() string                      { return "BATOU-FW-ACTIX-006" }
func (r *ActixErrorExposure) Name() string                    { return "ActixErrorExposure" }
func (r *ActixErrorExposure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ActixErrorExposure) Description() string {
	return "Detects actix-web error responses that expose internal error details, stack traces, or debug information to clients."
}
func (r *ActixErrorExposure) Languages() []rules.Language {
	return []rules.Language{rules.LangRust}
}

func (r *ActixErrorExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reActixErrorDisplay.FindString(line); m != "" {
			matched = m
		} else if m := reActixErrorDbg.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Actix-web error response exposes internal details",
				Description:   "An error response includes internal error messages, debug formatting ({:?}), or raw error objects. This reveals implementation details, database structures, or file paths that help attackers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Return generic error messages to clients: HttpResponse::InternalServerError().json(\"Internal server error\"). Log the detailed error server-side with log::error!() or tracing::error!().",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "actix", "rust", "information-disclosure"},
			})
		}
	}
	return findings
}
