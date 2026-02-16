package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- Echo
// ---------------------------------------------------------------------------

// BATOU-FW-ECHO-001: CORS wildcard
var reEchoCORSWildcard = regexp.MustCompile(`AllowOrigins\s*:\s*\[\s*\]\s*string\s*\{\s*"\*"\s*\}`)
var reEchoCORSAllowAll = regexp.MustCompile(`middleware\.CORSWithConfig\s*\(\s*middleware\.CORSConfig\s*\{`)
var reEchoCORSDefault = regexp.MustCompile(`middleware\.CORS\s*\(\s*\)`)

// BATOU-FW-ECHO-002: SQL injection via c.QueryParam
var reEchoSQLConcat = regexp.MustCompile(`(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"]*"\s*\+\s*c\.(?:QueryParam|Param|FormValue)\s*\(`)
var reEchoSQLFmt = regexp.MustCompile(`fmt\.Sprintf\s*\(\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"]*"\s*,\s*c\.(?:QueryParam|Param|FormValue)\s*\(`)

// BATOU-FW-ECHO-003: Static file with user path
var reEchoStaticUser = regexp.MustCompile(`(?:e|echo)\.(?:Static|File)\s*\(\s*[^,]+,\s*(?:c\.(?:QueryParam|Param|FormValue)|[a-zA-Z_]\w*\s*\+)`)

// BATOU-FW-ECHO-004: Template without escaping
var reEchoHTMLUnescaped = regexp.MustCompile(`template\.HTML\s*\(`)
var reEchoRenderRaw = regexp.MustCompile(`c\.HTML\s*\([^)]*template\.HTML`)

// BATOU-FW-ECHO-005: JWT with hardcoded key
var reEchoJWTHardcoded = regexp.MustCompile(`middleware\.JWT\s*\(\s*\[\s*\]\s*byte\s*\(\s*"[^"]{4,}"`)
var reEchoJWTConfig = regexp.MustCompile(`SigningKey\s*:\s*\[\s*\]\s*byte\s*\(\s*"[^"]{4,}"`)

// BATOU-FW-ECHO-006: CSRF not applied
var reEchoCSRF = regexp.MustCompile(`middleware\.CSRF\s*\(`)
var reEchoCSRFConfig = regexp.MustCompile(`middleware\.CSRFWithConfig`)

// BATOU-FW-ECHO-007: Binding without validation
var reEchoBind = regexp.MustCompile(`c\.Bind\s*\(`)
var reEchoValidate = regexp.MustCompile(`(?:Validate|validator|validate\.Struct)`)

// BATOU-FW-ECHO-008: Debug mode
var reEchoDebug = regexp.MustCompile(`e\.Debug\s*=\s*true`)

func init() {
	rules.Register(&EchoCORSWildcard{})
	rules.Register(&EchoSQLInjection{})
	rules.Register(&EchoStaticTraversal{})
	rules.Register(&EchoTemplateUnescaped{})
	rules.Register(&EchoJWTHardcoded{})
	rules.Register(&EchoNoCSRF{})
	rules.Register(&EchoBindNoValidation{})
	rules.Register(&EchoDebugMode{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-ECHO-001: CORS with AllowOrigins wildcard
// ---------------------------------------------------------------------------

type EchoCORSWildcard struct{}

func (r *EchoCORSWildcard) ID() string                      { return "BATOU-FW-ECHO-001" }
func (r *EchoCORSWildcard) Name() string                    { return "EchoCORSWildcard" }
func (r *EchoCORSWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r *EchoCORSWildcard) Description() string {
	return "Detects Echo CORS middleware configured with wildcard or default (all origins) settings."
}
func (r *EchoCORSWildcard) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *EchoCORSWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reEchoCORSWildcard.FindString(line); m != "" {
			matched = m
		} else if m := reEchoCORSDefault.FindString(line); m != "" {
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
				Title:         "Echo CORS allows all origins",
				Description:   "The Echo CORS middleware is configured with a wildcard origin or using default settings that allow all origins. This permits any website to make cross-origin requests to your API.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Configure specific origins in AllowOrigins: middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: []string{\"https://example.com\"}}).",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "echo", "cors"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ECHO-002: SQL injection via c.QueryParam
// ---------------------------------------------------------------------------

type EchoSQLInjection struct{}

func (r *EchoSQLInjection) ID() string                      { return "BATOU-FW-ECHO-002" }
func (r *EchoSQLInjection) Name() string                    { return "EchoSQLInjection" }
func (r *EchoSQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *EchoSQLInjection) Description() string {
	return "Detects SQL injection via Echo context query parameters in raw SQL statements."
}
func (r *EchoSQLInjection) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *EchoSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reEchoSQLConcat.FindString(line); m != "" {
			matched = m
		} else if m := reEchoSQLFmt.FindString(line); m != "" {
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
				Title:         "Echo SQL injection via c.QueryParam/c.Param in raw SQL",
				Description:   "User input from Echo context (c.QueryParam, c.Param, c.FormValue) is concatenated or formatted into a raw SQL string. This allows SQL injection attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = $1\", c.QueryParam(\"id\")). Never concatenate user input into SQL.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "echo", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ECHO-003: Static file serving with user path
// ---------------------------------------------------------------------------

type EchoStaticTraversal struct{}

func (r *EchoStaticTraversal) ID() string                      { return "BATOU-FW-ECHO-003" }
func (r *EchoStaticTraversal) Name() string                    { return "EchoStaticTraversal" }
func (r *EchoStaticTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *EchoStaticTraversal) Description() string {
	return "Detects Echo static file serving with user-controlled path leading to path traversal."
}
func (r *EchoStaticTraversal) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *EchoStaticTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reEchoStaticUser.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Echo static file serving with user-controlled path",
				Description:   "Echo Static() or File() is called with a path derived from user input. An attacker can use path traversal sequences (../) to access files outside the intended directory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate and sanitize file paths using filepath.Clean() and verify the resolved path stays within the base directory. Use Echo's built-in static middleware with a fixed root directory.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "echo", "path-traversal"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ECHO-004: Template rendering without escaping
// ---------------------------------------------------------------------------

type EchoTemplateUnescaped struct{}

func (r *EchoTemplateUnescaped) ID() string                      { return "BATOU-FW-ECHO-004" }
func (r *EchoTemplateUnescaped) Name() string                    { return "EchoTemplateUnescaped" }
func (r *EchoTemplateUnescaped) DefaultSeverity() rules.Severity { return rules.High }
func (r *EchoTemplateUnescaped) Description() string {
	return "Detects Echo template rendering using template.HTML() which bypasses Go auto-escaping."
}
func (r *EchoTemplateUnescaped) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *EchoTemplateUnescaped) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only flag in files that use Echo
	if !strings.Contains(ctx.Content, "echo.") && !strings.Contains(ctx.Content, "labstack") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reEchoRenderRaw.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Echo template rendering with unescaped HTML",
				Description:   "template.HTML() is used to pass unescaped content to Echo's HTML renderer. If this content includes user input, it creates a Cross-Site Scripting (XSS) vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Let Go's html/template auto-escape content. If raw HTML is needed, sanitize with bluemonday before wrapping in template.HTML().",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "echo", "xss", "template"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ECHO-005: JWT middleware with hardcoded key
// ---------------------------------------------------------------------------

type EchoJWTHardcoded struct{}

func (r *EchoJWTHardcoded) ID() string                      { return "BATOU-FW-ECHO-005" }
func (r *EchoJWTHardcoded) Name() string                    { return "EchoJWTHardcoded" }
func (r *EchoJWTHardcoded) DefaultSeverity() rules.Severity { return rules.High }
func (r *EchoJWTHardcoded) Description() string {
	return "Detects Echo JWT middleware configured with a hardcoded signing key."
}
func (r *EchoJWTHardcoded) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *EchoJWTHardcoded) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reEchoJWTHardcoded.FindString(line); m != "" {
			matched = m
		} else if m := reEchoJWTConfig.FindString(line); m != "" {
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
				Title:         "Echo JWT middleware with hardcoded signing key",
				Description:   "The Echo JWT middleware is configured with a hardcoded signing key string. Anyone with access to the source code can forge valid JWT tokens, bypassing authentication entirely.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Load JWT signing keys from environment variables: []byte(os.Getenv(\"JWT_SECRET\")). Use a strong, randomly generated key of at least 256 bits.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "echo", "jwt", "hardcoded-secret"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ECHO-006: CSRF middleware not applied
// ---------------------------------------------------------------------------

type EchoNoCSRF struct{}

func (r *EchoNoCSRF) ID() string                      { return "BATOU-FW-ECHO-006" }
func (r *EchoNoCSRF) Name() string                    { return "EchoNoCSRF" }
func (r *EchoNoCSRF) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *EchoNoCSRF) Description() string {
	return "Detects Echo web applications without CSRF middleware, making them vulnerable to cross-site request forgery."
}
func (r *EchoNoCSRF) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *EchoNoCSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check files that create Echo instances and have form-handling routes
	if !strings.Contains(ctx.Content, "echo.New") {
		return nil
	}
	if !strings.Contains(ctx.Content, "POST") && !strings.Contains(ctx.Content, "PUT") && !strings.Contains(ctx.Content, "DELETE") {
		return nil
	}
	if reEchoCSRF.MatchString(ctx.Content) || reEchoCSRFConfig.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if strings.Contains(line, "echo.New") {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Echo application without CSRF middleware",
				Description:   "This Echo application handles state-changing requests (POST/PUT/DELETE) but does not use CSRF middleware. Without CSRF protection, attackers can forge requests on behalf of authenticated users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add CSRF middleware: e.Use(middleware.CSRF()) or e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{...})). For API-only applications using token auth, CSRF may not be needed.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "echo", "csrf"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ECHO-007: Binding without validation
// ---------------------------------------------------------------------------

type EchoBindNoValidation struct{}

func (r *EchoBindNoValidation) ID() string                      { return "BATOU-FW-ECHO-007" }
func (r *EchoBindNoValidation) Name() string                    { return "EchoBindNoValidation" }
func (r *EchoBindNoValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *EchoBindNoValidation) Description() string {
	return "Detects Echo request binding without validation, accepting any input without checks."
}
func (r *EchoBindNoValidation) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *EchoBindNoValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reEchoBind.MatchString(ctx.Content) {
		return nil
	}
	if reEchoValidate.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reEchoBind.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Echo c.Bind() without validation",
				Description:   "Request data is bound via c.Bind() but the file does not contain validation logic. Without validation, malformed or malicious input will be accepted and processed.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add a custom validator to Echo: e.Validator = &CustomValidator{validator: validator.New()}. Use validate tags on struct fields and call c.Validate(data) after c.Bind(data).",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "echo", "validation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-ECHO-008: Debug mode enabled
// ---------------------------------------------------------------------------

type EchoDebugMode struct{}

func (r *EchoDebugMode) ID() string                      { return "BATOU-FW-ECHO-008" }
func (r *EchoDebugMode) Name() string                    { return "EchoDebugMode" }
func (r *EchoDebugMode) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *EchoDebugMode) Description() string {
	return "Detects Echo debug mode enabled via e.Debug = true."
}
func (r *EchoDebugMode) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *EchoDebugMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reEchoDebug.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Echo debug mode enabled",
				Description:   "e.Debug = true enables debug mode in Echo, which outputs detailed error messages with stack traces to clients. This reveals internal implementation details in production.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set e.Debug = false in production. Use environment variables to control: e.Debug = os.Getenv(\"ENV\") != \"production\".",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "echo", "debug"},
			})
		}
	}
	return findings
}
