package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- Gin
// ---------------------------------------------------------------------------

// GTSS-FW-GIN-001: Trusted proxies not configured
var reGinEngine = regexp.MustCompile(`gin\.(?:Default|New)\s*\(`)
var reGinSetTrustedProxies = regexp.MustCompile(`\.SetTrustedProxies\s*\(`)

// GTSS-FW-GIN-002: CORS wildcard
var reGinCORSWildcard = regexp.MustCompile(`AllowOrigins\s*:\s*\[\s*\]\s*string\s*\{\s*"\*"\s*\}`)
var reGinCORSAllowAll = regexp.MustCompile(`AllowAllOrigins\s*:\s*true`)

// GTSS-FW-GIN-003: ShouldBind without validation
var reGinShouldBind = regexp.MustCompile(`\.(?:ShouldBind|ShouldBindJSON|ShouldBindQuery|ShouldBindUri|Bind|BindJSON)\s*\(`)
var reGinBindingTag = regexp.MustCompile("`" + `[^` + "`" + `]*binding:"[^"]*required[^"]*"[^` + "`" + `]*` + "`")

// GTSS-FW-GIN-004: HTML template with unescaped data
var reGinHTMLUnescaped = regexp.MustCompile(`template\.HTML\s*\(`)

// GTSS-FW-GIN-005: Debug mode in production
var reGinDebugMode = regexp.MustCompile(`gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)`)

// GTSS-FW-GIN-006: File serve with user-controlled path
var reGinFilePath = regexp.MustCompile(`c\.(?:File|FileAttachment|FileFromFS)\s*\(\s*(?:c\.(?:Param|Query|PostForm)|[a-zA-Z_]\w*\s*\+)`)

// GTSS-FW-GIN-007: SQL injection via c.Query
var reGinSQLQuery = regexp.MustCompile(`(?:db\.(?:Raw|Exec|Query|QueryRow)|\.(?:Raw|Exec)\s*\()\s*\(\s*(?:"[^"]*"\s*\+\s*c\.(?:Query|Param|PostForm)|fmt\.Sprintf\s*\([^)]*c\.(?:Query|Param|PostForm))`)
var reGinSQLConcat = regexp.MustCompile(`(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"]*"\s*\+\s*c\.(?:Query|Param|PostForm|DefaultQuery)\s*\(`)

// GTSS-FW-GIN-008: Cookie without Secure/HttpOnly flags
var reGinSetCookie = regexp.MustCompile(`c\.SetCookie\s*\(`)
var reGinSetCookieInsecure = regexp.MustCompile(`c\.SetCookie\s*\([^)]*,\s*false\s*,\s*false\s*\)`)

// GTSS-FW-GIN-009: BasicAuth with hardcoded credentials
var reGinBasicAuth = regexp.MustCompile(`gin\.Accounts\s*\{[^}]*"[^"]+"\s*:\s*"[^"]+"`)

// GTSS-FW-GIN-010: Middleware ordering
var reGinUseAuth = regexp.MustCompile(`\.Use\s*\(\s*(?:\w*[Aa]uth\w*|[Mm]iddleware|[Gg]uard)`)
var reGinRouteHandler = regexp.MustCompile(`\.\s*(?:GET|POST|PUT|DELETE|PATCH|Handle|Any)\s*\(`)

func init() {
	rules.Register(&GinTrustedProxies{})
	rules.Register(&GinCORSWildcard{})
	rules.Register(&GinBindNoValidation{})
	rules.Register(&GinHTMLUnescaped{})
	rules.Register(&GinDebugMode{})
	rules.Register(&GinFilePathTraversal{})
	rules.Register(&GinSQLInjection{})
	rules.Register(&GinInsecureCookie{})
	rules.Register(&GinHardcodedAuth{})
	rules.Register(&GinMiddlewareOrder{})
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-001: Trusted proxies not configured
// ---------------------------------------------------------------------------

type GinTrustedProxies struct{}

func (r *GinTrustedProxies) ID() string                      { return "GTSS-FW-GIN-001" }
func (r *GinTrustedProxies) Name() string                    { return "GinTrustedProxies" }
func (r *GinTrustedProxies) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GinTrustedProxies) Description() string {
	return "Detects Gin engine creation without SetTrustedProxies configuration, enabling IP spoofing."
}
func (r *GinTrustedProxies) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinTrustedProxies) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reGinEngine.MatchString(ctx.Content) {
		return nil
	}
	if reGinSetTrustedProxies.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reGinEngine.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Gin engine without SetTrustedProxies (IP spoofing risk)",
				Description:   "The Gin engine is created without calling SetTrustedProxies(). Without this, Gin trusts all proxies by default, allowing attackers to spoof IP addresses via X-Forwarded-For headers, bypassing rate limiting and IP-based access controls.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Call router.SetTrustedProxies([]string{\"10.0.0.0/8\"}) with your actual proxy IPs. Use router.SetTrustedProxies(nil) to trust no proxies if not behind a reverse proxy.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "gin", "ip-spoofing"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-002: CORS with wildcard origin
// ---------------------------------------------------------------------------

type GinCORSWildcard struct{}

func (r *GinCORSWildcard) ID() string                      { return "GTSS-FW-GIN-002" }
func (r *GinCORSWildcard) Name() string                    { return "GinCORSWildcard" }
func (r *GinCORSWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r *GinCORSWildcard) Description() string {
	return "Detects Gin CORS middleware configured with wildcard origin."
}
func (r *GinCORSWildcard) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinCORSWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reGinCORSWildcard.FindString(line); m != "" {
			matched = m
		} else if m := reGinCORSAllowAll.FindString(line); m != "" {
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
				Title:         "Gin CORS allows all origins",
				Description:   "The Gin CORS middleware is configured to allow requests from any origin. This permits untrusted websites to make cross-origin requests to your API, potentially stealing data or performing unauthorized actions.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Specify explicit trusted origins in AllowOrigins: []string{\"https://example.com\"}. Set AllowAllOrigins to false.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "gin", "cors"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-003: ShouldBind without validation tags
// ---------------------------------------------------------------------------

type GinBindNoValidation struct{}

func (r *GinBindNoValidation) ID() string                      { return "GTSS-FW-GIN-003" }
func (r *GinBindNoValidation) Name() string                    { return "GinBindNoValidation" }
func (r *GinBindNoValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GinBindNoValidation) Description() string {
	return "Detects Gin request binding without validation struct tags."
}
func (r *GinBindNoValidation) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinBindNoValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reGinShouldBind.MatchString(ctx.Content) {
		return nil
	}
	if reGinBindingTag.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reGinShouldBind.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Gin ShouldBind without validation tags",
				Description:   "Request data is bound to a struct using ShouldBind/BindJSON but the file does not contain binding validation tags. Without validation, malformed or malicious input will be accepted without checks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add binding validation tags to your struct fields: `binding:\"required,min=1,max=100\"`. Use ShouldBind (not Bind) and check the returned error to reject invalid input.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "gin", "validation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-004: HTML template with unescaped data
// ---------------------------------------------------------------------------

type GinHTMLUnescaped struct{}

func (r *GinHTMLUnescaped) ID() string                      { return "GTSS-FW-GIN-004" }
func (r *GinHTMLUnescaped) Name() string                    { return "GinHTMLUnescaped" }
func (r *GinHTMLUnescaped) DefaultSeverity() rules.Severity { return rules.High }
func (r *GinHTMLUnescaped) Description() string {
	return "Detects Gin template.HTML() usage that bypasses Go's html/template auto-escaping."
}
func (r *GinHTMLUnescaped) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinHTMLUnescaped) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reGinHTMLUnescaped.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Gin template.HTML() bypasses auto-escaping (XSS risk)",
				Description:   "template.HTML() converts a string to an unescaped HTML type, bypassing Go's html/template auto-escaping. If the string contains user input, this creates a Cross-Site Scripting vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Avoid template.HTML() with user input. Let Go's html/template auto-escape content. If raw HTML is needed, sanitize with a library like bluemonday before wrapping in template.HTML().",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "gin", "xss", "template"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-005: Debug mode in production
// ---------------------------------------------------------------------------

type GinDebugMode struct{}

func (r *GinDebugMode) ID() string                      { return "GTSS-FW-GIN-005" }
func (r *GinDebugMode) Name() string                    { return "GinDebugMode" }
func (r *GinDebugMode) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GinDebugMode) Description() string {
	return "Detects Gin explicitly set to debug mode via gin.SetMode(gin.DebugMode)."
}
func (r *GinDebugMode) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinDebugMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reGinDebugMode.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Gin debug mode explicitly enabled",
				Description:   "gin.SetMode(gin.DebugMode) is explicitly set. Debug mode outputs detailed routing information and may expose internal implementation details. This should not be used in production.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use gin.SetMode(gin.ReleaseMode) in production. Set mode via environment variable: gin.SetMode(os.Getenv(\"GIN_MODE\")).",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "gin", "debug"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-006: File serve with user-controlled path
// ---------------------------------------------------------------------------

type GinFilePathTraversal struct{}

func (r *GinFilePathTraversal) ID() string                      { return "GTSS-FW-GIN-006" }
func (r *GinFilePathTraversal) Name() string                    { return "GinFilePathTraversal" }
func (r *GinFilePathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *GinFilePathTraversal) Description() string {
	return "Detects Gin c.File/c.FileAttachment serving files with user-controlled path."
}
func (r *GinFilePathTraversal) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinFilePathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reGinFilePath.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Gin file serving with user-controlled path (path traversal)",
				Description:   "c.File(), c.FileAttachment(), or c.FileFromFS() is called with a path derived from user input (c.Param, c.Query, or string concatenation). An attacker can use path traversal (../) to read arbitrary files from the server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate and sanitize file paths. Use filepath.Clean() and verify the resolved path is within the intended directory: if !strings.HasPrefix(filepath.Clean(path), baseDir) { return }.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "gin", "path-traversal"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-007: SQL injection via c.Query in raw SQL
// ---------------------------------------------------------------------------

type GinSQLInjection struct{}

func (r *GinSQLInjection) ID() string                      { return "GTSS-FW-GIN-007" }
func (r *GinSQLInjection) Name() string                    { return "GinSQLInjection" }
func (r *GinSQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *GinSQLInjection) Description() string {
	return "Detects SQL injection via Gin context query parameters concatenated into raw SQL strings."
}
func (r *GinSQLInjection) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		var matched string
		if m := reGinSQLQuery.FindString(line); m != "" {
			matched = m
		} else if m := reGinSQLConcat.FindString(line); m != "" {
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
				Title:         "Gin SQL injection via c.Query/c.Param in raw SQL",
				Description:   "User input from Gin context (c.Query, c.Param, c.PostForm) is concatenated into a raw SQL string. This allows SQL injection attacks that can read, modify, or delete database data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use parameterized queries: db.Raw(\"SELECT * FROM users WHERE id = ?\", c.Query(\"id\")). Never concatenate user input into SQL strings.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "gin", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-008: Cookie without Secure/HttpOnly flags
// ---------------------------------------------------------------------------

type GinInsecureCookie struct{}

func (r *GinInsecureCookie) ID() string                      { return "GTSS-FW-GIN-008" }
func (r *GinInsecureCookie) Name() string                    { return "GinInsecureCookie" }
func (r *GinInsecureCookie) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GinInsecureCookie) Description() string {
	return "Detects Gin c.SetCookie() calls with Secure and HttpOnly flags set to false."
}
func (r *GinInsecureCookie) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinInsecureCookie) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reGinSetCookieInsecure.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Gin cookie set without Secure and HttpOnly flags",
				Description:   "c.SetCookie() is called with both Secure and HttpOnly set to false. The cookie will be sent over unencrypted HTTP and is accessible to JavaScript, making it vulnerable to interception and XSS-based theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set Secure to true (HTTPS only) and HttpOnly to true (no JavaScript access): c.SetCookie(name, value, maxAge, path, domain, true, true).",
				CWEID:         "CWE-614",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "gin", "cookie"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-009: BasicAuth with hardcoded credentials
// ---------------------------------------------------------------------------

type GinHardcodedAuth struct{}

func (r *GinHardcodedAuth) ID() string                      { return "GTSS-FW-GIN-009" }
func (r *GinHardcodedAuth) Name() string                    { return "GinHardcodedAuth" }
func (r *GinHardcodedAuth) DefaultSeverity() rules.Severity { return rules.High }
func (r *GinHardcodedAuth) Description() string {
	return "Detects Gin BasicAuth middleware with hardcoded credentials in source code."
}
func (r *GinHardcodedAuth) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinHardcodedAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reGinBasicAuth.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Gin BasicAuth with hardcoded credentials",
				Description:   "gin.Accounts contains hardcoded username/password pairs in source code. Credentials in source code can be extracted from version control, compiled binaries, or backups.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Load credentials from environment variables or a secrets manager: gin.Accounts{os.Getenv(\"ADMIN_USER\"): os.Getenv(\"ADMIN_PASS\")}. Use bcrypt hashing for password storage.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "gin", "hardcoded-credentials"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-GIN-010: Middleware ordering (auth after handler)
// ---------------------------------------------------------------------------

type GinMiddlewareOrder struct{}

func (r *GinMiddlewareOrder) ID() string                      { return "GTSS-FW-GIN-010" }
func (r *GinMiddlewareOrder) Name() string                    { return "GinMiddlewareOrder" }
func (r *GinMiddlewareOrder) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *GinMiddlewareOrder) Description() string {
	return "Detects Gin auth middleware registered after route handlers, rendering it ineffective."
}
func (r *GinMiddlewareOrder) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *GinMiddlewareOrder) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	firstRouteLine := -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if firstRouteLine == -1 && reGinRouteHandler.MatchString(line) {
			firstRouteLine = i
		}
		if firstRouteLine >= 0 && reGinUseAuth.MatchString(line) && i > firstRouteLine {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Gin auth middleware registered after route handlers",
				Description:   "Authentication middleware is registered via .Use() after route handlers have already been defined. In Gin, middleware only applies to routes registered after it, so earlier routes will not be protected by this middleware.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Register authentication middleware before defining route handlers: router.Use(AuthMiddleware()) must come before router.GET/POST/etc calls.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "gin", "middleware-order"},
			})
		}
	}
	return findings
}
