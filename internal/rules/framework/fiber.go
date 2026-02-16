package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- Fiber
// ---------------------------------------------------------------------------

// BATOU-FW-FIBER-001: CORS with AllowOrigins *
var reFiberCORSWildcard = regexp.MustCompile(`AllowOrigins\s*:\s*"\*"`)
var reFiberCORSDefault = regexp.MustCompile(`cors\.New\s*\(\s*\)`)

// BATOU-FW-FIBER-002: Static file serve with user path
var reFiberStaticUser = regexp.MustCompile(`c\.(?:SendFile|Download)\s*\(\s*(?:c\.(?:Query|Params)|[a-zA-Z_]\w*\s*\+)`)

// BATOU-FW-FIBER-003: BodyParser without validation
var reFiberBodyParser = regexp.MustCompile(`c\.BodyParser\s*\(`)
var reFiberValidation = regexp.MustCompile(`(?:Validate|validator|validate\.Struct|govalidator)`)

// BATOU-FW-FIBER-004: Cookie without Secure flag
var reFiberCookieInsecure = regexp.MustCompile(`(?:fiber\.Cookie\s*\{|&fiber\.Cookie\s*\{)`)
var reFiberCookieSecure = regexp.MustCompile(`Secure\s*:\s*true`)

// BATOU-FW-FIBER-005: JWT with weak secret
var reFiberJWTSecret = regexp.MustCompile(`SigningKey\s*:\s*\[\s*\]\s*byte\s*\(\s*"[^"]{1,15}"`)
var reFiberJWTHardcoded = regexp.MustCompile(`jwtware\.New\s*\(\s*jwtware\.Config\s*\{[^}]*SigningKey\s*:\s*\[\s*\]\s*byte\s*\(\s*"[^"]*"`)

// BATOU-FW-FIBER-006: Rate limiter not configured
var reFiberLimiter = regexp.MustCompile(`(?:limiter\.New|limiter\.Config|app\.Use\s*\(\s*limiter)`)
var reFiberApp = regexp.MustCompile(`fiber\.New\s*\(`)

// BATOU-FW-FIBER-007: Template injection
var reFiberTemplateInject = regexp.MustCompile(`c\.Render\s*\([^,]*,\s*(?:fiber\.Map\s*\{[^}]*c\.(?:Query|Params|FormValue)|c\.(?:Query|Params|FormValue))`)

// BATOU-FW-FIBER-008: Helmet not used
var reFiberHelmet = regexp.MustCompile(`(?:helmet\.New|app\.Use\s*\(\s*helmet)`)

func init() {
	rules.Register(&FiberCORSWildcard{})
	rules.Register(&FiberStaticTraversal{})
	rules.Register(&FiberBodyNoValidation{})
	rules.Register(&FiberCookieInsecure{})
	rules.Register(&FiberJWTWeak{})
	rules.Register(&FiberNoRateLimit{})
	rules.Register(&FiberTemplateInjection{})
	rules.Register(&FiberNoHelmet{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-FIBER-001: CORS with AllowOrigins *
// ---------------------------------------------------------------------------

type FiberCORSWildcard struct{}

func (r *FiberCORSWildcard) ID() string                      { return "BATOU-FW-FIBER-001" }
func (r *FiberCORSWildcard) Name() string                    { return "FiberCORSWildcard" }
func (r *FiberCORSWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r *FiberCORSWildcard) Description() string {
	return "Detects Fiber CORS middleware configured with wildcard AllowOrigins."
}
func (r *FiberCORSWildcard) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *FiberCORSWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reFiberCORSWildcard.FindString(line); m != "" {
			matched = m
		} else if m := reFiberCORSDefault.FindString(line); m != "" {
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
				Title:         "Fiber CORS allows all origins",
				Description:   "The Fiber CORS middleware is configured with AllowOrigins: \"*\" or using default settings, allowing any website to make cross-origin requests to your API.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Specify trusted origins: cors.New(cors.Config{AllowOrigins: \"https://example.com, https://app.example.com\"}). Never use wildcards in production.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fiber", "cors"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FIBER-002: Static file serve with user path
// ---------------------------------------------------------------------------

type FiberStaticTraversal struct{}

func (r *FiberStaticTraversal) ID() string                      { return "BATOU-FW-FIBER-002" }
func (r *FiberStaticTraversal) Name() string                    { return "FiberStaticTraversal" }
func (r *FiberStaticTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *FiberStaticTraversal) Description() string {
	return "Detects Fiber c.SendFile/c.Download serving files with user-controlled path."
}
func (r *FiberStaticTraversal) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *FiberStaticTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reFiberStaticUser.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Fiber file serving with user-controlled path (path traversal)",
				Description:   "c.SendFile() or c.Download() is called with a path derived from user input (c.Query, c.Params, or string concatenation). Attackers can use path traversal (../) to read arbitrary server files.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate and sanitize paths with filepath.Clean() and verify the result is within the intended directory: if !strings.HasPrefix(clean, baseDir) { return c.SendStatus(403) }.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fiber", "path-traversal"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FIBER-003: BodyParser without validation
// ---------------------------------------------------------------------------

type FiberBodyNoValidation struct{}

func (r *FiberBodyNoValidation) ID() string                      { return "BATOU-FW-FIBER-003" }
func (r *FiberBodyNoValidation) Name() string                    { return "FiberBodyNoValidation" }
func (r *FiberBodyNoValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FiberBodyNoValidation) Description() string {
	return "Detects Fiber BodyParser usage without validation of the parsed data."
}
func (r *FiberBodyNoValidation) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *FiberBodyNoValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reFiberBodyParser.MatchString(ctx.Content) {
		return nil
	}
	if reFiberValidation.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reFiberBodyParser.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Fiber BodyParser without input validation",
				Description:   "Request data is parsed via c.BodyParser() but no validation is performed on the result. Without validation, malformed or oversized input can lead to security issues.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use a validation library such as go-playground/validator. Add validate tags to struct fields and call validate.Struct(data) after c.BodyParser(&data).",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "fiber", "validation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FIBER-004: Cookie without Secure flag
// ---------------------------------------------------------------------------

type FiberCookieInsecure struct{}

func (r *FiberCookieInsecure) ID() string                      { return "BATOU-FW-FIBER-004" }
func (r *FiberCookieInsecure) Name() string                    { return "FiberCookieInsecure" }
func (r *FiberCookieInsecure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FiberCookieInsecure) Description() string {
	return "Detects Fiber cookie creation without the Secure flag set to true."
}
func (r *FiberCookieInsecure) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *FiberCookieInsecure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if !reFiberCookieInsecure.MatchString(line) {
			continue
		}

		// Look ahead to see if Secure: true is set
		lookAhead := 10
		if i+lookAhead > len(lines) {
			lookAhead = len(lines) - i
		}
		block := strings.Join(lines[i:i+lookAhead], "\n")
		if reFiberCookieSecure.MatchString(block) {
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
			Title:         "Fiber cookie without Secure flag",
			Description:   "A fiber.Cookie is created without Secure: true. The cookie will be sent over unencrypted HTTP connections, exposing it to network interception attacks.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Add Secure: true to the cookie: &fiber.Cookie{Name: name, Value: value, Secure: true, HTTPOnly: true, SameSite: \"Strict\"}.",
			CWEID:         "CWE-614",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"framework", "fiber", "cookie"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FIBER-005: JWT middleware with weak secret
// ---------------------------------------------------------------------------

type FiberJWTWeak struct{}

func (r *FiberJWTWeak) ID() string                      { return "BATOU-FW-FIBER-005" }
func (r *FiberJWTWeak) Name() string                    { return "FiberJWTWeak" }
func (r *FiberJWTWeak) DefaultSeverity() rules.Severity { return rules.High }
func (r *FiberJWTWeak) Description() string {
	return "Detects Fiber JWT middleware with a short or hardcoded signing key."
}
func (r *FiberJWTWeak) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *FiberJWTWeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reFiberJWTSecret.FindString(line); m != "" {
			matched = m
		} else if m := reFiberJWTHardcoded.FindString(line); m != "" {
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
				Title:         "Fiber JWT middleware with weak or hardcoded signing key",
				Description:   "The Fiber JWT middleware uses a hardcoded or short (under 16 characters) signing key. Short keys can be brute-forced, and hardcoded keys in source code can be extracted from version control or compiled binaries to forge valid tokens.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Load JWT keys from environment variables: SigningKey: []byte(os.Getenv(\"JWT_SECRET\")). Use a key of at least 32 bytes (256 bits) generated with a cryptographically secure random generator.",
				CWEID:         "CWE-326",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fiber", "jwt", "weak-key"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FIBER-006: Rate limiter not configured
// ---------------------------------------------------------------------------

type FiberNoRateLimit struct{}

func (r *FiberNoRateLimit) ID() string                      { return "BATOU-FW-FIBER-006" }
func (r *FiberNoRateLimit) Name() string                    { return "FiberNoRateLimit" }
func (r *FiberNoRateLimit) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FiberNoRateLimit) Description() string {
	return "Detects Fiber applications without rate limiting middleware."
}
func (r *FiberNoRateLimit) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *FiberNoRateLimit) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reFiberApp.MatchString(ctx.Content) {
		return nil
	}
	if reFiberLimiter.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reFiberApp.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Fiber application without rate limiting",
				Description:   "The Fiber application does not configure rate limiting middleware. Without rate limiting, the API is vulnerable to brute force attacks, credential stuffing, and denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add rate limiting: app.Use(limiter.New(limiter.Config{Max: 100, Expiration: 1 * time.Minute})). Apply stricter limits to authentication endpoints.",
				CWEID:         "CWE-770",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "fiber", "rate-limiting"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FIBER-007: Template injection via user input
// ---------------------------------------------------------------------------

type FiberTemplateInjection struct{}

func (r *FiberTemplateInjection) ID() string                      { return "BATOU-FW-FIBER-007" }
func (r *FiberTemplateInjection) Name() string                    { return "FiberTemplateInjection" }
func (r *FiberTemplateInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *FiberTemplateInjection) Description() string {
	return "Detects Fiber template rendering with unsanitized user input passed directly to templates."
}
func (r *FiberTemplateInjection) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *FiberTemplateInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reFiberTemplateInject.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Fiber template injection via user input",
				Description:   "User input from c.Query(), c.Params(), or c.FormValue() is passed directly to c.Render() as template data. If the template engine does not auto-escape, this can lead to Server-Side Template Injection (SSTI) or XSS.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Sanitize user input before passing to templates. Ensure your template engine has auto-escaping enabled. Validate and restrict input to expected formats.",
				CWEID:         "CWE-1336",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "fiber", "template-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FIBER-008: Helmet middleware not used
// ---------------------------------------------------------------------------

type FiberNoHelmet struct{}

func (r *FiberNoHelmet) ID() string                      { return "BATOU-FW-FIBER-008" }
func (r *FiberNoHelmet) Name() string                    { return "FiberNoHelmet" }
func (r *FiberNoHelmet) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FiberNoHelmet) Description() string {
	return "Detects Fiber applications without helmet middleware for security headers."
}
func (r *FiberNoHelmet) Languages() []rules.Language { return []rules.Language{rules.LangGo} }

func (r *FiberNoHelmet) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reFiberApp.MatchString(ctx.Content) {
		return nil
	}
	if reFiberHelmet.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reFiberApp.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Fiber application without helmet middleware",
				Description:   "The Fiber application does not use helmet middleware to set security-related HTTP headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, etc.).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add helmet middleware: app.Use(helmet.New()). This sets important security headers with sensible defaults.",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "fiber", "helmet", "security-headers"},
			})
			break
		}
	}
	return findings
}
