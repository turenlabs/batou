package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// --- Compiled patterns ---

// BATOU-FW-EXPRESS-001: Missing Helmet middleware
var (
	expressAppCreate = regexp.MustCompile(`\b(?:express\s*\(\s*\)|require\s*\(\s*['"]express['"]\s*\))`)
	helmetUse        = regexp.MustCompile(`(?:app|server|router)\s*\.\s*use\s*\(\s*helmet\s*\(`)
	helmetImport     = regexp.MustCompile(`(?:require\s*\(\s*['"]helmet['"]\s*\)|import\s+.*\bhelmet\b.*from\s+['"]helmet['"])`)
)

// BATOU-FW-EXPRESS-002: Insecure session configuration
var (
	sessionConfig      = regexp.MustCompile(`session\s*\(\s*\{`)
	sessionSecureFalse = regexp.MustCompile(`secure\s*:\s*false`)
	sessionHttpOnly    = regexp.MustCompile(`httpOnly\s*:\s*false`)
	sessionSameSiteNone = regexp.MustCompile(`sameSite\s*:\s*['"]none['"]`)
)

// BATOU-FW-EXPRESS-003: Stack trace leak in error handler
var (
	errorHandlerSig  = regexp.MustCompile(`\(\s*err\s*,\s*req\s*,\s*res\s*,\s*next\s*\)`)
	stackTraceLeak   = regexp.MustCompile(`res\s*\.(?:\s*status\s*\([^)]*\)\s*\.)?\s*(?:send|json|write|end)\s*\(\s*(?:err\s*\.\s*stack|err\s*\.\s*message|err\.toString\s*\(\s*\)|String\s*\(\s*err\s*\))`)
	stackTraceRender = regexp.MustCompile(`res\s*\.(?:\s*status\s*\([^)]*\)\s*\.)?\s*(?:send|json|write)\s*\(\s*\{[^}]*(?:error|message|stack)\s*:\s*err(?:\s*\.\s*(?:stack|message))?\b`)
)

// BATOU-FW-EXPRESS-004: Dynamic require with user input
var (
	dynamicRequire     = regexp.MustCompile(`require\s*\(\s*(?:req\s*\.\s*(?:params|query|body)\s*\.\s*\w+|` +
		`[^)]*\+\s*(?:req\s*\.\s*(?:params|query|body)\b|userInput|input|moduleName|modName|name)|` +
		`[` + "`" + `]['"]?\s*\$\{(?:req\s*\.\s*(?:params|query|body)\s*\.\s*\w+|userInput|input|moduleName)\})`)
	dynamicImport      = regexp.MustCompile(`import\s*\(\s*(?:req\s*\.\s*(?:params|query|body)\s*\.\s*\w+|` +
		`\w+\s*\+\s*(?:req\s*\.\s*(?:params|query|body)|userInput|input)|` +
		`[` + "`" + `]\s*\$\{(?:req\s*\.\s*(?:params|query|body)\s*\.\s*\w+|userInput|input)\})`)
	requireVariable    = regexp.MustCompile(`require\s*\(\s*[a-zA-Z_]\w*\s*\)`)
	importVariable     = regexp.MustCompile(`(?:await\s+)?import\s*\(\s*[a-zA-Z_]\w*\s*\)`)
)

// BATOU-FW-EXPRESS-005: Static serving sensitive directories
var (
	expressStatic = regexp.MustCompile(`express\s*\.\s*static\s*\(\s*['"]([^'"]+)['"]`)
	sensitiveStaticDirs = []string{
		"/", ".", "..", "../", "./", "/etc", "/root", "/home",
		".git", ".env", ".ssh", ".aws", "config", "secrets",
		"private", "node_modules", ".config", "server",
	}
)

// BATOU-FW-EXPRESS-006: Trust proxy misconfiguration
var (
	trustProxyTrue = regexp.MustCompile(`(?:app|server)\s*\.\s*set\s*\(\s*['"]trust\s+proxy['"]\s*,\s*true\s*\)`)
)

// BATOU-FW-EXPRESS-007: Missing session expiration
var (
	sessionCookieConfig = regexp.MustCompile(`session\s*\(\s*\{`)
	sessionMaxAge       = regexp.MustCompile(`maxAge\s*:`)
	sessionExpires      = regexp.MustCompile(`expires\s*:`)
)

// BATOU-FW-EXPRESS-008: Process.env leaked to client response
var (
	processEnvLeak = regexp.MustCompile(`res\s*\.(?:\s*status\s*\([^)]*\)\s*\.)?\s*(?:send|json|write|render)\s*\(\s*process\s*\.\s*env\s*[),;\s]`)
	processEnvSpread = regexp.MustCompile(`(?:\.\.\.process\.env|\bprocess\.env\b)\s*(?:\)|,|\})`)
)

func init() {
	rules.Register(&MissingHelmet{})
	rules.Register(&InsecureSession{})
	rules.Register(&StackTraceLeak{})
	rules.Register(&DynamicRequire{})
	rules.Register(&SensitiveStaticDir{})
	rules.Register(&TrustProxyMisconfig{})
	rules.Register(&MissingSessionExpiry{})
	rules.Register(&ProcessEnvLeak{})
}

// --- helpers ---

func isExpressApp(content string) bool {
	return expressAppCreate.MatchString(content) ||
		strings.Contains(content, "from 'express'") ||
		strings.Contains(content, "from \"express\"") ||
		strings.Contains(content, "require('express')") ||
		strings.Contains(content, "require(\"express\")")
}

// --- BATOU-FW-EXPRESS-001: Missing Helmet ---

type MissingHelmet struct{}

func (r *MissingHelmet) ID() string                    { return "BATOU-FW-EXPRESS-001" }
func (r *MissingHelmet) Name() string                  { return "MissingHelmet" }
func (r *MissingHelmet) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingHelmet) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *MissingHelmet) Description() string {
	return "Detects Express applications without Helmet middleware, which sets security-related HTTP headers (CSP, HSTS, X-Frame-Options, etc.)."
}

func (r *MissingHelmet) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isExpressApp(ctx.Content) {
		return nil
	}

	// If helmet is imported/required, assume it's being used correctly
	if helmetImport.MatchString(ctx.Content) {
		return nil
	}

	// Check for manual header protections that partially substitute helmet
	lower := strings.ToLower(ctx.Content)
	if strings.Contains(lower, "x-powered-by") && strings.Contains(lower, "disable") {
		return nil
	}

	// Find the express() call line for the finding location
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if expressAppCreate.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Express app without Helmet security headers middleware",
				Description:   "This Express application does not use Helmet middleware. Helmet sets important security headers including Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and X-Frame-Options.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Install helmet (npm install helmet) and add app.use(helmet()) before your routes. This sets 15 security headers with sensible defaults.",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Confidence:    "medium",
				Tags:          []string{"express", "helmet", "security-headers", "framework"},
			}}
		}
	}

	return nil
}

// --- BATOU-FW-EXPRESS-002: Insecure Session Configuration ---

type InsecureSession struct{}

func (r *InsecureSession) ID() string                    { return "BATOU-FW-EXPRESS-002" }
func (r *InsecureSession) Name() string                  { return "InsecureSession" }
func (r *InsecureSession) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureSession) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *InsecureSession) Description() string {
	return "Detects Express session middleware configured with insecure cookie settings (secure: false, httpOnly: false, sameSite: none)."
}

func (r *InsecureSession) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inSessionBlock := false
	sessionStartLine := 0
	braceDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// Detect session configuration start
		if sessionConfig.MatchString(line) {
			inSessionBlock = true
			sessionStartLine = i
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inSessionBlock {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if sessionSecureFalse.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "Session cookie with secure: false",
					Description:   "The session cookie is configured with secure: false, allowing it to be transmitted over unencrypted HTTP connections. This exposes the session ID to network interception.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Set secure: true on session cookies to ensure they are only sent over HTTPS. Use conditional logic for development: secure: process.env.NODE_ENV === 'production'.",
					CWEID:         "CWE-614",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Confidence:    "high",
					Tags:          []string{"express", "session", "cookie", "framework"},
				})
			}

			if sessionHttpOnly.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.High,
					Title:         "Session cookie with httpOnly: false",
					Description:   "The session cookie is configured with httpOnly: false, making it accessible to JavaScript via document.cookie. This enables session hijacking through XSS attacks.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Set httpOnly: true on session cookies to prevent client-side JavaScript from accessing them.",
					CWEID:         "CWE-1004",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Confidence:    "high",
					Tags:          []string{"express", "session", "cookie", "xss", "framework"},
				})
			}

			if sessionSameSiteNone.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "Session cookie with sameSite: 'none'",
					Description:   "The session cookie is configured with sameSite: 'none', allowing it to be sent in cross-origin requests. This weakens CSRF protections and may enable cross-site attacks.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Set sameSite: 'strict' or 'lax' unless cross-site cookie access is required for a legitimate purpose (e.g., OAuth flows).",
					CWEID:         "CWE-352",
					OWASPCategory: "A01:2021-Broken Access Control",
					Confidence:    "high",
					Tags:          []string{"express", "session", "cookie", "csrf", "framework"},
				})
			}

			if braceDepth <= 0 {
				inSessionBlock = false
				_ = sessionStartLine
			}
		}
	}

	return findings
}

// --- BATOU-FW-EXPRESS-003: Stack Trace Leak ---

type StackTraceLeak struct{}

func (r *StackTraceLeak) ID() string                    { return "BATOU-FW-EXPRESS-003" }
func (r *StackTraceLeak) Name() string                  { return "StackTraceLeak" }
func (r *StackTraceLeak) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *StackTraceLeak) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *StackTraceLeak) Description() string {
	return "Detects Express error handlers that leak stack traces or detailed error messages to clients."
}

func (r *StackTraceLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inErrorHandler := false
	handlerBraceDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// Detect Express error handler middleware signature: (err, req, res, next)
		if errorHandlerSig.MatchString(line) {
			inErrorHandler = true
			handlerBraceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inErrorHandler {
			handlerBraceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			// Check for direct stack/message leaks
			if stackTraceLeak.MatchString(line) || stackTraceRender.MatchString(line) {
				// Check if there's a production guard
				hasEnvCheck := false
				start := i - 10
				if start < 0 {
					start = 0
				}
				for _, contextLine := range lines[start:i] {
					if strings.Contains(contextLine, "NODE_ENV") && strings.Contains(contextLine, "production") {
						hasEnvCheck = true
						break
					}
				}

				if !hasEnvCheck {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						Title:         "Error handler leaks stack trace to client",
						Description:   "An Express error handler sends error details (stack trace or message) directly to the client response. This reveals internal implementation details, file paths, and dependency versions that help attackers.",
						LineNumber:    i + 1,
						MatchedText:   truncate(strings.TrimSpace(line), 120),
						Suggestion:    "Return a generic error message to clients. Log the full error server-side. Guard detailed errors with: if (process.env.NODE_ENV !== 'production') { ... }.",
						CWEID:         "CWE-209",
						OWASPCategory: "A05:2021-Security Misconfiguration",
						Confidence:    "high",
						Tags:          []string{"express", "error-handling", "information-disclosure", "framework"},
					})
				}
			}

			if handlerBraceDepth <= 0 {
				inErrorHandler = false
			}
		}
	}

	return findings
}

// --- BATOU-FW-EXPRESS-004: Dynamic Require with User Input ---

type DynamicRequire struct{}

func (r *DynamicRequire) ID() string                    { return "BATOU-FW-EXPRESS-004" }
func (r *DynamicRequire) Name() string                  { return "DynamicRequire" }
func (r *DynamicRequire) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *DynamicRequire) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *DynamicRequire) Description() string {
	return "Detects require() or import() calls with user-controlled input, which allows arbitrary module loading and potential remote code execution."
}

func (r *DynamicRequire) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasUserInput := strings.Contains(ctx.Content, "req.params") ||
		strings.Contains(ctx.Content, "req.query") ||
		strings.Contains(ctx.Content, "req.body") ||
		strings.Contains(ctx.Content, "request.params") ||
		strings.Contains(ctx.Content, "request.query") ||
		strings.Contains(ctx.Content, "request.body") ||
		strings.Contains(ctx.Content, "userInput") ||
		strings.Contains(ctx.Content, "user_input")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// High confidence: require/import with explicit req.params/query/body
		if dynamicRequire.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				Title:         "Dynamic require() with user-controlled input",
				Description:   "A require() call uses user-supplied input to determine which module to load. An attacker can use this to load arbitrary modules, read arbitrary files, or achieve remote code execution.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never pass user input to require(). Use a lookup map of allowed module names: const allowed = { 'a': require('./a'), 'b': require('./b') }; const mod = allowed[userInput].",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Confidence:    "high",
				Tags:          []string{"express", "require", "rce", "code-injection", "framework"},
			})
			continue
		}

		if dynamicImport.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				Title:         "Dynamic import() with user-controlled input",
				Description:   "A dynamic import() call uses user-supplied input to determine which module to load. This can allow arbitrary code execution.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never pass user input to import(). Use a lookup map to restrict which modules can be loaded.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Confidence:    "high",
				Tags:          []string{"express", "import", "rce", "code-injection", "framework"},
			})
			continue
		}

		// Medium confidence: require(variable) in a file that also has user input
		if hasUserInput && requireVariable.MatchString(line) {
			// Exclude common safe patterns (string literal requires)
			if strings.Contains(line, "require('") || strings.Contains(line, "require(\"") {
				continue
			}
			// Exclude top-level requires that appear before any function/route definition
			isTopLevel := true
			for j := 0; j < i; j++ {
				if strings.Contains(lines[j], "function") || strings.Contains(lines[j], "=>") ||
					strings.Contains(lines[j], "app.get") || strings.Contains(lines[j], "app.post") ||
					strings.Contains(lines[j], "app.put") || strings.Contains(lines[j], "app.delete") ||
					strings.Contains(lines[j], "router.") {
					isTopLevel = false
					break
				}
			}
			if isTopLevel {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				Title:         "Dynamic require() with variable in file handling user input",
				Description:   "A require() call uses a variable in a file that processes user input. If the variable is derived from user input, this enables arbitrary module loading and code execution.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Ensure the variable passed to require() is not derived from user input. Use a static allowlist mapping instead of dynamic require().",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Confidence:    "medium",
				Tags:          []string{"express", "require", "code-injection", "framework"},
			})
		}

		// Dynamic import(variable) in file with user input
		if hasUserInput && importVariable.MatchString(line) {
			if strings.Contains(line, "import('") || strings.Contains(line, "import(\"") {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				Title:         "Dynamic import() with variable in file handling user input",
				Description:   "A dynamic import() uses a variable in a file that processes user input. If the variable is derived from user input, this allows arbitrary module loading.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Ensure the variable passed to import() is not derived from user input. Use a static allowlist mapping instead.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Confidence:    "medium",
				Tags:          []string{"express", "import", "code-injection", "framework"},
			})
		}
	}

	return findings
}

// --- BATOU-FW-EXPRESS-005: Sensitive Static Directory ---

type SensitiveStaticDir struct{}

func (r *SensitiveStaticDir) ID() string                    { return "BATOU-FW-EXPRESS-005" }
func (r *SensitiveStaticDir) Name() string                  { return "SensitiveStaticDir" }
func (r *SensitiveStaticDir) DefaultSeverity() rules.Severity { return rules.High }
func (r *SensitiveStaticDir) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *SensitiveStaticDir) Description() string {
	return "Detects express.static() serving directories that may expose sensitive files (.git, .env, node_modules, config, etc.)."
}

func (r *SensitiveStaticDir) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		matches := expressStatic.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		staticPath := matches[1]
		staticPathLower := strings.ToLower(staticPath)

		for _, sensitive := range sensitiveStaticDirs {
			if staticPathLower == sensitive || strings.HasSuffix(staticPathLower, "/"+sensitive) ||
				strings.HasPrefix(staticPathLower, sensitive+"/") {

				severity := r.DefaultSeverity()
				confidence := "high"

				// Root directory serving is critical
				if staticPath == "/" || staticPath == "." || staticPath == ".." || staticPath == "./" {
					severity = rules.Critical
				}

				// .git and .env are critical
				if strings.Contains(staticPathLower, ".git") || strings.Contains(staticPathLower, ".env") ||
					strings.Contains(staticPathLower, ".ssh") || strings.Contains(staticPathLower, ".aws") {
					severity = rules.Critical
				}

				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      severity,
					Title:         "express.static() serves sensitive directory: " + staticPath,
					Description:   "The express.static() middleware is configured to serve a directory that likely contains sensitive files. This could expose source code, secrets, configuration, or dependency code to the public.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Serve only a dedicated public/ or static/ directory. Never serve the project root, .git, .env, node_modules, or config directories. Use express.static('public') with a restricted directory.",
					CWEID:         "CWE-552",
					OWASPCategory: "A01:2021-Broken Access Control",
					Confidence:    confidence,
					Tags:          []string{"express", "static-files", "information-disclosure", "framework"},
				})
				break
			}
		}
	}

	return findings
}

// --- BATOU-FW-EXPRESS-006: Trust Proxy Misconfiguration ---

type TrustProxyMisconfig struct{}

func (r *TrustProxyMisconfig) ID() string                    { return "BATOU-FW-EXPRESS-006" }
func (r *TrustProxyMisconfig) Name() string                  { return "TrustProxyMisconfig" }
func (r *TrustProxyMisconfig) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *TrustProxyMisconfig) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *TrustProxyMisconfig) Description() string {
	return "Detects Express app.set('trust proxy', true) which trusts all proxies, allowing IP spoofing via X-Forwarded-For headers."
}

func (r *TrustProxyMisconfig) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if trustProxyTrue.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Express trust proxy set to true (trusts all proxies)",
				Description:   "Setting trust proxy to true makes Express trust X-Forwarded-For headers from any source. An attacker can spoof their IP address by injecting this header, bypassing IP-based rate limiting, access controls, and audit logging.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set trust proxy to the number of trusted hops (e.g., 1) or a specific subnet: app.set('trust proxy', '10.0.0.0/8'). Only trust the actual reverse proxy addresses.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Confidence:    "high",
				Tags:          []string{"express", "trust-proxy", "ip-spoofing", "framework"},
			})
		}
	}

	return findings
}

// --- BATOU-FW-EXPRESS-007: Missing Session Expiration ---

type MissingSessionExpiry struct{}

func (r *MissingSessionExpiry) ID() string                    { return "BATOU-FW-EXPRESS-007" }
func (r *MissingSessionExpiry) Name() string                  { return "MissingSessionExpiry" }
func (r *MissingSessionExpiry) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingSessionExpiry) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *MissingSessionExpiry) Description() string {
	return "Detects Express session configuration without maxAge or expires, creating sessions that never expire."
}

func (r *MissingSessionExpiry) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if !sessionCookieConfig.MatchString(line) {
			continue
		}

		// Look forward in the session block for maxAge or expires
		hasExpiry := false
		end := i + 30
		if end > len(lines) {
			end = len(lines)
		}
		braceDepth := strings.Count(line, "{") - strings.Count(line, "}")

		for j := i + 1; j < end; j++ {
			braceDepth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")

			if sessionMaxAge.MatchString(lines[j]) || sessionExpires.MatchString(lines[j]) {
				hasExpiry = true
				break
			}

			if braceDepth <= 0 {
				break
			}
		}

		if !hasExpiry {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Session configured without expiration (no maxAge or expires)",
				Description:   "The session configuration lacks a maxAge or expires setting on the cookie. Sessions without expiration remain valid indefinitely, increasing the window for session hijacking if a session token is compromised.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Add a cookie maxAge to the session configuration: cookie: { maxAge: 24 * 60 * 60 * 1000 } (24 hours). Shorter durations are better for sensitive applications.",
				CWEID:         "CWE-613",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Confidence:    "medium",
				Tags:          []string{"express", "session", "expiration", "framework"},
			})
		}
	}

	return findings
}

// --- BATOU-FW-EXPRESS-008: Process.env Leak to Client ---

type ProcessEnvLeak struct{}

func (r *ProcessEnvLeak) ID() string                    { return "BATOU-FW-EXPRESS-008" }
func (r *ProcessEnvLeak) Name() string                  { return "ProcessEnvLeak" }
func (r *ProcessEnvLeak) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ProcessEnvLeak) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *ProcessEnvLeak) Description() string {
	return "Detects process.env being sent directly in client responses, which can expose secrets, API keys, and database credentials."
}

func (r *ProcessEnvLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if processEnvLeak.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				Title:         "process.env sent in client response",
				Description:   "process.env is included in a response sent to the client. The process environment typically contains secrets (API keys, database passwords, JWT secrets) that must never be exposed to end users.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never send process.env to clients. Only expose specific, non-sensitive environment variables: res.json({ apiUrl: process.env.PUBLIC_API_URL }).",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "high",
				Tags:          []string{"express", "env-leak", "information-disclosure", "framework"},
			})
			continue
		}

		// Check for spread of process.env into response objects
		if strings.Contains(line, "res.") && (strings.Contains(line, "send") || strings.Contains(line, "json")) {
			if processEnvSpread.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.High,
					Title:         "process.env spread into client response",
					Description:   "process.env is spread or included in a response. This can expose all environment variables including secrets to the client.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Never send process.env to clients. Construct response objects with only the specific values needed.",
					CWEID:         "CWE-200",
					OWASPCategory: "A01:2021-Broken Access Control",
					Confidence:    "medium",
					Tags:          []string{"express", "env-leak", "information-disclosure", "framework"},
				})
			}
		}
	}

	return findings
}
