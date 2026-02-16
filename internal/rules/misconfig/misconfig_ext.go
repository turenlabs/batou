package misconfig

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended misconfig rules
// ---------------------------------------------------------------------------

// BATOU-MISC-004: Debug mode enabled in production
var (
	reExtDebugProd   = regexp.MustCompile(`(?i)\bdebug\s*[:=]\s*(?:true|1|['"]true['"]|['"]1['"]|['"]yes['"])`)
	reExtDevMode     = regexp.MustCompile(`(?i)(?:development|dev[_-]mode|devMode)\s*[:=]\s*(?:true|1|['"]true['"])`)
	reExtProdContext = regexp.MustCompile(`(?i)(?:production|prod\b|\.prod\.|deploy|release)`)
	reExtEnvGuard    = regexp.MustCompile(`(?i)(?:process\.env|os\.environ|System\.getenv|ENV\[|getenv|os\.Getenv|NODE_ENV|RAILS_ENV)`)
)

// BATOU-MISC-005: Default/example configuration
var (
	reDefaultConfig    = regexp.MustCompile(`(?i)(?:example\.com|changeme|change_me|CHANGE_ME|default_?password|default_?secret|todo.?change|replace.?this|your.?secret.?here|your.?password.?here|enter.?your|set.?your|UPDATE_?ME|FIXME.?secret)`)
	reSecretContext    = regexp.MustCompile(`(?i)(?:secret|password|key|token|credential|api_key|auth|database_url|connection_string)`)
)

// BATOU-MISC-006: Verbose error messages
var (
	reVerboseError       = regexp.MustCompile(`(?i)(?:res\.(?:send|json|status\s*\([^)]*\)\.(?:send|json))|response\.(?:write|body|send)|HttpResponse|JsonResponse|jsonify|render|echo)\s*\([^)]*(?:\.stack|\.message|\.toString\(\)|traceback|stackTrace|getStackTrace|\.getMessage\(\)|str\s*\(\s*(?:e|err|error|exception)\s*\)|format_exc)`)
)

// BATOU-MISC-007: Admin interface exposed
var (
	reAdminRoute         = regexp.MustCompile(`(?i)(?:['"/]admin['"/]|admin_?panel|admin_?dashboard|admin_?interface|/admin\b)`)
	reAdminAuthCheck     = regexp.MustCompile(`(?i)(?:isAdmin|is_admin|admin_?only|requireAdmin|require_admin|@admin_required|role\s*===?\s*['"]admin['"]|hasRole\s*\(\s*['"]admin['"])`)
	reIPRestriction      = regexp.MustCompile(`(?i)(?:ip_?whitelist|ip_?allowlist|allowed_?ips|ip_?restrict|RemoteAddr|X-Forwarded-For|ipFilter|ip_filter|\.allow\s*\()`)
)

// BATOU-MISC-008: HTTPS redirect not enforced
var (
	reHTTPServer         = regexp.MustCompile(`(?i)(?:http\.createServer|http\.ListenAndServe|app\.listen|app\.run|server\.listen)\s*\(`)
	reHTTPSRedirect      = regexp.MustCompile(`(?i)(?:https?.*redirect|forceSSL|force_ssl|requireHTTPS|require_https|SECURE_SSL_REDIRECT|HSTS|https_redirect|ssl_required|\.redirect.*https)`)
	reHTTPSSetup         = regexp.MustCompile(`(?i)(?:https\.createServer|tls\.Listen|ListenAndServeTLS|ssl_context|SSLContext|\.useSSL|https_only)`)
)

// BATOU-MISC-009: Directory listing enabled
var (
	reDirectoryListing   = regexp.MustCompile(`(?i)(?:autoindex\s+on|Options\s+\+?Indexes|directory\s+listing|serveIndex|express\.static.*index\s*:\s*false|DirectoryIndex\s+disabled|enable_listing\s*[:=]\s*true|list_directory\s*[:=]\s*True)`)
)

// BATOU-MISC-010: Insecure default permissions
var (
	reWorldReadWrite     = regexp.MustCompile(`(?i)(?:0o?777|0o?666|0o?776|0o?767|permissions?\s*[:=]\s*0o?777|chmod\s+(?:777|666)|os\.chmod\s*\([^,]+,\s*0o?777|os\.FileMode\s*\(\s*0o?777|stat\.S_IRWXO)`)
	reOpenPerms          = regexp.MustCompile(`(?i)(?:umask\s*\(\s*0o?0+\s*\)|world.?(?:readable|writable)|others?.?(?:read|write))`)
)

// BATOU-MISC-011: Stack traces in error responses
var (
	reStackTraceEnabled  = regexp.MustCompile(`(?i)(?:includeStackTrace|include_stack_trace|showStackTrace|show_stack_trace|stackTrace\s*[:=]\s*true|stack_trace\s*[:=]\s*True|displayErrors\s*[:=]\s*true|display_errors\s*[:=]\s*true)`)
	reFullStackResponse  = regexp.MustCompile(`(?i)(?:err|error|exception|e)\.(?:stack|stackTrace|getStackTrace|backtrace|format_exc|traceback)\b`)
)

// ---------------------------------------------------------------------------
// BATOU-MISC-004: Debug Mode Enabled in Production
// ---------------------------------------------------------------------------

type DebugModeProd struct{}

func (r *DebugModeProd) ID() string                     { return "BATOU-MISC-004" }
func (r *DebugModeProd) Name() string                   { return "DebugModeProd" }
func (r *DebugModeProd) DefaultSeverity() rules.Severity { return rules.High }
func (r *DebugModeProd) Description() string {
	return "Detects debug mode flags enabled without environment guards, which may be active in production and expose sensitive internal state."
}
func (r *DebugModeProd) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *DebugModeProd) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		matched := ""
		if loc := reExtDebugProd.FindString(line); loc != "" {
			matched = loc
		} else if loc := reExtDevMode.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			// Skip if guarded by environment check
			if reExtEnvGuard.MatchString(line) {
				continue
			}
			// Skip if/ternary checks
			if strings.Contains(line, "if") || strings.Contains(line, "?") || strings.Contains(line, "===") || strings.Contains(line, "!==") {
				continue
			}
			confidence := "medium"
			if reExtProdContext.MatchString(ctx.FilePath) {
				confidence = "high"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Debug mode enabled without environment guard",
				Description:   "A debug flag is set to true without an environment variable check. This configuration will be active in all environments including production, exposing detailed error messages, stack traces, and internal state.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Guard debug flags with environment checks: debug = process.env.NODE_ENV !== 'production'. Or use environment-specific config files (settings_prod.py vs settings_dev.py).",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"misconfig", "debug", "production", "cwe-489"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-MISC-005: Default/Example Configuration in Production
// ---------------------------------------------------------------------------

type DefaultConfig struct{}

func (r *DefaultConfig) ID() string                     { return "BATOU-MISC-005" }
func (r *DefaultConfig) Name() string                   { return "DefaultConfig" }
func (r *DefaultConfig) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DefaultConfig) Description() string {
	return "Detects default, example, or placeholder values in security-sensitive configuration (passwords, secrets, API keys)."
}
func (r *DefaultConfig) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *DefaultConfig) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if reDefaultConfig.MatchString(line) && reSecretContext.MatchString(line) {
			matched := trimmed
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Default/placeholder value in security-sensitive configuration",
				Description:   "A security-sensitive configuration value (password, secret, API key) contains a default, example, or placeholder value like 'changeme', 'example.com', or 'your-secret-here'. These indicate unconfigured security settings.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Replace default/placeholder values with actual secrets loaded from environment variables or a secrets manager. Never deploy with placeholder credentials.",
				CWEID:         "CWE-1188",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"misconfig", "default-config", "credentials", "cwe-1188"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-MISC-006: Verbose Error Messages Exposed to Users
// ---------------------------------------------------------------------------

type VerboseErrorExposed struct{}

func (r *VerboseErrorExposed) ID() string                     { return "BATOU-MISC-006" }
func (r *VerboseErrorExposed) Name() string                   { return "VerboseErrorExposed" }
func (r *VerboseErrorExposed) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *VerboseErrorExposed) Description() string {
	return "Detects verbose error messages, exception details, or stack traces being sent in HTTP responses to users."
}
func (r *VerboseErrorExposed) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangPHP, rules.LangGo, rules.LangRuby}
}

func (r *VerboseErrorExposed) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if loc := reVerboseError.FindString(line); loc != "" {
			matched := loc
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Verbose error message sent in HTTP response",
				Description:   "Detailed error information (stack trace, error message, exception details) is included in the HTTP response. This reveals internal file paths, library versions, database structure, and other details useful for targeted attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Log detailed errors server-side. Return only a generic error message and correlation ID to clients: {error: 'An unexpected error occurred', requestId: correlationId}.",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"misconfig", "error-disclosure", "verbose-errors", "cwe-209"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-MISC-007: Admin Interface Exposed Without IP Restriction
// ---------------------------------------------------------------------------

type AdminExposedNoIPRestriction struct{}

func (r *AdminExposedNoIPRestriction) ID() string                     { return "BATOU-MISC-007" }
func (r *AdminExposedNoIPRestriction) Name() string                   { return "AdminExposedNoIPRestriction" }
func (r *AdminExposedNoIPRestriction) DefaultSeverity() rules.Severity { return rules.High }
func (r *AdminExposedNoIPRestriction) Description() string {
	return "Detects admin interface routes without IP restriction or additional access controls beyond basic authentication."
}
func (r *AdminExposedNoIPRestriction) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *AdminExposedNoIPRestriction) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	if !reAdminRoute.MatchString(ctx.Content) {
		return nil
	}
	if reIPRestriction.MatchString(ctx.Content) {
		return nil
	}
	if reAdminAuthCheck.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if loc := reAdminRoute.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Admin interface exposed without IP restriction or strong auth check",
				Description:   "An admin interface route is accessible without IP restriction or role-based access control. Admin panels are high-value targets and should be protected by multiple layers: IP allowlisting, MFA, and role-based access.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   loc,
				Suggestion:    "Restrict admin access by IP allowlist (internal/VPN only). Add role-based access control requiring admin role. Enable MFA for admin accounts. Consider running admin interfaces on a separate port or subdomain.",
				CWEID:         "CWE-284",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"misconfig", "admin", "access-control", "cwe-284"},
			})
			return findings
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-MISC-008: HTTPS Redirect Not Enforced
// ---------------------------------------------------------------------------

type HTTPSNotEnforced struct{}

func (r *HTTPSNotEnforced) ID() string                     { return "BATOU-MISC-008" }
func (r *HTTPSNotEnforced) Name() string                   { return "HTTPSNotEnforced" }
func (r *HTTPSNotEnforced) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *HTTPSNotEnforced) Description() string {
	return "Detects HTTP server setups without HTTPS redirect enforcement, allowing plaintext traffic that can be intercepted."
}
func (r *HTTPSNotEnforced) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangJava, rules.LangRuby, rules.LangPHP}
}

func (r *HTTPSNotEnforced) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if HTTPS redirect or HTTPS setup is present
	if reHTTPSRedirect.MatchString(ctx.Content) || reHTTPSSetup.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if loc := reHTTPServer.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "HTTP server without HTTPS redirect enforcement",
				Description:   "An HTTP server is configured without HTTPS redirect or TLS setup. Plaintext HTTP traffic can be intercepted by man-in-the-middle attackers, exposing credentials, session tokens, and sensitive data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   loc,
				Suggestion:    "Enforce HTTPS by redirecting all HTTP traffic to HTTPS. Enable HSTS (Strict-Transport-Security) header. Use TLS certificates from Let's Encrypt or your CA. Set SECURE_SSL_REDIRECT=True (Django) or use helmet.hsts() (Express).",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"misconfig", "https", "tls", "cwe-319"},
			})
			return findings
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-MISC-009: Directory Listing Enabled
// ---------------------------------------------------------------------------

type DirectoryListingEnabled struct{}

func (r *DirectoryListingEnabled) ID() string                     { return "BATOU-MISC-009" }
func (r *DirectoryListingEnabled) Name() string                   { return "DirectoryListingEnabled" }
func (r *DirectoryListingEnabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DirectoryListingEnabled) Description() string {
	return "Detects web server configurations that enable directory listing, exposing file structures and potentially sensitive files."
}
func (r *DirectoryListingEnabled) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *DirectoryListingEnabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if loc := reDirectoryListing.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Directory listing enabled in web server configuration",
				Description:   "Directory listing is enabled, allowing users to browse the file structure of served directories. This can expose backup files, configuration files, source code, and other sensitive files that should not be publicly accessible.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   loc,
				Suggestion:    "Disable directory listing. For nginx: set autoindex off. For Apache: remove Options Indexes. For Express: remove serveIndex middleware. Serve only specific files, not directory contents.",
				CWEID:         "CWE-548",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"misconfig", "directory-listing", "information-disclosure", "cwe-548"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-MISC-010: Insecure Default Permissions
// ---------------------------------------------------------------------------

type InsecurePermissions struct{}

func (r *InsecurePermissions) ID() string                     { return "BATOU-MISC-010" }
func (r *InsecurePermissions) Name() string                   { return "InsecurePermissions" }
func (r *InsecurePermissions) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecurePermissions) Description() string {
	return "Detects files or directories created with world-readable or world-writable permissions (777, 666), allowing any user on the system to access or modify them."
}
func (r *InsecurePermissions) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *InsecurePermissions) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		matched := ""
		if loc := reWorldReadWrite.FindString(line); loc != "" {
			matched = loc
		} else if loc := reOpenPerms.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Insecure file permissions (world-readable/writable)",
				Description:   "File or directory is created with overly permissive permissions (777 or 666). This allows any user on the system to read, modify, or execute the file, which can lead to data theft, tampering, or privilege escalation.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use restrictive permissions. Files: 0o644 (owner read/write, others read). Sensitive files: 0o600 (owner only). Directories: 0o755 (owner full, others read/execute). Never use 777 or 666 in production.",
				CWEID:         "CWE-276",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"misconfig", "permissions", "file-security", "cwe-276"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-MISC-011: Stack Traces Enabled in Error Responses
// ---------------------------------------------------------------------------

type StackTracesEnabled struct{}

func (r *StackTracesEnabled) ID() string                     { return "BATOU-MISC-011" }
func (r *StackTracesEnabled) Name() string                   { return "StackTracesEnabled" }
func (r *StackTracesEnabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *StackTracesEnabled) Description() string {
	return "Detects configuration flags that enable stack traces in error responses, leaking internal implementation details to users."
}
func (r *StackTracesEnabled) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *StackTracesEnabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if loc := reStackTraceEnabled.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Stack traces enabled in error responses via configuration flag",
				Description:   "A configuration flag explicitly enables stack traces in error responses. Stack traces reveal internal file paths, library versions, database queries, and application structure that aid attackers in crafting targeted exploits.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   loc,
				Suggestion:    "Disable stack traces in production responses. Set includeStackTrace/showStackTrace to false. Log full stack traces server-side for debugging but never expose them to end users.",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"misconfig", "stack-trace", "information-disclosure", "cwe-209"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&DebugModeProd{})
	rules.Register(&DefaultConfig{})
	rules.Register(&VerboseErrorExposed{})
	rules.Register(&AdminExposedNoIPRestriction{})
	rules.Register(&HTTPSNotEnforced{})
	rules.Register(&DirectoryListingEnabled{})
	rules.Register(&InsecurePermissions{})
	rules.Register(&StackTracesEnabled{})
}
