package generic

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended generic rules
// ---------------------------------------------------------------------------

// BATOU-GEN-013: Hardcoded IP address
var (
	reHardcodedIPv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	reLocalIP       = regexp.MustCompile(`\b(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1)\b`)
	reExampleIP     = regexp.MustCompile(`\b(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+)\b`)
	reIPInConfig    = regexp.MustCompile(`(?i)(?:host|server|addr|address|endpoint|url|bind|listen|connect|ip)\s*[:=]\s*['"]?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}`)
)

// BATOU-GEN-014: TODO/FIXME/HACK in security-critical code
var (
	reTodoSecurity = regexp.MustCompile(`(?i)(?://|#|/\*|\*)\s*(?:TODO|FIXME|HACK|XXX|TEMP|TEMPORARY)\s*[:!]?\s*.*(?:auth|secur|encrypt|password|token|secret|credential|session|permission|access.?control|csrf|xss|injection|sanitiz|validat|vulnerab)`)
)

// BATOU-GEN-015: Commented-out security code
var (
	reCommentedAuth   = regexp.MustCompile(`(?i)(?://|#)\s*(?:if\s*\(|require|import|use\s+).*(?:auth|authenticate|authorize|verify|check_?permission|requireLogin|isAuthenticated|@login_required|@auth|before_action\s*:authenticate)`)
	reCommentedCrypto = regexp.MustCompile(`(?i)(?://|#)\s*(?:.*(?:encrypt|hash|bcrypt|argon|scrypt|hmac|verify_?password|check_?password|csrf_?protect|rate_?limit|sanitize|escape|validate))`)
)

// BATOU-GEN-016: Empty catch/except block
var (
	reEmptyCatchJS   = regexp.MustCompile(`catch\s*\([^)]*\)\s*\{\s*\}`)
	reEmptyCatchJava = regexp.MustCompile(`catch\s*\([^)]*\)\s*\{\s*\}`)
	reEmptyExceptPy  = regexp.MustCompile(`except\s*(?:\w+\s*(?:as\s*\w+)?)?\s*:\s*$`)
	rePassAfterExcept = regexp.MustCompile(`^\s*pass\s*$`)
	reEmptyRescueRb  = regexp.MustCompile(`rescue\s*(?:=>?\s*\w+)?\s*$`)
)

// BATOU-GEN-017: chmod 777/666
var (
	reChmod777      = regexp.MustCompile(`chmod\s+(?:777|666|a\+rwx)\b`)
	reChmodFunc777  = regexp.MustCompile(`(?:os\.chmod|chmod|File\.chmod|fs\.chmod(?:Sync)?)\s*\([^,]+,\s*(?:0o?777|0o?666|0x1ff|511)\b`)
	reOsWriteAll    = regexp.MustCompile(`os\.(?:WriteFile|Create|OpenFile)\s*\([^,]+,\s*[^,]*,\s*(?:0o?777|0o?666)\b`)
)

// BATOU-GEN-018: dangerouslySetInnerHTML/v-html/[innerHTML]
var (
	reDangerousHTML  = regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:`)
	reVHTML          = regexp.MustCompile(`v-html\s*=\s*['"]`)
	reInnerHTMLBind  = regexp.MustCompile(`\[innerHTML\]\s*=\s*['"]`)
	reInnerHTMLAssign = regexp.MustCompile(`\.innerHTML\s*=\s*(?:[a-zA-Z_]\w*|` + "`" + `|['"][^'"]*\$)`)
)

// BATOU-GEN-019: Disabled security feature
var (
	reDisabledSecurity = regexp.MustCompile(`(?i)(?:csrf|xss|cors|auth|security|ssl|tls|https|hsts|csp|frame|clickjack|sanitiz|escap|encrypt|verify|validat|protect|secure|defense|guard|shield|firewall|waf|rate.?limit)\w*\s*[:=]\s*(?:false|0|['"]false['"]|['"]off['"]|['"]disabled?['"]|nil|null|None)`)
	reSkipVerify       = regexp.MustCompile(`(?i)(?:InsecureSkipVerify|skip_?ssl|ssl_?verify|verify_?ssl|verify_?peer|check_?hostname|CURLOPT_SSL_VERIFYPEER|verify_?certs?)\s*[:=]\s*(?:true|false|0|False)`)
)

// BATOU-GEN-020: Sensitive data in URL query string
var (
	reSensitiveInURL = regexp.MustCompile(`(?i)(?:url|href|link|redirect|src|action|endpoint)\s*[:=]\s*['"\x60][^'"` + "`" + `\n]*[?&](?:password|token|secret|api_key|apikey|access_token|auth|session_id|ssn|credit_card)\s*=`)
	reSensitiveQuery = regexp.MustCompile(`(?i)(?:\?|&)(?:password|token|secret|api_?key|access_token|auth_token|session_id|ssn|credit_card)\s*=\s*['"\x60$]`)
)

// BATOU-GEN-021: Insecure temporary file creation
var (
	reTmpFilePath    = regexp.MustCompile(`(?i)(?:['"/]tmp/|['"/]temp/|tempfile|tmpfile|os\.path\.join\s*\(\s*['"](?:/tmp|/temp))[^'"]*(?:\.(?:txt|log|json|xml|csv|dat|db|sql|key|pem|conf|cfg|ini|yaml|yml))?['"]?`)
	reTmpInsecure    = regexp.MustCompile(`(?i)(?:mktemp\s+[^-]|mktemp\s*$|tmpnam|tempnam|os\.tmpnam|tmpfile\(\)|tempfile\.mktemp)\b`)
	reTmpSecure      = regexp.MustCompile(`(?i)(?:tempfile\.mkstemp|tempfile\.NamedTemporaryFile|tempfile\.mkdtemp|os\.CreateTemp|ioutil\.TempFile|os\.MkdirTemp|File\.createTempFile|fs\.mkdtemp|mkstemp)\b`)
)

// ---------------------------------------------------------------------------
// BATOU-GEN-013: Hardcoded IP Address in Source Code
// ---------------------------------------------------------------------------

type HardcodedIPAddress struct{}

func (r *HardcodedIPAddress) ID() string                     { return "BATOU-GEN-013" }
func (r *HardcodedIPAddress) Name() string                   { return "HardcodedIPAddress" }
func (r *HardcodedIPAddress) DefaultSeverity() rules.Severity { return rules.Low }
func (r *HardcodedIPAddress) Description() string {
	return "Detects hardcoded IP addresses in source code, which can indicate environment-specific configurations that should be externalized."
}
func (r *HardcodedIPAddress) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *HardcodedIPAddress) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if loc := reIPInConfig.FindStringIndex(line); loc != nil {
			// Skip localhost/loopback
			if reLocalIP.MatchString(line) {
				continue
			}
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded IP address in source code",
				Description:   "An IP address is hardcoded in what appears to be a configuration value. Hardcoded IPs make code environment-dependent, complicate deployment, and may expose internal network topology.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use environment variables or configuration files for IP addresses. Use DNS names instead of IPs where possible. Never hardcode production server addresses in source code.",
				CWEID:         "CWE-547",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"generic", "hardcoded-ip", "configuration", "cwe-547"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GEN-014: TODO/FIXME/HACK in Security-Critical Code
// ---------------------------------------------------------------------------

type TodoInSecurityCode struct{}

func (r *TodoInSecurityCode) ID() string                     { return "BATOU-GEN-014" }
func (r *TodoInSecurityCode) Name() string                   { return "TodoInSecurityCode" }
func (r *TodoInSecurityCode) DefaultSeverity() rules.Severity { return rules.Info }
func (r *TodoInSecurityCode) Description() string {
	return "Detects TODO/FIXME/HACK comments in security-critical code sections, indicating incomplete security implementations."
}
func (r *TodoInSecurityCode) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *TodoInSecurityCode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if loc := reTodoSecurity.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "TODO/FIXME in security-critical code",
				Description:   "A TODO, FIXME, or HACK comment exists in security-critical code. This indicates an incomplete security implementation that should be addressed before deployment.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Address all TODO/FIXME comments in security code before deploying to production. Incomplete security implementations can be worse than no implementation, as they give a false sense of safety.",
				CWEID:         "CWE-546",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"generic", "todo", "security-debt", "cwe-546"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GEN-015: Commented-Out Security Logic
// ---------------------------------------------------------------------------

type CommentedOutSecurityCode struct{}

func (r *CommentedOutSecurityCode) ID() string                     { return "BATOU-GEN-015" }
func (r *CommentedOutSecurityCode) Name() string                   { return "CommentedOutSecurityCode" }
func (r *CommentedOutSecurityCode) DefaultSeverity() rules.Severity { return rules.Low }
func (r *CommentedOutSecurityCode) Description() string {
	return "Detects commented-out security logic (authentication checks, encryption, CSRF protection) that may have been disabled during debugging."
}
func (r *CommentedOutSecurityCode) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *CommentedOutSecurityCode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		matched := ""
		if loc := reCommentedAuth.FindString(line); loc != "" {
			matched = loc
		} else if loc := reCommentedCrypto.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Commented-out security code detected",
				Description:   "Security-related code (authentication, authorization, encryption, CSRF protection, rate limiting) appears to be commented out. This may have been done during debugging and accidentally left disabled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Re-enable the commented-out security code or remove it entirely. If the security check was intentionally removed, document why and ensure an alternative protection is in place.",
				CWEID:         "CWE-546",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"generic", "commented-code", "security-debt", "cwe-546"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GEN-016: Empty Catch/Except Block
// ---------------------------------------------------------------------------

type EmptyCatchBlock struct{}

func (r *EmptyCatchBlock) ID() string                     { return "BATOU-GEN-016" }
func (r *EmptyCatchBlock) Name() string                   { return "EmptyCatchBlock" }
func (r *EmptyCatchBlock) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *EmptyCatchBlock) Description() string {
	return "Detects empty catch/except/rescue blocks that silently swallow errors, potentially hiding security-relevant failures."
}
func (r *EmptyCatchBlock) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPython, rules.LangRuby, rules.LangCSharp}
}

func (r *EmptyCatchBlock) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		matched := ""
		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangCSharp:
			if loc := reEmptyCatchJS.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangPython:
			if reEmptyExceptPy.MatchString(line) {
				// Check if next non-empty line is just 'pass'
				for j := i + 1; j < len(lines) && j < i+3; j++ {
					nextTrimmed := strings.TrimSpace(lines[j])
					if nextTrimmed == "" {
						continue
					}
					if rePassAfterExcept.MatchString(lines[j]) {
						matched = trimmed + " pass"
					}
					break
				}
			}
		case rules.LangRuby:
			if reEmptyRescueRb.MatchString(line) {
				// Check if next non-empty line is just 'end' or empty
				for j := i + 1; j < len(lines) && j < i+3; j++ {
					nextTrimmed := strings.TrimSpace(lines[j])
					if nextTrimmed == "" {
						continue
					}
					if nextTrimmed == "end" {
						matched = trimmed
					}
					break
				}
			}
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Empty catch/except block swallows errors silently",
				Description:   "An exception handler catches errors but does nothing with them. Silently swallowing errors can hide security failures (authentication errors, authorization denials, integrity check failures) and make debugging impossible.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "At minimum, log the error. For security-critical code, re-throw the exception or return an error response. Empty catch blocks should be replaced with proper error handling.",
				CWEID:         "CWE-390",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"generic", "empty-catch", "error-handling", "cwe-390"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GEN-017: Unrestricted File Permissions (chmod 777/666)
// ---------------------------------------------------------------------------

type UnrestrictedFilePermissions struct{}

func (r *UnrestrictedFilePermissions) ID() string                     { return "BATOU-GEN-017" }
func (r *UnrestrictedFilePermissions) Name() string                   { return "UnrestrictedFilePermissions" }
func (r *UnrestrictedFilePermissions) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnrestrictedFilePermissions) Description() string {
	return "Detects chmod 777 or 666 and equivalent programmatic calls that set world-readable/writable permissions."
}
func (r *UnrestrictedFilePermissions) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *UnrestrictedFilePermissions) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		matched := ""
		if loc := reChmod777.FindString(line); loc != "" {
			matched = loc
		} else if loc := reChmodFunc777.FindString(line); loc != "" {
			matched = loc
		} else if loc := reOsWriteAll.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unrestricted file permissions (chmod 777/666)",
				Description:   "File or directory permissions are set to world-readable/writable (777 or 666). Any user on the system can read, modify, or execute this file, which can lead to data theft, code injection, or privilege escalation.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use restrictive permissions: 0644 for regular files (owner write, others read), 0600 for sensitive files (owner only), 0755 for directories. Never use 777 or 666 in production.",
				CWEID:         "CWE-732",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"generic", "permissions", "chmod", "cwe-732"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GEN-018: Unsafe dangerouslySetInnerHTML/v-html/[innerHTML]
// ---------------------------------------------------------------------------

type UnsafeInnerHTML struct{}

func (r *UnsafeInnerHTML) ID() string                     { return "BATOU-GEN-018" }
func (r *UnsafeInnerHTML) Name() string                   { return "UnsafeInnerHTML" }
func (r *UnsafeInnerHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnsafeInnerHTML) Description() string {
	return "Detects use of dangerouslySetInnerHTML (React), v-html (Vue), [innerHTML] (Angular), or direct innerHTML assignment which can lead to XSS."
}
func (r *UnsafeInnerHTML) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *UnsafeInnerHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}
		matched := ""
		title := ""
		if loc := reDangerousHTML.FindString(line); loc != "" {
			matched = loc
			title = "React dangerouslySetInnerHTML renders unescaped HTML"
		} else if loc := reVHTML.FindString(line); loc != "" {
			matched = loc
			title = "Vue v-html renders unescaped HTML"
		} else if loc := reInnerHTMLBind.FindString(line); loc != "" {
			matched = loc
			title = "Angular [innerHTML] renders unescaped HTML"
		} else if loc := reInnerHTMLAssign.FindString(line); loc != "" {
			matched = loc
			title = "Direct innerHTML assignment with dynamic content"
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
				Description:   "Rendering raw HTML from a variable bypasses framework XSS protections. If the HTML content includes user input, attackers can inject malicious scripts that execute in other users' browsers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Avoid using innerHTML/dangerouslySetInnerHTML/v-html. Use text content instead. If HTML rendering is required, sanitize input with DOMPurify: DOMPurify.sanitize(html). For React, consider using a safe markdown renderer.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"generic", "xss", "innerHTML", "cwe-79"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GEN-019: Disabled Security Feature via Config Flag
// ---------------------------------------------------------------------------

type DisabledSecurityFeature struct{}

func (r *DisabledSecurityFeature) ID() string                     { return "BATOU-GEN-019" }
func (r *DisabledSecurityFeature) Name() string                   { return "DisabledSecurityFeature" }
func (r *DisabledSecurityFeature) DefaultSeverity() rules.Severity { return rules.High }
func (r *DisabledSecurityFeature) Description() string {
	return "Detects security features explicitly disabled via configuration flags (CSRF protection, SSL verification, authentication, etc.)."
}
func (r *DisabledSecurityFeature) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *DisabledSecurityFeature) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		matched := ""
		if loc := reDisabledSecurity.FindString(line); loc != "" {
			matched = loc
		} else if loc := reSkipVerify.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			// Skip if in a conditional/ternary
			if strings.Contains(line, "if") || strings.Contains(line, "?") {
				continue
			}
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Security feature explicitly disabled via configuration",
				Description:   "A security feature (CSRF protection, SSL verification, authentication, rate limiting, input sanitization, or similar) is explicitly set to disabled/false. This removes a layer of defense and may have been done during development but not re-enabled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Re-enable the security feature. If it must be disabled for a specific reason, document why in a comment and ensure compensating controls are in place. Never disable SSL verification in production.",
				CWEID:         "CWE-16",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"generic", "disabled-security", "misconfiguration", "cwe-16"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GEN-020: Sensitive Data in URL Query String
// ---------------------------------------------------------------------------

type SensitiveDataInURL struct{}

func (r *SensitiveDataInURL) ID() string                     { return "BATOU-GEN-020" }
func (r *SensitiveDataInURL) Name() string                   { return "SensitiveDataInURL" }
func (r *SensitiveDataInURL) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SensitiveDataInURL) Description() string {
	return "Detects sensitive data (passwords, tokens, API keys) passed in URL query strings, which are logged in server logs, browser history, and referrer headers."
}
func (r *SensitiveDataInURL) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *SensitiveDataInURL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		matched := ""
		if loc := reSensitiveInURL.FindString(line); loc != "" {
			matched = loc
		} else if loc := reSensitiveQuery.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Sensitive data in URL query string",
				Description:   "Sensitive data (password, token, API key, SSN) is passed in a URL query string. Query strings are logged in web server access logs, stored in browser history, sent in Referer headers to third parties, and visible in network monitoring tools.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Send sensitive data in HTTP request headers (Authorization header) or request body instead of URL query strings. Use POST instead of GET for requests containing sensitive data.",
				CWEID:         "CWE-598",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"generic", "sensitive-url", "information-disclosure", "cwe-598"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-GEN-021: Insecure Temporary File Creation
// ---------------------------------------------------------------------------

type InsecureTempFile struct{}

func (r *InsecureTempFile) ID() string                     { return "BATOU-GEN-021" }
func (r *InsecureTempFile) Name() string                   { return "InsecureTempFile" }
func (r *InsecureTempFile) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureTempFile) Description() string {
	return "Detects insecure temporary file creation patterns (predictable names, race conditions) that can be exploited for symlink attacks or information disclosure."
}
func (r *InsecureTempFile) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangC, rules.LangCPP, rules.LangPerl, rules.LangRuby, rules.LangPHP, rules.LangGo, rules.LangJavaScript, rules.LangTypeScript}
}

func (r *InsecureTempFile) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if secure temp functions are used
	if reTmpSecure.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if loc := reTmpInsecure.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Insecure temporary file creation (predictable name or race condition)",
				Description:   "An insecure temporary file creation function is used. Functions like tmpnam, tempnam, and tempfile.mktemp create predictable file names or have TOCTOU race conditions that allow symlink attacks, where an attacker replaces the temp file with a symlink to a sensitive file.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   loc,
				Suggestion:    "Use secure temp file creation: Python tempfile.mkstemp() or NamedTemporaryFile(), Go os.CreateTemp(), C mkstemp(), Java File.createTempFile(). These create files atomically with unpredictable names.",
				CWEID:         "CWE-377",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"generic", "temp-file", "race-condition", "cwe-377"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&HardcodedIPAddress{})
	rules.Register(&TodoInSecurityCode{})
	rules.Register(&CommentedOutSecurityCode{})
	rules.Register(&EmptyCatchBlock{})
	rules.Register(&UnrestrictedFilePermissions{})
	rules.Register(&UnsafeInnerHTML{})
	rules.Register(&DisabledSecurityFeature{})
	rules.Register(&SensitiveDataInURL{})
	rules.Register(&InsecureTempFile{})
}
