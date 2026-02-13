package php

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for PHP-specific security rules
// ---------------------------------------------------------------------------

// PHP-001: Type juggling (== instead of === for security comparisons)
var (
	reTypeJuggleLoose = regexp.MustCompile(`(?:password|token|secret|hash|key|auth|session|nonce|csrf|otp|pin|code|digest|signature|mac|hmac)\s*(?:==|!=)\s*`)
	// Also match the reverse: $input == $password
	reTypeJuggleLooseRev = regexp.MustCompile(`\$\w+\s*(?:==|!=)\s*\$(?:password|token|secret|hash|key|auth|session|nonce|csrf|otp|pin|code|digest|signature|mac|hmac)`)
	// Safe: using === or !==
	reTypeJuggleStrict = regexp.MustCompile(`===|!==`)
)

// PHP-002: file_get_contents/fopen with user URL (SSRF)
var (
	reSSRFFileGet = regexp.MustCompile(`\bfile_get_contents\s*\(\s*\$`)
	reSSRFFopen   = regexp.MustCompile(`\bfopen\s*\(\s*\$`)
	reSSRFCurl    = regexp.MustCompile(`\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$`)
	// Safe: file paths (not URLs)
	reSSRFSafeFilePath = regexp.MustCompile(`(?:__DIR__|dirname|__FILE__|realpath|DIRECTORY_SEPARATOR|\.txt|\.log|\.json|\.xml|\.csv|\.php)`)
)

// PHP-003: include/require with user input (LFI/RFI)
var (
	reIncludeUser    = regexp.MustCompile(`\b(?:include|include_once|require|require_once)\s*\(?\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|input|param|file|page|path|dir|template|module|lang|language)`)
	reIncludeConcat  = regexp.MustCompile(`\b(?:include|include_once|require|require_once)\s*\(?\s*["'][^"']*["']\s*\.\s*\$`)
	reIncludeDynamic = regexp.MustCompile(`\b(?:include|include_once|require|require_once)\s*\(\s*\$\w+\s*\)`)
)

// PHP-004: mail() header injection
var (
	reMailHeader      = regexp.MustCompile(`\bmail\s*\(\s*\$`)
	reMailHeaderConcat = regexp.MustCompile(`\bmail\s*\([^,]*,\s*[^,]*,\s*[^,]*,\s*(?:["'][^"']*["']\s*\.\s*\$|\$_(?:GET|POST|REQUEST|COOKIE))`)
	reMailHeaderParam = regexp.MustCompile(`\bmail\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)`)
)

// PHP-005: exec/system/passthru/shell_exec with user input (already partly in injection.go, more specific here)
var (
	rePHPShellUser = regexp.MustCompile(`\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|input|cmd|command|param|arg)`)
	rePHPBacktick  = regexp.MustCompile("`[^`]*\\$(?:_GET|_POST|_REQUEST|_COOKIE|input|cmd|command)")
)

// PHP-006: mysqli_query/pg_query without prepared statements
var (
	rePHPRawQuery      = regexp.MustCompile(`\b(?:mysqli_query|mysql_query|pg_query|pg_exec)\s*\(\s*\$\w+\s*,\s*(?:"[^"]*\$|'[^']*'\s*\.\s*\$)`)
	rePHPRawQueryConcat = regexp.MustCompile(`\b(?:mysqli_query|mysql_query|pg_query|pg_exec)\s*\(\s*\$\w+\s*,\s*\$`)
	rePHPRawQueryDotConcat = regexp.MustCompile(`\b(?:mysqli_query|mysql_query|pg_query|pg_exec)\s*\([^,]+,\s*"[^"]*"\s*\.\s*\$`)
)

// PHP-007: session.cookie_httponly/secure not set
var (
	reSessionCookieHttp   = regexp.MustCompile(`(?i)session\.cookie_httponly\s*=\s*(?:0|false|off)`)
	reSessionCookieSecure = regexp.MustCompile(`(?i)session\.cookie_secure\s*=\s*(?:0|false|off)`)
	reSessionCookieSame   = regexp.MustCompile(`(?i)session\.cookie_samesite\s*=\s*["']?\s*(?:None|none)`)
	reIniSetSessionHttp   = regexp.MustCompile(`\bini_set\s*\(\s*["']session\.cookie_httponly["']\s*,\s*(?:0|false|'0'|"0"|'false'|"false")`)
	reIniSetSessionSecure = regexp.MustCompile(`\bini_set\s*\(\s*["']session\.cookie_secure["']\s*,\s*(?:0|false|'0'|"0"|'false'|"false")`)
)

// PHP-008: Symfony Process injection
var (
	reSymfonyProcess     = regexp.MustCompile(`new\s+Process\s*\(\s*\[?\s*\$`)
	reSymfonyProcessRun  = regexp.MustCompile(`Process::fromShellCommandline\s*\(\s*\$`)
)

// PHP-009: Twig autoescape disabled / |raw filter
var (
	reTwigRawFilter   = regexp.MustCompile(`\|\s*raw\b`)
	reTwigAutoescOff  = regexp.MustCompile(`\{%[-\s]*autoescape\s+false\s*[-\s]*%\}`)
	reTwigAutoescConf = regexp.MustCompile(`'autoescape'\s*=>\s*false`)
)

// PHP-010: LDAP injection (ldap_search with unescaped filter)
var (
	reLDAPSearchPHP     = regexp.MustCompile(`\bldap_search\s*\([^,]+,\s*[^,]+,\s*(?:\$|["'][^"']*["']\s*\.\s*\$)`)
	reLDAPBindPHP       = regexp.MustCompile(`\bldap_bind\s*\([^,]+,\s*(?:\$|["'][^"']*["']\s*\.\s*\$)`)
	reLDAPSafeEscape    = regexp.MustCompile(`ldap_escape\s*\(`)
)

// PHP-011: Weak random number generation
var (
	rePHPWeakRand     = regexp.MustCompile(`\b(?:rand|mt_rand|array_rand|shuffle|str_shuffle)\s*\(`)
	rePHPSecureRand   = regexp.MustCompile(`\b(?:random_int|random_bytes|openssl_random_pseudo_bytes)\s*\(`)
	// Context: security-sensitive usage
	rePHPRandSecurity = regexp.MustCompile(`(?i)(?:token|password|secret|key|nonce|csrf|otp|salt|iv|session|reset|verify|auth)`)
)

// PHP-012: Disabled error reporting exposing info
var (
	reDisplayErrors = regexp.MustCompile(`(?i)display_errors\s*=\s*(?:1|on|true|'1'|"1"|'on'|"on")`)
	reIniSetDisplay = regexp.MustCompile(`\bini_set\s*\(\s*["']display_errors["']\s*,\s*(?:1|'1'|"1"|true|'true'|"true"|'on'|"on"|'On'|"On")`)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func hasNearbyPattern(lines []string, idx int, pat *regexp.Regexp) bool {
	start := idx - 15
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if pat.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GTSS-PHP-001: Type Juggling
// ---------------------------------------------------------------------------

type TypeJuggling struct{}

func (r *TypeJuggling) ID() string                      { return "GTSS-PHP-001" }
func (r *TypeJuggling) Name() string                    { return "PHPTypeJuggling" }
func (r *TypeJuggling) Description() string             { return "Detects PHP loose comparison (== / !=) on security-sensitive values that should use strict comparison (=== / !==)." }
func (r *TypeJuggling) DefaultSeverity() rules.Severity { return rules.High }
func (r *TypeJuggling) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *TypeJuggling) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		// Skip lines with strict comparison
		if reTypeJuggleStrict.MatchString(line) {
			continue
		}
		if reTypeJuggleLoose.MatchString(line) || reTypeJuggleLooseRev.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP type juggling: loose comparison on security-sensitive value",
				Description:   "Using == or != for comparing passwords, tokens, hashes, or other security values is vulnerable to type juggling. PHP may coerce types unexpectedly (e.g., '0e123' == '0e456' evaluates to true). This can bypass authentication checks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use strict comparison (=== / !==) or hash_equals() for comparing security-sensitive values like passwords, tokens, and hashes.",
				CWEID:         "CWE-1025",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "type-juggling", "authentication"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-002: SSRF via file_get_contents/fopen/curl
// ---------------------------------------------------------------------------

type SSRF struct{}

func (r *SSRF) ID() string                      { return "GTSS-PHP-002" }
func (r *SSRF) Name() string                    { return "PHPSSRF" }
func (r *SSRF) Description() string             { return "Detects PHP file_get_contents/fopen/curl_setopt with user-controlled URL, enabling SSRF." }
func (r *SSRF) DefaultSeverity() rules.Severity { return rules.High }
func (r *SSRF) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *SSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		// Skip file path patterns (not URLs)
		if reSSRFSafeFilePath.MatchString(line) {
			continue
		}

		var matched string
		var desc string

		if m := reSSRFFileGet.FindString(line); m != "" {
			matched = m
			desc = "file_get_contents() with user-controlled URL"
		} else if m := reSSRFFopen.FindString(line); m != "" {
			matched = m
			desc = "fopen() with user-controlled URL"
		} else if m := reSSRFCurl.FindString(line); m != "" {
			matched = m
			desc = "curl_setopt CURLOPT_URL with user-controlled value"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP SSRF: " + desc,
				Description:   "Passing a user-controlled variable as a URL to file_get_contents(), fopen(), or cURL allows an attacker to make requests to internal services, cloud metadata endpoints (169.254.169.254), or other restricted resources.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Validate and sanitize URLs against an allowlist of domains/protocols. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use parse_url() to validate the scheme and host before making the request.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-Server-Side Request Forgery",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "ssrf", "file-get-contents"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-003: Local/Remote File Inclusion
// ---------------------------------------------------------------------------

type FileInclusion struct{}

func (r *FileInclusion) ID() string                      { return "GTSS-PHP-003" }
func (r *FileInclusion) Name() string                    { return "PHPFileInclusion" }
func (r *FileInclusion) Description() string             { return "Detects PHP include/require with user input, enabling LFI/RFI." }
func (r *FileInclusion) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *FileInclusion) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *FileInclusion) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		confidence := "high"

		if m := reIncludeUser.FindString(line); m != "" {
			matched = m
		} else if m := reIncludeConcat.FindString(line); m != "" {
			matched = m
		} else if m := reIncludeDynamic.FindString(line); m != "" {
			matched = m
			confidence = "medium"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP file inclusion with user-controlled path (LFI/RFI)",
				Description:   "include/require with user-controlled input allows an attacker to include arbitrary local files (LFI) to read sensitive data like /etc/passwd, or remote files (RFI) to execute arbitrary PHP code if allow_url_include is enabled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never pass user input to include/require. Use an allowlist of valid file names and map user input to known paths. Disable allow_url_include in php.ini.",
				CWEID:         "CWE-98",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"php", "lfi", "rfi", "file-inclusion"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-004: mail() Header Injection
// ---------------------------------------------------------------------------

type MailHeaderInjection struct{}

func (r *MailHeaderInjection) ID() string                      { return "GTSS-PHP-004" }
func (r *MailHeaderInjection) Name() string                    { return "PHPMailHeaderInjection" }
func (r *MailHeaderInjection) Description() string             { return "Detects PHP mail() with user-controlled headers, enabling email header injection." }
func (r *MailHeaderInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *MailHeaderInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *MailHeaderInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		confidence := "high"

		if reMailHeaderParam.MatchString(line) {
			matched = true
		} else if reMailHeaderConcat.MatchString(line) {
			matched = true
		} else if reMailHeader.MatchString(line) {
			// Only flag bare mail($var, ...) if superglobals nearby
			if hasNearbyPattern(lines, i, regexp.MustCompile(`\$_(?:GET|POST|REQUEST)`)) {
				matched = true
				confidence = "medium"
			}
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP mail() with user-controlled parameters (header injection)",
				Description:   "The PHP mail() function with user-controlled parameters allows an attacker to inject additional email headers via CRLF (\\r\\n) sequences. This enables sending spam, phishing emails, or BCC to arbitrary recipients.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use a library like PHPMailer or SwiftMailer that sanitizes headers automatically. If using mail(), strip \\r and \\n from all user input used in headers. Never pass user input directly as the additional_headers parameter.",
				CWEID:         "CWE-93",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"php", "mail", "header-injection", "email"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-005: Command Injection (PHP-specific patterns beyond INJ-002)
// ---------------------------------------------------------------------------

type CommandInjection struct{}

func (r *CommandInjection) ID() string                      { return "GTSS-PHP-005" }
func (r *CommandInjection) Name() string                    { return "PHPCommandInjection" }
func (r *CommandInjection) Description() string             { return "Detects PHP shell execution with user input from superglobals." }
func (r *CommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CommandInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *CommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var desc string

		if m := rePHPShellUser.FindString(line); m != "" {
			matched = m
			desc = "shell function with user input variable"
		} else if m := rePHPBacktick.FindString(line); m != "" {
			matched = m
			desc = "backtick operator with user input"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP command injection: " + desc,
				Description:   "PHP shell execution functions (system, exec, passthru, shell_exec, popen, proc_open) with user-controlled input allow arbitrary OS command execution. An attacker can chain commands using ;, |, &&, or backtick injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use escapeshellarg() and escapeshellcmd() to sanitize user input before passing to shell functions. Better yet, avoid shell execution entirely and use built-in PHP functions for the same task.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "command-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-006: Raw SQL queries without prepared statements
// ---------------------------------------------------------------------------

type RawSQLQuery struct{}

func (r *RawSQLQuery) ID() string                      { return "GTSS-PHP-006" }
func (r *RawSQLQuery) Name() string                    { return "PHPRawSQLQuery" }
func (r *RawSQLQuery) Description() string             { return "Detects PHP mysqli_query/pg_query with variable interpolation instead of prepared statements." }
func (r *RawSQLQuery) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RawSQLQuery) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *RawSQLQuery) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		confidence := "high"

		if m := rePHPRawQuery.FindString(line); m != "" {
			matched = m
		} else if m := rePHPRawQueryDotConcat.FindString(line); m != "" {
			matched = m
		} else if m := rePHPRawQueryConcat.FindString(line); m != "" {
			matched = m
			confidence = "medium"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP SQL injection: raw query with variable interpolation",
				Description:   "mysqli_query/mysql_query/pg_query with variable interpolation or concatenation allows SQL injection. An attacker can modify query logic, extract data, or modify/delete records.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use prepared statements: $stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?'); $stmt->bind_param('i', $id); $stmt->execute(); Or use PDO with parameterized queries.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"php", "sql-injection", "prepared-statements"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-007: Insecure Session Cookie Configuration
// ---------------------------------------------------------------------------

type InsecureSessionCookie struct{}

func (r *InsecureSessionCookie) ID() string                      { return "GTSS-PHP-007" }
func (r *InsecureSessionCookie) Name() string                    { return "PHPInsecureSessionCookie" }
func (r *InsecureSessionCookie) Description() string             { return "Detects PHP session cookie configuration with httponly, secure, or samesite disabled." }
func (r *InsecureSessionCookie) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureSessionCookie) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *InsecureSessionCookie) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		// Also check .ini files
		if !strings.HasSuffix(ctx.FilePath, ".ini") && !strings.HasSuffix(ctx.FilePath, ".htaccess") {
			return nil
		}
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type check struct {
		re         *regexp.Regexp
		title      string
		desc       string
		suggestion string
	}

	checks := []check{
		{
			re:         reSessionCookieHttp,
			title:      "PHP session.cookie_httponly disabled",
			desc:       "Setting session.cookie_httponly to 0/false allows JavaScript to access session cookies via document.cookie, making session hijacking easier via XSS.",
			suggestion: "Set session.cookie_httponly = 1 to prevent JavaScript access to session cookies.",
		},
		{
			re:         reSessionCookieSecure,
			title:      "PHP session.cookie_secure disabled",
			desc:       "Setting session.cookie_secure to 0/false allows session cookies to be transmitted over unencrypted HTTP, exposing them to network interception.",
			suggestion: "Set session.cookie_secure = 1 to only send session cookies over HTTPS.",
		},
		{
			re:         reSessionCookieSame,
			title:      "PHP session.cookie_samesite set to None",
			desc:       "Setting session.cookie_samesite to None sends cookies with all cross-site requests, weakening CSRF protection.",
			suggestion: "Set session.cookie_samesite = Lax or Strict to prevent cross-site cookie transmission.",
		},
		{
			re:         reIniSetSessionHttp,
			title:      "PHP session.cookie_httponly disabled via ini_set",
			desc:       "ini_set() disables session.cookie_httponly, allowing JavaScript access to session cookies.",
			suggestion: "Set ini_set('session.cookie_httponly', 1) to prevent JavaScript access.",
		},
		{
			re:         reIniSetSessionSecure,
			title:      "PHP session.cookie_secure disabled via ini_set",
			desc:       "ini_set() disables session.cookie_secure, allowing cookies over HTTP.",
			suggestion: "Set ini_set('session.cookie_secure', 1) to enforce HTTPS-only cookies.",
		},
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		for _, c := range checks {
			if c.re.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         c.title,
					Description:   c.desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    c.suggestion,
					CWEID:         "CWE-614",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"php", "session", "cookie", "misconfiguration"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-008: Symfony Process Injection
// ---------------------------------------------------------------------------

type SymfonyProcessInjection struct{}

func (r *SymfonyProcessInjection) ID() string                      { return "GTSS-PHP-008" }
func (r *SymfonyProcessInjection) Name() string                    { return "PHPSymfonyProcessInjection" }
func (r *SymfonyProcessInjection) Description() string             { return "Detects Symfony Process class with user input, enabling command injection." }
func (r *SymfonyProcessInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SymfonyProcessInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *SymfonyProcessInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var desc string

		if m := reSymfonyProcessRun.FindString(line); m != "" {
			matched = m
			desc = "Process::fromShellCommandline() with user-controlled input"
		} else if m := reSymfonyProcess.FindString(line); m != "" {
			matched = m
			desc = "new Process() with user-controlled arguments"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Symfony process injection: " + desc,
				Description:   "The Symfony Process component with user-controlled input allows arbitrary command execution. Process::fromShellCommandline() is especially dangerous as it invokes a shell. Even new Process() with a user-controlled array element can be exploited.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use new Process() with an explicit array of arguments (not fromShellCommandline). Validate and sanitize all user input. Use escapeshellarg() for individual arguments if shell invocation is unavoidable.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "symfony", "command-injection", "process"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-009: Twig Autoescape Disabled / |raw Filter
// ---------------------------------------------------------------------------

type TwigRawFilter struct{}

func (r *TwigRawFilter) ID() string                      { return "GTSS-PHP-009" }
func (r *TwigRawFilter) Name() string                    { return "PHPTwigRawFilter" }
func (r *TwigRawFilter) Description() string             { return "Detects Twig |raw filter or autoescape disabled, which bypasses XSS protection." }
func (r *TwigRawFilter) DefaultSeverity() rules.Severity { return rules.High }
func (r *TwigRawFilter) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *TwigRawFilter) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched bool
		var title, desc string

		if reTwigRawFilter.MatchString(line) {
			matched = true
			title = "Twig |raw filter bypasses XSS auto-escaping"
			desc = "The |raw filter in Twig marks content as safe HTML, bypassing auto-escaping. If user input flows through this filter, it creates an XSS vulnerability."
		} else if reTwigAutoescOff.MatchString(line) {
			matched = true
			title = "Twig autoescape disabled"
			desc = "Disabling autoescape in a Twig block outputs all variables as raw HTML, creating XSS vulnerabilities for any user-controlled data in the block."
		} else if reTwigAutoescConf.MatchString(line) {
			matched = true
			title = "Twig autoescape disabled in configuration"
			desc = "Setting 'autoescape' => false in Twig configuration disables HTML escaping globally, creating XSS vulnerabilities throughout the application."
		}

		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Remove the |raw filter and let Twig auto-escape. If raw HTML is needed, sanitize with a library like HTML Purifier before passing to the template. Keep autoescape enabled globally.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "twig", "xss", "autoescape"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-010: LDAP Injection
// ---------------------------------------------------------------------------

type LDAPInjection struct{}

func (r *LDAPInjection) ID() string                      { return "GTSS-PHP-010" }
func (r *LDAPInjection) Name() string                    { return "PHPLDAPInjection" }
func (r *LDAPInjection) Description() string             { return "Detects PHP ldap_search/ldap_bind with unescaped user input, enabling LDAP injection." }
func (r *LDAPInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *LDAPInjection) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *LDAPInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		// Skip if ldap_escape is used nearby
		if hasNearbyPattern(lines, i, reLDAPSafeEscape) {
			continue
		}

		var matched string
		var desc string

		if m := reLDAPSearchPHP.FindString(line); m != "" {
			matched = m
			desc = "ldap_search() with user-controlled filter"
		} else if m := reLDAPBindPHP.FindString(line); m != "" {
			matched = m
			desc = "ldap_bind() with user-controlled DN"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP LDAP injection: " + desc,
				Description:   "LDAP functions with user-controlled input allow an attacker to modify LDAP queries. An attacker can bypass authentication, extract directory data, or modify LDAP entries by injecting special characters (*, (, ), \\, NUL).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use ldap_escape($input, '', LDAP_ESCAPE_FILTER) for filter values and ldap_escape($input, '', LDAP_ESCAPE_DN) for DN components before passing to ldap_search/ldap_bind.",
				CWEID:         "CWE-90",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "ldap", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-011: Weak Random Number Generation
// ---------------------------------------------------------------------------

type WeakRandom struct{}

func (r *WeakRandom) ID() string                      { return "GTSS-PHP-011" }
func (r *WeakRandom) Name() string                    { return "PHPWeakRandom" }
func (r *WeakRandom) Description() string             { return "Detects PHP weak random functions (rand, mt_rand) used in security-sensitive contexts." }
func (r *WeakRandom) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *WeakRandom) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *WeakRandom) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	// Skip if secure random functions are used in the file
	if rePHPSecureRand.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rePHPWeakRand.MatchString(line) {
			continue
		}
		// Only flag in security-sensitive contexts
		if !rePHPRandSecurity.MatchString(line) && !hasNearbyPattern(lines, i, rePHPRandSecurity) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "PHP weak random: rand()/mt_rand() in security context",
			Description:   "rand() and mt_rand() are not cryptographically secure. Using them for tokens, passwords, nonces, session IDs, or other security-sensitive values makes them predictable to an attacker.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use random_int() for integers or random_bytes() / bin2hex(random_bytes(32)) for generating cryptographically secure random values.",
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"php", "random", "cryptography"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-PHP-012: Display Errors Enabled
// ---------------------------------------------------------------------------

type DisplayErrors struct{}

func (r *DisplayErrors) ID() string                      { return "GTSS-PHP-012" }
func (r *DisplayErrors) Name() string                    { return "PHPDisplayErrors" }
func (r *DisplayErrors) Description() string             { return "Detects PHP display_errors enabled, which exposes stack traces and sensitive information." }
func (r *DisplayErrors) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DisplayErrors) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }

func (r *DisplayErrors) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		if !strings.HasSuffix(ctx.FilePath, ".ini") && !strings.HasSuffix(ctx.FilePath, ".htaccess") {
			return nil
		}
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reDisplayErrors.MatchString(line) || reIniSetDisplay.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP display_errors enabled (information disclosure)",
				Description:   "Enabling display_errors shows detailed error messages including file paths, SQL queries, stack traces, and potentially credentials to end users. This aids attackers in discovering vulnerabilities.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set display_errors = Off in production. Use error_log to log errors to a file and display a generic error page to users.",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"php", "display-errors", "information-disclosure"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&TypeJuggling{})
	rules.Register(&SSRF{})
	rules.Register(&FileInclusion{})
	rules.Register(&MailHeaderInjection{})
	rules.Register(&CommandInjection{})
	rules.Register(&RawSQLQuery{})
	rules.Register(&InsecureSessionCookie{})
	rules.Register(&SymfonyProcessInjection{})
	rules.Register(&TwigRawFilter{})
	rules.Register(&LDAPInjection{})
	rules.Register(&WeakRandom{})
	rules.Register(&DisplayErrors{})
}
