package session

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// GTSS-SESS-001: Session fixation - no regeneration after login
var (
	reLoginNoRegenPy     = regexp.MustCompile(`(?i)(?:def\s+login|def\s+authenticate|def\s+sign_in)\s*\(`)
	reSessionRegenPy     = regexp.MustCompile(`(?i)(?:request\.session\.cycle_key|session\.regenerate|request\.session\.flush|session_regenerate_id)`)
	reLoginNoRegenJava   = regexp.MustCompile(`(?i)(?:void\s+(?:do)?login|authenticate|signIn)\s*\(`)
	reSessionRegenJava   = regexp.MustCompile(`(?i)(?:request\.changeSessionId|session\.invalidate|HttpSession\s+\w+\s*=\s*request\.getSession\(true\))`)
	reLoginNoRegenPHP    = regexp.MustCompile(`(?i)(?:function\s+login|function\s+authenticate|function\s+signIn)\s*\(`)
	reSessionRegenPHP    = regexp.MustCompile(`(?i)session_regenerate_id\s*\(`)
	reLoginNoRegenRuby   = regexp.MustCompile(`(?i)(?:def\s+(?:create|login|sign_in|authenticate)\b)`)
	reSessionRegenRuby   = regexp.MustCompile(`(?i)(?:reset_session|regenerate)`)
	reLoginNoRegenExpress = regexp.MustCompile(`(?i)(?:(?:app|router)\.\s*post\s*\(\s*["']/(?:login|auth|signin)["']|function\s+login|const\s+login)`)
	reSessionRegenJS     = regexp.MustCompile(`(?i)(?:req\.session\.regenerate|session\.regenerate|req\.session\.destroy)`)
)

// GTSS-SESS-002: Session cookie without HttpOnly flag
var (
	reCookieNoHttpOnly    = regexp.MustCompile(`(?i)(?:Set-Cookie|cookie)\s*[=:]\s*["'][^"']*(?:;|$)`)
	reCookieHttpOnlyFalse = regexp.MustCompile(`(?i)(?:httpOnly|http_only|httponly)\s*[=:]\s*(?:false|False|FALSE|0)`)
	reSessionCookieNoHttp = regexp.MustCompile(`(?i)(?:session\.cookie_httponly|SESSION_COOKIE_HTTPONLY|cookie_httponly)\s*[=:]\s*(?:false|False|FALSE|0)`)
	rePHPIniNoHttpOnly    = regexp.MustCompile(`(?i)session\.cookie_httponly\s*=\s*(?:0|off|false|Off|False)`)
)

// GTSS-SESS-003: Session cookie without Secure flag
var (
	reCookieSecureFalse    = regexp.MustCompile(`(?i)(?:secure)\s*[=:]\s*(?:false|False|FALSE|0)`)
	reSessionCookieNoSecure = regexp.MustCompile(`(?i)(?:session\.cookie_secure|SESSION_COOKIE_SECURE|cookie_secure)\s*[=:]\s*(?:false|False|FALSE|0)`)
	rePHPIniNoSecure       = regexp.MustCompile(`(?i)session\.cookie_secure\s*=\s*(?:0|off|false|Off|False)`)
)

// GTSS-SESS-004: Session cookie without SameSite
var (
	reCookieSameSiteNone = regexp.MustCompile(`(?i)(?:sameSite|same_site|samesite)\s*[=:]\s*["']?(?:none|None)["']?`)
	reSessionNoSameSite  = regexp.MustCompile(`(?i)(?:SESSION_COOKIE_SAMESITE|session\.cookie_samesite)\s*[=:]\s*["']?(?:none|None|false|False)["']?`)
)

// GTSS-SESS-005: Session data in localStorage/sessionStorage
var (
	reLocalStorageSession   = regexp.MustCompile(`(?i)localStorage\.setItem\s*\(\s*["'](?:session|sessionId|session_id|sid|PHPSESSID|JSESSIONID|connect\.sid)["']`)
	reSessionStorageSession = regexp.MustCompile(`(?i)sessionStorage\.setItem\s*\(\s*["'](?:session|sessionId|session_id|sid|token|auth)["']`)
	reLocalStorageDirect    = regexp.MustCompile(`(?i)localStorage\s*\[\s*["'](?:session|sessionId|session_id|sid)["']\s*\]\s*=`)
)

// GTSS-SESS-006: Session ID in URL/query parameter
var (
	reSessionInURL       = regexp.MustCompile(`(?i)(?:\?|&)(?:session|sessionId|session_id|sid|PHPSESSID|JSESSIONID|sessid)\s*=`)
	reSessionURLParam    = regexp.MustCompile(`(?i)(?:req\.(?:query|params)|request\.(?:GET|args)|getParameter)\s*[\[(]\s*["'](?:session|sessionId|session_id|sid|PHPSESSID|JSESSIONID)["']`)
	reSessionURLConcat   = regexp.MustCompile(`(?i)(?:url|uri|href|redirect)\s*[=+]\s*[^;]*[?&](?:session|sessionId|session_id|sid)=`)
)

// GTSS-SESS-007: Excessive session timeout (>24h)
var (
	reSessionTimeoutLarge = regexp.MustCompile(`(?i)(?:session\.?(?:_)?(?:timeout|maxAge|max_age|lifetime|cookie_age|expire|expiry|maxInactiveInterval))\s*[=:]\s*(\d+)`)
	reSessionMaxAge       = regexp.MustCompile(`(?i)(?:maxAge|max_age|expires|cookie_lifetime)\s*[=:]\s*(\d+)`)
	rePHPSessionGC        = regexp.MustCompile(`(?i)session\.gc_maxlifetime\s*=\s*(\d+)`)
)

// GTSS-SESS-008: Session not invalidated on logout
var (
	reLogoutFuncPy    = regexp.MustCompile(`(?i)(?:def\s+logout|def\s+sign_out|def\s+log_out)\s*\(`)
	reLogoutFuncJS    = regexp.MustCompile(`(?i)(?:(?:app|router)\.\s*(?:post|get|delete)\s*\(\s*["']/(?:logout|signout|sign-out)["']|function\s+logout|const\s+logout)`)
	reLogoutFuncJava  = regexp.MustCompile(`(?i)(?:void\s+(?:do)?logout|void\s+signOut)\s*\(`)
	reLogoutFuncPHP   = regexp.MustCompile(`(?i)(?:function\s+logout|function\s+signOut|function\s+sign_out)\s*\(`)
	reSessionDestroy  = regexp.MustCompile(`(?i)(?:session\.(?:destroy|invalidate|flush|clear|delete|remove|abandon)|session_destroy|session_unset|req\.session\.destroy|request\.session\.flush|logout\(|sign_out|SecurityContextHolder\.clearContext)`)
)

// GTSS-SESS-009: Predictable session ID generation
var (
	rePredictableSessionMD5  = regexp.MustCompile(`(?i)(?:session_id|session|sid|sessionId)\s*=\s*(?:md5|sha1|hashlib\.md5|hashlib\.sha1|MessageDigest\.getInstance\s*\(\s*["']MD5["']\)|DigestUtils\.md5Hex)\s*\(`)
	rePredictableSessionTime = regexp.MustCompile(`(?i)(?:session_id|session|sid|sessionId)\s*=\s*(?:str\s*\(\s*time\.|Date\.now|System\.currentTimeMillis|microtime|Time\.now)`)
	rePredictableSessionRand = regexp.MustCompile(`(?i)(?:session_id|session|sid|sessionId)\s*=\s*(?:str\s*\(\s*random\.randint|Math\.random|rand\(|Random\(\)\.nextInt)`)
	rePredictableSessionSeq  = regexp.MustCompile(`(?i)(?:session_id|session|sid|sessionId)\s*=\s*(?:str\s*\(\s*(?:counter|next_id|seq|auto_increment)|[a-zA-Z_]*(?:counter|seq|next)\s*\+\+)`)
)

// GTSS-SESS-010: Sensitive data stored in session cookie
var (
	reSensitiveCookieData = regexp.MustCompile(`(?i)(?:(?:Set-Cookie|cookie|setCookie|set_cookie)\s*[=:(]\s*[^;]*(?:password|passwd|secret|credit.?card|ssn|social.?security|bank.?account|cvv|pin)\s*[=:])`)
	reSessionStoreSensitive = regexp.MustCompile(`(?i)(?:session|req\.session|request\.session)\s*\[\s*["'](?:password|passwd|secret|credit_card|ssn|social_security|bank_account|cvv|pin)["']\s*\]\s*=`)
	reCookieValueSensitive  = regexp.MustCompile(`(?i)(?:response\.set_cookie|res\.cookie|setcookie)\s*\(\s*["'](?:password|passwd|secret|credit_card|ssn|cvv)["']`)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// hasNearbyPattern checks if a pattern appears within a range of lines around idx.
func hasNearbyPattern(lines []string, idx, before, after int, re *regexp.Regexp) bool {
	start := idx - before
	if start < 0 {
		start = 0
	}
	end := idx + after + 1
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GTSS-SESS-001: Session fixation - no regeneration after login
// ---------------------------------------------------------------------------

type SessionFixation struct{}

func (r *SessionFixation) ID() string                     { return "GTSS-SESS-001" }
func (r *SessionFixation) Name() string                   { return "SessionFixation" }
func (r *SessionFixation) DefaultSeverity() rules.Severity { return rules.High }
func (r *SessionFixation) Description() string {
	return "Detects login/authentication functions that do not regenerate the session ID, making them vulnerable to session fixation attacks."
}
func (r *SessionFixation) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *SessionFixation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	var loginRe *regexp.Regexp
	var regenRe *regexp.Regexp

	switch ctx.Language {
	case rules.LangPython:
		loginRe = reLoginNoRegenPy
		regenRe = reSessionRegenPy
	case rules.LangJava:
		loginRe = reLoginNoRegenJava
		regenRe = reSessionRegenJava
	case rules.LangPHP:
		loginRe = reLoginNoRegenPHP
		regenRe = reSessionRegenPHP
	case rules.LangRuby:
		loginRe = reLoginNoRegenRuby
		regenRe = reSessionRegenRuby
	case rules.LangJavaScript, rules.LangTypeScript:
		loginRe = reLoginNoRegenExpress
		regenRe = reSessionRegenJS
	default:
		return findings
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if loginRe.MatchString(line) {
			// Check the next 30 lines for session regeneration
			if !hasNearbyPattern(lines, i, 0, 30, regenRe) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Session fixation: no session regeneration after login",
					Description:   "The login/authentication function does not regenerate the session ID after successful authentication. An attacker can fixate a known session ID and wait for the victim to authenticate, then hijack the session.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Regenerate the session ID immediately after successful authentication. Use request.session.cycle_key() (Django), session_regenerate_id(true) (PHP), request.changeSessionId() (Java Servlet), or req.session.regenerate() (Express).",
					CWEID:         "CWE-384",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"session", "session-fixation", "authentication"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-002: Session cookie without HttpOnly flag
// ---------------------------------------------------------------------------

type SessionNoHttpOnly struct{}

func (r *SessionNoHttpOnly) ID() string                     { return "GTSS-SESS-002" }
func (r *SessionNoHttpOnly) Name() string                   { return "SessionNoHttpOnly" }
func (r *SessionNoHttpOnly) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SessionNoHttpOnly) Description() string {
	return "Detects session cookie configurations where HttpOnly flag is explicitly disabled, making cookies accessible to JavaScript and XSS attacks."
}
func (r *SessionNoHttpOnly) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *SessionNoHttpOnly) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reCookieHttpOnlyFalse, reSessionCookieNoHttp, rePHPIniNoHttpOnly} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Session cookie HttpOnly flag disabled",
					Description:   "Session cookie has HttpOnly set to false. This allows JavaScript to read the cookie via document.cookie, making session tokens vulnerable to theft via XSS attacks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Set HttpOnly=true for session cookies. This prevents JavaScript access to the cookie, mitigating XSS-based session theft.",
					CWEID:         "CWE-1004",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"session", "cookie", "httponly", "xss"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-003: Session cookie without Secure flag
// ---------------------------------------------------------------------------

type SessionNoSecure struct{}

func (r *SessionNoSecure) ID() string                     { return "GTSS-SESS-003" }
func (r *SessionNoSecure) Name() string                   { return "SessionNoSecure" }
func (r *SessionNoSecure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SessionNoSecure) Description() string {
	return "Detects session cookie configurations where the Secure flag is explicitly disabled, allowing cookies to be sent over unencrypted HTTP."
}
func (r *SessionNoSecure) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *SessionNoSecure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reCookieSecureFalse, reSessionCookieNoSecure, rePHPIniNoSecure} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Session cookie Secure flag disabled",
					Description:   "Session cookie has Secure flag set to false. This allows the cookie to be transmitted over unencrypted HTTP connections, exposing it to network-level sniffing attacks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Set Secure=true for session cookies. This ensures cookies are only sent over HTTPS connections.",
					CWEID:         "CWE-614",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"session", "cookie", "secure-flag", "transport"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-004: Session cookie without SameSite
// ---------------------------------------------------------------------------

type SessionNoSameSite struct{}

func (r *SessionNoSameSite) ID() string                     { return "GTSS-SESS-004" }
func (r *SessionNoSameSite) Name() string                   { return "SessionNoSameSite" }
func (r *SessionNoSameSite) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SessionNoSameSite) Description() string {
	return "Detects session cookie configurations with SameSite=None, which allows cookies to be sent in cross-site requests, enabling CSRF attacks."
}
func (r *SessionNoSameSite) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *SessionNoSameSite) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reCookieSameSiteNone, reSessionNoSameSite} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Session cookie SameSite=None",
					Description:   "Session cookie has SameSite set to None, which allows the cookie to be sent in all cross-site requests. This effectively disables CSRF protection provided by SameSite cookies.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Set SameSite=Lax (default, good balance) or SameSite=Strict (maximum protection). Only use None if cross-site cookie sending is explicitly required, and always pair it with Secure=true.",
					CWEID:         "CWE-1275",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"session", "cookie", "samesite", "csrf"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-005: Session data in localStorage/sessionStorage
// ---------------------------------------------------------------------------

type SessionInStorage struct{}

func (r *SessionInStorage) ID() string                     { return "GTSS-SESS-005" }
func (r *SessionInStorage) Name() string                   { return "SessionInStorage" }
func (r *SessionInStorage) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SessionInStorage) Description() string {
	return "Detects session identifiers stored in localStorage or sessionStorage, which are accessible to JavaScript and vulnerable to XSS-based theft."
}
func (r *SessionInStorage) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *SessionInStorage) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reLocalStorageSession, reSessionStorageSession, reLocalStorageDirect} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Session data stored in Web Storage",
					Description:   "Session identifier stored in localStorage/sessionStorage is accessible to any JavaScript on the page. An XSS vulnerability would allow an attacker to steal the session token.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use HttpOnly, Secure cookies for session management. Web Storage should not be used for sensitive session tokens.",
					CWEID:         "CWE-922",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"session", "localstorage", "sessionstorage", "xss"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-006: Session ID in URL/query parameter
// ---------------------------------------------------------------------------

type SessionInURL struct{}

func (r *SessionInURL) ID() string                     { return "GTSS-SESS-006" }
func (r *SessionInURL) Name() string                   { return "SessionInURL" }
func (r *SessionInURL) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SessionInURL) Description() string {
	return "Detects session IDs passed via URL query parameters, which exposes them in logs, browser history, and referrer headers."
}
func (r *SessionInURL) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *SessionInURL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reSessionInURL, reSessionURLParam, reSessionURLConcat} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Session ID in URL parameter",
					Description:   "Session ID passed via URL query parameter is exposed in server logs, browser history, Referer headers, and bookmarks. This makes session hijacking significantly easier.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use cookies for session management instead of URL parameters. Ensure session IDs are never included in URLs, links, or redirects.",
					CWEID:         "CWE-598",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"session", "url-parameter", "session-exposure"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-007: Excessive session timeout (>24h)
// ---------------------------------------------------------------------------

type SessionExcessiveTimeout struct{}

func (r *SessionExcessiveTimeout) ID() string                     { return "GTSS-SESS-007" }
func (r *SessionExcessiveTimeout) Name() string                   { return "SessionExcessiveTimeout" }
func (r *SessionExcessiveTimeout) DefaultSeverity() rules.Severity { return rules.Low }
func (r *SessionExcessiveTimeout) Description() string {
	return "Detects session timeout configurations exceeding 24 hours, which increases the window for session hijacking."
}
func (r *SessionExcessiveTimeout) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *SessionExcessiveTimeout) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// 86400 seconds = 24 hours; 86400000 milliseconds = 24 hours
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reSessionTimeoutLarge, reSessionMaxAge, rePHPSessionGC} {
			loc := re.FindStringSubmatch(line)
			if len(loc) < 2 {
				continue
			}
			// Parse the numeric value
			val := 0
			for _, c := range loc[1] {
				if c >= '0' && c <= '9' {
					val = val*10 + int(c-'0')
				}
			}
			if val == 0 {
				continue
			}
			// Determine if value exceeds 24h threshold
			// Heuristic: if > 86400000, likely milliseconds, compare to 86400000
			// If > 86400 and <= 86400000, likely seconds, compare to 86400
			isExcessive := false
			if val > 86400000 {
				// Milliseconds, exceeds 24h
				isExcessive = true
			} else if val > 86400 && val <= 86400000 {
				// Could be seconds (>24h) or ms (>86.4s)
				// Check context for clues
				if strings.Contains(strings.ToLower(line), "ms") || strings.Contains(strings.ToLower(line), "millis") || strings.Contains(strings.ToLower(line), "maxage") {
					// Likely milliseconds, >86400 ms = ~86 seconds, not excessive
					if val > 86400000 {
						isExcessive = true
					}
				} else {
					// Likely seconds, > 86400 = > 24h
					isExcessive = true
				}
			}
			if isExcessive {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Excessive session timeout (>24 hours)",
					Description:   "Session timeout exceeds 24 hours. Long-lived sessions increase the window during which a stolen session token can be used for unauthorized access.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Set session timeout to 15-30 minutes for sensitive applications. Use sliding sessions with absolute maximum lifetime of 8-24 hours. Implement re-authentication for sensitive operations.",
					CWEID:         "CWE-613",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"session", "timeout", "session-lifetime"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-008: Session not invalidated on logout
// ---------------------------------------------------------------------------

type SessionNoLogoutInvalidation struct{}

func (r *SessionNoLogoutInvalidation) ID() string                     { return "GTSS-SESS-008" }
func (r *SessionNoLogoutInvalidation) Name() string                   { return "SessionNoLogoutInvalidation" }
func (r *SessionNoLogoutInvalidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SessionNoLogoutInvalidation) Description() string {
	return "Detects logout functions that do not invalidate or destroy the session, allowing the session to remain valid after logout."
}
func (r *SessionNoLogoutInvalidation) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *SessionNoLogoutInvalidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	var logoutRe *regexp.Regexp
	switch ctx.Language {
	case rules.LangPython:
		logoutRe = reLogoutFuncPy
	case rules.LangJavaScript, rules.LangTypeScript:
		logoutRe = reLogoutFuncJS
	case rules.LangJava:
		logoutRe = reLogoutFuncJava
	case rules.LangPHP:
		logoutRe = reLogoutFuncPHP
	default:
		return findings
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if logoutRe.MatchString(line) {
			if !hasNearbyPattern(lines, i, 0, 20, reSessionDestroy) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Session not invalidated on logout",
					Description:   "The logout function does not appear to invalidate or destroy the session. The session token remains valid after logout, allowing continued access if the token was captured.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Destroy or invalidate the session on logout. Use session.destroy() (Express), request.session.flush() (Django), session.invalidate() (Java Servlet), or session_destroy() (PHP).",
					CWEID:         "CWE-613",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"session", "logout", "session-invalidation"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-009: Predictable session ID generation
// ---------------------------------------------------------------------------

type PredictableSessionID struct{}

func (r *PredictableSessionID) ID() string                     { return "GTSS-SESS-009" }
func (r *PredictableSessionID) Name() string                   { return "PredictableSessionID" }
func (r *PredictableSessionID) DefaultSeverity() rules.Severity { return rules.High }
func (r *PredictableSessionID) Description() string {
	return "Detects session IDs generated using predictable methods like MD5 of timestamps, sequential counters, or weak random number generators."
}
func (r *PredictableSessionID) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *PredictableSessionID) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{rePredictableSessionMD5, rePredictableSessionTime, rePredictableSessionRand, rePredictableSessionSeq} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Predictable session ID generation",
					Description:   "Session ID is generated using a predictable method (timestamp, sequential counter, weak hash, or non-cryptographic random). An attacker can predict or brute-force valid session IDs.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use cryptographically secure random session ID generators: secrets.token_hex() (Python), crypto.randomBytes() (Node.js), SecureRandom (Java/Ruby). Use your framework's built-in session management.",
					CWEID:         "CWE-330",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"session", "predictable", "random", "session-id"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SESS-010: Sensitive data stored in session cookie
// ---------------------------------------------------------------------------

type SensitiveSessionData struct{}

func (r *SensitiveSessionData) ID() string                     { return "GTSS-SESS-010" }
func (r *SensitiveSessionData) Name() string                   { return "SensitiveSessionData" }
func (r *SensitiveSessionData) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SensitiveSessionData) Description() string {
	return "Detects sensitive data (passwords, credit card numbers, SSN) stored in session cookies or session storage, which may be exposed in transit or at rest."
}
func (r *SensitiveSessionData) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *SensitiveSessionData) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reSensitiveCookieData, reSessionStoreSensitive, reCookieValueSensitive} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Sensitive data in session/cookie",
					Description:   "Sensitive data (passwords, financial data, PII) is stored in a session cookie or session object. This data may be exposed via network interception, XSS, or session storage compromise.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Never store passwords, credit card numbers, SSN, or other sensitive data in sessions or cookies. Store only a session identifier and look up sensitive data server-side from a secure database.",
					CWEID:         "CWE-315",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"session", "sensitive-data", "cookie", "pii"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&SessionFixation{})
	rules.Register(&SessionNoHttpOnly{})
	rules.Register(&SessionNoSecure{})
	rules.Register(&SessionNoSameSite{})
	rules.Register(&SessionInStorage{})
	rules.Register(&SessionInURL{})
	rules.Register(&SessionExcessiveTimeout{})
	rules.Register(&SessionNoLogoutInvalidation{})
	rules.Register(&PredictableSessionID{})
	rules.Register(&SensitiveSessionData{})
}
