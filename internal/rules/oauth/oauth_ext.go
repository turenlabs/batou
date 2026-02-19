package oauth

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- OAuth extensions
// ---------------------------------------------------------------------------

// BATOU-OAUTH-010: OAuth token in query string
var (
	reOAuthTokenQueryString = regexp.MustCompile(`(?i)[\?&]access_token=`)
	reOAuthTokenInURL       = regexp.MustCompile(`(?i)(?:url|href|endpoint|uri|redirect)\s*[=:+]\s*[^;]*[\?&]access_token=`)
	reOAuthTokenURLBuild    = regexp.MustCompile(`(?i)access_token=\s*["']?\s*\+\s*|access_token=\s*\$\{|access_token=\s*%s|access_token=["']\s*\.\s*|access_token=\s*\{\{`)
	reOAuthTokenHeader      = regexp.MustCompile(`(?i)(?:Authorization|Bearer)\s*[:=]|\.setRequestHeader\s*\(\s*['"]Authorization|headers\s*\[?\s*['"]Authorization`)
)

// BATOU-OAUTH-011: OAuth refresh token exposed client-side or logged
var (
	reRefreshTokenClientStore = regexp.MustCompile(`(?i)(?:localStorage|sessionStorage)\s*\.\s*(?:setItem\s*\(\s*['"][^'"]*refresh_token|getItem\s*\(\s*['"][^'"]*refresh_token)`)
	reRefreshTokenClientSet   = regexp.MustCompile(`(?i)(?:localStorage|sessionStorage)\s*\[\s*['"][^'"]*refresh_token['"]?\s*\]\s*=`)
	reRefreshTokenLogged      = regexp.MustCompile(`(?i)console\s*\.\s*(?:log|info|warn|debug|error)\s*\([^)]*refresh_token`)
	reRefreshTokenCookie      = regexp.MustCompile(`(?i)(?:document\.cookie|Cookie)\s*[=:]\s*[^;]*refresh_token`)
)

func init() {
	rules.Register(&OAuthTokenQueryString{})
	rules.Register(&OAuthRefreshTokenExposed{})
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-010: OAuth access token in query string
// ---------------------------------------------------------------------------

type OAuthTokenQueryString struct{}

func (r *OAuthTokenQueryString) ID() string                      { return "BATOU-OAUTH-010" }
func (r *OAuthTokenQueryString) Name() string                    { return "OAuthTokenQueryString" }
func (r *OAuthTokenQueryString) DefaultSeverity() rules.Severity { return rules.High }
func (r *OAuthTokenQueryString) Description() string {
	return "Detects OAuth access tokens passed in URL query parameters, where they are exposed in server logs, browser history, and referrer headers."
}
func (r *OAuthTokenQueryString) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OAuthTokenQueryString) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// If the file uses Authorization header for tokens, skip
	if fileContains(ctx.Content, reOAuthTokenHeader) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		confidence := "high"

		if m := reOAuthTokenInURL.FindString(line); m != "" {
			matched = m
		} else if m := reOAuthTokenURLBuild.FindString(line); m != "" {
			matched = m
		} else if m := reOAuthTokenQueryString.FindString(line); m != "" {
			// Lower confidence for bare ?access_token= without URL context
			lower := strings.ToLower(line)
			if strings.Contains(lower, "url") || strings.Contains(lower, "href") ||
				strings.Contains(lower, "fetch") || strings.Contains(lower, "redirect") ||
				strings.Contains(lower, "http") || strings.Contains(lower, "request") {
				matched = m
			} else {
				matched = m
				confidence = "medium"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "OAuth access token passed in URL query string",
				Description:   "The OAuth access_token is included as a URL query parameter (?access_token=...). Query parameters are recorded in server access logs, proxy logs, browser history, and the HTTP Referer header, creating multiple vectors for token theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Send the access token in the Authorization header instead: Authorization: Bearer <token>. This is the recommended method per RFC 6750 and keeps tokens out of URLs.",
				CWEID:         "CWE-598",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"oauth", "token-exposure", "query-string"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-011: OAuth refresh token exposed client-side or logged
// ---------------------------------------------------------------------------

type OAuthRefreshTokenExposed struct{}

func (r *OAuthRefreshTokenExposed) ID() string                      { return "BATOU-OAUTH-011" }
func (r *OAuthRefreshTokenExposed) Name() string                    { return "OAuthRefreshTokenExposed" }
func (r *OAuthRefreshTokenExposed) DefaultSeverity() rules.Severity { return rules.High }
func (r *OAuthRefreshTokenExposed) Description() string {
	return "Detects OAuth refresh tokens stored in client-side storage (localStorage/sessionStorage), logged to console, or placed in cookies without HttpOnly flag."
}
func (r *OAuthRefreshTokenExposed) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OAuthRefreshTokenExposed) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var detail string

		if m := reRefreshTokenClientStore.FindString(line); m != "" {
			matched = m
			detail = "Refresh token stored in localStorage/sessionStorage. Any JavaScript running on the page (including XSS payloads) can read it. Refresh tokens grant long-lived access and should never be client-side accessible."
		} else if m := reRefreshTokenClientSet.FindString(line); m != "" {
			matched = m
			detail = "Refresh token stored in localStorage/sessionStorage via bracket notation. This exposes the long-lived token to JavaScript-based attacks."
		} else if m := reRefreshTokenLogged.FindString(line); m != "" {
			matched = m
			detail = "Refresh token logged to console. Console output may be captured by browser extensions, monitoring tools, or shared debug sessions, exposing the token."
		} else if m := reRefreshTokenCookie.FindString(line); m != "" {
			matched = m
			detail = "Refresh token set in a cookie via document.cookie or without HttpOnly flag. Client-accessible cookies are vulnerable to XSS-based theft."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "OAuth refresh token exposed client-side or logged",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Store refresh tokens server-side only (in the database or an encrypted HttpOnly cookie). Use the Backend-for-Frontend (BFF) pattern where the server manages token refresh and the client only receives a session cookie.",
				CWEID:         "CWE-522",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"oauth", "refresh-token", "client-exposure"},
			})
		}
	}
	return findings
}
