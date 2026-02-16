package oauth

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-OAUTH-001: OAuth state parameter missing (CSRF)
var (
	reOAuthAuthURL        = regexp.MustCompile(`(?i)(?:authorize_url|authorization_url|auth_url|authorizationEndpoint|authorize_endpoint|/authorize\?|/oauth/authorize)`)
	reOAuthStateParam     = regexp.MustCompile(`(?i)(?:state\s*[=:&]|[&?]state=|\bstate\b\s*[:=]\s*[^,\s])`)
	reOAuthNoState        = regexp.MustCompile(`(?i)(?:authorize_url|authorization_url|auth_url|/authorize\?)[^;]*(?:\?|&)(?:client_id|response_type|redirect_uri)`)
	reOAuthStateVerify    = regexp.MustCompile(`(?i)(?:verify_state|validate_state|check_state|state\s*(?:===?|!==?|==|!=)\s*(?:session|stored|expected|saved)|session\s*\[\s*["']state["']\s*\])`)
)

// BATOU-OAUTH-002: OAuth implicit grant flow (deprecated)
var (
	reOAuthImplicitGrant = regexp.MustCompile(`(?i)(?:response_type\s*[=:]\s*["']token["']|response_type=token(?:&|$|["']))`)
	reOAuthImplicitFlow  = regexp.MustCompile(`(?i)(?:grant_type\s*[=:]\s*["']implicit["']|implicit\s*(?:grant|flow)|ImplicitGrant)`)
)

// BATOU-OAUTH-003: OAuth redirect_uri not validated
var (
	reOAuthRedirectOpen     = regexp.MustCompile(`(?i)(?:redirect_uri|callback_url|return_url)\s*[=:]\s*(?:req\.|request\.|params|input|\$_GET|\$_POST|args)`)
	reOAuthRedirectConcat   = regexp.MustCompile(`(?i)(?:redirect_uri|callback_url|return_url)\s*[=:]\s*["'][^"']*["']\s*\+`)
	reOAuthRedirectValidate = regexp.MustCompile(`(?i)(?:validate_redirect|verify_redirect|allowed_redirect|whitelisted_redirect|redirect_whitelist|redirect_allowlist|isValidRedirect|is_valid_redirect)`)
)

// BATOU-OAUTH-004: OAuth token in URL fragment
var (
	reOAuthTokenFragment = regexp.MustCompile(`(?i)(?:window\.location\.hash|location\.hash|fragment|#access_token|#token)`)
	reOAuthTokenFromHash = regexp.MustCompile(`(?i)(?:location\.hash\.(?:split|match|substring|replace|slice)|URLSearchParams\s*\(\s*(?:window\.)?location\.hash)`)
)

// BATOU-OAUTH-005: PKCE not used
var (
	reOAuthCodeGrant     = regexp.MustCompile(`(?i)(?:response_type\s*[=:]\s*["']code["']|grant_type\s*[=:]\s*["']authorization_code["']|AuthorizationCode)`)
	reOAuthPKCE          = regexp.MustCompile(`(?i)(?:code_challenge|code_verifier|PKCE|S256|pkce|proof.?key)`)
)

// BATOU-OAUTH-006: OAuth client secret exposed in frontend
var (
	reOAuthClientSecretFE = regexp.MustCompile(`(?i)(?:client_secret|clientSecret|CLIENT_SECRET)\s*[=:]\s*["'][^"']{5,}["']`)
	reFrontendContext     = regexp.MustCompile(`(?i)(?:document\.|window\.|localStorage|sessionStorage|fetch\s*\(|XMLHttpRequest|axios\.|React\.|angular\.|Vue\.|\.tsx?$|\.jsx?$|\.component\.)`)
)

// BATOU-OAUTH-007: OAuth scope not validated server-side
var (
	reOAuthScopeFromUser = regexp.MustCompile(`(?i)(?:scope|scopes)\s*[=:]\s*(?:req\.|request\.|params|input|\$_GET|\$_POST|args)`)
	reOAuthScopeConcat   = regexp.MustCompile(`(?i)(?:scope|scopes)\s*[=:]\s*[^;]*(?:\+\s*(?:req\.|request\.|params|input)|\.join\s*\()`)
	reOAuthScopeValidate = regexp.MustCompile(`(?i)(?:validate_scope|verify_scope|allowed_scopes|valid_scopes|scope_whitelist|scope_allowlist|isValidScope|is_valid_scope)`)
)

// BATOU-OAUTH-008: OAuth token stored in localStorage
var (
	reOAuthTokenLocalStorage = regexp.MustCompile(`(?i)localStorage\.setItem\s*\(\s*["'](?:oauth_token|access_token|refresh_token|auth_token|oauth2_token|oidc_token)["']`)
	reOAuthTokenLSDirect     = regexp.MustCompile(`(?i)localStorage\s*\[\s*["'](?:oauth_token|access_token|refresh_token|auth_token)["']\s*\]\s*=`)
)

// BATOU-OAUTH-009: OpenID Connect nonce not validated
var (
	reOIDCAuthRequest   = regexp.MustCompile(`(?i)(?:openid|id_token|response_type\s*[=:]\s*["'][^"']*id_token)`)
	reOIDCNonce         = regexp.MustCompile(`(?i)(?:nonce\s*[=:&]|[&?]nonce=|\bnonce\b\s*[:=]\s*[^,\s])`)
	reOIDCNonceVerify   = regexp.MustCompile(`(?i)(?:verify_nonce|validate_nonce|check_nonce|nonce\s*(?:===?|!==?|==|!=)\s*(?:session|stored|expected|saved)|claims\s*\[\s*["']nonce["']\s*\])`)
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

// fileContains checks if the pattern appears anywhere in the file.
func fileContains(content string, re *regexp.Regexp) bool {
	return re.MatchString(content)
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-001: OAuth state parameter missing (CSRF)
// ---------------------------------------------------------------------------

type OAuthNoState struct{}

func (r *OAuthNoState) ID() string                     { return "BATOU-OAUTH-001" }
func (r *OAuthNoState) Name() string                   { return "OAuthNoState" }
func (r *OAuthNoState) DefaultSeverity() rules.Severity { return rules.High }
func (r *OAuthNoState) Description() string {
	return "Detects OAuth authorization requests missing the state parameter, making the flow vulnerable to CSRF attacks."
}
func (r *OAuthNoState) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OAuthNoState) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reOAuthNoState.FindString(line); m != "" {
			// Check if state parameter is included
			if reOAuthStateParam.MatchString(line) {
				continue
			}
			if hasNearbyPattern(lines, i, 5, 5, reOAuthStateParam) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "OAuth authorization request missing state parameter",
				Description:   "The OAuth authorization URL is constructed without a state parameter. Without state, the OAuth callback is vulnerable to CSRF: an attacker can initiate an OAuth flow and trick the victim into completing it, linking the attacker's account.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Generate a cryptographically random state parameter, store it in the session, include it in the authorization URL, and verify it in the callback. Most OAuth libraries handle this automatically.",
				CWEID:         "CWE-352",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"oauth", "csrf", "state-parameter"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-002: OAuth implicit grant flow (deprecated)
// ---------------------------------------------------------------------------

type OAuthImplicitGrant struct{}

func (r *OAuthImplicitGrant) ID() string                     { return "BATOU-OAUTH-002" }
func (r *OAuthImplicitGrant) Name() string                   { return "OAuthImplicitGrant" }
func (r *OAuthImplicitGrant) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *OAuthImplicitGrant) Description() string {
	return "Detects use of the OAuth 2.0 implicit grant flow (response_type=token), which is deprecated due to token exposure in URL fragments and browser history."
}
func (r *OAuthImplicitGrant) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OAuthImplicitGrant) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reOAuthImplicitGrant, reOAuthImplicitFlow} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OAuth implicit grant flow (deprecated)",
					Description:   "The OAuth 2.0 implicit grant (response_type=token) is deprecated per OAuth 2.0 Security Best Current Practice. Tokens are exposed in URL fragments, browser history, and referrer headers. The implicit flow has no mechanism for token binding or refresh.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use the Authorization Code flow with PKCE instead. For SPAs, use response_type=code with a code_challenge. This provides token binding and avoids exposing tokens in the URL.",
					CWEID:         "CWE-287",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"oauth", "implicit-grant", "deprecated"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-003: OAuth redirect_uri not validated
// ---------------------------------------------------------------------------

type OAuthOpenRedirect struct{}

func (r *OAuthOpenRedirect) ID() string                     { return "BATOU-OAUTH-003" }
func (r *OAuthOpenRedirect) Name() string                   { return "OAuthOpenRedirect" }
func (r *OAuthOpenRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *OAuthOpenRedirect) Description() string {
	return "Detects OAuth redirect_uri constructed from user input without validation, enabling authorization code/token theft via open redirect."
}
func (r *OAuthOpenRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OAuthOpenRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reOAuthRedirectOpen, reOAuthRedirectConcat} {
			if m := re.FindString(line); m != "" {
				if hasNearbyPattern(lines, i, 10, 10, reOAuthRedirectValidate) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OAuth redirect_uri from user input (open redirect)",
					Description:   "The OAuth redirect_uri is constructed from user-controlled input without validation. An attacker can manipulate the redirect_uri to steal authorization codes or tokens by redirecting to their own server.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use a fixed, pre-registered redirect_uri. If dynamic redirects are needed, validate against a strict allowlist of exact URI matches. Never construct redirect_uri from user input.",
					CWEID:         "CWE-601",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"oauth", "redirect-uri", "open-redirect", "token-theft"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-004: OAuth token in URL fragment
// ---------------------------------------------------------------------------

type OAuthTokenFragment struct{}

func (r *OAuthTokenFragment) ID() string                     { return "BATOU-OAUTH-004" }
func (r *OAuthTokenFragment) Name() string                   { return "OAuthTokenFragment" }
func (r *OAuthTokenFragment) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *OAuthTokenFragment) Description() string {
	return "Detects code that extracts OAuth tokens from URL fragments (hash), indicating use of the insecure implicit flow or improper token handling."
}
func (r *OAuthTokenFragment) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OAuthTokenFragment) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reOAuthTokenFragment, reOAuthTokenFromHash} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OAuth token extracted from URL fragment",
					Description:   "OAuth token is being extracted from the URL fragment (hash). This indicates use of the implicit flow where tokens are exposed in the URL. URL fragments can leak via browser history, referrer headers, and JavaScript access.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Migrate to the Authorization Code flow with PKCE. Tokens should be exchanged via back-channel HTTP requests, not exposed in URL fragments.",
					CWEID:         "CWE-598",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"oauth", "token-exposure", "url-fragment"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-005: PKCE not used
// ---------------------------------------------------------------------------

type OAuthNoPKCE struct{}

func (r *OAuthNoPKCE) ID() string                     { return "BATOU-OAUTH-005" }
func (r *OAuthNoPKCE) Name() string                   { return "OAuthNoPKCE" }
func (r *OAuthNoPKCE) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *OAuthNoPKCE) Description() string {
	return "Detects OAuth authorization code flow without PKCE (Proof Key for Code Exchange), which is required for public clients and recommended for all clients."
}
func (r *OAuthNoPKCE) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OAuthNoPKCE) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reOAuthCodeGrant.FindString(line); m != "" {
			// Check if PKCE is used in the file
			if fileContains(ctx.Content, reOAuthPKCE) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "OAuth authorization code flow without PKCE",
				Description:   "OAuth authorization code flow is used without PKCE (Proof Key for Code Exchange). Without PKCE, authorization codes are vulnerable to interception attacks, especially for public clients (SPAs, mobile apps).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Add PKCE to the OAuth flow: generate a random code_verifier, derive code_challenge=SHA256(code_verifier), include code_challenge in the authorization request, and send code_verifier in the token exchange.",
				CWEID:         "CWE-287",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"oauth", "pkce", "authorization-code"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-006: OAuth client secret exposed in frontend
// ---------------------------------------------------------------------------

type OAuthClientSecretFE struct{}

func (r *OAuthClientSecretFE) ID() string                     { return "BATOU-OAUTH-006" }
func (r *OAuthClientSecretFE) Name() string                   { return "OAuthClientSecretFE" }
func (r *OAuthClientSecretFE) DefaultSeverity() rules.Severity { return rules.High }
func (r *OAuthClientSecretFE) Description() string {
	return "Detects OAuth client_secret hardcoded in frontend JavaScript/TypeScript code, where it is exposed to all users."
}
func (r *OAuthClientSecretFE) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *OAuthClientSecretFE) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reOAuthClientSecretFE.FindString(line); m != "" {
			// Check if this looks like frontend code
			if fileContains(ctx.Content, reFrontendContext) || strings.HasSuffix(ctx.FilePath, ".jsx") || strings.HasSuffix(ctx.FilePath, ".tsx") || strings.Contains(ctx.FilePath, "public/") || strings.Contains(ctx.FilePath, "static/") || strings.Contains(ctx.FilePath, "src/") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OAuth client_secret in frontend code",
					Description:   "OAuth client_secret is hardcoded in JavaScript/TypeScript code that appears to be frontend (browser) code. The client secret is visible to anyone who views the page source, allowing them to impersonate the application.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Never include client_secret in frontend code. Use the Authorization Code flow with PKCE (which does not require a client secret for public clients). Handle token exchange on the server side.",
					CWEID:         "CWE-798",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"oauth", "client-secret", "frontend-exposure"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-007: OAuth scope not validated server-side
// ---------------------------------------------------------------------------

type OAuthScopeNotValidated struct{}

func (r *OAuthScopeNotValidated) ID() string                     { return "BATOU-OAUTH-007" }
func (r *OAuthScopeNotValidated) Name() string                   { return "OAuthScopeNotValidated" }
func (r *OAuthScopeNotValidated) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *OAuthScopeNotValidated) Description() string {
	return "Detects OAuth scope values taken directly from user input without server-side validation, allowing scope escalation."
}
func (r *OAuthScopeNotValidated) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OAuthScopeNotValidated) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reOAuthScopeFromUser, reOAuthScopeConcat} {
			if m := re.FindString(line); m != "" {
				if hasNearbyPattern(lines, i, 10, 10, reOAuthScopeValidate) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OAuth scope from user input without validation",
					Description:   "OAuth scope is taken directly from user input without server-side validation. An attacker can request elevated scopes (e.g., admin, write) that the application did not intend to grant.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Validate requested scopes against a server-side allowlist. Only grant scopes that the client is authorized to request. Ignore or reject unknown/unauthorized scopes.",
					CWEID:         "CWE-863",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"oauth", "scope", "privilege-escalation"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-008: OAuth token stored in localStorage
// ---------------------------------------------------------------------------

type OAuthTokenLocalStorage struct{}

func (r *OAuthTokenLocalStorage) ID() string                     { return "BATOU-OAUTH-008" }
func (r *OAuthTokenLocalStorage) Name() string                   { return "OAuthTokenLocalStorage" }
func (r *OAuthTokenLocalStorage) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *OAuthTokenLocalStorage) Description() string {
	return "Detects OAuth tokens stored in localStorage, which is accessible to any JavaScript on the page including XSS payloads."
}
func (r *OAuthTokenLocalStorage) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *OAuthTokenLocalStorage) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reOAuthTokenLocalStorage, reOAuthTokenLSDirect} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OAuth token stored in localStorage",
					Description:   "OAuth token is stored in localStorage, which is accessible to any JavaScript on the page. A single XSS vulnerability allows an attacker to steal the OAuth token and access protected resources.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Store OAuth tokens in HttpOnly, Secure, SameSite cookies. Use the Backend-for-Frontend (BFF) pattern where the server handles token storage and the frontend only receives a session cookie.",
					CWEID:         "CWE-922",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"oauth", "localstorage", "token-storage", "xss"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-OAUTH-009: OpenID Connect nonce not validated
// ---------------------------------------------------------------------------

type OIDCNoNonce struct{}

func (r *OIDCNoNonce) ID() string                     { return "BATOU-OAUTH-009" }
func (r *OIDCNoNonce) Name() string                   { return "OIDCNoNonce" }
func (r *OIDCNoNonce) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *OIDCNoNonce) Description() string {
	return "Detects OpenID Connect flows that do not include or validate the nonce parameter, making them vulnerable to token replay attacks."
}
func (r *OIDCNoNonce) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *OIDCNoNonce) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reOIDCAuthRequest.FindString(line); m != "" {
			// Check if nonce is included in the request
			if fileContains(ctx.Content, reOIDCNonce) {
				// Also check if nonce is verified
				if fileContains(ctx.Content, reOIDCNonceVerify) {
					continue
				}
				// Nonce present but not verified
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OpenID Connect nonce not verified",
					Description:   "OpenID Connect flow includes a nonce but does not appear to verify it in the ID token response. Without nonce verification, the flow is vulnerable to token replay attacks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Verify the nonce claim in the ID token matches the nonce sent in the authorization request. Store the nonce in the session and compare after receiving the ID token.",
					CWEID:         "CWE-330",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"oauth", "oidc", "nonce", "replay-attack"},
				})
			} else {
				// No nonce at all
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "OpenID Connect flow missing nonce parameter",
					Description:   "OpenID Connect authorization request does not include a nonce parameter. The nonce binds the ID token to the client session, preventing token replay attacks and CSRF.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Generate a cryptographically random nonce, include it in the authorization request, store it in the session, and verify it in the ID token response.",
					CWEID:         "CWE-330",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"oauth", "oidc", "nonce", "replay-attack"},
				})
			}
			// Only flag once per file for OIDC nonce issues
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&OAuthNoState{})
	rules.Register(&OAuthImplicitGrant{})
	rules.Register(&OAuthOpenRedirect{})
	rules.Register(&OAuthTokenFragment{})
	rules.Register(&OAuthNoPKCE{})
	rules.Register(&OAuthClientSecretFE{})
	rules.Register(&OAuthScopeNotValidated{})
	rules.Register(&OAuthTokenLocalStorage{})
	rules.Register(&OIDCNoNonce{})
}
