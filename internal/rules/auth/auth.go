package auth

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// --- Compiled patterns ---

// GTSS-AUTH-001: Hardcoded credential patterns
var (
	// Equality checks against string literals in auth contexts
	reHardcodedPasswordGo = regexp.MustCompile(`(?i)(?:password|passwd|pass|pwd|secret|token)\s*(?:==|!=)\s*"[^"]{1,}"`)
	reHardcodedPasswordPy = regexp.MustCompile(`(?i)(?:password|passwd|pass|pwd|secret|token)\s*(?:==|!=)\s*(?:"[^"]{1,}"|'[^']{1,}')`)
	reHardcodedPasswordJS = regexp.MustCompile(`(?i)(?:password|passwd|pass|pwd|secret|token)\s*(?:===?|!==?)\s*(?:"[^"]{1,}"|'[^']{1,}'|` + "`[^`]{1,}`" + `)`)
	reHardcodedUserCheck  = regexp.MustCompile(`(?i)(?:user(?:name)?|login|admin)\s*(?:===?|==)\s*(?:"[^"]{1,}"|'[^']{1,}')`)
	reHardcodedCredPHP    = regexp.MustCompile(`(?i)\$(?:password|passwd|pass|pwd|secret|token)\s*(?:==|===|!=|!==)\s*(?:"[^"]{1,}"|'[^']{1,}')`)
)

// JWT "none" algorithm allowed in verify options (used by GTSS-AUTH-001)
var reJWTNoneAlgorithm = regexp.MustCompile(`(?i)algorithms?\s*:\s*\[.*['"]none['"]`)

// GTSS-AUTH-002: Missing auth check patterns
var (
	reGoHandleFunc       = regexp.MustCompile(`http\.HandleFunc\s*\(`)
	reGoMuxHandle        = regexp.MustCompile(`\.Handle(?:Func)?\s*\(`)
	reExpressRoute       = regexp.MustCompile(`(?:app|router)\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['"]\/(?:admin|dashboard|manage|internal|settings)`)
	reDjangoView         = regexp.MustCompile(`^\s*def\s+\w+\(.*request`)
	reDjangoLoginReq     = regexp.MustCompile(`@login_required`)
	reDjangoPermRequired = regexp.MustCompile(`@permission_required`)
	reExpressAuthMW      = regexp.MustCompile(`(?:auth|authenticate|isAuthenticated|requireAuth|verifyToken|passport\.authenticate)\s*(?:\(|,)`)
)

// GTSS-AUTH-003: CORS wildcard patterns
var (
	reCORSAllowAll       = regexp.MustCompile(`(?i)(?:Access-Control-Allow-Origin|AllowOrigins?|origin)\s*["']?\s*[,:=]\s*["']?\*["']?`)
	reCORSAllowAllOrigin = regexp.MustCompile(`(?i)AllowAllOrigins\s*:\s*true`)
	reCORSCredentials    = regexp.MustCompile(`(?i)(?:Allow-Credentials|AllowCredentials|credentials)\s*[:=]\s*["']?true["']?`)
	reCORSWildcardJS     = regexp.MustCompile(`cors\s*\(\s*\{[^}]*origin\s*:\s*['"]?\*['"]?`)
	reCORSWildcardPy     = regexp.MustCompile(`(?i)CORS_ALLOW_ALL_ORIGINS\s*=\s*True`)
)

// GTSS-AUTH-004: Session fixation patterns
var (
	reLoginHandler       = regexp.MustCompile(`(?i)(?:def\s+login|func.*login|function\s+login|\.post\s*\(\s*['"]\/login)`)
	reSessionCyclePy     = regexp.MustCompile(`(?:session\.cycle_key|request\.session\.flush|request\.session\.create)`)
	reSessionRegenPHP    = regexp.MustCompile(`session_regenerate_id\s*\(`)
	reSessionRegenRuby   = regexp.MustCompile(`reset_session`)
	reSessionRegenExpress = regexp.MustCompile(`req\.session\.regenerate\s*\(`)
)

// GTSS-AUTH-005: Weak password policy patterns
var (
	reWeakPassLen    = regexp.MustCompile(`(?i)(?:len\s*\(\s*(?:password|passwd|pass|pwd)\s*\)|(?:password|passwd|pass|pwd)\.(?:length|len|size))\s*(?:>=?|>|<|<=)\s*([0-9]+)`)
	reWeakPassMinLen = regexp.MustCompile(`(?i)(?:min_?length|minLen|MIN_PASSWORD_LENGTH|PASSWORD_MIN)\s*[:=]\s*([0-9]+)`)
)

// GTSS-AUTH-006: Insecure cookie patterns
var (
	reGoCookieLiteral   = regexp.MustCompile(`http\.Cookie\s*\{`)
	reGoCookieSecure    = regexp.MustCompile(`Secure\s*:\s*true`)
	reGoCookieHTTPOnly  = regexp.MustCompile(`HttpOnly\s*:\s*true`)
	reJSSetCookie       = regexp.MustCompile(`\.cookie\s*\(`)
	reJSCookieSecure    = regexp.MustCompile(`secure\s*:\s*true`)
	reJSCookieHTTPOnly  = regexp.MustCompile(`httpOnly\s*:\s*true`)
	rePySetCookie       = regexp.MustCompile(`set_cookie\s*\(`)
	rePyCookieSecure    = regexp.MustCompile(`secure\s*=\s*True`)
	rePyCookieHTTPOnly  = regexp.MustCompile(`httponly\s*=\s*True`)
	rePHPSetCookie      = regexp.MustCompile(`setcookie\s*\(`)
)

// --- Rule 1: Hardcoded Credentials ---

type HardcodedCredentialCheck struct{}

func (r *HardcodedCredentialCheck) ID() string          { return "GTSS-AUTH-001" }
func (r *HardcodedCredentialCheck) Name() string         { return "HardcodedCredentialCheck" }
func (r *HardcodedCredentialCheck) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *HardcodedCredentialCheck) Description() string {
	return "Detects authentication checks comparing against hardcoded string values, which can be trivially bypassed."
}
func (r *HardcodedCredentialCheck) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangPHP, rules.LangRuby,
		rules.LangJava, rules.LangCSharp,
	}
}

func (r *HardcodedCredentialCheck) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		var matched string
		switch ctx.Language {
		case rules.LangGo, rules.LangJava, rules.LangCSharp:
			if m := reHardcodedPasswordGo.FindString(line); m != "" {
				matched = m
			} else if m := reHardcodedUserCheck.FindString(line); m != "" {
				matched = m
			}
		case rules.LangPython:
			if m := reHardcodedPasswordPy.FindString(line); m != "" {
				matched = m
			} else if m := reHardcodedUserCheck.FindString(line); m != "" {
				matched = m
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if m := reHardcodedPasswordJS.FindString(line); m != "" {
				matched = m
			} else if m := reHardcodedUserCheck.FindString(line); m != "" {
				matched = m
			}
		case rules.LangPHP:
			if m := reHardcodedCredPHP.FindString(line); m != "" {
				matched = m
			} else if m := reHardcodedUserCheck.FindString(line); m != "" {
				matched = m
			}
		default:
			if m := reHardcodedPasswordGo.FindString(line); m != "" {
				matched = m
			} else if m := reHardcodedUserCheck.FindString(line); m != "" {
				matched = m
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded credential in authentication check",
				Description:   "Authentication logic compares against a hardcoded string value. Credentials must be stored securely using hashing (e.g., bcrypt) and retrieved from a secure store.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use bcrypt/scrypt/argon2 to hash passwords and compare hashes. Store credentials in a secrets manager or environment variables.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "hardcoded", "credentials"},
			})
		}

		// JWT "none" algorithm: allowing the "none" algorithm lets attackers
		// forge tokens without a valid signature.
		if m := reJWTNoneAlgorithm.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "JWT 'none' algorithm allowed in token verification",
				Description:   "The JWT verification accepts the 'none' algorithm, which means tokens with no signature are considered valid. An attacker can forge arbitrary tokens by setting alg to 'none' and removing the signature.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   strings.TrimSpace(m),
				Suggestion:    "Remove 'none' from the allowed algorithms list. Only allow specific algorithms you intend to use (e.g., ['HS256'] or ['RS256']).",
				CWEID:         "CWE-345",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "jwt", "none-algorithm"},
			})
		}
	}
	return findings
}

// --- Rule 2: Missing Auth Check ---

type MissingAuthCheck struct{}

func (r *MissingAuthCheck) ID() string          { return "GTSS-AUTH-002" }
func (r *MissingAuthCheck) Name() string         { return "MissingAuthCheck" }
func (r *MissingAuthCheck) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingAuthCheck) Description() string {
	return "Detects HTTP handlers and routes that appear to lack authentication middleware, especially for sensitive endpoints."
}
func (r *MissingAuthCheck) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
	}
}

func (r *MissingAuthCheck) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	contentLower := strings.ToLower(ctx.Content)

	switch ctx.Language {
	case rules.LangGo:
		// Check for http.HandleFunc without any auth middleware reference in file
		hasAuthMiddleware := strings.Contains(contentLower, "authmiddleware") ||
			strings.Contains(contentLower, "requireauth") ||
			strings.Contains(contentLower, "authenticate") ||
			strings.Contains(contentLower, "authhandler")

		if !hasAuthMiddleware {
			for i, line := range lines {
				if reGoHandleFunc.MatchString(line) {
					lineLower := strings.ToLower(line)
					if strings.Contains(lineLower, "/admin") ||
						strings.Contains(lineLower, "/dashboard") || strings.Contains(lineLower, "/manage") ||
						strings.Contains(lineLower, "/settings") || strings.Contains(lineLower, "/internal") {
						findings = append(findings, r.makeFinding(ctx, i+1, strings.TrimSpace(line)))
					}
				}
			}
		}

	case rules.LangJavaScript, rules.LangTypeScript:
		hasAuthMiddleware := reExpressAuthMW.MatchString(ctx.Content)
		if !hasAuthMiddleware {
			for i, line := range lines {
				if reExpressRoute.MatchString(line) {
					findings = append(findings, r.makeFinding(ctx, i+1, strings.TrimSpace(line)))
				}
			}
		}

	case rules.LangPython:
		// Check for Django views without @login_required
		for i, line := range lines {
			if reDjangoView.MatchString(line) {
				lineLower := strings.ToLower(line)
				if strings.Contains(lineLower, "admin") || strings.Contains(lineLower, "dashboard") ||
					strings.Contains(lineLower, "manage") || strings.Contains(lineLower, "settings") {
					// Look back up to 5 lines for decorator
					hasDecorator := false
					start := i - 5
					if start < 0 {
						start = 0
					}
					for j := start; j < i; j++ {
						if reDjangoLoginReq.MatchString(lines[j]) || reDjangoPermRequired.MatchString(lines[j]) {
							hasDecorator = true
							break
						}
					}
					if !hasDecorator {
						findings = append(findings, r.makeFinding(ctx, i+1, strings.TrimSpace(line)))
					}
				}
			}
		}
	}

	return findings
}

func (r *MissingAuthCheck) makeFinding(ctx *rules.ScanContext, line int, matched string) rules.Finding {
	return rules.Finding{
		RuleID:        r.ID(),
		Severity:      r.DefaultSeverity(),
		SeverityLabel: r.DefaultSeverity().String(),
		Title:         "HTTP handler may lack authentication",
		Description:   "This route handler for a sensitive endpoint does not appear to use authentication middleware. Ensure all privileged endpoints require authentication.",
		FilePath:      ctx.FilePath,
		LineNumber:    line,
		MatchedText:   matched,
		Suggestion:    "Add authentication middleware to protect sensitive routes. Use established auth libraries for your framework.",
		CWEID:         "CWE-306",
		OWASPCategory: "A07:2021-Identification and Authentication Failures",
		Language:      ctx.Language,
		Confidence:    "low",
		Tags:          []string{"auth", "missing-auth", "access-control"},
	}
}

// --- Rule 3: CORS Wildcard ---

type CORSWildcard struct{}

func (r *CORSWildcard) ID() string          { return "GTSS-AUTH-003" }
func (r *CORSWildcard) Name() string         { return "CORSWildcard" }
func (r *CORSWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r *CORSWildcard) Description() string {
	return "Detects overly permissive CORS configuration using wildcard origins, especially combined with credentials."
}
func (r *CORSWildcard) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangJava, rules.LangPHP,
		rules.LangRuby,
	}
}

func (r *CORSWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	hasCredentials := reCORSCredentials.MatchString(ctx.Content)

	for i, line := range lines {
		var matched string
		if m := reCORSAllowAll.FindString(line); m != "" {
			matched = m
		} else if m := reCORSAllowAllOrigin.FindString(line); m != "" {
			matched = m
		} else if m := reCORSWildcardJS.FindString(line); m != "" {
			matched = m
		} else if m := reCORSWildcardPy.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			severity := r.DefaultSeverity()
			description := "CORS is configured to allow all origins. This permits any website to make cross-origin requests to your API."
			if hasCredentials {
				severity = rules.Critical
				description = "CORS allows all origins AND credentials. This is extremely dangerous as any website can make authenticated requests to your API, enabling full account takeover."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      severity,
				SeverityLabel: severity.String(),
				Title:         "Overly permissive CORS configuration",
				Description:   description,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Specify allowed origins explicitly instead of using wildcard. Never combine wildcard origin with credentials.",
				CWEID:         "CWE-942",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "cors", "misconfiguration"},
			})
		}
	}
	return findings
}

// --- Rule 4: Session Fixation ---

type SessionFixation struct{}

func (r *SessionFixation) ID() string          { return "GTSS-AUTH-004" }
func (r *SessionFixation) Name() string         { return "SessionFixation" }
func (r *SessionFixation) DefaultSeverity() rules.Severity { return rules.High }
func (r *SessionFixation) Description() string {
	return "Detects login handlers that do not regenerate the session ID after successful authentication, enabling session fixation attacks."
}
func (r *SessionFixation) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangPHP, rules.LangRuby,
		rules.LangJavaScript, rules.LangTypeScript,
	}
}

func (r *SessionFixation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if !reLoginHandler.MatchString(line) {
			continue
		}

		// Look ahead up to 40 lines for session regeneration
		end := i + 40
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		hasRegen := false
		switch ctx.Language {
		case rules.LangPython:
			hasRegen = reSessionCyclePy.MatchString(block)
		case rules.LangPHP:
			hasRegen = reSessionRegenPHP.MatchString(block)
		case rules.LangRuby:
			hasRegen = reSessionRegenRuby.MatchString(block)
		case rules.LangJavaScript, rules.LangTypeScript:
			hasRegen = reSessionRegenExpress.MatchString(block)
		}

		if !hasRegen {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Session not regenerated after login",
				Description:   "This login handler does not appear to regenerate the session ID after authentication. An attacker who sets a known session ID can hijack the authenticated session.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Regenerate the session ID immediately after successful authentication. Python: request.session.cycle_key(). PHP: session_regenerate_id(true). Express: req.session.regenerate().",
				CWEID:         "CWE-384",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"auth", "session", "fixation"},
			})
		}
	}
	return findings
}

// --- Rule 5: Weak Password Policy ---

type WeakPasswordPolicy struct{}

func (r *WeakPasswordPolicy) ID() string          { return "GTSS-AUTH-005" }
func (r *WeakPasswordPolicy) Name() string         { return "WeakPasswordPolicy" }
func (r *WeakPasswordPolicy) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *WeakPasswordPolicy) Description() string {
	return "Detects password validation with weak requirements such as minimum length below 8 characters or missing complexity checks."
}
func (r *WeakPasswordPolicy) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangJava, rules.LangPHP,
		rules.LangRuby, rules.LangCSharp,
	}
}

func (r *WeakPasswordPolicy) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		var matched string

		if m := reWeakPassLen.FindStringSubmatch(line); len(m) > 1 {
			val := parseSmallInt(m[1])
			if val > 0 && val < 8 {
				matched = strings.TrimSpace(line)
			}
		}
		if matched == "" {
			if m := reWeakPassMinLen.FindStringSubmatch(line); len(m) > 1 {
				val := parseSmallInt(m[1])
				if val > 0 && val < 8 {
					matched = strings.TrimSpace(line)
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Weak password length requirement",
				Description:   "Password validation allows passwords shorter than 8 characters. Short passwords are vulnerable to brute-force attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Require a minimum password length of at least 8 characters (NIST recommends 8+). Add complexity requirements or use a password strength estimator like zxcvbn.",
				CWEID:         "CWE-521",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "password", "policy"},
			})
		}
	}
	return findings
}

// parseSmallInt converts a short numeric string to int. Returns 0 on failure.
func parseSmallInt(s string) int {
	val := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		val = val*10 + int(c-'0')
	}
	return val
}

// --- Rule 6: Insecure Cookie ---

type InsecureCookie struct{}

func (r *InsecureCookie) ID() string          { return "GTSS-AUTH-006" }
func (r *InsecureCookie) Name() string         { return "InsecureCookie" }
func (r *InsecureCookie) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureCookie) Description() string {
	return "Detects cookies set without Secure, HttpOnly, or SameSite flags, which can expose session tokens to theft."
}
func (r *InsecureCookie) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangPHP,
	}
}

func (r *InsecureCookie) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	switch ctx.Language {
	case rules.LangGo:
		findings = r.scanGoCookies(ctx, lines)
	case rules.LangJavaScript, rules.LangTypeScript:
		findings = r.scanJSCookies(ctx, lines)
	case rules.LangPython:
		findings = r.scanPyCookies(ctx, lines)
	case rules.LangPHP:
		findings = r.scanPHPCookies(ctx, lines)
	}

	return findings
}

func (r *InsecureCookie) scanGoCookies(ctx *rules.ScanContext, lines []string) []rules.Finding {
	var findings []rules.Finding
	for i, line := range lines {
		if !reGoCookieLiteral.MatchString(line) {
			continue
		}
		// Look ahead up to 15 lines for closing brace to find the cookie struct
		end := i + 15
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		var missing []string
		if !reGoCookieSecure.MatchString(block) {
			missing = append(missing, "Secure")
		}
		if !reGoCookieHTTPOnly.MatchString(block) {
			missing = append(missing, "HttpOnly")
		}
		if len(missing) > 0 {
			findings = append(findings, r.makeFinding(ctx, i+1, strings.TrimSpace(line), missing))
		}
	}
	return findings
}

func (r *InsecureCookie) scanJSCookies(ctx *rules.ScanContext, lines []string) []rules.Finding {
	var findings []rules.Finding
	for i, line := range lines {
		if !reJSSetCookie.MatchString(line) {
			continue
		}
		end := i + 10
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		var missing []string
		if !reJSCookieSecure.MatchString(block) {
			missing = append(missing, "secure")
		}
		if !reJSCookieHTTPOnly.MatchString(block) {
			missing = append(missing, "httpOnly")
		}
		if len(missing) > 0 {
			findings = append(findings, r.makeFinding(ctx, i+1, strings.TrimSpace(line), missing))
		}
	}
	return findings
}

func (r *InsecureCookie) scanPyCookies(ctx *rules.ScanContext, lines []string) []rules.Finding {
	var findings []rules.Finding
	for i, line := range lines {
		if !rePySetCookie.MatchString(line) {
			continue
		}
		end := i + 10
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		var missing []string
		if !rePyCookieSecure.MatchString(block) {
			missing = append(missing, "secure")
		}
		if !rePyCookieHTTPOnly.MatchString(block) {
			missing = append(missing, "httponly")
		}
		if len(missing) > 0 {
			findings = append(findings, r.makeFinding(ctx, i+1, strings.TrimSpace(line), missing))
		}
	}
	return findings
}

func (r *InsecureCookie) scanPHPCookies(ctx *rules.ScanContext, lines []string) []rules.Finding {
	var findings []rules.Finding
	for i, line := range lines {
		if !rePHPSetCookie.MatchString(line) {
			continue
		}
		// PHP setcookie has positional args: setcookie(name, value, expire, path, domain, secure, httponly)
		// Check if the line/block has enough arguments with true for secure/httponly
		end := i + 5
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")
		trueCount := strings.Count(strings.ToLower(block), "true")
		if trueCount < 2 {
			findings = append(findings, r.makeFinding(ctx, i+1, strings.TrimSpace(line), []string{"secure", "httponly"}))
		}
	}
	return findings
}

func (r *InsecureCookie) makeFinding(ctx *rules.ScanContext, line int, matched string, missing []string) rules.Finding {
	return rules.Finding{
		RuleID:        r.ID(),
		Severity:      r.DefaultSeverity(),
		SeverityLabel: r.DefaultSeverity().String(),
		Title:         "Cookie set without security flags",
		Description:   "Cookie is missing security flags: " + strings.Join(missing, ", ") + ". Without these flags, cookies may be transmitted over insecure connections or accessed by client-side scripts.",
		FilePath:      ctx.FilePath,
		LineNumber:    line,
		MatchedText:   matched,
		Suggestion:    "Set Secure, HttpOnly, and SameSite flags on all cookies, especially session cookies.",
		CWEID:         "CWE-614",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      ctx.Language,
		Confidence:    "high",
		Tags:          []string{"auth", "cookie", "security-flags"},
	}
}

// GTSS-AUTH-007: Privilege escalation patterns (CWE-269)
var (
	// C: setuid(0) / setgid(0)
	reCSetuid0       = regexp.MustCompile(`\bsetuid\s*\(\s*0\s*\)`)
	reCSetgid0       = regexp.MustCompile(`\bsetgid\s*\(\s*0\s*\)`)
	// Python: os.setuid(0) / os.setgid(0)
	rePySetuid0      = regexp.MustCompile(`\bos\.setuid\s*\(\s*0\s*\)`)
	rePySetgid0      = regexp.MustCompile(`\bos\.setgid\s*\(\s*0\s*\)`)
	// Shell/Makefile: chmod 777, chmod a+rwx
	reChmod777       = regexp.MustCompile(`\bchmod\s+(?:777|a\+rwx)\b`)
	// Go: os.Chmod with 0777
	reGoChmod777     = regexp.MustCompile(`os\.Chmod\s*\([^,]+,\s*0o?777\s*\)`)
	// Dockerfile: USER root without later USER nonroot
	reDockerUserRoot = regexp.MustCompile(`(?i)^\s*USER\s+root\s*$`)
	reDockerUserNon  = regexp.MustCompile(`(?i)^\s*USER\s+\S+`)
)

// --- Rule 7: Privilege Escalation ---

type PrivilegeEscalation struct{}

func (r *PrivilegeEscalation) ID() string                     { return "GTSS-AUTH-007" }
func (r *PrivilegeEscalation) Name() string                   { return "PrivilegeEscalation" }
func (r *PrivilegeEscalation) DefaultSeverity() rules.Severity { return rules.High }
func (r *PrivilegeEscalation) Description() string {
	return "Detects privilege escalation patterns such as setuid(0), chmod 777, and Dockerfiles running as root."
}
func (r *PrivilegeEscalation) Languages() []rules.Language {
	return []rules.Language{
		rules.LangC, rules.LangCPP, rules.LangPython, rules.LangGo,
		rules.LangShell, rules.LangDocker, rules.LangAny,
	}
}

func (r *PrivilegeEscalation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		desc string
		sug  string
	}

	// Language-specific patterns
	var langPatterns []pattern

	switch ctx.Language {
	case rules.LangC, rules.LangCPP:
		langPatterns = []pattern{
			{reCSetuid0, "setuid(0) escalates to root privileges", "Avoid running as root. Use capabilities (CAP_NET_BIND_SERVICE, etc.) or drop privileges after initialization."},
			{reCSetgid0, "setgid(0) escalates group to root", "Avoid running with root group. Use specific group IDs."},
		}
	case rules.LangPython:
		langPatterns = []pattern{
			{rePySetuid0, "os.setuid(0) escalates to root privileges", "Avoid running as root. Use specific user IDs and capabilities."},
			{rePySetgid0, "os.setgid(0) escalates group to root", "Avoid running with root group."},
		}
	case rules.LangGo:
		langPatterns = []pattern{
			{reGoChmod777, "os.Chmod with 0777 grants world-writable permissions", "Use restrictive permissions: 0644 for files, 0755 for directories."},
		}
	}

	// Universal patterns (shell, Makefile, any)
	universalPatterns := []pattern{
		{reChmod777, "chmod 777/a+rwx grants world-writable permissions", "Use restrictive permissions: chmod 644 for files, chmod 755 for directories."},
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		for _, p := range langPatterns {
			if m := p.re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Privilege escalation: " + p.desc,
					Description:   "Code escalates privileges or sets overly permissive access controls, which can be exploited for unauthorized access.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   m,
					Suggestion:    p.sug,
					CWEID:         "CWE-269",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"auth", "privilege-escalation", "permissions"},
				})
				break
			}
		}

		for _, p := range universalPatterns {
			if m := p.re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Privilege escalation: " + p.desc,
					Description:   "Overly permissive file permissions allow any user on the system to read, write, and execute the file.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   m,
					Suggestion:    p.sug,
					CWEID:         "CWE-269",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"auth", "privilege-escalation", "permissions"},
				})
				break
			}
		}
	}

	// Dockerfile-specific: USER root without later USER nonroot
	if ctx.Language == rules.LangDocker {
		lastUserRootLine := -1
		hasNonRootAfter := false
		for i, line := range lines {
			if reDockerUserRoot.MatchString(line) {
				lastUserRootLine = i
				hasNonRootAfter = false
			} else if reDockerUserNon.MatchString(line) && !reDockerUserRoot.MatchString(line) && lastUserRootLine >= 0 {
				hasNonRootAfter = true
			}
		}
		if lastUserRootLine >= 0 && !hasNonRootAfter {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Privilege escalation: Dockerfile runs as root",
				Description:   "Dockerfile sets USER root without switching to a non-root user. Containers running as root have full host privileges if they escape the container.",
				FilePath:      ctx.FilePath,
				LineNumber:    lastUserRootLine + 1,
				MatchedText:   strings.TrimSpace(lines[lastUserRootLine]),
				Suggestion:    "Add 'USER nonroot' or 'USER 1000' after the commands that require root privileges. Only use root for package installation, then switch to a non-root user.",
				CWEID:         "CWE-269",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "privilege-escalation", "docker", "container"},
			})
		}
	}

	return findings
}

// --- Registration ---

func init() {
	rules.Register(&HardcodedCredentialCheck{})
	rules.Register(&MissingAuthCheck{})
	rules.Register(&CORSWildcard{})
	rules.Register(&SessionFixation{})
	rules.Register(&WeakPasswordPolicy{})
	rules.Register(&InsecureCookie{})
	rules.Register(&PrivilegeEscalation{})
}
