package auth

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended auth detection
// ---------------------------------------------------------------------------

var (
	// GTSS-AUTH-008: Missing rate limiting on login
	reExtLoginRoute = regexp.MustCompile(`(?i)(?:\.post|\.put|HandleFunc|handle)\s*\(\s*["']/(?:login|signin|sign-in|auth|authenticate|api/login|api/auth)["']`)
	reExtRateLimit  = regexp.MustCompile(`(?i)(?:rate[_-]?limit|throttle|limiter|RateLimit|slowDown|express-rate-limit|express-brute|ratelimit|Throttle)`)

	// GTSS-AUTH-009: Password comparison using ==
	reExtPasswordEqGo   = regexp.MustCompile(`(?i)(?:password|passwd|pass|pwd)\s*==\s*(?:[a-zA-Z_]\w*|"[^"]+"|'[^']+')`)
	reExtPasswordEqJS   = regexp.MustCompile(`(?i)(?:password|passwd|pass|pwd)\s*===?\s*(?:[a-zA-Z_]\w*|"[^"]+"|'[^']+')`)
	reExtPasswordEqPy   = regexp.MustCompile(`(?i)(?:password|passwd|pass|pwd)\s*==\s*(?:[a-zA-Z_]\w*|"[^"]+"|'[^']+')`)
	reExtSafeCompare    = regexp.MustCompile(`(?i)(?:bcrypt|argon2|scrypt|pbkdf2|hmac|constant_time|compare_digest|timing_safe|timingSafeEqual|subtle\.ConstantTimeCompare|crypto\.timingSafeEqual|secrets\.compare_digest)`)

	// GTSS-AUTH-010: Hardcoded admin/default credentials
	reExtHardcodedAdmin = regexp.MustCompile(`(?i)(?:admin|administrator|root|superuser|default)\s*[:=]\s*["'](?:admin|password|123456|root|default|changeme|admin123|pass|passwd|test|secret)["']`)
	reExtDefaultCreds   = regexp.MustCompile(`(?i)(?:default[_-]?(?:password|user|admin|cred)|admin[_-]?(?:password|pass|pwd))\s*[:=]\s*["'][^"']{1,}["']`)

	// GTSS-AUTH-011: Missing CSRF protection
	reExtCSRFToken     = regexp.MustCompile(`(?i)(?:csrf|xsrf|_token|csrfmiddleware|anti[_-]?forgery|AntiForgeryToken|authenticity_token|__RequestVerificationToken)`)
	reExtStateChanging = regexp.MustCompile(`(?i)(?:\.post|\.put|\.patch|\.delete)\s*\(\s*["']/`)

	// GTSS-AUTH-012: Auth bypass via parameter manipulation
	reExtAuthBypass = regexp.MustCompile(`(?i)(?:is[_-]?admin|isAdmin|is[_-]?authenticated|is_superuser|role|user_?role|admin)\s*[:=]\s*(?:req\.(?:body|query|params)|request\.(?:POST|GET|data|json|form)|params\[|\$_(?:GET|POST|REQUEST))`)

	// GTSS-AUTH-013: Broken function-level access control
	reExtAdminEndpoint       = regexp.MustCompile(`(?i)(?:\.(?:get|post|put|delete|patch|all))\s*\(\s*["']/(?:admin|internal|management|supervisor|moderator|api/admin)`)
	reExtAccessControlCheck  = regexp.MustCompile(`(?i)(?:isAdmin|is_admin|requireAdmin|require_admin|authorize|@admin_required|@staff_member_required|@permission_required|hasRole|has_role|checkPermission)`)

	// GTSS-AUTH-014: Insecure password reset
	reExtPasswordReset      = regexp.MustCompile(`(?i)(?:reset[_-]?(?:password|token|code)|forgot[_-]?password|password[_-]?reset)`)
	reExtPredictableToken   = regexp.MustCompile(`(?i)(?:uuid\.uuid1|Math\.random|rand\(\)|time\.Now|Date\.now|random\.randint|srand|mt_rand|uniqid)\s*\(`)
	reExtSecureToken        = regexp.MustCompile(`(?i)(?:crypto\.random|secrets\.token|uuid\.uuid4|uuid\.v4|RandomBytes|SecureRandom|crypto\.getRandomValues|os\.urandom|RandRead)`)

	// GTSS-AUTH-015: Missing MFA check
	reExtMFACheck    = regexp.MustCompile(`(?i)(?:mfa|2fa|two[_-]?factor|totp|otp|multi[_-]?factor|second[_-]?factor)`)
	reExtSensitiveOp = regexp.MustCompile(`(?i)(?:transfer|withdraw|payment|wire|change[_-]?password|change[_-]?email|delete[_-]?account|export[_-]?data)`)

	// GTSS-AUTH-016: Username enumeration via different error messages
	reExtUserNotFound    = regexp.MustCompile(`(?i)["'](?:user\s+not\s+found|username\s+does\s+not\s+exist|no\s+(?:such\s+)?user|account\s+not\s+found|invalid\s+username|email\s+not\s+found|unknown\s+user|user\s+does\s+not\s+exist)["']`)
	reExtWrongPassword   = regexp.MustCompile(`(?i)["'](?:wrong\s+password|incorrect\s+password|invalid\s+password|password\s+(?:is\s+)?incorrect|bad\s+password)["']`)

	// GTSS-AUTH-017: Weak password policy
	reExtWeakPolicyNoUpper = regexp.MustCompile(`(?i)(?:min_?length|minLen|minimum.?length|PASSWORD_MIN)\s*[:=]\s*([0-9]+)`)
	reExtComplexityCheck   = regexp.MustCompile(`(?i)(?:uppercase|upper[_-]?case|[A-Z].*required|must.*[A-Z]|special.*char|complexity|zxcvbn|password.*strength|strongPassword)`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&MissingRateLimit{})
	rules.Register(&TimingAttackComparison{})
	rules.Register(&HardcodedAdminCreds{})
	rules.Register(&MissingCSRF{})
	rules.Register(&AuthBypassParam{})
	rules.Register(&BrokenAccessControl{})
	rules.Register(&InsecurePasswordReset{})
	rules.Register(&MissingMFA{})
	rules.Register(&UsernameEnumeration{})
	rules.Register(&WeakPasswordPolicyExt{})
}

// ========================================================================
// GTSS-AUTH-008: Missing Rate Limiting on Login
// ========================================================================

type MissingRateLimit struct{}

func (r *MissingRateLimit) ID() string                     { return "GTSS-AUTH-008" }
func (r *MissingRateLimit) Name() string                   { return "MissingRateLimit" }
func (r *MissingRateLimit) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingRateLimit) Description() string {
	return "Detects login/authentication endpoints without rate limiting middleware, enabling brute-force attacks."
}
func (r *MissingRateLimit) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangPHP}
}

func (r *MissingRateLimit) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasRateLimit := reExtRateLimit.MatchString(ctx.Content)
	if hasRateLimit {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtLoginRoute.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Login endpoint without rate limiting",
				Description:   "This login/authentication endpoint does not appear to have rate limiting middleware. Without rate limiting, attackers can perform brute-force and credential stuffing attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add rate limiting middleware to login endpoints. Use libraries like express-rate-limit (Node.js), django-ratelimit (Python), or implement token bucket algorithm.",
				CWEID:         "CWE-307",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"auth", "rate-limiting", "brute-force"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-009: Password Comparison Using == (Timing Attack)
// ========================================================================

type TimingAttackComparison struct{}

func (r *TimingAttackComparison) ID() string                     { return "GTSS-AUTH-009" }
func (r *TimingAttackComparison) Name() string                   { return "TimingAttackComparison" }
func (r *TimingAttackComparison) DefaultSeverity() rules.Severity { return rules.High }
func (r *TimingAttackComparison) Description() string {
	return "Detects password/secret comparison using == operator instead of constant-time comparison, enabling timing side-channel attacks."
}
func (r *TimingAttackComparison) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava}
}

func (r *TimingAttackComparison) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if file already uses safe comparison functions
	if reExtSafeCompare.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		var matched string
		switch ctx.Language {
		case rules.LangGo, rules.LangJava:
			matched = reExtPasswordEqGo.FindString(line)
		case rules.LangJavaScript, rules.LangTypeScript:
			matched = reExtPasswordEqJS.FindString(line)
		case rules.LangPython:
			matched = reExtPasswordEqPy.FindString(line)
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Password compared with == operator (timing attack risk)",
				Description:   "Passwords or secrets are compared using the == operator, which is vulnerable to timing attacks. An attacker can determine the correct value character-by-character by measuring response times.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use constant-time comparison: crypto.timingSafeEqual (Node.js), hmac.compare_digest (Python), subtle.ConstantTimeCompare (Go), or MessageDigest.isEqual (Java). Better yet, use bcrypt/argon2 for password hashing.",
				CWEID:         "CWE-208",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "timing-attack", "password"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-010: Hardcoded Admin/Default Credentials
// ========================================================================

type HardcodedAdminCreds struct{}

func (r *HardcodedAdminCreds) ID() string                     { return "GTSS-AUTH-010" }
func (r *HardcodedAdminCreds) Name() string                   { return "HardcodedAdminCreds" }
func (r *HardcodedAdminCreds) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *HardcodedAdminCreds) Description() string {
	return "Detects hardcoded admin or default credentials in source code."
}
func (r *HardcodedAdminCreds) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *HardcodedAdminCreds) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		var matched string
		if m := reExtHardcodedAdmin.FindString(line); m != "" {
			matched = m
		} else if m := reExtDefaultCreds.FindString(line); m != "" {
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
				Title:         "Hardcoded admin/default credentials detected",
				Description:   "Default or admin credentials are hardcoded in source code. These credentials are often well-known and provide immediate access to the system.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove hardcoded credentials. Use environment variables or a secrets manager. Force credential changes on first login.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "hardcoded", "default-credentials", "admin"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-011: Missing CSRF Protection
// ========================================================================

type MissingCSRF struct{}

func (r *MissingCSRF) ID() string                     { return "GTSS-AUTH-011" }
func (r *MissingCSRF) Name() string                   { return "MissingCSRF" }
func (r *MissingCSRF) DefaultSeverity() rules.Severity { return rules.High }
func (r *MissingCSRF) Description() string {
	return "Detects state-changing endpoints without CSRF token validation."
}
func (r *MissingCSRF) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangPHP}
}

func (r *MissingCSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasCSRF := reExtCSRFToken.MatchString(ctx.Content)
	if hasCSRF {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtStateChanging.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "State-changing endpoint without CSRF protection",
				Description:   "This state-changing endpoint (POST/PUT/PATCH/DELETE) does not appear to have CSRF token validation. An attacker can trick a user's browser into making unauthorized requests.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add CSRF middleware: csurf (Express), django.middleware.csrf (Django), csrf_field() (Laravel). Use SameSite cookie attribute as additional protection.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"auth", "csrf", "state-changing"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-012: Authentication Bypass via Parameter Manipulation
// ========================================================================

type AuthBypassParam struct{}

func (r *AuthBypassParam) ID() string                     { return "GTSS-AUTH-012" }
func (r *AuthBypassParam) Name() string                   { return "AuthBypassParam" }
func (r *AuthBypassParam) DefaultSeverity() rules.Severity { return rules.High }
func (r *AuthBypassParam) Description() string {
	return "Detects authentication/authorization decisions based on user-controllable request parameters."
}
func (r *AuthBypassParam) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *AuthBypassParam) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtAuthBypass.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Auth decision based on user-controllable parameter",
				Description:   "An authorization flag (isAdmin, role, etc.) is being set from user-controlled request input. An attacker can simply set this parameter to gain elevated privileges.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Never trust user input for authorization decisions. Derive roles and permissions from the authenticated session, JWT claims, or database. Never accept admin flags from request body/query.",
				CWEID:         "CWE-287",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "bypass", "parameter-manipulation"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-013: Broken Function-Level Access Control
// ========================================================================

type BrokenAccessControl struct{}

func (r *BrokenAccessControl) ID() string                     { return "GTSS-AUTH-013" }
func (r *BrokenAccessControl) Name() string                   { return "BrokenAccessControl" }
func (r *BrokenAccessControl) DefaultSeverity() rules.Severity { return rules.High }
func (r *BrokenAccessControl) Description() string {
	return "Detects admin/privileged endpoints without access control checks."
}
func (r *BrokenAccessControl) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo}
}

func (r *BrokenAccessControl) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasAccessControl := reExtAccessControlCheck.MatchString(ctx.Content)
	if hasAccessControl {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtAdminEndpoint.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Admin endpoint without access control check",
				Description:   "This admin/privileged endpoint does not appear to have role-based access control. Any authenticated (or unauthenticated) user may be able to access admin functionality.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add role-based access control middleware. Verify the user has admin/appropriate role before executing the handler. Use @admin_required (Django), requireRole('admin') (Express), or equivalent.",
				CWEID:         "CWE-285",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"auth", "access-control", "admin"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-014: Insecure Password Reset (Predictable Token)
// ========================================================================

type InsecurePasswordReset struct{}

func (r *InsecurePasswordReset) ID() string                     { return "GTSS-AUTH-014" }
func (r *InsecurePasswordReset) Name() string                   { return "InsecurePasswordReset" }
func (r *InsecurePasswordReset) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecurePasswordReset) Description() string {
	return "Detects password reset functionality using predictable token generation (Math.random, time-based, sequential)."
}
func (r *InsecurePasswordReset) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *InsecurePasswordReset) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reExtPasswordReset.MatchString(ctx.Content) {
		return nil
	}
	// Skip if secure token generation is present
	if reExtSecureToken.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtPredictableToken.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Predictable token in password reset flow",
				Description:   "A password reset token is generated using a predictable method (Math.random, time-based, sequential ID). An attacker can guess or predict the token and reset any user's password.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use cryptographically secure random token generation: crypto.randomBytes (Node.js), secrets.token_urlsafe (Python), crypto/rand (Go), SecureRandom (Java/Ruby).",
				CWEID:         "CWE-640",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"auth", "password-reset", "predictable-token"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-015: Missing MFA Check
// ========================================================================

type MissingMFA struct{}

func (r *MissingMFA) ID() string                     { return "GTSS-AUTH-015" }
func (r *MissingMFA) Name() string                   { return "MissingMFA" }
func (r *MissingMFA) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingMFA) Description() string {
	return "Detects sensitive operations (transfers, password changes) without multi-factor authentication verification."
}
func (r *MissingMFA) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *MissingMFA) Scan(ctx *rules.ScanContext) []rules.Finding {
	if reExtMFACheck.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtSensitiveOp.FindString(line); m != "" {
			// Only flag route definitions, not variable names
			if strings.Contains(line, "(") && (strings.Contains(line, "/") || strings.Contains(line, "def ") || strings.Contains(line, "func ")) {
				matched := m
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Sensitive operation without MFA verification",
					Description:   "This sensitive operation does not appear to require multi-factor authentication. High-value operations (transfers, password changes, account deletion) should require step-up authentication.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncateExt(strings.TrimSpace(line), 120),
					Suggestion:    "Require MFA/2FA verification before executing sensitive operations. Use TOTP, SMS, or push notification as a second factor.",
					CWEID:         "CWE-308",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"auth", "mfa", "sensitive-operation"},
				})
			}
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-016: Username Enumeration via Different Error Messages
// ========================================================================

type UsernameEnumeration struct{}

func (r *UsernameEnumeration) ID() string                     { return "GTSS-AUTH-016" }
func (r *UsernameEnumeration) Name() string                   { return "UsernameEnumeration" }
func (r *UsernameEnumeration) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UsernameEnumeration) Description() string {
	return "Detects different error messages for invalid username vs invalid password, enabling username enumeration."
}
func (r *UsernameEnumeration) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *UsernameEnumeration) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasUserNotFound := reExtUserNotFound.MatchString(ctx.Content)
	hasWrongPassword := reExtWrongPassword.MatchString(ctx.Content)
	if !hasUserNotFound || !hasWrongPassword {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtUserNotFound.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Username enumeration via different error messages",
				Description:   "Different error messages are used for 'user not found' and 'wrong password'. An attacker can determine valid usernames by observing which error message is returned.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use a generic error message for both cases: 'Invalid username or password'. Ensure response timing is consistent regardless of whether the username exists.",
				CWEID:         "CWE-204",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"auth", "enumeration", "information-disclosure"},
			})
			break // One finding per file
		}
	}
	return findings
}

// ========================================================================
// GTSS-AUTH-017: Weak Password Policy (No Complexity Requirement)
// ========================================================================

type WeakPasswordPolicyExt struct{}

func (r *WeakPasswordPolicyExt) ID() string                     { return "GTSS-AUTH-017" }
func (r *WeakPasswordPolicyExt) Name() string                   { return "WeakPasswordPolicyExt" }
func (r *WeakPasswordPolicyExt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *WeakPasswordPolicyExt) Description() string {
	return "Detects password policies that only check length without requiring character complexity."
}
func (r *WeakPasswordPolicyExt) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *WeakPasswordPolicyExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Check if the file has password length checks but no complexity requirements
	hasLengthCheck := reExtWeakPolicyNoUpper.MatchString(ctx.Content)
	hasComplexity := reExtComplexityCheck.MatchString(ctx.Content)

	if !hasLengthCheck || hasComplexity {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtWeakPolicyNoUpper.FindStringSubmatch(line); m != nil {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Password policy lacks complexity requirements",
				Description:   "Password validation checks length but does not enforce character complexity (uppercase, lowercase, digits, special characters). Length-only policies allow weak passwords like 'aaaaaaaa'.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add complexity requirements or use a password strength estimator like zxcvbn. NIST SP 800-63B recommends checking against breached password lists rather than complex character rules.",
				CWEID:         "CWE-521",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"auth", "password", "policy", "complexity"},
			})
			break
		}
	}
	return findings
}

// truncateExt truncates string for display (uniquely named to avoid conflict with main file).
func truncateExt(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
