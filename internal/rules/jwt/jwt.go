package jwt

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-JWT-001: JWT none algorithm accepted
var (
	reJWTNoneAlg     = regexp.MustCompile(`(?i)["'](?:alg|algorithm)["']\s*[=:]\s*["'](?:none|None|NONE|nOnE)["']`)
	reJWTAlgNone     = regexp.MustCompile(`(?i)(?:algorithms?\s*[=:]\s*\[?\s*["']none["']|verify\s*[=:]\s*(?:false|False|FALSE))`)
	reJWTNoVerify    = regexp.MustCompile(`(?i)(?:jwt\.decode|jwt_decode|JWT\.decode|Jose\.JWT\.Decode)\s*\([^)]*(?:verify\s*[=:]\s*(?:false|False)|options\s*[=:]\s*\{[^}]*(?:algorithms?\s*[=:]\s*\[?\s*["']none["']|verify\s*[=:]\s*false))`)
	reJWTNoAlgCheck  = regexp.MustCompile(`(?i)(?:algorithms?\s*=\s*\[\s*["']none["'])`)
)

// BATOU-JWT-002: JWT hardcoded secret key
var (
	reJWTHardcodedSecret = regexp.MustCompile(`(?i)(?:jwt\.(?:sign|encode|create|Sign)|JWT\.(?:create|encode|sign)|jose\.\w+\.sign|jsonwebtoken\.sign)\s*\([^,]+,\s*["'][^"']{1,100}["']`)
	reJWTSecretAssign    = regexp.MustCompile(`(?i)(?:jwt_secret|jwt_key|secret_key|signing_key|token_secret|JWT_SECRET|SIGNING_KEY)\s*[=:]\s*["'][^"']{1,100}["']`)
	reJWTSecretConst     = regexp.MustCompile(`(?i)(?:const|var|let|final|static)\s+\w*(?:secret|key|Secret|Key)\w*\s*[=:]\s*["'][^"']{3,100}["']`)
)

// BATOU-JWT-003: JWT algorithm confusion RS/HS
var (
	reJWTAlgConfusion = regexp.MustCompile(`(?i)(?:algorithms?\s*[=:]\s*\[\s*["'](?:HS256|HS384|HS512)["']\s*,\s*["'](?:RS256|RS384|RS512)["']|algorithms?\s*[=:]\s*\[\s*["'](?:RS256|RS384|RS512)["']\s*,\s*["'](?:HS256|HS384|HS512)["'])`)
	reJWTAlgMixed     = regexp.MustCompile(`(?i)(?:algorithms?\s*[=:]\s*\[(?:[^]]*["'](?:HS|RS|ES|PS)\d{3}["']\s*,?\s*){2,})`)
)

// BATOU-JWT-004: JWT not verifying expiration
var (
	reJWTNoExpVerify = regexp.MustCompile(`(?i)(?:verify_exp\s*[=:]\s*(?:false|False)|options\s*[=:]\s*\{[^}]*ignoreExpiration\s*[=:]\s*true|ignore_expiration\s*[=:]\s*(?:true|True)|exp\s*[=:]\s*false)`)
	reJWTNoExpCheck  = regexp.MustCompile(`(?i)(?:ClockSkew\s*=\s*TimeSpan\.MaxValue|verify_expiration\s*=\s*False)`)
)

// BATOU-JWT-005: JWT not verifying issuer/audience
var (
	reJWTNoIssVerify = regexp.MustCompile(`(?i)(?:verify_iss\s*[=:]\s*(?:false|False)|ValidateIssuer\s*=\s*false|ignoreIssuer\s*[=:]\s*true)`)
	reJWTNoAudVerify = regexp.MustCompile(`(?i)(?:verify_aud\s*[=:]\s*(?:false|False)|ValidateAudience\s*=\s*false|ignoreAudience\s*[=:]\s*true)`)
)

// BATOU-JWT-006: JWT weak HMAC secret (short string literal)
var (
	reJWTWeakSecret = regexp.MustCompile(`(?i)(?:jwt\.(?:sign|encode)|JWT\.(?:create|encode)|jsonwebtoken\.sign)\s*\([^,]+,\s*["'][^"']{1,15}["']`)
)

// BATOU-JWT-007: JWT token in URL parameter
var (
	reJWTInURL = regexp.MustCompile(`(?i)(?:\?|&)(?:token|jwt|access_token|id_token|auth_token)\s*=\s*(?:eyJ|\w+\.ey)`)
	reJWTURLParam = regexp.MustCompile(`(?i)(?:req\.(?:query|params)|request\.(?:GET|args|params)|getParameter)\s*[\[(]\s*["'](?:token|jwt|access_token|id_token)["']`)
	reJWTInQueryStr = regexp.MustCompile(`(?i)(?:url|uri|href|redirect|link)\s*[=+:]\s*[^;]*[?&](?:token|jwt|access_token)=`)
)

// BATOU-JWT-008: JWT decode without verify
var (
	reJWTDecodeNoVerify  = regexp.MustCompile(`(?i)\bjwt\.decode\s*\([^)]*(?:verify\s*=\s*False|options\s*=\s*\{[^}]*"verify"\s*:\s*false|algorithms?\s*=\s*\[\s*\])`)
	reJWTDecodeUnsafe    = regexp.MustCompile(`(?i)(?:jwt_decode|jose\.JWT\.Decode|JWT\.decode)\s*\([^)]*(?:verify\s*[=:]\s*false|do_verify\s*[=:]\s*false)`)
	reJWTUnsafeHeader    = regexp.MustCompile(`(?i)(?:jwt\.get_unverified_header|jwt\.decode_complete|jose\.jwt\.get_unverified_claims)\s*\(`)
	reJWTBase64Decode    = regexp.MustCompile(`(?i)(?:base64\.(?:b64decode|urlsafe_b64decode|decode)|atob|Buffer\.from)\s*\(\s*(?:token|jwt|access_token)\b`)
)

// BATOU-JWT-009: JWT kid header injection
var (
	reJWTKidSQL    = regexp.MustCompile(`(?i)["']kid["']\s*[=:]\s*(?:["'][^"']*(?:UNION|SELECT|OR|AND|\x27|--|;)[^"']*["']|.*(?:request\.|getParameter|params|query))`)
	reJWTKidFile   = regexp.MustCompile(`(?i)["']kid["']\s*[=:]\s*["'][^"']*(?:\.\.\/|/etc/|/dev/null|/proc/)[^"']*["']`)
	reJWTKidCmd    = regexp.MustCompile(`(?i)["']kid["']\s*[=:]\s*["'][^"']*(?:\||;|` + "`" + `|\$\()[^"']*["']`)
)

// BATOU-JWT-010: JWT stored in localStorage
var (
	reJWTLocalStorage    = regexp.MustCompile(`(?i)localStorage\.setItem\s*\(\s*["'](?:token|jwt|access_token|id_token|auth_token|refreshToken|refresh_token)["']`)
	reJWTLocalStorageGet = regexp.MustCompile(`(?i)localStorage\.getItem\s*\(\s*["'](?:token|jwt|access_token|id_token|auth_token)["']`)
	reJWTLocalStorageDirect = regexp.MustCompile(`(?i)localStorage\s*\[\s*["'](?:token|jwt|access_token|id_token|auth_token)["']\s*\]\s*=`)
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

// ---------------------------------------------------------------------------
// BATOU-JWT-001: JWT none/None algorithm accepted
// ---------------------------------------------------------------------------

type JWTNoneAlgorithm struct{}

func (r *JWTNoneAlgorithm) ID() string                     { return "BATOU-JWT-001" }
func (r *JWTNoneAlgorithm) Name() string                   { return "JWTNoneAlgorithm" }
func (r *JWTNoneAlgorithm) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JWTNoneAlgorithm) Description() string {
	return "Detects JWT configurations that accept the 'none' algorithm, which allows attackers to forge tokens without any signature."
}
func (r *JWTNoneAlgorithm) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP, rules.LangCSharp}
}

func (r *JWTNoneAlgorithm) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTNoneAlg, reJWTAlgNone, reJWTNoVerify, reJWTNoAlgCheck} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT 'none' algorithm accepted",
					Description:   "The JWT configuration accepts the 'none' algorithm or disables verification. An attacker can forge a JWT with alg=none and no signature, bypassing all authentication.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Always specify an explicit list of allowed algorithms (e.g., ['RS256']). Never include 'none'. Always verify signatures.",
					CWEID:         "CWE-327",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"jwt", "authentication", "none-algorithm", "token-forgery"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-002: JWT hardcoded secret key
// ---------------------------------------------------------------------------

type JWTHardcodedSecret struct{}

func (r *JWTHardcodedSecret) ID() string                     { return "BATOU-JWT-002" }
func (r *JWTHardcodedSecret) Name() string                   { return "JWTHardcodedSecret" }
func (r *JWTHardcodedSecret) DefaultSeverity() rules.Severity { return rules.High }
func (r *JWTHardcodedSecret) Description() string {
	return "Detects JWT signing operations or secret assignments using hardcoded string literals, which allows anyone with source code access to forge tokens."
}
func (r *JWTHardcodedSecret) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP, rules.LangCSharp}
}

func (r *JWTHardcodedSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTHardcodedSecret, reJWTSecretAssign} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT hardcoded secret key",
					Description:   "JWT signing secret is hardcoded as a string literal. Anyone with access to the source code can forge valid JWT tokens.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Load JWT secrets from environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Use asymmetric keys (RS256/ES256) for better security.",
					CWEID:         "CWE-798",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"jwt", "hardcoded-secret", "credentials"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-003: JWT algorithm confusion RS/HS
// ---------------------------------------------------------------------------

type JWTAlgorithmConfusion struct{}

func (r *JWTAlgorithmConfusion) ID() string                     { return "BATOU-JWT-003" }
func (r *JWTAlgorithmConfusion) Name() string                   { return "JWTAlgorithmConfusion" }
func (r *JWTAlgorithmConfusion) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JWTAlgorithmConfusion) Description() string {
	return "Detects JWT configurations that accept both HMAC (HS*) and RSA (RS*) algorithms, enabling algorithm confusion attacks where the public key is used as an HMAC secret."
}
func (r *JWTAlgorithmConfusion) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP, rules.LangCSharp}
}

func (r *JWTAlgorithmConfusion) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTAlgConfusion, reJWTAlgMixed} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT algorithm confusion (HS/RS mixed)",
					Description:   "JWT verification accepts both HMAC and RSA algorithms. An attacker can change the algorithm to HS256 and sign with the public RSA key, which the server will accept as a valid HMAC signature.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Accept only a single algorithm family. If using RSA, only allow RS256/RS384/RS512. Never mix symmetric (HS) and asymmetric (RS/ES/PS) algorithms.",
					CWEID:         "CWE-327",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"jwt", "algorithm-confusion", "key-confusion"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-004: JWT not verifying expiration
// ---------------------------------------------------------------------------

type JWTNoExpiration struct{}

func (r *JWTNoExpiration) ID() string                     { return "BATOU-JWT-004" }
func (r *JWTNoExpiration) Name() string                   { return "JWTNoExpiration" }
func (r *JWTNoExpiration) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JWTNoExpiration) Description() string {
	return "Detects JWT verification that disables expiration checking, allowing tokens to be used indefinitely after compromise."
}
func (r *JWTNoExpiration) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP, rules.LangCSharp}
}

func (r *JWTNoExpiration) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTNoExpVerify, reJWTNoExpCheck} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT expiration check disabled",
					Description:   "JWT verification is configured to skip expiration (exp) claim validation. A stolen or leaked token can be used indefinitely.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Always verify the exp claim. Set reasonable token lifetimes (e.g., 15 minutes for access tokens). Use refresh tokens for long-lived sessions.",
					CWEID:         "CWE-613",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"jwt", "expiration", "token-lifetime"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-005: JWT not verifying issuer/audience
// ---------------------------------------------------------------------------

type JWTNoIssuerAudience struct{}

func (r *JWTNoIssuerAudience) ID() string                     { return "BATOU-JWT-005" }
func (r *JWTNoIssuerAudience) Name() string                   { return "JWTNoIssuerAudience" }
func (r *JWTNoIssuerAudience) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JWTNoIssuerAudience) Description() string {
	return "Detects JWT verification that skips issuer (iss) or audience (aud) validation, allowing tokens from other services to be accepted."
}
func (r *JWTNoIssuerAudience) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangCSharp}
}

func (r *JWTNoIssuerAudience) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTNoIssVerify, reJWTNoAudVerify} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT issuer/audience verification disabled",
					Description:   "JWT verification skips issuer or audience validation. Tokens issued by other services or intended for different audiences could be accepted, enabling cross-service token abuse.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Always validate the iss (issuer) and aud (audience) claims against expected values. This prevents tokens from other services from being accepted.",
					CWEID:         "CWE-287",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"jwt", "issuer", "audience", "validation"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-006: JWT weak HMAC secret (short string literal)
// ---------------------------------------------------------------------------

type JWTWeakSecret struct{}

func (r *JWTWeakSecret) ID() string                     { return "BATOU-JWT-006" }
func (r *JWTWeakSecret) Name() string                   { return "JWTWeakSecret" }
func (r *JWTWeakSecret) DefaultSeverity() rules.Severity { return rules.High }
func (r *JWTWeakSecret) Description() string {
	return "Detects JWT signing with a weak HMAC secret (short string literal of 15 characters or less), which can be brute-forced."
}
func (r *JWTWeakSecret) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *JWTWeakSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reJWTWeakSecret.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "JWT weak HMAC secret",
				Description:   "JWT is signed with a short HMAC secret (15 characters or less). Short secrets can be brute-forced with tools like jwt-cracker or hashcat in minutes to hours.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use a cryptographically random secret of at least 256 bits (32 bytes). Better yet, use asymmetric algorithms (RS256/ES256) with proper key management.",
				CWEID:         "CWE-326",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jwt", "weak-secret", "brute-force"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-007: JWT token in URL parameter
// ---------------------------------------------------------------------------

type JWTInURL struct{}

func (r *JWTInURL) ID() string                     { return "BATOU-JWT-007" }
func (r *JWTInURL) Name() string                   { return "JWTInURL" }
func (r *JWTInURL) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JWTInURL) Description() string {
	return "Detects JWT tokens being passed via URL query parameters, which exposes them in server logs, browser history, and referrer headers."
}
func (r *JWTInURL) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *JWTInURL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTInURL, reJWTURLParam, reJWTInQueryStr} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT token in URL parameter",
					Description:   "JWT tokens passed via URL query parameters are exposed in server access logs, browser history, Referer headers, and proxy logs. This makes token theft significantly easier.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Pass JWT tokens in the Authorization header (Bearer token) or in an HttpOnly secure cookie. Never pass tokens in URL parameters.",
					CWEID:         "CWE-598",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"jwt", "token-exposure", "url-parameter"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-008: JWT decode without verify
// ---------------------------------------------------------------------------

type JWTDecodeNoVerify struct{}

func (r *JWTDecodeNoVerify) ID() string                     { return "BATOU-JWT-008" }
func (r *JWTDecodeNoVerify) Name() string                   { return "JWTDecodeNoVerify" }
func (r *JWTDecodeNoVerify) DefaultSeverity() rules.Severity { return rules.High }
func (r *JWTDecodeNoVerify) Description() string {
	return "Detects JWT tokens being decoded without signature verification, allowing attackers to modify token claims."
}
func (r *JWTDecodeNoVerify) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP, rules.LangCSharp}
}

func (r *JWTDecodeNoVerify) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTDecodeNoVerify, reJWTDecodeUnsafe, reJWTUnsafeHeader, reJWTBase64Decode} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT decoded without signature verification",
					Description:   "JWT is decoded without verifying its signature. An attacker can modify the token payload (e.g., change user_id, role, permissions) and the changes will be trusted by the application.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Always verify JWT signatures before trusting the payload. Use jwt.decode() with verify=True and specify the algorithm and secret/key.",
					CWEID:         "CWE-345",
					OWASPCategory: "A08:2021-Software and Data Integrity Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"jwt", "signature-bypass", "decode-without-verify"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-009: JWT kid header injection
// ---------------------------------------------------------------------------

type JWTKidInjection struct{}

func (r *JWTKidInjection) ID() string                     { return "BATOU-JWT-009" }
func (r *JWTKidInjection) Name() string                   { return "JWTKidInjection" }
func (r *JWTKidInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *JWTKidInjection) Description() string {
	return "Detects JWT kid (Key ID) header values that contain injection payloads (SQL, path traversal, command injection), indicating the kid is used unsafely."
}
func (r *JWTKidInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *JWTKidInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTKidSQL, reJWTKidFile, reJWTKidCmd} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT kid header injection",
					Description:   "The JWT 'kid' (Key ID) header is used in a way vulnerable to injection. If kid is used in SQL queries, file paths, or shell commands without sanitization, attackers can exploit it for SQL injection, path traversal, or RCE.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Validate kid against an allowlist of known key IDs. Never use kid directly in SQL queries, file paths, or shell commands. Use a key lookup map instead.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"jwt", "kid-injection", "header-manipulation"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-JWT-010: JWT stored in localStorage
// ---------------------------------------------------------------------------

type JWTLocalStorage struct{}

func (r *JWTLocalStorage) ID() string                     { return "BATOU-JWT-010" }
func (r *JWTLocalStorage) Name() string                   { return "JWTLocalStorage" }
func (r *JWTLocalStorage) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JWTLocalStorage) Description() string {
	return "Detects JWT tokens stored in localStorage, which is accessible to any JavaScript on the page including XSS payloads."
}
func (r *JWTLocalStorage) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *JWTLocalStorage) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reJWTLocalStorage, reJWTLocalStorageDirect} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "JWT token stored in localStorage",
					Description:   "JWT stored in localStorage is accessible to any JavaScript on the page. A single XSS vulnerability allows an attacker to steal the token and impersonate the user.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Store tokens in HttpOnly, Secure, SameSite cookies instead. If you must use localStorage, ensure robust XSS protection and consider token binding.",
					CWEID:         "CWE-922",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"jwt", "localstorage", "xss", "token-storage"},
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
	rules.Register(&JWTNoneAlgorithm{})
	rules.Register(&JWTHardcodedSecret{})
	rules.Register(&JWTAlgorithmConfusion{})
	rules.Register(&JWTNoExpiration{})
	rules.Register(&JWTNoIssuerAudience{})
	rules.Register(&JWTWeakSecret{})
	rules.Register(&JWTInURL{})
	rules.Register(&JWTDecodeNoVerify{})
	rules.Register(&JWTKidInjection{})
	rules.Register(&JWTLocalStorage{})
}
