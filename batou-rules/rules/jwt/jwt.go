package jwt

import (
	"regexp"

	"github.com/turenlabs/batou-rules/rules"
)

// Common language sets used by JWT rules.
var (
	jwtAllLangs = []rules.Language{
		rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP, rules.LangCSharp,
	}
	jwtNoCSLangs = []rules.Language{
		rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP,
	}
	jwtFrontendLangs = []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript,
	}
)

func init() {
	for i := range jwtRules {
		rules.Register(&jwtRules[i])
	}
}

var jwtRules = []rules.RegexRule{
	{
		RuleID:   "BATOU-JWT-001",
		RuleName: "JWTNoneAlgorithm",
		Desc:     "Detects JWT configurations that accept the 'none' algorithm, which allows attackers to forge tokens without any signature.",
		Sev:      rules.Critical,
		Langs:    jwtAllLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)["'](?:alg|algorithm)["']\s*[=:]\s*["'](?:none|None|NONE|nOnE)["']`),
			// `\bverify` prevents matching Go's `InsecureSkipVerify: false`
			// (where `false` means verification is ENABLED — the opposite of
			// the `verify=False` pattern this rule targets).
			regexp.MustCompile(`(?i)(?:algorithms?\s*[=:]\s*\[?\s*["']none["']|\bverify\s*[=:]\s*(?:false|False|FALSE))`),
			regexp.MustCompile(`(?i)(?:jwt\.decode|jwt_decode|JWT\.decode|Jose\.JWT\.Decode)\s*\([^)]*(?:\bverify\s*[=:]\s*(?:false|False)|options\s*[=:]\s*\{[^}]*(?:algorithms?\s*[=:]\s*\[?\s*["']none["']|\bverify\s*[=:]\s*false))`),
			regexp.MustCompile(`(?i)(?:algorithms?\s*=\s*\[\s*["']none["'])`),
		},
		Title:    "JWT 'none' algorithm accepted",
		FindDesc: "The JWT configuration accepts the 'none' algorithm or disables verification. An attacker can forge a JWT with alg=none and no signature, bypassing all authentication.",
		Fix:      "Always specify an explicit list of allowed algorithms (e.g., ['RS256']). Never include 'none'. Always verify signatures.",
		CWE:      "CWE-327",
		OWASP:    "A02:2021-Cryptographic Failures",
		Conf:     "high",
		RuleTags: []string{"jwt", "authentication", "none-algorithm", "token-forgery"},
	},
	{
		RuleID:   "BATOU-JWT-002",
		RuleName: "JWTHardcodedSecret",
		Desc:     "Detects JWT signing operations or secret assignments using hardcoded string literals, which allows anyone with source code access to forge tokens.",
		Sev:      rules.High,
		Langs:    jwtAllLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(?:jwt\.(?:sign|encode|create|Sign)|JWT\.(?:create|encode|sign)|jose\.\w+\.sign|jsonwebtoken\.sign)\s*\([^,]+,\s*["'][^"']{1,100}["']`),
			regexp.MustCompile(`(?i)(?:jwt_secret|jwt_key|secret_key|signing_key|token_secret|JWT_SECRET|SIGNING_KEY)\s*[=:]\s*["'][^"']{1,100}["']`),
		},
		Title:    "JWT hardcoded secret key",
		FindDesc: "JWT signing secret is hardcoded as a string literal. Anyone with access to the source code can forge valid JWT tokens.",
		Fix:      "Load JWT secrets from environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Use asymmetric keys (RS256/ES256) for better security.",
		CWE:      "CWE-798",
		OWASP:    "A02:2021-Cryptographic Failures",
		Conf:     "high",
		RuleTags: []string{"jwt", "hardcoded-secret", "credentials"},
	},
	{
		RuleID:   "BATOU-JWT-003",
		RuleName: "JWTAlgorithmConfusion",
		Desc:     "Detects JWT configurations that accept both HMAC (HS*) and RSA (RS*) algorithms, enabling algorithm confusion attacks where the public key is used as an HMAC secret.",
		Sev:      rules.Critical,
		Langs:    jwtAllLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(?:algorithms?\s*[=:]\s*\[\s*["'](?:HS256|HS384|HS512)["']\s*,\s*["'](?:RS256|RS384|RS512)["']|algorithms?\s*[=:]\s*\[\s*["'](?:RS256|RS384|RS512)["']\s*,\s*["'](?:HS256|HS384|HS512)["'])`),
			regexp.MustCompile(`(?i)(?:algorithms?\s*[=:]\s*\[(?:[^]]*["'](?:HS|RS|ES|PS)\d{3}["']\s*,?\s*){2,})`),
		},
		Title:    "JWT algorithm confusion (HS/RS mixed)",
		FindDesc: "JWT verification accepts both HMAC and RSA algorithms. An attacker can change the algorithm to HS256 and sign with the public RSA key, which the server will accept as a valid HMAC signature.",
		Fix:      "Accept only a single algorithm family. If using RSA, only allow RS256/RS384/RS512. Never mix symmetric (HS) and asymmetric (RS/ES/PS) algorithms.",
		CWE:      "CWE-327",
		OWASP:    "A02:2021-Cryptographic Failures",
		Conf:     "high",
		RuleTags: []string{"jwt", "algorithm-confusion", "key-confusion"},
	},
	{
		RuleID:   "BATOU-JWT-004",
		RuleName: "JWTNoExpiration",
		Desc:     "Detects JWT verification that disables expiration checking, allowing tokens to be used indefinitely after compromise.",
		Sev:      rules.Medium,
		Langs:    jwtAllLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(?:verify_exp\s*[=:]\s*(?:false|False)|options\s*[=:]\s*\{[^}]*ignoreExpiration\s*[=:]\s*true|ignore_expiration\s*[=:]\s*(?:true|True)|exp\s*[=:]\s*false)`),
			regexp.MustCompile(`(?i)(?:ClockSkew\s*=\s*TimeSpan\.MaxValue|verify_expiration\s*=\s*False)`),
		},
		Title:    "JWT expiration check disabled",
		FindDesc: "JWT verification is configured to skip expiration (exp) claim validation. A stolen or leaked token can be used indefinitely.",
		Fix:      "Always verify the exp claim. Set reasonable token lifetimes (e.g., 15 minutes for access tokens). Use refresh tokens for long-lived sessions.",
		CWE:      "CWE-613",
		OWASP:    "A07:2021-Identification and Authentication Failures",
		Conf:     "high",
		RuleTags: []string{"jwt", "expiration", "token-lifetime"},
	},
	{
		RuleID:   "BATOU-JWT-005",
		RuleName: "JWTNoIssuerAudience",
		Desc:     "Detects JWT verification that skips issuer (iss) or audience (aud) validation, allowing tokens from other services to be accepted.",
		Sev:      rules.Medium,
		Langs:    []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangGo, rules.LangCSharp},
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(?:verify_iss\s*[=:]\s*(?:false|False)|ValidateIssuer\s*=\s*false|ignoreIssuer\s*[=:]\s*true)`),
			regexp.MustCompile(`(?i)(?:verify_aud\s*[=:]\s*(?:false|False)|ValidateAudience\s*=\s*false|ignoreAudience\s*[=:]\s*true)`),
		},
		Title:    "JWT issuer/audience verification disabled",
		FindDesc: "JWT verification skips issuer or audience validation. Tokens issued by other services or intended for different audiences could be accepted, enabling cross-service token abuse.",
		Fix:      "Always validate the iss (issuer) and aud (audience) claims against expected values. This prevents tokens from other services from being accepted.",
		CWE:      "CWE-287",
		OWASP:    "A07:2021-Identification and Authentication Failures",
		Conf:     "medium",
		RuleTags: []string{"jwt", "issuer", "audience", "validation"},
	},
	{
		RuleID:   "BATOU-JWT-006",
		RuleName: "JWTWeakSecret",
		Desc:     "Detects JWT signing with a weak HMAC secret (short string literal of 15 characters or less), which can be brute-forced.",
		Sev:      rules.High,
		Langs:    jwtNoCSLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(?:jwt\.(?:sign|encode)|JWT\.(?:create|encode)|jsonwebtoken\.sign)\s*\([^,]+,\s*["'][^"']{1,15}["']`),
		},
		Title:    "JWT weak HMAC secret",
		FindDesc: "JWT is signed with a short HMAC secret (15 characters or less). Short secrets can be brute-forced with tools like jwt-cracker or hashcat in minutes to hours.",
		Fix:      "Use a cryptographically random secret of at least 256 bits (32 bytes). Better yet, use asymmetric algorithms (RS256/ES256) with proper key management.",
		CWE:      "CWE-326",
		OWASP:    "A02:2021-Cryptographic Failures",
		Conf:     "high",
		RuleTags: []string{"jwt", "weak-secret", "brute-force"},
	},
	{
		RuleID:   "BATOU-JWT-007",
		RuleName: "JWTInURL",
		Desc:     "Detects JWT tokens being passed via URL query parameters, which exposes them in server logs, browser history, and referrer headers.",
		Sev:      rules.Medium,
		Langs:    jwtNoCSLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(?:\?|&)(?:token|jwt|access_token|id_token|auth_token)\s*=\s*(?:eyJ|\w+\.ey)`),
			regexp.MustCompile(`(?i)(?:req\.(?:query|params)|request\.(?:GET|args|params)|getParameter)\s*[\[(]\s*["'](?:token|jwt|access_token|id_token)["']`),
			regexp.MustCompile(`(?i)(?:url|uri|href|redirect|link)\s*[=+:]\s*[^;]*[?&](?:token|jwt|access_token)=`),
		},
		Title:    "JWT token in URL parameter",
		FindDesc: "JWT tokens passed via URL query parameters are exposed in server access logs, browser history, Referer headers, and proxy logs. This makes token theft significantly easier.",
		Fix:      "Pass JWT tokens in the Authorization header (Bearer token) or in an HttpOnly secure cookie. Never pass tokens in URL parameters.",
		CWE:      "CWE-598",
		OWASP:    "A07:2021-Identification and Authentication Failures",
		Conf:     "medium",
		RuleTags: []string{"jwt", "token-exposure", "url-parameter"},
	},
	{
		RuleID:   "BATOU-JWT-008",
		RuleName: "JWTDecodeNoVerify",
		Desc:     "Detects JWT tokens being decoded without signature verification, allowing attackers to modify token claims.",
		Sev:      rules.High,
		Langs:    jwtAllLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bjwt\.decode\s*\([^)]*(?:verify\s*=\s*False|options\s*=\s*\{[^}]*"verify"\s*:\s*false|algorithms?\s*=\s*\[\s*\])`),
			regexp.MustCompile(`(?i)(?:jwt_decode|jose\.JWT\.Decode|JWT\.decode)\s*\([^)]*(?:verify\s*[=:]\s*false|do_verify\s*[=:]\s*false)`),
			regexp.MustCompile(`(?i)(?:jwt\.get_unverified_header|jwt\.decode_complete|jose\.jwt\.get_unverified_claims)\s*\(`),
			regexp.MustCompile(`(?i)(?:base64\.(?:b64decode|urlsafe_b64decode|decode)|atob|Buffer\.from)\s*\(\s*(?:token|jwt|access_token)\b`),
		},
		Title:    "JWT decoded without signature verification",
		FindDesc: "JWT is decoded without verifying its signature. An attacker can modify the token payload (e.g., change user_id, role, permissions) and the changes will be trusted by the application.",
		Fix:      "Always verify JWT signatures before trusting the payload. Use jwt.decode() with verify=True and specify the algorithm and secret/key.",
		CWE:      "CWE-345",
		OWASP:    "A08:2021-Software and Data Integrity Failures",
		Conf:     "high",
		RuleTags: []string{"jwt", "signature-bypass", "decode-without-verify"},
	},
	{
		RuleID:   "BATOU-JWT-009",
		RuleName: "JWTKidInjection",
		Desc:     "Detects JWT kid (Key ID) header values that contain injection payloads (SQL, path traversal, command injection), indicating the kid is used unsafely.",
		Sev:      rules.High,
		Langs:    jwtNoCSLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)["']kid["']\s*[=:]\s*(?:["'][^"']*(?:UNION|SELECT|OR|AND|\x27|--|;)[^"']*["']|.*(?:request\.|getParameter|params|query))`),
			regexp.MustCompile(`(?i)["']kid["']\s*[=:]\s*["'][^"']*(?:\.\.\/|/etc/|/dev/null|/proc/)[^"']*["']`),
			regexp.MustCompile(`(?i)["']kid["']\s*[=:]\s*["'][^"']*(?:\||;|` + "`" + `|\$\()[^"']*["']`),
		},
		Title:    "JWT kid header injection",
		FindDesc: "The JWT 'kid' (Key ID) header is used in a way vulnerable to injection. If kid is used in SQL queries, file paths, or shell commands without sanitization, attackers can exploit it for SQL injection, path traversal, or RCE.",
		Fix:      "Validate kid against an allowlist of known key IDs. Never use kid directly in SQL queries, file paths, or shell commands. Use a key lookup map instead.",
		CWE:      "CWE-89",
		OWASP:    "A03:2021-Injection",
		Conf:     "high",
		RuleTags: []string{"jwt", "kid-injection", "header-manipulation"},
	},
	{
		RuleID:   "BATOU-JWT-010",
		RuleName: "JWTLocalStorage",
		Desc:     "Detects JWT tokens stored in localStorage, which is accessible to any JavaScript on the page including XSS payloads.",
		Sev:      rules.Medium,
		Langs:    jwtFrontendLangs,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)localStorage\.setItem\s*\(\s*["'](?:token|jwt|access_token|id_token|auth_token|refreshToken|refresh_token)["']`),
			regexp.MustCompile(`(?i)localStorage\s*\[\s*["'](?:token|jwt|access_token|id_token|auth_token)["']\s*\]\s*=`),
		},
		Title:    "JWT token stored in localStorage",
		FindDesc: "JWT stored in localStorage is accessible to any JavaScript on the page. A single XSS vulnerability allows an attacker to steal the token and impersonate the user.",
		Fix:      "Store tokens in HttpOnly, Secure, SameSite cookies instead. If you must use localStorage, ensure robust XSS protection and consider token binding.",
		CWE:      "CWE-922",
		OWASP:    "A07:2021-Identification and Authentication Failures",
		Conf:     "high",
		RuleTags: []string{"jwt", "localstorage", "xss", "token-storage"},
	},
}
