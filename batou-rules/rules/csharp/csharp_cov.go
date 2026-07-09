package csharp

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// C# coverage-expansion rules (BATOU-CS-031 .. BATOU-CS-044)
//
// These close gaps in the reference-SAST coverage census where the detection is a
// *construction* or *configuration* pattern that fires on the .NET type/API
// name itself (no dataflow required). Every pattern is anchored on a concrete
// .NET framework type or member so it does not collide with generic
// bare-name code on other languages.
// ---------------------------------------------------------------------------

var (
	// CS-031: TLS certificate validation bypass (CWE-295).
	// The existing BATOU-CRY-024 only catches the `delegate { return true }`
	// form on ServicePointManager. These add the `=> true` lambda form and the
	// HttpClientHandler / WebRequestHandler / SocketsHttpHandler property, which
	// are the dominant modern-.NET shapes.
	reCertCallbackLambdaTrue = regexp.MustCompile(`(?:ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)\s*=\s*\(?[^)=]*\)?\s*=>\s*true\b`)
	// Assigning the DangerousAcceptAnyServerCertificateValidator sentinel.
	reCertDangerousAccept = regexp.MustCompile(`ServerCertificateCustomValidationCallback\s*=\s*HttpClientHandler\.DangerousAcceptAnyServerCertificateValidator`)
	// Inline single-statement lambda/delegate block whose body returns true.
	reCertCallbackBlockTrue = regexp.MustCompile(`(?:ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)\s*=\s*(?:\([^)]*\)|delegate\s*\([^)]*\))\s*(?:=>\s*)?\{[^}]*\breturn\s+true\s*;`)

	// CS-032: Weak symmetric cipher constructed by concrete .NET type name
	// (CWE-327). The language-agnostic crypto WeakCipher rule misses these
	// because `DESCryptoServiceProvider` has no word boundary after `DES`.
	reWeakCipherNet = regexp.MustCompile(`new\s+(?:DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider|RijndaelManaged)\s*\(`)
	// Factory form: DES.Create(), TripleDES.Create(), RC2.Create().
	reWeakCipherFactory = regexp.MustCompile(`\b(?:DES|TripleDES|RC2)\.Create\s*\(`)

	// CS-033: Weak hash constructed by concrete .NET type name (CWE-327/328).
	reWeakHashNet     = regexp.MustCompile(`new\s+(?:MD5CryptoServiceProvider|SHA1CryptoServiceProvider|SHA1Managed|MD5Managed|RIPEMD160Managed)\s*\(`)
	reWeakHashFactory = regexp.MustCompile(`\b(?:MD5|SHA1)\.Create\s*\(`)
	// HashAlgorithm.Create("MD5") / CryptoConfig.CreateFromName("SHA1").
	reWeakHashByName = regexp.MustCompile(`(?:HashAlgorithm|CryptoConfig)\.(?:Create|CreateFromName)\s*\(\s*["'](?:MD5|SHA1|SHA-1)["']`)
	// Don't flag non-security uses (checksums, ETags, cache keys, dedup, and
	// the Gravatar protocol which mandates MD5 of the email address).
	reHashNonSecurity = regexp.MustCompile(`(?i)(?:checksum|etag|cache\s*key|cachekey|dedup|content\s*hash|contenthash|file\s*hash|filehash|fingerprint|non[\s-]?crypto|gravatar)`)

	// CS-034: JWT validation weakened (CWE-347 signature, CWE-613 expiry).
	reJwtNoSignedTokens  = regexp.MustCompile(`RequireSignedTokens\s*=\s*false`)
	reJwtCustomSigValid  = regexp.MustCompile(`SignatureValidator\s*=\s*\(?[^)]*\)?\s*=>`)
	reJwtNoLifetime      = regexp.MustCompile(`ValidateLifetime\s*=\s*false`)
	reJwtNoExpiry        = regexp.MustCompile(`RequireExpirationTime\s*=\s*false`)
	reJwtNoIssuerSignKey = regexp.MustCompile(`ValidateIssuerSigningKey\s*=\s*false`)
	// Anchor: only inside a TokenValidationParameters / JwtBearer context.
	reTokenValidationCtx = regexp.MustCompile(`TokenValidationParameters|JwtBearerOptions`)

	// CS-035: ASP.NET Core CORS reflective allow-all (CWE-942).
	// CS-010 already covers AllowAnyOrigin()+AllowCredentials(); this adds the
	// SetIsOriginAllowed(_ => true) reflective-origin bypass.
	reCorsSetIsOriginAllowedTrue = regexp.MustCompile(`SetIsOriginAllowed\s*\(\s*(?:_|[A-Za-z_]\w*|\([^)]*\))\s*=>\s*true\s*\)`)

	// CS-036: Missing HSTS in the ASP.NET Core request pipeline (CWE-346).
	reUseHttpsRedirection = regexp.MustCompile(`\.UseHttpsRedirection\s*\(`)
	reUseHsts             = regexp.MustCompile(`\.UseHsts\s*\(`)
	reAddHsts             = regexp.MustCompile(`\.AddHsts\s*\(`)
	reConfigurePipeline   = regexp.MustCompile(`(?:IApplicationBuilder|WebApplication)\b|public\s+void\s+Configure\s*\(`)

	// CS-037: Directory browsing enabled (CWE-548).
	reUseDirectoryBrowser = regexp.MustCompile(`\.UseDirectoryBrowser\s*\(`)

	// CS-038: Account lockout disabled (CWE-307).
	reLockoutMaxZero     = regexp.MustCompile(`(?:Lockout\.)?MaxFailedAccessAttempts\s*=\s*0\b`)
	reLockoutNewUsersOff = regexp.MustCompile(`(?:Lockout\.)?AllowedForNewUsers\s*=\s*false`)

	// CS-039: .NET Remoting TypeFilterLevel.Full polymorphic deserialization (CWE-502).
	reTypeFilterFull = regexp.MustCompile(`TypeFilterLevel\s*=\s*TypeFilterLevel\.Full`)

	// CS-040: HttpListener bound to a wildcard prefix (CWE-706).
	reHttpListenerWildcard = regexp.MustCompile(`\.Prefixes\.Add\s*\(\s*\$?["']https?://(?:\+|\*):`)

	// CS-041: web.config <compilation debug="true"> (CWE-11).
	reCompilationDebug = regexp.MustCompile(`(?i)<compilation\b[^>]*\bdebug\s*=\s*["']true["']`)

	// CS-042: web.config <trace enabled="true" localOnly="false"> (CWE-1323).
	reTraceEnabled   = regexp.MustCompile(`(?i)<trace\b[^>]*\benabled\s*=\s*["']true["']`)
	reTraceLocalOnly = regexp.MustCompile(`(?i)localOnly\s*=\s*["']false["']`)

	// CS-043: X509Certificate2 loaded with a hardcoded PFX/key password (CWE-310).
	reX509HardcodedPw = regexp.MustCompile(`new\s+X509Certificate2\s*\(\s*[^,)]+,\s*["'][^"']{3,}["']`)

	// CS-044: X509 chain build result ignored / verification flags disabled (CWE-295).
	reX509VerifyNoFlag   = regexp.MustCompile(`VerificationFlags\s*=\s*X509VerificationFlags\.(?:AllFlags|IgnoreInvalidName|IgnoreCertificateAuthorityRevocationUnknown|IgnoreRootRevocationUnknown|IgnoreEndRevocationUnknown|IgnoreInvalidBasicConstraints|IgnoreWrongUsage|IgnoreInvalidPolicy|IgnoreNotTimeValid)`)
	reX509RevocationNone = regexp.MustCompile(`RevocationMode\s*=\s*X509RevocationMode\.NoCheck`)

	// CS-045: DataContractSerializer constructed with a custom resolver (CWE-502).
	// Default DataContractSerializer use is safe (fixed contract); the danger is
	// a custom DataContractResolver / KnownTypeResolver that resolves
	// attacker-named types. Anchor on the resolver-carrying construction.
	reDataContractCustomResolver = regexp.MustCompile(`new\s+DataContractSerializer\s*\(.*(?:DataContractResolver|KnownTypeResolver)`)

	// CS-046: RSA encryption with PKCS#1 v1.5 padding (CWE-780). The padding mode
	// argument distinguishes vulnerable PKCS#1 from secure OAEP, so this is a
	// regex rule (the structural taint engine keys only on method name and can't
	// see the padding constant). Matches the explicit Pkcs1 enum and the legacy
	// `Encrypt(data, false)` (fOAEP=false) overload.
	reRsaPkcs1Padding = regexp.MustCompile(`\.Encrypt\s*\(\s*[A-Za-z_][\w.\[\]]*\s*,\s*(?:RSAEncryptionPadding\.Pkcs1|false)\s*\)`)
)

func init() {
	rules.Register(&CSharpCertValidationBypass{})
	rules.Register(&CSharpWeakSymmetricCipher{})
	rules.Register(&CSharpWeakHashAlgorithm{})
	rules.Register(&CSharpJwtValidationWeakened{})
	rules.Register(&CSharpCorsReflectiveAllowAll{})
	rules.Register(&CSharpMissingHsts{})
	rules.Register(&CSharpDirectoryBrowsing{})
	rules.Register(&CSharpLockoutDisabled{})
	rules.Register(&CSharpRemotingTypeFilterFull{})
	rules.Register(&CSharpHttpListenerWildcard{})
	rules.Register(&CSharpWebConfigDebug{})
	rules.Register(&CSharpWebConfigTrace{})
	rules.Register(&CSharpX509HardcodedPassword{})
	rules.Register(&CSharpX509ChainNotValidated{})
	rules.Register(&CSharpDataContractCustomResolver{})
	rules.Register(&CSharpRsaPkcs1Padding{})
}

var (
	reCertPropAssign        = regexp.MustCompile(`(?:ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)\s*(?:=|\+=)\s*[A-Za-z_]\w*\s*;`)
	reMethodReturnsTrueOnly = regexp.MustCompile(`(?s)\bbool\s+\w+\s*\([^)]*X509Certificate[^)]*\)\s*\{\s*return\s+true\s*;\s*\}`)
)

// assignsBareTrueValidator detects a cert-callback property assigned a named
// method whose body in the same file is just `return true;` — a common
// cert-bypass shape that lambda regexes miss. Strict (both signals required).
func assignsBareTrueValidator(content string, propRe *regexp.Regexp) bool {
	if !propRe.MatchString(content) {
		return false
	}
	return reMethodReturnsTrueOnly.MatchString(content)
}

func csTrim(line string) string { return strings.TrimSpace(line) }

// ---------------------------------------------------------------------------
// BATOU-CS-031: TLS certificate validation bypass
// ---------------------------------------------------------------------------

type CSharpCertValidationBypass struct{}

func (r *CSharpCertValidationBypass) ID() string                      { return "BATOU-CS-031" }
func (r *CSharpCertValidationBypass) Name() string                    { return "CSharpCertValidationBypass" }
func (r *CSharpCertValidationBypass) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CSharpCertValidationBypass) Description() string {
	return "Detects TLS server-certificate validation bypass in C# via a callback that always returns true (=> true lambda, return-true block, or DangerousAcceptAnyServerCertificateValidator) on ServicePointManager/HttpClientHandler."
}
func (r *CSharpCertValidationBypass) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpCertValidationBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	namedBypass := assignsBareTrueValidator(ctx.Content, reCertPropAssign)

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		switch {
		case rules.GMatchLower(reCertDangerousAccept, line, lowered[i]):
			matched = rules.GFindLower(reCertDangerousAccept, line, lowered[i])
		case rules.GMatchLower(reCertCallbackLambdaTrue, line, lowered[i]):
			matched = rules.GFindLower(reCertCallbackLambdaTrue, line, lowered[i])
		case rules.GMatchLower(reCertCallbackBlockTrue, line, lowered[i]):
			matched = rules.GFindLower(reCertCallbackBlockTrue, line, lowered[i])
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "TLS certificate validation disabled (callback always returns true)",
			Description:   "A server-certificate validation callback that unconditionally returns true accepts ANY certificate, including self-signed and attacker-controlled ones. This silently defeats TLS and enables man-in-the-middle attacks.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(matched, 120),
			Suggestion:    "Remove the override and let the platform validate certificates, or implement real validation (check the chain status, SslPolicyErrors == None, and pin the expected certificate/thumbprint).",
			CWEID:         "CWE-295",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "tls", "certificate", "mitm"},
		})
	}

	if namedBypass {
		for i, line := range lines {
			if isCommentLine(line) {
				continue
			}
			if rules.GMatchLower(reCertPropAssign, line, lowered[i]) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "TLS certificate validation disabled (validator method returns true)",
					Description:   "The certificate-validation callback is assigned a method whose body unconditionally returns true, accepting any certificate and enabling man-in-the-middle attacks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(csTrim(line), 120),
					Suggestion:    "Implement real validation in the callback (verify SslPolicyErrors and the certificate chain) or remove the override.",
					CWEID:         "CWE-295",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"csharp", "tls", "certificate", "mitm"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-032: Weak symmetric cipher (concrete .NET types)
// ---------------------------------------------------------------------------

type CSharpWeakSymmetricCipher struct{}

func (r *CSharpWeakSymmetricCipher) ID() string                      { return "BATOU-CS-032" }
func (r *CSharpWeakSymmetricCipher) Name() string                    { return "CSharpWeakSymmetricCipher" }
func (r *CSharpWeakSymmetricCipher) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpWeakSymmetricCipher) Description() string {
	return "Detects construction of deprecated/weak .NET symmetric ciphers (DES/TripleDES/RC2 ServiceProviders, RijndaelManaged, DES.Create)."
}
func (r *CSharpWeakSymmetricCipher) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpWeakSymmetricCipher) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched, detail string
		if m := rules.GFindLower(reWeakCipherNet, line, lowered[i]); m != "" {
			matched = m
			detail = "Constructs a deprecated/weak symmetric cipher type. DES/RC2 are 64-bit-block ciphers broken by brute force/birthday attacks; TripleDES has known weaknesses; RijndaelManaged permits non-standard block sizes incompatible with AES."
		} else if m := rules.GFindLower(reWeakCipherFactory, line, lowered[i]); m != "" {
			matched = m
			detail = "DES/TripleDES/RC2.Create() instantiates a deprecated weak symmetric cipher."
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak symmetric cipher: " + truncate(matched, 60),
			Description:   detail,
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(matched, 120),
			Suggestion:    "Use Aes.Create() (or AesGcm for authenticated encryption). Avoid DES, TripleDES, RC2, and RijndaelManaged.",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "crypto", "weak-cipher"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-033: Weak hash algorithm (concrete .NET types)
// ---------------------------------------------------------------------------

type CSharpWeakHashAlgorithm struct{}

func (r *CSharpWeakHashAlgorithm) ID() string                      { return "BATOU-CS-033" }
func (r *CSharpWeakHashAlgorithm) Name() string                    { return "CSharpWeakHashAlgorithm" }
func (r *CSharpWeakHashAlgorithm) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpWeakHashAlgorithm) Description() string {
	return "Detects use of MD5/SHA1 via concrete .NET types (MD5.Create, SHA1.Create, MD5CryptoServiceProvider, SHA1Managed, HashAlgorithm.Create(\"MD5\")) for security-relevant hashing."
}
func (r *CSharpWeakHashAlgorithm) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpWeakHashAlgorithm) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	// File-level non-security context: a Gravatar helper mandates MD5 of the
	// email by the Gravatar protocol (not a security weakness). Recognize it by
	// the conventional file/class name so the per-line filter does not have to.
	if reHashNonSecurity.MatchString(ctx.FilePath) {
		return nil
	}
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		if m := rules.GFindLower(reWeakHashNet, line, lowered[i]); m != "" {
			matched = m
		} else if m := rules.GFindLower(reWeakHashFactory, line, lowered[i]); m != "" {
			matched = m
		} else if m := rules.GFindLower(reWeakHashByName, line, lowered[i]); m != "" {
			matched = m
		}
		if matched == "" {
			continue
		}
		// Suppress non-security uses (checksums, ETags, cache keys) nearby.
		if hasNearbySafe(lines, i, reHashNonSecurity) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak hash algorithm (MD5/SHA1): " + truncate(matched, 50),
			Description:   "MD5 and SHA-1 are cryptographically broken (practical collisions). Using them for signatures, integrity verification, password hashing, or token derivation is insecure.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(matched, 120),
			Suggestion:    "Use SHA-256/SHA-384/SHA-512 for integrity, or a password hashing KDF (PBKDF2/Rfc2898DeriveBytes, Argon2, scrypt) for passwords. If the hash is a non-security checksum, name it accordingly.",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"csharp", "crypto", "weak-hash"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-034: JWT validation weakened
// ---------------------------------------------------------------------------

type CSharpJwtValidationWeakened struct{}

func (r *CSharpJwtValidationWeakened) ID() string                      { return "BATOU-CS-034" }
func (r *CSharpJwtValidationWeakened) Name() string                    { return "CSharpJwtValidationWeakened" }
func (r *CSharpJwtValidationWeakened) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpJwtValidationWeakened) Description() string {
	return "Detects JWT validation weakened in TokenValidationParameters: RequireSignedTokens=false, a custom always-accept SignatureValidator, ValidateLifetime=false, RequireExpirationTime=false, or ValidateIssuerSigningKey=false."
}
func (r *CSharpJwtValidationWeakened) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpJwtValidationWeakened) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Anchor: only run when the file configures token validation.
	if !rules.GMatchFile(reTokenValidationCtx, ctx) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched, detail, cwe string
		switch {
		case rules.GMatchLower(reJwtNoSignedTokens, line, lowered[i]):
			matched, cwe = rules.GFindLower(reJwtNoSignedTokens, line, lowered[i]), "CWE-347"
			detail = "RequireSignedTokens = false lets the handler accept unsigned (alg=none-style) tokens, allowing forged identities."
		case rules.GMatchLower(reJwtCustomSigValid, line, lowered[i]):
			matched, cwe = rules.GFindLower(reJwtCustomSigValid, line, lowered[i]), "CWE-347"
			detail = "A custom SignatureValidator delegate replaces real signature verification. If it returns a token without validating the signature, any token is accepted."
		case rules.GMatchLower(reJwtNoIssuerSignKey, line, lowered[i]):
			matched, cwe = rules.GFindLower(reJwtNoIssuerSignKey, line, lowered[i]), "CWE-347"
			detail = "ValidateIssuerSigningKey = false skips verification that the signing key is trusted."
		case rules.GMatchLower(reJwtNoLifetime, line, lowered[i]):
			matched, cwe = rules.GFindLower(reJwtNoLifetime, line, lowered[i]), "CWE-613"
			detail = "ValidateLifetime = false means expired tokens are accepted indefinitely."
		case rules.GMatchLower(reJwtNoExpiry, line, lowered[i]):
			matched, cwe = rules.GFindLower(reJwtNoExpiry, line, lowered[i]), "CWE-613"
			detail = "RequireExpirationTime = false allows tokens with no expiry to be accepted."
		}
		if matched == "" {
			continue
		}
		sev := rules.High
		if cwe == "CWE-613" {
			sev = rules.Medium
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      sev,
			SeverityLabel: sev.String(),
			Title:         "JWT validation weakened: " + truncate(matched, 50),
			Description:   detail,
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(csTrim(line), 120),
			Suggestion:    "Keep RequireSignedTokens, ValidateIssuerSigningKey, ValidateLifetime, and RequireExpirationTime at their secure (true) defaults; never supply a SignatureValidator that skips verification.",
			CWEID:         cwe,
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "jwt", "authentication"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-035: CORS reflective allow-all (SetIsOriginAllowed(_ => true))
// ---------------------------------------------------------------------------

type CSharpCorsReflectiveAllowAll struct{}

func (r *CSharpCorsReflectiveAllowAll) ID() string                      { return "BATOU-CS-035" }
func (r *CSharpCorsReflectiveAllowAll) Name() string                    { return "CSharpCorsReflectiveAllowAll" }
func (r *CSharpCorsReflectiveAllowAll) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpCorsReflectiveAllowAll) Description() string {
	return "Detects an ASP.NET Core CORS policy that reflects any origin via SetIsOriginAllowed(_ => true), which is equivalent to AllowAnyOrigin but also works with credentials."
}
func (r *CSharpCorsReflectiveAllowAll) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpCorsReflectiveAllowAll) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		m := rules.GFindLower(reCorsSetIsOriginAllowedTrue, line, lowered[i])
		if m == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "CORS reflects any origin: SetIsOriginAllowed(_ => true)",
			Description:   "SetIsOriginAllowed(_ => true) tells ASP.NET Core to echo back any caller's Origin as an allowed origin. Combined with AllowCredentials() this exposes authenticated endpoints to every website.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(m, 120),
			Suggestion:    "Validate origins against an explicit allowlist: WithOrigins(\"https://trusted.example\") or SetIsOriginAllowed(o => allowed.Contains(o)).",
			CWEID:         "CWE-942",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "cors", "aspnetcore"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-036: Missing HSTS in the ASP.NET Core pipeline
// ---------------------------------------------------------------------------

type CSharpMissingHsts struct{}

func (r *CSharpMissingHsts) ID() string                      { return "BATOU-CS-036" }
func (r *CSharpMissingHsts) Name() string                    { return "CSharpMissingHsts" }
func (r *CSharpMissingHsts) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpMissingHsts) Description() string {
	return "Detects an ASP.NET Core pipeline that enables HTTPS redirection but never adds HSTS (UseHsts/AddHsts), leaving the first request downgradeable."
}
func (r *CSharpMissingHsts) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpMissingHsts) Scan(ctx *rules.ScanContext) []rules.Finding {
	content := ctx.Content
	if !reConfigurePipeline.MatchString(content) {
		return nil
	}
	if !reUseHttpsRedirection.MatchString(content) {
		return nil
	}
	if reUseHsts.MatchString(content) || reAddHsts.MatchString(content) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if !rules.GMatchLower(reUseHttpsRedirection, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Missing HSTS (UseHttpsRedirection without UseHsts)",
			Description:   "The pipeline enables HTTPS redirection but never calls UseHsts(). Without HSTS, a browser's first (or any cleartext) request can be intercepted and downgraded before the redirect, enabling SSL-stripping man-in-the-middle attacks.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(csTrim(line), 120),
			Suggestion:    "Add app.UseHsts() (guarded for non-development) alongside UseHttpsRedirection, and configure services.AddHsts(...) with an appropriate MaxAge.",
			CWEID:         "CWE-346",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"csharp", "aspnetcore", "hsts", "tls"},
		})
		break // one finding per file is enough
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-037: Directory browsing enabled
// ---------------------------------------------------------------------------

type CSharpDirectoryBrowsing struct{}

func (r *CSharpDirectoryBrowsing) ID() string                      { return "BATOU-CS-037" }
func (r *CSharpDirectoryBrowsing) Name() string                    { return "CSharpDirectoryBrowsing" }
func (r *CSharpDirectoryBrowsing) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpDirectoryBrowsing) Description() string {
	return "Detects app.UseDirectoryBrowser() which exposes a browseable listing of static-file directories."
}
func (r *CSharpDirectoryBrowsing) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpDirectoryBrowsing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		m := rules.GFindLower(reUseDirectoryBrowser, line, lowered[i])
		if m == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Directory browsing enabled (UseDirectoryBrowser)",
			Description:   "UseDirectoryBrowser() serves a browseable index of the configured directory. This can disclose file names, backup files, and resources that were never meant to be enumerated.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(csTrim(line), 120),
			Suggestion:    "Remove UseDirectoryBrowser() in production, or restrict it to a specific non-sensitive path and protect it with authorization.",
			CWEID:         "CWE-548",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "aspnetcore", "information-disclosure"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-038: Account lockout disabled
// ---------------------------------------------------------------------------

type CSharpLockoutDisabled struct{}

func (r *CSharpLockoutDisabled) ID() string                      { return "BATOU-CS-038" }
func (r *CSharpLockoutDisabled) Name() string                    { return "CSharpLockoutDisabled" }
func (r *CSharpLockoutDisabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpLockoutDisabled) Description() string {
	return "Detects ASP.NET Core Identity lockout disabled (MaxFailedAccessAttempts = 0 or Lockout.AllowedForNewUsers = false), removing brute-force protection."
}
func (r *CSharpLockoutDisabled) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpLockoutDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Anchor on an Identity/lockout-configuration context to avoid matching an
	// unrelated `MaxFailedAccessAttempts = 0` field somewhere else.
	if !strings.Contains(ctx.Content, "Lockout") && !strings.Contains(ctx.Content, "IdentityOptions") {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched, detail string
		if m := rules.GFindLower(reLockoutMaxZero, line, lowered[i]); m != "" {
			matched = m
			detail = "MaxFailedAccessAttempts = 0 means an account is never locked, allowing unlimited password-guessing attempts."
		} else if m := rules.GFindLower(reLockoutNewUsersOff, line, lowered[i]); m != "" {
			matched = m
			detail = "Lockout.AllowedForNewUsers = false disables lockout for newly created accounts, the most commonly targeted ones."
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Account lockout disabled: " + truncate(matched, 50),
			Description:   detail,
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(csTrim(line), 120),
			Suggestion:    "Set a positive MaxFailedAccessAttempts (e.g. 5), keep Lockout.AllowedForNewUsers = true, and configure DefaultLockoutTimeSpan.",
			CWEID:         "CWE-307",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"csharp", "aspnetcore", "identity", "brute-force"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-039: .NET Remoting TypeFilterLevel.Full
// ---------------------------------------------------------------------------

type CSharpRemotingTypeFilterFull struct{}

func (r *CSharpRemotingTypeFilterFull) ID() string                      { return "BATOU-CS-039" }
func (r *CSharpRemotingTypeFilterFull) Name() string                    { return "CSharpRemotingTypeFilterFull" }
func (r *CSharpRemotingTypeFilterFull) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpRemotingTypeFilterFull) Description() string {
	return "Detects .NET Remoting/WCF formatter TypeFilterLevel.Full, which enables full polymorphic (gadget-chain) deserialization of untrusted payloads."
}
func (r *CSharpRemotingTypeFilterFull) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpRemotingTypeFilterFull) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if !rules.GMatchLower(reTypeFilterFull, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Remoting formatter TypeFilterLevel.Full (unsafe deserialization)",
			Description:   "TypeFilterLevel.Full on a BinaryServerFormatterSinkProvider (or remoting formatter) permits deserialization of arbitrary object graphs over the channel, exposing the well-known BinaryFormatter gadget chains to remote code execution.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(csTrim(line), 120),
			Suggestion:    "Leave TypeFilterLevel at the default Low, and migrate away from .NET Remoting/BinaryFormatter to a contract-based serializer with an allowlist of types.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "deserialization", "remoting"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-040: HttpListener wildcard prefix
// ---------------------------------------------------------------------------

type CSharpHttpListenerWildcard struct{}

func (r *CSharpHttpListenerWildcard) ID() string                      { return "BATOU-CS-040" }
func (r *CSharpHttpListenerWildcard) Name() string                    { return "CSharpHttpListenerWildcard" }
func (r *CSharpHttpListenerWildcard) DefaultSeverity() rules.Severity { return rules.Low }
func (r *CSharpHttpListenerWildcard) Description() string {
	return "Detects HttpListener bound to a wildcard prefix (http://+:port/ or http://*:port/), exposing the service on all interfaces, often over cleartext HTTP."
}
func (r *CSharpHttpListenerWildcard) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpHttpListenerWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		m := rules.GFindLower(reHttpListenerWildcard, line, lowered[i])
		if m == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "HttpListener bound to wildcard prefix",
			Description:   "Adding a wildcard prefix (http://+ or http://*) makes the HttpListener accept connections on every network interface. If unintended, this exposes an internal/admin service to the whole network, frequently over unencrypted HTTP.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(m, 120),
			Suggestion:    "Bind to a specific host (http://localhost:port/ or a fixed internal IP) and use HTTPS. Only use a wildcard prefix when the service is genuinely meant to be reachable on all interfaces.",
			CWEID:         "CWE-706",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"csharp", "network", "exposure"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-041: web.config compilation debug="true"
// ---------------------------------------------------------------------------

type CSharpWebConfigDebug struct{}

func (r *CSharpWebConfigDebug) ID() string                      { return "BATOU-CS-041" }
func (r *CSharpWebConfigDebug) Name() string                    { return "CSharpWebConfigDebug" }
func (r *CSharpWebConfigDebug) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpWebConfigDebug) Description() string {
	return "Detects <compilation debug=\"true\"> in an ASP.NET web.config, which disables optimizations and leaks debug symbols in production."
}
func (r *CSharpWebConfigDebug) Languages() []rules.Language {
	// .config / .xml files are detected as LangAny; gate body on the path.
	return []rules.Language{rules.LangCSharp, rules.LangAny}
}

func (r *CSharpWebConfigDebug) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isWebConfigPath(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		m := rules.GFindLower(reCompilationDebug, line, lowered[i])
		if m == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "web.config compilation debug=\"true\"",
			Description:   "<compilation debug=\"true\"> ships a debug build to production: it disables compiler optimizations, generates verbose error output, and can leak source paths and symbols. It also degrades performance and may bypass request timeouts.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(csTrim(line), 120),
			Suggestion:    "Set debug=\"false\" for production builds (or strip the attribute and rely on the retail switch / deployment transform).",
			CWEID:         "CWE-11",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "aspnet", "web.config", "misconfig"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-042: web.config trace enabled localOnly="false"
// ---------------------------------------------------------------------------

type CSharpWebConfigTrace struct{}

func (r *CSharpWebConfigTrace) ID() string                      { return "BATOU-CS-042" }
func (r *CSharpWebConfigTrace) Name() string                    { return "CSharpWebConfigTrace" }
func (r *CSharpWebConfigTrace) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpWebConfigTrace) Description() string {
	return "Detects <trace enabled=\"true\" localOnly=\"false\"> in web.config, which exposes ASP.NET trace.axd request data to remote users."
}
func (r *CSharpWebConfigTrace) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp, rules.LangAny}
}

func (r *CSharpWebConfigTrace) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isWebConfigPath(ctx.FilePath) {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if !rules.GMatchLower(reTraceEnabled, line, lowered[i]) {
			continue
		}
		// Require localOnly=false on the same element. If localOnly is absent it
		// defaults to true (safe), so we only flag the explicit remote case.
		if !rules.GMatchLower(reTraceLocalOnly, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "web.config trace enabled with localOnly=\"false\"",
			Description:   "<trace enabled=\"true\" localOnly=\"false\"> exposes trace.axd to remote clients, disclosing recent requests, headers, cookies, session state, and server variables.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(csTrim(line), 120),
			Suggestion:    "Disable tracing in production (enabled=\"false\") or at minimum keep localOnly=\"true\" so trace.axd is reachable only from the server itself.",
			CWEID:         "CWE-1323",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "aspnet", "web.config", "information-disclosure"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-043: X509Certificate2 with hardcoded password
// ---------------------------------------------------------------------------

type CSharpX509HardcodedPassword struct{}

func (r *CSharpX509HardcodedPassword) ID() string                      { return "BATOU-CS-043" }
func (r *CSharpX509HardcodedPassword) Name() string                    { return "CSharpX509HardcodedPassword" }
func (r *CSharpX509HardcodedPassword) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpX509HardcodedPassword) Description() string {
	return "Detects new X509Certificate2(..., \"hardcoded-password\") loading a PFX/private key with an inline literal password."
}
func (r *CSharpX509HardcodedPassword) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpX509HardcodedPassword) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		m := rules.GFindLower(reX509HardcodedPw, line, lowered[i])
		if m == "" {
			continue
		}
		// Skip empty-string placeholders (no real secret).
		if strings.Contains(m, `""`) || strings.Contains(m, "''") {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "X509Certificate2 loaded with hardcoded password",
			Description:   "Passing a literal password to the X509Certificate2 constructor embeds the PFX/private-key password in source. Anyone with the binary or repository can extract the key material.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(m, 120),
			Suggestion:    "Load the certificate password from a secret store (Azure Key Vault, environment variable, DPAPI), and prefer X509KeyStorageFlags / the certificate store over inline PFX passwords.",
			CWEID:         "CWE-310",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"csharp", "crypto", "secrets", "certificate"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-044: X509 chain verification disabled
// ---------------------------------------------------------------------------

type CSharpX509ChainNotValidated struct{}

func (r *CSharpX509ChainNotValidated) ID() string                      { return "BATOU-CS-044" }
func (r *CSharpX509ChainNotValidated) Name() string                    { return "CSharpX509ChainNotValidated" }
func (r *CSharpX509ChainNotValidated) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpX509ChainNotValidated) Description() string {
	return "Detects X509Chain verification weakened via X509ChainPolicy.VerificationFlags (Ignore*/AllFlags) or RevocationMode = NoCheck."
}
func (r *CSharpX509ChainNotValidated) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpX509ChainNotValidated) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched, detail string
		if m := rules.GFindLower(reX509VerifyNoFlag, line, lowered[i]); m != "" {
			matched = m
			detail = "X509ChainPolicy.VerificationFlags is set to ignore validation errors (AllFlags or an Ignore* flag), so the chain build will succeed even for invalid, expired, or untrusted certificates."
		} else if m := rules.GFindLower(reX509RevocationNone, line, lowered[i]); m != "" {
			matched = m
			detail = "X509RevocationMode.NoCheck disables CRL/OCSP revocation checking, so revoked certificates are still accepted."
		}
		if matched == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "X509 chain verification weakened: " + truncate(matched, 50),
			Description:   detail,
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(csTrim(line), 120),
			Suggestion:    "Leave VerificationFlags at NoFlag-free defaults and use RevocationMode.Online; explicitly handle X509Chain.Build()==false and inspect ChainStatus instead of suppressing errors.",
			CWEID:         "CWE-295",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"csharp", "tls", "certificate", "x509"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-045: DataContractSerializer with a custom resolver
// ---------------------------------------------------------------------------

type CSharpDataContractCustomResolver struct{}

func (r *CSharpDataContractCustomResolver) ID() string   { return "BATOU-CS-045" }
func (r *CSharpDataContractCustomResolver) Name() string { return "CSharpDataContractCustomResolver" }
func (r *CSharpDataContractCustomResolver) DefaultSeverity() rules.Severity {
	return rules.High
}
func (r *CSharpDataContractCustomResolver) Description() string {
	return "Detects DataContractSerializer/DataContractSerializer constructed with a custom DataContractResolver or KnownTypeResolver, which resolves arbitrary attacker-named types during deserialization."
}
func (r *CSharpDataContractCustomResolver) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpDataContractCustomResolver) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		m := rules.GFindLower(reDataContractCustomResolver, line, lowered[i])
		if m == "" {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "DataContractSerializer with custom type resolver",
			Description:   "A DataContractSerializer constructed with a custom DataContractResolver/KnownTypeResolver resolves types by attacker-supplied name during ReadObject. A resolver that returns arbitrary Types reintroduces the polymorphic type-confusion deserialization risk the contract model was meant to prevent.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(m, 120),
			Suggestion:    "Use DataContractSerializer with a fixed, explicit set of known types (the knownTypes constructor argument) and avoid a resolver that maps arbitrary names to Types. If a resolver is required, restrict it to an allowlist.",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"csharp", "deserialization", "datacontract"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-CS-046: RSA encryption with PKCS#1 v1.5 padding
// ---------------------------------------------------------------------------

type CSharpRsaPkcs1Padding struct{}

func (r *CSharpRsaPkcs1Padding) ID() string                      { return "BATOU-CS-046" }
func (r *CSharpRsaPkcs1Padding) Name() string                    { return "CSharpRsaPkcs1Padding" }
func (r *CSharpRsaPkcs1Padding) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpRsaPkcs1Padding) Description() string {
	return "Detects RSA.Encrypt with PKCS#1 v1.5 padding (RSAEncryptionPadding.Pkcs1 or the fOAEP=false overload), which is vulnerable to Bleichenbacher padding-oracle attacks."
}
func (r *CSharpRsaPkcs1Padding) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpRsaPkcs1Padding) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		m := rules.GFindLower(reRsaPkcs1Padding, line, lowered[i])
		if m == "" {
			continue
		}
		// Anchor to an RSA context so a generic `.Encrypt(x, false)` on an
		// unrelated API does not match: require an RSA/Pkcs1 token on the line.
		if !strings.Contains(line, "RSAEncryptionPadding.Pkcs1") &&
			!strings.Contains(line, "rsa.Encrypt") && !strings.Contains(line, "Rsa.Encrypt") &&
			!strings.Contains(line, "RSA.Encrypt") && !strings.Contains(line, "_rsa.Encrypt") {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "RSA encryption with PKCS#1 v1.5 padding",
			Description:   "RSA.Encrypt with RSAEncryptionPadding.Pkcs1 (or the legacy fOAEP=false overload) uses PKCS#1 v1.5 padding, which is susceptible to Bleichenbacher / padding-oracle chosen-ciphertext attacks that can recover plaintext or forge signatures.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(m, 120),
			Suggestion:    "Use OAEP padding: rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256).",
			CWEID:         "CWE-780",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"csharp", "crypto", "rsa", "padding"},
		})
	}
	return findings
}

// isWebConfigPath reports whether the path is an ASP.NET .config file that can
// contain <compilation>/<trace> elements.
func isWebConfigPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".config")
}
