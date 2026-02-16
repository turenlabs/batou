package crypto

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended crypto rules
// ---------------------------------------------------------------------------

// GTSS-CRY-019: ECB mode encryption (no diffusion)
var (
	reECBModeGo     = regexp.MustCompile(`cipher\.NewCBCEncrypter|cipher\.NewCBCDecrypter`)
	reECBModeJava   = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["']AES/ECB`)
	reECBModePy     = regexp.MustCompile(`(?:AES\.MODE_ECB|mode\s*=\s*['"]ECB['"])`)
	reECBModeJS     = regexp.MustCompile(`createCipher(?:iv)?\s*\(\s*['"]aes-\d+-ecb['"]`)
	reECBModeCSharp = regexp.MustCompile(`(?:CipherMode\.ECB|Mode\s*=\s*CipherMode\.ECB)`)
	reECBModeGeneric = regexp.MustCompile(`(?i)\bECB\b.*(?i)(?:cipher|encrypt|aes|block|mode)`)
)

// GTSS-CRY-020: Static/hardcoded IV/nonce
var (
	reStaticIVAllZero  = regexp.MustCompile(`(?i)\b(?:iv|nonce|initialization.?vector)\s*[:=]\s*(?:\[\]byte\s*\{(?:\s*0\s*,?\s*){4,}|b?["']\\x00|bytes\s*\(\s*(?:16|12|8)\s*\)|new\s+byte\s*\[\s*(?:16|12|8)\s*\])`)
	reStaticIVRepeat   = regexp.MustCompile(`(?i)\b(?:iv|nonce)\s*[:=]\s*(?:\[\]byte\s*\{\s*(?:0x[0-9a-fA-F]{2}\s*,\s*){3,}|b?["'][^"']{8,}["'])`)
	reIVFromConst      = regexp.MustCompile(`(?i)\b(?:iv|nonce)\s*[:=]\s*(?:FIXED_|STATIC_|DEFAULT_|CONST_)`)
)

// GTSS-CRY-021: Weak key derivation
var (
	reWeakKDF          = regexp.MustCompile(`(?i)\b(?:key|encryption_key|aes_key|cipher_key|secret_key)\s*[:=]\s*(?:hashlib\.|md5\.|sha1\.|sha256\.|MessageDigest|crypto\.createHash|md5\.Sum|sha256\.Sum)`)
	reSimpleHashKey    = regexp.MustCompile(`(?i)(?:md5|sha1|sha256|sha512)\s*\(.*(?:password|passphrase|secret|key)\b`)
	reProperKDFPresent = regexp.MustCompile(`(?i)(?:pbkdf2|scrypt|argon2|hkdf|PBKDF2WithHmacSHA|Rfc2898DeriveBytes|bcrypt|key_derivation)`)
)

// GTSS-CRY-022: Insecure random for cryptographic use
var (
	reCryptoCtxRandom  = regexp.MustCompile(`(?i)(?:key|iv|nonce|salt|token|secret|session)\s*[:=]\s*(?:rand\.|random\.|Math\.random|mt_rand|array_rand|Random\.)`)
	reKeyGenMathRand   = regexp.MustCompile(`(?i)(?:generate|create|make|new).{0,20}(?:key|token|nonce|salt|iv|secret)\w*.*(?:rand\.|random\.|Math\.random|mt_rand)`)
)

// GTSS-CRY-023: RSA key size < 2048 bits
var (
	reRSASmallKeyPy   = regexp.MustCompile(`(?i)(?:RSA\.generate|rsa\.generate_private_key)\s*\(\s*(?:512|768|1024)\b`)
	reRSASmallKeyRuby = regexp.MustCompile(`(?i)OpenSSL::PKey::RSA\.(?:new|generate)\s*\(\s*(?:512|768|1024)\b`)
	reRSASmallKeyCSharp = regexp.MustCompile(`(?i)(?:RSACryptoServiceProvider|RSA\.Create)\s*\(\s*(?:512|768|1024)\b`)
	reRSASmallKeyJS   = regexp.MustCompile(`(?i)(?:modulusLength|key_size|keySize)\s*:\s*(?:512|768|1024)\b`)
)

// GTSS-CRY-024: Disabled certificate validation
var (
	reCertValidationOff = regexp.MustCompile(`(?i)(?:VERIFY_NONE|verify\s*(?:=|:)\s*(?:false|False|0)|CERT_NONE|SSL_VERIFY_NONE|ServerCertificateValidationCallback\s*=\s*\(\s*[^)]*\)\s*=>\s*true|checkServerIdentity\s*:\s*\(\)\s*=>\s*(?:undefined|null|true)|ServicePointManager\.ServerCertificateValidationCallback\s*=\s*delegate\s*\{?\s*return\s+true)`)
	reCurlInsecure     = regexp.MustCompile(`(?i)(?:CURLOPT_SSL_VERIFYPEER\s*(?:,|=>)\s*(?:false|0)|CURLOPT_SSL_VERIFYHOST\s*(?:,|=>)\s*(?:false|0))`)
	reHttpClientNoCert = regexp.MustCompile(`(?i)(?:SSLContext\.(?:getInstance|getDefault)|TrustAllCerts|AcceptAllCerts|NullHostnameVerifier|AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER)`)
)

// GTSS-CRY-025: Deprecated TLS version
var (
	reTLSv10Explicit = regexp.MustCompile(`(?i)(?:TLSv1(?:\.0)?|SSLv3|TLS_1_0|PROTOCOL_TLSv1(?:_0)?)\b`)
	reTLSv11Explicit = regexp.MustCompile(`(?i)(?:TLSv1\.1|TLS_1_1|PROTOCOL_TLSv1_1)\b`)
	reTLSContext     = regexp.MustCompile(`(?i)(?:ssl|tls|https|certificate|transport|secure|crypto)`)
	reMinVersionOld  = regexp.MustCompile(`(?i)(?:MinVersion|min_version|minVersion|minimum_version)\s*[:=]\s*(?:tls\.VersionTLS10|tls\.VersionTLS11|['"]TLSv1(?:\.0|\.1)?['"]|0x0301|0x0302|ssl\.PROTOCOL_TLSv1|TLS_1_0|TLS_1_1)`)
)

// GTSS-CRY-026: Null cipher / no encryption
var (
	reNullCipher     = regexp.MustCompile(`(?i)(?:eNULL|aNULL|NULL)\b.*(?:cipher|ssl|tls)`)
	reCipherNull     = regexp.MustCompile(`(?i)(?:cipher|ssl|tls).*(?:eNULL|aNULL|NULL)\b`)
	reTLSNoCipher    = regexp.MustCompile(`(?i)(?:cipher_suites|ciphers|ssl_ciphers|CipherSuites)\s*[:=]\s*(?:["']\s*["']|nil|\[\s*\]|null|None|"")`)
	reInsecureCipher = regexp.MustCompile(`(?i)(?:RC4|DES|NULL|EXPORT|anon)[-_].*(?:cipher|suite|ssl|tls)`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&ECBModeEncryption{})
	rules.Register(&StaticIVNonce{})
	rules.Register(&WeakKeyDerivation{})
	rules.Register(&InsecureRandomCrypto{})
	rules.Register(&RSASmallKeyBroad{})
	rules.Register(&DisabledCertValidation{})
	rules.Register(&DeprecatedTLSVersion{})
	rules.Register(&NullCipherTLS{})
}

// ---------------------------------------------------------------------------
// GTSS-CRY-019: ECB mode encryption (no diffusion)
// ---------------------------------------------------------------------------

type ECBModeEncryption struct{}

func (r *ECBModeEncryption) ID() string                     { return "GTSS-CRY-019" }
func (r *ECBModeEncryption) Name() string                   { return "ECBModeEncryption" }
func (r *ECBModeEncryption) DefaultSeverity() rules.Severity { return rules.High }
func (r *ECBModeEncryption) Description() string {
	return "Detects use of ECB (Electronic Codebook) mode for block cipher encryption, which does not provide diffusion and reveals patterns in encrypted data."
}
func (r *ECBModeEncryption) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangCSharp, rules.LangAny}
}

func (r *ECBModeEncryption) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	langPats := map[rules.Language][]*regexp.Regexp{
		rules.LangJava:       {reECBModeJava},
		rules.LangPython:     {reECBModePy},
		rules.LangJavaScript: {reECBModeJS},
		rules.LangTypeScript: {reECBModeJS},
		rules.LangCSharp:     {reECBModeCSharp},
	}

	pats := langPats[ctx.Language]
	pats = append(pats, reECBModeGeneric)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if isCommentCE(trimmed) {
			continue
		}
		for _, p := range pats {
			if m := p.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "ECB mode encryption (no diffusion)",
					Description: "ECB mode encrypts each block independently, preserving patterns in the plaintext. Identical plaintext blocks produce identical ciphertext blocks (the 'ECB penguin' problem), leaking data structure.",
					FilePath: ctx.FilePath, LineNumber: lineNum, MatchedText: truncateCE(trimmed, 120),
					Suggestion:    "Use AES-GCM or AES-CBC with HMAC. GCM provides both confidentiality and authenticity. Never use ECB mode for any purpose.",
					CWEID:         "CWE-327",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language: ctx.Language, Confidence: "high",
					Tags: []string{"crypto", "ecb", "block-cipher"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CRY-020: Static/hardcoded IV/nonce
// ---------------------------------------------------------------------------

type StaticIVNonce struct{}

func (r *StaticIVNonce) ID() string                     { return "GTSS-CRY-020" }
func (r *StaticIVNonce) Name() string                   { return "StaticIVNonce" }
func (r *StaticIVNonce) DefaultSeverity() rules.Severity { return rules.High }
func (r *StaticIVNonce) Description() string {
	return "Detects static, all-zero, or constant-derived initialization vectors and nonces, which make encryption deterministic and compromise security."
}
func (r *StaticIVNonce) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangCSharp, rules.LangRuby, rules.LangPHP, rules.LangAny}
}

func (r *StaticIVNonce) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reStaticIVAllZero, reStaticIVRepeat, reIVFromConst}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if isCommentCE(trimmed) {
			continue
		}
		for _, p := range pats {
			if m := p.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Static or hardcoded IV/nonce",
					Description: "A static, all-zero, or constant-derived IV/nonce makes encryption deterministic. For AES-GCM, nonce reuse is catastrophic (key recovery). For AES-CBC, it enables chosen-plaintext attacks.",
					FilePath: ctx.FilePath, LineNumber: lineNum, MatchedText: truncateCE(trimmed, 120),
					Suggestion:    "Generate a fresh random IV/nonce for each encryption operation using a CSPRNG. For AES-GCM, use 12-byte random nonces. For AES-CBC, use 16-byte random IVs.",
					CWEID:         "CWE-329",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language: ctx.Language, Confidence: "high",
					Tags: []string{"crypto", "iv", "nonce", "static"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CRY-021: Weak key derivation
// ---------------------------------------------------------------------------

type WeakKeyDerivation struct{}

func (r *WeakKeyDerivation) ID() string                     { return "GTSS-CRY-021" }
func (r *WeakKeyDerivation) Name() string                   { return "WeakKeyDerivation" }
func (r *WeakKeyDerivation) DefaultSeverity() rules.Severity { return rules.High }
func (r *WeakKeyDerivation) Description() string {
	return "Detects use of plain hash functions (MD5, SHA-1, SHA-256) to derive encryption keys from passwords instead of proper key derivation functions (PBKDF2, scrypt, Argon2, HKDF)."
}
func (r *WeakKeyDerivation) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp}
}

func (r *WeakKeyDerivation) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if proper KDF is present
	if reProperKDFPresent.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reWeakKDF, reSimpleHashKey}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if isCommentCE(trimmed) {
			continue
		}
		for _, p := range pats {
			if m := p.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Weak key derivation: hash used instead of KDF",
					Description: "Plain hash functions (MD5, SHA-256, etc.) are not suitable for deriving encryption keys from passwords. They are too fast (enabling brute-force) and lack salt support.",
					FilePath: ctx.FilePath, LineNumber: lineNum, MatchedText: truncateCE(trimmed, 120),
					Suggestion:    "Use PBKDF2, scrypt, or Argon2id for password-based key derivation. Use HKDF for deriving keys from other key material. These provide computational hardness and salt support.",
					CWEID:         "CWE-916",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language: ctx.Language, Confidence: "high",
					Tags: []string{"crypto", "kdf", "key-derivation"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CRY-022: Insecure random for cryptographic use
// ---------------------------------------------------------------------------

type InsecureRandomCrypto struct{}

func (r *InsecureRandomCrypto) ID() string                     { return "GTSS-CRY-022" }
func (r *InsecureRandomCrypto) Name() string                   { return "InsecureRandomCrypto" }
func (r *InsecureRandomCrypto) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureRandomCrypto) Description() string {
	return "Detects non-cryptographic random number generators used to generate cryptographic material (keys, IVs, nonces, salts, tokens)."
}
func (r *InsecureRandomCrypto) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp}
}

func (r *InsecureRandomCrypto) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reCryptoCtxRandom, reKeyGenMathRand}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if isCommentCE(trimmed) {
			continue
		}
		for _, p := range pats {
			if m := p.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Insecure random used for cryptographic material",
					Description: "Non-cryptographic PRNG (Math.random, random, mt_rand, etc.) used to generate keys, IVs, nonces, salts, or tokens. The output is predictable, making the cryptographic material weak.",
					FilePath: ctx.FilePath, LineNumber: lineNum, MatchedText: truncateCE(trimmed, 120),
					Suggestion:    "Use a CSPRNG: crypto/rand (Go), secrets (Python), crypto.randomBytes (Node.js), SecureRandom (Java/Ruby), random_bytes (PHP), RNGCryptoServiceProvider (C#).",
					CWEID:         "CWE-338",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language: ctx.Language, Confidence: "high",
					Tags: []string{"crypto", "random", "key-generation"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CRY-023: RSA key size < 2048 bits (broader)
// ---------------------------------------------------------------------------

type RSASmallKeyBroad struct{}

func (r *RSASmallKeyBroad) ID() string                     { return "GTSS-CRY-023" }
func (r *RSASmallKeyBroad) Name() string                   { return "RSASmallKeyBroad" }
func (r *RSASmallKeyBroad) DefaultSeverity() rules.Severity { return rules.High }
func (r *RSASmallKeyBroad) Description() string {
	return "Detects RSA key generation with key sizes less than 2048 bits across Python, Ruby, C#, and JavaScript/TypeScript, in addition to Go and Java covered by CRY-006."
}
func (r *RSASmallKeyBroad) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangRuby, rules.LangCSharp, rules.LangJavaScript, rules.LangTypeScript}
}

func (r *RSASmallKeyBroad) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	langPats := map[rules.Language][]*regexp.Regexp{
		rules.LangPython:     {reRSASmallKeyPy},
		rules.LangRuby:       {reRSASmallKeyRuby},
		rules.LangCSharp:     {reRSASmallKeyCSharp},
		rules.LangJavaScript: {reRSASmallKeyJS},
		rules.LangTypeScript: {reRSASmallKeyJS},
	}
	pats := langPats[ctx.Language]
	if len(pats) == 0 {
		return nil
	}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if isCommentCE(trimmed) {
			continue
		}
		for _, p := range pats {
			if m := p.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "RSA key size too small (< 2048 bits)",
					Description: "RSA keys smaller than 2048 bits can be factored with current computing resources. NIST recommends a minimum of 2048 bits, with 3072+ bits for long-term security.",
					FilePath: ctx.FilePath, LineNumber: lineNum, MatchedText: truncateCE(trimmed, 120),
					Suggestion:    "Use RSA-2048 or larger key sizes. For new applications, consider RSA-4096 or switch to elliptic curve cryptography (P-256 or Ed25519).",
					CWEID:         "CWE-326",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language: ctx.Language, Confidence: "high",
					Tags: []string{"crypto", "rsa", "key-size"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CRY-024: Disabled certificate validation
// ---------------------------------------------------------------------------

type DisabledCertValidation struct{}

func (r *DisabledCertValidation) ID() string                     { return "GTSS-CRY-024" }
func (r *DisabledCertValidation) Name() string                   { return "DisabledCertValidation" }
func (r *DisabledCertValidation) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *DisabledCertValidation) Description() string {
	return "Detects disabled TLS/SSL certificate validation across multiple languages and libraries, enabling man-in-the-middle attacks."
}
func (r *DisabledCertValidation) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp}
}

func (r *DisabledCertValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reCertValidationOff, reCurlInsecure, reHttpClientNoCert}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if isCommentCE(trimmed) {
			continue
		}
		for _, p := range pats {
			if m := p.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "TLS/SSL certificate validation disabled",
					Description: "Certificate validation is disabled, allowing connections to any server regardless of certificate validity. This enables man-in-the-middle attacks where an attacker can intercept, read, and modify all traffic.",
					FilePath: ctx.FilePath, LineNumber: lineNum, MatchedText: truncateCE(trimmed, 120),
					Suggestion:    "Enable certificate validation. If custom CA certificates are needed, configure a custom trust store instead of disabling validation entirely.",
					CWEID:         "CWE-295",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language: ctx.Language, Confidence: "high",
					Tags: []string{"crypto", "tls", "certificate-validation"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CRY-025: Deprecated TLS version (TLS 1.0/1.1)
// ---------------------------------------------------------------------------

type DeprecatedTLSVersion struct{}

func (r *DeprecatedTLSVersion) ID() string                     { return "GTSS-CRY-025" }
func (r *DeprecatedTLSVersion) Name() string                   { return "DeprecatedTLSVersion" }
func (r *DeprecatedTLSVersion) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DeprecatedTLSVersion) Description() string {
	return "Detects explicit use or configuration of deprecated TLS versions (TLS 1.0, TLS 1.1, SSLv3) which have known vulnerabilities."
}
func (r *DeprecatedTLSVersion) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp, rules.LangAny}
}

func (r *DeprecatedTLSVersion) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reMinVersionOld, reTLSv10Explicit, reTLSv11Explicit}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if isCommentCE(trimmed) {
			continue
		}
		for _, p := range pats {
			if m := p.FindString(line); m != "" {
				// Only flag TLS version references in TLS/SSL context
				if !reTLSContext.MatchString(line) && !reTLSContext.MatchString(nearbyLinesCE(lines, i, 5)) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Deprecated TLS version configured: " + m,
					Description: "TLS 1.0 and TLS 1.1 are deprecated by RFC 8996. They have known vulnerabilities (BEAST, POODLE, Lucky13) and should not be used. SSLv3 is completely broken.",
					FilePath: ctx.FilePath, LineNumber: lineNum, MatchedText: truncateCE(trimmed, 120),
					Suggestion:    "Set the minimum TLS version to 1.2. Prefer TLS 1.3 when supported. Remove any references to TLS 1.0, TLS 1.1, or SSLv3.",
					CWEID:         "CWE-326",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language: ctx.Language, Confidence: "high",
					Tags: []string{"crypto", "tls", "deprecated"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CRY-026: Null cipher / no encryption in TLS config
// ---------------------------------------------------------------------------

type NullCipherTLS struct{}

func (r *NullCipherTLS) ID() string                     { return "GTSS-CRY-026" }
func (r *NullCipherTLS) Name() string                   { return "NullCipherTLS" }
func (r *NullCipherTLS) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *NullCipherTLS) Description() string {
	return "Detects TLS/SSL configuration with NULL cipher suites, empty cipher lists, or known insecure cipher suites (EXPORT, anon, RC4), which provide no encryption."
}
func (r *NullCipherTLS) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp, rules.LangAny}
}

func (r *NullCipherTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reNullCipher, reCipherNull, reTLSNoCipher, reInsecureCipher}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if isCommentCE(trimmed) {
			continue
		}
		for _, p := range pats {
			if m := p.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Null cipher or insecure cipher suite in TLS configuration",
					Description: "NULL cipher suites provide no encryption (plaintext), EXPORT ciphers use intentionally weak keys (40-56 bit), and anon ciphers provide no authentication. All traffic is exposed.",
					FilePath: ctx.FilePath, LineNumber: lineNum, MatchedText: truncateCE(trimmed, 120),
					Suggestion:    "Use strong cipher suites only. For TLS 1.2: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 and similar. For TLS 1.3: TLS_AES_256_GCM_SHA384. Remove all NULL, EXPORT, anon, RC4, and DES cipher suites.",
					CWEID:         "CWE-327",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language: ctx.Language, Confidence: "high",
					Tags: []string{"crypto", "tls", "null-cipher"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helpers unique to this ext file (avoid redefinition conflicts)
// ---------------------------------------------------------------------------

func isCommentCE(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncateCE(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func nearbyLinesCE(lines []string, idx, window int) string {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}
