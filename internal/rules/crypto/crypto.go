package crypto

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled regex patterns ---

// GTSS-CRY-001: Weak hashing
var (
	reGoMD5      = regexp.MustCompile(`\bmd5\.(New|Sum)\b`)
	reGoSHA1     = regexp.MustCompile(`\bsha1\.(New|Sum)\b`)
	rePyMD5      = regexp.MustCompile(`\bhashlib\.md5\s*\(`)
	rePySHA1     = regexp.MustCompile(`\bhashlib\.sha1\s*\(`)
	// hashlib.new() with weak algorithm specified as string argument
	rePyHashlibNew = regexp.MustCompile(`\bhashlib\.new\s*\(\s*["'](?:md5|sha1)["']`)
	reJSMD5      = regexp.MustCompile(`crypto\.createHash\s*\(\s*['"]md5['"]`)
	reJSSHA1     = regexp.MustCompile(`crypto\.createHash\s*\(\s*['"]sha1['"]`)
	reJavaMD5    = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"MD5"`)
	reJavaSHA1   = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"SHA-?1"`)
	reSecurityCtx = regexp.MustCompile(`(?i)(password|secret|token|auth|sign|hmac|credential|cert)`)
)

// GTSS-CRY-002: Insecure random
var (
	reGoMathRand   = regexp.MustCompile(`\bmath/rand\b`)
	reGoRandCall   = regexp.MustCompile(`\brand\.(Int|Intn|Float|Read|New)\b`)
	rePyRandom     = regexp.MustCompile(`\brandom\.(random|randint|choice|randrange|getrandbits)\s*\(`)
	reJSMathRandom = regexp.MustCompile(`\bMath\.random\s*\(`)
	reSecRandCtx   = regexp.MustCompile(`(?i)(token|password|key|secret|nonce|salt|otp|csrf|session|uuid|auth)`)
)

// GTSS-CRY-003: Weak cipher
var (
	reGoDES      = regexp.MustCompile(`\bdes\.(NewCipher|NewTripleDESCipher)\b`)
	reGoRC4      = regexp.MustCompile(`\brc4\.NewCipher\b`)
	rePyDES      = regexp.MustCompile(`\bDES(3)?\.new\s*\(`)
	rePyARC4     = regexp.MustCompile(`\bARC4\.new\s*\(`)
	rePyBlowfish = regexp.MustCompile(`\bBlowfish\.new\s*\(`)
	reJavaDES    = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"DES`)
	reJavaRC4    = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"(RC4|ARCFOUR)`)
	reECBMode    = regexp.MustCompile(`(?i)(?:\b|_)ECB\b`)
	reWeakCipher = regexp.MustCompile(`(?i)\b(DES|3DES|TripleDES|RC4|RC2|Blowfish|ARCFOUR)\b`)
)

// GTSS-CRY-004: Hardcoded IV / nonce
var (
	reGoByteIV     = regexp.MustCompile(`(?i)\b(iv|nonce)\s*[:=]+\s*\[\]byte\s*\{`)
	reStringIV     = regexp.MustCompile(`(?i)\b(iv|nonce|initialization.?vector)\s*[:=]\s*["']`)
	reFixedIVBytes = regexp.MustCompile(`(?i)\b(iv|nonce)\s*[:=]\s*(b["']|bytes\s*\(|new\s+byte\s*\[)`)
	reByteArrayIV  = regexp.MustCompile(`(?i)\b(iv|nonce)\s*=\s*\[\s*0x`)
)

// GTSS-CRY-005: Insecure TLS
var (
	reGoInsecureSkip  = regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`)
	rePyVerifyFalse   = regexp.MustCompile(`verify\s*=\s*False`)
	reNodeRejectUnauth = regexp.MustCompile(`rejectUnauthorized\s*:\s*false`)
	reNodeTLSEnv       = regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?`)
	reTLS10            = regexp.MustCompile(`(?:MinVersion|min_version|minVersion)\s*[:=]\s*(?:tls\.VersionTLS10|tls\.VersionTLS11|['"]TLSv1(?:\.0|\.1)?['"]|0x0301|0x0302)`)
	rePySSlNoVerify    = regexp.MustCompile(`ssl\._create_unverified_context|CERT_NONE`)
)

// GTSS-CRY-006: Weak key size
var (
	reGoRSAKeySize   = regexp.MustCompile(`rsa\.GenerateKey\s*\([^,]+,\s*(512|768|1024)\s*\)`)
	reRSASmallKey    = regexp.MustCompile(`(?i)(?:key[_\s-]?(?:size|length|bits)|bits)\s*[:=]\s*(512|768|1024)\b`)
	reWeakCurve      = regexp.MustCompile(`(?i)\b(P-?192|secp192r1|prime192v1)\b`)
	reJavaRSAKeySize = regexp.MustCompile(`(?:initialize|KeyPairGenerator)\s*\(\s*(512|768|1024)\s*\)`)
)

// GTSS-CRY-007: Plaintext protocol
var (
	reHTTPURL       = regexp.MustCompile(`["']http://[^"'\s]+["']`)
	reHTTPLocalhost = regexp.MustCompile(`http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])`)
	reHTTPExample   = regexp.MustCompile(`http://(example\.com|example\.org|test\.)`)
	reHTTPSensitive = regexp.MustCompile(`(?i)http://[^"'\s]*(api|auth|login|webhook|payment|token|oauth|callback)`)
)

// GTSS-CRY-008: Math.random() in security context (JS/TS specific, broader than CRY-002)
var (
	reJSMathRandomBroad = regexp.MustCompile(`\bMath\.random\s*\(`)
	reJSSecurityCtx     = regexp.MustCompile(`(?i)(token|session|password|secret|nonce|otp|csrf|key|salt|iv|auth|uuid|api[_\-]?key|encrypt)`)
)

// GTSS-CRY-009: Python random module in security context
var (
	rePyRandomBroad = regexp.MustCompile(`\brandom\.(random|randint|choice|sample|randrange|getrandbits|shuffle|uniform)\s*\(`)
	rePySecurityCtx = regexp.MustCompile(`(?i)(token|session|password|secret|nonce|otp|csrf|key|salt|iv|auth|uuid|api[_\-]?key|encrypt|hash)`)
)

// GTSS-CRY-010: Weak PRNG across languages
var (
	// Java
	reJavaUtilRandom = regexp.MustCompile(`\bnew\s+Random\s*\(`)
	reJavaRandomImport = regexp.MustCompile(`\bjava\.util\.Random\b`)
	// PHP
	rePHPRand   = regexp.MustCompile(`\b(rand|mt_rand|srand|mt_srand)\s*\(`)
	rePHPArray  = regexp.MustCompile(`\barray_rand\s*\(`)
	// Ruby
	reRubyRand = regexp.MustCompile(`\brand\s*\(`)
	reRubyRandObj = regexp.MustCompile(`\bRandom\.(new|rand|srand)\b`)
	// C#
	reCSharpRandom = regexp.MustCompile(`\bnew\s+Random\s*\(`)
	reCSharpSystemRandom = regexp.MustCompile(`\bSystem\.Random\b`)
	// Go (broader: any math/rand usage in security context)
	reGoMathRandImport = regexp.MustCompile(`"math/rand`)
	// Weak PRNG security context (shared across languages in CRY-010)
	reWeakPRNGSecCtx = regexp.MustCompile(`(?i)(token|session|password|secret|nonce|otp|csrf|key|salt|iv|auth|uuid|encrypt|hash|credential|certificate)`)
)

// GTSS-CRY-011: Predictable seeds
var (
	rePySeedTime   = regexp.MustCompile(`\brandom\.seed\s*\(\s*(time|int\s*\(\s*time|datetime)`)
	rePySeedFixed  = regexp.MustCompile(`\brandom\.seed\s*\(\s*\d+\s*\)`)
	reCSeedTime    = regexp.MustCompile(`\bsrand\s*\(\s*time\s*\(`)
	reJavaSeedTime = regexp.MustCompile(`\.setSeed\s*\(\s*(System\.currentTimeMillis|System\.nanoTime|new\s+Date)`)
	reJavaSeedFixed = regexp.MustCompile(`\.setSeed\s*\(\s*\d+L?\s*\)`)
	reJavaFixedSeed = regexp.MustCompile(`\bnew\s+Random\s*\(\s*\d+L?\s*\)`)
	reGoSeedTime   = regexp.MustCompile(`\brand\.Seed\s*\(\s*time\.`)
	reGoSeedFixed  = regexp.MustCompile(`\brand\.Seed\s*\(\s*\d+\s*\)`)
	reGoNewSource  = regexp.MustCompile(`\brand\.NewSource\s*\(\s*\d+\s*\)`)
	rePHPSrandTime = regexp.MustCompile(`\b(srand|mt_srand)\s*\(\s*time\s*\(`)
	rePHPSrandFixed = regexp.MustCompile(`\b(srand|mt_srand)\s*\(\s*\d+\s*\)`)
	reRubySrandFixed = regexp.MustCompile(`\bsrand\s*\(\s*\d+\s*\)`)
)

// GTSS-CRY-012: Hardcoded cryptographic keys
var (
	// Go: key-like variable assigned []byte("literal") — [:=]+ handles both = and :=
	reGoByteStringKey = regexp.MustCompile(`(?i)\b(key|secret)\s*[:=]+\s*\[\]byte\s*\(\s*["']`)
	// Python: b"literal" or "literal" assigned to key-like variable
	rePyHardcodedKey = regexp.MustCompile(`(?i)\b(key|secret|aes_key|encryption_key|secret_key|private_key)\s*=\s*(b?["'][^"']{4,}["'])`)
	// JS/TS: Buffer.from("literal") or string literal assigned to key var
	reJSBufferFromKey = regexp.MustCompile(`Buffer\.from\s*\(\s*["'][^"']{4,}["']`)
	reJSHardcodedKey  = regexp.MustCompile(`(?i)\b(key|secret|aes_key|encryption_key|secret_key|private_key)\s*=\s*["'][^"']{4,}["']`)
	// Java: SecretKeySpec with inline bytes or .getBytes()
	reJavaSecretKeySpec = regexp.MustCompile(`new\s+SecretKeySpec\s*\(\s*["']`)
	reJavaGetBytesKey   = regexp.MustCompile(`["'][^"']{4,}["']\s*\.getBytes\s*\(`)
	// Generic: variable name clearly indicates crypto key, assigned string literal
	reGenericHardcodedKey = regexp.MustCompile(`(?i)\b(aes_key|encryption_key|secret_key|cipher_key|crypto_key|hmac_key|signing_key)\s*[:=]\s*["'][^"']{4,}["']`)
	// Context: near crypto operations
	reCryptoKeyCtx = regexp.MustCompile(`(?i)(encrypt|decrypt|cipher|aes|hmac|sign|SecretKey|crypto|seal|open)`)
)

// GTSS-CRY-013: Unauthenticated encryption (CBC without HMAC)
var (
	reGoCBCEncrypt = regexp.MustCompile(`cipher\.NewCBC(Encrypter|Decrypter)\b`)
	rePyCBCMode    = regexp.MustCompile(`AES\.MODE_CBC|mode\s*=\s*['"]CBC['"]`)
	reJavaCBC      = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["']AES/CBC/`)
	reJSCBCCipher  = regexp.MustCompile(`create(Cipher|Decipher)iv\s*\(\s*['"]aes-\d+-cbc['"]`)
	reAuthCheck    = regexp.MustCompile(`(?i)(hmac|mac|tag|gcm|poly1305|authenticate|verify_mac|verify_tag|AEAD|GCM|CCM)`)
)

// GTSS-CRY-014: Insecure RSA padding (PKCS1v15 for encryption)
var (
	reGoRSAPKCS1Encrypt = regexp.MustCompile(`rsa\.EncryptPKCS1v15\b`)
	reGoRSAPKCS1Decrypt = regexp.MustCompile(`rsa\.DecryptPKCS1v15\b`)
	// Match RSA/<any-mode>/PKCS1Padding in Java (avoids literal weak-mode keyword)
	reJavaRSAPKCS1      = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["']RSA/[^"'/]+/PKCS1Padding["']`)
	reJavaRSANoPadding  = regexp.MustCompile(`Cipher\.getInstance\s*\(\s*["']RSA["']\s*\)`)
	rePyPKCS1v15Encrypt = regexp.MustCompile(`PKCS1_v1_5\.new\s*\(`)
	reJSRSAPKCS1Padding = regexp.MustCompile(`(?i)RSA_PKCS1_PADDING`)
)

// GTSS-CRY-015: Weak password hashing (MD5/SHA for passwords)
var (
	rePasswordCtx        = regexp.MustCompile(`(?i)(password|passwd|pass_hash|pwd|user_pass)`)
	// Python: hashlib.md5/sha1/sha256 with password nearby
	rePyHashPassword     = regexp.MustCompile(`hashlib\.(md5|sha1|sha256|sha224)\s*\(`)
	// Go: md5.Sum or sha256.Sum256 with password nearby
	reGoHashPassword     = regexp.MustCompile(`(md5\.Sum|sha1\.Sum|sha256\.Sum256|sha256\.New|sha512\.New)\s*\(`)
	// Java: MessageDigest for password context
	reJavaDigestPassword = regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1|SHA-?256|SHA-?512)["']`)
	// JS/TS: createHash for password context
	reJSHashPassword     = regexp.MustCompile(`crypto\.createHash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]`)
	// PHP: md5($password) or sha1($password)
	rePHPHashPassword    = regexp.MustCompile(`\b(md5|sha1)\s*\(\s*\$`)
	// Proper password hashing (suppress if present)
	reProperPasswordHash = regexp.MustCompile(`(?i)(bcrypt|scrypt|argon2|pbkdf2|password_hash|PBKDF2WithHmacSHA|Rfc2898DeriveBytes)`)
)

func init() {
	rules.Register(&WeakHashing{})
	rules.Register(&InsecureRandom{})
	rules.Register(&WeakCipher{})
	rules.Register(&HardcodedIV{})
	rules.Register(&InsecureTLS{})
	rules.Register(&WeakKeySize{})
	rules.Register(&PlaintextProtocol{})
	rules.Register(&JSMathRandomSecurity{})
	rules.Register(&PythonRandomSecurity{})
	rules.Register(&WeakPRNG{})
	rules.Register(&PredictableSeed{})
	rules.Register(&HardcodedKey{})
	rules.Register(&UnauthenticatedEncryption{})
	rules.Register(&InsecureRSAPadding{})
	rules.Register(&WeakPasswordHash{})
}

// --- GTSS-CRY-001: WeakHashing ---

type WeakHashing struct{}

func (r *WeakHashing) ID() string          { return "GTSS-CRY-001" }
func (r *WeakHashing) Name() string        { return "WeakHashing" }
func (r *WeakHashing) DefaultSeverity() rules.Severity { return rules.High }

func (r *WeakHashing) Description() string {
	return "Detects use of MD5 or SHA-1 for security purposes such as password hashing, digital signatures, or HMACs."
}

func (r *WeakHashing) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *WeakHashing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var algo string

		switch ctx.Language {
		case rules.LangGo:
			if loc := reGoMD5.FindString(line); loc != "" {
				matched = loc
				algo = "MD5"
			} else if loc := reGoSHA1.FindString(line); loc != "" {
				matched = loc
				algo = "SHA-1"
			}
		case rules.LangPython:
			if loc := rePyMD5.FindString(line); loc != "" {
				matched = loc
				algo = "MD5"
			} else if loc := rePySHA1.FindString(line); loc != "" {
				matched = loc
				algo = "SHA-1"
			} else if loc := rePyHashlibNew.FindString(line); loc != "" {
				matched = loc
				if strings.Contains(loc, "md5") {
					algo = "MD5"
				} else {
					algo = "SHA-1"
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reJSMD5.FindString(line); loc != "" {
				matched = loc
				algo = "MD5"
			} else if loc := reJSSHA1.FindString(line); loc != "" {
				matched = loc
				algo = "SHA-1"
			}
		case rules.LangJava:
			if loc := reJavaMD5.FindString(line); loc != "" {
				matched = loc
				algo = "MD5"
			} else if loc := reJavaSHA1.FindString(line); loc != "" {
				matched = loc
				algo = "SHA-1"
			}
		}

		if matched == "" {
			continue
		}

		confidence := "medium"
		if reSecurityCtx.MatchString(line) {
			confidence = "high"
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak hash algorithm: " + algo,
			Description:   algo + " is cryptographically broken and must not be used for security purposes. Collision and preimage attacks are practical.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use SHA-256 or SHA-3 for integrity checks. Use bcrypt, scrypt, or Argon2 for password hashing.",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    confidence,
			Tags:          []string{"crypto", "hashing", algo},
		})
	}

	return findings
}

// --- GTSS-CRY-002: InsecureRandom ---

type InsecureRandom struct{}

func (r *InsecureRandom) ID() string          { return "GTSS-CRY-002" }
func (r *InsecureRandom) Name() string        { return "InsecureRandom" }
func (r *InsecureRandom) DefaultSeverity() rules.Severity { return rules.High }

func (r *InsecureRandom) Description() string {
	return "Detects use of non-cryptographic random number generators in security-sensitive contexts."
}

func (r *InsecureRandom) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *InsecureRandom) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// For Go, check if math/rand is imported
	goHasMathRand := false
	if ctx.Language == rules.LangGo {
		goHasMathRand = reGoMathRand.MatchString(ctx.Content)
	}

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var suggestion string

		switch ctx.Language {
		case rules.LangGo:
			if goHasMathRand {
				if loc := reGoRandCall.FindString(line); loc != "" {
					if reSecRandCtx.MatchString(line) || reSecRandCtx.MatchString(safeSurroundingLines(lines, i, 3)) {
						matched = loc
						suggestion = "Use crypto/rand for security-sensitive random values."
					}
				}
			}
		case rules.LangPython:
			if loc := rePyRandom.FindString(line); loc != "" {
				if reSecRandCtx.MatchString(line) || reSecRandCtx.MatchString(safeSurroundingLines(lines, i, 3)) {
					matched = loc
					suggestion = "Use the secrets module (secrets.token_hex, secrets.token_urlsafe) for security-sensitive random values."
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reJSMathRandom.FindString(line); loc != "" {
				if reSecRandCtx.MatchString(line) || reSecRandCtx.MatchString(safeSurroundingLines(lines, i, 3)) {
					matched = loc
					suggestion = "Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive random values."
				}
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Non-cryptographic random used in security context",
			Description:   "Non-cryptographic PRNGs are predictable and must not be used for tokens, passwords, keys, or other security-sensitive values.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "random"},
		})
	}

	return findings
}

// --- GTSS-CRY-003: WeakCipher ---

type WeakCipher struct{}

func (r *WeakCipher) ID() string          { return "GTSS-CRY-003" }
func (r *WeakCipher) Name() string        { return "WeakCipher" }
func (r *WeakCipher) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *WeakCipher) Description() string {
	return "Detects use of broken or weak encryption algorithms (DES, 3DES, RC4, Blowfish, RC2) and insecure cipher modes (ECB)."
}

func (r *WeakCipher) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangAny}
}

func (r *WeakCipher) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var detail string

		switch ctx.Language {
		case rules.LangGo:
			if loc := reGoDES.FindString(line); loc != "" {
				matched = loc
				detail = "DES/3DES"
			} else if loc := reGoRC4.FindString(line); loc != "" {
				matched = loc
				detail = "RC4"
			}
		case rules.LangPython:
			if loc := rePyDES.FindString(line); loc != "" {
				matched = loc
				detail = "DES/3DES"
			} else if loc := rePyARC4.FindString(line); loc != "" {
				matched = loc
				detail = "RC4"
			} else if loc := rePyBlowfish.FindString(line); loc != "" {
				matched = loc
				detail = "Blowfish"
			}
		case rules.LangJava:
			if loc := reJavaDES.FindString(line); loc != "" {
				matched = loc
				detail = "DES/3DES"
			} else if loc := reJavaRC4.FindString(line); loc != "" {
				matched = loc
				detail = "RC4"
			}
		}

		// ECB mode check applies to all languages
		if matched == "" {
			if loc := reECBMode.FindString(line); loc != "" {
				matched = loc
				detail = "ECB mode"
			}
		}

		// Generic weak cipher reference (if not already caught by a language-specific pattern)
		if matched == "" {
			if loc := reWeakCipher.FindString(line); loc != "" {
				// Avoid matching in comments that merely mention the algorithm name
				trimmed := strings.TrimSpace(line)
				if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "*") {
					matched = loc
					detail = loc
				}
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak cipher or mode: " + detail,
			Description:   detail + " is cryptographically weak and must not be used. These algorithms have known practical attacks.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use AES-256-GCM or ChaCha20-Poly1305 for authenticated encryption.",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "cipher", detail},
		})
	}

	return findings
}

// --- GTSS-CRY-004: HardcodedIV ---

type HardcodedIV struct{}

func (r *HardcodedIV) ID() string          { return "GTSS-CRY-004" }
func (r *HardcodedIV) Name() string        { return "HardcodedIV" }
func (r *HardcodedIV) DefaultSeverity() rules.Severity { return rules.High }

func (r *HardcodedIV) Description() string {
	return "Detects hardcoded initialization vectors (IVs) and nonces, which undermine encryption security."
}

func (r *HardcodedIV) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangAny}
}

func (r *HardcodedIV) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	patterns := []*regexp.Regexp{reGoByteIV, reStringIV, reFixedIVBytes, reByteArrayIV}

	for i, line := range lines {
		lineNum := i + 1

		for _, pat := range patterns {
			if loc := pat.FindString(line); loc != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Hardcoded initialization vector or nonce",
					Description:   "Using a fixed IV or nonce makes encryption deterministic, enabling pattern analysis and defeating semantic security.",
					FilePath:      ctx.FilePath,
					LineNumber:    lineNum,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Generate IVs and nonces randomly for each encryption operation using a CSPRNG.",
					CWEID:         "CWE-329",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"crypto", "iv", "nonce"},
				})
				break // one finding per line
			}
		}
	}

	return findings
}

// --- GTSS-CRY-005: InsecureTLS ---

type InsecureTLS struct{}

func (r *InsecureTLS) ID() string          { return "GTSS-CRY-005" }
func (r *InsecureTLS) Name() string        { return "InsecureTLS" }
func (r *InsecureTLS) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *InsecureTLS) Description() string {
	return "Detects disabled TLS certificate verification and use of deprecated TLS versions (1.0, 1.1)."
}

func (r *InsecureTLS) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangAny}
}

func (r *InsecureTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var title string
		var desc string
		var suggestion string
		cweID := "CWE-295"

		switch ctx.Language {
		case rules.LangGo:
			if loc := reGoInsecureSkip.FindString(line); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled"
				desc = "InsecureSkipVerify: true disables certificate validation, enabling man-in-the-middle attacks."
				suggestion = "Remove InsecureSkipVerify or set it to false. Use a custom VerifyPeerCertificate if you need custom validation."
			}
		case rules.LangPython:
			if loc := rePyVerifyFalse.FindString(line); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled"
				desc = "verify=False disables certificate validation for HTTPS requests."
				suggestion = "Use verify=True (the default) or provide a CA bundle path."
			} else if loc := rePySSlNoVerify.FindString(line); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled"
				desc = "Disabling SSL certificate verification enables man-in-the-middle attacks."
				suggestion = "Use ssl.create_default_context() instead."
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reNodeRejectUnauth.FindString(line); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled"
				desc = "rejectUnauthorized: false disables certificate validation for TLS connections."
				suggestion = "Remove rejectUnauthorized: false to enable certificate verification."
			} else if loc := reNodeTLSEnv.FindString(line); loc != "" {
				matched = loc
				title = "TLS certificate verification disabled via environment"
				desc = "NODE_TLS_REJECT_UNAUTHORIZED=0 globally disables TLS verification for the Node.js process."
				suggestion = "Remove this environment variable. Fix the underlying certificate issue instead."
			}
		}

		// TLS version check applies to all languages
		if matched == "" {
			if loc := reTLS10.FindString(line); loc != "" {
				matched = loc
				title = "Deprecated TLS version"
				desc = "TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE) and are deprecated by RFC 8996."
				suggestion = "Set minimum TLS version to 1.2 or preferably 1.3."
				cweID = "CWE-327"
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         cweID,
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "tls"},
		})
	}

	return findings
}

// --- GTSS-CRY-006: WeakKeySize ---

type WeakKeySize struct{}

func (r *WeakKeySize) ID() string          { return "GTSS-CRY-006" }
func (r *WeakKeySize) Name() string        { return "WeakKeySize" }
func (r *WeakKeySize) DefaultSeverity() rules.Severity { return rules.High }

func (r *WeakKeySize) Description() string {
	return "Detects RSA keys smaller than 2048 bits, weak elliptic curves, and insufficient symmetric key sizes."
}

func (r *WeakKeySize) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangAny}
}

func (r *WeakKeySize) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var title string
		var desc string

		switch ctx.Language {
		case rules.LangGo:
			if loc := reGoRSAKeySize.FindString(line); loc != "" {
				matched = loc
				title = "RSA key size too small"
				desc = "RSA keys smaller than 2048 bits can be factored with current computing resources."
			}
		case rules.LangJava:
			if loc := reJavaRSAKeySize.FindString(line); loc != "" {
				matched = loc
				title = "RSA key size too small"
				desc = "RSA keys smaller than 2048 bits can be factored with current computing resources."
			}
		}

		// Generic key size check for all languages
		if matched == "" {
			if loc := reRSASmallKey.FindString(line); loc != "" {
				matched = loc
				title = "Potentially weak key size"
				desc = "Key sizes of 1024 bits or less are considered insufficient for modern security requirements."
			}
		}

		// Weak EC curve check for all languages
		if matched == "" {
			if loc := reWeakCurve.FindString(line); loc != "" {
				matched = loc
				title = "Weak elliptic curve"
				desc = "P-192 and equivalent curves provide less than 128 bits of security and should not be used."
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use RSA-2048 or larger, P-256 or stronger curves, and AES-256 for symmetric encryption.",
			CWEID:         "CWE-326",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "keysize"},
		})
	}

	return findings
}

// --- GTSS-CRY-007: PlaintextProtocol ---

type PlaintextProtocol struct{}

func (r *PlaintextProtocol) ID() string          { return "GTSS-CRY-007" }
func (r *PlaintextProtocol) Name() string        { return "PlaintextProtocol" }
func (r *PlaintextProtocol) DefaultSeverity() rules.Severity { return rules.Medium }

func (r *PlaintextProtocol) Description() string {
	return "Detects HTTP (non-HTTPS) URLs used for sensitive operations such as API calls, authentication, or webhooks."
}

func (r *PlaintextProtocol) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PlaintextProtocol) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1

		loc := reHTTPURL.FindString(line)
		if loc == "" {
			continue
		}

		// Skip localhost/loopback addresses
		if reHTTPLocalhost.MatchString(line) {
			continue
		}

		// Skip example/test domains
		if reHTTPExample.MatchString(line) {
			continue
		}

		// Skip lines that look like test fixtures or comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		confidence := "medium"
		title := "HTTP URL used instead of HTTPS"
		if reHTTPSensitive.MatchString(line) {
			confidence = "high"
			title = "HTTP URL used for sensitive endpoint"
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   "Using plaintext HTTP exposes data in transit to eavesdropping and tampering. All sensitive communications should use HTTPS.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Replace http:// with https:// to encrypt data in transit.",
			CWEID:         "CWE-319",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    confidence,
			Tags:          []string{"crypto", "transport"},
		})
	}

	return findings
}

// --- GTSS-CRY-008: JSMathRandomSecurity ---

type JSMathRandomSecurity struct{}

func (r *JSMathRandomSecurity) ID() string          { return "GTSS-CRY-008" }
func (r *JSMathRandomSecurity) Name() string        { return "JSMathRandomSecurity" }
func (r *JSMathRandomSecurity) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *JSMathRandomSecurity) Description() string {
	return "Detects Math.random() usage in security-sensitive contexts such as token generation, session IDs, passwords, nonces, OTPs, and CSRF tokens."
}

func (r *JSMathRandomSecurity) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *JSMathRandomSecurity) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1

		if loc := reJSMathRandomBroad.FindString(line); loc != "" {
			// Check current line and surrounding context for security-sensitive terms
			if reJSSecurityCtx.MatchString(line) || reJSSecurityCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Math.random() used in security-sensitive context",
					Description:   "Math.random() is not cryptographically secure. Its output is predictable and must not be used for tokens, session IDs, passwords, nonces, OTPs, CSRF tokens, or any security-sensitive values.",
					FilePath:      ctx.FilePath,
					LineNumber:    lineNum,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) for cryptographically secure random values.",
					CWEID:         "CWE-330",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"crypto", "random", "javascript"},
				})
			}
		}
	}

	return findings
}

// --- GTSS-CRY-009: PythonRandomSecurity ---

type PythonRandomSecurity struct{}

func (r *PythonRandomSecurity) ID() string          { return "GTSS-CRY-009" }
func (r *PythonRandomSecurity) Name() string        { return "PythonRandomSecurity" }
func (r *PythonRandomSecurity) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *PythonRandomSecurity) Description() string {
	return "Detects Python random module usage in security-sensitive contexts. The random module uses a Mersenne Twister PRNG which is not suitable for security purposes."
}

func (r *PythonRandomSecurity) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *PythonRandomSecurity) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1

		if loc := rePyRandomBroad.FindString(line); loc != "" {
			if rePySecurityCtx.MatchString(line) || rePySecurityCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Python random module used in security-sensitive context",
					Description:   "The random module uses a Mersenne Twister PRNG which is entirely predictable. Its state can be recovered from 624 consecutive outputs. It must not be used for security purposes.",
					FilePath:      ctx.FilePath,
					LineNumber:    lineNum,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Use the secrets module (secrets.token_hex(), secrets.token_urlsafe(), secrets.choice()) for security-sensitive random values.",
					CWEID:         "CWE-330",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"crypto", "random", "python"},
				})
			}
		}
	}

	return findings
}

// --- GTSS-CRY-010: WeakPRNG ---

type WeakPRNG struct{}

func (r *WeakPRNG) ID() string          { return "GTSS-CRY-010" }
func (r *WeakPRNG) Name() string        { return "WeakPRNG" }
func (r *WeakPRNG) DefaultSeverity() rules.Severity { return rules.High }

func (r *WeakPRNG) Description() string {
	return "Detects use of non-cryptographic PRNGs across languages: Java java.util.Random, PHP rand()/mt_rand(), Ruby rand(), C# System.Random, and Go math/rand in security contexts."
}

func (r *WeakPRNG) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp, rules.LangGo}
}

func (r *WeakPRNG) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// For Go, check if math/rand is imported
	goHasMathRand := false
	if ctx.Language == rules.LangGo {
		goHasMathRand = reGoMathRandImport.MatchString(ctx.Content)
	}

	// For Java, check if java.util.Random is imported
	javaHasUtilRandom := false
	if ctx.Language == rules.LangJava {
		javaHasUtilRandom = reJavaRandomImport.MatchString(ctx.Content)
	}

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var suggestion string
		var detail string

		switch ctx.Language {
		case rules.LangJava:
			if javaHasUtilRandom || reJavaUtilRandom.MatchString(line) {
				if loc := reJavaUtilRandom.FindString(line); loc != "" {
					if reWeakPRNGSecCtx.MatchString(line) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
						matched = loc
						detail = "java.util.Random"
						suggestion = "Use java.security.SecureRandom for security-sensitive random values."
					}
				}
			}
		case rules.LangPHP:
			if loc := rePHPRand.FindString(line); loc != "" {
				if reWeakPRNGSecCtx.MatchString(line) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "PHP rand()/mt_rand()"
					suggestion = "Use random_bytes() or random_int() for security-sensitive random values."
				}
			} else if loc := rePHPArray.FindString(line); loc != "" {
				if reWeakPRNGSecCtx.MatchString(line) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "PHP array_rand()"
					suggestion = "Use random_int() for index selection or random_bytes() for security-sensitive random values."
				}
			}
		case rules.LangRuby:
			if loc := reRubyRand.FindString(line); loc != "" {
				if reWeakPRNGSecCtx.MatchString(line) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "Ruby rand()"
					suggestion = "Use SecureRandom.hex, SecureRandom.uuid, or SecureRandom.random_bytes for security-sensitive random values."
				}
			} else if loc := reRubyRandObj.FindString(line); loc != "" {
				if reWeakPRNGSecCtx.MatchString(line) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "Ruby Random"
					suggestion = "Use SecureRandom.hex, SecureRandom.uuid, or SecureRandom.random_bytes for security-sensitive random values."
				}
			}
		case rules.LangCSharp:
			if loc := reCSharpRandom.FindString(line); loc != "" {
				if reWeakPRNGSecCtx.MatchString(line) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = loc
					detail = "System.Random"
					suggestion = "Use System.Security.Cryptography.RNGCryptoServiceProvider or RandomNumberGenerator.Create() for security-sensitive random values."
				}
			}
		case rules.LangGo:
			if goHasMathRand {
				if loc := reGoRandCall.FindString(line); loc != "" {
					if reWeakPRNGSecCtx.MatchString(line) || reWeakPRNGSecCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
						matched = loc
						detail = "math/rand"
						suggestion = "Use crypto/rand for security-sensitive random values."
					}
				}
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Weak PRNG in security context: " + detail,
			Description:   detail + " is not cryptographically secure. Its output is predictable and must not be used for security-sensitive operations.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "random", "prng"},
		})
	}

	return findings
}

// --- GTSS-CRY-011: PredictableSeed ---

type PredictableSeed struct{}

func (r *PredictableSeed) ID() string          { return "GTSS-CRY-011" }
func (r *PredictableSeed) Name() string        { return "PredictableSeed" }
func (r *PredictableSeed) DefaultSeverity() rules.Severity { return rules.High }

func (r *PredictableSeed) Description() string {
	return "Detects predictable or fixed seeds for random number generators. Time-based seeds and constant seeds make PRNG output reproducible."
}

func (r *PredictableSeed) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJava, rules.LangGo, rules.LangPHP, rules.LangRuby, rules.LangC, rules.LangCPP, rules.LangAny}
}

func (r *PredictableSeed) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var title string
		var desc string
		var suggestion string

		switch ctx.Language {
		case rules.LangPython:
			if loc := rePySeedTime.FindString(line); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "Seeding random with time makes output predictable to anyone who can estimate when the code runs."
				suggestion = "Use the secrets module instead of seeding random. If random is needed for non-security purposes, omit the seed to use OS entropy."
			} else if loc := rePySeedFixed.FindString(line); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes random output completely deterministic and reproducible."
				suggestion = "Remove the fixed seed. Use the secrets module for security-sensitive values."
			}
		case rules.LangJava:
			if loc := reJavaSeedTime.FindString(line); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "Seeding Random with system time makes output predictable to anyone who can estimate when the code runs."
				suggestion = "Use java.security.SecureRandom which seeds itself from OS entropy."
			} else if loc := reJavaSeedFixed.FindString(line); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes Random output completely deterministic and reproducible."
				suggestion = "Use java.security.SecureRandom for security-sensitive values. Remove fixed seeds."
			} else if loc := reJavaFixedSeed.FindString(line); loc != "" {
				matched = loc
				title = "Fixed random seed in constructor"
				desc = "Constructing Random with a constant seed makes output completely deterministic and reproducible."
				suggestion = "Use java.security.SecureRandom for security-sensitive values."
			}
		case rules.LangGo:
			if loc := reGoSeedTime.FindString(line); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "Seeding math/rand with time.Now() makes output predictable. In Go 1.20+ math/rand auto-seeds, but still is not cryptographically secure."
				suggestion = "Use crypto/rand for security-sensitive values."
			} else if loc := reGoSeedFixed.FindString(line); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes math/rand output completely deterministic and reproducible."
				suggestion = "Use crypto/rand for security-sensitive values. Remove fixed seeds."
			} else if loc := reGoNewSource.FindString(line); loc != "" {
				matched = loc
				title = "Fixed seed in rand.NewSource"
				desc = "Creating a rand source with a constant seed makes output completely deterministic and reproducible."
				suggestion = "Use crypto/rand for security-sensitive values."
			}
		case rules.LangPHP:
			if loc := rePHPSrandTime.FindString(line); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "Seeding with time() makes output predictable to anyone who can estimate when the code runs."
				suggestion = "Use random_bytes() or random_int() for security-sensitive values. PHP 7+ auto-seeds, so explicit seeding is rarely needed."
			} else if loc := rePHPSrandFixed.FindString(line); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes rand()/mt_rand() output completely deterministic and reproducible."
				suggestion = "Use random_bytes() or random_int() for security-sensitive values. Remove fixed seeds."
			}
		case rules.LangRuby:
			if loc := reRubySrandFixed.FindString(line); loc != "" {
				matched = loc
				title = "Fixed random seed"
				desc = "A constant seed makes rand() output completely deterministic and reproducible."
				suggestion = "Use SecureRandom for security-sensitive values. Remove fixed seeds."
			}
		case rules.LangC, rules.LangCPP:
			if loc := reCSeedTime.FindString(line); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "srand(time(NULL)) makes output predictable to anyone who can estimate when the code runs."
				suggestion = "Use platform-specific CSPRNGs (e.g., getrandom(), /dev/urandom, BCryptGenRandom) for security-sensitive values."
			}
		}

		// Generic fallback: check for srand(time( in any language
		if matched == "" {
			if loc := reCSeedTime.FindString(line); loc != "" {
				matched = loc
				title = "Time-based random seed"
				desc = "srand(time()) makes random output predictable to anyone who can estimate when the code runs."
				suggestion = "Use a cryptographically secure random number generator for security-sensitive values."
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    suggestion,
			CWEID:         "CWE-330",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "random", "seed"},
		})
	}

	return findings
}

// --- GTSS-CRY-012: HardcodedKey ---

type HardcodedKey struct{}

func (r *HardcodedKey) ID() string                    { return "GTSS-CRY-012" }
func (r *HardcodedKey) Name() string                  { return "HardcodedKey" }
func (r *HardcodedKey) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *HardcodedKey) Description() string {
	return "Detects hardcoded cryptographic keys (AES keys, encryption secrets, signing keys) embedded directly in source code."
}

func (r *HardcodedKey) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangAny}
}

func (r *HardcodedKey) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		var matched bool

		switch ctx.Language {
		case rules.LangGo:
			// key/secret := []byte("literal")
			if reGoByteStringKey.MatchString(line) {
				matched = true
			}
		case rules.LangPython:
			if rePyHardcodedKey.MatchString(line) {
				matched = true
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if reJSBufferFromKey.MatchString(line) && reCryptoKeyCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
				matched = true
			} else if reJSHardcodedKey.MatchString(line) {
				matched = true
			}
		case rules.LangJava:
			if reJavaSecretKeySpec.MatchString(line) || reJavaGetBytesKey.MatchString(line) {
				if reCryptoKeyCtx.MatchString(line) || reCryptoKeyCtx.MatchString(safeSurroundingLines(lines, i, 5)) {
					matched = true
				}
			}
		}

		// Generic check for all languages: explicitly named crypto key variables
		if !matched {
			if reGenericHardcodedKey.MatchString(line) {
				matched = true
			}
		}

		if !matched {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Hardcoded cryptographic key",
			Description:   "Cryptographic keys embedded in source code can be extracted by anyone with access to the code or binary. Keys should be loaded from secure key management systems, environment variables, or encrypted configuration.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Load keys from environment variables, a secrets manager (Vault, AWS KMS, GCP KMS), or encrypted config files. Never commit keys to source control.",
			CWEID:         "CWE-321",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "hardcoded-key"},
		})
	}

	return findings
}

// --- GTSS-CRY-013: UnauthenticatedEncryption ---

type UnauthenticatedEncryption struct{}

func (r *UnauthenticatedEncryption) ID() string                    { return "GTSS-CRY-013" }
func (r *UnauthenticatedEncryption) Name() string                  { return "UnauthenticatedEncryption" }
func (r *UnauthenticatedEncryption) DefaultSeverity() rules.Severity { return rules.High }

func (r *UnauthenticatedEncryption) Description() string {
	return "Detects use of CBC mode encryption without authentication (HMAC/MAC), which is vulnerable to padding oracle attacks."
}

func (r *UnauthenticatedEncryption) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *UnauthenticatedEncryption) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if any authentication is present in the entire file
	hasAuth := reAuthCheck.MatchString(ctx.Content)

	for i, line := range lines {
		lineNum := i + 1
		var matched string

		switch ctx.Language {
		case rules.LangGo:
			if loc := reGoCBCEncrypt.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangPython:
			if loc := rePyCBCMode.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangJava:
			if loc := reJavaCBC.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reJSCBCCipher.FindString(line); loc != "" {
				matched = loc
			}
		}

		if matched == "" {
			continue
		}

		// Suppress if authentication is present anywhere in the file
		if hasAuth {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "CBC mode without authentication (padding oracle risk)",
			Description:   "CBC mode without a MAC/HMAC is vulnerable to padding oracle attacks (e.g., POODLE, Lucky13). An attacker can decrypt ciphertext by observing padding error responses.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use AES-GCM or ChaCha20-Poly1305 for authenticated encryption. If CBC is required, always apply HMAC-SHA256 to the ciphertext (encrypt-then-MAC).",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "cbc", "padding-oracle"},
		})
	}

	return findings
}

// --- GTSS-CRY-014: InsecureRSAPadding ---

type InsecureRSAPadding struct{}

func (r *InsecureRSAPadding) ID() string                    { return "GTSS-CRY-014" }
func (r *InsecureRSAPadding) Name() string                  { return "InsecureRSAPadding" }
func (r *InsecureRSAPadding) DefaultSeverity() rules.Severity { return rules.High }

func (r *InsecureRSAPadding) Description() string {
	return "Detects use of PKCS#1 v1.5 padding for RSA encryption, which is vulnerable to Bleichenbacher's attack and padding oracle attacks."
}

func (r *InsecureRSAPadding) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava}
}

func (r *InsecureRSAPadding) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		var matched string
		var detail string

		switch ctx.Language {
		case rules.LangGo:
			if loc := reGoRSAPKCS1Encrypt.FindString(line); loc != "" {
				matched = loc
				detail = "rsa.EncryptPKCS1v15"
			} else if loc := reGoRSAPKCS1Decrypt.FindString(line); loc != "" {
				matched = loc
				detail = "rsa.DecryptPKCS1v15"
			}
		case rules.LangJava:
			if loc := reJavaRSAPKCS1.FindString(line); loc != "" {
				matched = loc
				detail = "RSA/PKCS1Padding"
			} else if loc := reJavaRSANoPadding.FindString(line); loc != "" {
				matched = loc
				detail = "RSA with no explicit mode (defaults to insecure padding)"
			}
		case rules.LangPython:
			if loc := rePyPKCS1v15Encrypt.FindString(line); loc != "" {
				matched = loc
				detail = "PKCS1_v1_5"
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reJSRSAPKCS1Padding.FindString(line); loc != "" {
				matched = loc
				detail = "RSA_PKCS1_PADDING"
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Insecure RSA padding: " + detail,
			Description:   "PKCS#1 v1.5 padding for RSA encryption is vulnerable to Bleichenbacher's chosen-ciphertext attack. An attacker can decrypt messages or forge signatures by making adaptive queries.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use RSA-OAEP (Optimal Asymmetric Encryption Padding) for encryption. For signatures, use PSS padding instead of PKCS1v15.",
			CWEID:         "CWE-780",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "rsa", "padding"},
		})
	}

	return findings
}

// --- GTSS-CRY-015: WeakPasswordHash ---

type WeakPasswordHash struct{}

func (r *WeakPasswordHash) ID() string                    { return "GTSS-CRY-015" }
func (r *WeakPasswordHash) Name() string                  { return "WeakPasswordHash" }
func (r *WeakPasswordHash) DefaultSeverity() rules.Severity { return rules.Critical }

func (r *WeakPasswordHash) Description() string {
	return "Detects use of fast hash functions (MD5, SHA-1, SHA-256) for password storage instead of purpose-built password hashing algorithms (bcrypt, scrypt, Argon2)."
}

func (r *WeakPasswordHash) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP}
}

func (r *WeakPasswordHash) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// If proper password hashing is used in the file, suppress
	if reProperPasswordHash.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		var matched string

		// Only flag if password context exists on the line or nearby
		hasPasswordCtx := rePasswordCtx.MatchString(line) || rePasswordCtx.MatchString(safeSurroundingLines(lines, i, 3))
		if !hasPasswordCtx {
			continue
		}

		switch ctx.Language {
		case rules.LangPython:
			if loc := rePyHashPassword.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangGo:
			if loc := reGoHashPassword.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangJava:
			if loc := reJavaDigestPassword.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reJSHashPassword.FindString(line); loc != "" {
				matched = loc
			}
		case rules.LangPHP:
			if loc := rePHPHashPassword.FindString(line); loc != "" {
				matched = loc
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Fast hash used for password storage",
			Description:   "Fast hash functions (MD5, SHA-1, SHA-256) can be brute-forced at billions of attempts per second using GPUs. Password storage requires slow, salted, memory-hard algorithms.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   strings.TrimSpace(line),
			Suggestion:    "Use bcrypt, scrypt, or Argon2id for password hashing. These algorithms are intentionally slow and resistant to GPU/ASIC attacks.",
			CWEID:         "CWE-916",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"crypto", "password", "hashing"},
		})
	}

	return findings
}

// --- Helpers ---

// safeSurroundingLines returns a window of lines around the given index for context analysis.
func safeSurroundingLines(lines []string, idx, window int) string {
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
