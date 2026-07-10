package ruby

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Ruby crypto / auth extension rules (BATOU-RB-021 .. BATOU-RB-025)
//
// These detect cryptographic and authentication misconfigurations that are
// fixed by shape (a literal argument, a disabled flag, a weak algorithm), not
// by taint flow. Each rule is anchored to a specific library API so it cannot
// collide with unrelated method names.
// ---------------------------------------------------------------------------

var (
	// RB-021: ruby-jwt JWT.decode with signature verification disabled.
	//   JWT.decode(token, key, false)            -> 3rd positional arg false = no verify
	//   JWT.decode(token, nil, false)
	//   JWT.decode(token, key, true, algorithm: 'none')
	//   JWT.decode(..., verify: false)
	reJWTDecode       = regexp.MustCompile(`\bJWT\.decode\s*\(`)
	reJWTDecodeFalse3 = regexp.MustCompile(`\bJWT\.decode\s*\(\s*[^,]+,\s*[^,]+,\s*false\b`)
	reJWTVerifyFalse  = regexp.MustCompile(`verify\s*:\s*false`)
	reJWTAlgNone      = regexp.MustCompile(`(?i)algorithm[s]?\s*:\s*(?:\[\s*)?["']none["']`)

	// RB-022: OpenSSL::PKey::RSA.new(bits) with bits < 2048.
	reRSANew = regexp.MustCompile(`OpenSSL::PKey::RSA\.(?:new|generate)\s*\(\s*(\d+)`)
	// RB-023: OpenSSL::PKey::RSA.new(data, 'literal_passphrase') — second arg is
	// a string literal passphrase.
	reRSANewPass = regexp.MustCompile(`OpenSSL::PKey::RSA\.new\s*\(\s*[^,]+,\s*["'][^"']+["']\s*\)`)

	// RB-024: DB connection with TLS disabled via sslmode disable.
	//   sslmode: 'disable'  / "sslmode=disable" / sslmode: :disable
	reSSLModeDisable = regexp.MustCompile(`(?i)sslmode\s*[:=]\s*["']?disable["']?`)

	// RB-025: Digest::SHA224 used to hash a password/secret (weak-for-password).
	reSHA224 = regexp.MustCompile(`\bDigest::SHA224\.\w+\s*\(`)
)

func init() {
	rules.Register(&RubyJWTNoVerify{})
	rules.Register(&RubyRSAWeakKeySize{})
	rules.Register(&RubyRSALiteralPassphrase{})
	rules.Register(&RubySSLModeDisable{})
	rules.Register(&RubySHA224Password{})
}

// ---------------------------------------------------------------------------
// BATOU-RB-021: JWT.decode with signature verification disabled
// ---------------------------------------------------------------------------

type RubyJWTNoVerify struct{}

func (r *RubyJWTNoVerify) ID() string                      { return "BATOU-RB-021" }
func (r *RubyJWTNoVerify) Name() string                    { return "RubyJWTNoVerify" }
func (r *RubyJWTNoVerify) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RubyJWTNoVerify) Description() string {
	return "Detects ruby-jwt JWT.decode with signature verification disabled (verify=false, verify: false, or algorithm 'none'), letting an attacker forge token claims."
}
func (r *RubyJWTNoVerify) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RubyJWTNoVerify) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reJWTDecode, line, lowered[i]) {
			continue
		}
		var why string
		switch {
		case rules.GMatchLower(reJWTDecodeFalse3, line, lowered[i]):
			why = "the third positional argument is false, which disables signature verification"
		case rules.GMatchLower(reJWTVerifyFalse, line, lowered[i]):
			why = "verify: false disables signature verification"
		case rules.GMatchLower(reJWTAlgNone, line, lowered[i]):
			why = "the 'none' algorithm is accepted, which means unsigned tokens are trusted"
		default:
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "JWT decoded without signature verification",
			Description:   "JWT.decode is called with " + why + ". An attacker can craft a token with arbitrary claims (e.g. admin: true, a different user id) and it will be accepted, since the cryptographic signature is never checked.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Verify the signature: JWT.decode(token, secret, true, { algorithm: 'HS256' }). Never pass false / verify: false, and never accept the 'none' algorithm.",
			CWEID:         "CWE-347",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"ruby", "jwt", "authentication", "signature-bypass"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-022: OpenSSL RSA key size < 2048 bits
// ---------------------------------------------------------------------------

type RubyRSAWeakKeySize struct{}

func (r *RubyRSAWeakKeySize) ID() string                      { return "BATOU-RB-022" }
func (r *RubyRSAWeakKeySize) Name() string                    { return "RubyRSAWeakKeySize" }
func (r *RubyRSAWeakKeySize) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RubyRSAWeakKeySize) Description() string {
	return "Detects OpenSSL::PKey::RSA.new/generate with a key size below 2048 bits, which is cryptographically weak."
}
func (r *RubyRSAWeakKeySize) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RubyRSAWeakKeySize) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		m := rules.GFindSubmatchLower(reRSANew, line, lowered[i])
		if m == nil {
			continue
		}
		bits, err := strconv.Atoi(m[1])
		if err != nil || bits >= 2048 {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Insufficient RSA key size (< 2048 bits)",
			Description:   "An RSA key of " + m[1] + " bits is generated. Keys below 2048 bits are considered breakable; NIST and modern guidance require at least 2048 bits (3072+ preferred for long-lived keys).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Generate at least a 2048-bit key: OpenSSL::PKey::RSA.new(2048). Use 3072 or 4096 bits for keys with a long lifetime.",
			CWEID:         "CWE-326",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"ruby", "crypto", "rsa", "key-size"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-023: OpenSSL RSA hardcoded passphrase
// ---------------------------------------------------------------------------

type RubyRSALiteralPassphrase struct{}

func (r *RubyRSALiteralPassphrase) ID() string                      { return "BATOU-RB-023" }
func (r *RubyRSALiteralPassphrase) Name() string                    { return "RubyRSALiteralPassphrase" }
func (r *RubyRSALiteralPassphrase) DefaultSeverity() rules.Severity { return rules.High }
func (r *RubyRSALiteralPassphrase) Description() string {
	return "Detects OpenSSL::PKey::RSA.new(data, 'passphrase') with a string-literal private-key passphrase, hardcoding the key password in source."
}
func (r *RubyRSALiteralPassphrase) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RubyRSALiteralPassphrase) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reRSANewPass, line, lowered[i]) {
			continue
		}
		// Skip when the passphrase clearly comes from ENV/credentials (the
		// literal is the key data path or similar, not a secret).
		if strings.Contains(line, "ENV") || strings.Contains(line, "credentials") {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Hardcoded RSA private-key passphrase",
			Description:   "OpenSSL::PKey::RSA.new is called with a string-literal passphrase as its second argument. This passphrase protects the RSA private key; committing it to source control means anyone with repo access can decrypt and use the key.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Load the passphrase from the environment or Rails credentials: OpenSSL::PKey::RSA.new(data, ENV['RSA_KEY_PASSPHRASE']).",
			CWEID:         "CWE-798",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"ruby", "crypto", "rsa", "hardcoded-secret"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-024: DB connection with sslmode disable
// ---------------------------------------------------------------------------

type RubySSLModeDisable struct{}

func (r *RubySSLModeDisable) ID() string                      { return "BATOU-RB-024" }
func (r *RubySSLModeDisable) Name() string                    { return "RubySSLModeDisable" }
func (r *RubySSLModeDisable) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RubySSLModeDisable) Description() string {
	return "Detects a database connection configured with sslmode disable, sending DB traffic (including credentials) in cleartext."
}
func (r *RubySSLModeDisable) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby, rules.LangAny}
}

func (r *RubySSLModeDisable) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Applies to .rb connection setup and database.yml-style config.
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reSSLModeDisable, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Database connection with TLS disabled (sslmode=disable)",
			Description:   "The PostgreSQL/MySQL connection sets sslmode to 'disable', so the connection is never encrypted. Database credentials and all query data travel in cleartext and can be read or modified by anyone on the network path.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use sslmode 'require' (encrypt) or 'verify-full' (encrypt + verify the server certificate). Never use 'disable' outside an isolated local environment.",
			CWEID:         "CWE-319",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"ruby", "tls", "database", "cleartext"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-RB-025: Digest::SHA224 used to hash a password/secret
// ---------------------------------------------------------------------------

type RubySHA224Password struct{}

func (r *RubySHA224Password) ID() string                      { return "BATOU-RB-025" }
func (r *RubySHA224Password) Name() string                    { return "RubySHA224Password" }
func (r *RubySHA224Password) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RubySHA224Password) Description() string {
	return "Detects Digest::SHA224 hashing a password/secret, which is an unsuitable fast hash for credential storage."
}
func (r *RubySHA224Password) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RubySHA224Password) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reSHA224, line, lowered[i]) {
			continue
		}
		// Only flag when the hashed value is a credential — require a
		// password/secret/token indicator on the line, otherwise SHA-224 over
		// non-credential data (a content checksum) is acceptable.
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "password") && !strings.Contains(lower, "passwd") &&
			!strings.Contains(lower, "secret") && !strings.Contains(lower, "pwd") &&
			!strings.Contains(lower, "credential") {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Password hashed with SHA-224 (weak for credentials)",
			Description:   "Digest::SHA224 is a fast, general-purpose hash. Using it to store passwords/secrets makes them cheap to brute-force with GPUs/ASICs; it has no salt and no work factor. A leaked database of SHA-224 password hashes is rapidly crackable.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use a purpose-built password hash with a work factor: bcrypt (BCrypt::Password.create), scrypt, or Argon2 (argon2 gem). In Rails use has_secure_password.",
			CWEID:         "CWE-328",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"ruby", "crypto", "password-hash", "sha224"},
		})
	}
	return findings
}
