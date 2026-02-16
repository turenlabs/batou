package secrets

import (
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/turenlabs/batou/internal/rules"
)

// --- Compiled regex patterns ---

// BATOU-SEC-001: Hardcoded password patterns per language family.
var (
	// Variable names commonly used for secrets.
	secretVarNames = `(?i)(password|passwd|pwd|pass|secret|api_key|apikey|token|auth_token|access_token|private_key)`

	// Go / Java / C# style:  varName = "value"  or  varName := "value"
	rePasswordCStyle = regexp.MustCompile(
		`(?i)(?:^|[\s{(,;])` + secretVarNames + `\s*[:=]=?\s*"([^"]{2,})"`)

	// Python / Ruby style:  varName = "value" or varName = 'value'
	rePasswordPyRuby = regexp.MustCompile(
		`(?i)(?:^|[\s{(,;])` + secretVarNames + `\s*=\s*["']([^"']{2,})["']`)

	// PHP style: $varName = "value"
	rePasswordPHP = regexp.MustCompile(
		`(?i)\$` + secretVarNames + `\s*=\s*["']([^"']{2,})["']`)

	// Generic assignment across languages (catches additional patterns).
	rePasswordGeneric = regexp.MustCompile(
		`(?i)(?:^|[\s{(,;])` + secretVarNames + `\s*[:=]=?\s*["']([^"']{2,})["']`)

	// Placeholder / example values to exclude.
	placeholderValues = []string{
		"changeme", "change_me", "change-me",
		"todo", "fixme", "xxx", "yyy", "zzz",
		"example", "placeholder", "your_password", "your-password",
		"password", "passwd", "pass", "secret",
		"<password>", "<secret>", "<token>", "<api_key>",
		"${", "#{", "{{", "os.environ", "process.env",
		"none", "null", "nil", "undefined", "true", "false",
	}

	// Test file path patterns.
	reTestFile = regexp.MustCompile(`(?i)(_test\.go|_test\.py|\.test\.[jt]sx?|\.spec\.[jt]sx?|test_.*\.py|tests?/|__tests__/|spec/|fixtures?/|mock|fake|stub|example)`)
)

// BATOU-SEC-002: API key patterns.
var (
	reAWSAccessKey = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)`)
	reAWSSecretKey = regexp.MustCompile(`(?i)(?:aws).{0,20}(?:secret|key).{0,10}[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`)

	reGitHubToken = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(gh[pousr]_[A-Za-z0-9_]{36,255})(?:[^A-Za-z0-9]|$)`)

	reSlackToken = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(xox[bposatr]-[A-Za-z0-9-]{10,250})(?:[^A-Za-z0-9]|$)`)

	reStripeKey = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(sk_live_[A-Za-z0-9]{24,99})(?:[^A-Za-z0-9]|$)`)

	reGoogleAPIKey = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(AIza[0-9A-Za-z\-_]{35})(?:[^A-Za-z0-9]|$)`)

	reSendGridKey = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?:[^A-Za-z0-9]|$)`)

	reTwilioKey = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(SK[0-9a-fA-F]{32})(?:[^A-Za-z0-9]|$)`)

	// Generic pattern: api_key/apikey/api-key = "high-entropy-string"
	reGenericAPIKey = regexp.MustCompile(
		`(?i)(?:api[_-]?key|api[_-]?secret|client[_-]?secret)\s*[:=]=?\s*["']([A-Za-z0-9+/=_\-]{20,})["']`)
)

// BATOU-SEC-003: Private key patterns.
var (
	rePrivateKey = regexp.MustCompile(`-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----`)
)

// BATOU-SEC-004: Connection string patterns.
var (
	reConnStringURI = regexp.MustCompile(
		`(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:]+:[^\s@]+@[^\s]+`)

	reJDBCPassword = regexp.MustCompile(
		`(?i)jdbc:[a-z]+://[^\s]+.*(?:password|pwd)\s*=\s*["']?([^\s;"'&]+)`)

	reConnStringKV = regexp.MustCompile(
		`(?i)(?:Server|Data Source|Host)\s*=.*(?:Password|Pwd)\s*=\s*["']?([^\s;"']+)`)
)

// BATOU-SEC-005: JWT secret patterns.
var (
	reJWTSign = regexp.MustCompile(
		`(?i)jwt\.(?:sign|encode|decode)\s*\([^,]+,\s*["']([^"']{2,})["']`)

	reJWTSecret = regexp.MustCompile(
		`(?i)(?:jwt[_-]?secret|signing[_-]?key|secret[_-]?key)\s*[:=]=?\s*(?:[^"'\n]*\|\|\s*)?["']([^"']{2,})["']`)
)

// BATOU-SEC-006: Environment variable leak patterns.
var (
	reEnvFileContent = regexp.MustCompile(
		`(?i)^[A-Z_]{2,50}=["']?[^\s"']+["']?`)

	reEnvLogJS = regexp.MustCompile(
		`(?i)console\.(?:log|info|warn|error|debug)\s*\(.*process\.env\.[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|CREDENTIAL|AUTH)`)

	reEnvLogPy = regexp.MustCompile(
		`(?i)(?:print|logging\.(?:info|debug|warning|error))\s*\(.*os\.environ(?:\[|\.get\s*\().*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|CREDENTIAL|AUTH)`)

	reEnvLogGeneric = regexp.MustCompile(
		`(?i)(?:log|logger|console|fmt\.Print|println|puts|echo)\s*[.(].*(?:process\.env|os\.environ|ENV\[|getenv)\s*[[(."'].*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|CREDENTIAL|AUTH)`)
)

// --- Helper functions ---

// isTestFile returns true if the file path looks like a test / fixture / example file.
func isTestFile(path string) bool {
	return reTestFile.MatchString(path)
}

// isPlaceholder checks if the value is a common placeholder / example that should be excluded.
func isPlaceholder(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, p := range placeholderValues {
		if lower == p || strings.HasPrefix(lower, p) {
			return true
		}
	}
	// If it looks like a variable reference, skip it.
	if strings.ContainsAny(value, "${}%") {
		return true
	}
	return false
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// hasHighEntropy returns true if the string appears to have enough randomness
// to be a real secret (mix of character classes, sufficient entropy).
func hasHighEntropy(s string, minEntropy float64) bool {
	if len(s) < 8 {
		return false
	}
	return shannonEntropy(s) >= minEntropy
}

// hasCharacterDiversity checks if the string contains at least 3 of: uppercase, lowercase, digits, special.
func hasCharacterDiversity(s string) bool {
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range s {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	count := 0
	for _, b := range []bool{hasUpper, hasLower, hasDigit, hasSpecial} {
		if b {
			count++
		}
	}
	return count >= 3
}

// redactValue replaces most of a secret value with asterisks for safe display.
func redactValue(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	visible := 4
	if len(s) < 8 {
		visible = 2
	}
	return s[:visible] + strings.Repeat("*", len(s)-visible)
}

// isEnvFile checks if the file is a .env style file.
func isEnvFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".env") ||
		strings.Contains(lower, ".env.") ||
		strings.HasSuffix(lower, "/env") ||
		strings.HasSuffix(lower, ".env.local") ||
		strings.HasSuffix(lower, ".env.production") ||
		strings.HasSuffix(lower, ".env.development")
}

// isCommentLine checks if the line is likely a comment.
func isCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "<!--") ||
		strings.HasPrefix(trimmed, "--")
}

// ========================================================================
// Rule 1: BATOU-SEC-001 HardcodedPassword
// ========================================================================

// HardcodedPassword detects password and secret values assigned as string literals.
type HardcodedPassword struct{}

func (r *HardcodedPassword) ID() string          { return "BATOU-SEC-001" }
func (r *HardcodedPassword) Name() string         { return "HardcodedPassword" }
func (r *HardcodedPassword) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *HardcodedPassword) Description() string {
	return "Detects hardcoded passwords, secrets, and credentials assigned as string literals in source code."
}
func (r *HardcodedPassword) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangRuby, rules.LangPHP, rules.LangCSharp,
	}
}

func (r *HardcodedPassword) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Choose pattern set based on language.
	patterns := []*regexp.Regexp{rePasswordGeneric}
	switch ctx.Language {
	case rules.LangGo, rules.LangJava, rules.LangCSharp:
		patterns = append(patterns, rePasswordCStyle)
	case rules.LangPython, rules.LangRuby:
		patterns = append(patterns, rePasswordPyRuby)
	case rules.LangPHP:
		patterns = append(patterns, rePasswordPHP)
	}

	seen := make(map[int]bool) // avoid duplicate findings on same line

	for lineNum, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, pat := range patterns {
			matches := pat.FindStringSubmatch(line)
			if matches == nil || seen[lineNum+1] {
				continue
			}
			// matches[1] = variable name, matches[2] = value
			if len(matches) < 3 {
				continue
			}
			varName := matches[1]
			value := matches[2]

			if isPlaceholder(value) {
				continue
			}

			seen[lineNum+1] = true
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded credential detected",
				Description:   "Variable '" + varName + "' is assigned a hardcoded secret value. Use environment variables, a secrets manager, or a configuration vault instead.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Replace the hardcoded value with an environment variable (e.g., os.Getenv(\"" + strings.ToUpper(varName) + "\")) or a secrets manager lookup.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "credentials", "hardcoded"},
			})
		}
	}
	return findings
}

// ========================================================================
// Rule 2: BATOU-SEC-002 APIKeyExposure
// ========================================================================

// APIKeyExposure detects hardcoded API keys with known provider formats.
type APIKeyExposure struct{}

func (r *APIKeyExposure) ID() string          { return "BATOU-SEC-002" }
func (r *APIKeyExposure) Name() string         { return "APIKeyExposure" }
func (r *APIKeyExposure) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *APIKeyExposure) Description() string {
	return "Detects hardcoded API keys from known providers (AWS, GitHub, Slack, Stripe, Google, SendGrid, Twilio) and generic high-entropy API key patterns."
}
func (r *APIKeyExposure) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

// apiKeyPattern bundles a compiled regex with a provider label.
type apiKeyPattern struct {
	re       *regexp.Regexp
	provider string
}

var knownAPIKeyPatterns = []apiKeyPattern{
	{reAWSAccessKey, "AWS Access Key"},
	{reAWSSecretKey, "AWS Secret Key"},
	{reGitHubToken, "GitHub Token"},
	{reSlackToken, "Slack Token"},
	{reStripeKey, "Stripe Secret Key"},
	{reGoogleAPIKey, "Google API Key"},
	{reSendGridKey, "SendGrid API Key"},
	{reTwilioKey, "Twilio API Key"},
}

func (r *APIKeyExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	seen := make(map[int]bool)

	for lineNum, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Check known provider patterns.
		for _, kp := range knownAPIKeyPatterns {
			matches := kp.re.FindStringSubmatch(line)
			if matches == nil || seen[lineNum+1] {
				continue
			}
			keyValue := matches[1]

			seen[lineNum+1] = true
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         kp.provider + " exposed in source code",
				Description:   "A " + kp.provider + " (" + redactValue(keyValue) + ") was found hardcoded in source code. Rotate this key immediately and move it to a secrets manager.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Revoke and rotate this " + kp.provider + ". Store secrets in environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "api-key", strings.ToLower(strings.ReplaceAll(kp.provider, " ", "-"))},
			})
		}

		// Check generic API key pattern with entropy validation.
		if !seen[lineNum+1] {
			matches := reGenericAPIKey.FindStringSubmatch(line)
			if matches != nil {
				value := matches[1]
				if hasHighEntropy(value, 3.5) && hasCharacterDiversity(value) {
					seen[lineNum+1] = true
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						SeverityLabel: r.DefaultSeverity().String(),
						Title:         "Possible API key exposed in source code",
						Description:   "A high-entropy string (" + redactValue(value) + ") was found assigned to an API key variable. This may be a real credential.",
						FilePath:      ctx.FilePath,
						LineNumber:    lineNum + 1,
						MatchedText:   strings.TrimSpace(line),
						Suggestion:    "Move this value to an environment variable or secrets manager.",
						CWEID:         "CWE-798",
						OWASPCategory: "A07:2021-Identification and Authentication Failures",
						Language:      ctx.Language,
						Confidence:    "medium",
						Tags:          []string{"secrets", "api-key", "generic"},
					})
				}
			}
		}
	}
	return findings
}

// ========================================================================
// Rule 3: BATOU-SEC-003 PrivateKeyInCode
// ========================================================================

// PrivateKeyInCode detects embedded PEM-encoded private keys.
type PrivateKeyInCode struct{}

func (r *PrivateKeyInCode) ID() string          { return "BATOU-SEC-003" }
func (r *PrivateKeyInCode) Name() string         { return "PrivateKeyInCode" }
func (r *PrivateKeyInCode) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PrivateKeyInCode) Description() string {
	return "Detects PEM-encoded private keys (RSA, EC, DSA, OpenSSH, Ed25519) embedded in source code."
}
func (r *PrivateKeyInCode) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PrivateKeyInCode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for lineNum, line := range lines {
		if rePrivateKey.MatchString(line) {
			keyType := "Private Key"
			match := rePrivateKey.FindString(line)
			if strings.Contains(match, "RSA") {
				keyType = "RSA Private Key"
			} else if strings.Contains(match, "EC") {
				keyType = "EC Private Key"
			} else if strings.Contains(match, "DSA") {
				keyType = "DSA Private Key"
			} else if strings.Contains(match, "OPENSSH") {
				keyType = "OpenSSH Private Key"
			} else if strings.Contains(match, "ED25519") {
				keyType = "Ed25519 Private Key"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         keyType + " embedded in source code",
				Description:   "A PEM-encoded " + keyType + " was found in the source file. Private keys must never be stored in source code.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum + 1,
				MatchedText:   match,
				Suggestion:    "Remove the private key from source code. Store it in a secure key management system (e.g., AWS KMS, HashiCorp Vault) or load it from a file path specified via environment variable.",
				CWEID:         "CWE-321",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "private-key", "cryptography"},
			})
		}
	}
	return findings
}

// ========================================================================
// Rule 4: BATOU-SEC-004 ConnectionString
// ========================================================================

// ConnectionString detects database connection strings with embedded credentials.
type ConnectionString struct{}

func (r *ConnectionString) ID() string          { return "BATOU-SEC-004" }
func (r *ConnectionString) Name() string         { return "ConnectionString" }
func (r *ConnectionString) DefaultSeverity() rules.Severity { return rules.High }
func (r *ConnectionString) Description() string {
	return "Detects database connection strings (PostgreSQL, MySQL, MongoDB, Redis, MSSQL) containing embedded credentials."
}
func (r *ConnectionString) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *ConnectionString) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	seen := make(map[int]bool)

	connPatterns := []struct {
		re    *regexp.Regexp
		label string
	}{
		{reConnStringURI, "Database connection string with credentials"},
		{reJDBCPassword, "JDBC connection string with password"},
		{reConnStringKV, "Connection string with embedded password"},
	}

	for lineNum, line := range lines {
		if isCommentLine(line) {
			continue
		}

		for _, cp := range connPatterns {
			if !cp.re.MatchString(line) || seen[lineNum+1] {
				continue
			}

			// Exclude placeholder URIs.
			lower := strings.ToLower(line)
			if strings.Contains(lower, "username:password@") ||
				strings.Contains(lower, "user:pass@") ||
				strings.Contains(lower, "user:password@") ||
				strings.Contains(lower, "<password>") ||
				strings.Contains(lower, "${") ||
				strings.Contains(lower, "#{") ||
				strings.Contains(lower, "{{") {
				continue
			}

			seen[lineNum+1] = true
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         cp.label,
				Description:   "A database connection string with embedded credentials was found. Credentials in connection strings can be extracted if source code is exposed.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Use environment variables for connection parameters. Construct the connection string at runtime from separately managed credentials.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "credentials", "database", "connection-string"},
			})
		}
	}
	return findings
}

// ========================================================================
// Rule 5: BATOU-SEC-005 JWTSecret
// ========================================================================

// JWTSecret detects hardcoded JWT signing secrets and keys.
type JWTSecret struct{}

func (r *JWTSecret) ID() string          { return "BATOU-SEC-005" }
func (r *JWTSecret) Name() string         { return "JWTSecret" }
func (r *JWTSecret) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JWTSecret) Description() string {
	return "Detects hardcoded JWT signing secrets and keys used in jwt.sign(), jwt.encode(), and SECRET_KEY assignments."
}
func (r *JWTSecret) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangRuby, rules.LangPHP,
	}
}

func (r *JWTSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	if isTestFile(ctx.FilePath) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	seen := make(map[int]bool)

	jwtPatterns := []*regexp.Regexp{reJWTSign, reJWTSecret}

	for lineNum, line := range lines {
		if isCommentLine(line) {
			continue
		}

		for _, pat := range jwtPatterns {
			matches := pat.FindStringSubmatch(line)
			if matches == nil || seen[lineNum+1] {
				continue
			}
			value := matches[1]

			if isPlaceholder(value) {
				continue
			}

			seen[lineNum+1] = true
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded JWT signing secret",
				Description:   "A hardcoded JWT signing secret (" + redactValue(value) + ") was detected. An attacker with this secret can forge authentication tokens.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Load the JWT signing secret from an environment variable or secrets manager. Use asymmetric keys (RS256/ES256) where possible.",
				CWEID:         "CWE-321",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"secrets", "jwt", "authentication", "cryptography"},
			})
		}
	}
	return findings
}

// ========================================================================
// Rule 6: BATOU-SEC-006 EnvironmentLeak
// ========================================================================

// EnvironmentLeak detects .env file contents and sensitive env vars being logged.
type EnvironmentLeak struct{}

func (r *EnvironmentLeak) ID() string          { return "BATOU-SEC-006" }
func (r *EnvironmentLeak) Name() string         { return "EnvironmentLeak" }
func (r *EnvironmentLeak) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *EnvironmentLeak) Description() string {
	return "Detects .env file contents being committed and sensitive environment variables being logged or printed."
}
func (r *EnvironmentLeak) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *EnvironmentLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if this is a .env file with real content.
	if isEnvFile(ctx.FilePath) {
		sensitiveEnvVars := regexp.MustCompile(
			`(?i)^(.*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|CREDENTIAL|AUTH|PRIVATE).*)=["']?([^\s"']+)`)
		for lineNum, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if sensitiveEnvVars.MatchString(line) {
				matches := sensitiveEnvVars.FindStringSubmatch(line)
				varName := ""
				if len(matches) >= 2 {
					varName = matches[1]
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.High, // Elevated for actual .env files.
					SeverityLabel: rules.High.String(),
					Title:         "Sensitive value in .env file",
					Description:   "The .env file contains a sensitive variable '" + varName + "'. Environment files with real credentials should never be committed to source control.",
					FilePath:      ctx.FilePath,
					LineNumber:    lineNum + 1,
					MatchedText:   strings.TrimSpace(line),
					Suggestion:    "Add .env to .gitignore. Use .env.example with placeholder values for documentation. Store real values in a secrets manager.",
					CWEID:         "CWE-312",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"secrets", "env-file", "configuration"},
				})
			}
		}
		return findings
	}

	// For non-.env files, detect logging of sensitive env vars.
	logPatterns := []*regexp.Regexp{reEnvLogJS, reEnvLogPy, reEnvLogGeneric}

	seen := make(map[int]bool)
	for lineNum, line := range lines {
		if isCommentLine(line) {
			continue
		}

		for _, pat := range logPatterns {
			if !pat.MatchString(line) || seen[lineNum+1] {
				continue
			}

			seen[lineNum+1] = true
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Sensitive environment variable logged",
				Description:   "A sensitive environment variable is being logged or printed. This can expose secrets in log files, console output, or monitoring systems.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum + 1,
				MatchedText:   strings.TrimSpace(line),
				Suggestion:    "Remove the logging statement for this sensitive variable. If debugging is needed, log only a masked version (e.g., first 4 characters).",
				CWEID:         "CWE-312",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"secrets", "logging", "environment-variable"},
			})
		}
	}
	return findings
}

// --- Registration ---

func init() {
	rules.Register(&HardcodedPassword{})
	rules.Register(&APIKeyExposure{})
	rules.Register(&PrivateKeyInCode{})
	rules.Register(&ConnectionString{})
	rules.Register(&JWTSecret{})
	rules.Register(&EnvironmentLeak{})
}
