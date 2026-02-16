package swift

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// --- Compiled patterns ---

// SWIFT-001: Insecure URLSession (TLS validation disabled)
var (
	urlSessionDelegate       = regexp.MustCompile(`URLSession\s*\(\s*configuration:.*delegate:`)
	tlsValidationDisabled    = regexp.MustCompile(`didReceive\s+challenge:.*URLAuthenticationChallenge`)
	trustAllCerts            = regexp.MustCompile(`\.useCredential\(|\.performDefaultHandling|completionHandler\(\s*\.useCredential`)
	cancelAuthChallenge      = regexp.MustCompile(`\.cancelAuthenticationChallenge|\.rejectProtectionSpace`)
	allowsArbitraryLoads     = regexp.MustCompile(`NSAllowsArbitraryLoads\s*</true>|"NSAllowsArbitraryLoads"\s*:\s*true|allowsArbitraryLoads\s*=\s*true`)
	serverTrustAlwaysAccept  = regexp.MustCompile(`serverTrust.*\.proceed|disposition\s*=\s*\.useCredential|URLCredential\(\s*trust:`)
)

// SWIFT-002: App Transport Security bypass
var (
	atsArbitraryLoads     = regexp.MustCompile(`NSAllowsArbitraryLoads`)
	atsInsecureHTTPLoads  = regexp.MustCompile(`NSExceptionAllowsInsecureHTTPLoads`)
	atsTrueValue          = regexp.MustCompile(`<true\s*/?>|:\s*true|=\s*true|YES`)
)

// SWIFT-003: Insecure Keychain storage
var (
	keychainAccessibleAlways = regexp.MustCompile(`kSecAttrAccessibleAlways\b`)
	keychainAlwaysDevice     = regexp.MustCompile(`kSecAttrAccessibleAlwaysThisDeviceOnly\b`)
	keychainAfterFirstUnlock = regexp.MustCompile(`kSecAttrAccessibleAfterFirstUnlock\b`)
)

// SWIFT-004: UIWebView usage (deprecated)
var (
	uiWebViewUsage = regexp.MustCompile(`\bUIWebView\b`)
)

// SWIFT-005: Hardcoded secrets
var (
	hardcodedAPIKey    = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*"[A-Za-z0-9_\-]{16,}"`)
	hardcodedPassword  = regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*"[^"]{4,}"`)
	hardcodedToken     = regexp.MustCompile(`(?i)(?:token|secret|auth[_-]?key|private[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*"[A-Za-z0-9_\-/.+]{8,}"`)
	hardcodedAWSKey    = regexp.MustCompile(`(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}`)
	letVarStringAssign = regexp.MustCompile(`(?:let|var)\s+\w*(?i:(?:key|secret|token|password|credential|auth))\w*\s*[:=]\s*"[^"]{8,}"`)
)

// SWIFT-006: Insecure random
var (
	arc4randomBare    = regexp.MustCompile(`\barc4random\(\)`)
	srandRand         = regexp.MustCompile(`\bsrand\(|srand48\(|\brand\(\)|\bdrand48\(\)|\brand\(\)\s*%`)
	gameplayRandom    = regexp.MustCompile(`GKRandomSource\(\)`)
)

// SWIFT-007: SQL injection in SQLite
var (
	sqlite3ExecInterp   = regexp.MustCompile(`sqlite3_exec\s*\(\s*\w+\s*,\s*"[^"]*\\?\(`)
	sqlite3PrepInterp   = regexp.MustCompile(`sqlite3_prepare(?:_v[23])?\s*\(\s*\w+\s*,\s*"[^"]*\\?\(`)
	sqlStringConcat     = regexp.MustCompile(`(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*["']\s*\+\s*\w+|` +
		`(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\\\(`)
	sqlStringInterp     = regexp.MustCompile(`"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s[^"]*\\\([^)]+\)`)
)

// SWIFT-008: WKWebView JavaScript injection
var (
	evaluateJSPattern    = regexp.MustCompile(`\.evaluateJavaScript\(`)
	loadHTMLStringPattern = regexp.MustCompile(`\.loadHTMLString\(`)
	jsStringInterp       = regexp.MustCompile(`\.evaluateJavaScript\(\s*"[^"]*\\\(|\.evaluateJavaScript\(\s*\w+\s*\+|\.evaluateJavaScript\(\s*String\(format:`)
	htmlStringInterp     = regexp.MustCompile(`\.loadHTMLString\(\s*"[^"]*\\\(|\.loadHTMLString\(\s*\w+\s*\+|\.loadHTMLString\(\s*String\(format:`)
)

// SWIFT-009: Insecure data storage
var (
	userDefaultsSecrets  = regexp.MustCompile(`UserDefaults\.standard\.set\(\s*\w*(?i:(?:password|token|secret|key|credential|auth|session|cookie|pin|ssn|credit))\w*`)
	userDefaultsKeyStore = regexp.MustCompile(`UserDefaults\.standard\.set\([^,]+,\s*forKey:\s*"(?i:(?:password|token|secret|key|credential|auth|session|cookie|pin|ssn|credit))[^"]*"`)
	nscodingPattern      = regexp.MustCompile(`NSCoding|NSKeyedArchiver\.archivedData|NSKeyedArchiver\.archiveRootObject`)
	nscodingSensitive    = regexp.MustCompile(`(?i)(?:password|token|secret|credential|private|auth|session|cookie)\w*.*NSKeyedArchiver|NSKeyedArchiver.*(?i:(?:password|token|secret|credential|private|auth|session|cookie))`)
)

// SWIFT-010: Jailbreak detection bypass
var (
	jailbreakFileCheck    = regexp.MustCompile(`"/Applications/Cydia\.app"|"/Library/MobileSubstrate"|"/usr/sbin/sshd"|"/etc/apt"|"/bin/bash"|"/private/var/stash"`)
	jailbreakCanOpen      = regexp.MustCompile(`canOpenURL\(\s*URL\(\s*string:\s*"cydia://`)
	jailbreakWriteTest    = regexp.MustCompile(`"/.installed_turing"|"/private/jailbreak"|try\s*".*"\.write\(\s*toFile:\s*"/private/`)
)

func init() {
	rules.Register(&InsecureURLSession{})
	rules.Register(&ATSBypass{})
	rules.Register(&InsecureKeychain{})
	rules.Register(&UIWebViewUsage{})
	rules.Register(&HardcodedSecrets{})
	rules.Register(&InsecureRandom{})
	rules.Register(&SQLiteInjection{})
	rules.Register(&WKWebViewInjection{})
	rules.Register(&InsecureDataStorage{})
	rules.Register(&JailbreakDetectionBypass{})
}

// --- helpers ---

func isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// --- SWIFT-001: Insecure URLSession ---

type InsecureURLSession struct{}

func (r *InsecureURLSession) ID() string                      { return "BATOU-SWIFT-001" }
func (r *InsecureURLSession) Name() string                    { return "InsecureURLSession" }
func (r *InsecureURLSession) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureURLSession) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *InsecureURLSession) Description() string {
	return "Detects URLSession delegates that disable TLS certificate validation or accept all server certificates."
}

func (r *InsecureURLSession) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inChallengeHandler := false
	handlerStartLine := 0
	braceDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if tlsValidationDisabled.MatchString(line) {
			inChallengeHandler = true
			handlerStartLine = i
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inChallengeHandler {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if serverTrustAlwaysAccept.MatchString(line) {
				// Check if there's proper certificate pinning logic nearby
				hasPinning := false
				start := handlerStartLine
				end := i + 5
				if end > len(lines) {
					end = len(lines)
				}
				for _, contextLine := range lines[start:end] {
					if strings.Contains(contextLine, "SecTrustEvaluate") ||
						strings.Contains(contextLine, "SecTrustCopyPublicKey") ||
						strings.Contains(contextLine, "pinnedCert") ||
						strings.Contains(contextLine, "SecCertificateCopyData") ||
						strings.Contains(contextLine, "SecTrustEvaluateWithError") {
						hasPinning = true
						break
					}
				}

				if !hasPinning {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						Title:         "URLSession delegate accepts all server certificates without validation",
						Description:   "The URLAuthenticationChallenge handler accepts server trust without proper certificate validation. This disables TLS certificate pinning and allows man-in-the-middle attacks.",
						LineNumber:    i + 1,
						MatchedText:   truncate(strings.TrimSpace(line), 120),
						Suggestion:    "Implement proper certificate pinning by verifying the server certificate against a known pin. Use SecTrustEvaluateWithError and compare the server's public key or certificate hash against pinned values.",
						CWEID:         "CWE-295",
						OWASPCategory: "A07:2021-Identification and Authentication Failures",
						Confidence:    "high",
						Tags:          []string{"swift", "tls", "certificate-validation", "ios"},
					})
				}
			}

			if braceDepth <= 0 {
				inChallengeHandler = false
			}
		}
	}

	return findings
}

// --- SWIFT-002: App Transport Security Bypass ---

type ATSBypass struct{}

func (r *ATSBypass) ID() string                      { return "BATOU-SWIFT-002" }
func (r *ATSBypass) Name() string                    { return "ATSBypass" }
func (r *ATSBypass) DefaultSeverity() rules.Severity { return rules.High }
func (r *ATSBypass) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift, rules.LangAny}
}
func (r *ATSBypass) Description() string {
	return "Detects App Transport Security bypass configurations (NSAllowsArbitraryLoads, NSExceptionAllowsInsecureHTTPLoads) in Info.plist or Swift code."
}

func (r *ATSBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only scan plist files and Swift files
	lower := strings.ToLower(ctx.FilePath)
	if !strings.HasSuffix(lower, ".plist") && !strings.HasSuffix(lower, ".swift") &&
		!strings.HasSuffix(lower, ".xml") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if atsArbitraryLoads.MatchString(line) {
			// Check if the next few lines contain <true/>
			hasTrue := false
			end := i + 3
			if end > len(lines) {
				end = len(lines)
			}
			for j := i; j < end; j++ {
				if atsTrueValue.MatchString(lines[j]) {
					hasTrue = true
					break
				}
			}
			if hasTrue || strings.Contains(line, "true") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "App Transport Security disabled (NSAllowsArbitraryLoads)",
					Description:   "NSAllowsArbitraryLoads is set to true, disabling App Transport Security for all network connections. This allows plaintext HTTP traffic and connections to servers with invalid certificates.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Remove NSAllowsArbitraryLoads or set it to false. Use NSExceptionDomains to allow specific domains that require HTTP, and configure them with the minimum necessary exceptions.",
					CWEID:         "CWE-319",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Confidence:    "high",
					Tags:          []string{"swift", "ats", "transport-security", "ios", "plist"},
				})
			}
		}

		if atsInsecureHTTPLoads.MatchString(line) {
			hasTrue := false
			end := i + 3
			if end > len(lines) {
				end = len(lines)
			}
			for j := i; j < end; j++ {
				if atsTrueValue.MatchString(lines[j]) {
					hasTrue = true
					break
				}
			}
			if hasTrue || strings.Contains(line, "true") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Medium,
					Title:         "ATS exception allows insecure HTTP loads for domain",
					Description:   "NSExceptionAllowsInsecureHTTPLoads permits plaintext HTTP connections for a specific domain exception. This weakens transport security for that domain.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Ensure the target server supports HTTPS and remove the insecure HTTP exception. If HTTP is temporarily necessary, document the reason and plan migration to HTTPS.",
					CWEID:         "CWE-319",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Confidence:    "high",
					Tags:          []string{"swift", "ats", "transport-security", "ios", "plist"},
				})
			}
		}
	}

	return findings
}

// --- SWIFT-003: Insecure Keychain Storage ---

type InsecureKeychain struct{}

func (r *InsecureKeychain) ID() string                      { return "BATOU-SWIFT-003" }
func (r *InsecureKeychain) Name() string                    { return "InsecureKeychain" }
func (r *InsecureKeychain) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureKeychain) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *InsecureKeychain) Description() string {
	return "Detects insecure Keychain accessibility settings (kSecAttrAccessibleAlways, kSecAttrAccessibleAlwaysThisDeviceOnly) that make items accessible when device is locked."
}

func (r *InsecureKeychain) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if keychainAccessibleAlways.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Keychain item accessible when device is locked (kSecAttrAccessibleAlways)",
				Description:   "The Keychain item uses kSecAttrAccessibleAlways, making it accessible even when the device is locked. This accessibility level is deprecated and allows extraction of secrets from a locked device.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use kSecAttrAccessibleWhenUnlocked or kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly for sensitive data. These ensure the item is only accessible when the device is unlocked by the user.",
				CWEID:         "CWE-921",
				OWASPCategory: "A04:2021-Insecure Design",
				Confidence:    "high",
				Tags:          []string{"swift", "keychain", "storage", "ios"},
			})
		}

		if keychainAlwaysDevice.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Medium,
				Title:         "Keychain item accessible when device is locked (kSecAttrAccessibleAlwaysThisDeviceOnly)",
				Description:   "The Keychain item uses kSecAttrAccessibleAlwaysThisDeviceOnly, making it accessible when the device is locked. While device-only prevents backup extraction, the item is still vulnerable on an unlocked or jailbroken device.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly for better protection.",
				CWEID:         "CWE-921",
				OWASPCategory: "A04:2021-Insecure Design",
				Confidence:    "high",
				Tags:          []string{"swift", "keychain", "storage", "ios"},
			})
		}
	}

	return findings
}

// --- SWIFT-004: UIWebView Usage ---

type UIWebViewUsage struct{}

func (r *UIWebViewUsage) ID() string                      { return "BATOU-SWIFT-004" }
func (r *UIWebViewUsage) Name() string                    { return "UIWebViewUsage" }
func (r *UIWebViewUsage) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UIWebViewUsage) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *UIWebViewUsage) Description() string {
	return "Detects usage of UIWebView, which is deprecated and lacks modern security features like content filtering and JavaScript sandboxing."
}

func (r *UIWebViewUsage) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if uiWebViewUsage.MatchString(line) {
			// Skip import statements - only flag actual usage
			if strings.Contains(trimmed, "import") {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Deprecated UIWebView usage detected",
				Description:   "UIWebView is deprecated since iOS 12 and rejected by the App Store since December 2020. It lacks WKWebView's security features including process isolation, content filtering, and the ability to disable JavaScript.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Replace UIWebView with WKWebView. WKWebView runs in a separate process, provides better security isolation, and supports content rules and JavaScript sandboxing.",
				CWEID:         "CWE-477",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Confidence:    "high",
				Tags:          []string{"swift", "webview", "deprecated", "ios"},
			})
		}
	}

	return findings
}

// --- SWIFT-005: Hardcoded Secrets ---

type HardcodedSecrets struct{}

func (r *HardcodedSecrets) ID() string                      { return "BATOU-SWIFT-005" }
func (r *HardcodedSecrets) Name() string                    { return "HardcodedSecrets" }
func (r *HardcodedSecrets) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *HardcodedSecrets) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *HardcodedSecrets) Description() string {
	return "Detects hardcoded API keys, passwords, tokens, and other secrets as string literals in Swift code."
}

func (r *HardcodedSecrets) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// Skip test/example/placeholder values
		lower := strings.ToLower(line)
		if strings.Contains(lower, "example") || strings.Contains(lower, "placeholder") ||
			strings.Contains(lower, "test") || strings.Contains(lower, "todo") ||
			strings.Contains(lower, "fixme") || strings.Contains(lower, "xxx") ||
			strings.Contains(lower, "your_") || strings.Contains(lower, "your-") ||
			strings.Contains(lower, "<your") || strings.Contains(lower, "change_me") {
			continue
		}

		if hardcodedAWSKey.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				Title:         "Hardcoded AWS access key detected",
				Description:   "An AWS access key ID is embedded directly in source code. AWS keys in source code can be extracted from compiled binaries or source repositories, granting attackers access to AWS resources.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Store AWS credentials in the iOS Keychain or load them from a secure backend service at runtime. Never embed cloud provider keys in client-side code.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Confidence:    "high",
				Tags:          []string{"swift", "secrets", "aws", "hardcoded", "ios"},
			})
			continue
		}

		if letVarStringAssign.MatchString(line) {
			severity := rules.High
			confidence := "high"

			if hardcodedPassword.MatchString(line) {
				severity = rules.Critical
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      severity,
				Title:         "Hardcoded secret in Swift string literal",
				Description:   "A secret value (API key, password, token, or credential) is hardcoded as a string literal. Secrets in compiled iOS apps can be extracted using tools like class-dump or strings.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Store secrets in the iOS Keychain using SecItemAdd. For API keys, use a server-side proxy or fetch keys securely at runtime. Consider using Xcode configuration files (.xcconfig) with .gitignore for build-time secrets.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Confidence:    confidence,
				Tags:          []string{"swift", "secrets", "hardcoded", "ios"},
			})
		}
	}

	return findings
}

// --- SWIFT-006: Insecure Random ---

type InsecureRandom struct{}

func (r *InsecureRandom) ID() string                      { return "BATOU-SWIFT-006" }
func (r *InsecureRandom) Name() string                    { return "InsecureRandom" }
func (r *InsecureRandom) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureRandom) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *InsecureRandom) Description() string {
	return "Detects insecure random number generation patterns including arc4random() without uniform distribution and C-library rand/srand."
}

func (r *InsecureRandom) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if the file uses random in a security-sensitive context
	contentLower := strings.ToLower(ctx.Content)
	isSecurityContext := strings.Contains(contentLower, "token") ||
		strings.Contains(contentLower, "password") ||
		strings.Contains(contentLower, "nonce") ||
		strings.Contains(contentLower, "secret") ||
		strings.Contains(contentLower, "key") ||
		strings.Contains(contentLower, "salt") ||
		strings.Contains(contentLower, "otp") ||
		strings.Contains(contentLower, "cipher") ||
		strings.Contains(contentLower, "encrypt") ||
		strings.Contains(contentLower, "session") ||
		strings.Contains(contentLower, "csrf")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if srandRand.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				Title:         "C-library random function used (srand/rand/drand48)",
				Description:   "C-library random functions (srand, rand, drand48) produce predictable sequences and are not suitable for any use in Swift. The output can be reproduced if the seed is known or guessed.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use SecRandomCopyBytes for cryptographic randomness, or Int.random(in:) / SystemRandomNumberGenerator for non-security purposes.",
				CWEID:         "CWE-338",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Confidence:    "high",
				Tags:          []string{"swift", "random", "cryptography", "ios"},
			})
			continue
		}

		if arc4randomBare.MatchString(line) && isSecurityContext {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "arc4random() used in security context (modulo bias)",
				Description:   "arc4random() without arc4random_uniform() in a security-sensitive context can introduce modulo bias when used with the modulo operator. While arc4random is cryptographically secure, modulo bias can make some values more likely than others.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use SecRandomCopyBytes for cryptographic purposes, or arc4random_uniform() for uniform distribution in a range. In Swift 4.2+, prefer Int.random(in:) which uses SystemRandomNumberGenerator.",
				CWEID:         "CWE-338",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Confidence:    "medium",
				Tags:          []string{"swift", "random", "cryptography", "ios"},
			})
		}
	}

	return findings
}

// --- SWIFT-007: SQL Injection in SQLite ---

type SQLiteInjection struct{}

func (r *SQLiteInjection) ID() string                      { return "BATOU-SWIFT-007" }
func (r *SQLiteInjection) Name() string                    { return "SQLiteInjection" }
func (r *SQLiteInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SQLiteInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *SQLiteInjection) Description() string {
	return "Detects SQL injection vulnerabilities in SQLite queries using string interpolation or concatenation instead of parameterized queries."
}

func (r *SQLiteInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasSQLiteImport := strings.Contains(ctx.Content, "sqlite3") ||
		strings.Contains(ctx.Content, "SQLite") ||
		strings.Contains(ctx.Content, "import GRDB") ||
		strings.Contains(ctx.Content, "import SQLite")

	if !hasSQLiteImport {
		return nil
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// Check for string interpolation in SQL queries
		if sqlStringInterp.MatchString(line) {
			// Check if sqlite3_bind is used nearby (parameterized)
			hasBind := false
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			for j := i; j < end; j++ {
				if strings.Contains(lines[j], "sqlite3_bind_") {
					hasBind = true
					break
				}
			}
			if !hasBind {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "SQL injection via string interpolation in SQLite query",
					Description:   "A SQLite query uses Swift string interpolation (\\()) to embed values directly in the SQL string. An attacker can inject arbitrary SQL commands through the interpolated value.",
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use parameterized queries with sqlite3_prepare_v2 and sqlite3_bind_text/int. Replace string interpolation with ? placeholders and bind values separately.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Confidence:    "high",
					Tags:          []string{"swift", "sqlite", "sql-injection", "ios"},
				})
			}
		}
	}

	return findings
}

// --- SWIFT-008: WKWebView JavaScript Injection ---

type WKWebViewInjection struct{}

func (r *WKWebViewInjection) ID() string                      { return "BATOU-SWIFT-008" }
func (r *WKWebViewInjection) Name() string                    { return "WKWebViewInjection" }
func (r *WKWebViewInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *WKWebViewInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *WKWebViewInjection) Description() string {
	return "Detects WKWebView evaluateJavaScript or loadHTMLString with user input via string interpolation, enabling JavaScript injection or XSS."
}

func (r *WKWebViewInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if jsStringInterp.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "WKWebView evaluateJavaScript with dynamic string content",
				Description:   "The evaluateJavaScript call uses string interpolation or concatenation to build the JavaScript string. If user input is included, an attacker can execute arbitrary JavaScript in the WebView context, accessing cookies, local storage, and app-registered handlers.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Avoid string interpolation in evaluateJavaScript. Use WKWebView's callAsyncJavaScript or pass data via WKScriptMessageHandler and postMessage. If interpolation is needed, sanitize all input by escaping special JavaScript characters.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Confidence:    "high",
				Tags:          []string{"swift", "webview", "xss", "javascript-injection", "ios"},
			})
		}

		if htmlStringInterp.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "WKWebView loadHTMLString with dynamic HTML content",
				Description:   "The loadHTMLString call uses string interpolation or concatenation to build HTML. If user input is included, an attacker can inject arbitrary HTML or JavaScript, leading to XSS within the WebView.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Sanitize all user input before including it in HTML strings. Encode HTML entities (< > & \" '). Set baseURL to about:blank to prevent file:// access. Consider using a templating library with auto-escaping.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Confidence:    "high",
				Tags:          []string{"swift", "webview", "xss", "html-injection", "ios"},
			})
		}
	}

	return findings
}

// --- SWIFT-009: Insecure Data Storage ---

type InsecureDataStorage struct{}

func (r *InsecureDataStorage) ID() string                      { return "BATOU-SWIFT-009" }
func (r *InsecureDataStorage) Name() string                    { return "InsecureDataStorage" }
func (r *InsecureDataStorage) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureDataStorage) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *InsecureDataStorage) Description() string {
	return "Detects sensitive data stored in UserDefaults (unencrypted plist) or NSCoding archives instead of the Keychain."
}

func (r *InsecureDataStorage) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if userDefaultsSecrets.MatchString(line) || userDefaultsKeyStore.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Sensitive data stored in UserDefaults",
				Description:   "Sensitive data (password, token, secret, credential) is being stored in UserDefaults, which writes to an unencrypted plist file. On jailbroken devices or via iTunes backup, this data is trivially accessible.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Store sensitive data in the iOS Keychain using SecItemAdd/SecItemUpdate with appropriate kSecAttrAccessible settings. UserDefaults is only suitable for non-sensitive user preferences.",
				CWEID:         "CWE-922",
				OWASPCategory: "A04:2021-Insecure Design",
				Confidence:    "high",
				Tags:          []string{"swift", "storage", "userdefaults", "ios"},
			})
		}

		if nscodingSensitive.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Medium,
				Title:         "Sensitive data archived with NSKeyedArchiver",
				Description:   "Sensitive data is being serialized using NSKeyedArchiver, which produces unencrypted archive files. The archived data can be read by anyone with access to the file system.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Encrypt sensitive data before archiving, or store it in the Keychain. If using NSKeyedArchiver, ensure the output file has NSFileProtectionComplete data protection.",
				CWEID:         "CWE-922",
				OWASPCategory: "A04:2021-Insecure Design",
				Confidence:    "medium",
				Tags:          []string{"swift", "storage", "nscoding", "ios"},
			})
		}
	}

	return findings
}

// --- SWIFT-010: Jailbreak Detection Bypass ---

type JailbreakDetectionBypass struct{}

func (r *JailbreakDetectionBypass) ID() string                      { return "BATOU-SWIFT-010" }
func (r *JailbreakDetectionBypass) Name() string                    { return "JailbreakDetectionBypass" }
func (r *JailbreakDetectionBypass) DefaultSeverity() rules.Severity { return rules.Low }
func (r *JailbreakDetectionBypass) Languages() []rules.Language {
	return []rules.Language{rules.LangSwift}
}
func (r *JailbreakDetectionBypass) Description() string {
	return "Detects common jailbreak detection checks that are easily bypassed by tools like Frida, Liberty Lite, and Shadow. These checks provide minimal security value."
}

func (r *JailbreakDetectionBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if jailbreakFileCheck.MatchString(line) || jailbreakCanOpen.MatchString(line) ||
			jailbreakWriteTest.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Easily bypassed jailbreak detection check",
				Description:   "This jailbreak detection method (file existence check, URL scheme check, or write test) is trivially bypassed by common jailbreak bypass tools such as Frida, Liberty Lite, Shadow, and A-Bypass. Do not rely on this as a security control.",
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "If jailbreak detection is needed, use multiple detection methods together and integrate with a server-side risk assessment. Consider using Apple's DeviceCheck API or App Attest for device integrity verification. Jailbreak detection alone should not be a primary security control.",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Confidence:    "medium",
				Tags:          []string{"swift", "jailbreak", "detection", "ios"},
			})
			// Only one finding per file for this rule
			return findings
		}
	}

	return findings
}
