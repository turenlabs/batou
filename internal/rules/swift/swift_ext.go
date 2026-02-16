package swift

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Swift extension rules (GTSS-SWIFT-011 .. GTSS-SWIFT-018)
// ---------------------------------------------------------------------------

// SWIFT-011: URLSession with disabled SSL validation
var (
	reURLSessionNoValidate   = regexp.MustCompile(`\.serverTrust\b`)
	reDispositionUseCredential = regexp.MustCompile(`disposition\s*=\s*\.useCredential`)
	reURLCredentialTrust     = regexp.MustCompile(`URLCredential\s*\(\s*trust\s*:`)
	reCompletionUseCredential = regexp.MustCompile(`completionHandler\s*\(\s*\.useCredential`)
)

// SWIFT-012: Keychain access without authentication
var (
	reKeychainAdd           = regexp.MustCompile(`SecItemAdd\s*\(`)
	reKeychainQuery         = regexp.MustCompile(`SecItemCopyMatching\s*\(`)
	reKeychainAccessible    = regexp.MustCompile(`kSecAttrAccessible\b`)
	reKeychainAlways        = regexp.MustCompile(`kSecAttrAccessibleAlways\b|kSecAttrAccessibleAlwaysThisDeviceOnly\b`)
	reKeychainAccessControl = regexp.MustCompile(`SecAccessControlCreateWithFlags\s*\(|kSecAttrAccessControl\b`)
)

// SWIFT-013: UserDefaults storing sensitive data
var (
	reUserDefaultsSet = regexp.MustCompile(`UserDefaults\.standard\.set\s*\(`)
	reUserDefaultsSensKey = regexp.MustCompile(`(?i)UserDefaults\.standard\.set\s*\([^,]+,\s*forKey\s*:\s*"[^"]*(?:password|token|secret|key|auth|credential|pin|ssn|credit|session)[^"]*"`)
)

// SWIFT-014: WKWebView JavaScript enabled without content rules
var (
	reWKPrefsJSEnabled = regexp.MustCompile(`\.javaScriptEnabled\s*=\s*true|preferences\.javaScriptEnabled\s*=\s*true`)
	reWKContentRules   = regexp.MustCompile(`WKContentRuleListStore|contentRuleLists|WKUserContentController`)
	reWKNavDelegate    = regexp.MustCompile(`navigationDelegate\s*=|WKNavigationDelegate`)
)

// SWIFT-015: Hardcoded encryption key/IV
var (
	reHardcodedKey    = regexp.MustCompile(`(?i)(?:key|iv|nonce|salt)\s*(?::\s*\[UInt8\]\s*)?=\s*\[\s*0x[0-9a-fA-F]`)
	reHardcodedKeyStr = regexp.MustCompile(`(?i)(?:encryption|aes|des|cipher)(?:Key|IV)\s*=\s*"[^"]{8,}"`)
	reHardcodedKeyData = regexp.MustCompile(`(?i)(?:key|iv).*Data\s*\(\s*(?:bytes|base64Encoded)\s*:\s*(?:\[|")`)
)

// SWIFT-016: String interpolation in SQL/predicate
var (
	reSQLInterp      = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+.*\\?\(`)
	rePredicateInterp = regexp.MustCompile(`NSPredicate\s*\(\s*format\s*:\s*"[^"]*\\?\(`)
	rePredicateConcat = regexp.MustCompile(`NSPredicate\s*\(\s*format\s*:\s*"[^"]*"\s*\+`)
	reSQLStringInterp = regexp.MustCompile(`"(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"]*\\\(`)
)

// SWIFT-017: Insecure NSCoding deserialization
var (
	reNSKeyedUnarchiver     = regexp.MustCompile(`NSKeyedUnarchiver\.unarchiveObject\s*\(`)
	reNSKeyedUnarchiverData = regexp.MustCompile(`NSKeyedUnarchiver\.unarchiveObject\s*\(\s*with\s*:`)
	reNSCodingDecode        = regexp.MustCompile(`\.decodeObject\s*\(\s*forKey\s*:`)
	reNSSecureCoding        = regexp.MustCompile(`NSSecureCoding|requiresSecureCoding\s*=\s*true|unarchivedObject\s*\(\s*ofClass`)
)

// SWIFT-018: App Transport Security disabled
var (
	reATSDisabled      = regexp.MustCompile(`NSAllowsArbitraryLoads`)
	reATSInfoPlist     = regexp.MustCompile(`NSAppTransportSecurity`)
	reATSTrueValue     = regexp.MustCompile(`<true\s*/?>|:\s*true|=\s*true`)
)

func init() {
	rules.Register(&SwiftURLSessionNoSSL{})
	rules.Register(&SwiftKeychainNoAuth{})
	rules.Register(&SwiftUserDefaultsSensitive{})
	rules.Register(&SwiftWKWebViewJS{})
	rules.Register(&SwiftHardcodedKey{})
	rules.Register(&SwiftSQLPredicateInterp{})
	rules.Register(&SwiftNSCodingDeser{})
	rules.Register(&SwiftATSDisabled{})
}

// ---------------------------------------------------------------------------
// GTSS-SWIFT-011: Swift URLSession with disabled SSL validation
// ---------------------------------------------------------------------------

type SwiftURLSessionNoSSL struct{}

func (r *SwiftURLSessionNoSSL) ID() string                      { return "GTSS-SWIFT-011" }
func (r *SwiftURLSessionNoSSL) Name() string                    { return "SwiftURLSessionNoSSL" }
func (r *SwiftURLSessionNoSSL) Description() string             { return "Detects Swift URLSession delegates that unconditionally accept server trust challenges, disabling SSL/TLS certificate validation." }
func (r *SwiftURLSessionNoSSL) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SwiftURLSessionNoSSL) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftURLSessionNoSSL) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reURLSessionNoValidate.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var desc string

		if m := reDispositionUseCredential.FindString(line); m != "" {
			matched = m
			desc = "URLSession delegate sets disposition to .useCredential, unconditionally accepting the server certificate. This disables TLS certificate validation for all connections."
		} else if m := reURLCredentialTrust.FindString(line); m != "" {
			matched = m
			desc = "URLCredential is created from a server trust without proper validation. The certificate chain is accepted without checking validity, enabling man-in-the-middle attacks."
		} else if m := reCompletionUseCredential.FindString(line); m != "" {
			matched = m
			desc = "URLSession completion handler unconditionally uses .useCredential disposition, accepting any server certificate regardless of validity."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Swift URLSession with disabled SSL validation",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove the custom URLSession delegate or properly validate the server trust: evaluate SecTrust using SecTrustEvaluateWithError and only accept valid certificates. Use certificate pinning for sensitive connections.",
				CWEID:         "CWE-295",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "ios", "tls", "ssl-validation", "mitm"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SWIFT-012: Swift Keychain access without authentication
// ---------------------------------------------------------------------------

type SwiftKeychainNoAuth struct{}

func (r *SwiftKeychainNoAuth) ID() string                      { return "GTSS-SWIFT-012" }
func (r *SwiftKeychainNoAuth) Name() string                    { return "SwiftKeychainNoAuth" }
func (r *SwiftKeychainNoAuth) Description() string             { return "Detects Swift Keychain items stored with kSecAttrAccessibleAlways or without access control flags, making them readable without device authentication." }
func (r *SwiftKeychainNoAuth) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftKeychainNoAuth) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftKeychainNoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reKeychainAdd.MatchString(ctx.Content) && !reKeychainQuery.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if reKeychainAlways.MatchString(line) {
			matched := reKeychainAlways.FindString(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Swift Keychain with kSecAttrAccessibleAlways",
				Description:   "Keychain item is accessible at all times, even when the device is locked. This means keychain data can be extracted from a locked device backup or by physical access.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly. For sensitive data, add biometric protection via SecAccessControlCreateWithFlags with .biometryAny.",
				CWEID:         "CWE-287",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "ios", "keychain", "authentication"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SWIFT-013: Swift UserDefaults storing sensitive data
// ---------------------------------------------------------------------------

type SwiftUserDefaultsSensitive struct{}

func (r *SwiftUserDefaultsSensitive) ID() string                      { return "GTSS-SWIFT-013" }
func (r *SwiftUserDefaultsSensitive) Name() string                    { return "SwiftUserDefaultsSensitive" }
func (r *SwiftUserDefaultsSensitive) Description() string             { return "Detects Swift UserDefaults storing sensitive data (passwords, tokens, keys) which is stored unencrypted on the device." }
func (r *SwiftUserDefaultsSensitive) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftUserDefaultsSensitive) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftUserDefaultsSensitive) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reUserDefaultsSet.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if m := reUserDefaultsSensKey.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Swift UserDefaults storing sensitive data",
				Description:   "Sensitive data (password, token, secret, key, credential) is stored in UserDefaults which is a plaintext plist file on the device. It can be extracted via device backups, filesystem access on jailbroken devices, or by other apps with file sharing enabled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use the iOS Keychain (SecItemAdd) for sensitive data storage. For encryption keys, use the Secure Enclave. UserDefaults should only store non-sensitive preferences.",
				CWEID:         "CWE-312",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "ios", "userdefaults", "plaintext-storage"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SWIFT-014: Swift WKWebView JavaScript enabled without content rules
// ---------------------------------------------------------------------------

type SwiftWKWebViewJS struct{}

func (r *SwiftWKWebViewJS) ID() string                      { return "GTSS-SWIFT-014" }
func (r *SwiftWKWebViewJS) Name() string                    { return "SwiftWKWebViewJS" }
func (r *SwiftWKWebViewJS) Description() string             { return "Detects Swift WKWebView with JavaScript enabled but without content rule lists or navigation delegation for URL restriction." }
func (r *SwiftWKWebViewJS) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftWKWebViewJS) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftWKWebViewJS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reWKPrefsJSEnabled.MatchString(ctx.Content) {
		return nil
	}

	// Skip if content rules or navigation delegate is set
	if reWKContentRules.MatchString(ctx.Content) && reWKNavDelegate.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if reWKPrefsJSEnabled.MatchString(line) {
			matched := reWKPrefsJSEnabled.FindString(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Swift WKWebView JavaScript enabled without content rules",
				Description:   "A WKWebView has JavaScript enabled without WKContentRuleListStore or a WKNavigationDelegate to restrict content. If the WebView loads untrusted URLs, malicious JavaScript can access the app's JavaScript bridge or perform cross-site scripting.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add a WKNavigationDelegate to restrict allowed URLs. Use WKContentRuleListStore to block dangerous content. Only enable JavaScript if required, and limit the WebView to trusted origins.",
				CWEID:         "CWE-749",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"swift", "ios", "wkwebview", "javascript"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SWIFT-015: Swift hardcoded encryption key/IV
// ---------------------------------------------------------------------------

type SwiftHardcodedKey struct{}

func (r *SwiftHardcodedKey) ID() string                      { return "GTSS-SWIFT-015" }
func (r *SwiftHardcodedKey) Name() string                    { return "SwiftHardcodedKey" }
func (r *SwiftHardcodedKey) Description() string             { return "Detects Swift hardcoded encryption keys, IVs, or nonces as byte arrays or string literals." }
func (r *SwiftHardcodedKey) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftHardcodedKey) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftHardcodedKey) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string

		if m := reHardcodedKey.FindString(line); m != "" {
			matched = m
		} else if m := reHardcodedKeyStr.FindString(line); m != "" {
			matched = m
		} else if m := reHardcodedKeyData.FindString(line); m != "" {
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
				Title:         "Swift hardcoded encryption key/IV",
				Description:   "An encryption key, initialization vector, or nonce is hardcoded in source code. Hardcoded keys can be extracted from the compiled binary via reverse engineering, compromising all encrypted data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Generate keys at runtime using SecRandomCopyBytes or CryptoKit (SymmetricKey(size:)). Store keys in the iOS Keychain or Secure Enclave. Use key derivation (HKDF, PBKDF2) for password-based keys.",
				CWEID:         "CWE-321",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "crypto", "hardcoded-key", "secrets"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SWIFT-016: Swift string interpolation in SQL/predicate
// ---------------------------------------------------------------------------

type SwiftSQLPredicateInterp struct{}

func (r *SwiftSQLPredicateInterp) ID() string                      { return "GTSS-SWIFT-016" }
func (r *SwiftSQLPredicateInterp) Name() string                    { return "SwiftSQLPredicateInterp" }
func (r *SwiftSQLPredicateInterp) Description() string             { return "Detects Swift string interpolation in SQL queries or NSPredicate format strings, enabling injection attacks." }
func (r *SwiftSQLPredicateInterp) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftSQLPredicateInterp) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftSQLPredicateInterp) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string
		var title, desc string

		if m := rePredicateInterp.FindString(line); m != "" {
			matched = m
			title = "Swift NSPredicate with string interpolation"
			desc = "NSPredicate format string uses Swift string interpolation (\\()). An attacker can inject predicate operators to bypass filters, extract data, or cause crashes via malformed predicates."
		} else if m := rePredicateConcat.FindString(line); m != "" {
			matched = m
			title = "Swift NSPredicate with string concatenation"
			desc = "NSPredicate format string is built via concatenation. User input can inject predicate operators to bypass query filters or cause application errors."
		} else if m := reSQLStringInterp.FindString(line); m != "" {
			matched = m
			title = "Swift SQL query with string interpolation"
			desc = "A SQL query string uses Swift string interpolation (\\()). User-controlled values are embedded directly, enabling SQL injection to modify queries, extract data, or damage the database."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "For NSPredicate, use %@ placeholders: NSPredicate(format: \"name == %@\", userInput). For SQL, use parameterized queries with ? placeholders and bind parameters.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "sql-injection", "nspredicate", "interpolation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SWIFT-017: Swift insecure NSCoding deserialization
// ---------------------------------------------------------------------------

type SwiftNSCodingDeser struct{}

func (r *SwiftNSCodingDeser) ID() string                      { return "GTSS-SWIFT-017" }
func (r *SwiftNSCodingDeser) Name() string                    { return "SwiftNSCodingDeser" }
func (r *SwiftNSCodingDeser) Description() string             { return "Detects Swift NSKeyedUnarchiver.unarchiveObject (deprecated, insecure) without NSSecureCoding, enabling deserialization attacks." }
func (r *SwiftNSCodingDeser) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftNSCodingDeser) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftNSCodingDeser) Scan(ctx *rules.ScanContext) []rules.Finding {
	// If using NSSecureCoding, the secure alternative, skip
	if reNSSecureCoding.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		var matched string

		if m := reNSKeyedUnarchiver.FindString(line); m != "" {
			matched = m
		} else if m := reNSKeyedUnarchiverData.FindString(line); m != "" {
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
				Title:         "Swift insecure NSCoding deserialization",
				Description:   "NSKeyedUnarchiver.unarchiveObject(with:) is deprecated and does not validate the class of deserialized objects. If the archived data comes from untrusted sources, an attacker can craft payloads to instantiate arbitrary classes, potentially achieving code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use NSKeyedUnarchiver.unarchivedObject(ofClass:from:) with NSSecureCoding to validate deserialized types. Ensure all archived classes adopt NSSecureCoding with requiresSecureCoding = true.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "deserialization", "nscoding", "nssecurecoding"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-SWIFT-018: Swift App Transport Security disabled
// ---------------------------------------------------------------------------

type SwiftATSDisabled struct{}

func (r *SwiftATSDisabled) ID() string                      { return "GTSS-SWIFT-018" }
func (r *SwiftATSDisabled) Name() string                    { return "SwiftATSDisabled" }
func (r *SwiftATSDisabled) Description() string             { return "Detects App Transport Security (ATS) disabled via NSAllowsArbitraryLoads in Info.plist, allowing plaintext HTTP connections." }
func (r *SwiftATSDisabled) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftATSDisabled) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftATSDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reATSInfoPlist.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if reATSDisabled.MatchString(line) {
			// Check if the next line or same line contains true
			checkEnd := i + 2
			if checkEnd > len(lines) {
				checkEnd = len(lines)
			}
			isTrueNearby := false
			for j := i; j < checkEnd; j++ {
				if reATSTrueValue.MatchString(lines[j]) {
					isTrueNearby = true
					break
				}
			}
			if isTrueNearby {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Swift App Transport Security disabled",
					Description:   "NSAllowsArbitraryLoads is set to true in the App Transport Security dictionary, disabling ATS globally. This allows the app to make plaintext HTTP connections, exposing all network traffic to eavesdropping and man-in-the-middle attacks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Remove NSAllowsArbitraryLoads or set it to false. Use NSExceptionDomains for specific domains that require HTTP. Apple requires justification for ATS exceptions during App Store review.",
					CWEID:         "CWE-319",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"swift", "ios", "ats", "http", "plaintext"},
				})
			}
		}
	}
	return findings
}
