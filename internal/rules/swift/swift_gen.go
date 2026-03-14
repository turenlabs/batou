package swift

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Swift generated rules (BATOU-SWIFT-019 .. BATOU-SWIFT-028)
// ---------------------------------------------------------------------------

// SWIFT-019: Core Data predicate injection
var (
	reNSPredicateFormatInterp = regexp.MustCompile(`NSPredicate\s*\(\s*format\s*:\s*"[^"]*\\\(`)
)

// SWIFT-020: URL scheme hijacking
var (
	reOpenURL       = regexp.MustCompile(`openURL\s*\(`)
	reCanOpenURL    = regexp.MustCompile(`canOpenURL\s*\(`)
)

// SWIFT-021: Unsafe URLSession trust override
var (
	reCompletionHandlerUseCredential = regexp.MustCompile(`completionHandler\s*\(\s*\.useCredential`)
)

// SWIFT-022: WKWebView message handler injection
var (
	reDidReceiveMessage   = regexp.MustCompile(`didReceive\s+message\s*:`)
	reEvaluateJavaScript  = regexp.MustCompile(`evaluateJavaScript\s*\(`)
)

// SWIFT-023: UnsafePointer usage
var (
	reUnsafePointerSwift = regexp.MustCompile(`\b(?:UnsafeRawPointer|UnsafeMutablePointer|UnsafeBufferPointer|UnsafeMutableRawPointer|UnsafeMutableBufferPointer)\b`)
)

// SWIFT-024: Missing SSL pinning Alamofire
var (
	reServerTrustManager    = regexp.MustCompile(`ServerTrustManager\s*\(`)
	reDisableEvaluation     = regexp.MustCompile(`disableEvaluation|allHostsMustBeEvaluated\s*:\s*false`)
)

// SWIFT-025: Hardcoded Firebase key
var (
	reFirebaseAPIKey  = regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)
	reFirebaseConfig  = regexp.MustCompile(`(?i)FirebaseApp\.configure\s*\(\s*options\s*:\s*FirebaseOptions\s*\(`)
)

// SWIFT-026: Unprotected deep link
var (
	reDeepLinkHandler     = regexp.MustCompile(`application\s*\(\s*_\s*:\s*.*open\s+url\s*:`)
	reSchemeHostValidation = regexp.MustCompile(`\.scheme\s*==|\.host\s*==|guard\s+.*\.scheme|guard\s+.*\.host`)
)

// SWIFT-027: Clipboard data exposure
var (
	rePasteboardSet  = regexp.MustCompile(`UIPasteboard\.general\.string\s*=`)
)

// SWIFT-028: Force-unwrap in network handlers
var (
	reForceUnwrapData     = regexp.MustCompile(`data\s*!`)
	reForceUnwrapResponse = regexp.MustCompile(`response\s*!`)
	reURLSessionCallback  = regexp.MustCompile(`URLSession.*completionHandler|dataTask\s*\(\s*with\s*:|\.dataTask\s*\(`)
)

func init() {
	rules.Register(&SwiftPredicateInjection{})
	rules.Register(&SwiftURLSchemeHijack{})
	rules.Register(&SwiftUnsafeTrustOverride{})
	rules.Register(&SwiftWKMessageInjection{})
	rules.Register(&SwiftUnsafePointer{})
	rules.Register(&SwiftAlamofireNoPinning{})
	rules.Register(&SwiftHardcodedFirebase{})
	rules.Register(&SwiftUnprotectedDeepLink{})
	rules.Register(&SwiftClipboardExposure{})
	rules.Register(&SwiftForceUnwrapNetwork{})
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-019: Core Data predicate injection
// ---------------------------------------------------------------------------

type SwiftPredicateInjection struct{}

func (r *SwiftPredicateInjection) ID() string                      { return "BATOU-SWIFT-019" }
func (r *SwiftPredicateInjection) Name() string                    { return "SwiftPredicateInjection" }
func (r *SwiftPredicateInjection) Description() string             { return "Detects NSPredicate(format:) with Swift string interpolation, enabling predicate injection in Core Data queries." }
func (r *SwiftPredicateInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SwiftPredicateInjection) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftPredicateInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if reNSPredicateFormatInterp.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "NSPredicate format string with interpolation",
				Description:   "NSPredicate(format:) uses Swift string interpolation (\\()) to embed values directly in the predicate format string. An attacker can inject predicate operators to bypass access controls or extract unauthorized data from Core Data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use NSPredicate format substitution: NSPredicate(format: \"name == %@\", userInput) instead of NSPredicate(format: \"name == '\\(userInput)'\"). The %@ substitution safely escapes values.",
				CWEID:         "CWE-943",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "coredata", "predicate-injection", "ios"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-020: URL scheme hijacking
// ---------------------------------------------------------------------------

type SwiftURLSchemeHijack struct{}

func (r *SwiftURLSchemeHijack) ID() string                      { return "BATOU-SWIFT-020" }
func (r *SwiftURLSchemeHijack) Name() string                    { return "SwiftURLSchemeHijack" }
func (r *SwiftURLSchemeHijack) Description() string             { return "Detects openURL() calls without prior canOpenURL() validation, which may allow URL scheme hijacking by malicious apps." }
func (r *SwiftURLSchemeHijack) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftURLSchemeHijack) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftURLSchemeHijack) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reOpenURL.MatchString(ctx.Content) {
		return nil
	}

	hasCanOpenURL := reCanOpenURL.MatchString(ctx.Content)

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if reOpenURL.MatchString(line) && !hasCanOpenURL {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "openURL called without canOpenURL validation",
				Description:   "openURL() is called without a prior canOpenURL() check. On iOS, a malicious app can register the same URL scheme and intercept the request, potentially stealing sensitive data passed in the URL or redirecting the user to a phishing interface.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Call canOpenURL() before openURL() to verify the scheme is handled. Use Universal Links (https://) instead of custom URL schemes for inter-app communication, as they are verified against a domain's apple-app-site-association file.",
				CWEID:         "CWE-939",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"swift", "url-scheme", "hijacking", "ios"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-021: Unsafe URLSession trust override
// ---------------------------------------------------------------------------

type SwiftUnsafeTrustOverride struct{}

func (r *SwiftUnsafeTrustOverride) ID() string                      { return "BATOU-SWIFT-021" }
func (r *SwiftUnsafeTrustOverride) Name() string                    { return "SwiftUnsafeTrustOverride" }
func (r *SwiftUnsafeTrustOverride) Description() string             { return "Detects URLSession delegate methods that unconditionally call completionHandler(.useCredential), bypassing TLS certificate validation." }
func (r *SwiftUnsafeTrustOverride) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SwiftUnsafeTrustOverride) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftUnsafeTrustOverride) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if reCompletionHandlerUseCredential.MatchString(line) {
			// Check if there's proper validation nearby
			start := i - 10
			if start < 0 {
				start = 0
			}
			end := i + 5
			if end > len(lines) {
				end = len(lines)
			}
			hasValidation := false
			for j := start; j < end; j++ {
				if strings.Contains(lines[j], "SecTrustEvaluateWithError") ||
					strings.Contains(lines[j], "SecTrustEvaluate") ||
					strings.Contains(lines[j], "pinnedCert") ||
					strings.Contains(lines[j], "SecCertificateCopyData") {
					hasValidation = true
					break
				}
			}
			if !hasValidation {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "URLSession trust override without certificate validation",
					Description:   "The URLSession delegate unconditionally calls completionHandler(.useCredential) without performing certificate validation via SecTrustEvaluateWithError or certificate pinning. This accepts all server certificates, enabling man-in-the-middle attacks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Validate the server certificate using SecTrustEvaluateWithError before calling .useCredential. Implement certificate pinning by comparing the server's public key or certificate hash against known values.",
					CWEID:         "CWE-295",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"swift", "tls", "certificate-validation", "ios"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-022: WKWebView message handler injection
// ---------------------------------------------------------------------------

type SwiftWKMessageInjection struct{}

func (r *SwiftWKMessageInjection) ID() string                      { return "BATOU-SWIFT-022" }
func (r *SwiftWKMessageInjection) Name() string                    { return "SwiftWKMessageInjection" }
func (r *SwiftWKMessageInjection) Description() string             { return "Detects WKWebView message handler (didReceive message) flowing into evaluateJavaScript, enabling JavaScript injection." }
func (r *SwiftWKMessageInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftWKMessageInjection) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftWKMessageInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reDidReceiveMessage.MatchString(ctx.Content) {
		return nil
	}
	if !reEvaluateJavaScript.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inHandler := false
	braceDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if reDidReceiveMessage.MatchString(line) {
			inHandler = true
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inHandler {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if reEvaluateJavaScript.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WKWebView message handler data flows into evaluateJavaScript",
					Description:   "Data received from a WKScriptMessageHandler (didReceive message) is used in evaluateJavaScript(). If the message body is not sanitized, a malicious webpage can inject arbitrary JavaScript that executes in the WebView context with access to native bridges.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Validate and sanitize all data from message.body before using it in evaluateJavaScript. Use JSON encoding instead of string interpolation. Consider using callAsyncJavaScript with parameter binding.",
					CWEID:         "CWE-79",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"swift", "webview", "xss", "message-handler", "ios"},
				})
			}

			if braceDepth <= 0 {
				inHandler = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-023: UnsafePointer usage
// ---------------------------------------------------------------------------

type SwiftUnsafePointer struct{}

func (r *SwiftUnsafePointer) ID() string                      { return "BATOU-SWIFT-023" }
func (r *SwiftUnsafePointer) Name() string                    { return "SwiftUnsafePointer" }
func (r *SwiftUnsafePointer) Description() string             { return "Detects usage of UnsafeRawPointer, UnsafeMutablePointer, and UnsafeBufferPointer, which bypass Swift's memory safety guarantees." }
func (r *SwiftUnsafePointer) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftUnsafePointer) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftUnsafePointer) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// Skip import statements
		if strings.HasPrefix(trimmed, "import") {
			continue
		}

		if reUnsafePointerSwift.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe pointer usage bypasses Swift memory safety",
				Description:   "UnsafeRawPointer, UnsafeMutablePointer, or UnsafeBufferPointer usage bypasses Swift's memory safety guarantees. Incorrect pointer arithmetic, dangling references, or type confusion can cause buffer overflows, use-after-free, or arbitrary code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use safe alternatives like Array, Data, or withUnsafeBytes/withUnsafeMutableBytes which provide scoped access. If unsafe pointers are required, document safety invariants and minimize the scope of unsafe operations.",
				CWEID:         "CWE-119",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"swift", "unsafe-pointer", "memory-safety", "ios"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-024: Missing SSL pinning Alamofire
// ---------------------------------------------------------------------------

type SwiftAlamofireNoPinning struct{}

func (r *SwiftAlamofireNoPinning) ID() string                      { return "BATOU-SWIFT-024" }
func (r *SwiftAlamofireNoPinning) Name() string                    { return "SwiftAlamofireNoPinning" }
func (r *SwiftAlamofireNoPinning) Description() string             { return "Detects Alamofire ServerTrustManager with disableEvaluation or allHostsMustBeEvaluated: false, which disables SSL certificate pinning." }
func (r *SwiftAlamofireNoPinning) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftAlamofireNoPinning) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftAlamofireNoPinning) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reServerTrustManager.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if reDisableEvaluation.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Alamofire ServerTrustManager with disabled evaluation",
				Description:   "The Alamofire ServerTrustManager uses DisableTrustEvaluator or sets allHostsMustBeEvaluated to false, disabling SSL certificate pinning. This allows man-in-the-middle attacks by accepting any server certificate.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use PublicKeysTrustEvaluator or PinnedCertificatesTrustEvaluator to pin the server's certificate or public key. Set allHostsMustBeEvaluated to true to ensure all hosts are validated.",
				CWEID:         "CWE-295",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "alamofire", "ssl-pinning", "tls", "ios"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-025: Hardcoded Firebase key
// ---------------------------------------------------------------------------

type SwiftHardcodedFirebase struct{}

func (r *SwiftHardcodedFirebase) ID() string                      { return "BATOU-SWIFT-025" }
func (r *SwiftHardcodedFirebase) Name() string                    { return "SwiftHardcodedFirebase" }
func (r *SwiftHardcodedFirebase) Description() string             { return "Detects hardcoded Firebase API keys (AIza...) or inline Firebase configuration in Swift source code." }
func (r *SwiftHardcodedFirebase) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftHardcodedFirebase) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftHardcodedFirebase) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if reFirebaseAPIKey.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded Firebase API key detected",
				Description:   "A Firebase API key (AIza...) is embedded directly in Swift source code. While Firebase API keys are not secret by design, hardcoding them makes it difficult to rotate keys and may indicate other Firebase configuration secrets (database URLs, project IDs) are also hardcoded.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Store Firebase configuration in GoogleService-Info.plist (managed by Firebase SDK) instead of hardcoding values. Ensure Firebase Security Rules are configured to protect data regardless of key exposure.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"swift", "firebase", "hardcoded-key", "ios"},
			})
			continue
		}

		if reFirebaseConfig.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Inline Firebase configuration in Swift code",
				Description:   "FirebaseApp.configure() is called with inline FirebaseOptions instead of using GoogleService-Info.plist. Inline configuration embeds project IDs, API keys, and other Firebase identifiers directly in compiled code.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use GoogleService-Info.plist for Firebase configuration: FirebaseApp.configure() without arguments reads from the plist automatically.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"swift", "firebase", "configuration", "ios"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-026: Unprotected deep link
// ---------------------------------------------------------------------------

type SwiftUnprotectedDeepLink struct{}

func (r *SwiftUnprotectedDeepLink) ID() string                      { return "BATOU-SWIFT-026" }
func (r *SwiftUnprotectedDeepLink) Name() string                    { return "SwiftUnprotectedDeepLink" }
func (r *SwiftUnprotectedDeepLink) Description() string             { return "Detects application(_:open url:) deep link handlers without scheme or host validation, allowing malicious apps to trigger actions via crafted URLs." }
func (r *SwiftUnprotectedDeepLink) DefaultSeverity() rules.Severity { return rules.High }
func (r *SwiftUnprotectedDeepLink) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftUnprotectedDeepLink) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reDeepLinkHandler.MatchString(ctx.Content) {
		return nil
	}

	hasValidation := reSchemeHostValidation.MatchString(ctx.Content)
	if hasValidation {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if reDeepLinkHandler.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Deep link handler without scheme/host validation",
				Description:   "The application(_:open url:) handler processes deep links without validating the URL scheme or host. A malicious app can craft URLs with unexpected schemes or hosts to trigger unintended actions, access protected resources, or perform open redirect attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Validate the URL scheme and host before processing: guard url.scheme == \"myapp\" && url.host == \"expected\" else { return false }. Use Universal Links instead of custom URL schemes for better security.",
				CWEID:         "CWE-939",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"swift", "deep-link", "url-scheme", "ios"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-027: Clipboard data exposure
// ---------------------------------------------------------------------------

type SwiftClipboardExposure struct{}

func (r *SwiftClipboardExposure) ID() string                      { return "BATOU-SWIFT-027" }
func (r *SwiftClipboardExposure) Name() string                    { return "SwiftClipboardExposure" }
func (r *SwiftClipboardExposure) Description() string             { return "Detects writing data to UIPasteboard.general, which can be read by any app and may expose sensitive information." }
func (r *SwiftClipboardExposure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SwiftClipboardExposure) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftClipboardExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	contentLower := strings.ToLower(ctx.Content)
	hasSensitiveContext := strings.Contains(contentLower, "password") ||
		strings.Contains(contentLower, "token") ||
		strings.Contains(contentLower, "secret") ||
		strings.Contains(contentLower, "credential") ||
		strings.Contains(contentLower, "auth") ||
		strings.Contains(contentLower, "session") ||
		strings.Contains(contentLower, "key")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if rePasteboardSet.MatchString(line) && hasSensitiveContext {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Sensitive data written to system clipboard",
				Description:   "Data is written to UIPasteboard.general in a file that handles sensitive information. The system clipboard is accessible to all apps on the device, and on iOS 14+ a paste notification is shown. Sensitive data on the clipboard can be stolen by malicious apps or seen in screenshots.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Avoid copying sensitive data to the clipboard. If clipboard usage is required, use UIPasteboard.withLocalOnly or set an expiration: UIPasteboard.general.setItems([[.string: value]], options: [.expirationDate: Date().addingTimeInterval(60)]).",
				CWEID:         "CWE-200",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"swift", "clipboard", "data-exposure", "ios"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-SWIFT-028: Force-unwrap in network handlers
// ---------------------------------------------------------------------------

type SwiftForceUnwrapNetwork struct{}

func (r *SwiftForceUnwrapNetwork) ID() string                      { return "BATOU-SWIFT-028" }
func (r *SwiftForceUnwrapNetwork) Name() string                    { return "SwiftForceUnwrapNetwork" }
func (r *SwiftForceUnwrapNetwork) Description() string             { return "Detects force-unwrapping (data!, response!) in URLSession completion handlers, which can crash the app on network errors." }
func (r *SwiftForceUnwrapNetwork) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SwiftForceUnwrapNetwork) Languages() []rules.Language     { return []rules.Language{rules.LangSwift} }

func (r *SwiftForceUnwrapNetwork) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reURLSessionCallback.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if reForceUnwrapData.MatchString(line) || reForceUnwrapResponse.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Force-unwrap in network completion handler",
				Description:   "Force-unwrapping data! or response! in a URLSession completion handler will crash the app when the network request fails and these values are nil. An attacker can trigger this crash by disrupting network connectivity or causing server errors, leading to denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use optional binding: guard let data = data else { return } or if let response = response { ... }. Handle the error parameter to gracefully recover from network failures.",
				CWEID:         "CWE-755",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"swift", "force-unwrap", "network", "crash", "ios"},
			})
		}
	}
	return findings
}
