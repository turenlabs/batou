package kotlin

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Kotlin generated rules (BATOU-KT-025 .. BATOU-KT-034)
// ---------------------------------------------------------------------------

// KT-025: PendingIntent without FLAG_IMMUTABLE
var (
	rePendingIntentGet   = regexp.MustCompile(`PendingIntent\.(?:getActivity|getService|getBroadcast)\s*\(`)
	reFlagImmutable      = regexp.MustCompile(`FLAG_IMMUTABLE`)
)

// KT-026: Content provider SQL injection
var (
	reContentResolverQueryGen = regexp.MustCompile(`contentResolver\.query\s*\(`)
	reContentResolverInterp   = regexp.MustCompile(`contentResolver\.query\s*\([^)]*\$\{`)
)

// KT-027: Ktor CORS wildcard
var (
	reKtorInstallCORS = regexp.MustCompile(`install\s*\(\s*CORS\s*\)`)
	reKtorAnyHost     = regexp.MustCompile(`anyHost\s*\(\s*\)`)
)

// KT-028: Room RawQuery injection
var (
	reSimpleSQLiteQueryInterp = regexp.MustCompile(`SimpleSQLiteQuery\s*\(\s*(?:"[^"]*\$\{|"\$)`)
)

// KT-029: Trust-all TrustManager
var (
	reCheckServerTrustedEmpty = regexp.MustCompile(`checkServerTrusted\s*\([^)]*\)\s*\{\s*\}`)
)

// KT-030: Exported component without permission
var (
	reExportedTrue     = regexp.MustCompile(`android:exported\s*=\s*"true"`)
	reAndroidPermission = regexp.MustCompile(`android:permission\s*=`)
)

// KT-031: Jetpack Compose WebView JS
var (
	reAndroidViewWebView = regexp.MustCompile(`AndroidView\s*\(`)
	reWebViewInFactory   = regexp.MustCompile(`WebView\s*\(`)
	reJSEnabledTrue      = regexp.MustCompile(`javaScriptEnabled\s*=\s*true`)
)

// KT-032: Implicit broadcast receiver
var (
	reRegisterReceiverCall   = regexp.MustCompile(`registerReceiver\s*\(`)
	reReceiverNotExported    = regexp.MustCompile(`RECEIVER_NOT_EXPORTED`)
)

// KT-033: Coroutine exception swallowed
var (
	reLaunchBlock              = regexp.MustCompile(`launch\s*\{`)
	reCoroutineExceptionHandler = regexp.MustCompile(`CoroutineExceptionHandler`)
	reTryBlock                  = regexp.MustCompile(`try\s*\{`)
)

// KT-034: Hardcoded API key
var (
	reHardcodedAPIKeyKt = regexp.MustCompile(`(?i)(?:val|var)\s+\w*(?:apiKey|apiSecret|token)\w*\s*=\s*"[A-Za-z0-9_\-/.+]{16,}"`)
)

func init() {
	rules.Register(&KtPendingIntentMutable{})
	rules.Register(&KtContentProviderSQLi{})
	rules.Register(&KtKtorCORSWildcard{})
	rules.Register(&KtRoomRawQueryInterp{})
	rules.Register(&KtTrustAllTrustManager{})
	rules.Register(&KtExportedNoPermission{})
	rules.Register(&KtComposeWebViewJS{})
	rules.Register(&KtImplicitBroadcast{})
	rules.Register(&KtCoroutineExceptionSwallowed{})
	rules.Register(&KtHardcodedAPIKey{})
}

// ---------------------------------------------------------------------------
// BATOU-KT-025: PendingIntent without FLAG_IMMUTABLE
// ---------------------------------------------------------------------------

type KtPendingIntentMutable struct{}

func (r *KtPendingIntentMutable) ID() string                      { return "BATOU-KT-025" }
func (r *KtPendingIntentMutable) Name() string                    { return "KtPendingIntentMutable" }
func (r *KtPendingIntentMutable) Description() string             { return "Detects PendingIntent creation without FLAG_IMMUTABLE, allowing other apps to modify the intent." }
func (r *KtPendingIntentMutable) DefaultSeverity() rules.Severity { return rules.High }
func (r *KtPendingIntentMutable) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtPendingIntentMutable) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		if rePendingIntentGet.MatchString(line) {
			// Check surrounding lines for FLAG_IMMUTABLE
			start := i - 3
			if start < 0 {
				start = 0
			}
			end := i + 3
			if end > len(lines) {
				end = len(lines)
			}
			hasImmutable := false
			for j := start; j < end; j++ {
				if reFlagImmutable.MatchString(lines[j]) {
					hasImmutable = true
					break
				}
			}
			if !hasImmutable {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "PendingIntent created without FLAG_IMMUTABLE",
					Description:   "PendingIntent is created without FLAG_IMMUTABLE. On Android 12+ this is required, and without it other apps can modify the intent fields, potentially redirecting it to a malicious component.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Add PendingIntent.FLAG_IMMUTABLE to the flags parameter unless mutability is explicitly required. Use FLAG_MUTABLE only when the intent must be modified by the receiver.",
					CWEID:         "CWE-927",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"kotlin", "android", "pending-intent", "immutable"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-026: Content provider SQL injection
// ---------------------------------------------------------------------------

type KtContentProviderSQLi struct{}

func (r *KtContentProviderSQLi) ID() string                      { return "BATOU-KT-026" }
func (r *KtContentProviderSQLi) Name() string                    { return "KtContentProviderSQLi" }
func (r *KtContentProviderSQLi) Description() string             { return "Detects contentResolver.query with string interpolation, enabling SQL injection through content providers." }
func (r *KtContentProviderSQLi) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *KtContentProviderSQLi) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtContentProviderSQLi) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reContentResolverQueryGen.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		if reContentResolverInterp.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Content provider query with string interpolation",
				Description:   "contentResolver.query() uses Kotlin string interpolation (${ }) to build the query. User-controlled values inserted this way are not parameterized, enabling SQL injection through the content provider.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use the selectionArgs parameter for user-provided values: contentResolver.query(uri, projection, \"column = ?\", arrayOf(userInput), null).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "android", "sql-injection", "content-provider"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-027: Ktor CORS wildcard
// ---------------------------------------------------------------------------

type KtKtorCORSWildcard struct{}

func (r *KtKtorCORSWildcard) ID() string                      { return "BATOU-KT-027" }
func (r *KtKtorCORSWildcard) Name() string                    { return "KtKtorCORSWildcard" }
func (r *KtKtorCORSWildcard) Description() string             { return "Detects Ktor CORS configuration with anyHost(), allowing requests from any origin." }
func (r *KtKtorCORSWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r *KtKtorCORSWildcard) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtKtorCORSWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reKtorInstallCORS.MatchString(ctx.Content) && !strings.Contains(ctx.Content, "CORS") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		if reKtorAnyHost.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ktor CORS configured with anyHost()",
				Description:   "The Ktor CORS plugin is configured with anyHost(), allowing cross-origin requests from any domain. This disables same-origin policy protections and may expose authenticated endpoints to malicious sites.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Replace anyHost() with allowHost(\"yourdomain.com\") to restrict CORS to specific trusted origins.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "ktor", "cors", "misconfiguration"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-028: Room RawQuery injection
// ---------------------------------------------------------------------------

type KtRoomRawQueryInterp struct{}

func (r *KtRoomRawQueryInterp) ID() string                      { return "BATOU-KT-028" }
func (r *KtRoomRawQueryInterp) Name() string                    { return "KtRoomRawQueryInterp" }
func (r *KtRoomRawQueryInterp) Description() string             { return "Detects SimpleSQLiteQuery with Kotlin string interpolation, enabling SQL injection in Room database queries." }
func (r *KtRoomRawQueryInterp) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *KtRoomRawQueryInterp) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtRoomRawQueryInterp) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		if reSimpleSQLiteQueryInterp.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Room SimpleSQLiteQuery with string interpolation",
				Description:   "SimpleSQLiteQuery is constructed with Kotlin string interpolation (${ }). User input interpolated into the SQL string enables SQL injection, bypassing Room's parameterized query protections.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use SimpleSQLiteQuery with bind arguments: SimpleSQLiteQuery(\"SELECT * FROM table WHERE id = ?\", arrayOf(userInput)).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "android", "room", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-029: Trust-all TrustManager
// ---------------------------------------------------------------------------

type KtTrustAllTrustManager struct{}

func (r *KtTrustAllTrustManager) ID() string                      { return "BATOU-KT-029" }
func (r *KtTrustAllTrustManager) Name() string                    { return "KtTrustAllTrustManager" }
func (r *KtTrustAllTrustManager) Description() string             { return "Detects X509TrustManager implementations with empty checkServerTrusted, which disables TLS certificate validation." }
func (r *KtTrustAllTrustManager) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *KtTrustAllTrustManager) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtTrustAllTrustManager) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		if reCheckServerTrustedEmpty.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "TrustManager with empty checkServerTrusted",
				Description:   "The X509TrustManager implementation has an empty checkServerTrusted method, which accepts all server certificates without validation. This completely disables TLS certificate verification and allows man-in-the-middle attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use the default TrustManager or implement proper certificate pinning with OkHttp's CertificatePinner or Android's Network Security Config.",
				CWEID:         "CWE-295",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "android", "tls", "trust-manager", "certificate"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-030: Exported component without permission
// ---------------------------------------------------------------------------

type KtExportedNoPermission struct{}

func (r *KtExportedNoPermission) ID() string                      { return "BATOU-KT-030" }
func (r *KtExportedNoPermission) Name() string                    { return "KtExportedNoPermission" }
func (r *KtExportedNoPermission) Description() string             { return "Detects Android components with android:exported=\"true\" but no android:permission attribute, allowing unrestricted access from other apps." }
func (r *KtExportedNoPermission) DefaultSeverity() rules.Severity { return rules.High }
func (r *KtExportedNoPermission) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin, rules.LangAny} }

func (r *KtExportedNoPermission) Scan(ctx *rules.ScanContext) []rules.Finding {
	lower := strings.ToLower(ctx.FilePath)
	if !strings.HasSuffix(lower, ".xml") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if reExportedTrue.MatchString(line) {
			// Check surrounding lines for android:permission
			start := i - 5
			if start < 0 {
				start = 0
			}
			end := i + 5
			if end > len(lines) {
				end = len(lines)
			}
			hasPermission := false
			for j := start; j < end; j++ {
				if reAndroidPermission.MatchString(lines[j]) {
					hasPermission = true
					break
				}
			}
			if !hasPermission {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Exported Android component without permission protection",
					Description:   "An Android component is exported (android:exported=\"true\") without specifying an android:permission attribute. Any app on the device can interact with this component, potentially accessing sensitive data or triggering privileged operations.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Add android:permission=\"your.custom.PERMISSION\" to restrict access, or set android:exported=\"false\" if the component does not need to be accessible to other apps.",
					CWEID:         "CWE-926",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"kotlin", "android", "manifest", "exported-component"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-031: Jetpack Compose WebView JS
// ---------------------------------------------------------------------------

type KtComposeWebViewJS struct{}

func (r *KtComposeWebViewJS) ID() string                      { return "BATOU-KT-031" }
func (r *KtComposeWebViewJS) Name() string                    { return "KtComposeWebViewJS" }
func (r *KtComposeWebViewJS) Description() string             { return "Detects Jetpack Compose AndroidView with WebView and javaScriptEnabled, which exposes the app to XSS and JavaScript injection attacks." }
func (r *KtComposeWebViewJS) DefaultSeverity() rules.Severity { return rules.High }
func (r *KtComposeWebViewJS) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtComposeWebViewJS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reAndroidViewWebView.MatchString(ctx.Content) {
		return nil
	}
	if !reJSEnabledTrue.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		if reJSEnabledTrue.MatchString(line) && reWebViewInFactory.MatchString(ctx.Content) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Jetpack Compose WebView with JavaScript enabled",
				Description:   "A WebView created inside a Jetpack Compose AndroidView has javaScriptEnabled set to true. If the WebView loads untrusted content, JavaScript code can access exposed interfaces, steal data, or perform actions on behalf of the user.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Disable JavaScript if not required. If JavaScript is needed, set a WebViewClient to validate URLs, avoid loading untrusted content, and do not use addJavascriptInterface with user-controlled pages.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"kotlin", "android", "compose", "webview", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-032: Implicit broadcast receiver
// ---------------------------------------------------------------------------

type KtImplicitBroadcast struct{}

func (r *KtImplicitBroadcast) ID() string                      { return "BATOU-KT-032" }
func (r *KtImplicitBroadcast) Name() string                    { return "KtImplicitBroadcast" }
func (r *KtImplicitBroadcast) Description() string             { return "Detects registerReceiver() calls without RECEIVER_NOT_EXPORTED flag, allowing other apps to send broadcasts to the receiver." }
func (r *KtImplicitBroadcast) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *KtImplicitBroadcast) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtImplicitBroadcast) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		if reRegisterReceiverCall.MatchString(line) {
			// Check surrounding lines for RECEIVER_NOT_EXPORTED
			start := i - 3
			if start < 0 {
				start = 0
			}
			end := i + 3
			if end > len(lines) {
				end = len(lines)
			}
			hasFlag := false
			for j := start; j < end; j++ {
				if reReceiverNotExported.MatchString(lines[j]) {
					hasFlag = true
					break
				}
			}
			if !hasFlag {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Broadcast receiver registered without RECEIVER_NOT_EXPORTED",
					Description:   "registerReceiver() is called without the RECEIVER_NOT_EXPORTED flag. On Android 14+, this is required for receivers not intended to receive broadcasts from other apps. Without it, any app can send broadcasts to this receiver, potentially injecting malicious data.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Add Context.RECEIVER_NOT_EXPORTED as a flag: registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED). Use RECEIVER_EXPORTED only when the receiver must accept broadcasts from other apps.",
					CWEID:         "CWE-927",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"kotlin", "android", "broadcast-receiver", "exported"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-033: Coroutine exception swallowed
// ---------------------------------------------------------------------------

type KtCoroutineExceptionSwallowed struct{}

func (r *KtCoroutineExceptionSwallowed) ID() string                      { return "BATOU-KT-033" }
func (r *KtCoroutineExceptionSwallowed) Name() string                    { return "KtCoroutineExceptionSwallowed" }
func (r *KtCoroutineExceptionSwallowed) Description() string             { return "Detects coroutine launch blocks without CoroutineExceptionHandler or try-catch, which silently swallows exceptions and can mask security failures." }
func (r *KtCoroutineExceptionSwallowed) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *KtCoroutineExceptionSwallowed) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtCoroutineExceptionSwallowed) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick check: file must contain launch { and NOT have a global handler
	if !reLaunchBlock.MatchString(ctx.Content) {
		return nil
	}
	hasGlobalHandler := reCoroutineExceptionHandler.MatchString(ctx.Content)

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		if reLaunchBlock.MatchString(line) {
			if hasGlobalHandler {
				continue
			}
			// Check if there's a try block within the next few lines
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			hasTry := false
			for j := i + 1; j < end; j++ {
				if reTryBlock.MatchString(lines[j]) {
					hasTry = true
					break
				}
			}
			if !hasTry {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Coroutine launch without exception handling",
					Description:   "A coroutine is launched without a CoroutineExceptionHandler or try-catch block. Uncaught exceptions in launch blocks propagate to the parent scope and can crash the application or silently fail, masking security-relevant errors such as authentication or authorization failures.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Add a CoroutineExceptionHandler to the launch context, or wrap the body in try-catch: launch(CoroutineExceptionHandler { _, e -> log(e) }) { ... } or launch { try { ... } catch (e: Exception) { ... } }.",
					CWEID:         "CWE-755",
					OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"kotlin", "coroutine", "exception-handling"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-034: Hardcoded API key
// ---------------------------------------------------------------------------

type KtHardcodedAPIKey struct{}

func (r *KtHardcodedAPIKey) ID() string                      { return "BATOU-KT-034" }
func (r *KtHardcodedAPIKey) Name() string                    { return "KtHardcodedAPIKey" }
func (r *KtHardcodedAPIKey) Description() string             { return "Detects hardcoded API keys, secrets, or tokens assigned to variables in Kotlin code." }
func (r *KtHardcodedAPIKey) DefaultSeverity() rules.Severity { return rules.High }
func (r *KtHardcodedAPIKey) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtHardcodedAPIKey) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if isComment(t) {
			continue
		}

		// Skip test/example/placeholder values
		lower := strings.ToLower(line)
		if strings.Contains(lower, "example") || strings.Contains(lower, "placeholder") ||
			strings.Contains(lower, "test") || strings.Contains(lower, "todo") ||
			strings.Contains(lower, "your_") || strings.Contains(lower, "your-") ||
			strings.Contains(lower, "<your") || strings.Contains(lower, "change_me") {
			continue
		}

		if reHardcodedAPIKeyKt.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded API key or token in Kotlin source",
				Description:   "An API key, secret, or token is hardcoded as a string literal in Kotlin source code. Secrets in compiled Android APKs can be extracted using tools like apktool or jadx, granting attackers unauthorized access to backend services.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Store secrets in Android Keystore, use BuildConfig fields loaded from local.properties (gitignored), or fetch secrets from a secure backend at runtime. Never commit secrets to source control.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "android", "secrets", "hardcoded-key"},
			})
		}
	}
	return findings
}
