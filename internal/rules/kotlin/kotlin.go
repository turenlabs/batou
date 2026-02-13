package kotlin

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled patterns ---

// KT-001: Android SQL Injection
var (
	rawQueryConcat = regexp.MustCompile(`\.rawQuery\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+|\$\{|\$[a-zA-Z_])`)
	execSQLConcat  = regexp.MustCompile(`\.execSQL\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+|\$\{|\$[a-zA-Z_])`)
	// String template in rawQuery/execSQL
	rawQueryTemplate = regexp.MustCompile(`\.rawQuery\s*\(\s*"[^"]*\$\{`)
	execSQLTemplate  = regexp.MustCompile(`\.execSQL\s*\(\s*"[^"]*\$\{`)
)

// KT-002: Android Intent Injection
var (
	implicitIntent     = regexp.MustCompile(`Intent\s*\(\s*(?:"[^"]*"|[A-Z_]+)\s*\)`)
	intentPutExtra     = regexp.MustCompile(`\.putExtra\s*\(`)
	intentSetData      = regexp.MustCompile(`\.(?:setData|data)\s*=`)
	sendBroadcast      = regexp.MustCompile(`sendBroadcast\s*\(`)
	startActivityNoVal = regexp.MustCompile(`startActivity\s*\(`)
)

// KT-003: WebView JavaScript Injection
var (
	loadUrlJavascript       = regexp.MustCompile(`\.loadUrl\s*\(\s*"javascript:`)
	loadUrlTemplate         = regexp.MustCompile(`\.loadUrl\s*\(\s*"javascript:[^"]*\$\{`)
	loadUrlConcat           = regexp.MustCompile(`\.loadUrl\s*\(\s*"javascript:[^"]*"\s*\+`)
	addJavascriptInterface  = regexp.MustCompile(`\.addJavascriptInterface\s*\(`)
	evaluateJavascriptTaint = regexp.MustCompile(`\.evaluateJavascript\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+|"[^"]*\$\{)`)
)

// KT-004: Insecure SharedPreferences
var (
	sharedPrefsEdit    = regexp.MustCompile(`getSharedPreferences\s*\(`)
	sharedPrefsPutData = regexp.MustCompile(`\.(?:putString|putInt|putBoolean|putFloat|putLong)\s*\(`)
	sensitiveKeyNames  = regexp.MustCompile(`(?i)(?:password|secret|token|api[_\s]?key|private[_\s]?key|credential|auth|session)`)
)

// KT-005: Android Exported Components
var (
	exportedTrue       = regexp.MustCompile(`android:exported\s*=\s*"true"`)
	permissionAttr     = regexp.MustCompile(`android:permission\s*=`)
	intentFilterTag    = regexp.MustCompile(`<intent-filter`)
	activityTag        = regexp.MustCompile(`<activity\b`)
	serviceTag         = regexp.MustCompile(`<service\b`)
	receiverTag        = regexp.MustCompile(`<receiver\b`)
	providerTag        = regexp.MustCompile(`<provider\b`)
)

// KT-006: Ktor CORS Misconfiguration
var (
	ktorCORSAnyHost         = regexp.MustCompile(`anyHost\s*\(`)
	ktorCORSAllowCredentials = regexp.MustCompile(`allowCredentials\s*=\s*true`)
	ktorCORSBlock           = regexp.MustCompile(`install\s*\(\s*CORS\s*\)|cors\s*\{`)
)

// KT-007: Unsafe Coroutine Exception Handling
var (
	globalScopeLaunch     = regexp.MustCompile(`GlobalScope\s*\.\s*launch\s*\{`)
	globalScopeAsync      = regexp.MustCompile(`GlobalScope\s*\.\s*async\s*\{`)
	coroutineExceptionHandler = regexp.MustCompile(`CoroutineExceptionHandler`)
	supervisorJob         = regexp.MustCompile(`SupervisorJob\s*\(`)
)

// KT-008: Kotlin Serialization with Untrusted Input
var (
	jsonDecodeFromString = regexp.MustCompile(`Json\.decodeFromString\s*[<(]`)
	jsonDecodeCustom     = regexp.MustCompile(`Json\s*\{[^}]*\}\s*\.decodeFromString`)
)

func init() {
	rules.Register(&AndroidSQLInjection{})
	rules.Register(&AndroidIntentInjection{})
	rules.Register(&WebViewJSInjection{})
	rules.Register(&InsecureSharedPreferences{})
	rules.Register(&ExportedComponents{})
	rules.Register(&KtorCORSMisconfig{})
	rules.Register(&UnsafeCoroutineException{})
	rules.Register(&KotlinSerializationUntrusted{})
}

// --- KT-001: Android SQL Injection ---

type AndroidSQLInjection struct{}

func (r *AndroidSQLInjection) ID() string                      { return "GTSS-KT-001" }
func (r *AndroidSQLInjection) Name() string                    { return "AndroidSQLInjection" }
func (r *AndroidSQLInjection) Description() string             { return "Detects Android SQLite rawQuery/execSQL with string concatenation or template interpolation." }
func (r *AndroidSQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *AndroidSQLInjection) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *AndroidSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		if loc := rawQueryConcat.FindString(line); loc != "" {
			matched = loc
			desc = "rawQuery with string concatenation"
		} else if loc := rawQueryTemplate.FindString(line); loc != "" {
			matched = loc
			desc = "rawQuery with string template interpolation"
		} else if loc := execSQLConcat.FindString(line); loc != "" {
			matched = loc
			desc = "execSQL with string concatenation"
		} else if loc := execSQLTemplate.FindString(line); loc != "" {
			matched = loc
			desc = "execSQL with string template interpolation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Android SQL injection via " + desc,
				Description:   "SQLite " + desc + " is vulnerable to SQL injection. User-controlled data concatenated into SQL queries allows attackers to modify query logic, extract data, or corrupt the database.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized queries: db.rawQuery(\"SELECT * FROM users WHERE id = ?\", arrayOf(userId)) or Room DAO with @Query annotations.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"android", "sqlite", "sql-injection"},
			})
		}
	}

	return findings
}

// --- KT-002: Android Intent Injection ---

type AndroidIntentInjection struct{}

func (r *AndroidIntentInjection) ID() string                      { return "GTSS-KT-002" }
func (r *AndroidIntentInjection) Name() string                    { return "AndroidIntentInjection" }
func (r *AndroidIntentInjection) Description() string             { return "Detects implicit intents with user-controlled data that could be intercepted by malicious apps." }
func (r *AndroidIntentInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *AndroidIntentInjection) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *AndroidIntentInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if file uses user input sources
	hasUserInput := strings.Contains(ctx.Content, "getStringExtra") ||
		strings.Contains(ctx.Content, "intent.data") ||
		strings.Contains(ctx.Content, "intent.extras") ||
		strings.Contains(ctx.Content, "editText") ||
		strings.Contains(ctx.Content, ".text.toString()")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// Detect sendBroadcast with implicit intent
		if sendBroadcast.MatchString(line) && hasUserInput {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "sendBroadcast with implicit intent may leak sensitive data",
				Description:   "sendBroadcast() with an implicit Intent can be intercepted by any app that registers a matching BroadcastReceiver. If user data is included in the extras, it may be leaked to malicious applications.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use LocalBroadcastManager.getInstance(context).sendBroadcast() for app-internal communication, or specify the target package with intent.setPackage() to limit receivers.",
				CWEID:         "CWE-927",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"android", "intent", "broadcast"},
			})
		}

		// Detect implicit intent with user data sent via startActivity
		if implicitIntent.MatchString(line) && hasUserInput {
			context := surroundingContext(lines, i, 5)
			if intentPutExtra.MatchString(context) || intentSetData.MatchString(context) {
				confidence := "medium"
				if strings.Contains(context, "getStringExtra") || strings.Contains(context, ".text.toString()") {
					confidence = "high"
				}

				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Implicit intent with user-controlled data",
					Description:   "An implicit Intent carries user-controlled data via putExtra() or setData(). Any app matching the intent filter can receive this data, potentially exposing sensitive information.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Use explicit intents (Intent(context, TargetActivity::class.java)) when sending sensitive data. For cross-app communication, use setPackage() or verify the target with resolveActivity().",
					CWEID:         "CWE-927",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    confidence,
					Tags:          []string{"android", "intent", "injection"},
				})
			}
		}
	}

	return findings
}

// --- KT-003: WebView JavaScript Injection ---

type WebViewJSInjection struct{}

func (r *WebViewJSInjection) ID() string                      { return "GTSS-KT-003" }
func (r *WebViewJSInjection) Name() string                    { return "WebViewJSInjection" }
func (r *WebViewJSInjection) Description() string             { return "Detects Android WebView JavaScript injection via loadUrl(\"javascript:\") and addJavascriptInterface." }
func (r *WebViewJSInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *WebViewJSInjection) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *WebViewJSInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// loadUrl("javascript:..." + userInput) or loadUrl("javascript:...${}...")
		if loc := loadUrlConcat.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "WebView JavaScript injection via loadUrl with concatenation",
				Description:   "loadUrl(\"javascript:...\") with string concatenation allows injection of arbitrary JavaScript into the WebView. An attacker can execute scripts in the WebView context, access the DOM, steal cookies, or call exposed Java/Kotlin interfaces.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use evaluateJavascript() with properly escaped parameters, or pass data via postMessage/WebMessagePort instead of injecting it into JavaScript strings.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"android", "webview", "xss", "javascript-injection"},
			})
		} else if loc := loadUrlTemplate.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "WebView JavaScript injection via loadUrl with string template",
				Description:   "loadUrl(\"javascript:...\") with Kotlin string template interpolation (${ }) allows injection of arbitrary JavaScript into the WebView.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use evaluateJavascript() with properly escaped parameters, or pass data via postMessage/WebMessagePort instead of injecting it into JavaScript strings.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"android", "webview", "xss", "javascript-injection"},
			})
		}

		// evaluateJavascript with tainted input
		if loc := evaluateJavascriptTaint.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "WebView evaluateJavascript with untrusted input",
				Description:   "evaluateJavascript() is called with user-controlled input via string concatenation or template interpolation. This allows arbitrary JavaScript execution in the WebView context.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Sanitize all user input before passing to evaluateJavascript(). Use JSON encoding for data and avoid constructing JavaScript code strings from user input.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"android", "webview", "xss", "javascript-injection"},
			})
		}

		// addJavascriptInterface
		if addJavascriptInterface.MatchString(line) {
			severity := rules.High
			confidence := "medium"
			context := surroundingContext(lines, i, 10)
			// Higher severity if WebView loads external URLs
			if strings.Contains(context, "loadUrl") && !strings.Contains(context, "file://") {
				severity = rules.Critical
				confidence = "high"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      severity,
				SeverityLabel: severity.String(),
				Title:         "WebView addJavascriptInterface exposes Kotlin objects to JavaScript",
				Description:   "addJavascriptInterface() exposes Kotlin/Java objects to JavaScript running in the WebView. If the WebView loads untrusted content, malicious JavaScript can call the exposed methods, potentially leading to remote code execution (pre-API 17) or data theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Ensure the WebView only loads trusted content (same-origin). Use @JavascriptInterface annotation on only the methods that need to be exposed (API 17+). Consider using WebMessagePort for safer communication.",
				CWEID:         "CWE-749",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"android", "webview", "javascript-interface"},
			})
		}
	}

	return findings
}

// --- KT-004: Insecure SharedPreferences ---

type InsecureSharedPreferences struct{}

func (r *InsecureSharedPreferences) ID() string                      { return "GTSS-KT-004" }
func (r *InsecureSharedPreferences) Name() string                    { return "InsecureSharedPreferences" }
func (r *InsecureSharedPreferences) Description() string             { return "Detects storage of secrets in SharedPreferences without encryption." }
func (r *InsecureSharedPreferences) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureSharedPreferences) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *InsecureSharedPreferences) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if using EncryptedSharedPreferences
	if strings.Contains(ctx.Content, "EncryptedSharedPreferences") {
		return nil
	}

	// Only trigger if file uses SharedPreferences
	if !sharedPrefsEdit.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if sharedPrefsPutData.MatchString(line) && sensitiveKeyNames.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Sensitive data stored in unencrypted SharedPreferences",
				Description:   "Secrets (passwords, tokens, API keys) are being stored in SharedPreferences without encryption. SharedPreferences are stored as plain-text XML on the device filesystem and can be extracted via backup, root access, or device compromise.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use EncryptedSharedPreferences from the AndroidX Security library: EncryptedSharedPreferences.create(..., MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)). For highly sensitive data, use the Android Keystore system.",
				CWEID:         "CWE-312",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"android", "shared-preferences", "plaintext-storage"},
			})
		}
	}

	return findings
}

// --- KT-005: Android Exported Components ---

type ExportedComponents struct{}

func (r *ExportedComponents) ID() string                      { return "GTSS-KT-005" }
func (r *ExportedComponents) Name() string                    { return "ExportedComponents" }
func (r *ExportedComponents) Description() string             { return "Detects Android components exported without permission protection in AndroidManifest.xml." }
func (r *ExportedComponents) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ExportedComponents) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin, rules.LangJava, rules.LangAny} }

func (r *ExportedComponents) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only scan AndroidManifest.xml files
	if !strings.HasSuffix(ctx.FilePath, "AndroidManifest.xml") {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if !exportedTrue.MatchString(line) {
			continue
		}

		// Determine component type
		componentType := "component"
		context := surroundingContext(lines, i, 5)
		if activityTag.MatchString(context) {
			componentType = "Activity"
		} else if serviceTag.MatchString(context) {
			componentType = "Service"
		} else if receiverTag.MatchString(context) {
			componentType = "BroadcastReceiver"
		} else if providerTag.MatchString(context) {
			componentType = "ContentProvider"
		}

		// Check if permission is set nearby
		if permissionAttr.MatchString(context) {
			continue // Protected by permission, skip
		}

		severity := r.DefaultSeverity()
		if componentType == "ContentProvider" || componentType == "Service" {
			severity = rules.High
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      severity,
			SeverityLabel: severity.String(),
			Title:         "Android " + componentType + " exported without permission protection",
			Description:   "The " + componentType + " has android:exported=\"true\" without an android:permission attribute. Any app on the device can interact with this component, potentially accessing sensitive data or triggering unintended actions.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Add android:permission to restrict access, or set android:exported=\"false\" if the component does not need to be accessible to other apps. For ContentProviders, also set android:readPermission and android:writePermission.",
			CWEID:         "CWE-926",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"android", "manifest", "exported-component"},
		})
	}

	return findings
}

// --- KT-006: Ktor CORS Misconfiguration ---

type KtorCORSMisconfig struct{}

func (r *KtorCORSMisconfig) ID() string                      { return "GTSS-KT-006" }
func (r *KtorCORSMisconfig) Name() string                    { return "KtorCORSMisconfig" }
func (r *KtorCORSMisconfig) Description() string             { return "Detects Ktor CORS plugin misconfiguration with anyHost() and allowCredentials." }
func (r *KtorCORSMisconfig) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *KtorCORSMisconfig) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KtorCORSMisconfig) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	if !ktorCORSBlock.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	hasAnyHost := ktorCORSAnyHost.MatchString(ctx.Content)
	hasAllowCredentials := ktorCORSAllowCredentials.MatchString(ctx.Content)

	if hasAnyHost && hasAllowCredentials {
		// Find the anyHost() line
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if ktorCORSAnyHost.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.High,
					SeverityLabel: rules.High.String(),
					Title:         "Ktor CORS allows all origins with credentials enabled",
					Description:   "The Ktor CORS plugin is configured with anyHost() and allowCredentials = true. This allows any website to make authenticated cross-origin requests, potentially stealing user data or performing unauthorized actions.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Replace anyHost() with allowHost(\"trusted-domain.com\") to whitelist specific origins. If credentials are needed, each origin must be explicitly listed.",
					CWEID:         "CWE-942",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"ktor", "cors", "security-config"},
				})
				break
			}
		}
	} else if hasAnyHost {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if ktorCORSAnyHost.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Ktor CORS allows all origins via anyHost()",
					Description:   "The Ktor CORS plugin is configured with anyHost(), allowing requests from any origin. While less dangerous without credentials, this expands the attack surface unnecessarily.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Replace anyHost() with allowHost(\"trusted-domain.com\") to restrict CORS to specific trusted origins.",
					CWEID:         "CWE-942",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"ktor", "cors", "security-config"},
				})
				break
			}
		}
	}

	return findings
}

// --- KT-007: Unsafe Coroutine Exception Handling ---

type UnsafeCoroutineException struct{}

func (r *UnsafeCoroutineException) ID() string                      { return "GTSS-KT-007" }
func (r *UnsafeCoroutineException) Name() string                    { return "UnsafeCoroutineException" }
func (r *UnsafeCoroutineException) Description() string             { return "Detects GlobalScope.launch/async without CoroutineExceptionHandler." }
func (r *UnsafeCoroutineException) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UnsafeCoroutineException) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *UnsafeCoroutineException) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	hasExceptionHandler := coroutineExceptionHandler.MatchString(ctx.Content)
	hasSupervisorJob := supervisorJob.MatchString(ctx.Content)

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		if loc := globalScopeLaunch.FindString(line); loc != "" {
			matched = loc
		} else if loc := globalScopeAsync.FindString(line); loc != "" {
			matched = loc
		}

		if matched != "" {
			// Lower confidence if handler exists elsewhere in file
			if hasExceptionHandler || hasSupervisorJob {
				continue
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "GlobalScope coroutine without exception handler",
				Description:   "GlobalScope.launch/async without a CoroutineExceptionHandler will silently swallow exceptions or crash the application. Unhandled exceptions in security-critical coroutines (authentication, authorization checks) may leave the system in an insecure state.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use structured concurrency (coroutineScope, viewModelScope, lifecycleScope) instead of GlobalScope. If GlobalScope is necessary, provide a CoroutineExceptionHandler: GlobalScope.launch(handler) { ... }.",
				CWEID:         "CWE-755",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"kotlin", "coroutine", "exception-handling"},
			})
		}
	}

	return findings
}

// --- KT-008: Kotlin Serialization with Untrusted Input ---

type KotlinSerializationUntrusted struct{}

func (r *KotlinSerializationUntrusted) ID() string                      { return "GTSS-KT-008" }
func (r *KotlinSerializationUntrusted) Name() string                    { return "KotlinSerializationUntrusted" }
func (r *KotlinSerializationUntrusted) Description() string             { return "Detects kotlinx.serialization Json.decodeFromString with potentially untrusted input." }
func (r *KotlinSerializationUntrusted) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinSerializationUntrusted) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinSerializationUntrusted) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag when there's evidence of user input in the file
	hasUserInput := strings.Contains(ctx.Content, "call.receive") ||
		strings.Contains(ctx.Content, "call.receiveText") ||
		strings.Contains(ctx.Content, "queryParameters") ||
		strings.Contains(ctx.Content, "@RequestBody") ||
		strings.Contains(ctx.Content, "@RequestParam") ||
		strings.Contains(ctx.Content, "request.getParameter") ||
		strings.Contains(ctx.Content, "intent.getStringExtra") ||
		strings.Contains(ctx.Content, "readLine()")

	if !hasUserInput {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		if loc := jsonDecodeFromString.FindString(line); loc != "" {
			matched = loc
		} else if loc := jsonDecodeCustom.FindString(line); loc != "" {
			matched = loc
		}

		if matched != "" {
			// Check if nearby code validates or sanitizes input
			context := surroundingContext(lines, i, 5)
			confidence := "medium"
			if strings.Contains(context, "receiveText") || strings.Contains(context, "queryParameters") {
				confidence = "high"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "kotlinx.serialization decoding potentially untrusted input",
				Description:   "Json.decodeFromString() is used in a context with user input. If the JSON structure controls which class gets instantiated (e.g., via polymorphic serialization with open polymorphism), an attacker may force deserialization of unexpected types leading to unexpected behavior or denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate input before deserialization. Avoid open polymorphic serialization with untrusted input. Use sealed class hierarchies for polymorphism and wrap deserialization in try-catch to handle malformed input gracefully.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"kotlin", "serialization", "deserialization"},
			})
		}
	}

	return findings
}

// --- Helpers ---

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func surroundingContext(lines []string, idx, radius int) string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}
