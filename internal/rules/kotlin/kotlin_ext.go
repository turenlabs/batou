package kotlin

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Kotlin extension rules (BATOU-KT-017 .. BATOU-KT-024)
// ---------------------------------------------------------------------------

// KT-017: Runtime.exec with string concatenation
var (
	reRuntimeExecConcat  = regexp.MustCompile(`Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+|\$\{|\$[a-zA-Z_])`)
	reRuntimeExecInterp  = regexp.MustCompile(`Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*"[^"]*\$\{`)
	reProcessBuilderConcat = regexp.MustCompile(`ProcessBuilder\s*\(\s*(?:listOf|arrayOf)?\s*\(?\s*(?:"[^"]*"\s*\+|\$\{|\$[a-zA-Z_])`)
)

// KT-018: WebView JavaScript enabled without protection
var (
	reWebViewJSEnabled     = regexp.MustCompile(`\.settings\s*\.\s*javaScriptEnabled\s*=\s*true`)
	reAddJavascriptInterface = regexp.MustCompile(`\.addJavascriptInterface\s*\(`)
	reWebViewClientSafe    = regexp.MustCompile(`\.webViewClient\s*=|setWebViewClient\s*\(`)
)

// KT-019: SharedPreferences storing sensitive data
var (
	reSharedPrefEdit     = regexp.MustCompile(`(?:getSharedPreferences|PreferenceManager\.getDefaultSharedPreferences)\s*\(`)
	reSharedPrefPutSens  = regexp.MustCompile(`\.(?:putString|putInt|putBoolean)\s*\(\s*"[^"]*(?i:password|token|secret|key|auth|credential|pin|ssn|credit|session)[^"]*"`)
)

// KT-020: Intent with user-controlled component
var (
	reIntentSetComponent  = regexp.MustCompile(`(?:intent|Intent)\s*(?:\(\s*\))?\s*\.?\s*(?:setComponent|setClassName|setClass)\s*\(`)
	reIntentComponentVar  = regexp.MustCompile(`\.(?:setComponent|setClassName|setClass)\s*\(\s*[a-zA-Z_]\w*`)
	reIntentFromExtra     = regexp.MustCompile(`getStringExtra\s*\([^)]*\)\s*.*\.(?:setComponent|setClassName|setClass)`)
)

// KT-021: Exported ContentProvider without permissions
var (
	reContentProviderExported = regexp.MustCompile(`android:exported\s*=\s*"true"`)
	reProviderTag             = regexp.MustCompile(`<provider\b`)
	reProviderPermission      = regexp.MustCompile(`android:(?:permission|readPermission|writePermission)\s*=`)
)

// KT-022: Insecure broadcast receiver
var (
	reSendBroadcastNoPermission = regexp.MustCompile(`sendBroadcast\s*\(\s*[a-zA-Z_]\w*\s*\)`)
	reRegisterReceiverInsecure  = regexp.MustCompile(`registerReceiver\s*\(\s*[a-zA-Z_]\w*\s*,\s*[a-zA-Z_]\w*\s*\)`)
)

// KT-023: SQL injection in Room raw query
var (
	reRoomRawQueryAnnot  = regexp.MustCompile(`@RawQuery`)
	reSupportSQLiteQuery = regexp.MustCompile(`SimpleSQLiteQuery\s*\(\s*(?:"[^"]*"\s*\+|"[^"]*\$\{|\$"[^"]*\$\{|[a-zA-Z_]\w*\s*\+)`)
	reRoomQueryRaw       = regexp.MustCompile(`\.query\s*\(\s*(?:SimpleSQLiteQuery|SupportSQLiteQuery)\s*\(\s*(?:"[^"]*"\s*\+|"[^"]*\$\{)`)
)

// KT-024: Certificate pinning bypass (trust all)
var (
	reTrustAllCerts    = regexp.MustCompile(`TrustManager|X509TrustManager`)
	reCheckServerEmpty = regexp.MustCompile(`checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}?`)
	reHostnameVerifier = regexp.MustCompile(`HostnameVerifier\s*\{?\s*(?:_\s*,\s*_\s*->|.*->)\s*true`)
	reSSLSocketFactory = regexp.MustCompile(`sslSocketFactory\s*\(|SSLContext\.getInstance`)
)

func init() {
	rules.Register(&KotlinRuntimeExec{})
	rules.Register(&KotlinWebViewJS{})
	rules.Register(&KotlinSharedPrefSensitive{})
	rules.Register(&KotlinIntentRedirect{})
	rules.Register(&KotlinExportedProvider{})
	rules.Register(&KotlinInsecureBroadcast{})
	rules.Register(&KotlinRoomRawQuery{})
	rules.Register(&KotlinTrustAllCerts{})
}

// ---------------------------------------------------------------------------
// BATOU-KT-017: Kotlin Runtime.exec with string concatenation
// ---------------------------------------------------------------------------

type KotlinRuntimeExec struct{}

func (r *KotlinRuntimeExec) ID() string                      { return "BATOU-KT-017" }
func (r *KotlinRuntimeExec) Name() string                    { return "KotlinRuntimeExec" }
func (r *KotlinRuntimeExec) Description() string             { return "Detects Kotlin Runtime.exec or ProcessBuilder with string concatenation or template interpolation, enabling command injection." }
func (r *KotlinRuntimeExec) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinRuntimeExec) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinRuntimeExec) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		var desc string

		if m := reRuntimeExecConcat.FindString(line); m != "" {
			matched = m
			desc = "Runtime.exec() with string concatenation or template"
		} else if m := reRuntimeExecInterp.FindString(line); m != "" {
			matched = m
			desc = "Runtime.exec() with string template interpolation"
		} else if m := reProcessBuilderConcat.FindString(line); m != "" {
			matched = m
			desc = "ProcessBuilder with string concatenation or template"
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Kotlin command injection via " + desc,
				Description:   "Constructing commands via string concatenation or Kotlin string templates (${ }) and passing them to Runtime.exec() or ProcessBuilder allows injection of arbitrary OS commands via shell metacharacters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use ProcessBuilder with a separate argument list instead of a single command string: ProcessBuilder(\"cmd\", arg1, arg2). Validate and sanitize all user-provided values.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "command-injection", "runtime-exec"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-018: Kotlin WebView JavaScript enabled without protection
// ---------------------------------------------------------------------------

type KotlinWebViewJS struct{}

func (r *KotlinWebViewJS) ID() string                      { return "BATOU-KT-018" }
func (r *KotlinWebViewJS) Name() string                    { return "KotlinWebViewJS" }
func (r *KotlinWebViewJS) Description() string             { return "Detects Kotlin WebView with JavaScript enabled and addJavascriptInterface without proper WebViewClient protection." }
func (r *KotlinWebViewJS) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinWebViewJS) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinWebViewJS) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only flag if JavaScript is enabled
	if !reWebViewJSEnabled.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		if reAddJavascriptInterface.MatchString(line) {
			matched := reAddJavascriptInterface.FindString(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Kotlin WebView with JavaScript and addJavascriptInterface",
				Description:   "A WebView has JavaScript enabled and exposes a Java/Kotlin object via addJavascriptInterface(). On Android versions below 4.2, this allows arbitrary code execution via reflection. On all versions, any JavaScript running in the WebView can call exposed methods.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove addJavascriptInterface if not needed. Use @JavascriptInterface annotation on exposed methods only. Set a WebViewClient and override shouldOverrideUrlLoading to restrict navigation. Use evaluateJavascript() for communication instead.",
				CWEID:         "CWE-749",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "android", "webview", "javascript-interface"},
			})
		}

		if reWebViewJSEnabled.MatchString(line) && !reWebViewClientSafe.MatchString(ctx.Content) {
			matched := reWebViewJSEnabled.FindString(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Medium,
				SeverityLabel: rules.Medium.String(),
				Title:         "Kotlin WebView JavaScript enabled without WebViewClient",
				Description:   "A WebView has JavaScript enabled without a custom WebViewClient. Without URL restrictions, the WebView can navigate to arbitrary URLs and execute JavaScript from untrusted origins.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set a WebViewClient and override shouldOverrideUrlLoading to restrict allowed URLs. Only enable JavaScript if absolutely necessary.",
				CWEID:         "CWE-749",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"kotlin", "android", "webview", "javascript"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-019: Kotlin SharedPreferences storing sensitive data
// ---------------------------------------------------------------------------

type KotlinSharedPrefSensitive struct{}

func (r *KotlinSharedPrefSensitive) ID() string                      { return "BATOU-KT-019" }
func (r *KotlinSharedPrefSensitive) Name() string                    { return "KotlinSharedPrefSensitive" }
func (r *KotlinSharedPrefSensitive) Description() string             { return "Detects Kotlin SharedPreferences storing sensitive data (passwords, tokens, keys) in plaintext." }
func (r *KotlinSharedPrefSensitive) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinSharedPrefSensitive) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinSharedPrefSensitive) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Quick bail: no SharedPreferences usage
	if !reSharedPrefEdit.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		if m := reSharedPrefPutSens.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Kotlin SharedPreferences storing sensitive data in plaintext",
				Description:   "Sensitive data (password, token, secret, key, credential) is stored in Android SharedPreferences which are stored as plaintext XML on the device filesystem. Rooted devices or backup extraction can expose this data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use EncryptedSharedPreferences from AndroidX Security library: EncryptedSharedPreferences.create(\"secret_prefs\", masterKey, ...). Alternatively, use the Android Keystore system for cryptographic keys.",
				CWEID:         "CWE-312",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "android", "shared-preferences", "plaintext-storage"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-020: Kotlin Intent with user-controlled component
// ---------------------------------------------------------------------------

type KotlinIntentRedirect struct{}

func (r *KotlinIntentRedirect) ID() string                      { return "BATOU-KT-020" }
func (r *KotlinIntentRedirect) Name() string                    { return "KotlinIntentRedirect" }
func (r *KotlinIntentRedirect) Description() string             { return "Detects Kotlin Intent with user-controlled component class, enabling intent redirect attacks to access private activities." }
func (r *KotlinIntentRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinIntentRedirect) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinIntentRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reIntentSetComponent.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		if reIntentComponentVar.MatchString(line) || reIntentFromExtra.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Kotlin Intent with user-controlled component (intent redirect)",
				Description:   "An Intent's component (setComponent/setClassName/setClass) is set from a variable that may originate from user input (extras, deep links). An attacker can redirect the Intent to access non-exported activities, potentially bypassing authentication or accessing private data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate the target component against an allowlist of permitted activity classes before starting it. Never use user input directly in setComponent/setClassName. Use explicit intents with hardcoded class references.",
				CWEID:         "CWE-927",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"kotlin", "android", "intent-redirect", "access-control"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-021: Kotlin exported ContentProvider without permissions
// ---------------------------------------------------------------------------

type KotlinExportedProvider struct{}

func (r *KotlinExportedProvider) ID() string                      { return "BATOU-KT-021" }
func (r *KotlinExportedProvider) Name() string                    { return "KotlinExportedProvider" }
func (r *KotlinExportedProvider) Description() string             { return "Detects Android exported ContentProvider without read/write permissions in manifest files." }
func (r *KotlinExportedProvider) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinExportedProvider) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinExportedProvider) Scan(ctx *rules.ScanContext) []rules.Finding {
	// This rule targets AndroidManifest.xml or similar Kotlin config
	if !reProviderTag.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inProvider := false
	providerStartLine := 0

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "<!--") {
			continue
		}

		if reProviderTag.MatchString(line) {
			inProvider = true
			providerStartLine = i
		}

		if inProvider && reContentProviderExported.MatchString(line) {
			// Check if there's a permission in the provider block
			hasPermission := false
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			for j := providerStartLine; j < end; j++ {
				if reProviderPermission.MatchString(lines[j]) {
					hasPermission = true
					break
				}
				if strings.Contains(lines[j], "/>") || strings.Contains(lines[j], "</provider>") {
					break
				}
			}

			if !hasPermission {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Exported ContentProvider without permissions",
					Description:   "A ContentProvider is exported (android:exported=true) without specifying readPermission or writePermission. Any app on the device can read from or write to this provider, potentially accessing or modifying sensitive data.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Add android:readPermission and android:writePermission to restrict access, or set android:exported=\"false\" if the provider is not needed by other apps. Use signature-level permissions for inter-app access.",
					CWEID:         "CWE-926",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"kotlin", "android", "content-provider", "exported"},
				})
			}
		}

		if inProvider && (strings.Contains(line, "/>") || strings.Contains(line, "</provider>")) {
			inProvider = false
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-022: Kotlin insecure broadcast receiver
// ---------------------------------------------------------------------------

type KotlinInsecureBroadcast struct{}

func (r *KotlinInsecureBroadcast) ID() string                      { return "BATOU-KT-022" }
func (r *KotlinInsecureBroadcast) Name() string                    { return "KotlinInsecureBroadcast" }
func (r *KotlinInsecureBroadcast) Description() string             { return "Detects Kotlin sendBroadcast or registerReceiver without permission protection." }
func (r *KotlinInsecureBroadcast) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *KotlinInsecureBroadcast) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinInsecureBroadcast) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		var desc string

		if m := reSendBroadcastNoPermission.FindString(line); m != "" {
			matched = m
			desc = "sendBroadcast() is called without a receiver permission parameter. Any app can receive this broadcast, potentially leaking sensitive data."
		} else if m := reRegisterReceiverInsecure.FindString(line); m != "" {
			matched = m
			desc = "registerReceiver() is called without a sender permission parameter. Any app can send intents to this receiver, potentially injecting malicious data."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Kotlin insecure broadcast (no permission)",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "For sendBroadcast, specify a receiver permission: sendBroadcast(intent, \"com.app.MY_PERMISSION\"). For registerReceiver, use LocalBroadcastManager for app-internal broadcasts or specify a sender permission.",
				CWEID:         "CWE-927",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"kotlin", "android", "broadcast", "ipc"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-KT-023: Kotlin SQL injection in Room raw query
// ---------------------------------------------------------------------------

type KotlinRoomRawQuery struct{}

func (r *KotlinRoomRawQuery) ID() string                      { return "BATOU-KT-023" }
func (r *KotlinRoomRawQuery) Name() string                    { return "KotlinRoomRawQuery" }
func (r *KotlinRoomRawQuery) Description() string             { return "Detects Kotlin SQL injection via Room @RawQuery with SimpleSQLiteQuery built from string concatenation." }
func (r *KotlinRoomRawQuery) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinRoomRawQuery) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinRoomRawQuery) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string

		if m := reSupportSQLiteQuery.FindString(line); m != "" {
			matched = m
		} else if m := reRoomQueryRaw.FindString(line); m != "" {
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
				Title:         "Kotlin SQL injection in Room raw query",
				Description:   "A SimpleSQLiteQuery is constructed with string concatenation or Kotlin string templates. If user input is included, this enables SQL injection bypassing Room's built-in parameterization.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use Room's @Query annotation with parameter binding: @Query(\"SELECT * FROM users WHERE id = :userId\"). For dynamic queries, use SimpleSQLiteQuery with bind parameters: SimpleSQLiteQuery(\"SELECT * FROM users WHERE id = ?\", arrayOf(userId)).",
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
// BATOU-KT-024: Kotlin certificate pinning bypass (trust all)
// ---------------------------------------------------------------------------

type KotlinTrustAllCerts struct{}

func (r *KotlinTrustAllCerts) ID() string                      { return "BATOU-KT-024" }
func (r *KotlinTrustAllCerts) Name() string                    { return "KotlinTrustAllCerts" }
func (r *KotlinTrustAllCerts) Description() string             { return "Detects Kotlin TLS bypasses: custom TrustManager that trusts all certs, HostnameVerifier that always returns true, disabling SSL verification." }
func (r *KotlinTrustAllCerts) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *KotlinTrustAllCerts) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }

func (r *KotlinTrustAllCerts) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		var title, desc string

		if m := reHostnameVerifier.FindString(line); m != "" {
			matched = m
			title = "Kotlin HostnameVerifier always returns true"
			desc = "A HostnameVerifier is configured to always return true, disabling hostname verification. Any valid TLS certificate will be accepted regardless of the hostname, enabling man-in-the-middle attacks."
		} else if reCheckServerEmpty.MatchString(line) && reTrustAllCerts.MatchString(ctx.Content) {
			matched = strings.TrimSpace(line)
			title = "Kotlin TrustManager with empty checkServerTrusted"
			desc = "A custom X509TrustManager with an empty or permissive checkServerTrusted method trusts all server certificates, including self-signed and expired ones. This completely disables TLS certificate verification."
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
				Suggestion:    "Remove custom TrustManager/HostnameVerifier. Use certificate pinning via OkHttp CertificatePinner or Android's network_security_config.xml. For testing, use build-type-specific configurations rather than disabling TLS globally.",
				CWEID:         "CWE-295",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"kotlin", "tls", "certificate-bypass", "mitm"},
			})
		}
	}
	return findings
}
