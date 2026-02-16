package jsts

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Extension patterns for JSTS-019 through JSTS-030
// ---------------------------------------------------------------------------

// JSTS-019: Electron nodeIntegration enabled (more specific than JSTS-013)
var (
	reElectronNodeIntExt    = regexp.MustCompile(`nodeIntegration\s*:\s*true`)
	reElectronPreloadExt    = regexp.MustCompile(`preload\s*:`)
	reElectronSandboxFalse  = regexp.MustCompile(`sandbox\s*:\s*false`)
)

// JSTS-020: Electron contextIsolation disabled
var (
	reElectronCtxIsoFalse = regexp.MustCompile(`contextIsolation\s*:\s*false`)
	reElectronCtxBridge   = regexp.MustCompile(`contextBridge\.exposeInMainWorld`)
)

// JSTS-021: postMessage without origin check (extended)
var (
	reOnMessage          = regexp.MustCompile(`\.onmessage\s*=\s*`)
	rePostMsgWildcard    = regexp.MustCompile(`\.postMessage\s*\([^,]+,\s*["']\*["']\s*\)`)
)

// JSTS-022: Insecure WebView loadURL with user input
var (
	reWebViewLoadURL     = regexp.MustCompile(`\.loadURL\s*\(\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|url|param|data)`)
	reWebViewSrc         = regexp.MustCompile(`<webview[^>]*src\s*=\s*\{`)
	reWebViewNavPolicy   = regexp.MustCompile(`will-navigate|new-window`)
)

// JSTS-023: Prototype pollution via Object.assign/spread
var (
	reObjectAssignReq   = regexp.MustCompile(`Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req\.(?:body|query|params)|userInput|user[Ii]nput|input|data|payload)`)
	reSpreadReq         = regexp.MustCompile(`\{\s*\.\.\.(?:req\.(?:body|query|params)|userInput|user[Ii]nput|input|data|payload)\s*\}`)
	reMergeDeep         = regexp.MustCompile(`(?:merge|deepMerge|_.merge|lodash\.merge|extend)\s*\(\s*\{\s*\}\s*,\s*(?:req\.(?:body|query|params)|userInput|user[Ii]nput|input|data|payload)`)
)

// JSTS-024: Regex DoS (catastrophic backtracking patterns)
var (
	reCatastrophicRegex  = regexp.MustCompile(`/\([^)]*[+*]\)[+*]`)
	reNestedQuantifier   = regexp.MustCompile(`/\([^)]*\([^)]*[+*]\)[^)]*\)[+*]`)
	reRegexFromInput     = regexp.MustCompile(`new\s+RegExp\s*\(\s*(?:req\.|user|input|query|search|param|data)`)
)

// JSTS-025: npm script postinstall executing remote code
var (
	rePostinstallCurl  = regexp.MustCompile(`"(?:postinstall|preinstall|install)"\s*:\s*"[^"]*(?:curl|wget|node\s+-e|sh\s+-c|bash\s+-c)`)
	rePostinstallPipe  = regexp.MustCompile(`"(?:postinstall|preinstall|install)"\s*:\s*"[^"]*\|`)
)

// JSTS-026: Insecure use of Math.random for security
var (
	reMathRandom        = regexp.MustCompile(`Math\.random\s*\(\s*\)`)
	reMathRandSecurity  = regexp.MustCompile(`(?i)(?:token|password|secret|key|nonce|salt|otp|csrf|session|uuid|auth|api[_\-]?key|hash|encrypt|credential|random[Bb]ytes)`)
)

// JSTS-027: DOM clobbering via unsanitized element IDs (extended)
var (
	reDOMIdAccess      = regexp.MustCompile(`document\.getElementById\s*\(\s*[^"')\s]`)
	reWindowNameAccess = regexp.MustCompile(`window\[(?:req\.|user|input|param|data|query)`)
	reDOMNamedAccess   = regexp.MustCompile(`document\s*\.\s*(?:forms|anchors|embeds|images|links)\s*\[`)
)

// JSTS-028: Missing Content-Type header in API response
var (
	reResJSON          = regexp.MustCompile(`res\.(?:send|write)\s*\(`)
	reResContentType   = regexp.MustCompile(`res\.(?:setHeader|set|type|header)\s*\(\s*["'](?:Content-Type|content-type)["']`)
	reResJsonMethod    = regexp.MustCompile(`res\.json\s*\(`)
	reExpressApp       = regexp.MustCompile(`(?:express\s*\(\s*\)|app\s*\.\s*(?:get|post|put|delete|patch|all)\s*\()`)
)

// JSTS-029: Node.js require() with user-controlled path
var (
	reRequireUserVar   = regexp.MustCompile(`require\s*\(\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|param|module|plugin|name|path)\b`)
	reRequireConcat    = regexp.MustCompile(`require\s*\(\s*(?:['"][^'"]*['"]\s*\+\s*(?:req\.|user|input|param)|` + "`[^`]*\\$\\{" + `)`)
	reImportExprUser   = regexp.MustCompile(`import\s*\(\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|param|module)`)
)

// JSTS-030: Insecure cookie settings
var (
	reSetCookieHeader   = regexp.MustCompile(`res\.setHeader\s*\(\s*["']Set-Cookie["']`)
	reCookieNoHttpOnly  = regexp.MustCompile(`Set-Cookie["'][^)]*(?:session|token|auth|jwt)`)
	reCookieParserNoOpts = regexp.MustCompile(`cookieParser\s*\(\s*\)`)
)

func init() {
	rules.Register(&ElectronNodeIntExt{})
	rules.Register(&ElectronCtxIsoExt{})
	rules.Register(&PostMsgOriginExt{})
	rules.Register(&WebViewLoadURLExt{})
	rules.Register(&PrototypePollution{})
	rules.Register(&RegexCatastrophic{})
	rules.Register(&NPMPostinstallRCE{})
	rules.Register(&MathRandomSecurity{})
	rules.Register(&DOMClobberingExt{})
	rules.Register(&MissingContentType{})
	rules.Register(&RequireUserPath{})
	rules.Register(&InsecureCookieExt{})
}

// ---------------------------------------------------------------------------
// JSTS-019: Electron nodeIntegration enabled
// ---------------------------------------------------------------------------

type ElectronNodeIntExt struct{}

func (r *ElectronNodeIntExt) ID() string                     { return "GTSS-JSTS-019" }
func (r *ElectronNodeIntExt) Name() string                   { return "ElectronNodeIntExt" }
func (r *ElectronNodeIntExt) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ElectronNodeIntExt) Description() string {
	return "Detects Electron BrowserWindow with nodeIntegration:true without sandbox, giving renderer full Node.js access."
}
func (r *ElectronNodeIntExt) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ElectronNodeIntExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	if !strings.Contains(ctx.Content, "BrowserWindow") && !strings.Contains(ctx.Content, "electron") {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reElectronNodeIntExt.MatchString(line) && !reElectronSandboxFalse.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Electron nodeIntegration enabled (RCE risk)",
				Description:   "nodeIntegration:true gives the renderer process unrestricted access to Node.js APIs. Any XSS in the renderer leads to full remote code execution including file system access and child_process.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Set nodeIntegration: false and contextIsolation: true. Use a preload script with contextBridge.exposeInMainWorld() to safely expose specific APIs.",
				CWEID:         "CWE-94",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"electron", "node-integration", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-020: Electron contextIsolation disabled
// ---------------------------------------------------------------------------

type ElectronCtxIsoExt struct{}

func (r *ElectronCtxIsoExt) ID() string                     { return "GTSS-JSTS-020" }
func (r *ElectronCtxIsoExt) Name() string                   { return "ElectronCtxIsoExt" }
func (r *ElectronCtxIsoExt) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ElectronCtxIsoExt) Description() string {
	return "Detects Electron with contextIsolation:false, allowing renderer scripts to access preload script context."
}
func (r *ElectronCtxIsoExt) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ElectronCtxIsoExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	if !strings.Contains(ctx.Content, "contextIsolation") {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reElectronCtxIsoFalse.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Electron contextIsolation disabled (privilege escalation risk)",
				Description:   "contextIsolation:false allows web page scripts to share the same JavaScript context as preload scripts. This lets XSS payloads access Node.js APIs exposed by the preload script, escalating to RCE.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Set contextIsolation: true (default since Electron 12). Use contextBridge.exposeInMainWorld() in the preload script to safely expose limited APIs.",
				CWEID:         "CWE-94",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"electron", "context-isolation", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-021: postMessage without origin check (extended: wildcard target)
// ---------------------------------------------------------------------------

type PostMsgOriginExt struct{}

func (r *PostMsgOriginExt) ID() string                     { return "GTSS-JSTS-021" }
func (r *PostMsgOriginExt) Name() string                   { return "PostMsgOriginExt" }
func (r *PostMsgOriginExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *PostMsgOriginExt) Description() string {
	return "Detects postMessage with wildcard '*' target origin, sending data to any window that receives it."
}
func (r *PostMsgOriginExt) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *PostMsgOriginExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := rePostMsgWildcard.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "postMessage with wildcard '*' target origin",
				Description:   "Calling postMessage with '*' as the target origin sends the message to any window, including potentially hostile ones. Sensitive data can be intercepted by any page that has a reference to this window.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Specify the exact target origin: window.postMessage(data, 'https://trusted.example.com'). Never use '*' when sending sensitive data.",
				CWEID:         "CWE-346",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"postmessage", "origin", "cross-origin"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-022: Insecure WebView loadURL with user input
// ---------------------------------------------------------------------------

type WebViewLoadURLExt struct{}

func (r *WebViewLoadURLExt) ID() string                     { return "GTSS-JSTS-022" }
func (r *WebViewLoadURLExt) Name() string                   { return "WebViewLoadURLExt" }
func (r *WebViewLoadURLExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *WebViewLoadURLExt) Description() string {
	return "Detects Electron/WebView loadURL with user-controlled input, enabling XSS or arbitrary page loading."
}
func (r *WebViewLoadURLExt) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *WebViewLoadURLExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := reWebViewLoadURL.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "WebView/BrowserWindow loadURL with user-controlled input",
				Description:   "Passing user-controlled input to loadURL() allows loading arbitrary pages including file:// URLs, javascript: URLs, or attacker-controlled sites that could exploit nodeIntegration if enabled.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Validate the URL scheme (allow only https://), check the hostname against an allowlist, and reject file://, javascript:, and data: URLs.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"electron", "webview", "xss", "url"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-023: Prototype pollution via Object.assign/spread
// ---------------------------------------------------------------------------

type PrototypePollution struct{}

func (r *PrototypePollution) ID() string                     { return "GTSS-JSTS-023" }
func (r *PrototypePollution) Name() string                   { return "PrototypePollution" }
func (r *PrototypePollution) DefaultSeverity() rules.Severity { return rules.High }
func (r *PrototypePollution) Description() string {
	return "Detects Object.assign, spread operator, or deep merge with user input, enabling prototype pollution."
}
func (r *PrototypePollution) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *PrototypePollution) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reObjectAssignReq.FindString(line); m != "" {
			matched = m
		} else if m := reSpreadReq.FindString(line); m != "" {
			matched = m
		} else if m := reMergeDeep.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Prototype pollution via Object.assign/spread/merge with user input",
				Description:   "Merging user-controlled input into objects can pollute Object.prototype via __proto__ or constructor.prototype keys. This can modify behavior of all objects in the application, leading to auth bypass, RCE, or DoS.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Sanitize input: delete __proto__ and constructor keys. Use Object.create(null) as target. Use Map instead of plain objects for user data. Consider using JSON schema validation.",
				CWEID:         "CWE-1321",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"prototype-pollution", "object-assign", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-024: Regex DoS (catastrophic backtracking) pattern
// ---------------------------------------------------------------------------

type RegexCatastrophic struct{}

func (r *RegexCatastrophic) ID() string                     { return "GTSS-JSTS-024" }
func (r *RegexCatastrophic) Name() string                   { return "RegexCatastrophic" }
func (r *RegexCatastrophic) DefaultSeverity() rules.Severity { return rules.High }
func (r *RegexCatastrophic) Description() string {
	return "Detects regex patterns with nested quantifiers that cause catastrophic backtracking, or RegExp with user input."
}
func (r *RegexCatastrophic) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *RegexCatastrophic) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reCatastrophicRegex.FindString(line); m != "" {
			matched = m
		} else if m := reNestedQuantifier.FindString(line); m != "" {
			matched = m
		} else if m := reRegexFromInput.FindString(line); m != "" {
			if !strings.Contains(line, "escapeRegExp") && !strings.Contains(line, "escape_regex") {
				matched = m
			}
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Regex with catastrophic backtracking potential (ReDoS)",
				Description:   "This regex contains nested quantifiers (e.g., (a+)+) or is constructed from user input, which can cause exponential backtracking. On crafted input, a single regex match can freeze the event loop for minutes.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Simplify the regex to avoid nested quantifiers. Use atomic groups or possessive quantifiers if available. For user input, escape with escapeRegExp() or use re2 (linear-time regex).",
				CWEID:         "CWE-1333",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"redos", "regex", "backtracking"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-025: npm script postinstall executing remote code
// ---------------------------------------------------------------------------

type NPMPostinstallRCE struct{}

func (r *NPMPostinstallRCE) ID() string                     { return "GTSS-JSTS-025" }
func (r *NPMPostinstallRCE) Name() string                   { return "NPMPostinstallRCE" }
func (r *NPMPostinstallRCE) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *NPMPostinstallRCE) Description() string {
	return "Detects npm lifecycle scripts (postinstall/preinstall) that download and execute remote code."
}
func (r *NPMPostinstallRCE) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NPMPostinstallRCE) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	if !strings.Contains(ctx.Content, "postinstall") && !strings.Contains(ctx.Content, "preinstall") {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := rePostinstallCurl.FindString(line); m != "" {
			matched = m
		} else if m := rePostinstallPipe.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "npm lifecycle script executes remote code (supply chain risk)",
				Description:   "The postinstall/preinstall script downloads and executes code from a remote source. This is a common supply chain attack vector used in malicious npm packages to install backdoors.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Audit lifecycle scripts in dependencies. Use --ignore-scripts during npm install. Pin dependencies with lockfiles and use npm audit. Consider using socket.dev or snyk for supply chain security.",
				CWEID:         "CWE-506",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"npm", "supply-chain", "postinstall", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-026: Insecure use of Math.random for security
// ---------------------------------------------------------------------------

type MathRandomSecurity struct{}

func (r *MathRandomSecurity) ID() string                     { return "GTSS-JSTS-026" }
func (r *MathRandomSecurity) Name() string                   { return "MathRandomSecurity" }
func (r *MathRandomSecurity) DefaultSeverity() rules.Severity { return rules.High }
func (r *MathRandomSecurity) Description() string {
	return "Detects Math.random() used in security-sensitive contexts (tokens, keys, sessions)."
}
func (r *MathRandomSecurity) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *MathRandomSecurity) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	if !reMathRandom.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reMathRandom.MatchString(line) {
			if reMathRandSecurity.MatchString(line) || hasNearbyMatch(lines, i, reMathRandSecurity, 5) {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Math.random() used in security-sensitive context",
					Description:   "Math.random() is not cryptographically secure. Its output is predictable and can be reverse-engineered from observed values. Using it for tokens, keys, or session IDs allows attackers to predict future values.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Use crypto.randomBytes() in Node.js or crypto.getRandomValues() in browsers for cryptographically secure random values. For UUIDs, use the uuid package with v4.",
					CWEID:         "CWE-338",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"math-random", "crypto", "predictable"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-027: DOM clobbering via unsanitized element IDs (extended)
// ---------------------------------------------------------------------------

type DOMClobberingExt struct{}

func (r *DOMClobberingExt) ID() string                     { return "GTSS-JSTS-027" }
func (r *DOMClobberingExt) Name() string                   { return "DOMClobberingExt" }
func (r *DOMClobberingExt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DOMClobberingExt) Description() string {
	return "Detects DOM element access via dynamic IDs or named collections vulnerable to DOM clobbering attacks."
}
func (r *DOMClobberingExt) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DOMClobberingExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reDOMIdAccess.FindString(line); m != "" {
			matched = m
		} else if m := reWindowNameAccess.FindString(line); m != "" {
			matched = m
		} else if m := reDOMNamedAccess.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "DOM element access with dynamic ID (DOM clobbering risk)",
				Description:   "Accessing DOM elements by dynamic/user-controlled IDs or via named collections (document.forms, window[name]) is vulnerable to DOM clobbering. An attacker injecting HTML with matching id/name attributes can override expected values.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use data attributes or a unique prefix for element IDs. Verify element types with instanceof before accessing properties. Use DOMPurify for user-controlled HTML.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"dom-clobbering", "xss", "dom"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-028: Missing Content-Type header in API response
// ---------------------------------------------------------------------------

type MissingContentType struct{}

func (r *MissingContentType) ID() string                     { return "GTSS-JSTS-028" }
func (r *MissingContentType) Name() string                   { return "MissingContentType" }
func (r *MissingContentType) DefaultSeverity() rules.Severity { return rules.Low }
func (r *MissingContentType) Description() string {
	return "Detects Express res.send/write without Content-Type, allowing MIME sniffing and XSS."
}
func (r *MissingContentType) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *MissingContentType) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	if !reExpressApp.MatchString(ctx.Content) {
		return nil
	}
	if reResContentType.MatchString(ctx.Content) || reResJsonMethod.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reResJSON.MatchString(line) && !reResJsonMethod.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "API response without explicit Content-Type header",
				Description:   "res.send/write without setting Content-Type lets the browser perform MIME sniffing. If the response contains user data, the browser may interpret it as HTML, enabling XSS.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Set Content-Type explicitly: res.set('Content-Type', 'application/json') or use res.json(). Add X-Content-Type-Options: nosniff header or use helmet middleware.",
				CWEID:         "CWE-16",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"content-type", "mime-sniffing", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-029: Node.js require() with user-controlled path
// ---------------------------------------------------------------------------

type RequireUserPath struct{}

func (r *RequireUserPath) ID() string                     { return "GTSS-JSTS-029" }
func (r *RequireUserPath) Name() string                   { return "RequireUserPath" }
func (r *RequireUserPath) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RequireUserPath) Description() string {
	return "Detects require() or dynamic import() with user-controlled paths, enabling arbitrary module loading and RCE."
}
func (r *RequireUserPath) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *RequireUserPath) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		if m := reRequireUserVar.FindString(line); m != "" {
			matched = m
		} else if m := reRequireConcat.FindString(line); m != "" {
			matched = m
		} else if m := reImportExprUser.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         "require()/import() with user-controlled path (arbitrary code execution)",
				Description:   "Passing user-controlled input to require() or dynamic import() allows loading and executing arbitrary Node.js modules. An attacker can load modules that execute system commands or access the filesystem.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user input to require() or import(). Use an allowlist of valid module names: const allowed = {'a': './a', 'b': './b'}; const mod = allowed[userInput]; if (!mod) throw new Error();",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"require", "import", "rce", "code-execution"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// JSTS-030: Insecure cookie settings (missing httpOnly/secure)
// ---------------------------------------------------------------------------

type InsecureCookieExt struct{}

func (r *InsecureCookieExt) ID() string                     { return "GTSS-JSTS-030" }
func (r *InsecureCookieExt) Name() string                   { return "InsecureCookieExt" }
func (r *InsecureCookieExt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureCookieExt) Description() string {
	return "Detects Set-Cookie headers for sensitive cookies without httpOnly/secure flags, or cookieParser without options."
}
func (r *InsecureCookieExt) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *InsecureCookieExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched string
		var title string
		if reSetCookieHeader.MatchString(line) && reCookieNoHttpOnly.MatchString(line) {
			if !strings.Contains(line, "HttpOnly") && !strings.Contains(line, "httponly") {
				matched = strings.TrimSpace(line)
				title = "Sensitive cookie set via Set-Cookie header without HttpOnly flag"
			}
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Sensitive cookies (session, token, auth) set via Set-Cookie header without HttpOnly flag are accessible to JavaScript via document.cookie. XSS attacks can steal these cookies for session hijacking.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add HttpOnly; Secure; SameSite=Strict flags to Set-Cookie headers. Use res.cookie() with { httpOnly: true, secure: true, sameSite: 'strict' } options.",
				CWEID:         "CWE-614",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"cookie", "httponly", "session"},
			})
		}
	}
	return findings
}
