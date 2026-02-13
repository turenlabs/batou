package jsts

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// GTSS-JSTS-001: postMessage without origin check
var (
	reMessageListener    = regexp.MustCompile(`addEventListener\s*\(\s*['"]message['"]`)
	reOriginCheck        = regexp.MustCompile(`(?:\.origin\s*[!=]==?\s*['"]|\.origin\s*[!=]==?\s*\w|checkOrigin|validateOrigin|allowedOrigin|trustedOrigin)`)
	reMessageData        = regexp.MustCompile(`(?:\.data\b|event\.data|e\.data|msg\.data)`)
)

// GTSS-JSTS-002: DOM clobbering risk
var (
	reDOMClobber = regexp.MustCompile(`(?:document\.getElementById|document\.getElementsByName|document\.querySelector)\s*\([^)]+\)\s*\.\s*(?:href|src|action|innerHTML|textContent|value)`)
	reFormAssign = regexp.MustCompile(`(?:document\.forms|document\.anchors|document\.images)\s*\[`)
)

// GTSS-JSTS-003: Regex DoS (ReDoS)
var (
	reNewRegExpVar    = regexp.MustCompile(`new\s+RegExp\s*\(\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|param|data|query|search|pattern|regex)`)
	reNewRegExpConcat = regexp.MustCompile("new\\s+RegExp\\s*\\(\\s*(?:[^\"'`\\s)]+\\s*\\+|`[^`]*\\$\\{)")
	reNewRegExpFmt    = regexp.MustCompile("new\\s+RegExp\\s*\\(\\s*`[^`]*\\$\\{")
)

// GTSS-JSTS-004: child_process.exec with template literal or concat (shell injection)
var (
	reExecTmplLit = regexp.MustCompile("(?:exec|execSync)\\s*\\(\\s*`[^`]*\\$\\{")
	reExecConcat  = regexp.MustCompile(`(?:exec|execSync)\s*\(\s*(?:['"][^'"]*['"]\s*\+\s*\w|\w+\s*\+\s*['"])`)
)

// GTSS-JSTS-005: eval/Function with template literal
var (
	reEvalTmplLit     = regexp.MustCompile("\\beval\\s*\\(\\s*`[^`]*\\$\\{")
	reFuncCtorTmplLit = regexp.MustCompile("\\bnew\\s+Function\\s*\\(\\s*`[^`]*\\$\\{")
)

// GTSS-JSTS-006: JWT verify without algorithm restriction
var (
	reJWTVerify       = regexp.MustCompile(`(?:jwt|jsonwebtoken)\s*\.\s*verify\s*\(`)
	reJWTAlgorithms   = regexp.MustCompile(`algorithms\s*:`)
	reJWTVerifyNoOpts = regexp.MustCompile(`(?:jwt|jsonwebtoken)\s*\.\s*verify\s*\(\s*[^,]+,\s*[^,]+\s*\)`)
)

// GTSS-JSTS-007: Insecure cookie (missing secure/httpOnly/sameSite)
var (
	reCookieSet        = regexp.MustCompile(`res\.cookie\s*\(\s*['"][^'"]+['"]\s*,`)
	reCookieSecure     = regexp.MustCompile(`secure\s*:\s*true`)
	reCookieHttpOnly   = regexp.MustCompile(`httpOnly\s*:\s*true`)
)

// GTSS-JSTS-008: Next.js getServerSideProps data exposure
var (
	reGetSSP           = regexp.MustCompile(`(?:export\s+(?:async\s+)?function\s+getServerSideProps|export\s+const\s+getServerSideProps)`)
	reSensitiveReturn  = regexp.MustCompile(`(?i)(?:password|secret|token|apiKey|api_key|privateKey|private_key|credential|ssn|creditCard|credit_card)\s*[,:=]`)
)

// GTSS-JSTS-009: React useEffect with unsanitized URL
var (
	reUseEffect        = regexp.MustCompile(`useEffect\s*\(`)
	reLocationInEffect = regexp.MustCompile(`(?:window\.location|document\.location|location\.href|location\.search|location\.hash|location\.pathname)`)
	reInnerHTMLInEffect = regexp.MustCompile(`\.innerHTML\s*=`)
)

// GTSS-JSTS-010: Node.js vm sandbox escape
var (
	reVMModule     = regexp.MustCompile(`(?:require\s*\(\s*['"](?:vm|vm2)['"]\s*\)|from\s+['"](?:vm|vm2)['"])`)
	reVMRunInCtx   = regexp.MustCompile(`\b(?:vm|VM)\s*\.\s*(?:runInNewContext|runInThisContext|createContext|Script|compileFunction)\s*\(`)
	reVM2Create    = regexp.MustCompile(`\bnew\s+(?:VM|NodeVM|VMScript)\s*\(`)
)

// GTSS-JSTS-011: path.join doesn't prevent traversal
var (
	rePathJoinInput = regexp.MustCompile(`path\s*\.\s*(?:join|resolve)\s*\([^)]*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|param|filename|filepath|file_?name|file_?path)`)
	rePathJoinNormalize = regexp.MustCompile(`path\s*\.\s*(?:join|resolve)\s*\([^)]*\.\.`)
)

// GTSS-JSTS-012: Handlebars SafeString XSS
var (
	reHandlebarsSafeString = regexp.MustCompile(`(?:Handlebars\.SafeString|new\s+(?:hbs|Handlebars)\.SafeString)\s*\(`)
)

// GTSS-JSTS-013: Electron nodeIntegration enabled
var (
	reElectronNodeIntegration       = regexp.MustCompile(`nodeIntegration\s*:\s*true`)
	reElectronContextIsolation      = regexp.MustCompile(`contextIsolation\s*:\s*false`)
	reElectronRemoteModule          = regexp.MustCompile(`enableRemoteModule\s*:\s*true`)
	reElectronWebSecurity           = regexp.MustCompile(`webSecurity\s*:\s*false`)
	reElectronBrowserWindow         = regexp.MustCompile(`(?:new\s+BrowserWindow|BrowserWindow\s*\()`)
)

// GTSS-JSTS-014: Unvalidated redirect (res.redirect with user input)
// NOTE: This complements the existing redirect/redirect.go rules by catching
// additional patterns specific to JS/TS like location.href assignment
var (
	reLocationAssignment = regexp.MustCompile(`(?:window\.)?location\s*(?:\.\s*href)?\s*=\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|url|redirect[Uu]rl|returnUrl|return_url|next|target|dest)`)
	reLocationReplace    = regexp.MustCompile(`(?:window\.)?location\s*\.\s*(?:replace|assign)\s*\(\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|url|redirect[Uu]rl|returnUrl|return_url|next|target|dest)`)
)

// GTSS-JSTS-015: Server-side template injection (pug/ejs compile)
var (
	reEjsRenderVar   = regexp.MustCompile(`ejs\s*\.\s*(?:render|compile)\s*\(\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|template|tmpl|body|content)`)
	rePugCompileVar  = regexp.MustCompile(`pug\s*\.\s*(?:compile|render|renderFile)\s*\(\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|template|tmpl|body|content)`)
	reNunjucksRender = regexp.MustCompile(`nunjucks\s*\.\s*renderString\s*\(\s*(?:req\.(?:query|params|body)|userInput|user[Ii]nput|input|template|tmpl|body|content)`)
)

// GTSS-JSTS-016: Insecure WebSocket (ws without origin validation)
var (
	reWSServer         = regexp.MustCompile(`new\s+(?:WebSocket\.Server|WebSocketServer|Server)\s*\(`)
	reWSOriginCheck    = regexp.MustCompile(`(?:verifyClient|origin|handleProtocols)`)
	reWSNoVerify       = regexp.MustCompile(`verifyClient\s*:\s*(?:false|null|undefined)`)
)

// GTSS-JSTS-017: crypto.createCipher (deprecated, use createCipheriv)
var (
	reCreateCipher = regexp.MustCompile(`crypto\s*\.\s*createCipher\s*\(`)
	reCreateCipherIv = regexp.MustCompile(`crypto\s*\.\s*createCipheriv\s*\(`)
)

// GTSS-JSTS-018: fs.chmod/chown with permissive modes
var (
	reFsChmod777    = regexp.MustCompile(`fs\s*\.\s*(?:chmod|chmodSync|fchmod|fchmodSync)\s*\([^,]+,\s*(?:0o?777|0o?766|0o?776|511|438)\b`)
	reFsChmodWorld  = regexp.MustCompile(`fs\s*\.\s*(?:chmod|chmodSync|fchmod|fchmodSync)\s*\([^,]+,\s*0o?7[67][67]\b`)
	reFsWriteWorld  = regexp.MustCompile(`fs\s*\.\s*(?:writeFile|writeFileSync)\s*\([^)]+mode\s*:\s*(?:0o?777|0o?766|0o?776|511)`)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "//") ||
		strings.HasPrefix(t, "#") ||
		strings.HasPrefix(t, "*") ||
		strings.HasPrefix(t, "/*") ||
		strings.HasPrefix(t, "<!--")
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func isJSOrTS(lang rules.Language) bool {
	return lang == rules.LangJavaScript || lang == rules.LangTypeScript
}

func hasNearbyMatch(lines []string, idx int, pattern *regexp.Regexp, window int) bool {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if pattern.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-001: postMessage without origin check
// ---------------------------------------------------------------------------

type PostMessageNoOrigin struct{}

func (r *PostMessageNoOrigin) ID() string                     { return "GTSS-JSTS-001" }
func (r *PostMessageNoOrigin) Name() string                   { return "PostMessageNoOrigin" }
func (r *PostMessageNoOrigin) DefaultSeverity() rules.Severity { return rules.High }
func (r *PostMessageNoOrigin) Description() string {
	return "Detects window.addEventListener('message') handlers that process event.data without validating event.origin, enabling cross-origin message attacks."
}
func (r *PostMessageNoOrigin) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *PostMessageNoOrigin) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reMessageListener.MatchString(line) {
			continue
		}

		// Look ahead for origin check within the handler (30 lines)
		end := i + 30
		if end > len(lines) {
			end = len(lines)
		}
		handlerBlock := strings.Join(lines[i:end], "\n")

		hasOriginCheck := reOriginCheck.MatchString(handlerBlock)
		hasDataUsage := reMessageData.MatchString(handlerBlock)

		if !hasOriginCheck && hasDataUsage {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "postMessage handler without origin validation",
				Description:   "This message event listener processes event.data without checking event.origin. Any website can send postMessage to this window, potentially injecting malicious data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Always validate event.origin against a trusted list before processing event.data: if (event.origin !== 'https://trusted.com') return;",
				CWEID:         "CWE-346",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"postmessage", "origin-validation", "cross-origin"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-002: DOM clobbering risk
// ---------------------------------------------------------------------------

type DOMClobberingRisk struct{}

func (r *DOMClobberingRisk) ID() string                     { return "GTSS-JSTS-002" }
func (r *DOMClobberingRisk) Name() string                   { return "DOMClobberingRisk" }
func (r *DOMClobberingRisk) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DOMClobberingRisk) Description() string {
	return "Detects patterns where DOM element properties (href, src, innerHTML) are accessed directly after getElementById/querySelector, which may be vulnerable to DOM clobbering attacks."
}
func (r *DOMClobberingRisk) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DOMClobberingRisk) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		if m := reDOMClobber.FindString(line); m != "" {
			matched = m
		} else if m := reFormAssign.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "DOM element property access vulnerable to DOM clobbering",
				Description:   "Accessing properties like href, src, or innerHTML directly from DOM elements obtained via getElementById/querySelector can be exploited via DOM clobbering if an attacker can inject HTML with matching id/name attributes.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use instanceof checks before accessing DOM element properties. Verify the element type is what you expect: if (el instanceof HTMLAnchorElement) { ... }. Use DOMPurify to sanitize any user-controlled HTML.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"dom-clobbering", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-003: Regular Expression DoS (ReDoS)
// ---------------------------------------------------------------------------

type RegexDoS struct{}

func (r *RegexDoS) ID() string                     { return "GTSS-JSTS-003" }
func (r *RegexDoS) Name() string                   { return "RegexDoS" }
func (r *RegexDoS) DefaultSeverity() rules.Severity { return rules.High }
func (r *RegexDoS) Description() string {
	return "Detects new RegExp() constructed with user input, which can cause catastrophic backtracking (ReDoS) denial of service."
}
func (r *RegexDoS) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *RegexDoS) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		var confidence string

		if m := reNewRegExpVar.FindString(line); m != "" {
			matched = m
			confidence = "high"
		} else if m := reNewRegExpConcat.FindString(line); m != "" {
			matched = m
			confidence = "medium"
		} else if m := reNewRegExpFmt.FindString(line); m != "" {
			matched = m
			confidence = "medium"
		}

		if matched != "" {
			// Skip if there's escaping nearby
			if strings.Contains(line, "escapeRegExp") || strings.Contains(line, "escape_regex") ||
				strings.Contains(line, "escapeRegex") || strings.Contains(line, "lodash.escapeRegExp") ||
				strings.Contains(line, "_.escapeRegExp") {
				continue
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Regular Expression DoS (ReDoS): user input in RegExp constructor",
				Description:   "Constructing regular expressions from user input can allow an attacker to craft patterns that cause catastrophic backtracking, leading to denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Escape user input before passing to RegExp: new RegExp(escapeRegExp(input)). Or use a safe regex library like re2. Consider using string methods (indexOf, includes) instead of regex.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"redos", "regex", "denial-of-service"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-004: child_process.exec with shell injection
// ---------------------------------------------------------------------------

type ExecShellInjection struct{}

func (r *ExecShellInjection) ID() string                     { return "GTSS-JSTS-004" }
func (r *ExecShellInjection) Name() string                   { return "ExecShellInjection" }
func (r *ExecShellInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ExecShellInjection) Description() string {
	return "Detects child_process.exec/execSync with template literals or string concatenation, indicating shell command injection risk."
}
func (r *ExecShellInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExecShellInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		if m := reExecTmplLit.FindString(line); m != "" {
			matched = m
		} else if m := reExecConcat.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Shell injection: exec/execSync with dynamic command string",
				Description:   "child_process.exec() runs commands through a shell, making string interpolation or concatenation a command injection vector. An attacker can inject shell metacharacters (; | && etc.) to run arbitrary commands.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use child_process.execFile() or spawn() with an array of arguments instead of exec(). These bypass the shell and prevent injection. If exec is required, use shell-escape or shell-quote to sanitize inputs.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"injection", "command", "shell", "child-process"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-005: eval/Function constructor with template literal
// ---------------------------------------------------------------------------

type EvalTemplateLiteral struct{}

func (r *EvalTemplateLiteral) ID() string                     { return "GTSS-JSTS-005" }
func (r *EvalTemplateLiteral) Name() string                   { return "EvalTemplateLiteral" }
func (r *EvalTemplateLiteral) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *EvalTemplateLiteral) Description() string {
	return "Detects eval() or new Function() with template literals containing interpolated values, enabling code injection."
}
func (r *EvalTemplateLiteral) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *EvalTemplateLiteral) Scan(ctx *rules.ScanContext) []rules.Finding {
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

		if m := reEvalTmplLit.FindString(line); m != "" {
			matched = m
			title = "eval() with template literal interpolation"
		} else if m := reFuncCtorTmplLit.FindString(line); m != "" {
			matched = m
			title = "new Function() with template literal interpolation"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "Using eval() or new Function() with template literals containing interpolated values allows arbitrary code execution. If any interpolated value is user-controlled, this is a critical code injection vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never use eval() or new Function() with user-controlled data. Use JSON.parse() for data, or redesign to avoid dynamic code execution entirely.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"injection", "eval", "code-execution", "template-literal"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-006: JWT verify without algorithms option
// ---------------------------------------------------------------------------

type JWTVerifyNoAlgorithm struct{}

func (r *JWTVerifyNoAlgorithm) ID() string                     { return "GTSS-JSTS-006" }
func (r *JWTVerifyNoAlgorithm) Name() string                   { return "JWTVerifyNoAlgorithm" }
func (r *JWTVerifyNoAlgorithm) DefaultSeverity() rules.Severity { return rules.High }
func (r *JWTVerifyNoAlgorithm) Description() string {
	return "Detects jsonwebtoken.verify() calls without the algorithms option, which allows algorithm confusion attacks (e.g., switching RS256 to HS256)."
}
func (r *JWTVerifyNoAlgorithm) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *JWTVerifyNoAlgorithm) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}

	// Only scan files that import/require jsonwebtoken or use jwt
	if !strings.Contains(ctx.Content, "jsonwebtoken") && !strings.Contains(ctx.Content, "jwt.verify") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reJWTVerify.MatchString(line) {
			continue
		}

		// Check if algorithms option is specified in this line or next few lines
		end := i + 5
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		if !reJWTAlgorithms.MatchString(block) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "JWT verify without algorithms restriction",
				Description:   "jwt.verify() is called without specifying the algorithms option. This allows algorithm confusion attacks where an attacker changes the JWT header to use HS256 with the public key as the secret, bypassing signature verification.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Always specify the algorithms option: jwt.verify(token, secret, { algorithms: ['RS256'] }). Never allow the JWT header to dictate the algorithm.",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"jwt", "algorithm-confusion", "authentication"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-007: Insecure cookie settings (res.cookie without secure flags)
// ---------------------------------------------------------------------------

type InsecureCookie struct{}

func (r *InsecureCookie) ID() string                     { return "GTSS-JSTS-007" }
func (r *InsecureCookie) Name() string                   { return "InsecureCookie" }
func (r *InsecureCookie) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureCookie) Description() string {
	return "Detects res.cookie() calls without secure/httpOnly flags, making cookies vulnerable to interception and XSS-based theft."
}
func (r *InsecureCookie) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *InsecureCookie) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reCookieSet.MatchString(line) {
			continue
		}

		// Look ahead for cookie options
		end := i + 10
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		hasSecure := reCookieSecure.MatchString(block)
		hasHttpOnly := reCookieHttpOnly.MatchString(block)

		if !hasSecure || !hasHttpOnly {
			var title string
			if !hasSecure && !hasHttpOnly {
				title = "Cookie set without secure and httpOnly flags"
			} else if !hasSecure {
				title = "Cookie set without secure flag"
			} else {
				title = "Cookie set without httpOnly flag"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "res.cookie() is called without proper security flags. Without secure:true, the cookie can be sent over HTTP. Without httpOnly:true, JavaScript can access it via document.cookie, enabling XSS-based session theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Set security flags: res.cookie('name', 'value', { secure: true, httpOnly: true, sameSite: 'strict' }).",
				CWEID:         "CWE-614",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"cookie", "security-flags", "session"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-008: Next.js getServerSideProps data exposure
// ---------------------------------------------------------------------------

type NextJSDataExposure struct{}

func (r *NextJSDataExposure) ID() string                     { return "GTSS-JSTS-008" }
func (r *NextJSDataExposure) Name() string                   { return "NextJSDataExposure" }
func (r *NextJSDataExposure) DefaultSeverity() rules.Severity { return rules.High }
func (r *NextJSDataExposure) Description() string {
	return "Detects Next.js getServerSideProps returning potentially sensitive data (passwords, secrets, API keys) to the client."
}
func (r *NextJSDataExposure) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSDataExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	if !reGetSSP.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inSSP := false
	braceDepth := 0

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		if reGetSSP.MatchString(line) {
			inSSP = true
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inSSP {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if reSensitiveReturn.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Next.js getServerSideProps returns sensitive data to client",
					Description:   "getServerSideProps props are serialized and sent to the browser as JSON in the page source. Sensitive data like passwords, secrets, or API keys returned here are exposed to all users.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Only return data the client needs to render the page. Filter out sensitive fields before returning props. Use server-side API routes for sensitive operations.",
					CWEID:         "CWE-200",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"nextjs", "data-exposure", "ssr"},
				})
			}

			if braceDepth <= 0 {
				inSSP = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-009: React useEffect with unsanitized URL manipulation
// ---------------------------------------------------------------------------

type UseEffectURLManipulation struct{}

func (r *UseEffectURLManipulation) ID() string                     { return "GTSS-JSTS-009" }
func (r *UseEffectURLManipulation) Name() string                   { return "UseEffectURLManipulation" }
func (r *UseEffectURLManipulation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UseEffectURLManipulation) Description() string {
	return "Detects React useEffect reading window.location and writing to innerHTML, creating a DOM XSS sink."
}
func (r *UseEffectURLManipulation) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *UseEffectURLManipulation) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	if !reUseEffect.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reUseEffect.MatchString(line) {
			continue
		}

		// Look for window.location usage and innerHTML assignment in the effect
		end := i + 30
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		hasLocation := reLocationInEffect.MatchString(block)
		hasInnerHTML := reInnerHTMLInEffect.MatchString(block)

		if hasLocation && hasInnerHTML {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "useEffect reads URL and writes to innerHTML (DOM XSS)",
				Description:   "A React useEffect hook reads from window.location and writes to innerHTML. URL parameters are attacker-controlled, and innerHTML executes HTML/scripts, creating a DOM-based XSS vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use textContent instead of innerHTML to insert URL-derived data. If HTML rendering is needed, sanitize with DOMPurify. Consider using React state and JSX rendering instead of direct DOM manipulation.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"react", "useEffect", "dom-xss", "url-manipulation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-010: Node.js vm/vm2 sandbox escape
// ---------------------------------------------------------------------------

type VMSandboxEscape struct{}

func (r *VMSandboxEscape) ID() string                     { return "GTSS-JSTS-010" }
func (r *VMSandboxEscape) Name() string                   { return "VMSandboxEscape" }
func (r *VMSandboxEscape) DefaultSeverity() rules.Severity { return rules.High }
func (r *VMSandboxEscape) Description() string {
	return "Detects use of Node.js vm or vm2 modules for sandboxing. The vm module is not a security mechanism, and vm2 has known sandbox escape CVEs."
}
func (r *VMSandboxEscape) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *VMSandboxEscape) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	if !reVMModule.MatchString(ctx.Content) {
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

		if m := reVMRunInCtx.FindString(line); m != "" {
			matched = m
			title = "Node.js vm module used for sandboxing (not a security mechanism)"
		} else if m := reVM2Create.FindString(line); m != "" {
			matched = m
			title = "vm2 sandbox used (multiple known escape CVEs)"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "The Node.js vm module is explicitly documented as 'not a security mechanism' and can be trivially escaped. vm2 has multiple CVEs allowing sandbox escape (CVE-2023-37466, CVE-2023-37903). Neither should be used to run untrusted code.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use isolated-vm for sandboxing, or run untrusted code in separate processes with OS-level isolation (Docker containers, Web Workers). Never rely on vm/vm2 for security boundaries.",
				CWEID:         "CWE-265",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"vm", "sandbox-escape", "code-execution"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-011: path.join doesn't prevent traversal
// ---------------------------------------------------------------------------

type PathJoinTraversal struct{}

func (r *PathJoinTraversal) ID() string                     { return "GTSS-JSTS-011" }
func (r *PathJoinTraversal) Name() string                   { return "PathJoinTraversal" }
func (r *PathJoinTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *PathJoinTraversal) Description() string {
	return "Detects path.join/path.resolve with user input. path.join does NOT prevent directory traversal - path.join('/uploads', '../../../etc/passwd') resolves to /etc/passwd."
}
func (r *PathJoinTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *PathJoinTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		if m := rePathJoinInput.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			// Skip if there's a traversal check nearby
			if hasTraversalCheck(lines, i) {
				continue
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "path.join/resolve with user input does not prevent traversal",
				Description:   "path.join() and path.resolve() do NOT prevent directory traversal attacks. path.join('/uploads', '../../../etc/passwd') resolves to '/etc/passwd'. User input must be validated separately.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "After path.join(), verify the result starts with the intended base directory: const resolved = path.resolve(base, userInput); if (!resolved.startsWith(path.resolve(base))) throw new Error('Path traversal');",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"path-traversal", "directory-traversal", "lfi"},
			})
		}
	}
	return findings
}

func hasTraversalCheck(lines []string, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "startswith") || strings.Contains(lower, "startsWith") ||
			strings.Contains(lower, "normalize") || strings.Contains(lower, "sanitize") ||
			strings.Contains(lower, "..") && (strings.Contains(lower, "includes") || strings.Contains(lower, "indexof") || strings.Contains(lower, "reject") || strings.Contains(lower, "throw")) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-012: Handlebars SafeString XSS
// ---------------------------------------------------------------------------

type HandlebarsSafeStringXSS struct{}

func (r *HandlebarsSafeStringXSS) ID() string                     { return "GTSS-JSTS-012" }
func (r *HandlebarsSafeStringXSS) Name() string                   { return "HandlebarsSafeStringXSS" }
func (r *HandlebarsSafeStringXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *HandlebarsSafeStringXSS) Description() string {
	return "Detects Handlebars.SafeString which bypasses auto-escaping. If user input is wrapped in SafeString, it creates an XSS vulnerability."
}
func (r *HandlebarsSafeStringXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *HandlebarsSafeStringXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := reHandlebarsSafeString.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Handlebars SafeString bypasses auto-escaping",
				Description:   "Handlebars.SafeString marks content as safe HTML, bypassing Handlebars auto-escaping. If the content includes any user input, this creates an XSS vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Avoid SafeString with user input. Use Handlebars.escapeExpression() to manually escape user content before wrapping in SafeString, or use regular double-brace {{ }} output.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"xss", "handlebars", "template-escaping"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-013: Electron nodeIntegration / contextIsolation misconfiguration
// ---------------------------------------------------------------------------

type ElectronInsecureConfig struct{}

func (r *ElectronInsecureConfig) ID() string                     { return "GTSS-JSTS-013" }
func (r *ElectronInsecureConfig) Name() string                   { return "ElectronInsecureConfig" }
func (r *ElectronInsecureConfig) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ElectronInsecureConfig) Description() string {
	return "Detects insecure Electron BrowserWindow configuration: nodeIntegration enabled, contextIsolation disabled, or webSecurity disabled."
}
func (r *ElectronInsecureConfig) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ElectronInsecureConfig) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	// Only scan files that reference BrowserWindow or electron
	if !strings.Contains(ctx.Content, "BrowserWindow") && !strings.Contains(ctx.Content, "electron") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		type check struct {
			re    *regexp.Regexp
			title string
			desc  string
		}

		checks := []check{
			{reElectronNodeIntegration, "Electron nodeIntegration enabled",
				"nodeIntegration: true gives the renderer process full access to Node.js APIs. If the renderer loads any remote or untrusted content, this allows remote code execution."},
			{reElectronContextIsolation, "Electron contextIsolation disabled",
				"contextIsolation: false allows preload scripts and web page scripts to share the same context. This can expose Node.js APIs to web content, enabling RCE if any XSS exists."},
			{reElectronWebSecurity, "Electron webSecurity disabled",
				"webSecurity: false disables same-origin policy in the renderer. This allows any loaded content to make cross-origin requests and access local files."},
			{reElectronRemoteModule, "Electron remote module enabled",
				"enableRemoteModule: true exposes main process modules to the renderer. This is deprecated and increases the attack surface for RCE via the renderer."},
		}

		for _, c := range checks {
			if c.re.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         c.title,
					Description:   c.desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Use secure defaults: nodeIntegration: false, contextIsolation: true, webSecurity: true. Use a preload script with contextBridge.exposeInMainWorld() for IPC.",
					CWEID:         "CWE-269",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"electron", "node-integration", "rce", "misconfiguration"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-014: Unvalidated redirect via location assignment
// ---------------------------------------------------------------------------

type LocationRedirectUserInput struct{}

func (r *LocationRedirectUserInput) ID() string                     { return "GTSS-JSTS-014" }
func (r *LocationRedirectUserInput) Name() string                   { return "LocationRedirectUserInput" }
func (r *LocationRedirectUserInput) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LocationRedirectUserInput) Description() string {
	return "Detects client-side redirect via location.href/replace/assign with user-controlled variables, enabling open redirect or javascript: XSS."
}
func (r *LocationRedirectUserInput) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *LocationRedirectUserInput) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		if m := reLocationAssignment.FindString(line); m != "" {
			matched = m
		} else if m := reLocationReplace.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Client-side redirect with user-controlled URL",
				Description:   "Setting window.location to a user-controlled value enables open redirect attacks (phishing) and javascript: protocol XSS. An attacker can craft URLs that redirect users to malicious sites.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate the redirect URL scheme (allow only http/https). Parse with new URL() and compare the hostname against an allowlist. Never allow javascript: or data: URLs.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"redirect", "open-redirect", "client-side"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-015: Server-side template injection (EJS/Pug/Nunjucks)
// ---------------------------------------------------------------------------

type SSTITemplateEngine struct{}

func (r *SSTITemplateEngine) ID() string                     { return "GTSS-JSTS-015" }
func (r *SSTITemplateEngine) Name() string                   { return "SSTITemplateEngine" }
func (r *SSTITemplateEngine) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SSTITemplateEngine) Description() string {
	return "Detects EJS/Pug/Nunjucks render/compile with user input as template source, enabling server-side template injection and RCE."
}
func (r *SSTITemplateEngine) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *SSTITemplateEngine) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		var engine string

		if m := reEjsRenderVar.FindString(line); m != "" {
			matched = m
			engine = "EJS"
		} else if m := rePugCompileVar.FindString(line); m != "" {
			matched = m
			engine = "Pug"
		} else if m := reNunjucksRender.FindString(line); m != "" {
			matched = m
			engine = "Nunjucks"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         engine + " template engine render/compile with user input as template source",
				Description:   "User input is passed as the template source to " + engine + " render/compile. An attacker can inject template directives to execute arbitrary code on the server (SSTI -> RCE).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user input as the template source. Use render with a file path and pass user data as template variables: res.render('template', { userValue: input }).",
				CWEID:         "CWE-1336",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ssti", "template-injection", "rce", strings.ToLower(engine)},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-016: Insecure WebSocket (no origin validation)
// ---------------------------------------------------------------------------

type InsecureWebSocket struct{}

func (r *InsecureWebSocket) ID() string                     { return "GTSS-JSTS-016" }
func (r *InsecureWebSocket) Name() string                   { return "InsecureWebSocket" }
func (r *InsecureWebSocket) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureWebSocket) Description() string {
	return "Detects WebSocket.Server creation without verifyClient origin validation, or with verifyClient explicitly disabled."
}
func (r *InsecureWebSocket) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *InsecureWebSocket) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	// Only check files that use ws/WebSocket
	if !strings.Contains(ctx.Content, "WebSocket") && !strings.Contains(ctx.Content, "ws") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}

		// Check for explicit verifyClient: false
		if reWSNoVerify.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "WebSocket server with verifyClient disabled",
				Description:   "The WebSocket server explicitly disables client verification. Without origin validation, any website can establish a WebSocket connection, enabling cross-site WebSocket hijacking (CSWSH).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Implement verifyClient to check the origin header: verifyClient: (info) => allowedOrigins.includes(info.origin). Also use authentication tokens.",
				CWEID:         "CWE-346",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"websocket", "origin-validation", "cswsh"},
			})
			continue
		}

		// Check for WebSocket.Server without verifyClient
		if reWSServer.MatchString(line) && strings.Contains(line, "ws") {
			end := i + 15
			if end > len(lines) {
				end = len(lines)
			}
			block := strings.Join(lines[i:end], "\n")
			if !reWSOriginCheck.MatchString(block) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "WebSocket server without origin validation",
					Description:   "The WebSocket server does not implement verifyClient or origin checking. Without origin validation, any website can establish a WebSocket connection on behalf of authenticated users (CSWSH).",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Add verifyClient to validate the origin header against trusted domains. Also require authentication tokens in the WebSocket handshake.",
					CWEID:         "CWE-346",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"websocket", "origin-validation", "cswsh"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-017: crypto.createCipher (deprecated)
// ---------------------------------------------------------------------------

type DeprecatedCreateCipher struct{}

func (r *DeprecatedCreateCipher) ID() string                     { return "GTSS-JSTS-017" }
func (r *DeprecatedCreateCipher) Name() string                   { return "DeprecatedCreateCipher" }
func (r *DeprecatedCreateCipher) DefaultSeverity() rules.Severity { return rules.High }
func (r *DeprecatedCreateCipher) Description() string {
	return "Detects crypto.createCipher() which is deprecated and derives the IV from the password using MD5, making it vulnerable. Use crypto.createCipheriv() instead."
}
func (r *DeprecatedCreateCipher) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DeprecatedCreateCipher) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if m := reCreateCipher.FindString(line); m != "" {
			// Exclude createCipheriv (the safe variant)
			if reCreateCipherIv.MatchString(line) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "crypto.createCipher() is deprecated and insecure",
				Description:   "crypto.createCipher() derives the key and IV from the password using MD5 without a salt, making it vulnerable to dictionary attacks and producing identical ciphertext for identical plaintext+password combinations.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use crypto.createCipheriv() with an explicit IV: const iv = crypto.randomBytes(16); const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"crypto", "deprecated", "weak-cipher"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-JSTS-018: fs.chmod/chown with permissive modes
// ---------------------------------------------------------------------------

type FsPermissiveModes struct{}

func (r *FsPermissiveModes) ID() string                     { return "GTSS-JSTS-018" }
func (r *FsPermissiveModes) Name() string                   { return "FsPermissiveModes" }
func (r *FsPermissiveModes) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FsPermissiveModes) Description() string {
	return "Detects fs.chmod/writeFile with world-readable/writable permissions (0o777, 0o766, etc.) which can expose sensitive files."
}
func (r *FsPermissiveModes) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *FsPermissiveModes) Scan(ctx *rules.ScanContext) []rules.Finding {
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
		if m := reFsChmod777.FindString(line); m != "" {
			matched = m
		} else if m := reFsChmodWorld.FindString(line); m != "" {
			matched = m
		} else if m := reFsWriteWorld.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "File created/modified with world-writable permissions",
				Description:   "Setting file permissions to 0o777 or similar world-writable modes allows any user on the system to read, write, and execute the file. This can lead to data exposure or code injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use restrictive permissions: 0o600 (owner read/write) for sensitive files, 0o644 (owner write, others read) for public files. Never use 0o777.",
				CWEID:         "CWE-732",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"filesystem", "permissions", "chmod"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&PostMessageNoOrigin{})
	rules.Register(&DOMClobberingRisk{})
	rules.Register(&RegexDoS{})
	rules.Register(&ExecShellInjection{})
	rules.Register(&EvalTemplateLiteral{})
	rules.Register(&JWTVerifyNoAlgorithm{})
	rules.Register(&InsecureCookie{})
	rules.Register(&NextJSDataExposure{})
	rules.Register(&UseEffectURLManipulation{})
	rules.Register(&VMSandboxEscape{})
	rules.Register(&PathJoinTraversal{})
	rules.Register(&HandlebarsSafeStringXSS{})
	rules.Register(&ElectronInsecureConfig{})
	rules.Register(&LocationRedirectUserInput{})
	rules.Register(&SSTITemplateEngine{})
	rules.Register(&InsecureWebSocket{})
	rules.Register(&DeprecatedCreateCipher{})
	rules.Register(&FsPermissiveModes{})
}
