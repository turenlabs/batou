package xss

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// Compiled regex patterns for XSS detection.
var (
	// BATOU-XSS-001: innerHTML/outerHTML assignment with dynamic content
	reInnerHTMLAssign = regexp.MustCompile(`\.\s*(innerHTML|outerHTML)\s*=\s*(.+)`)
	reStaticString    = regexp.MustCompile(`^\s*["'` + "`" + `][^"'` + "`" + `]*["'` + "`" + `]\s*;?\s*$`)
	// insertAdjacentHTML — functionally equivalent to innerHTML
	reInsertAdjacentHTML = regexp.MustCompile(`\.insertAdjacentHTML\s*\(\s*["'][^"']*["']\s*,`)
	// jQuery .html() with argument — equivalent to innerHTML
	reJQueryHTML = regexp.MustCompile(`\.\s*html\s*\(\s*[^)]`)
	// createContextualFragment — parses HTML from string
	reContextualFragment = regexp.MustCompile(`\.createContextualFragment\s*\(`)

	// BATOU-XSS-002: React dangerouslySetInnerHTML
	reDangerouslySet = regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{\s*\{`)

	// BATOU-XSS-003: document.write / document.writeln
	reDocWrite      = regexp.MustCompile(`document\s*\.\s*(write|writeln)\s*\((.+)\)`)
	reDocWriteStatic = regexp.MustCompile(`document\s*\.\s*(write|writeln)\s*\(\s*["'` + "`" + `]`)

	// BATOU-XSS-004: Unescaped template output
	reGoTemplateHTML   = regexp.MustCompile(`template\.HTML\s*\(`)
	reJinjaSafe        = regexp.MustCompile(`\|\s*safe\b`)
	reJinjaAutoescOff  = regexp.MustCompile(`\{%[-\s]*autoescape\s+(false|off)\s*[-\s]*%\}`)
	reERBUnescaped     = regexp.MustCompile(`<%==?\s+`)
	reERBRaw           = regexp.MustCompile(`\braw\s*\(`)
	reHandlebarTriple  = regexp.MustCompile(`\{\{\{.+?\}\}\}`)
	rePHPEcho          = regexp.MustCompile(`<\?(?:php)?\s+echo\s+\$`)
	rePHPEchoSafe      = regexp.MustCompile(`htmlspecialchars\s*\(|htmlentities\s*\(|strip_tags\s*\(`)

	// BATOU-XSS-005: Risky DOM manipulation
	reEvalCall         = regexp.MustCompile(`\beval\s*\(`)
	reLocationAssign   = regexp.MustCompile(`(?:location\.href|location\.assign|location\.replace)\s*=\s*(.+)`)
	reWindowOpen       = regexp.MustCompile(`window\.open\s*\(`)
	reSetAttrDangerous = regexp.MustCompile(`setAttribute\s*\(\s*["'](href|src|action|on\w+)["']\s*,`)

	// BATOU-XSS-006: Response header injection
	reNodeSetHeader  = regexp.MustCompile(`(?:res|response)\.setHeader\s*\(\s*["'][\w-]+["']\s*,\s*(.+)\)`)
	reGoHeaderSet    = regexp.MustCompile(`\.Header\(\)\s*\.Set\s*\(\s*["'][\w-]+["']\s*,\s*(.+)\)`)
	reHeaderFromReq  = regexp.MustCompile(`\.Header\(\)\s*\.Set\s*\(.+(?:req\.|request\.|r\.|params|query|body)`)
	reNodeHeaderReq  = regexp.MustCompile(`\.setHeader\s*\(.+(?:req\.|request\.|params|query|body)`)

	// BATOU-XSS-007: URL scheme injection (javascript: protocol)
	reJSProtocolHref = regexp.MustCompile(`(?:href|src|action)\s*=\s*["']javascript:`)
	reHrefDynamic    = regexp.MustCompile(`(?:href|src|action)\s*=\s*\{[^}]*\}`)
	reJSProtocolVar  = regexp.MustCompile(`["']javascript:["']\s*\+`)

	// BATOU-XSS-008: Server-side rendering without escaping (cross-language)
	rePyMarkup       = regexp.MustCompile(`\bMarkup\s*\(`)
	rePyMarkupFmt    = regexp.MustCompile(`\bMarkup\.format\s*\(`)
	rePyMarkSafe     = regexp.MustCompile(`\bmark_safe\s*\(`)
	reJSPUnescaped   = regexp.MustCompile(`<%=\s*request\.getParameter\s*\(`)
	reJavaHTMLConcat = regexp.MustCompile(`(?:out\.print(?:ln)?|writer\.write|writer\.println)\s*\(\s*["']<[^"']*["']\s*\+`)
	reGoFprintfHTML  = regexp.MustCompile(`fmt\.Fprintf\s*\(\s*w\s*,\s*["'].*<[^"']*%`)
	reRubyHTMLSafe   = regexp.MustCompile(`\.html_safe\b`)
	reCSharpHtmlRaw  = regexp.MustCompile(`@?Html\.Raw\s*\(`)

	// BATOU-XSS-009: Missing Content-Type on HTML response
	reGoWriteHTML      = regexp.MustCompile(`w\.Write\s*\(\s*\[\]byte\s*\(\s*["']<`)
	reGoFprintfHTMLTag = regexp.MustCompile(`fmt\.Fprint(?:f|ln)?\s*\(\s*w\s*,\s*["']<(?:html|head|body|div|span|p|h[1-6]|script|table|form|a\s)`)

	// BATOU-XSS-010: JSON response with user data and wrong content type
	reNodeResSend     = regexp.MustCompile(`res\.(?:send|end|write)\s*\(`)
	reNodeResJSON     = regexp.MustCompile(`res\.json\s*\(`)
	reNodeContentJSON = regexp.MustCompile(`(?:Content-Type|content-type).*application/json`)

	// BATOU-XSS-013: Python f-string HTML building without escaping
	rePyFStringHTML = regexp.MustCompile(`(?:html|response|output|body|page|content|markup|template_str)\s*(?:\+?=|=)\s*f["'].*<.*\{`)
	rePyFormatHTML  = regexp.MustCompile(`(?:html|response|output|body|page|content|markup|template_str)\s*(?:\+?=|=)\s*["'].*<.*["']\s*\.format\s*\(`)
	rePyPctHTML     = regexp.MustCompile(`(?:html|response|output|body|page|content|markup|template_str)\s*(?:\+?=|=)\s*["'].*<.*%s`)
	rePyEscape      = regexp.MustCompile(`(?:escape|html\.escape|markupsafe\.escape|cgi\.escape|bleach\.clean)\s*\(`)

	// BATOU-XSS-011: Reflected XSS patterns
	rePyReflected      = regexp.MustCompile(`(?:return|response)\s*.*(?:request\.args\.get|request\.form\.get|request\.values\.get|request\.args\[)`)
	rePyFStringReq     = regexp.MustCompile(`f["'].*\{request\.(?:args|form|values)`)
	rePHPEchoGet       = regexp.MustCompile(`echo\s+\$_(?:GET|POST|REQUEST)\s*\[`)
	reGoReflected      = regexp.MustCompile(`fmt\.Fprintf\s*\(\s*w\s*,.*r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue)\s*\(`)
	reGoFprintfReqBody = regexp.MustCompile(`fmt\.Fprintf\s*\(\s*w\s*,.*(?:r\.Body|r\.Form|r\.URL\.Query)`)
	reJavaReflected    = regexp.MustCompile(`(?:out\.print(?:ln)?|writer\.(?:write|println))\s*\(.*request\.getParameter\s*\(`)
	reRubyReflected    = regexp.MustCompile(`render\s+(?:html|inline|text)\s*:.*params\s*\[`)
	// JS/TS: res.send with template literal containing user input (reflected XSS)
	reJSResSendHTML    = regexp.MustCompile(`res\.send\s*\(`)
	// Indicators of user input in nearby lines for JS/TS
	reJSReqInput       = regexp.MustCompile(`req\.(?:query|params|body)\b`)

	// PHP: echo with variable concatenation (. $var) or interpolation ("...$var...")
	rePHPEchoVarConcat = regexp.MustCompile(`(?i)\becho\s+["'].*\.\s*\$\w+`)
	rePHPEchoVarInterp = regexp.MustCompile(`(?i)\becho\s+"[^"]*\$\w+`)
	// PHP superglobal usage nearby (indicates user input)
	rePHPSuperglobal   = regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`)

	// BATOU-XSS-014: Java HTML string concatenation with user input
	// StringBuilder/StringBuffer.append with HTML tags and variables
	reJavaStringBuilderHTML = regexp.MustCompile(`(?:StringBuilder|StringBuffer)\s*(?:\(\s*\))?[^;]*\.append\s*\(\s*["']<[^"']*["']\s*\+`)
	reJavaStringBuilderAppendConcat = regexp.MustCompile(`\.append\s*\(\s*["']<[^"']*["']\s*\+`)
	// String concatenation with HTML tags: "<tag>" + variable
	reJavaHTMLStringConcat = regexp.MustCompile(`["']<\s*(?:div|span|p|h[1-6]|br|td|tr|table|li|ul|ol|a|form|input|img|script|body|html|head|title|meta|link|b|i|u|strong|em|label|button|select|option|textarea|section|article|header|footer|nav|main)[^"']*>?\s*["']\s*\+`)
	// Variable + "</tag>" pattern
	reJavaHTMLCloseConcat = regexp.MustCompile(`\+\s*["']\s*<\s*/\s*(?:div|span|p|h[1-6]|br|td|tr|table|li|ul|ol|a|form|input|img|script|body|html|head|title)[^"']*>\s*["']`)
	// General pattern: "...<tag>..." + var or var + "...</tag>..."
	reJavaHTMLConcatGeneral = regexp.MustCompile(`["'][^"']*<[^"'>]+>[^"']*["']\s*\+\s*[a-zA-Z_]\w*`)
	// Java encoder/escaper methods (safe patterns)
	reJavaEncoder = regexp.MustCompile(`(?:Encode\.forHtml|escapeHtml|escapeXml|StringEscapeUtils\.escapeHtml|HtmlUtils\.htmlEscape|ESAPI\.encoder|sanitize)\s*\(`)
	// @RequestParam or @RequestBody annotation nearby (indicates user input)
	reJavaRequestParam = regexp.MustCompile(`@(?:RequestParam|RequestBody|PathVariable|RequestHeader|CookieValue)`)

	// BATOU-XSS-015: Java response writer XSS (HttpServletResponse, Spring @ResponseBody, String.format)
	// response.getWriter().print/println/write with HTML and concatenation
	reJavaResponseWriterHTML = regexp.MustCompile(`(?:response\.getWriter\(\)|response\.getOutputStream\(\))\s*\.\s*(?:print(?:ln)?|write)\s*\(\s*["']<.+?["']\s*\+`)
	// String.format with HTML template containing %s (potential user data injection)
	reJavaStringFormatHTML = regexp.MustCompile(`String\.format\s*\(\s*["'][^"']*<[^"']*%s[^"']*["']`)
	// Spring @ResponseBody returning string concatenation with HTML
	reJavaResponseBodyReturn = regexp.MustCompile(`return\s+["']<[^"']*["']\s*\+`)
	// @ResponseBody annotation indicator
	reJavaResponseBodyAnnotation = regexp.MustCompile(`@ResponseBody`)
	// @RestController annotation indicator
	reJavaRestController = regexp.MustCompile(`@RestController`)
)

func init() {
	rules.Register(&InnerHTMLUsage{})
	rules.Register(&DangerouslySetInnerHTML{})
	rules.Register(&DocumentWrite{})
	rules.Register(&UnescapedTemplateOutput{})
	rules.Register(&DOMManipulation{})
	rules.Register(&ResponseHeaderInjection{})
	rules.Register(&URLSchemeInjection{})
	rules.Register(&ServerSideRenderingXSS{})
	rules.Register(&MissingContentType{})
	rules.Register(&JSONContentTypeXSS{})
	rules.Register(&ReflectedXSS{})
	rules.Register(&PythonFStringHTML{})
	rules.Register(&JavaHTMLStringConcat{})
	rules.Register(&JavaResponseWriterXSS{})
}

// ---------- helpers ----------

func makeFinding(ruleID, title, desc, filePath string, line int, matched, suggestion, cwe, lang string, sev rules.Severity, confidence string) rules.Finding {
	return rules.Finding{
		RuleID:        ruleID,
		Severity:      sev,
		SeverityLabel: sev.String(),
		Title:         title,
		Description:   desc,
		FilePath:      filePath,
		LineNumber:    line,
		MatchedText:   strings.TrimSpace(matched),
		Suggestion:    suggestion,
		CWEID:         cwe,
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.Language(lang),
		Confidence:    confidence,
		Tags:          []string{"xss", "injection"},
	}
}

func isJSOrTS(lang rules.Language) bool {
	return lang == rules.LangJavaScript || lang == rules.LangTypeScript
}

// ---------- BATOU-XSS-001: InnerHTMLUsage ----------

type InnerHTMLUsage struct{}

func (r *InnerHTMLUsage) ID() string                   { return "BATOU-XSS-001" }
func (r *InnerHTMLUsage) Name() string                 { return "InnerHTMLUsage" }
func (r *InnerHTMLUsage) Description() string          { return "Detects innerHTML/outerHTML assignments with dynamic content that may lead to XSS" }
func (r *InnerHTMLUsage) DefaultSeverity() rules.Severity { return rules.High }
func (r *InnerHTMLUsage) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *InnerHTMLUsage) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		// Original innerHTML/outerHTML assignment check
		m := reInnerHTMLAssign.FindStringSubmatch(line)
		if m != nil {
			rhs := m[2]
			// Skip static string assignments like .innerHTML = "" or .innerHTML = "<br>"
			if reStaticString.MatchString(rhs) {
				continue
			}
			findings = append(findings, makeFinding(
				r.ID(), "innerHTML/outerHTML assignment with dynamic content",
				"Assigning dynamic values to innerHTML/outerHTML can lead to XSS if the value contains unsanitized user input.",
				ctx.FilePath, i+1, strings.TrimSpace(line),
				"Use textContent for plain text, or sanitize HTML with a library like DOMPurify before assigning to innerHTML.",
				"CWE-79", string(ctx.Language), rules.High, "high",
			))
			continue
		}
		// insertAdjacentHTML — functionally identical to innerHTML
		if reInsertAdjacentHTML.MatchString(line) {
			findings = append(findings, makeFinding(
				r.ID(), "insertAdjacentHTML with dynamic content",
				"insertAdjacentHTML() inserts raw HTML into the DOM, equivalent to innerHTML. If the content includes unsanitized user input, it creates an XSS vulnerability.",
				ctx.FilePath, i+1, strings.TrimSpace(line),
				"Sanitize HTML with DOMPurify before passing to insertAdjacentHTML, or use textContent/createElement for safe insertion.",
				"CWE-79", string(ctx.Language), rules.High, "high",
			))
			continue
		}
		// jQuery .html() with argument
		if reJQueryHTML.MatchString(line) {
			findings = append(findings, makeFinding(
				r.ID(), "jQuery .html() with dynamic content",
				"jQuery's .html() method sets innerHTML on the matched elements. If the argument includes unsanitized user input, it creates an XSS vulnerability.",
				ctx.FilePath, i+1, strings.TrimSpace(line),
				"Use .text() for plain text, or sanitize HTML with DOMPurify before passing to .html().",
				"CWE-79", string(ctx.Language), rules.High, "medium",
			))
			continue
		}
		// createContextualFragment
		if reContextualFragment.MatchString(line) {
			findings = append(findings, makeFinding(
				r.ID(), "createContextualFragment with dynamic content",
				"createContextualFragment() parses a string as HTML. If the string includes unsanitized user input, it creates an XSS vulnerability.",
				ctx.FilePath, i+1, strings.TrimSpace(line),
				"Sanitize HTML with DOMPurify before passing to createContextualFragment.",
				"CWE-79", string(ctx.Language), rules.High, "medium",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-002: DangerouslySetInnerHTML ----------

type DangerouslySetInnerHTML struct{}

func (r *DangerouslySetInnerHTML) ID() string                   { return "BATOU-XSS-002" }
func (r *DangerouslySetInnerHTML) Name() string                 { return "DangerouslySetInnerHTML" }
func (r *DangerouslySetInnerHTML) Description() string          { return "Detects React dangerouslySetInnerHTML usage that may lead to XSS" }
func (r *DangerouslySetInnerHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *DangerouslySetInnerHTML) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DangerouslySetInnerHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if !reDangerouslySet.MatchString(line) {
			continue
		}
		findings = append(findings, makeFinding(
			r.ID(), "dangerouslySetInnerHTML usage",
			"React's dangerouslySetInnerHTML bypasses built-in XSS protections. If the HTML content includes unsanitized user input, it creates an XSS vulnerability.",
			ctx.FilePath, i+1, strings.TrimSpace(line),
			"Sanitize the HTML with DOMPurify before passing it to dangerouslySetInnerHTML, or use safe React rendering instead.",
			"CWE-79", string(ctx.Language), rules.High, "high",
		))
	}
	return findings
}

// ---------- BATOU-XSS-003: DocumentWrite ----------

type DocumentWrite struct{}

func (r *DocumentWrite) ID() string                   { return "BATOU-XSS-003" }
func (r *DocumentWrite) Name() string                 { return "DocumentWrite" }
func (r *DocumentWrite) Description() string          { return "Detects document.write/writeln calls with dynamic content" }
func (r *DocumentWrite) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DocumentWrite) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DocumentWrite) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if !reDocWrite.MatchString(line) {
			continue
		}
		// Skip purely static string arguments
		if reDocWriteStatic.MatchString(line) && !strings.Contains(line, "+") && !strings.Contains(line, "${") {
			continue
		}
		findings = append(findings, makeFinding(
			r.ID(), "document.write/writeln with dynamic content",
			"document.write() and document.writeln() inject raw HTML into the page. Using dynamic content can lead to XSS.",
			ctx.FilePath, i+1, strings.TrimSpace(line),
			"Use DOM APIs (createElement, textContent) instead of document.write. If HTML insertion is needed, sanitize with DOMPurify.",
			"CWE-79", string(ctx.Language), rules.Medium, "medium",
		))
	}
	return findings
}

// ---------- BATOU-XSS-004: UnescapedTemplateOutput ----------

type UnescapedTemplateOutput struct{}

func (r *UnescapedTemplateOutput) ID() string                   { return "BATOU-XSS-004" }
func (r *UnescapedTemplateOutput) Name() string                 { return "UnescapedTemplateOutput" }
func (r *UnescapedTemplateOutput) Description() string          { return "Detects template engines outputting unescaped content" }
func (r *UnescapedTemplateOutput) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnescapedTemplateOutput) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangRuby, rules.LangPHP,
		rules.LangJavaScript, rules.LangTypeScript,
	}
}

func (r *UnescapedTemplateOutput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		var matched bool
		var desc, suggestion string

		switch ctx.Language {
		case rules.LangGo:
			if reGoTemplateHTML.MatchString(line) {
				matched = true
				desc = "template.HTML() casts a string to unescaped HTML, bypassing Go's html/template auto-escaping."
				suggestion = "Avoid template.HTML() with user input. Sanitize the content first or use auto-escaping."
			}

		case rules.LangPython:
			if reJinjaSafe.MatchString(line) {
				matched = true
				desc = "The |safe filter in Jinja2 marks content as safe HTML, bypassing auto-escaping."
				suggestion = "Remove |safe and let Jinja2 auto-escape the content, or sanitize with bleach before marking safe."
			} else if reJinjaAutoescOff.MatchString(line) {
				matched = true
				desc = "Disabling autoescape in Jinja2 outputs raw HTML for all variables in the block."
				suggestion = "Keep autoescape enabled. If specific values must be raw, sanitize them individually."
			}

		case rules.LangRuby:
			if reERBUnescaped.MatchString(line) {
				matched = true
				desc = "ERB <%== %> outputs unescaped HTML content."
				suggestion = "Use <%= %> for auto-escaped output, or sanitize with sanitize() helper before outputting."
			} else if reERBRaw.MatchString(line) {
				matched = true
				desc = "raw() outputs unescaped HTML in Rails templates."
				suggestion = "Remove raw() and let Rails auto-escape, or sanitize with sanitize() helper."
			}

		case rules.LangPHP:
			if rePHPEcho.MatchString(line) && !rePHPEchoSafe.MatchString(line) {
				matched = true
				desc = "echo with a variable and no htmlspecialchars() can output unescaped user input."
				suggestion = "Wrap the variable with htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before echoing."
			}

		case rules.LangJavaScript, rules.LangTypeScript:
			if reHandlebarTriple.MatchString(line) {
				matched = true
				desc = "Handlebars triple-brace {{{ }}} outputs unescaped HTML."
				suggestion = "Use double-brace {{ }} for auto-escaped output, or sanitize the content before rendering."
			}
		}

		if matched {
			findings = append(findings, makeFinding(
				r.ID(), "Unescaped template output",
				desc, ctx.FilePath, i+1, strings.TrimSpace(line),
				suggestion, "CWE-79", string(ctx.Language), rules.High, "high",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-005: DOMManipulation ----------

type DOMManipulation struct{}

func (r *DOMManipulation) ID() string                   { return "BATOU-XSS-005" }
func (r *DOMManipulation) Name() string                 { return "DOMManipulation" }
func (r *DOMManipulation) Description() string          { return "Detects risky DOM APIs that can lead to XSS when used with user-controlled data" }
func (r *DOMManipulation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DOMManipulation) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DOMManipulation) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// eval() - especially dangerous with URL/query params
		if reEvalCall.MatchString(line) {
			confidence := "medium"
			if strings.Contains(line, "location") || strings.Contains(line, "search") ||
				strings.Contains(line, "param") || strings.Contains(line, "query") ||
				strings.Contains(line, "hash") || strings.Contains(line, "url") {
				confidence = "high"
			}
			findings = append(findings, makeFinding(
				r.ID(), "eval() call with potential user input",
				"eval() executes arbitrary JavaScript. If the argument contains user-controlled data, it leads to XSS or code injection.",
				ctx.FilePath, i+1, trimmed,
				"Avoid eval(). Use JSON.parse() for data parsing, or Function constructor with validated input if dynamic code is truly needed.",
				"CWE-79", string(ctx.Language), rules.Medium, confidence,
			))
			continue
		}

		// location.href / location.assign / location.replace assignment
		if reLocationAssign.MatchString(line) {
			m := reLocationAssign.FindStringSubmatch(line)
			rhs := m[1]
			if strings.Contains(rhs, "location") || strings.Contains(rhs, "param") ||
				strings.Contains(rhs, "query") || strings.Contains(rhs, "input") ||
				strings.Contains(rhs, "user") || strings.Contains(rhs, "search") ||
				strings.Contains(rhs, "hash") || strings.Contains(rhs, "url") {
				findings = append(findings, makeFinding(
					r.ID(), "location assignment from potential user input",
					"Assigning user-controlled values to location.href can enable open redirects or javascript: URL XSS.",
					ctx.FilePath, i+1, trimmed,
					"Validate the URL scheme (allow only http/https) and use a URL allowlist when redirecting based on user input.",
					"CWE-79", string(ctx.Language), rules.Medium, "medium",
				))
				continue
			}
		}

		// window.open()
		if reWindowOpen.MatchString(line) {
			if strings.Contains(line, "location") || strings.Contains(line, "param") ||
				strings.Contains(line, "query") || strings.Contains(line, "input") ||
				strings.Contains(line, "user") || strings.Contains(line, "url") {
				findings = append(findings, makeFinding(
					r.ID(), "window.open() with potential user-controlled URL",
					"window.open() with a user-controlled URL can be used for phishing or javascript: protocol XSS.",
					ctx.FilePath, i+1, trimmed,
					"Validate the URL scheme (allow only http/https) before passing to window.open().",
					"CWE-79", string(ctx.Language), rules.Medium, "medium",
				))
				continue
			}
		}

		// setAttribute with dangerous attributes
		if reSetAttrDangerous.MatchString(line) {
			findings = append(findings, makeFinding(
				r.ID(), "setAttribute with dangerous attribute",
				"Setting href, src, action, or event handler attributes via setAttribute can introduce XSS if the value is user-controlled.",
				ctx.FilePath, i+1, trimmed,
				"Validate attribute values. For URLs, ensure the scheme is http/https. Never set event handler attributes from user input.",
				"CWE-79", string(ctx.Language), rules.Medium, "medium",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-006: ResponseHeaderInjection ----------

type ResponseHeaderInjection struct{}

func (r *ResponseHeaderInjection) ID() string                   { return "BATOU-XSS-006" }
func (r *ResponseHeaderInjection) Name() string                 { return "ResponseHeaderInjection" }
func (r *ResponseHeaderInjection) Description() string          { return "Detects HTTP response headers set with unsanitized input" }
func (r *ResponseHeaderInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *ResponseHeaderInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangGo}
}

func (r *ResponseHeaderInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		var matched bool

		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript:
			// res.setHeader('Content-Type', userInput)
			if reNodeSetHeader.MatchString(line) || reNodeHeaderReq.MatchString(line) {
				m := reNodeSetHeader.FindStringSubmatch(line)
				if m != nil {
					val := m[1]
					// Skip static string values
					if reStaticString.MatchString(val) {
						continue
					}
				}
				matched = true
			}

		case rules.LangGo:
			// w.Header().Set(key, userInput)
			if reGoHeaderSet.MatchString(line) || reHeaderFromReq.MatchString(line) {
				m := reGoHeaderSet.FindStringSubmatch(line)
				if m != nil {
					val := m[1]
					if reStaticString.MatchString(val) {
						continue
					}
				}
				matched = true
			}
		}

		if matched {
			findings = append(findings, makeFinding(
				r.ID(), "HTTP response header set with unsanitized value",
				"Setting HTTP response headers with user-controlled values can lead to header injection, enabling XSS via Content-Type manipulation or response splitting.",
				ctx.FilePath, i+1, trimmed,
				"Validate and sanitize header values. Use allowlists for Content-Type. Strip newline characters (\\r\\n) from header values.",
				"CWE-79", string(ctx.Language), rules.High, "medium",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-007: URLSchemeInjection ----------

type URLSchemeInjection struct{}

func (r *URLSchemeInjection) ID() string                   { return "BATOU-XSS-007" }
func (r *URLSchemeInjection) Name() string                 { return "URLSchemeInjection" }
func (r *URLSchemeInjection) Description() string          { return "Detects javascript: protocol in URLs and dynamic href/src without protocol validation" }
func (r *URLSchemeInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *URLSchemeInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *URLSchemeInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Explicit javascript: in href/src/action attributes
		if reJSProtocolHref.MatchString(line) {
			findings = append(findings, makeFinding(
				r.ID(), "javascript: protocol in URL attribute",
				"Using javascript: protocol in href, src, or action attributes executes JavaScript when the link is clicked or resource loaded.",
				ctx.FilePath, i+1, trimmed,
				"Remove the javascript: URL. Use event handlers instead, or navigate to a safe http/https URL.",
				"CWE-79", string(ctx.Language), rules.High, "high",
			))
			continue
		}

		// javascript: protocol concatenation
		if reJSProtocolVar.MatchString(line) {
			findings = append(findings, makeFinding(
				r.ID(), "javascript: protocol string concatenation",
				"Concatenating 'javascript:' with dynamic content constructs an XSS payload.",
				ctx.FilePath, i+1, trimmed,
				"Never construct javascript: URLs. Use event handlers or validated http/https URLs instead.",
				"CWE-79", string(ctx.Language), rules.High, "high",
			))
			continue
		}

		// Dynamic href/src in JSX: href={userInput} without validation
		if reHrefDynamic.MatchString(line) {
			// Check that it's not using a safe pattern like href={`/path`} or href={"static"}
			// Only flag when the value references a variable that could be user-controlled
			if strings.Contains(line, "url") || strings.Contains(line, "href") ||
				strings.Contains(line, "link") || strings.Contains(line, "src") ||
				strings.Contains(line, "input") || strings.Contains(line, "param") ||
				strings.Contains(line, "user") || strings.Contains(line, "data") {
				findings = append(findings, makeFinding(
					r.ID(), "Dynamic URL in href/src without protocol validation",
					"Setting href or src to a user-controlled value without validating the URL scheme can allow javascript: protocol XSS.",
					ctx.FilePath, i+1, trimmed,
					"Validate that the URL starts with http:// or https:// before using it in href/src attributes. Consider using a URL sanitization library.",
					"CWE-79", string(ctx.Language), rules.High, "medium",
				))
			}
		}
	}
	return findings
}

// ---------- BATOU-XSS-008: ServerSideRenderingXSS ----------

type ServerSideRenderingXSS struct{}

func (r *ServerSideRenderingXSS) ID() string                   { return "BATOU-XSS-008" }
func (r *ServerSideRenderingXSS) Name() string                 { return "ServerSideRenderingXSS" }
func (r *ServerSideRenderingXSS) Description() string          { return "Detects server-side rendering without escaping across Python, Java, Go, Ruby, and C#" }
func (r *ServerSideRenderingXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *ServerSideRenderingXSS) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangCSharp,
	}
}

func (r *ServerSideRenderingXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		var matched bool
		var desc, suggestion string

		switch ctx.Language {
		case rules.LangPython:
			if rePyMarkup.MatchString(line) || rePyMarkupFmt.MatchString(line) {
				matched = true
				desc = "Markup() marks a string as safe HTML, bypassing Jinja2/Flask auto-escaping. If user input is passed in, it creates an XSS vulnerability."
				suggestion = "Do not pass user input to Markup(). Use auto-escaping or sanitize with bleach before wrapping in Markup()."
			} else if rePyMarkSafe.MatchString(line) {
				matched = true
				desc = "Django's mark_safe() marks a string as safe HTML, bypassing auto-escaping. If user input is included, it creates an XSS vulnerability."
				suggestion = "Do not pass user input to mark_safe(). Use the |escape filter or django.utils.html.escape() on user data before marking safe."
			}

		case rules.LangJava:
			if reJSPUnescaped.MatchString(line) {
				matched = true
				desc = "JSP expression tag (<%= %>) outputs request.getParameter() without escaping, creating a reflected XSS vulnerability."
				suggestion = "Use <c:out value=\"${param.name}\"/> or fn:escapeXml() instead of direct expression output."
			} else if reJavaHTMLConcat.MatchString(line) {
				// Skip if the line uses a known encoder
				if !strings.Contains(line, "Encode.forHtml") && !strings.Contains(line, "escapeHtml") &&
					!strings.Contains(line, "escapeXml") && !strings.Contains(line, "StringEscapeUtils") &&
					!strings.Contains(line, "HtmlUtils.htmlEscape") {
					matched = true
					desc = "Constructing HTML by concatenating strings with user input in a PrintWriter/response writer creates an XSS vulnerability."
					suggestion = "Use a template engine with auto-escaping, or apply OWASP Java Encoder (Encode.forHtml()) before outputting."
				}
			}

		case rules.LangGo:
			if reGoFprintfHTML.MatchString(line) {
				matched = true
				desc = "Writing HTML content with fmt.Fprintf to an http.ResponseWriter using %s or %v format verbs can inject unsanitized user data into the response."
				suggestion = "Use html/template for HTML rendering. If fmt.Fprintf is necessary, escape user data with html.EscapeString() first."
			}

		case rules.LangRuby:
			if reRubyHTMLSafe.MatchString(line) {
				// Check for user-input indicators near html_safe
				if strings.Contains(line, "param") || strings.Contains(line, "input") ||
					strings.Contains(line, "user") || strings.Contains(line, "request") ||
					strings.Contains(line, "query") || strings.Contains(line, "args") {
					matched = true
					desc = "Calling .html_safe on a string containing user input bypasses Rails auto-escaping and creates an XSS vulnerability."
					suggestion = "Do not call .html_safe on user-controlled strings. Use sanitize() helper or ERB auto-escaping instead."
				}
			}

		case rules.LangCSharp:
			if reCSharpHtmlRaw.MatchString(line) {
				matched = true
				desc = "Html.Raw() bypasses Razor auto-escaping. If user input is included, it creates an XSS vulnerability."
				suggestion = "Remove Html.Raw() and let Razor auto-escape, or sanitize input with an HTML sanitizer before using Html.Raw()."
			}
		}

		if matched {
			findings = append(findings, makeFinding(
				r.ID(), "Server-side rendering without escaping",
				desc, ctx.FilePath, i+1, trimmed,
				suggestion, "CWE-79", string(ctx.Language), rules.High, "high",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-009: MissingContentType ----------

type MissingContentType struct{}

func (r *MissingContentType) ID() string                   { return "BATOU-XSS-009" }
func (r *MissingContentType) Name() string                 { return "MissingContentType" }
func (r *MissingContentType) Description() string          { return "Detects HTML-like content written to HTTP responses without Content-Type header" }
func (r *MissingContentType) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingContentType) Languages() []rules.Language {
	return []rules.Language{rules.LangGo}
}

func (r *MissingContentType) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangGo {
		return nil
	}

	// Check if content contains HTML writes but no Content-Type header set
	hasHTMLWrite := reGoWriteHTML.MatchString(ctx.Content) || reGoFprintfHTMLTag.MatchString(ctx.Content)
	if !hasHTMLWrite {
		return nil
	}

	hasContentType := strings.Contains(ctx.Content, `Header().Set("Content-Type"`) ||
		strings.Contains(ctx.Content, `Header().Set("content-type"`) ||
		strings.Contains(ctx.Content, `Header().Add("Content-Type"`)

	if hasContentType {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if reGoWriteHTML.MatchString(line) || reGoFprintfHTMLTag.MatchString(line) {
			findings = append(findings, makeFinding(
				r.ID(), "HTML response without Content-Type header",
				"Writing HTML content to an HTTP response without explicitly setting Content-Type allows browsers to sniff the content type, potentially executing scripts in contexts where they shouldn't.",
				ctx.FilePath, i+1, strings.TrimSpace(line),
				"Set Content-Type explicitly with w.Header().Set(\"Content-Type\", \"text/html; charset=utf-8\") before writing HTML, or use \"text/plain\" for non-HTML responses.",
				"CWE-79", string(ctx.Language), rules.Medium, "medium",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-010: JSONContentTypeXSS ----------

type JSONContentTypeXSS struct{}

func (r *JSONContentTypeXSS) ID() string                   { return "BATOU-XSS-010" }
func (r *JSONContentTypeXSS) Name() string                 { return "JSONContentTypeXSS" }
func (r *JSONContentTypeXSS) Description() string          { return "Detects JSON responses with user data sent without proper application/json Content-Type" }
func (r *JSONContentTypeXSS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *JSONContentTypeXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *JSONContentTypeXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}

	// Only flag if there are res.send/end/write calls but no res.json and no application/json Content-Type
	if !reNodeResSend.MatchString(ctx.Content) {
		return nil
	}
	// If res.json is used or application/json is set, skip
	if reNodeResJSON.MatchString(ctx.Content) || reNodeContentJSON.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if !reNodeResSend.MatchString(line) {
			continue
		}
		// Flag lines that look like they're sending JSON-like content via res.send/end
		if strings.Contains(line, "JSON") || strings.Contains(line, "stringify") ||
			strings.Contains(line, "{") {
			findings = append(findings, makeFinding(
				r.ID(), "JSON response without application/json Content-Type",
				"Sending JSON-like data via res.send()/res.end() without setting Content-Type to application/json may cause browsers to render the response as HTML, enabling XSS if user data is included.",
				ctx.FilePath, i+1, strings.TrimSpace(line),
				"Use res.json() instead of res.send() for JSON responses, or explicitly set Content-Type to application/json.",
				"CWE-79", string(ctx.Language), rules.Medium, "medium",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-011: ReflectedXSS ----------

type ReflectedXSS struct{}

func (r *ReflectedXSS) ID() string                   { return "BATOU-XSS-011" }
func (r *ReflectedXSS) Name() string                 { return "ReflectedXSS" }
func (r *ReflectedXSS) Description() string          { return "Detects direct reflection of request parameters in HTTP response body" }
func (r *ReflectedXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *ReflectedXSS) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangPHP, rules.LangGo, rules.LangJava, rules.LangRuby,
		rules.LangJavaScript, rules.LangTypeScript,
	}
}

func (r *ReflectedXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		var matched bool
		var desc, suggestion string

		switch ctx.Language {
		case rules.LangPython:
			if rePyReflected.MatchString(line) || rePyFStringReq.MatchString(line) {
				matched = true
				desc = "Request parameters are reflected directly in the HTTP response without escaping, creating a reflected XSS vulnerability."
				suggestion = "Escape user input with markupsafe.escape() or html.escape() before including in response. Use template rendering with auto-escaping instead of string formatting."
			}

		case rules.LangPHP:
			if rePHPEchoGet.MatchString(line) {
				matched = true
				desc = "PHP echo outputs superglobal parameters directly in the response without escaping, creating a reflected XSS vulnerability."
				suggestion = "Wrap with htmlspecialchars($value, ENT_QUOTES, 'UTF-8') before echoing, or use a template engine with auto-escaping."
			} else if (rePHPEchoVarConcat.MatchString(line) || rePHPEchoVarInterp.MatchString(line)) &&
				!rePHPEchoSafe.MatchString(line) && hasNearbyPHPSuperglobal(lines, i) {
				matched = true
				desc = "PHP echo outputs a variable derived from user input (superglobals) without escaping, creating a reflected XSS vulnerability."
				suggestion = "Wrap with htmlspecialchars($value, ENT_QUOTES, 'UTF-8') before echoing, or use a template engine with auto-escaping."
			}

		case rules.LangGo:
			if reGoReflected.MatchString(line) || reGoFprintfReqBody.MatchString(line) {
				matched = true
				desc = "Request parameters from URL query or form data are written directly to the HTTP response via fmt.Fprintf, creating a reflected XSS vulnerability."
				suggestion = "Escape user input with html.EscapeString() before writing to the response, or use html/template for rendering HTML."
			}

		case rules.LangJava:
			if reJavaReflected.MatchString(line) {
				matched = true
				desc = "request.getParameter() is written directly to the response via PrintWriter, creating a reflected XSS vulnerability."
				suggestion = "Use OWASP Java Encoder (Encode.forHtml()) to escape user input, or use a template engine with auto-escaping like Thymeleaf."
			}

		case rules.LangRuby:
			if reRubyReflected.MatchString(line) {
				matched = true
				desc = "Request params are rendered directly in the response without escaping, creating a reflected XSS vulnerability."
				suggestion = "Use ERB auto-escaping (<%= %>) or call ERB::Util.html_escape() / h() on params before rendering."
			}

		case rules.LangJavaScript, rules.LangTypeScript:
			// res.send() with HTML content and user input nearby
			if reJSResSendHTML.MatchString(line) {
				// Check if the line or nearby context contains HTML tags and user input
				hasHTML := strings.Contains(line, "<") || strings.Contains(line, "html") || strings.Contains(line, "${")
				if hasHTML && hasNearbyJSInput(lines, i) {
					matched = true
					desc = "User input from req.query/req.params/req.body is reflected in an HTML response via res.send(), creating a reflected XSS vulnerability."
					suggestion = "Escape user input before embedding in HTML responses. Use a template engine with auto-escaping, or apply a sanitization library like DOMPurify."
				}
			}
		}

		if matched {
			findings = append(findings, makeFinding(
				r.ID(), "Reflected XSS: request parameters in response",
				desc, ctx.FilePath, i+1, trimmed,
				suggestion, "CWE-79", string(ctx.Language), rules.High, "high",
			))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-XSS-013: Python f-string HTML Building
// ---------------------------------------------------------------------------

type PythonFStringHTML struct{}

func (r *PythonFStringHTML) ID() string                     { return "BATOU-XSS-013" }
func (r *PythonFStringHTML) Name() string                   { return "PythonFStringHTML" }
func (r *PythonFStringHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *PythonFStringHTML) Description() string {
	return "Detects Python code that builds HTML strings using f-strings, .format(), or % formatting with unescaped variables, leading to stored/reflected XSS."
}
func (r *PythonFStringHTML) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *PythonFStringHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if file uses escape functions anywhere
	hasEscapeImport := rePyEscape.MatchString(ctx.Content)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		var matched string
		if m := rePyFStringHTML.FindString(line); m != "" {
			matched = m
		} else if m := rePyFormatHTML.FindString(line); m != "" {
			matched = m
		} else if m := rePyPctHTML.FindString(line); m != "" {
			matched = m
		}

		if matched == "" {
			continue
		}

		// Check if the interpolated variable on this line was escaped
		// Look back a few lines for escape() calls on the variables used
		lineEscaped := false
		if hasEscapeImport {
			start := i - 5
			if start < 0 {
				start = 0
			}
			for j := start; j <= i; j++ {
				if rePyEscape.MatchString(lines[j]) {
					lineEscaped = true
					break
				}
			}
		}

		if !lineEscaped {
			if len(matched) > 120 {
				matched = matched[:120]
			}
			findings = append(findings, makeFinding(
				r.ID(),
				"HTML built with unescaped Python f-string/format interpolation",
				"Building HTML strings with f-strings, .format(), or % formatting inserts unescaped user data into HTML, enabling XSS. Use a template engine with auto-escaping (Jinja2) or explicitly escape with markupsafe.escape().",
				ctx.FilePath, i+1, matched,
				"Use a template engine with auto-escaping (e.g., Jinja2), or escape all interpolated values with markupsafe.escape() / html.escape() before embedding in HTML.",
				"CWE-79", string(ctx.Language), r.DefaultSeverity(), "high",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-014: JavaHTMLStringConcat ----------

type JavaHTMLStringConcat struct{}

func (r *JavaHTMLStringConcat) ID() string                      { return "BATOU-XSS-014" }
func (r *JavaHTMLStringConcat) Name() string                    { return "JavaHTMLStringConcat" }
func (r *JavaHTMLStringConcat) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaHTMLStringConcat) Description() string {
	return "Detects Java string concatenation or StringBuilder.append building HTML with unsanitized user input, leading to stored or reflected XSS."
}
func (r *JavaHTMLStringConcat) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *JavaHTMLStringConcat) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if file has encoder imports (reduces false positives)
	fileHasEncoder := reJavaEncoder.MatchString(ctx.Content)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Skip lines that use an encoder
		if reJavaEncoder.MatchString(line) {
			continue
		}

		var matched bool
		var desc string

		// StringBuilder/StringBuffer.append with HTML + concatenation
		if reJavaStringBuilderAppendConcat.MatchString(line) {
			// Only flag if the concat part looks like a variable (not another string literal)
			// Skip lines where all + operands are string literals: "..." + "..."
			if !isJavaAllStringLiteralConcat(line) {
				if !fileHasEncoder || !hasNearbyJavaEncoder(lines, i) {
					matched = true
					desc = "StringBuilder/StringBuffer.append() concatenates HTML tags with variables. If any variable contains user input, this creates an XSS vulnerability."
				}
			}
		}

		// String concat: "<tag>" + variable  or  variable + "</tag>"
		if !matched && !isJavaAllStringLiteralConcatLine(line) &&
			(reJavaHTMLStringConcat.MatchString(line) || reJavaHTMLCloseConcat.MatchString(line) || reJavaHTMLConcatGeneral.MatchString(line)) {
			// Only flag if not inside a test and not using an encoder
			if !fileHasEncoder || !hasNearbyJavaEncoder(lines, i) {
				// Check for user input indicators nearby (request params, annotations)
				if hasNearbyJavaUserInput(lines, i) {
					matched = true
					desc = "HTML is built by concatenating string literals with variables derived from user input (@RequestParam, request.getParameter). This creates an XSS vulnerability."
				}
			}
		}

		if matched {
			findings = append(findings, makeFinding(
				r.ID(), "Java HTML string concatenation with user input",
				desc, ctx.FilePath, i+1, trimmed,
				"Use a template engine with auto-escaping (Thymeleaf, JSP with JSTL <c:out>), or escape with OWASP Java Encoder (Encode.forHtml()) before concatenation.",
				"CWE-79", string(ctx.Language), rules.High, "high",
			))
		}
	}
	return findings
}

// ---------- BATOU-XSS-015: JavaResponseWriterXSS ----------

type JavaResponseWriterXSS struct{}

func (r *JavaResponseWriterXSS) ID() string                      { return "BATOU-XSS-015" }
func (r *JavaResponseWriterXSS) Name() string                    { return "JavaResponseWriterXSS" }
func (r *JavaResponseWriterXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaResponseWriterXSS) Description() string {
	return "Detects Java HttpServletResponse writer, String.format HTML, and Spring @ResponseBody returning unsanitized HTML with user data."
}
func (r *JavaResponseWriterXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *JavaResponseWriterXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Detect file-level annotations for Spring controllers
	isResponseBody := reJavaResponseBodyAnnotation.MatchString(ctx.Content)
	isRestController := reJavaRestController.MatchString(ctx.Content)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Skip lines using encoders
		if reJavaEncoder.MatchString(line) {
			continue
		}

		var matched bool
		var desc string

		// response.getWriter().print/write("<html>" + var)
		if reJavaResponseWriterHTML.MatchString(line) {
			if !hasNearbyJavaEncoder(lines, i) {
				matched = true
				desc = "HttpServletResponse writer outputs HTML concatenated with variables. If any variable contains user input, this creates an XSS vulnerability."
			}
		}

		// String.format("<html>%s</html>", userInput)
		if !matched && reJavaStringFormatHTML.MatchString(line) {
			if !hasNearbyJavaEncoder(lines, i) {
				matched = true
				desc = "String.format() builds HTML with %s placeholders. User input inserted via format parameters creates an XSS vulnerability."
			}
		}

		// return "<tag>" + var in @ResponseBody or @RestController
		if !matched && reJavaResponseBodyReturn.MatchString(line) {
			if isResponseBody || isRestController {
				if !hasNearbyJavaEncoder(lines, i) {
					matched = true
					desc = "Spring @ResponseBody/@RestController method returns HTML built by string concatenation. User input in the concatenated value creates an XSS vulnerability."
				}
			}
		}

		if matched {
			findings = append(findings, makeFinding(
				r.ID(), "Java response writer XSS",
				desc, ctx.FilePath, i+1, trimmed,
				"Use a template engine (Thymeleaf) for HTML responses. If raw response writing is needed, escape all user input with OWASP Java Encoder (Encode.forHtml()) or use Content-Type application/json.",
				"CWE-79", string(ctx.Language), rules.High, "high",
			))
		}
	}
	return findings
}

// isJavaAllStringLiteralConcat checks if all + operands in a .append() call are
// string literals (e.g., .append("<nav>" + "Home" + "</nav>")). Returns true if
// there are no variable references between the concatenation operators.
func isJavaAllStringLiteralConcat(line string) bool {
	// Find the append argument portion
	idx := strings.Index(line, ".append(")
	if idx < 0 {
		return false
	}
	arg := line[idx+len(".append("):]
	// Find the closing paren (simple heuristic)
	depth := 1
	end := -1
	for i, ch := range arg {
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
	}
	if end < 0 {
		return false
	}
	arg = arg[:end]
	// Split on + and check each part is a string literal
	parts := strings.Split(arg, "+")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if (strings.HasPrefix(p, `"`) && strings.HasSuffix(p, `"`)) ||
			(strings.HasPrefix(p, `'`) && strings.HasSuffix(p, `'`)) {
			continue
		}
		return false
	}
	return true
}

// isJavaAllStringLiteralConcatLine checks if all + operands on the line are
// string literals. Returns true if concatenation only joins string literals
// (e.g., "<h1>" + "text" + "</h1>") with no variable references.
func isJavaAllStringLiteralConcatLine(line string) bool {
	// Only applies to lines with concatenation
	if !strings.Contains(line, "+") {
		return false
	}
	// Extract the portion after = or after ( that contains the concat
	// Simple approach: split entire line on + and check each part
	parts := strings.Split(line, "+")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Strip trailing ; ) etc.
		p = strings.TrimRight(p, ";) \t")
		// Strip leading assignment, method call prefix etc.
		// Find the last " or ' bounded token
		if p == "" {
			continue
		}
		// Check if this part is or ends with a string literal
		// A part is safe if after removing prefix code, it's a string literal
		dqIdx := strings.LastIndex(p, `"`)
		sqIdx := strings.LastIndex(p, `'`)
		if dqIdx < 0 && sqIdx < 0 {
			// No string literal found in this part — it's a variable
			return false
		}
	}
	return true
}

// hasNearbyJavaEncoder checks if OWASP encoder or escapeHtml is used within 5 lines.
func hasNearbyJavaEncoder(lines []string, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 3
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if reJavaEncoder.MatchString(l) {
			return true
		}
	}
	return false
}

// hasNearbyJavaUserInput checks if request.getParameter, @RequestParam, or similar
// user input patterns appear within 30 lines before the current line.
func hasNearbyJavaUserInput(lines []string, idx int) bool {
	start := idx - 30
	if start < 0 {
		start = 0
	}
	end := idx + 1
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if strings.Contains(l, "request.getParameter") ||
			strings.Contains(l, "request.getHeader") ||
			strings.Contains(l, "request.getCookies") ||
			reJavaRequestParam.MatchString(l) {
			return true
		}
	}
	return false
}

// hasNearbyPHPSuperglobal checks if $_GET/$_POST/$_REQUEST/$_COOKIE appears
// within 20 lines before the current line (same function scope).
func hasNearbyPHPSuperglobal(lines []string, idx int) bool {
	start := idx - 20
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start : idx+1] {
		if rePHPSuperglobal.MatchString(l) {
			return true
		}
	}
	return false
}

// hasNearbyJSInput checks surrounding lines for req.query/params/body user input.
func hasNearbyJSInput(lines []string, idx int) bool {
	start := idx - 15
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if reJSReqInput.MatchString(l) {
			return true
		}
	}
	return false
}
