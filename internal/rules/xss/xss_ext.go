package xss

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended XSS rules
// ---------------------------------------------------------------------------

// GTSS-XSS-016: DOM XSS via document.write with user input
var (
	reDocWriteLocation   = regexp.MustCompile(`document\.(?:write|writeln)\s*\(.*(?:location\.|document\.URL|document\.referrer|document\.documentURI|window\.name)`)
	reDocWriteUserInput  = regexp.MustCompile(`document\.(?:write|writeln)\s*\(.*(?:location\.(?:hash|search|href|pathname)|document\.cookie|window\.name|document\.referrer)`)
)

// GTSS-XSS-017: DOM XSS via location.hash/search
var (
	reLocationHashUse    = regexp.MustCompile(`(?:location\.hash|location\.search|location\.href|document\.URL|document\.referrer)`)
	reDOMSinkWithLoc     = regexp.MustCompile(`(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|\.html\s*\(|eval\s*\().*(?:location\.(?:hash|search|href)|document\.URL|document\.referrer)`)
	reLocationToVar      = regexp.MustCompile(`(?:=\s*(?:location\.(?:hash|search|href)|document\.URL|document\.referrer|window\.location))`)
)

// GTSS-XSS-018: Angular bypassSecurityTrustHtml
var (
	reAngularBypass      = regexp.MustCompile(`bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(`)
	reAngularSanitizer   = regexp.MustCompile(`DomSanitizer`)
)

// GTSS-XSS-019: Vue v-html directive
var (
	reVueVHTML           = regexp.MustCompile(`v-html\s*=\s*["']`)
	reVueSanitize        = regexp.MustCompile(`(?i)(?:sanitize|DOMPurify|xss|filterXSS)`)
)

// GTSS-XSS-020: jQuery .html() with user input
var (
	reJQueryHTMLUserInput = regexp.MustCompile(`\$\s*\([^)]*\)\s*\.html\s*\(\s*(?:(?:location|document|window)\.|.*\+|.*\$\{)`)
	reJQueryHTMLVar       = regexp.MustCompile(`\.\s*html\s*\(\s*[a-zA-Z_]\w*\s*\)`)
)

// GTSS-XSS-021: React dangerouslySetInnerHTML with variable
var (
	reReactDangerVar     = regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:[a-zA-Z_]\w*(?:\.\w+)*|(?:props|state|data|user|input|param|query)\.)`)
	reReactDangerConcat  = regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:.*\+`)
)

// GTSS-XSS-022: Reflected XSS via response.write
var (
	reRespWriteConcat    = regexp.MustCompile(`(?i)(?:response\.write|res\.write|res\.send|res\.end|out\.print|out\.println|writer\.write|writer\.println|w\.Write|fmt\.Fprint)\s*\(.*(?:\+\s*(?:req\.|request\.|params|query|body|args|GET|POST))`)
	reRespWriteFmt       = regexp.MustCompile(`(?i)(?:response\.write|res\.write|res\.send|fmt\.Fprintf)\s*\(.*(?:f["']|%[sv]|\.format\().*(?:req\.|request\.|params|query|body|args|GET|POST)`)
)

// GTSS-XSS-023: Stored XSS via database value in HTML
var (
	reDBValueInHTML      = regexp.MustCompile(`(?i)(?:innerHTML|outerHTML|document\.write|\.html\s*\(|dangerouslySetInnerHTML).*(?:\.(?:find|query|fetch|get|select|execute|findOne|findAll)\s*\(|db\.|database|cursor|result|row|record)`)
	reDBHTMLConcat       = regexp.MustCompile(`(?i)(?:["']<[^"']*>\s*["']\s*\+|html\s*(?:\+?=)\s*["']<).*(?:row|record|result|data|item|entry|user|comment|post|message)\s*[\[.]`)
)

// GTSS-XSS-024: XSS via SVG/MathML
var (
	reSVGUpload          = regexp.MustCompile(`(?i)(?:svg|mathml|image/svg).*(?:upload|file|input|content|src|source|user|data)`)
	reSVGInline          = regexp.MustCompile(`(?i)<svg\b[^>]*>.*(?:onload|onerror|onclick|onmouseover|javascript:)`)
	reSVGContentType     = regexp.MustCompile(`(?i)(?:Content-Type|contentType|content_type).*image/svg`)
)

// GTSS-XSS-025: XSS in error message reflection
var (
	reErrorReflect       = regexp.MustCompile(`(?i)(?:error|err|exception|message|msg)\s*(?:\+?=|=).*(?:req\.|request\.|params|query|body|args|input|user|\$_GET|\$_POST|\$_REQUEST)`)
	reErrorHTML          = regexp.MustCompile(`(?i)(?:res\.send|response\.write|out\.print|writer\.write|w\.Write|fmt\.Fprint|echo|print|render).*(?:error|err|exception|message|msg)\b`)
	reErrorDisplay       = regexp.MustCompile(`(?i)(?:innerHTML|outerHTML|textContent|\.html\s*\(|\.text\s*\().*(?:error|err|exception|message|msg)\b`)
)

// GTSS-XSS-026: JavaScript URI scheme in href/src
var (
	reJSURIHref          = regexp.MustCompile(`(?i)(?:href|src|action|formaction|data|poster|background)\s*=\s*(?:["']\s*javascript\s*:|[{(]\s*["']\s*javascript\s*:)`)
	reJSURIDynamic       = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*\{?\s*(?:user|input|param|query|data|url|link|href|src)\w*\s*\}?`)
	reJSURISanitize      = regexp.MustCompile(`(?i)(?:sanitizeUrl|DOMPurify|filterXSS|isValidUrl|isAbsoluteUrl|isSafeUrl|validateUrl)`)
)

// GTSS-XSS-027: Event handler injection
var (
	reEventHandler       = regexp.MustCompile(`(?i)(?:on(?:load|error|click|mouseover|mouseout|mouseenter|mouseleave|focus|blur|submit|change|input|keyup|keydown|keypress|abort|beforeunload|contextmenu|dblclick|drag|dragend|dragenter|dragleave|dragover|dragstart|drop))\s*=\s*(?:["'][^"']*(?:req\.|request\.|params|query|body|input|user)|["'][^"']*["']\s*\+)`)
	reEventHandlerConcat = regexp.MustCompile(`(?i)(?:["']<[^"']*\s+on(?:load|error|click|mouseover|focus|blur|submit|change|input|keyup|keydown))\s*=\s*["']\s*\+\s*\w+`)
	reEventDynamic       = regexp.MustCompile(`(?i)setAttribute\s*\(\s*["']on(?:load|error|click|mouseover|focus|blur|submit|change|input|keyup|keydown)["']\s*,\s*(?:[a-zA-Z_]\w*|req\.|request\.)`)
)

// ---------------------------------------------------------------------------
// Helpers unique to this ext file
// ---------------------------------------------------------------------------

func isCommentXE(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncateXE(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func nearbyLinesXE(lines []string, idx, window int) string {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&DOMXSSDocWrite{})
	rules.Register(&DOMXSSLocationHash{})
	rules.Register(&AngularBypassSecurity{})
	rules.Register(&VueVHTML{})
	rules.Register(&JQueryHTMLXSS{})
	rules.Register(&ReactDangerousVar{})
	rules.Register(&ReflectedXSSRespWrite{})
	rules.Register(&StoredXSSDatabase{})
	rules.Register(&SVGMathMLXSS{})
	rules.Register(&ErrorMessageXSS{})
	rules.Register(&JavaScriptURIScheme{})
	rules.Register(&EventHandlerInjection{})
}

// ---------------------------------------------------------------------------
// GTSS-XSS-016: DOM XSS via document.write with user input
// ---------------------------------------------------------------------------

type DOMXSSDocWrite struct{}

func (r *DOMXSSDocWrite) ID() string                     { return "GTSS-XSS-016" }
func (r *DOMXSSDocWrite) Name() string                   { return "DOMXSSDocWrite" }
func (r *DOMXSSDocWrite) DefaultSeverity() rules.Severity { return rules.High }
func (r *DOMXSSDocWrite) Description() string {
	return "Detects document.write/writeln calls with DOM-based user input sources (location.hash, location.search, document.URL, document.referrer), creating DOM-based XSS."
}
func (r *DOMXSSDocWrite) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DOMXSSDocWrite) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) { return nil }
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reDocWriteUserInput.MatchString(line) || reDocWriteLocation.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "DOM XSS: document.write with location/URL input",
				"document.write() called with DOM-based input (location.hash, location.search, document.URL, document.referrer). An attacker can craft a URL that injects script into the page.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Never pass location/URL data to document.write. Use textContent for safe text insertion, or sanitize with DOMPurify.",
				"CWE-79", string(ctx.Language), rules.High, "high"))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-017: DOM XSS via location.hash/search
// ---------------------------------------------------------------------------

type DOMXSSLocationHash struct{}

func (r *DOMXSSLocationHash) ID() string                     { return "GTSS-XSS-017" }
func (r *DOMXSSLocationHash) Name() string                   { return "DOMXSSLocationHash" }
func (r *DOMXSSLocationHash) DefaultSeverity() rules.Severity { return rules.High }
func (r *DOMXSSLocationHash) Description() string {
	return "Detects DOM-based XSS where location.hash, location.search, or document.URL flows into a dangerous DOM sink (innerHTML, eval, document.write)."
}
func (r *DOMXSSLocationHash) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DOMXSSLocationHash) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) { return nil }
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reDOMSinkWithLoc.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "DOM XSS: location data flows into dangerous sink",
				"DOM-based user input (location.hash/search/href, document.URL/referrer) flows into a dangerous DOM sink (innerHTML, eval, document.write). An attacker controls these values via the URL.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Sanitize location data with DOMPurify before inserting into the DOM. Use textContent instead of innerHTML.",
				"CWE-79", string(ctx.Language), rules.High, "high"))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-018: Angular bypassSecurityTrustHtml
// ---------------------------------------------------------------------------

type AngularBypassSecurity struct{}

func (r *AngularBypassSecurity) ID() string                     { return "GTSS-XSS-018" }
func (r *AngularBypassSecurity) Name() string                   { return "AngularBypassSecurity" }
func (r *AngularBypassSecurity) DefaultSeverity() rules.Severity { return rules.High }
func (r *AngularBypassSecurity) Description() string {
	return "Detects Angular DomSanitizer.bypassSecurityTrustHtml/Script/Style/Url usage, which explicitly bypasses Angular's built-in XSS protection."
}
func (r *AngularBypassSecurity) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *AngularBypassSecurity) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) { return nil }
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reAngularBypass.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "Angular bypassSecurityTrust* disables XSS protection",
				"Angular's DomSanitizer.bypassSecurityTrustHtml/Script/Style/Url explicitly marks content as safe, bypassing Angular's built-in XSS sanitization. If user input is passed, it creates an XSS vulnerability.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Avoid bypassSecurityTrust* methods. Use Angular's built-in sanitization. If bypass is necessary, sanitize with DOMPurify first.",
				"CWE-79", string(ctx.Language), rules.High, "high"))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-019: Vue v-html directive
// ---------------------------------------------------------------------------

type VueVHTML struct{}

func (r *VueVHTML) ID() string                     { return "GTSS-XSS-019" }
func (r *VueVHTML) Name() string                   { return "VueVHTML" }
func (r *VueVHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *VueVHTML) Description() string {
	return "Detects Vue.js v-html directive usage, which renders raw HTML and bypasses Vue's default XSS protection."
}
func (r *VueVHTML) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *VueVHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if sanitization is present nearby
	if reVueSanitize.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reVueVHTML.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "Vue v-html renders raw HTML (XSS risk)",
				"Vue's v-html directive renders raw HTML, bypassing Vue's default text interpolation escaping. If the bound data contains user input, this creates an XSS vulnerability.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Use {{ }} text interpolation instead of v-html. If HTML rendering is needed, sanitize with DOMPurify before binding.",
				"CWE-79", string(ctx.Language), rules.High, "high"))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-020: jQuery .html() with user input
// ---------------------------------------------------------------------------

type JQueryHTMLXSS struct{}

func (r *JQueryHTMLXSS) ID() string                     { return "GTSS-XSS-020" }
func (r *JQueryHTMLXSS) Name() string                   { return "JQueryHTMLXSS" }
func (r *JQueryHTMLXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *JQueryHTMLXSS) Description() string {
	return "Detects jQuery .html() calls with user-controlled input (URL parameters, location data, concatenation), creating DOM-based XSS."
}
func (r *JQueryHTMLXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *JQueryHTMLXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) { return nil }
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reJQueryHTMLUserInput.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "jQuery .html() with user-controlled input",
				"jQuery .html() sets innerHTML with user-controlled data (location, concatenation, template literal). This creates a DOM-based XSS vulnerability.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Use .text() for safe text insertion, or sanitize HTML with DOMPurify before passing to .html().",
				"CWE-79", string(ctx.Language), rules.High, "high"))
		} else if reJQueryHTMLVar.MatchString(line) {
			// Check if variable likely comes from user input
			if reLocationHashUse.MatchString(nearbyLinesXE(lines, i, 10)) {
				findings = append(findings, makeFinding(r.ID(), "jQuery .html() with variable from URL input",
					"jQuery .html() receives a variable that may contain URL-derived user input (location.hash/search). Verify the variable is sanitized.",
					ctx.FilePath, i+1, truncateXE(trimmed, 120),
					"Use .text() for safe text insertion, or sanitize HTML with DOMPurify before passing to .html().",
					"CWE-79", string(ctx.Language), rules.High, "medium"))
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-021: React dangerouslySetInnerHTML with variable
// ---------------------------------------------------------------------------

type ReactDangerousVar struct{}

func (r *ReactDangerousVar) ID() string                     { return "GTSS-XSS-021" }
func (r *ReactDangerousVar) Name() string                   { return "ReactDangerousVar" }
func (r *ReactDangerousVar) DefaultSeverity() rules.Severity { return rules.High }
func (r *ReactDangerousVar) Description() string {
	return "Detects React dangerouslySetInnerHTML with user-controlled data from props, state, or request parameters."
}
func (r *ReactDangerousVar) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ReactDangerousVar) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) { return nil }
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reReactDangerVar.MatchString(line) || reReactDangerConcat.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "React dangerouslySetInnerHTML with user-controlled data",
				"dangerouslySetInnerHTML receives data from props, state, or user input. If this data is not sanitized, it creates an XSS vulnerability that bypasses React's built-in XSS protection.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Sanitize HTML with DOMPurify.sanitize() before passing to dangerouslySetInnerHTML. Consider using safe React rendering instead.",
				"CWE-79", string(ctx.Language), rules.High, "high"))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-022: Reflected XSS via response.write
// ---------------------------------------------------------------------------

type ReflectedXSSRespWrite struct{}

func (r *ReflectedXSSRespWrite) ID() string                     { return "GTSS-XSS-022" }
func (r *ReflectedXSSRespWrite) Name() string                   { return "ReflectedXSSRespWrite" }
func (r *ReflectedXSSRespWrite) DefaultSeverity() rules.Severity { return rules.High }
func (r *ReflectedXSSRespWrite) Description() string {
	return "Detects request parameter values written directly to HTTP response body via response.write, res.send, or equivalent, creating reflected XSS."
}
func (r *ReflectedXSSRespWrite) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp}
}

func (r *ReflectedXSSRespWrite) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reRespWriteConcat, reRespWriteFmt}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, makeFinding(r.ID(), "Reflected XSS via response write with request data",
					"Request parameters are concatenated or formatted directly into the HTTP response body without encoding. An attacker can inject HTML/JavaScript via the request parameter.",
					ctx.FilePath, i+1, truncateXE(line[loc[0]:loc[1]], 120),
					"HTML-encode all request parameter values before including in response. Use a template engine with auto-escaping.",
					"CWE-79", string(ctx.Language), rules.High, "high"))
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-023: Stored XSS via database value in HTML
// ---------------------------------------------------------------------------

type StoredXSSDatabase struct{}

func (r *StoredXSSDatabase) ID() string                     { return "GTSS-XSS-023" }
func (r *StoredXSSDatabase) Name() string                   { return "StoredXSSDatabase" }
func (r *StoredXSSDatabase) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *StoredXSSDatabase) Description() string {
	return "Detects database query results inserted into HTML without encoding, which can lead to stored XSS if the database contains user-supplied data."
}
func (r *StoredXSSDatabase) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *StoredXSSDatabase) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reDBValueInHTML, reDBHTMLConcat}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, makeFinding(r.ID(), "Stored XSS: database value in HTML without encoding",
					"Database query results are inserted into HTML via innerHTML/document.write/concatenation without encoding. If the database stores user-supplied data, this creates a stored XSS vulnerability.",
					ctx.FilePath, i+1, truncateXE(line[loc[0]:loc[1]], 120),
					"HTML-encode all database values before inserting into HTML. Use a template engine with auto-escaping. Sanitize user input on storage and output.",
					"CWE-79", string(ctx.Language), rules.Medium, "medium"))
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-024: XSS via SVG/MathML injection
// ---------------------------------------------------------------------------

type SVGMathMLXSS struct{}

func (r *SVGMathMLXSS) ID() string                     { return "GTSS-XSS-024" }
func (r *SVGMathMLXSS) Name() string                   { return "SVGMathMLXSS" }
func (r *SVGMathMLXSS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SVGMathMLXSS) Description() string {
	return "Detects SVG file handling or inline SVG with event handlers, which can contain embedded JavaScript for XSS attacks."
}
func (r *SVGMathMLXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *SVGMathMLXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reSVGInline.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "SVG with inline event handler (XSS)",
				"Inline SVG contains event handler attributes (onload, onerror) that execute JavaScript. If user-controlled SVG content is rendered, this creates an XSS vulnerability.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Sanitize SVG content with DOMPurify.sanitize(svg, {USE_PROFILES: {svg: true}}). Strip event handlers and script elements from uploaded SVGs.",
				"CWE-79", string(ctx.Language), rules.Medium, "high"))
		} else if reSVGUpload.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "SVG file handling with user input (potential XSS)",
				"SVG files can contain embedded JavaScript via event handlers and <script> elements. Serving user-uploaded SVG files with image/svg+xml Content-Type can lead to XSS.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Serve uploaded SVG files with Content-Disposition: attachment or Content-Type: application/octet-stream. Sanitize SVG content before rendering inline.",
				"CWE-79", string(ctx.Language), rules.Medium, "medium"))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-025: XSS in error message reflection
// ---------------------------------------------------------------------------

type ErrorMessageXSS struct{}

func (r *ErrorMessageXSS) ID() string                     { return "GTSS-XSS-025" }
func (r *ErrorMessageXSS) Name() string                   { return "ErrorMessageXSS" }
func (r *ErrorMessageXSS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ErrorMessageXSS) Description() string {
	return "Detects error messages that include user input and are displayed in HTTP responses, enabling XSS through crafted inputs that appear in error pages."
}
func (r *ErrorMessageXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *ErrorMessageXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reErrorReflect.MatchString(line) {
			// Only flag if the error is also displayed
			if reErrorHTML.MatchString(nearbyLinesXE(lines, i, 10)) || reErrorDisplay.MatchString(nearbyLinesXE(lines, i, 10)) {
				findings = append(findings, makeFinding(r.ID(), "XSS in error message: user input reflected in error page",
					"User input is included in an error message that is displayed in the HTTP response. An attacker can craft input that triggers an error with an XSS payload in the error message.",
					ctx.FilePath, i+1, truncateXE(trimmed, 120),
					"HTML-encode error messages before displaying. Use generic error messages for user-facing output. Log detailed errors server-side only.",
					"CWE-79", string(ctx.Language), rules.Medium, "medium"))
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-026: JavaScript URI scheme in href/src
// ---------------------------------------------------------------------------

type JavaScriptURIScheme struct{}

func (r *JavaScriptURIScheme) ID() string                     { return "GTSS-XSS-026" }
func (r *JavaScriptURIScheme) Name() string                   { return "JavaScriptURIScheme" }
func (r *JavaScriptURIScheme) DefaultSeverity() rules.Severity { return rules.High }
func (r *JavaScriptURIScheme) Description() string {
	return "Detects javascript: URI scheme in href, src, or action attributes, or user-controlled URLs in these attributes without protocol validation."
}
func (r *JavaScriptURIScheme) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *JavaScriptURIScheme) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		if reJSURIHref.MatchString(line) {
			findings = append(findings, makeFinding(r.ID(), "javascript: URI scheme in href/src/action",
				"The javascript: URI scheme in href, src, or action attributes executes JavaScript when the link is clicked or the resource is loaded. This is a direct XSS vulnerability.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Remove javascript: URIs. Use event handlers instead. For user-controlled URLs, validate the scheme is http:// or https://.",
				"CWE-79", string(ctx.Language), rules.High, "high"))
		} else if reJSURIDynamic.MatchString(line) && !reJSURISanitize.MatchString(nearbyLinesXE(lines, i, 5)) {
			findings = append(findings, makeFinding(r.ID(), "User-controlled URL in href/src without protocol validation",
				"A user-controlled variable is used in href/src/action without URL sanitization. An attacker can inject javascript: or data: URIs to execute JavaScript.",
				ctx.FilePath, i+1, truncateXE(trimmed, 120),
				"Validate that URLs start with http:// or https://. Use URL sanitization libraries. Never allow javascript: or data: schemes from user input.",
				"CWE-79", string(ctx.Language), rules.High, "medium"))
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XSS-027: Event handler injection
// ---------------------------------------------------------------------------

type EventHandlerInjection struct{}

func (r *EventHandlerInjection) ID() string                     { return "GTSS-XSS-027" }
func (r *EventHandlerInjection) Name() string                   { return "EventHandlerInjection" }
func (r *EventHandlerInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *EventHandlerInjection) Description() string {
	return "Detects HTML event handler attributes (onload, onerror, onclick, etc.) with user-controlled data, enabling XSS through event handler injection."
}
func (r *EventHandlerInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *EventHandlerInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reEventHandler, reEventHandlerConcat, reEventDynamic}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentXE(trimmed) { continue }
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, makeFinding(r.ID(), "Event handler injection: user data in on* attribute",
					"User-controlled data is used in an HTML event handler attribute (onload, onerror, onclick, etc.). Event handlers execute JavaScript, so any user input in these attributes creates an XSS vulnerability.",
					ctx.FilePath, i+1, truncateXE(line[loc[0]:loc[1]], 120),
					"Never include user input in event handler attributes. Use addEventListener() with properly validated data. Sanitize HTML output with DOMPurify.",
					"CWE-79", string(ctx.Language), rules.High, "high"))
				break
			}
		}
	}
	return findings
}
