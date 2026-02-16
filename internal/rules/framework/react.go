package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// React-specific security rule patterns
//
// Note: dangerouslySetInnerHTML is already covered by BATOU-XSS-002 and
// javascript: href by BATOU-XSS-007. This file covers additional React-specific
// patterns not handled by the general XSS rules.
// ---------------------------------------------------------------------------

var (
	// BATOU-FW-REACT-001: React SSR renderToString with unsanitized data
	reReactRenderToString  = regexp.MustCompile(`\brenderToString\s*\(`)
	reReactRenderToStatic  = regexp.MustCompile(`\brenderToStaticMarkup\s*\(`)
	reReactSSRUserInput    = regexp.MustCompile(`(?:req\.(?:query|params|body|cookies)|request\.(?:query|params|body)|props\.\w*[Uu]ser|props\.\w*[Ii]nput|props\.\w*[Dd]ata)`)

	// BATOU-FW-REACT-002: React ref-based innerHTML assignment
	reReactRefInnerHTML = regexp.MustCompile(`\.\s*current\s*\.\s*innerHTML\s*=`)

	// BATOU-FW-REACT-003: React component prop spreading from user input
	reReactSpreadProps = regexp.MustCompile(`<\w+\s+\{\s*\.\.\.(?:props|data|userInput|input|params|queryParams|req\.)`)

	// BATOU-FW-REACT-004: Dynamic script/iframe creation in React
	reReactCreateScript = regexp.MustCompile(`createElement\s*\(\s*["'](?:script|iframe)["']`)
	reReactDangerousTag = regexp.MustCompile(`<(?:script|iframe)\s+.*(?:src|srcdoc)\s*=\s*\{`)
)

// ---------------------------------------------------------------------------
// BATOU-FW-REACT-001: React SSR with unsanitized user data
// ---------------------------------------------------------------------------

type ReactSSRUnsanitized struct{}

func (r *ReactSSRUnsanitized) ID() string                      { return "BATOU-FW-REACT-001" }
func (r *ReactSSRUnsanitized) Name() string                    { return "ReactSSRUnsanitized" }
func (r *ReactSSRUnsanitized) DefaultSeverity() rules.Severity { return rules.High }
func (r *ReactSSRUnsanitized) Description() string {
	return "Detects React server-side rendering (renderToString/renderToStaticMarkup) in files that handle user input, which can lead to XSS if user data is embedded in the rendered HTML without escaping."
}
func (r *ReactSSRUnsanitized) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ReactSSRUnsanitized) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}

	// Only flag if the file also handles user input
	hasUserInput := reReactSSRUserInput.MatchString(ctx.Content)
	if !hasUserInput {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reReactRenderToString.MatchString(line) || reReactRenderToStatic.MatchString(line) {
			// Check if there's a DOMPurify or escape call nearby
			if hasSSRSanitizer(lines, i) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "React SSR with user input (XSS risk)",
				Description:   "renderToString/renderToStaticMarkup generates raw HTML on the server. If user-controlled data is passed as props without sanitization, it can result in XSS when the HTML is sent to the client. React's JSX escaping helps with text content, but dangerouslySetInnerHTML, style objects, and certain attributes can still be exploited.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Sanitize all user input before passing as props to SSR components. Use DOMPurify.sanitize() for HTML content. Implement a Content Security Policy (CSP) as defense-in-depth.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"react", "ssr", "xss", "renderToString"},
			})
		}
	}
	return findings
}

// hasSSRSanitizer checks if sanitization is present near SSR calls.
func hasSSRSanitizer(lines []string, idx int) bool {
	start := idx - 10
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "dompurify") || strings.Contains(lower, "sanitize") ||
			strings.Contains(lower, "escapehtml") || strings.Contains(lower, "escape_html") ||
			strings.Contains(lower, "xss") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-FW-REACT-002: React ref innerHTML assignment
// ---------------------------------------------------------------------------

type ReactRefInnerHTML struct{}

func (r *ReactRefInnerHTML) ID() string                      { return "BATOU-FW-REACT-002" }
func (r *ReactRefInnerHTML) Name() string                    { return "ReactRefInnerHTML" }
func (r *ReactRefInnerHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *ReactRefInnerHTML) Description() string {
	return "Detects assignment to ref.current.innerHTML in React, which bypasses React's XSS protections."
}
func (r *ReactRefInnerHTML) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ReactRefInnerHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reReactRefInnerHTML.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "React ref.current.innerHTML assignment (XSS bypass)",
				Description:   "Assigning to ref.current.innerHTML bypasses React's built-in XSS protection. This is functionally equivalent to dangerouslySetInnerHTML but harder to detect in code reviews.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use React's rendering model instead of direct DOM manipulation. If raw HTML is needed, use dangerouslySetInnerHTML with DOMPurify.sanitize().",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"react", "xss", "ref", "innerHTML"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-REACT-003: Prop spreading from user input
// ---------------------------------------------------------------------------

type ReactPropSpreading struct{}

func (r *ReactPropSpreading) ID() string                      { return "BATOU-FW-REACT-003" }
func (r *ReactPropSpreading) Name() string                    { return "ReactPropSpreading" }
func (r *ReactPropSpreading) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ReactPropSpreading) Description() string {
	return "Detects spreading of user-controlled data as React component props, which can inject dangerous props like dangerouslySetInnerHTML or event handlers."
}
func (r *ReactPropSpreading) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ReactPropSpreading) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reReactSpreadProps.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "React prop spreading from user-controlled data",
				Description:   "Spreading user-controlled objects as React props allows an attacker to inject dangerous props like dangerouslySetInnerHTML, style (for CSS injection), href (for javascript: URLs), or event handlers (onClick, onError, etc.).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Destructure only the expected props from user data: const { title, content } = data; <Component title={title} content={content} />. Never spread raw user input as props.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"react", "xss", "prop-spreading", "mass-assignment"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-REACT-004: Dynamic script/iframe creation
// ---------------------------------------------------------------------------

type ReactDynamicScriptIframe struct{}

func (r *ReactDynamicScriptIframe) ID() string                      { return "BATOU-FW-REACT-004" }
func (r *ReactDynamicScriptIframe) Name() string                    { return "ReactDynamicScriptIframe" }
func (r *ReactDynamicScriptIframe) DefaultSeverity() rules.Severity { return rules.High }
func (r *ReactDynamicScriptIframe) Description() string {
	return "Detects React.createElement('script'/'iframe') or JSX <script>/<iframe> with dynamic src/srcdoc attributes, which can lead to XSS."
}
func (r *ReactDynamicScriptIframe) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ReactDynamicScriptIframe) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isJSOrTS(ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reReactCreateScript.MatchString(line) || reReactDangerousTag.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Dynamic script/iframe creation in React",
				Description:   "Creating <script> or <iframe> elements with dynamic src or srcdoc attributes can load and execute attacker-controlled code if the URL/content comes from user input.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Avoid dynamically creating script/iframe elements. If needed, validate the src URL against an allowlist of trusted domains and use CSP headers to restrict script sources.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"react", "xss", "script-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isJSOrTS(lang rules.Language) bool {
	return lang == rules.LangJavaScript || lang == rules.LangTypeScript
}
