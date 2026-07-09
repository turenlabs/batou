package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Vue.js framework rules (independent implementation from the CWE definition
// and Vue's public API — no ported patterns).
//
// Vue auto-escapes text interpolation ({{ }}) but provides explicit escape
// hatches that re-introduce raw HTML / template compilation. The three
// dangerous primitives, all client-side, are:
//   - v-html="expr"               → raw innerHTML (CWE-79 DOM XSS)
//   - Vue.compile(str) / compile  → compiles a user string into a render
//                                   function (client-side SSTI → XSS, CWE-79)
//   - h(tag, { domProps:{innerHTML}}) / render innerHTML → raw HTML in a
//     render function (CWE-79)
//
// Each rule fires only when the bound/compiled value LOOKS user-controlled
// (user/input/data/content/html/message/param/query/body naming, or template
// interpolation/concatenation) so a constant `v-html="staticDoc"` stays clean.
// ---------------------------------------------------------------------------

// BATOU-FW-VUE-001: v-html binding fed by user-controlled data.
// Matches `v-html="...userish..."`, `v-html='...'`, and the `:v-html` /
// `v-html.prop` shapes, requiring the bound expression to name a
// user-controlled-looking variable.
var reVueVHtmlUserData = regexp.MustCompile(`v-html\s*=\s*["'][^"']*(?:[Uu]ser|[Ii]nput|[Dd]ata|[Cc]ontent|[Hh]tml|[Mm]essage|[Cc]omment|[Bb]ody|[Pp]aram|[Qq]uery|[Dd]esc|[Rr]aw|[Mm]arkdown|[Pp]ost|payload|props\.)[^"']*["']`)

// BATOU-FW-VUE-002: Vue.compile / compile() of a non-constant template — the
// argument is a JS expression (no surrounding quotes immediately) referencing
// user data, or a template literal / concatenation. A constant string literal
// argument (`Vue.compile('<p>hi</p>')`) does NOT match.
var reVueCompileUserData = regexp.MustCompile(`(?:Vue\.compile|\bcompileToFunctions|\$compile)\s*\(\s*(?:` +
	"`" + `[^` + "`" + `]*\$\{` + // template literal with interpolation
	`|["'][^"']*["']\s*\+` + // "..." + something
	`|\w*(?:[Uu]ser|[Ii]nput|[Dd]ata|[Cc]ontent|[Hh]tml|[Tt]emplate|[Mm]essage|[Pp]aram|[Qq]uery|[Bb]ody)\w*\s*[,)])`) // bare var name that looks user-controlled

// BATOU-FW-VUE-003: render-function innerHTML via domProps with user data.
// `h('div', { domProps: { innerHTML: userVar } })` and the JSX
// `domPropsInnerHTML={userVar}` form.
var reVueRenderInnerHTML = regexp.MustCompile(`(?:domProps\s*:\s*\{[^}]*innerHTML\s*:|domPropsInnerHTML\s*=\s*\{)\s*[^,}]*(?:[Uu]ser|[Ii]nput|[Dd]ata|[Cc]ontent|[Hh]tml|[Mm]essage|[Pp]aram|[Qq]uery|[Bb]ody|props\.)`)

func init() {
	rules.Register(&VueVHtmlInjection{})
	rules.Register(&VueCompileInjection{})
	rules.Register(&VueRenderInnerHTML{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-VUE-001: v-html with user input (XSS)
// ---------------------------------------------------------------------------

type VueVHtmlInjection struct{}

func (r *VueVHtmlInjection) ID() string                      { return "BATOU-FW-VUE-001" }
func (r *VueVHtmlInjection) Name() string                    { return "VueVHtmlInjection" }
func (r *VueVHtmlInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *VueVHtmlInjection) Description() string {
	return "Detects Vue v-html bindings fed user-controlled data (DOM XSS)."
}
func (r *VueVHtmlInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *VueVHtmlInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lowered := ctx.LowerLines()
	for i, line := range ctx.SplitLines() {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := rules.GFindLower(reVueVHtmlUserData, line, lowered[i]); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Vue v-html binding with user-controlled data (XSS)",
				Description:   "A Vue v-html directive renders its bound expression as raw HTML, bypassing Vue's automatic text escaping. When the bound value contains user-controlled data, an attacker can inject script and execute arbitrary JavaScript (DOM-based XSS).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Prefer text interpolation {{ }} which auto-escapes. If raw HTML is required, sanitize with DOMPurify before binding (e.g. v-html=\"sanitize(userHtml)\") and never bind unsanitized user input.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "vue", "xss", "v-html"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-VUE-002: Vue.compile() of user input (client-side SSTI)
// ---------------------------------------------------------------------------

type VueCompileInjection struct{}

func (r *VueCompileInjection) ID() string                      { return "BATOU-FW-VUE-002" }
func (r *VueCompileInjection) Name() string                    { return "VueCompileInjection" }
func (r *VueCompileInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *VueCompileInjection) Description() string {
	return "Detects Vue.compile() of user-controlled templates (client-side template injection / XSS)."
}
func (r *VueCompileInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *VueCompileInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lowered := ctx.LowerLines()
	for i, line := range ctx.SplitLines() {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := rules.GFindLower(reVueCompileUserData, line, lowered[i]); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Vue.compile() of user-controlled template (client-side template injection)",
				Description:   "Vue.compile()/compileToFunctions() turns a template string into a render function. When the template is built from user input, the attacker controls the compiled render function — a client-side template injection that executes arbitrary expressions / HTML in the Vue context (XSS).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Never compile templates from user input. Use static templates with data binding ({{ }}) and pass user data as bound values, not as template source.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "vue", "template-injection", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-VUE-003: render-function innerHTML via domProps (XSS)
// ---------------------------------------------------------------------------

type VueRenderInnerHTML struct{}

func (r *VueRenderInnerHTML) ID() string                      { return "BATOU-FW-VUE-003" }
func (r *VueRenderInnerHTML) Name() string                    { return "VueRenderInnerHTML" }
func (r *VueRenderInnerHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *VueRenderInnerHTML) Description() string {
	return "Detects Vue render-function innerHTML via domProps with user-controlled data (XSS)."
}
func (r *VueRenderInnerHTML) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *VueRenderInnerHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lowered := ctx.LowerLines()
	for i, line := range ctx.SplitLines() {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := rules.GFindLower(reVueRenderInnerHTML, line, lowered[i]); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Vue render-function innerHTML with user data (XSS)",
				Description:   "A Vue render function sets innerHTML via domProps (or domPropsInnerHTML in JSX) from user-controlled data. This injects raw HTML into the DOM, bypassing Vue's escaping, and is DOM-based XSS.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set text content (the children array / domProps.textContent) instead of innerHTML. If HTML is required, sanitize with DOMPurify before assigning innerHTML.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "vue", "xss", "innerHTML"},
			})
		}
	}
	return findings
}
