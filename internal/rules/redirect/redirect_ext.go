package redirect

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended redirect rules
// ---------------------------------------------------------------------------

// GTSS-REDIR-003: Open redirect via meta refresh tag
var (
	reMetaRefresh     = regexp.MustCompile(`(?i)<meta\s+[^>]*http-equiv\s*=\s*['"]refresh['"][^>]*content\s*=\s*['"][^'"]*url\s*=`)
	reMetaRefreshVar  = regexp.MustCompile(`(?i)meta.*refresh.*url\s*=\s*['"]?\s*(?:\$\{|\+\s*\w+|%s|%v|\{\{|<%=|#\{)`)
)

// GTSS-REDIR-004: Open redirect via window.location
var (
	reWindowLocation     = regexp.MustCompile(`(?i)(?:window\.location|document\.location)\s*(?:\.\s*href\s*)?\s*=\s*(?:(?:req|request|params|query|body|searchParams|location\.(?:search|hash)|document\.(?:URL|referrer)|URLSearchParams)[\w.]*)`)
	reWindowLocationGet  = regexp.MustCompile(`(?i)(?:window\.location|document\.location)\s*(?:\.\s*href\s*)?\s*=\s*\w+\.get\s*\(`)
)

// GTSS-REDIR-005: Redirect using unvalidated host header
var (
	reHostHeaderRedirect = regexp.MustCompile(`(?i)(?:redirect|location|Location)\s*[:=]\s*[^;{}\n]*(?:req\.headers\.host|request\.headers\[['"]host['"]\]|request\.META\[['"]HTTP_HOST['"]\]|\$_SERVER\[['"]HTTP_HOST['"]\]|r\.Host|request\.host|request\.getHeader\s*\(\s*['"]host['"]\))`)
)

// GTSS-REDIR-006: JavaScript redirect via location.href
var (
	reLocationHrefUserInput = regexp.MustCompile(`(?i)(?:window\.)?location\.href\s*=\s*(?:(?:new\s+URLSearchParams|URLSearchParams|location\.search|location\.hash|document\.referrer|document\.URL)[\w.()]*)`)
	reLocationHrefGet       = regexp.MustCompile(`(?i)(?:window\.)?location\.href\s*=\s*\w+\.(?:get|searchParams)`)
)

// GTSS-REDIR-007: Open redirect via form action
var (
	reFormActionVar    = regexp.MustCompile(`(?i)<form\s+[^>]*action\s*=\s*['"]?\s*(?:\$\{|\{\{|<%=|#\{|%s)`)
	reFormActionParam  = regexp.MustCompile(`(?i)(?:action|formAction)\s*[:=]\s*(?:req\.|request\.|params|query|body|searchParams|props\.)`)
)

// GTSS-REDIR-008: Protocol-relative URL redirect
var (
	reProtocolRelative = regexp.MustCompile(`(?i)(?:redirect|location|href|window\.location|res\.redirect|sendRedirect|redirect_to|HttpResponseRedirect)\s*(?:[:=(]\s*)['"]//[^/]`)
	reProtocolRelativeVar = regexp.MustCompile(`(?i)(?:redirect|location|href)\s*[:=]\s*['"]?\s*(?:\$\{|#\{|\+\s*)\s*['"]?//`)
)

// ---------------------------------------------------------------------------
// GTSS-REDIR-003: Open Redirect via Meta Refresh Tag
// ---------------------------------------------------------------------------

type MetaRefreshRedirect struct{}

func (r *MetaRefreshRedirect) ID() string                     { return "GTSS-REDIR-003" }
func (r *MetaRefreshRedirect) Name() string                   { return "MetaRefreshRedirect" }
func (r *MetaRefreshRedirect) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MetaRefreshRedirect) Description() string {
	return "Detects open redirect via HTML meta refresh tag with user-controlled URL, which bypasses server-side redirect protections."
}
func (r *MetaRefreshRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *MetaRefreshRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reMetaRefreshVar.FindString(line); loc != "" {
			matched = loc
		} else if loc := reMetaRefresh.FindString(line); loc != "" {
			// Only flag if there's dynamic content
			if strings.ContainsAny(line, "${}+<%#") {
				matched = loc
			}
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Open redirect via meta refresh tag with dynamic URL",
				Description:   "A meta refresh tag contains a dynamically constructed URL. Attackers can inject a malicious redirect URL that bypasses server-side redirect protections, since the redirect happens client-side via HTML.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Avoid using meta refresh for redirects. Use server-side redirects with URL validation instead. If meta refresh is required, validate the URL against an allowlist before rendering it in the HTML.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"redirect", "meta-refresh", "open-redirect", "cwe-601"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-REDIR-004: Open Redirect via window.location
// ---------------------------------------------------------------------------

type WindowLocationRedirect struct{}

func (r *WindowLocationRedirect) ID() string                     { return "GTSS-REDIR-004" }
func (r *WindowLocationRedirect) Name() string                   { return "WindowLocationRedirect" }
func (r *WindowLocationRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *WindowLocationRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *WindowLocationRedirect) Description() string {
	return "Detects window.location or document.location assignment with user-controlled values, enabling client-side open redirect attacks."
}

func (r *WindowLocationRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reWindowLocation.FindString(line); loc != "" {
			matched = loc
		} else if loc := reWindowLocationGet.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Open redirect via window.location assignment with user input",
				Description:   "window.location or document.location is assigned a value derived from user input (URL parameters, query strings, referrer). An attacker can craft a URL that redirects users to a malicious site.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate redirect URLs before assigning to window.location. Use URL parsing (new URL()) to verify the hostname matches your domain. Reject absolute URLs to external domains. Use a relative path allowlist.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"redirect", "window-location", "xss", "cwe-601"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-REDIR-005: Redirect Using Unvalidated Host Header
// ---------------------------------------------------------------------------

type HostHeaderRedirect struct{}

func (r *HostHeaderRedirect) ID() string                     { return "GTSS-REDIR-005" }
func (r *HostHeaderRedirect) Name() string                   { return "HostHeaderRedirect" }
func (r *HostHeaderRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *HostHeaderRedirect) Description() string {
	return "Detects redirect URLs constructed using the HTTP Host header, which is attacker-controlled and can be used for host header injection attacks."
}
func (r *HostHeaderRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *HostHeaderRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if loc := reHostHeaderRedirect.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Redirect URL constructed from Host header (host header injection)",
				Description:   "A redirect URL is built using the HTTP Host header, which is fully attacker-controlled. This enables host header injection for password reset poisoning, cache poisoning, and open redirect attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Never use the Host header to construct redirect URLs. Use a hardcoded server name from configuration, or validate the Host header against a whitelist of allowed hostnames.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"redirect", "host-header", "injection", "cwe-601"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-REDIR-006: JavaScript Redirect via location.href
// ---------------------------------------------------------------------------

type LocationHrefRedirect struct{}

func (r *LocationHrefRedirect) ID() string                     { return "GTSS-REDIR-006" }
func (r *LocationHrefRedirect) Name() string                   { return "LocationHrefRedirect" }
func (r *LocationHrefRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *LocationHrefRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (r *LocationHrefRedirect) Description() string {
	return "Detects location.href assignment from URL search parameters or other user-controlled sources, enabling DOM-based open redirect."
}

func (r *LocationHrefRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reLocationHrefUserInput.FindString(line); loc != "" {
			matched = loc
		} else if loc := reLocationHrefGet.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "DOM-based open redirect via location.href with URL parameter",
				Description:   "location.href is assigned a value extracted from URL search parameters, hash, or referrer. This is a DOM-based open redirect that executes entirely in the browser, making it harder to detect server-side.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate the URL before redirecting. Parse with new URL() and verify the hostname matches your domain. Reject javascript: and data: URLs. Use a server-side redirect with validation instead.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"redirect", "dom-based", "location-href", "cwe-601"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-REDIR-007: Open Redirect via Form Action
// ---------------------------------------------------------------------------

type FormActionRedirect struct{}

func (r *FormActionRedirect) ID() string                     { return "GTSS-REDIR-007" }
func (r *FormActionRedirect) Name() string                   { return "FormActionRedirect" }
func (r *FormActionRedirect) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FormActionRedirect) Description() string {
	return "Detects form action attributes set from user-controlled input, which can redirect form submissions to attacker-controlled servers."
}
func (r *FormActionRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *FormActionRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reFormActionVar.FindString(line); loc != "" {
			matched = loc
		} else if loc := reFormActionParam.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Form action attribute with user-controlled URL",
				Description:   "A form's action attribute is set from user-controlled input. An attacker can redirect form submissions (including credentials, CSRF tokens, and sensitive data) to an attacker-controlled server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use hardcoded form action URLs. If dynamic actions are needed, validate against an allowlist of permitted endpoints. Never allow arbitrary URLs in form action attributes.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"redirect", "form-action", "credential-theft", "cwe-601"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-REDIR-008: Protocol-Relative URL Redirect
// ---------------------------------------------------------------------------

type ProtocolRelativeRedirect struct{}

func (r *ProtocolRelativeRedirect) ID() string                     { return "GTSS-REDIR-008" }
func (r *ProtocolRelativeRedirect) Name() string                   { return "ProtocolRelativeRedirect" }
func (r *ProtocolRelativeRedirect) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ProtocolRelativeRedirect) Description() string {
	return "Detects redirects using protocol-relative URLs (//evil.com) which redirect to external domains while bypassing URL validation that only checks for http:// or https:// prefixes."
}
func (r *ProtocolRelativeRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *ProtocolRelativeRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reProtocolRelative.FindString(line); loc != "" {
			matched = loc
		} else if loc := reProtocolRelativeVar.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Redirect using protocol-relative URL (//evil.com)",
				Description:   "A redirect target uses a protocol-relative URL (starting with //) which resolves to an external domain. Protocol-relative URLs bypass naive URL validation that only checks for 'http://' or 'https://' prefixes, enabling open redirect attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "When validating redirect URLs, check for protocol-relative URLs (starting with //) in addition to absolute URLs. Parse the URL properly and verify the hostname. Only allow same-origin redirects using relative paths starting with a single /.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"redirect", "protocol-relative", "open-redirect", "cwe-601"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&MetaRefreshRedirect{})
	rules.Register(&WindowLocationRedirect{})
	rules.Register(&HostHeaderRedirect{})
	rules.Register(&LocationHrefRedirect{})
	rules.Register(&FormActionRedirect{})
	rules.Register(&ProtocolRelativeRedirect{})
}
