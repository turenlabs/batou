package cors

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended CORS rules
// ---------------------------------------------------------------------------

// GTSS-CORS-003: CORS allowing null origin
var (
	reNullOrigin      = regexp.MustCompile(`(?i)(?:Access-Control-Allow-Origin|allowedOrigins?|origin)\s*[:=]\s*['"]null['"]`)
	reNullOriginCheck = regexp.MustCompile(`(?i)(?:origin\s*===?\s*['"]null['"]|['"]null['"]\s*===?\s*origin|origin\s*==\s*['"]null['"])`)
)

// GTSS-CORS-004: Too permissive Allow-Methods
var (
	reAllowMethodsAll = regexp.MustCompile(`(?i)Access-Control-Allow-Methods\s*[:'"=]\s*['"]?\s*(?:\*|GET,\s*POST,\s*PUT,\s*DELETE,\s*PATCH,\s*OPTIONS,\s*HEAD)`)
	reMethodsPermissive = regexp.MustCompile(`(?i)(?:allowedMethods|allowed_methods|methods)\s*[:=]\s*(?:\[?\s*['"]?\*['"]?\]?|['"](?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)(?:,\s*(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)){5,}['"])`)
)

// GTSS-CORS-005: Expose-Headers leaking sensitive headers
var (
	reExposeHeaders = regexp.MustCompile(`(?i)Access-Control-Expose-Headers\s*[:'"=]\s*['"]?[^'"]*(?:Authorization|X-API-Key|X-Auth-Token|Set-Cookie|X-CSRF-Token|X-Session-ID)`)
	reExposeSensitive = regexp.MustCompile(`(?i)(?:exposeHeaders|expose_headers|exposedHeaders)\s*[:=]\s*\[[^\]]*(?:Authorization|X-API-Key|X-Auth-Token|Set-Cookie|X-CSRF-Token|X-Session-ID)`)
)

// GTSS-CORS-006: Preflight cache too long
var (
	reMaxAge = regexp.MustCompile(`(?i)(?:Access-Control-Max-Age|maxAge|max_age|MaxAge)\s*[:='"]\s*['"]?(\d+)`)
)

// GTSS-CORS-007: Origin validation regex without anchoring
var (
	reOriginRegexNoAnchor = regexp.MustCompile(`(?i)(?:origin|allowed).*(?:\.test|\.match|RegExp|re\.compile|regexp\.MustCompile)\s*\(\s*[/'"](?:[^^]|[^$])`)
	reOriginRegexFull     = regexp.MustCompile(`(?i)(?:origin|allowed).*(?:\.test|\.match|RegExp)\s*\(`)
	reAnchorPresent       = regexp.MustCompile(`[\^$]`)
)

// GTSS-CORS-008: Origin check using string contains
var (
	reOriginContains = regexp.MustCompile(`(?i)(?:origin|requestOrigin|reqOrigin|request_origin)\s*\.(?:includes|indexOf|contains|search)\s*\(`)
	reOriginEndsWith = regexp.MustCompile(`(?i)(?:origin|requestOrigin|reqOrigin|request_origin)\s*\.endsWith\s*\(`)
)

// ---------------------------------------------------------------------------
// GTSS-CORS-003: CORS Allowing Null Origin
// ---------------------------------------------------------------------------

type CORSNullOrigin struct{}

func (r *CORSNullOrigin) ID() string                     { return "GTSS-CORS-003" }
func (r *CORSNullOrigin) Name() string                   { return "CORSNullOrigin" }
func (r *CORSNullOrigin) DefaultSeverity() rules.Severity { return rules.High }
func (r *CORSNullOrigin) Description() string {
	return "Detects CORS configurations that allow the 'null' origin, which can be exploited via sandboxed iframes and data: URIs."
}
func (r *CORSNullOrigin) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *CORSNullOrigin) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reNullOrigin.FindString(line); loc != "" {
			matched = loc
		} else if loc := reNullOriginCheck.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CORS allows 'null' origin",
				Description:   "The CORS configuration allows the 'null' origin. Attackers can send requests with Origin: null from sandboxed iframes, data: URIs, or local files. This effectively allows any attacker-controlled page to make credentialed cross-origin requests.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Remove 'null' from allowed origins. The null origin is not a legitimate origin for web applications. Use an explicit allowlist of trusted domains.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"cors", "null-origin", "cwe-346"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CORS-004: Access-Control-Allow-Methods Too Permissive
// ---------------------------------------------------------------------------

type CORSMethodsTooPermissive struct{}

func (r *CORSMethodsTooPermissive) ID() string                     { return "GTSS-CORS-004" }
func (r *CORSMethodsTooPermissive) Name() string                   { return "CORSMethodsTooPermissive" }
func (r *CORSMethodsTooPermissive) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CORSMethodsTooPermissive) Description() string {
	return "Detects CORS configurations that allow all or excessively many HTTP methods, increasing the attack surface."
}
func (r *CORSMethodsTooPermissive) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *CORSMethodsTooPermissive) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reAllowMethodsAll.FindString(line); loc != "" {
			matched = loc
		} else if loc := reMethodsPermissive.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CORS Access-Control-Allow-Methods too permissive",
				Description:   "The CORS configuration allows all or most HTTP methods. This increases the attack surface by enabling cross-origin PUT, DELETE, and PATCH requests that may not be intended. Each allowed method should be explicitly required.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Only allow the HTTP methods actually needed by your API. For most endpoints, GET and POST are sufficient. Remove DELETE, PUT, PATCH unless specifically required for cross-origin use.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"cors", "methods", "permissive", "cwe-346"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CORS-005: Expose-Headers Leaking Sensitive Headers
// ---------------------------------------------------------------------------

type CORSExposeHeadersLeak struct{}

func (r *CORSExposeHeadersLeak) ID() string                     { return "GTSS-CORS-005" }
func (r *CORSExposeHeadersLeak) Name() string                   { return "CORSExposeHeadersLeak" }
func (r *CORSExposeHeadersLeak) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CORSExposeHeadersLeak) Description() string {
	return "Detects CORS configurations that expose sensitive response headers (Authorization, Set-Cookie, API keys) to cross-origin requests."
}
func (r *CORSExposeHeadersLeak) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *CORSExposeHeadersLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reExposeHeaders.FindString(line); loc != "" {
			matched = loc
		} else if loc := reExposeSensitive.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CORS exposes sensitive response headers to cross-origin requests",
				Description:   "Access-Control-Expose-Headers includes sensitive headers like Authorization, Set-Cookie, or API key headers. These headers will be readable by JavaScript in cross-origin responses, potentially leaking authentication tokens or session identifiers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Only expose headers that are specifically needed by cross-origin JavaScript. Never expose Authorization, Set-Cookie, X-API-Key, or session-related headers. Use application-specific non-sensitive headers instead.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"cors", "expose-headers", "information-disclosure", "cwe-200"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CORS-006: Preflight Cache Too Long
// ---------------------------------------------------------------------------

type CORSPreflightCacheTooLong struct{}

func (r *CORSPreflightCacheTooLong) ID() string                     { return "GTSS-CORS-006" }
func (r *CORSPreflightCacheTooLong) Name() string                   { return "CORSPreflightCacheTooLong" }
func (r *CORSPreflightCacheTooLong) DefaultSeverity() rules.Severity { return rules.Low }
func (r *CORSPreflightCacheTooLong) Description() string {
	return "Detects CORS Access-Control-Max-Age set to excessively long values, which delays CORS policy change propagation."
}
func (r *CORSPreflightCacheTooLong) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *CORSPreflightCacheTooLong) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matches := reMaxAge.FindStringSubmatch(line)
		if len(matches) >= 2 {
			// Parse the number and check if > 86400 (24 hours)
			val := 0
			for _, c := range matches[1] {
				val = val*10 + int(c-'0')
				if val > 1000000 {
					break
				}
			}
			if val > 86400 {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "CORS preflight cache duration too long (Access-Control-Max-Age)",
					Description:   "Access-Control-Max-Age is set to a very long value (over 24 hours). This means CORS policy changes will not take effect for cached preflight responses until the cache expires, creating a window where revoked origins retain access.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Set Access-Control-Max-Age to a reasonable value (e.g., 3600 for 1 hour, or 86400 for 24 hours). This balances performance (fewer preflight requests) with the ability to update CORS policy in a timely manner.",
					CWEID:         "CWE-346",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"cors", "max-age", "preflight", "cwe-346"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CORS-007: Origin Validation Regex Without Anchoring
// ---------------------------------------------------------------------------

type CORSOriginRegexNoAnchor struct{}

func (r *CORSOriginRegexNoAnchor) ID() string                     { return "GTSS-CORS-007" }
func (r *CORSOriginRegexNoAnchor) Name() string                   { return "CORSOriginRegexNoAnchor" }
func (r *CORSOriginRegexNoAnchor) DefaultSeverity() rules.Severity { return rules.High }
func (r *CORSOriginRegexNoAnchor) Description() string {
	return "Detects CORS origin validation using regex patterns without proper start/end anchors, allowing bypasses via subdomains or path manipulation."
}
func (r *CORSOriginRegexNoAnchor) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo}
}

func (r *CORSOriginRegexNoAnchor) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		if reOriginRegexFull.MatchString(line) && !reAnchorPresent.MatchString(line) {
			matched := reOriginRegexFull.FindString(line)
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CORS origin validated with unanchored regex",
				Description:   "Origin validation uses a regex without ^ and $ anchors. An attacker can bypass this by using a subdomain (e.g., trusted.com.evil.com) or by appending the trusted domain as a subdirectory. The regex /trusted\\.com/ would match 'evil-trusted.com'.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Always anchor origin validation regexes with ^ and $: /^https:\\/\\/trusted\\.example\\.com$/. Better yet, use exact string comparison against an allowlist of origins.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"cors", "regex", "origin-bypass", "cwe-346"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CORS-008: Origin Check Using String Contains
// ---------------------------------------------------------------------------

type CORSOriginContainsCheck struct{}

func (r *CORSOriginContainsCheck) ID() string                     { return "GTSS-CORS-008" }
func (r *CORSOriginContainsCheck) Name() string                   { return "CORSOriginContainsCheck" }
func (r *CORSOriginContainsCheck) DefaultSeverity() rules.Severity { return rules.High }
func (r *CORSOriginContainsCheck) Description() string {
	return "Detects CORS origin validation using string includes/contains/indexOf instead of exact match, which can be trivially bypassed."
}
func (r *CORSOriginContainsCheck) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangJava, rules.LangRuby, rules.LangPHP}
}

func (r *CORSOriginContainsCheck) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isComment(strings.TrimSpace(line)) {
			continue
		}
		matched := ""
		if loc := reOriginContains.FindString(line); loc != "" {
			matched = loc
		} else if loc := reOriginEndsWith.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CORS origin validated with string contains instead of exact match",
				Description:   "Origin is validated using includes/indexOf/contains/endsWith, which can be bypassed. For example, origin.includes('trusted.com') matches 'evil-trusted.com' and 'trusted.com.evil.com'. Even endsWith can be bypassed: 'eviltrusted.com'.endsWith('trusted.com') is true.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use exact string comparison for origin validation: origin === 'https://trusted.com'. Or parse the URL and compare the hostname exactly. Maintain an explicit Set/array of allowed origins and check membership.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"cors", "origin-bypass", "string-contains", "cwe-346"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&CORSNullOrigin{})
	rules.Register(&CORSMethodsTooPermissive{})
	rules.Register(&CORSExposeHeadersLeak{})
	rules.Register(&CORSPreflightCacheTooLong{})
	rules.Register(&CORSOriginRegexNoAnchor{})
	rules.Register(&CORSOriginContainsCheck{})
}
