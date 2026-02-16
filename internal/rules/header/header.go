package header

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-HDR-001: Missing Content-Security-Policy
var (
	reResponseHeaders = regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.set|\.Header\(\)\.Set|\.add_header|response\[|headers\[)\s*\(?\s*["']`)
	reCSPHeader       = regexp.MustCompile(`(?i)["']Content-Security-Policy["']`)
	reHelmetCSP       = regexp.MustCompile(`(?i)(?:helmet\.contentSecurityPolicy|csp\s*\(|contentSecurityPolicy\s*\()`)
	reMetaCSP         = regexp.MustCompile(`(?i)<meta\s+http-equiv\s*=\s*["']Content-Security-Policy["']`)
)

// BATOU-HDR-002: Missing X-Frame-Options
var (
	reXFrameHeader = regexp.MustCompile(`(?i)["']X-Frame-Options["']`)
	reHelmetFrame  = regexp.MustCompile(`(?i)helmet\.frameguard|frameguard\s*\(`)
	reCSPFrameAnc  = regexp.MustCompile(`(?i)frame-ancestors`)
)

// BATOU-HDR-003: Missing X-Content-Type-Options
var (
	reXCTOHeader  = regexp.MustCompile(`(?i)["']X-Content-Type-Options["']`)
	reHelmetXCTO  = regexp.MustCompile(`(?i)helmet\.noSniff|noSniff\s*\(`)
)

// BATOU-HDR-004: Missing Strict-Transport-Security
var (
	reHSTSHeader  = regexp.MustCompile(`(?i)["']Strict-Transport-Security["']`)
	reHelmetHSTS  = regexp.MustCompile(`(?i)helmet\.hsts|hsts\s*\(`)
)

// BATOU-HDR-005: Permissive CSP (unsafe-inline / unsafe-eval)
var (
	reCSPUnsafe = regexp.MustCompile(`(?i)(?:unsafe-inline|unsafe-eval)`)
	reCSPCtx    = regexp.MustCompile(`(?i)(?:Content-Security-Policy|contentSecurityPolicy|csp|script-src|style-src|default-src)`)
)

// BATOU-HDR-006: Missing X-XSS-Protection
var (
	reXXSSHeader = regexp.MustCompile(`(?i)["']X-XSS-Protection["']`)
)

// BATOU-HDR-007: Missing Referrer-Policy
var (
	reReferrerHeader = regexp.MustCompile(`(?i)["']Referrer-Policy["']`)
	reHelmetReferrer = regexp.MustCompile(`(?i)helmet\.referrerPolicy|referrerPolicy\s*\(`)
)

// BATOU-HDR-008: Missing Permissions-Policy
var (
	rePermPolicyHeader = regexp.MustCompile(`(?i)["']Permissions-Policy["']`)
	reFeaturePolicyH   = regexp.MustCompile(`(?i)["']Feature-Policy["']`)
	reHelmetPermPolicy = regexp.MustCompile(`(?i)helmet\.permittedCrossDomainPolicies|permissionsPolicy\s*\(`)
)

// BATOU-HDR-009: Cache-Control missing no-store
var (
	reCacheControl    = regexp.MustCompile(`(?i)["']Cache-Control["']`)
	reCacheNoStore    = regexp.MustCompile(`(?i)no-store`)
	reSensitivePath   = regexp.MustCompile(`(?i)(?:login|auth|account|profile|admin|dashboard|settings|password|token|session|checkout|payment|billing)`)
)

// BATOU-HDR-010: Server header disclosure
var (
	reServerHeader    = regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.set|\.Header\(\)\.Set|response\[|headers\[)\s*\(?\s*["']Server["']`)
	reServerRemove    = regexp.MustCompile(`(?i)(?:removeHeader|delete|remove|unset)\s*\(?\s*["']Server["']`)
	reHelmetHidePower = regexp.MustCompile(`(?i)helmet\.hidePoweredBy|hidePoweredBy\s*\(`)
)

// BATOU-HDR-011: X-Powered-By disclosure
var (
	reXPoweredByHeader = regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.set|\.Header\(\)\.Set|response\[|headers\[)\s*\(?\s*["']X-Powered-By["']`)
	reXPoweredByRemove = regexp.MustCompile(`(?i)(?:removeHeader|delete|remove|unset|disable)\s*\(?\s*["'](?:X-Powered-By|x-powered-by)["']`)
	reExpressDisable   = regexp.MustCompile(`(?i)app\.disable\s*\(\s*["']x-powered-by["']\s*\)`)
)

// BATOU-HDR-012: CRLF injection in header value
var (
	reCRLFHeaderInject = regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.set|\.Header\(\)\.Set|\.add_header|response\.headers)\s*\(?\s*["'][^"']+["']\s*[,]\s*(?:req\.|request\.|params\.|query\.|body\.|args\.|GET\[|POST\[|\$_)`)
	reCRLFDirectConcat = regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.set|\.Header\(\)\.Set)\s*\(\s*["'][^"']+["']\s*,\s*["'][^"']*["']\s*\+\s*(?:req\.|request\.|params|query|body)`)
	reCRLFPHPHeader    = regexp.MustCompile(`(?i)\bheader\s*\(\s*["'][^"']*:\s*["']\s*\.\s*\$(?:_GET|_POST|_REQUEST|_SERVER|input)`)
)

// ---------------------------------------------------------------------------
// Helpers (package-scoped)
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
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

// isHTTPHandlerFile checks if a file likely contains HTTP handler/route code.
func isHTTPHandlerFile(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "http") ||
		strings.Contains(lower, "request") ||
		strings.Contains(lower, "response") ||
		strings.Contains(lower, "handler") ||
		strings.Contains(lower, "router") ||
		strings.Contains(lower, "app.") ||
		strings.Contains(lower, "express") ||
		strings.Contains(lower, "flask") ||
		strings.Contains(lower, "django") ||
		strings.Contains(lower, "servlet")
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&MissingCSP{})
	rules.Register(&MissingXFrameOptions{})
	rules.Register(&MissingXContentTypeOptions{})
	rules.Register(&MissingHSTS{})
	rules.Register(&PermissiveCSP{})
	rules.Register(&MissingXXSSProtection{})
	rules.Register(&MissingReferrerPolicy{})
	rules.Register(&MissingPermissionsPolicy{})
	rules.Register(&CacheControlSensitive{})
	rules.Register(&ServerHeaderDisclosure{})
	rules.Register(&XPoweredByDisclosure{})
	rules.Register(&CRLFHeaderInjection{})
}

// ---------------------------------------------------------------------------
// BATOU-HDR-001: Missing Content-Security-Policy
// ---------------------------------------------------------------------------

type MissingCSP struct{}

func (r *MissingCSP) ID() string                     { return "BATOU-HDR-001" }
func (r *MissingCSP) Name() string                   { return "MissingCSP" }
func (r *MissingCSP) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingCSP) Description() string {
	return "Detects HTTP handler files that set response headers but do not include a Content-Security-Policy header, leaving the application vulnerable to XSS and data injection attacks."
}
func (r *MissingCSP) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *MissingCSP) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isHTTPHandlerFile(ctx.Content) {
		return nil
	}
	// Check if any response headers are being set
	if !reResponseHeaders.MatchString(ctx.Content) {
		return nil
	}
	// Check if CSP is already set
	if reCSPHeader.MatchString(ctx.Content) || reHelmetCSP.MatchString(ctx.Content) || reMetaCSP.MatchString(ctx.Content) {
		return nil
	}

	// Find the first header-setting line to anchor the finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reResponseHeaders.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing Content-Security-Policy header",
				Description:   "This file sets HTTP response headers but does not include a Content-Security-Policy (CSP) header. CSP mitigates XSS by restricting which scripts, styles, and resources the browser is allowed to load.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Add a Content-Security-Policy header. Start with a restrictive policy like \"default-src 'self'\" and loosen as needed. Consider using helmet.js (Node) or django-csp (Python).",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"header", "csp", "xss-prevention"},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BATOU-HDR-002: Missing X-Frame-Options
// ---------------------------------------------------------------------------

type MissingXFrameOptions struct{}

func (r *MissingXFrameOptions) ID() string                     { return "BATOU-HDR-002" }
func (r *MissingXFrameOptions) Name() string                   { return "MissingXFrameOptions" }
func (r *MissingXFrameOptions) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingXFrameOptions) Description() string {
	return "Detects HTTP handler files missing X-Frame-Options header, leaving the application vulnerable to clickjacking attacks."
}
func (r *MissingXFrameOptions) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *MissingXFrameOptions) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isHTTPHandlerFile(ctx.Content) || !reResponseHeaders.MatchString(ctx.Content) {
		return nil
	}
	if reXFrameHeader.MatchString(ctx.Content) || reHelmetFrame.MatchString(ctx.Content) || reCSPFrameAnc.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reResponseHeaders.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing X-Frame-Options header",
				Description:   "This file sets HTTP response headers but does not include X-Frame-Options or CSP frame-ancestors directive. Without this, the page can be embedded in iframes for clickjacking attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Add X-Frame-Options: DENY (or SAMEORIGIN if framing is needed). Alternatively, use CSP frame-ancestors directive.",
				CWEID:         "CWE-1021",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"header", "clickjacking"},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BATOU-HDR-003: Missing X-Content-Type-Options
// ---------------------------------------------------------------------------

type MissingXContentTypeOptions struct{}

func (r *MissingXContentTypeOptions) ID() string                     { return "BATOU-HDR-003" }
func (r *MissingXContentTypeOptions) Name() string                   { return "MissingXContentTypeOptions" }
func (r *MissingXContentTypeOptions) DefaultSeverity() rules.Severity { return rules.Low }
func (r *MissingXContentTypeOptions) Description() string {
	return "Detects HTTP handler files missing X-Content-Type-Options: nosniff header, which prevents MIME-type sniffing attacks."
}
func (r *MissingXContentTypeOptions) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *MissingXContentTypeOptions) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isHTTPHandlerFile(ctx.Content) || !reResponseHeaders.MatchString(ctx.Content) {
		return nil
	}
	if reXCTOHeader.MatchString(ctx.Content) || reHelmetXCTO.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reResponseHeaders.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing X-Content-Type-Options header",
				Description:   "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses and execute content as a different type than declared, enabling attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Add the header X-Content-Type-Options: nosniff to all responses.",
				CWEID:         "CWE-16",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"header", "mime-sniffing"},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BATOU-HDR-004: Missing Strict-Transport-Security
// ---------------------------------------------------------------------------

type MissingHSTS struct{}

func (r *MissingHSTS) ID() string                     { return "BATOU-HDR-004" }
func (r *MissingHSTS) Name() string                   { return "MissingHSTS" }
func (r *MissingHSTS) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingHSTS) Description() string {
	return "Detects HTTP handler files missing Strict-Transport-Security (HSTS) header, leaving the application vulnerable to SSL-stripping attacks."
}
func (r *MissingHSTS) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *MissingHSTS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isHTTPHandlerFile(ctx.Content) || !reResponseHeaders.MatchString(ctx.Content) {
		return nil
	}
	if reHSTSHeader.MatchString(ctx.Content) || reHelmetHSTS.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reResponseHeaders.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing Strict-Transport-Security (HSTS) header",
				Description:   "Without HSTS, browsers may connect over plain HTTP on the first visit, enabling SSL-stripping man-in-the-middle attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to enforce HTTPS. Consider HSTS preloading.",
				CWEID:         "CWE-319",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"header", "hsts", "transport-security"},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BATOU-HDR-005: Permissive CSP (unsafe-inline / unsafe-eval)
// ---------------------------------------------------------------------------

type PermissiveCSP struct{}

func (r *PermissiveCSP) ID() string                     { return "BATOU-HDR-005" }
func (r *PermissiveCSP) Name() string                   { return "PermissiveCSP" }
func (r *PermissiveCSP) DefaultSeverity() rules.Severity { return rules.High }
func (r *PermissiveCSP) Description() string {
	return "Detects Content-Security-Policy headers that include 'unsafe-inline' or 'unsafe-eval', which largely negate the XSS protection CSP provides."
}
func (r *PermissiveCSP) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangAny}
}

func (r *PermissiveCSP) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if !reCSPUnsafe.MatchString(line) {
			continue
		}
		// Only flag if in a CSP context
		if !reCSPCtx.MatchString(line) && !reCSPCtx.MatchString(nearbyLines(lines, i, 3)) {
			continue
		}

		m := reCSPUnsafe.FindString(line)
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Permissive Content-Security-Policy: " + m,
			Description:   "Using '" + m + "' in Content-Security-Policy defeats the purpose of CSP by allowing inline script execution or eval(), which are the primary attack vectors for XSS.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(trimmed, 120),
			Suggestion:    "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonce-based or hash-based CSP for inline scripts. Refactor code to avoid eval().",
			CWEID:         "CWE-693",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"header", "csp", "xss-prevention"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-HDR-006: Missing X-XSS-Protection (legacy)
// ---------------------------------------------------------------------------

type MissingXXSSProtection struct{}

func (r *MissingXXSSProtection) ID() string                     { return "BATOU-HDR-006" }
func (r *MissingXXSSProtection) Name() string                   { return "MissingXXSSProtection" }
func (r *MissingXXSSProtection) DefaultSeverity() rules.Severity { return rules.Low }
func (r *MissingXXSSProtection) Description() string {
	return "Detects HTTP handler files missing X-XSS-Protection header. While deprecated in modern browsers, it provides defense-in-depth for older browsers."
}
func (r *MissingXXSSProtection) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *MissingXXSSProtection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isHTTPHandlerFile(ctx.Content) || !reResponseHeaders.MatchString(ctx.Content) {
		return nil
	}
	if reXXSSHeader.MatchString(ctx.Content) {
		return nil
	}
	// Only flag if CSP is also not present (CSP replaces X-XSS-Protection)
	if reCSPHeader.MatchString(ctx.Content) || reHelmetCSP.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reResponseHeaders.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing X-XSS-Protection header (legacy browsers)",
				Description:   "X-XSS-Protection is deprecated in modern browsers but provides defense-in-depth for Internet Explorer and older Edge versions. Prefer Content-Security-Policy for modern protection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Add X-XSS-Protection: 0 (to disable the buggy auditor) or implement Content-Security-Policy instead.",
				CWEID:         "CWE-79",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"header", "xss-protection", "legacy"},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BATOU-HDR-007: Missing Referrer-Policy
// ---------------------------------------------------------------------------

type MissingReferrerPolicy struct{}

func (r *MissingReferrerPolicy) ID() string                     { return "BATOU-HDR-007" }
func (r *MissingReferrerPolicy) Name() string                   { return "MissingReferrerPolicy" }
func (r *MissingReferrerPolicy) DefaultSeverity() rules.Severity { return rules.Low }
func (r *MissingReferrerPolicy) Description() string {
	return "Detects HTTP handler files missing Referrer-Policy header, which can leak sensitive URL information (tokens, session IDs) to third parties via the Referer header."
}
func (r *MissingReferrerPolicy) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *MissingReferrerPolicy) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isHTTPHandlerFile(ctx.Content) || !reResponseHeaders.MatchString(ctx.Content) {
		return nil
	}
	if reReferrerHeader.MatchString(ctx.Content) || reHelmetReferrer.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reResponseHeaders.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing Referrer-Policy header",
				Description:   "Without Referrer-Policy, browsers send the full URL (potentially including tokens and session IDs) in the Referer header when navigating to external sites.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Add Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy).",
				CWEID:         "CWE-200",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"header", "referrer-policy", "information-disclosure"},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BATOU-HDR-008: Missing Permissions-Policy
// ---------------------------------------------------------------------------

type MissingPermissionsPolicy struct{}

func (r *MissingPermissionsPolicy) ID() string                     { return "BATOU-HDR-008" }
func (r *MissingPermissionsPolicy) Name() string                   { return "MissingPermissionsPolicy" }
func (r *MissingPermissionsPolicy) DefaultSeverity() rules.Severity { return rules.Low }
func (r *MissingPermissionsPolicy) Description() string {
	return "Detects HTTP handler files missing Permissions-Policy header, which controls access to browser features like camera, microphone, and geolocation."
}
func (r *MissingPermissionsPolicy) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *MissingPermissionsPolicy) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isHTTPHandlerFile(ctx.Content) || !reResponseHeaders.MatchString(ctx.Content) {
		return nil
	}
	if rePermPolicyHeader.MatchString(ctx.Content) || reFeaturePolicyH.MatchString(ctx.Content) || reHelmetPermPolicy.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reResponseHeaders.MatchString(line) {
			return []rules.Finding{{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing Permissions-Policy header",
				Description:   "Without Permissions-Policy, the page can access powerful browser APIs (camera, microphone, geolocation) that may be exploited if XSS occurs.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Add Permissions-Policy header to restrict browser feature access, e.g., Permissions-Policy: camera=(), microphone=(), geolocation=().",
				CWEID:         "CWE-16",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"header", "permissions-policy"},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// BATOU-HDR-009: Cache-Control missing no-store for sensitive pages
// ---------------------------------------------------------------------------

type CacheControlSensitive struct{}

func (r *CacheControlSensitive) ID() string                     { return "BATOU-HDR-009" }
func (r *CacheControlSensitive) Name() string                   { return "CacheControlSensitive" }
func (r *CacheControlSensitive) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CacheControlSensitive) Description() string {
	return "Detects sensitive pages (login, auth, account) that set Cache-Control but do not include no-store, potentially caching sensitive data in browsers or proxies."
}
func (r *CacheControlSensitive) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *CacheControlSensitive) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only flag in files that handle sensitive routes
	if !reSensitivePath.MatchString(ctx.FilePath) && !reSensitivePath.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if !reCacheControl.MatchString(line) {
			continue
		}
		if reCacheNoStore.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Cache-Control missing no-store on sensitive page",
			Description:   "Sensitive page responses should include Cache-Control: no-store to prevent browsers and proxies from caching potentially sensitive data such as authentication tokens, personal information, or financial data.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(trimmed, 120),
			Suggestion:    "Use Cache-Control: no-store, no-cache, must-revalidate for sensitive responses.",
			CWEID:         "CWE-525",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"header", "caching", "sensitive-data"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-HDR-010: Server header information disclosure
// ---------------------------------------------------------------------------

type ServerHeaderDisclosure struct{}

func (r *ServerHeaderDisclosure) ID() string                     { return "BATOU-HDR-010" }
func (r *ServerHeaderDisclosure) Name() string                   { return "ServerHeaderDisclosure" }
func (r *ServerHeaderDisclosure) DefaultSeverity() rules.Severity { return rules.Low }
func (r *ServerHeaderDisclosure) Description() string {
	return "Detects code that explicitly sets the Server response header, which discloses web server software and version information useful for targeted attacks."
}
func (r *ServerHeaderDisclosure) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *ServerHeaderDisclosure) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Don't flag if the Server header is being removed
	if reServerRemove.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if !reServerHeader.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Server header information disclosure",
			Description:   "The Server header reveals web server software and version information, helping attackers identify known vulnerabilities for the specific server version.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(trimmed, 120),
			Suggestion:    "Remove or suppress the Server header. Most web frameworks allow disabling it via configuration.",
			CWEID:         "CWE-200",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"header", "information-disclosure"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-HDR-011: X-Powered-By header information disclosure
// ---------------------------------------------------------------------------

type XPoweredByDisclosure struct{}

func (r *XPoweredByDisclosure) ID() string                     { return "BATOU-HDR-011" }
func (r *XPoweredByDisclosure) Name() string                   { return "XPoweredByDisclosure" }
func (r *XPoweredByDisclosure) DefaultSeverity() rules.Severity { return rules.Low }
func (r *XPoweredByDisclosure) Description() string {
	return "Detects code that explicitly sets the X-Powered-By response header, which discloses the application framework and aids attackers in targeting framework-specific vulnerabilities."
}
func (r *XPoweredByDisclosure) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *XPoweredByDisclosure) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Don't flag if being removed
	if reXPoweredByRemove.MatchString(ctx.Content) || reExpressDisable.MatchString(ctx.Content) || reHelmetHidePower.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if !reXPoweredByHeader.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "X-Powered-By header information disclosure",
			Description:   "The X-Powered-By header reveals the application framework (e.g., Express, PHP), helping attackers target framework-specific vulnerabilities.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(trimmed, 120),
			Suggestion:    "Remove the X-Powered-By header. In Express, use app.disable('x-powered-by') or helmet.hidePoweredBy(). In PHP, set expose_php=Off in php.ini.",
			CWEID:         "CWE-200",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"header", "information-disclosure"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-HDR-012: CRLF injection in header value
// ---------------------------------------------------------------------------

type CRLFHeaderInjection struct{}

func (r *CRLFHeaderInjection) ID() string                     { return "BATOU-HDR-012" }
func (r *CRLFHeaderInjection) Name() string                   { return "CRLFHeaderInjection" }
func (r *CRLFHeaderInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *CRLFHeaderInjection) Description() string {
	return "Detects HTTP response headers set with user-controlled values, enabling CRLF injection for HTTP response splitting, header injection, and cache poisoning."
}
func (r *CRLFHeaderInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *CRLFHeaderInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	patterns := []*regexp.Regexp{reCRLFHeaderInject, reCRLFDirectConcat, reCRLFPHPHeader}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, pat := range patterns {
			if m := pat.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "CRLF injection in HTTP response header (response splitting)",
					Description:   "User-controlled input is used in an HTTP response header value without sanitization. An attacker can inject \\r\\n (CRLF) sequences to split the HTTP response, inject arbitrary headers, or inject a response body for XSS.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Sanitize header values by stripping or rejecting \\r and \\n characters. Use framework-provided header methods that auto-sanitize. Never pass raw user input as header values.",
					CWEID:         "CWE-113",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"header", "crlf", "response-splitting", "injection"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func nearbyLines(lines []string, idx, window int) string {
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
