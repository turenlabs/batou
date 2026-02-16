package redirect

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// --- Compiled patterns ---

// BATOU-REDIR-001: Server redirect with user input
var (
	// Go: http.Redirect with user input variable
	reGoRedirectUserInput = regexp.MustCompile(`http\.Redirect\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*`)
	reGoUserInputSource   = regexp.MustCompile(`r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue|Form\.Get)\s*\(`)

	// Python: redirect/HttpResponseRedirect with request input
	rePyRedirectUserInput   = regexp.MustCompile(`(?:redirect|HttpResponseRedirect|HttpResponse)\s*\(\s*(?:request\.(?:GET|POST|args|params)|[a-zA-Z_]\w*)`)
	rePyRequestSource       = regexp.MustCompile(`request\.(?:GET|POST|args|params|data)\b`)

	// JS/TS: res.redirect with variable or req input
	reJSRedirectDirect      = regexp.MustCompile(`res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\b)`)
	reJSRedirectVar         = regexp.MustCompile(`res\.redirect\s*\(\s*[a-zA-Z_]\w*`)
	reJSUserInputSource     = regexp.MustCompile(`req\.(?:query|params|body)\b`)

	// PHP: header("Location: ...") with user input
	rePHPHeaderLocation     = regexp.MustCompile(`header\s*\(\s*['"]Location:\s*['"]?\s*\.?\s*\$`)
	rePHPDirectUserInput    = regexp.MustCompile(`\$_(?:GET|POST|REQUEST)\b`)

	// Ruby: redirect_to with params
	reRubyRedirectTo        = regexp.MustCompile(`redirect_to\s+(?:params\[|.*params\.)`)

	// Java: sendRedirect with user input
	reJavaSendRedirect      = regexp.MustCompile(`(?:response|res)\.sendRedirect\s*\(\s*(?:request\.getParameter|[a-zA-Z_]\w*)`)
	reJavaRequestSource     = regexp.MustCompile(`request\.getParameter\s*\(`)

	// Django: HttpResponseRedirect with request.GET
	reDjangoRedirect        = regexp.MustCompile(`HttpResponseRedirect\s*\(\s*request\.GET`)
)

// BATOU-REDIR-002: Bypassable URL allowlist
var (
	// url.includes("allowed.com") — can be bypassed with "allowed.com.evil.com"
	reJSURLIncludes       = regexp.MustCompile(`(?:url|href|redirect|target|dest|location|link)\w*\.includes\s*\(\s*['"]`)
	// url.indexOf("allowed.com") !== -1
	reJSURLIndexOf        = regexp.MustCompile(`(?:url|href|redirect|target|dest|location|link)\w*\.indexOf\s*\(\s*['"]`)
	// url.startsWith("http") — allows any http URL
	reJSURLStartsWithHTTP = regexp.MustCompile(`(?:url|href|redirect|target|dest|location|link)\w*\.startsWith\s*\(\s*['"]https?`)
	// Python: "allowed.com" in url
	rePyInOperator        = regexp.MustCompile(`['"][a-zA-Z0-9.-]+['"]\s+in\s+(?:url|href|redirect|target|dest|location|link)`)
	// Generic: regex test without anchoring
	reGenericRegexTest    = regexp.MustCompile(`(?:url|href|redirect|target|dest|location|link)\w*\.(?:match|test|search)\s*\(\s*(?:/[^$]|['"])`)
)

func init() {
	rules.Register(&ServerRedirectUserInput{})
	rules.Register(&BypassableURLAllowlist{})
}

// --- BATOU-REDIR-001: Server Redirect With User Input ---

type ServerRedirectUserInput struct{}

func (r *ServerRedirectUserInput) ID() string                     { return "BATOU-REDIR-001" }
func (r *ServerRedirectUserInput) Name() string                   { return "ServerRedirectUserInput" }
func (r *ServerRedirectUserInput) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ServerRedirectUserInput) Description() string {
	return "Detects server-side redirects where the destination URL is derived from user input, enabling open redirect attacks for phishing."
}
func (r *ServerRedirectUserInput) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript,
		rules.LangTypeScript, rules.LangPHP, rules.LangRuby, rules.LangJava,
	}
}

func (r *ServerRedirectUserInput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var confidence string

		switch ctx.Language {
		case rules.LangGo:
			matched, confidence = r.scanGoLine(line, lines, i)
		case rules.LangPython:
			matched, confidence = r.scanPythonLine(line, lines, i)
		case rules.LangJavaScript, rules.LangTypeScript:
			matched, confidence = r.scanJSLine(line, lines, i)
		case rules.LangPHP:
			matched, confidence = r.scanPHPLine(line)
		case rules.LangRuby:
			matched, confidence = r.scanRubyLine(line)
		case rules.LangJava:
			matched, confidence = r.scanJavaLine(line, lines, i)
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Server redirect with user-controlled URL (open redirect)",
				Description:   "The redirect destination URL is derived from user input without proper validation. An attacker can craft a URL that redirects users to a malicious site for phishing or credential theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate redirect URLs against a strict allowlist of permitted destinations. Use relative paths only, or verify the URL's host matches your domain. Reject absolute URLs to external domains.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"redirect", "open-redirect", "phishing", "user-input"},
			})
		}
	}

	return findings
}

func (r *ServerRedirectUserInput) scanGoLine(line string, lines []string, idx int) (string, string) {
	if m := reGoRedirectUserInput.FindString(line); m != "" {
		// High confidence if user input source is nearby
		if hasNearbyPattern(lines, idx, reGoUserInputSource, 15) {
			return m, "high"
		}
		// Lower confidence without direct user input evidence
		return "", ""
	}
	return "", ""
}

func (r *ServerRedirectUserInput) scanPythonLine(line string, lines []string, idx int) (string, string) {
	if m := reDjangoRedirect.FindString(line); m != "" {
		return m, "high"
	}
	if m := rePyRedirectUserInput.FindString(line); m != "" {
		if rePyRequestSource.MatchString(line) || hasNearbyPattern(lines, idx, rePyRequestSource, 10) {
			return m, "high"
		}
	}
	return "", ""
}

func (r *ServerRedirectUserInput) scanJSLine(line string, lines []string, idx int) (string, string) {
	if m := reJSRedirectDirect.FindString(line); m != "" {
		return m, "high"
	}
	if m := reJSRedirectVar.FindString(line); m != "" {
		if hasNearbyPattern(lines, idx, reJSUserInputSource, 15) {
			return m, "high"
		}
	}
	return "", ""
}

func (r *ServerRedirectUserInput) scanPHPLine(line string) (string, string) {
	if m := rePHPHeaderLocation.FindString(line); m != "" {
		if rePHPDirectUserInput.MatchString(line) {
			return m, "high"
		}
		return m, "medium"
	}
	return "", ""
}

func (r *ServerRedirectUserInput) scanRubyLine(line string) (string, string) {
	if m := reRubyRedirectTo.FindString(line); m != "" {
		return m, "high"
	}
	return "", ""
}

func (r *ServerRedirectUserInput) scanJavaLine(line string, lines []string, idx int) (string, string) {
	if m := reJavaSendRedirect.FindString(line); m != "" {
		if reJavaRequestSource.MatchString(line) || hasNearbyPattern(lines, idx, reJavaRequestSource, 10) {
			return m, "high"
		}
		return m, "medium"
	}
	return "", ""
}

// --- BATOU-REDIR-002: Bypassable URL Allowlist ---

type BypassableURLAllowlist struct{}

func (r *BypassableURLAllowlist) ID() string                     { return "BATOU-REDIR-002" }
func (r *BypassableURLAllowlist) Name() string                   { return "BypassableURLAllowlist" }
func (r *BypassableURLAllowlist) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *BypassableURLAllowlist) Description() string {
	return "Detects URL validation patterns that can be bypassed (e.g., url.includes('allowed.com') can be bypassed with 'allowed.com.evil.com')."
}
func (r *BypassableURLAllowlist) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript, rules.LangPython,
	}
}

func (r *BypassableURLAllowlist) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Only flag bypassable allowlists in files that also have redirects
	if !hasRedirectContext(ctx.Content) {
		return nil
	}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var detail string

		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript:
			if m := reJSURLIncludes.FindString(line); m != "" {
				matched = m
				detail = "url.includes('domain') can be bypassed with subdomains or path manipulation (e.g., 'allowed.com.evil.com' or 'evil.com/allowed.com'). Use URL parsing and exact host comparison instead."
			} else if m := reJSURLIndexOf.FindString(line); m != "" {
				matched = m
				detail = "url.indexOf('domain') can be bypassed with subdomains or path manipulation. Use URL parsing and exact host comparison instead."
			} else if m := reJSURLStartsWithHTTP.FindString(line); m != "" {
				matched = m
				detail = "url.startsWith('http') allows any HTTP/HTTPS URL including malicious ones. Validate the host portion against an allowlist instead."
			}
		case rules.LangPython:
			if m := rePyInOperator.FindString(line); m != "" {
				matched = m
				detail = "'domain' in url can be bypassed with subdomains or path manipulation. Use urllib.parse.urlparse() and compare the netloc against an allowlist."
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Bypassable URL allowlist check",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Parse the URL properly (new URL() in JS, urllib.parse.urlparse() in Python) and compare the hostname exactly against an allowlist. Ensure no path or subdomain tricks can bypass the check.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"redirect", "allowlist-bypass", "url-validation"},
			})
		}
	}

	return findings
}

// hasRedirectContext checks if the file contains redirect-related patterns.
func hasRedirectContext(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "redirect") ||
		strings.Contains(lower, "location") ||
		strings.Contains(lower, "returnurl") ||
		strings.Contains(lower, "return_url") ||
		strings.Contains(lower, "returnto") ||
		strings.Contains(lower, "return_to") ||
		strings.Contains(lower, "nexturl") ||
		strings.Contains(lower, "next_url")
}

// --- Helpers ---

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

// hasNearbyPattern checks lines within a window for a regex pattern match.
func hasNearbyPattern(lines []string, idx int, pattern *regexp.Regexp, window int) bool {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + 5
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
