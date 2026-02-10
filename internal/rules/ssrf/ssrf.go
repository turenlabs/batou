package ssrf

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled patterns ---

// GTSS-SSRF-001: URL from User Input
var (
	// Go: http.Get/Post/etc with variable
	goHTTPGetVar      = regexp.MustCompile(`\bhttp\.(?:Get|Post|Head|PostForm)\s*\(\s*[a-zA-Z_]\w*`)
	goHTTPNewRequest  = regexp.MustCompile(`http\.NewRequest\s*\(\s*"[A-Z]+"\s*,\s*[a-zA-Z_]\w*`)
	goHTTPClientDo    = regexp.MustCompile(`\.Do\s*\(\s*[a-zA-Z_]\w*`)
	// Python: requests library with variable URL
	pyRequestsCall    = regexp.MustCompile(`\brequests\.(?:get|post|put|delete|patch|head|options)\s*\(\s*[a-zA-Z_]\w*`)
	pyUrllibOpen      = regexp.MustCompile(`\b(?:urllib\.request\.urlopen|urllib2\.urlopen|urlopen)\s*\(\s*[a-zA-Z_]\w*`)
	pyHttpClient      = regexp.MustCompile(`\b(?:httpx|aiohttp)\.\w+\.\w+\s*\(\s*[a-zA-Z_]\w*`)
	// JS/TS: fetch, axios, http with variable URL
	jsFetchVar        = regexp.MustCompile(`\bfetch\s*\(\s*[a-zA-Z_]\w*`)
	jsAxiosCall       = regexp.MustCompile(`\baxios\.(?:get|post|put|delete|patch|head|options|request)\s*\(\s*[a-zA-Z_]\w*`)
	jsHTTPGet         = regexp.MustCompile(`\b(?:http|https)\.(?:get|request)\s*\(\s*[a-zA-Z_]\w*`)
	jsGotCall         = regexp.MustCompile(`\bgot\s*\(\s*[a-zA-Z_]\w*`)
	// PHP: curl/file_get_contents with variable
	phpCurlSetopt     = regexp.MustCompile(`\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$`)
	phpFileGetURL     = regexp.MustCompile(`\bfile_get_contents\s*\(\s*\$(?:_GET|_POST|_REQUEST|url|uri|link|input|param)`)
	phpFopen          = regexp.MustCompile(`\bfopen\s*\(\s*\$(?:_GET|_POST|_REQUEST|url|uri|link|input)`)
)

// GTSS-SSRF-002: Internal Network Access
var (
	// Patterns for internal/private IP ranges in URLs or strings
	internalIPLiteral = regexp.MustCompile(`(?:https?://)?(?:` +
		`127\.\d{1,3}\.\d{1,3}\.\d{1,3}` + // loopback
		`|10\.\d{1,3}\.\d{1,3}\.\d{1,3}` + // 10.0.0.0/8
		`|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}` + // 172.16.0.0/12
		`|192\.168\.\d{1,3}\.\d{1,3}` + // 192.168.0.0/16
		`|169\.254\.169\.254` + // cloud metadata endpoint
		`|0\.0\.0\.0` + // wildcard
		`|localhost` + // localhost
		`|\[::1\]` + // IPv6 loopback
		`|\[::ffff:127\.\d{1,3}\.\d{1,3}\.\d{1,3}\]` + // IPv4-mapped IPv6 loopback
		`|0x7f\d+` + // hex loopback (e.g., 0x7f000001)
		`|2130706433` + // decimal for 127.0.0.1
		`|0177\.\d+` + // octal loopback (e.g., 0177.0.0.1)
		`|127\.1\b` + // short form loopback (127.1)
		`)`)
	// Cloud metadata endpoints
	cloudMetadata = regexp.MustCompile(`169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com`)
)

// GTSS-SSRF-003: DNS Rebinding
var (
	// Pattern: DNS resolution followed by separate HTTP request
	goNetLookup  = regexp.MustCompile(`\bnet\.(?:LookupHost|LookupIP|LookupAddr|ResolveIPAddr|ResolveTCPAddr)\s*\(`)
	pySocketResolve = regexp.MustCompile(`\bsocket\.(?:gethostbyname|getaddrinfo|gethostbyname_ex)\s*\(`)
	jsDNSResolve = regexp.MustCompile(`\bdns\.(?:resolve|lookup|resolve4|resolve6)\s*\(`)
)

// GTSS-SSRF-004: Redirect Following
var (
	// Go: http.Client without CheckRedirect
	goHTTPClient       = regexp.MustCompile(`&http\.Client\s*\{`)
	goCheckRedirect    = regexp.MustCompile(`CheckRedirect\s*:`)
	// Python: allow_redirects=True (often default, but explicit is a signal)
	pyAllowRedirects   = regexp.MustCompile(`allow_redirects\s*=\s*True`)
	// JS: follow/maxRedirects configuration
	jsFollowRedirects  = regexp.MustCompile(`(?:follow\s*:\s*true|maxRedirects\s*:\s*[1-9]\d*|followRedirects?\s*:\s*true)`)
)

func init() {
	rules.Register(&URLFromUserInput{})
	rules.Register(&InternalNetworkAccess{})
	rules.Register(&DNSRebinding{})
	rules.Register(&RedirectFollowing{})
}

// --- GTSS-SSRF-001: URL From User Input ---

type URLFromUserInput struct{}

func (r *URLFromUserInput) ID() string             { return "GTSS-SSRF-001" }
func (r *URLFromUserInput) Name() string            { return "URLFromUserInput" }
func (r *URLFromUserInput) DefaultSeverity() rules.Severity { return rules.High }
func (r *URLFromUserInput) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *URLFromUserInput) Description() string {
	return "Detects HTTP requests where the URL is derived from user input, which may allow Server-Side Request Forgery (SSRF)."
}

func (r *URLFromUserInput) Scan(ctx *rules.ScanContext) []rules.Finding {
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
			if loc := goHTTPGetVar.FindString(line); loc != "" {
				if !hasURLValidation(lines, i) {
					matched = loc
					confidence = "medium"
				}
			}
			if matched == "" {
				if loc := goHTTPNewRequest.FindString(line); loc != "" {
					if !hasURLValidation(lines, i) {
						matched = loc
						confidence = "medium"
					}
				}
			}
		case rules.LangPython:
			if loc := pyRequestsCall.FindString(line); loc != "" {
				if !hasURLValidation(lines, i) {
					matched = loc
					confidence = "medium"
				}
			}
			if matched == "" {
				if loc := pyUrllibOpen.FindString(line); loc != "" {
					if !hasURLValidation(lines, i) {
						matched = loc
						confidence = "medium"
					}
				}
			}
			if matched == "" {
				if loc := pyHttpClient.FindString(line); loc != "" {
					if !hasURLValidation(lines, i) {
						matched = loc
						confidence = "medium"
					}
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := jsFetchVar.FindString(line); loc != "" {
				if !hasURLValidation(lines, i) {
					matched = loc
					confidence = "medium"
				}
			}
			if matched == "" {
				if loc := jsAxiosCall.FindString(line); loc != "" {
					if !hasURLValidation(lines, i) {
						matched = loc
						confidence = "medium"
					}
				}
			}
			if matched == "" {
				if loc := jsHTTPGet.FindString(line); loc != "" {
					if !hasURLValidation(lines, i) {
						matched = loc
						confidence = "medium"
					}
				}
			}
			if matched == "" {
				if loc := jsGotCall.FindString(line); loc != "" {
					if !hasURLValidation(lines, i) {
						matched = loc
						confidence = "low"
					}
				}
			}
		case rules.LangPHP:
			if loc := phpCurlSetopt.FindString(line); loc != "" {
				if !hasURLValidation(lines, i) {
					matched = loc
					confidence = "high"
				}
			}
			if matched == "" {
				if loc := phpFileGetURL.FindString(line); loc != "" {
					matched = loc
					confidence = "high"
				}
			}
			if matched == "" {
				if loc := phpFopen.FindString(line); loc != "" {
					matched = loc
					confidence = "high"
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "HTTP request with user-controlled URL (SSRF risk)",
				Description:   "An HTTP request is made using a URL that may be derived from user input. An attacker could exploit this to make the server access internal services, cloud metadata endpoints, or other unintended targets.",
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate and sanitize URLs before making requests. Use an allowlist of permitted domains/schemes. Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.169.254).",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Confidence:    confidence,
				Tags:          []string{"ssrf", "user-input", "http-request"},
			})
		}
	}

	return findings
}

// hasURLValidation checks surrounding lines for URL validation patterns.
func hasURLValidation(lines []string, idx int) bool {
	start := idx - 8
	if start < 0 {
		start = 0
	}
	end := idx + 3
	if end > len(lines) {
		end = len(lines)
	}

	for _, l := range lines[start:end] {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "allowlist") || strings.Contains(lower, "whitelist") ||
			strings.Contains(lower, "allowedhost") || strings.Contains(lower, "allowed_host") ||
			strings.Contains(lower, "validateurl") || strings.Contains(lower, "validate_url") ||
			strings.Contains(lower, "isallowedurl") || strings.Contains(lower, "is_allowed_url") ||
			strings.Contains(lower, "sanitizeurl") || strings.Contains(lower, "sanitize_url") ||
			strings.Contains(lower, "parseurl") || strings.Contains(lower, "url.parse") {
			return true
		}
	}
	return false
}

// --- GTSS-SSRF-002: Internal Network Access ---

type InternalNetworkAccess struct{}

func (r *InternalNetworkAccess) ID() string             { return "GTSS-SSRF-002" }
func (r *InternalNetworkAccess) Name() string            { return "InternalNetworkAccess" }
func (r *InternalNetworkAccess) DefaultSeverity() rules.Severity { return rules.High }
func (r *InternalNetworkAccess) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *InternalNetworkAccess) Description() string {
	return "Detects requests to internal/private IP ranges or cloud metadata endpoints that may indicate SSRF vulnerabilities."
}

func (r *InternalNetworkAccess) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		// Check for cloud metadata endpoint access (highest priority)
		if loc := cloudMetadata.FindString(line); loc != "" {
			// Determine if this is in an HTTP request context
			if isHTTPContext(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Critical,
					Title:         "Request to cloud metadata endpoint",
					Description:   "Code accesses a cloud metadata endpoint (169.254.169.254 or equivalent). If the URL is user-controlled, this enables SSRF to steal cloud credentials and instance metadata.",
					LineNumber:    lineNum,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Block requests to metadata endpoints. Use IMDSv2 (AWS) which requires a token header. Validate all URLs against an allowlist before making requests.",
					CWEID:         "CWE-918",
					OWASPCategory: "A10:2021-SSRF",
					Confidence:    "high",
					Tags:          []string{"ssrf", "cloud-metadata", "credential-theft"},
				})
				continue
			}
		}

		// Check for internal IP addresses in HTTP request contexts
		if loc := internalIPLiteral.FindString(line); loc != "" {
			if isHTTPContext(line) && !isTestOrConfig(line, lines, i) {
				confidence := "medium"
				if strings.Contains(line, "169.254.169.254") {
					confidence = "high"
				}

				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "HTTP request to internal/private network address",
					Description:   "An HTTP request targets an internal or private IP address. If the URL is user-influenced, an attacker could use this to scan internal networks or access internal services.",
					LineNumber:    lineNum,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Validate URLs against an allowlist of permitted external hosts. Block requests to RFC 1918 private ranges, loopback addresses, and link-local addresses.",
					CWEID:         "CWE-918",
					OWASPCategory: "A10:2021-SSRF",
					Confidence:    confidence,
					Tags:          []string{"ssrf", "internal-network", "private-ip"},
				})
			}
		}
	}

	return findings
}

// isHTTPContext checks if the line is in an HTTP request context.
func isHTTPContext(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "http") || strings.Contains(lower, "fetch") ||
		strings.Contains(lower, "request") || strings.Contains(lower, "curl") ||
		strings.Contains(lower, "get(") || strings.Contains(lower, "post(") ||
		strings.Contains(lower, "urlopen") || strings.Contains(lower, "axios")
}

// isTestOrConfig checks if the line is likely part of tests or configuration.
func isTestOrConfig(line string, lines []string, idx int) bool {
	lower := strings.ToLower(line)
	// Strip URLs (http:// and https://) before checking for comment markers,
	// so that "http://192.168..." doesn't false-positive on "//".
	stripped := strings.ReplaceAll(strings.ReplaceAll(lower, "https://", ""), "http://", "")
	if strings.Contains(stripped, "test") || strings.Contains(stripped, "mock") ||
		strings.Contains(stripped, "example") || strings.Contains(stripped, "//") {
		return true
	}
	// Check surrounding context for test patterns
	start := idx - 3
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start : idx+1] {
		if strings.Contains(l, "func Test") || strings.Contains(l, "def test_") ||
			strings.Contains(l, "describe(") || strings.Contains(l, "it(") {
			return true
		}
	}
	return false
}

// --- GTSS-SSRF-003: DNS Rebinding ---

type DNSRebinding struct{}

func (r *DNSRebinding) ID() string             { return "GTSS-SSRF-003" }
func (r *DNSRebinding) Name() string            { return "DNSRebinding" }
func (r *DNSRebinding) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DNSRebinding) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript}
}

func (r *DNSRebinding) Description() string {
	return "Detects patterns vulnerable to DNS rebinding: resolving a hostname then making a request in separate steps without re-validation."
}

func (r *DNSRebinding) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var dnsPattern *regexp.Regexp

		switch ctx.Language {
		case rules.LangGo:
			dnsPattern = goNetLookup
		case rules.LangPython:
			dnsPattern = pySocketResolve
		case rules.LangJavaScript, rules.LangTypeScript:
			dnsPattern = jsDNSResolve
		default:
			continue
		}

		if loc := dnsPattern.FindString(line); loc != "" {
			// Check if there is an HTTP request within the following lines
			// using the original hostname (not the resolved IP)
			hasSubsequentRequest := false
			end := i + 20
			if end > len(lines) {
				end = len(lines)
			}
			for _, subsequent := range lines[i+1 : end] {
				subLower := strings.ToLower(subsequent)
				if strings.Contains(subLower, "http.get") || strings.Contains(subLower, "http.newrequest") ||
					strings.Contains(subLower, "requests.get") || strings.Contains(subLower, "fetch(") ||
					strings.Contains(subLower, "axios.") || strings.Contains(subLower, "urlopen") ||
					strings.Contains(subLower, ".do(") {
					hasSubsequentRequest = true
					break
				}
			}

			if hasSubsequentRequest {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "DNS resolution followed by HTTP request (DNS rebinding risk)",
					Description:   "A DNS lookup is performed followed by an HTTP request. If the DNS resolution and request happen in separate steps, an attacker could exploit DNS rebinding to bypass IP-based access controls.",
					LineNumber:    lineNum,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Resolve the hostname and make the request in a single atomic operation, or pin the resolved IP and use it directly for the HTTP request. Validate the resolved IP is not in private ranges.",
					CWEID:         "CWE-918",
					OWASPCategory: "A10:2021-SSRF",
					Confidence:    "low",
					Tags:          []string{"ssrf", "dns-rebinding", "toctou"},
				})
			}
		}
	}

	return findings
}

// --- GTSS-SSRF-004: Redirect Following ---

type RedirectFollowing struct{}

func (r *RedirectFollowing) ID() string             { return "GTSS-SSRF-004" }
func (r *RedirectFollowing) Name() string            { return "RedirectFollowing" }
func (r *RedirectFollowing) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RedirectFollowing) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript}
}

func (r *RedirectFollowing) Description() string {
	return "Detects HTTP clients configured to follow redirects with user-controlled URLs, which could redirect requests to internal services."
}

func (r *RedirectFollowing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Track if the file has user-controlled URL patterns
	hasUserURL := fileHasUserURL(ctx.Content, ctx.Language)

	if !hasUserURL {
		return nil
	}

	switch ctx.Language {
	case rules.LangGo:
		findings = append(findings, r.scanGoRedirects(lines)...)
	case rules.LangPython:
		findings = append(findings, r.scanPythonRedirects(lines)...)
	case rules.LangJavaScript, rules.LangTypeScript:
		findings = append(findings, r.scanJSRedirects(lines)...)
	}

	return findings
}

func (r *RedirectFollowing) scanGoRedirects(lines []string) []rules.Finding {
	var findings []rules.Finding

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		// Look for http.Client{} without CheckRedirect
		if goHTTPClient.MatchString(line) {
			// Scan forward to find the closing brace and check for CheckRedirect
			hasCheckRedirect := false
			end := i + 15
			if end > len(lines) {
				end = len(lines)
			}
			for _, subsequent := range lines[i:end] {
				if goCheckRedirect.MatchString(subsequent) {
					hasCheckRedirect = true
					break
				}
				// Stop at closing brace
				if strings.Contains(subsequent, "}") && !strings.Contains(subsequent, "{") {
					break
				}
			}

			if !hasCheckRedirect {
				findings = append(findings, rules.Finding{
					RuleID:      r.ID(),
					Severity:    r.DefaultSeverity(),
					Title:       "HTTP client follows redirects without CheckRedirect (SSRF risk)",
					Description: "An http.Client is created without a CheckRedirect function. With user-controlled URLs, an attacker could use redirects to bypass URL validation and reach internal services.",
					LineNumber:  lineNum,
					MatchedText: truncate(strings.TrimSpace(line), 120),
					Suggestion:  "Set a CheckRedirect function on the http.Client that validates redirect URLs against the same allowlist used for the original URL.",
					CWEID:       "CWE-918",
					OWASPCategory: "A10:2021-SSRF",
					Confidence:  "medium",
					Tags:        []string{"ssrf", "redirect", "open-redirect"},
				})
			}
		}

		// Also flag http.Get/http.Post directly (they use default client which follows redirects)
		if goHTTPGetVar.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:      r.ID(),
				Severity:    r.DefaultSeverity(),
				Title:       "Default HTTP client follows redirects with user URL",
				Description: "The default http.Get/Post functions follow redirects automatically. With user-controlled URLs, redirects could reach internal services.",
				LineNumber:  lineNum,
				MatchedText: truncate(strings.TrimSpace(line), 120),
				Suggestion:  "Use a custom http.Client with a CheckRedirect function that validates redirect targets.",
				CWEID:       "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Confidence:  "low",
				Tags:        []string{"ssrf", "redirect"},
			})
		}
	}

	return findings
}

func (r *RedirectFollowing) scanPythonRedirects(lines []string) []rules.Finding {
	var findings []rules.Finding

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		if loc := pyAllowRedirects.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "HTTP request explicitly allows redirects with user URL",
				Description:   "allow_redirects=True is explicitly set on an HTTP request. If the URL is user-controlled, redirects could reach internal services and bypass URL validation.",
				LineNumber:    lineNum,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set allow_redirects=False and manually handle redirects, validating each redirect URL against an allowlist.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Confidence:    "medium",
				Tags:          []string{"ssrf", "redirect"},
			})
		}
	}

	return findings
}

func (r *RedirectFollowing) scanJSRedirects(lines []string) []rules.Finding {
	var findings []rules.Finding

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		if loc := jsFollowRedirects.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "HTTP client configured to follow redirects with user URL",
				Description:   "An HTTP client is configured to follow redirects. If the request URL is user-controlled, redirects could bypass URL validation and reach internal services.",
				LineNumber:    lineNum,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set redirect following to manual/disabled and validate each redirect URL against an allowlist before following.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Confidence:    "medium",
				Tags:          []string{"ssrf", "redirect"},
			})
		}
	}

	return findings
}

// fileHasUserURL checks if the file contains patterns suggesting user-controlled URLs.
func fileHasUserURL(content string, lang rules.Language) bool {
	lower := strings.ToLower(content)

	// Generic patterns for user-controlled URLs
	if strings.Contains(lower, "user_url") || strings.Contains(lower, "userinput") ||
		strings.Contains(lower, "user_input") || strings.Contains(lower, "userurl") ||
		strings.Contains(lower, "inputurl") || strings.Contains(lower, "input_url") {
		return true
	}

	switch lang {
	case rules.LangGo:
		return strings.Contains(content, "r.URL.Query()") ||
			strings.Contains(content, "r.FormValue") ||
			strings.Contains(content, "r.PostFormValue") ||
			strings.Contains(content, "c.Query(") ||
			strings.Contains(content, "c.Param(")
	case rules.LangPython:
		return strings.Contains(content, "request.args") ||
			strings.Contains(content, "request.form") ||
			strings.Contains(content, "request.GET") ||
			strings.Contains(content, "request.POST") ||
			strings.Contains(content, "request.data")
	case rules.LangJavaScript, rules.LangTypeScript:
		return strings.Contains(content, "req.query") ||
			strings.Contains(content, "req.params") ||
			strings.Contains(content, "req.body") ||
			strings.Contains(content, "searchParams")
	}
	return false
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
