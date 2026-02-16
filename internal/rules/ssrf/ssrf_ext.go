package ssrf

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended SSRF detection
// ---------------------------------------------------------------------------

var (
	// GTSS-SSRF-005: DNS rebinding via hostname without IP validation
	reExtDNSLookupThenUse = regexp.MustCompile(`(?i)(?:gethostbyname|getaddrinfo|dns\.resolve|dns\.lookup|net\.LookupHost|net\.LookupIP|InetAddress\.getByName)\s*\(`)

	// GTSS-SSRF-006: URL parser confusion (different URL parsers in same file)
	reExtURLParsePy     = regexp.MustCompile(`\b(?:urlparse|urlsplit|urllib\.parse\.urlparse)\s*\(`)
	reExtURLParseJS     = regexp.MustCompile(`\bnew\s+URL\s*\(`)
	reExtURLParseGo     = regexp.MustCompile(`\burl\.Parse\s*\(`)
	reExtURLParseJava   = regexp.MustCompile(`\bnew\s+(?:java\.net\.)?URL\s*\(`)
	reExtURLParseSecond = regexp.MustCompile(`(?i)(?:urllib|requests|http\.get|fetch|axios|\.openConnection|HttpClient)\s*[.(]`)

	// GTSS-SSRF-007: Cloud metadata endpoint access
	reExtCloudMetadata = regexp.MustCompile(`(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200)`)

	// GTSS-SSRF-008: SSRF via file:// protocol
	reExtFileProtocol = regexp.MustCompile(`(?i)file://`)
	reExtFileProtocolInURL = regexp.MustCompile(`(?i)(?:url|uri|href|src|path|endpoint)\s*[:=]\s*["']?\s*file://`)

	// GTSS-SSRF-009: SSRF via redirect following
	reExtRedirectFollow = regexp.MustCompile(`(?i)(?:follow_?redirects?\s*[:=]\s*(?:true|\d+)|max_?redirects?\s*[:=]\s*[1-9]|redirect\s*[:=]\s*['"]follow['"])`)

	// GTSS-SSRF-010: Blind SSRF via webhook/callback URL
	reExtWebhookURL = regexp.MustCompile(`(?i)(?:webhook[_-]?url|callback[_-]?url|notify[_-]?url|hook[_-]?url|postback[_-]?url)\s*[:=]\s*(?:req\.(?:body|query|params)|request\.(?:POST|GET|data|json|form)|params\[)`)

	// GTSS-SSRF-011: SSRF via PDF/image generation library
	reExtPDFGen = regexp.MustCompile(`(?i)(?:wkhtmltopdf|puppeteer|phantom|html-pdf|pdfkit|imgkit|weasyprint|chrome\.(?:printToPDF|screenshot)|page\.(?:goto|pdf|screenshot)|gotenberg)`)
	reExtPDFGenWithURL = regexp.MustCompile(`(?i)(?:wkhtmltopdf|puppeteer|phantom|html-pdf|pdfkit|imgkit|weasyprint|gotenberg).*(?:req\.|request\.|params|user_?input|url|uri)`)

	// GTSS-SSRF-012: SSRF via SVG processing (external entity)
	reExtSVGProcess = regexp.MustCompile(`(?i)(?:svg|image).*(?:parse|render|convert|process|load)\s*\(`)
	reExtSVGExternalRef = regexp.MustCompile(`(?i)(?:xlink:href|xmlns|href)\s*=\s*["']https?://`)
	reExtSVGLibrary = regexp.MustCompile(`(?i)(?:librsvg|rsvg|cairosvg|inkscape|imagemagick|sharp|svg2png|svgexport)`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&DNSRebindingExt{})
	rules.Register(&URLParserConfusion{})
	rules.Register(&CloudMetadataAccess{})
	rules.Register(&FileProtocolSSRF{})
	rules.Register(&RedirectFollowingSSRF{})
	rules.Register(&BlindSSRFWebhook{})
	rules.Register(&PDFGenSSRF{})
	rules.Register(&SVGProcessSSRF{})
}

// ========================================================================
// GTSS-SSRF-005: DNS Rebinding via Hostname without IP Validation
// ========================================================================

type DNSRebindingExt struct{}

func (r *DNSRebindingExt) ID() string                     { return "GTSS-SSRF-005" }
func (r *DNSRebindingExt) Name() string                   { return "DNSRebindingExt" }
func (r *DNSRebindingExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *DNSRebindingExt) Description() string {
	return "Detects DNS resolution of user-supplied hostnames without IP validation, enabling DNS rebinding attacks."
}
func (r *DNSRebindingExt) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *DNSRebindingExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtDNSLookupThenUse.FindString(line); m != "" {
			// Check if there's IP validation nearby
			if hasIPValidation(lines, i) {
				continue
			}
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "DNS resolution without IP validation (rebinding risk)",
				Description:   "A hostname is resolved via DNS without validating the resolved IP address against private/internal ranges. An attacker can use DNS rebinding to make the resolved IP switch from public to private between validation and use.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "After DNS resolution, validate that the resolved IP is not in private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.169.254). Pin the resolved IP for the subsequent request.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"ssrf", "dns-rebinding", "ip-validation"},
			})
		}
	}
	return findings
}

func hasIPValidation(lines []string, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 15
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		lower := strings.ToLower(l)
		if strings.Contains(lower, "isprivate") || strings.Contains(lower, "is_private") ||
			strings.Contains(lower, "isloopback") || strings.Contains(lower, "is_loopback") ||
			strings.Contains(lower, "isinternal") || strings.Contains(lower, "is_internal") ||
			strings.Contains(lower, "private_ip") || strings.Contains(lower, "privateip") ||
			strings.Contains(lower, "10.0.0") || strings.Contains(lower, "172.16") ||
			strings.Contains(lower, "192.168") || strings.Contains(lower, "127.0.0") {
			return true
		}
	}
	return false
}

// ========================================================================
// GTSS-SSRF-006: URL Parser Confusion
// ========================================================================

type URLParserConfusion struct{}

func (r *URLParserConfusion) ID() string                     { return "GTSS-SSRF-006" }
func (r *URLParserConfusion) Name() string                   { return "URLParserConfusion" }
func (r *URLParserConfusion) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *URLParserConfusion) Description() string {
	return "Detects use of URL parsing followed by a different HTTP client, which can lead to SSRF via URL parser disagreement."
}
func (r *URLParserConfusion) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangGo, rules.LangJava}
}

func (r *URLParserConfusion) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var parseMatch string
		switch ctx.Language {
		case rules.LangPython:
			parseMatch = reExtURLParsePy.FindString(line)
		case rules.LangJavaScript, rules.LangTypeScript:
			parseMatch = reExtURLParseJS.FindString(line)
		case rules.LangGo:
			parseMatch = reExtURLParseGo.FindString(line)
		case rules.LangJava:
			parseMatch = reExtURLParseJava.FindString(line)
		}
		if parseMatch == "" {
			continue
		}
		// Check if there's a separate HTTP client call nearby that could disagree
		end := i + 20
		if end > len(lines) {
			end = len(lines)
		}
		for _, subsequent := range lines[i+1 : end] {
			if reExtURLParseSecond.MatchString(subsequent) {
				matched := parseMatch
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "URL parsed and used by different libraries (parser confusion risk)",
					Description:   "A URL is parsed by one library and then used by another HTTP client. Different URL parsers can disagree on the hostname, allowing SSRF bypass via URL parsing ambiguity.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use the same library for both URL parsing and HTTP requests. Validate the URL after parsing and before making the request using the same parser.",
					CWEID:         "CWE-918",
					OWASPCategory: "A10:2021-SSRF",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"ssrf", "url-parser", "parser-confusion"},
				})
				break
			}
		}
	}
	return findings
}

// ========================================================================
// GTSS-SSRF-007: Cloud Metadata Endpoint Access
// ========================================================================

type CloudMetadataAccess struct{}

func (r *CloudMetadataAccess) ID() string                     { return "GTSS-SSRF-007" }
func (r *CloudMetadataAccess) Name() string                   { return "CloudMetadataAccess" }
func (r *CloudMetadataAccess) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CloudMetadataAccess) Description() string {
	return "Detects access to cloud metadata endpoints (169.254.169.254, metadata.google.internal) which can expose cloud credentials."
}
func (r *CloudMetadataAccess) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *CloudMetadataAccess) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtCloudMetadata.FindString(line); m != "" {
			// Skip test/config patterns
			lower := strings.ToLower(line)
			if strings.Contains(lower, "test") || strings.Contains(lower, "mock") || strings.Contains(lower, "example") {
				continue
			}
			matched := m
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Cloud metadata endpoint reference detected",
				Description:   "Code references a cloud metadata endpoint (" + matched + "). If this URL is constructed from user input or accessible via SSRF, an attacker can steal cloud instance credentials, access tokens, and configuration.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Block requests to metadata endpoints at the network/firewall level. Use IMDSv2 (AWS) which requires a PUT request with a TTL header. Validate all outbound URLs against a blocklist of internal IPs.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ssrf", "cloud-metadata", "credential-theft"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-SSRF-008: SSRF via file:// Protocol
// ========================================================================

type FileProtocolSSRF struct{}

func (r *FileProtocolSSRF) ID() string                     { return "GTSS-SSRF-008" }
func (r *FileProtocolSSRF) Name() string                   { return "FileProtocolSSRF" }
func (r *FileProtocolSSRF) DefaultSeverity() rules.Severity { return rules.High }
func (r *FileProtocolSSRF) Description() string {
	return "Detects use of file:// protocol in URL variables which can be used for local file reading via SSRF."
}
func (r *FileProtocolSSRF) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *FileProtocolSSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtFileProtocolInURL.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "file:// protocol in URL variable (SSRF/LFI risk)",
				Description:   "A file:// protocol URL is used in a URL variable. If user input can influence this URL, an attacker can read arbitrary local files from the server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Restrict allowed URL schemes to https:// only. Validate and reject URLs with file://, gopher://, dict://, and other non-HTTP schemes.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"ssrf", "file-protocol", "local-file-read"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-SSRF-009: SSRF via Redirect Following
// ========================================================================

type RedirectFollowingSSRF struct{}

func (r *RedirectFollowingSSRF) ID() string                     { return "GTSS-SSRF-009" }
func (r *RedirectFollowingSSRF) Name() string                   { return "RedirectFollowingSSRF" }
func (r *RedirectFollowingSSRF) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RedirectFollowingSSRF) Description() string {
	return "Detects HTTP clients configured to follow redirects, which can bypass SSRF URL validation via open redirects."
}
func (r *RedirectFollowingSSRF) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *RedirectFollowingSSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !fileHasUserURL(ctx.Content, ctx.Language) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtRedirectFollow.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "HTTP client follows redirects (SSRF bypass risk)",
				Description:   "An HTTP client is configured to follow redirects. An attacker can bypass URL validation by redirecting from an allowed domain to an internal service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Disable automatic redirect following. Manually handle redirects by validating each redirect URL against the same allowlist used for the original URL.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"ssrf", "redirect", "bypass"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-SSRF-010: Blind SSRF via Webhook/Callback URL
// ========================================================================

type BlindSSRFWebhook struct{}

func (r *BlindSSRFWebhook) ID() string                     { return "GTSS-SSRF-010" }
func (r *BlindSSRFWebhook) Name() string                   { return "BlindSSRFWebhook" }
func (r *BlindSSRFWebhook) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *BlindSSRFWebhook) Description() string {
	return "Detects user-controlled webhook/callback URLs that can be used for blind SSRF attacks."
}
func (r *BlindSSRFWebhook) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *BlindSSRFWebhook) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtWebhookURL.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "User-controlled webhook/callback URL (blind SSRF risk)",
				Description:   "A webhook or callback URL is sourced from user input. The server will make an outbound request to this URL, which an attacker can use to scan internal networks or access internal services (blind SSRF).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate webhook URLs against an allowlist of permitted domains. Block requests to internal IP ranges. Log and rate-limit outbound webhook requests.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"ssrf", "webhook", "callback", "blind-ssrf"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-SSRF-011: SSRF via PDF/Image Generation Library
// ========================================================================

type PDFGenSSRF struct{}

func (r *PDFGenSSRF) ID() string                     { return "GTSS-SSRF-011" }
func (r *PDFGenSSRF) Name() string                   { return "PDFGenSSRF" }
func (r *PDFGenSSRF) DefaultSeverity() rules.Severity { return rules.High }
func (r *PDFGenSSRF) Description() string {
	return "Detects PDF/image generation libraries processing user-controlled URLs, which can be exploited for SSRF via HTML/CSS injection."
}
func (r *PDFGenSSRF) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PDFGenSSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Only flag if there's both a PDF gen library and user input in the file
	hasPDFLib := reExtPDFGen.MatchString(ctx.Content)
	if !hasPDFLib {
		return nil
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtPDFGenWithURL.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PDF/image generation with user-controlled input (SSRF risk)",
				Description:   "A PDF or image generation library is processing user-controlled content. Attackers can inject HTML/CSS/SVG with internal URLs, causing the server to fetch internal resources and embed them in the generated output.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Sanitize HTML input before passing to PDF generators. Block requests to internal IP ranges at the network level. Use a sandbox or isolated network for PDF generation.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"ssrf", "pdf-generation", "image-generation"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-SSRF-012: SSRF via SVG Processing
// ========================================================================

type SVGProcessSSRF struct{}

func (r *SVGProcessSSRF) ID() string                     { return "GTSS-SSRF-012" }
func (r *SVGProcessSSRF) Name() string                   { return "SVGProcessSSRF" }
func (r *SVGProcessSSRF) DefaultSeverity() rules.Severity { return rules.High }
func (r *SVGProcessSSRF) Description() string {
	return "Detects SVG processing libraries that may follow external references, enabling SSRF via crafted SVG files."
}
func (r *SVGProcessSSRF) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *SVGProcessSSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	hasSVGLib := reExtSVGLibrary.MatchString(ctx.Content)
	if !hasSVGLib {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtSVGProcess.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SVG processing may follow external references (SSRF risk)",
				Description:   "An SVG processing library is used which may follow external references (xlink:href, external stylesheets, external images). A crafted SVG file can trigger SSRF by referencing internal URLs.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Sanitize SVG files before processing by removing external references. Disable external resource loading in the SVG library. Use a network sandbox for SVG rendering.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-SSRF",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"ssrf", "svg", "external-entity"},
			})
		}
	}
	return findings
}
