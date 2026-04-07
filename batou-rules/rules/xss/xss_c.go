package xss

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for C/C++ CGI XSS
// ---------------------------------------------------------------------------

var (
	// printf/fprintf/sprintf with HTML tags and %s format (CGI output)
	reCXSSPrintfHTML = regexp.MustCompile(`(?i)\b(?:printf|fprintf|sprintf|snprintf)\s*\([^;]*"[^"]*<\s*(?:html|body|div|span|p|h[1-6]|a|input|textarea|img|script|form|table|tr|td|li|ul|ol)[^"]*%s`)
	// cout << with HTML tags and << variable
	reCXSSCoutHTML = regexp.MustCompile(`(?i)<<\s*"[^"]*<\s*(?:html|body|div|span|p|h[1-6]|a|input|textarea|img|script|form|table|tr|td|li|ul|ol)[^"]*"\s*<<\s*[a-zA-Z_]\w*`)
	// String concat with HTML tags + variable (C++)
	reCXSSConcatHTML = regexp.MustCompile(`(?i)"[^"]*<\s*(?:html|body|div|span|p|h[1-6]|a|input|textarea|img|script|form|table|tr|td|li|ul|ol)[^"]*"\s*\+\s*(?:std::)?string\s*\(?\s*[a-zA-Z_]\w*`)
	// fputs with HTML to stdout
	reCXSSFputsHTML = regexp.MustCompile(`(?i)\bfputs\s*\(\s*[a-zA-Z_]\w*\s*,\s*stdout`)
	// Content-Type: text/html indicator
	reCXSSContentTypeHTML = regexp.MustCompile(`(?i)text/html`)
	// Safe patterns: escape/encode/sanitize functions, text/plain, application/json
	reCXSSSafeContentType = regexp.MustCompile(`(?i)(?:text/plain|application/json)`)
	reCXSSSafeFunction    = regexp.MustCompile(`(?i)(?:html_encode|escape_html|htmlspecialchars|html_escape|sanitize|encode|url_encode)`)
	// getenv("QUERY_STRING") — indicates CGI input
	reCXSSGetenv = regexp.MustCompile(`\bgetenv\s*\(\s*"QUERY_STRING"`)
)

func init() {
	rules.Register(&CGIXSS{})
}

// ---------------------------------------------------------------------------
// BATOU-XSS-028: C/C++ CGI Cross-Site Scripting
// ---------------------------------------------------------------------------

type CGIXSS struct{}

func (r *CGIXSS) ID() string                     { return "BATOU-XSS-028" }
func (r *CGIXSS) Name() string                   { return "CGIXSS" }
func (r *CGIXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *CGIXSS) Description() string {
	return "Detects unescaped user input in HTML output from C/C++ CGI programs, which enables Cross-Site Scripting (XSS)."
}
func (r *CGIXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

func (r *CGIXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only scan files that look like CGI programs (have getenv or Content-Type: text/html).
	hasHTMLContentType := reCXSSContentTypeHTML.MatchString(ctx.Content)
	hasGetenv := reCXSSGetenv.MatchString(ctx.Content)
	if !hasHTMLContentType && !hasGetenv {
		return nil
	}

	// Skip if using safe content type (text/plain, application/json).
	if reCXSSSafeContentType.MatchString(ctx.Content) {
		return nil
	}

	// Skip if using an HTML encoding/escaping function.
	if reCXSSSafeFunction.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLineXSS(line) {
			continue
		}

		var matched string

		if loc := reCXSSPrintfHTML.FindString(line); loc != "" {
			matched = loc
		} else if loc := reCXSSCoutHTML.FindString(line); loc != "" {
			matched = loc
		} else if loc := reCXSSConcatHTML.FindString(line); loc != "" {
			matched = loc
		} else if reCXSSFputsHTML.MatchString(line) {
			// fputs(variable, stdout) in a CGI context — check if variable
			// looks user-controlled (near getenv usage).
			if hasGetenv {
				matched = strings.TrimSpace(line)
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "C/C++ CGI XSS: unescaped user input in HTML output",
				Description:   "User input from getenv(\"QUERY_STRING\") or similar CGI sources is embedded in HTML output without escaping. An attacker can inject JavaScript via <script> tags or event handlers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncateXSS(matched, 120),
				Suggestion:    "HTML-encode all user input before embedding in HTML output. Replace <>&'\" with their HTML entity equivalents (&lt; &gt; &amp; &#39; &quot;).",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"xss", "cgi", "c-cpp"},
			})
		}
	}
	return findings
}

func isCommentLineXSS(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*")
}

func truncateXSS(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
