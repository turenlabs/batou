package encoding

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- Encoding extensions
// ---------------------------------------------------------------------------

// BATOU-ENC-009: UTF-7 XSS bypass (Content-Type without charset)
var (
	// batou:ignore BATOU-LOG-004 -- regex pattern definition, not logging
	reContentTypeHTMLNoCharset = regexp.MustCompile(`(?i)Content-Type['":\s]*text/html\s*['"]?\s*[;)\]}]?\s*$`)
	reContentTypeSetHTML       = regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.set|Header\(\)\.Set|\.writeHead|res\.type)\s*\([^)]*text/html`)
	reCharsetPresent           = regexp.MustCompile(`(?i)charset\s*=`)
	reUserOutputNearby         = regexp.MustCompile(`(?i)(?:res\.|response\.|write|send|render|print|echo|puts)\s*\(`)
)

// BATOU-ENC-010: Overlong UTF-8 / decode without normalization near file ops
var (
	reDecodeURI           = regexp.MustCompile(`(?i)(?:decodeURIComponent|decodeURI|unescape|urllib\.unquote|url\.QueryUnescape|URLDecoder\.decode|rawurldecode|urldecode|CGI\.unescape|Uri\.UnescapeDataString)\s*\(`)
	reFilePathOp          = regexp.MustCompile(`(?i)(?:readFile|writeFile|createReadStream|open\s*\(|path\.join|path\.resolve|filepath\.Join|filepath\.Clean|os\.Open|os\.ReadFile|file_get_contents|fopen|File\.open|File\.read|include\s|require\s)`)
	rePathNormalization   = regexp.MustCompile(`(?i)(?:path\.normalize|path\.resolve|filepath\.Clean|filepath\.Abs|realpath|os\.path\.abspath|os\.path\.normpath|Path\.GetFullPath|Pathname\.cleanpath)`)
)

func init() {
	rules.Register(&UTF7XSSBypass{})
	rules.Register(&DecodeWithoutNormalization{})
}

// ---------------------------------------------------------------------------
// BATOU-ENC-009: UTF-7 XSS bypass
// ---------------------------------------------------------------------------

type UTF7XSSBypass struct{}

func (r *UTF7XSSBypass) ID() string                      { return "BATOU-ENC-009" }
func (r *UTF7XSSBypass) Name() string                    { return "UTF7XSSBypass" }
func (r *UTF7XSSBypass) DefaultSeverity() rules.Severity { return rules.High }
func (r *UTF7XSSBypass) Description() string {
	return "Detects Content-Type text/html responses without an explicit charset, allowing UTF-7 XSS attacks in older browsers and certain configurations."
}
func (r *UTF7XSSBypass) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *UTF7XSSBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// Check for Content-Type set to text/html
		if !reContentTypeSetHTML.MatchString(line) {
			continue
		}

		// Check if charset is specified on this line or nearby
		if reCharsetPresent.MatchString(line) {
			continue
		}

		// Look ahead a few lines for charset in the same header setting
		hasCharset := false
		end := i + 3
		if end > len(lines) {
			end = len(lines)
		}
		for j := i; j < end; j++ {
			if reCharsetPresent.MatchString(lines[j]) {
				hasCharset = true
				break
			}
		}
		if hasCharset {
			continue
		}

		// Only flag if there's user output in the file (not just config)
		if !reUserOutputNearby.MatchString(ctx.Content) {
			continue
		}

		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Content-Type text/html without charset (UTF-7 XSS risk)",
			Description:   "The Content-Type header is set to text/html without specifying a charset. Without an explicit charset=utf-8, some browsers and proxies may auto-detect the encoding, allowing attackers to inject UTF-7 encoded XSS payloads like +ADw-script+AD4- that bypass HTML entity encoding.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Always include charset=utf-8 in Content-Type headers: Content-Type: text/html; charset=utf-8. This prevents encoding-based XSS attacks.",
			CWEID:         "CWE-116",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"encoding", "utf-7", "xss", "content-type"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-ENC-010: URL decode without path normalization
// ---------------------------------------------------------------------------

type DecodeWithoutNormalization struct{}

func (r *DecodeWithoutNormalization) ID() string                      { return "BATOU-ENC-010" }
func (r *DecodeWithoutNormalization) Name() string                    { return "DecodeWithoutNormalization" }
func (r *DecodeWithoutNormalization) DefaultSeverity() rules.Severity { return rules.High }
func (r *DecodeWithoutNormalization) Description() string {
	return "Detects URL decoding functions (decodeURIComponent, unescape, etc.) near file path operations without path normalization, enabling path traversal via encoded sequences like %2e%2e%2f."
}
func (r *DecodeWithoutNormalization) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *DecodeWithoutNormalization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only check files that have both decode and file operations
	if !reDecodeURI.MatchString(ctx.Content) {
		return nil
	}
	if !reFilePathOp.MatchString(ctx.Content) {
		return nil
	}

	// If normalization is present in the file, skip
	if rePathNormalization.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if m := reDecodeURI.FindString(line); m != "" {
			// Check if file path operations are nearby
			window := nearbyLines(lines, i, 10)
			if !reFilePathOp.MatchString(window) {
				continue
			}

			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "URL decoding near file operations without path normalization",
				Description:   "A URL decoding function is used near file path operations without path normalization. Attackers can use percent-encoded path traversal sequences (%2e%2e%2f for ../) or overlong UTF-8 representations to bypass path validation checks that run before decoding.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Always normalize file paths after decoding: use path.resolve() or path.normalize() (Node.js), os.path.abspath() (Python), or filepath.Clean() (Go). Verify the resolved path is within the intended base directory.",
				CWEID:         "CWE-176",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"encoding", "path-traversal", "url-decoding", "normalization"},
			})
		}
	}
	return findings
}
