package encoding

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-ENC-001: Double encoding
var (
	reDoubleEncode     = regexp.MustCompile(`(?i)(?:encodeURIComponent|encodeURI|urllib\.(?:parse\.)?quote|url\.QueryEscape|URLEncoder\.encode|rawurlencode|urlencode|CGI\.escape|Uri\.EscapeDataString)\s*\(\s*(?:encodeURIComponent|encodeURI|urllib\.(?:parse\.)?quote|url\.QueryEscape|URLEncoder\.encode|rawurlencode|urlencode|CGI\.escape|Uri\.EscapeDataString)\s*\(`)
	reDoubleEscapeHTML = regexp.MustCompile(`(?i)(?:html\.EscapeString|htmlspecialchars|htmlentities|escape|escapeHtml|ERB::Util\.html_escape|cgi\.escape|markupsafe\.escape)\s*\(\s*(?:html\.EscapeString|htmlspecialchars|htmlentities|escape|escapeHtml|ERB::Util\.html_escape|cgi\.escape|markupsafe\.escape)\s*\(`)
)

// BATOU-ENC-002: Missing output encoding before HTML insertion
var (
	reHTMLConcatVar   = regexp.MustCompile(`(?i)(?:html|output|body|page|content|response|markup)\s*(?:\+?=|=)\s*["']<[^"']*>\s*["']\s*\+\s*\w+`)
	reHTMLFmtInsert   = regexp.MustCompile(`(?i)(?:html|output|body|page|content|response|markup)\s*(?:\+?=|=)\s*(?:f["'].*<.*\{|["'].*<.*["']\s*%\s*|["'].*<.*["']\s*\.format\s*\()`)
	reEscapeFuncNearby = regexp.MustCompile(`(?i)(?:html\.EscapeString|htmlspecialchars|htmlentities|escapeHtml|escape|sanitize|DOMPurify|bleach\.clean|markupsafe\.escape|html\.escape|Encode\.forHtml|strip_tags)`)
)

// BATOU-ENC-003: Incorrect character encoding declaration
var (
	reCharsetMeta       = regexp.MustCompile(`(?i)<meta\s+[^>]*charset\s*=\s*["']?([^"'\s;>]+)`)
	reContentTypeBadEnc = regexp.MustCompile(`(?i)Content-Type.*charset\s*=\s*["']?(us-ascii|iso-8859-1|shift_jis|euc-jp|gb2312|big5|windows-1252)["']?`)
	reCharsetHeader     = regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.set|\.Header\(\)\.Set)\s*\([^)]*charset\s*=\s*["']?(us-ascii|iso-8859-1|shift_jis|euc-jp|gb2312|big5|windows-1252)`)
)

// BATOU-ENC-004: URL encoding bypass
var (
	rePercentEncodedCheck = regexp.MustCompile(`(?i)(?:if|match|test|includes|contains|indexOf|==|!=)\s*.*(?:%2[eEfF]|%2[fF]|%5[cC]|%0[aAdD]|%00|%3[cCeE])`)
	reSecurityCheck       = regexp.MustCompile(`(?i)(?:if|unless|guard|when|check|validate|filter|block|deny|reject)\s*.*(?:%[0-9a-fA-F]{2})`)
)

// BATOU-ENC-005: Base64 used as encryption
var (
	reBase64AsEncrypt  = regexp.MustCompile(`(?i)(?:encrypt|cipher|secure|protect|hide|obfuscate)\w*\s*(?:[:=]|=)\s*.*(?:base64|btoa|atob|b64encode|b64decode|Base64\.encode|Base64\.decode|Base64\.getEncoder|Base64\.getDecoder|base64_encode|base64_decode)`)
	reBase64FuncCrypto = regexp.MustCompile(`(?i)(?:base64|btoa|b64encode|Base64\.encode|base64_encode)\s*\(.*(?:password|secret|token|key|credential|ssn|credit)`)
)

// BATOU-ENC-006: Unicode normalization bypass
var (
	reUnicodeNormCheck  = regexp.MustCompile(`(?i)(?:normalize|NFC|NFD|NFKC|NFKD|unicodedata\.normalize)`)
	reHomoglyphPattern  = regexp.MustCompile(`[\x{FF01}-\x{FF5E}]|[\x{2000}-\x{200F}]|[\x{2028}-\x{202F}]|[\x{FEFF}]|[\x{200B}-\x{200D}]`)
	reSecurityCheckAfterNorm = regexp.MustCompile(`(?i)(?:if|match|test|includes|contains|indexOf|==|!=|filter|block|deny|validate)\b`)
)

// BATOU-ENC-007: Mixed encoding in SQL
var (
	reMixedEncodingSQL = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*(?:CHAR\s*\(|CHR\s*\(|CONVERT\s*\(|CAST\s*\(|UNHEX\s*\(|X['"])`)
	reSQLCharConcat    = regexp.MustCompile(`(?i)(?:CHAR|CHR)\s*\(\s*\d+\s*\)\s*(?:\+|\|\|)\s*(?:CHAR|CHR)\s*\(`)
	reSQLHexLiteral    = regexp.MustCompile(`(?i)(?:0x[0-9a-fA-F]{4,}|X'[0-9a-fA-F]{4,}')`)
)

// BATOU-ENC-008: Null byte injection
var (
	reNullByteParam    = regexp.MustCompile(`(?i)(?:%00|\\x00|\\0|\\u0000|\x00)`)
	reNullByteInPath   = regexp.MustCompile(`(?i)(?:open|read|include|require|fopen|file_get_contents|readFile|os\.path|Path\.join)\s*\(.*(?:%00|\\x00|\\0|\\u0000)`)
	reNullByteInCheck  = regexp.MustCompile(`(?i)(?:endsWith|endswith|ends_with|HasSuffix|match|test|includes)\s*\(.*(?:%00|\\x00|\\0|\\u0000)`)
	reNullByteInInput  = regexp.MustCompile(`(?i)(?:req\.|request\.|params\.|query\.|body\.|args\.|GET\[|POST\[|\$_).*(?:%00|\\x00|\\0)`)
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

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&DoubleEncoding{})
	rules.Register(&MissingOutputEncoding{})
	rules.Register(&IncorrectCharEncoding{})
	rules.Register(&URLEncodingBypass{})
	rules.Register(&Base64AsEncryption{})
	rules.Register(&UnicodeNormBypass{})
	rules.Register(&MixedEncodingSQL{})
	rules.Register(&NullByteInjection{})
}

// ---------------------------------------------------------------------------
// BATOU-ENC-001: Double encoding vulnerability
// ---------------------------------------------------------------------------

type DoubleEncoding struct{}

func (r *DoubleEncoding) ID() string                     { return "BATOU-ENC-001" }
func (r *DoubleEncoding) Name() string                   { return "DoubleEncoding" }
func (r *DoubleEncoding) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DoubleEncoding) Description() string {
	return "Detects double-encoding patterns where encoding functions are nested, which can cause encoding bypass vulnerabilities or data corruption."
}
func (r *DoubleEncoding) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp}
}

func (r *DoubleEncoding) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var m string
		if loc := reDoubleEncode.FindString(line); loc != "" {
			m = loc
		} else if loc := reDoubleEscapeHTML.FindString(line); loc != "" {
			m = loc
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Double encoding detected",
				Description:   "Nested encoding functions can cause double-encoding, which may bypass security filters that only decode once. Data will be incorrectly encoded/escaped, potentially creating injection vectors.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Encode data exactly once at the output boundary. Remove the nested encoding call.",
				CWEID:         "CWE-174",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"encoding", "double-encoding"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-ENC-002: Missing output encoding before HTML insertion
// ---------------------------------------------------------------------------

type MissingOutputEncoding struct{}

func (r *MissingOutputEncoding) ID() string                     { return "BATOU-ENC-002" }
func (r *MissingOutputEncoding) Name() string                   { return "MissingOutputEncoding" }
func (r *MissingOutputEncoding) DefaultSeverity() rules.Severity { return rules.High }
func (r *MissingOutputEncoding) Description() string {
	return "Detects variables inserted into HTML strings via concatenation or formatting without output encoding, enabling XSS."
}
func (r *MissingOutputEncoding) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp}
}

func (r *MissingOutputEncoding) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var matched bool
		if reHTMLConcatVar.MatchString(line) || reHTMLFmtInsert.MatchString(line) {
			// Check if encoding is applied nearby
			if !reEscapeFuncNearby.MatchString(line) && !reEscapeFuncNearby.MatchString(nearbyLines(lines, i, 3)) {
				matched = true
			}
		}
		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing output encoding before HTML insertion",
				Description:   "Variables are inserted into HTML strings without HTML entity encoding. If the variable contains user input, this creates an XSS vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Apply HTML entity encoding to all variables before inserting into HTML. Use html.EscapeString (Go), html.escape (Python), or a template engine with auto-escaping.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"encoding", "xss", "output-encoding"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-ENC-003: Incorrect character encoding declaration
// ---------------------------------------------------------------------------

type IncorrectCharEncoding struct{}

func (r *IncorrectCharEncoding) ID() string                     { return "BATOU-ENC-003" }
func (r *IncorrectCharEncoding) Name() string                   { return "IncorrectCharEncoding" }
func (r *IncorrectCharEncoding) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *IncorrectCharEncoding) Description() string {
	return "Detects use of legacy or non-UTF-8 character encodings (ISO-8859-1, Shift_JIS, etc.) which can enable encoding-based XSS attacks through character set confusion."
}
func (r *IncorrectCharEncoding) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *IncorrectCharEncoding) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var m string
		if loc := reContentTypeBadEnc.FindString(line); loc != "" {
			m = loc
		} else if loc := reCharsetHeader.FindString(line); loc != "" {
			m = loc
		} else if loc := reCharsetMeta.FindString(line); loc != "" {
			m = loc
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Non-UTF-8 character encoding declaration",
				Description:   "Using legacy character encodings (ISO-8859-1, Shift_JIS, etc.) can enable encoding-based XSS attacks. Browsers may misinterpret byte sequences in non-UTF-8 encodings as HTML special characters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use UTF-8 encoding consistently: charset=utf-8 in Content-Type headers and <meta charset=\"utf-8\"> in HTML.",
				CWEID:         "CWE-838",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"encoding", "charset", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-ENC-004: URL encoding bypass
// ---------------------------------------------------------------------------

type URLEncodingBypass struct{}

func (r *URLEncodingBypass) ID() string                     { return "BATOU-ENC-004" }
func (r *URLEncodingBypass) Name() string                   { return "URLEncodingBypass" }
func (r *URLEncodingBypass) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *URLEncodingBypass) Description() string {
	return "Detects security checks that reference percent-encoded characters, suggesting the check may be bypassable with different encoding forms (double encoding, mixed case, Unicode encoding)."
}
func (r *URLEncodingBypass) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *URLEncodingBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := rePercentEncodedCheck.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "URL encoding bypass in security check",
				Description:   "Security checks that match specific percent-encoded sequences can be bypassed using double encoding, different case, or Unicode encoding. Always decode before checking.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Decode URL-encoded input fully before performing security checks. Use canonical form comparison. Apply checks after all decoding layers.",
				CWEID:         "CWE-177",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"encoding", "bypass", "url-encoding"},
			})
		} else if m := reSecurityCheck.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "URL encoding bypass in security check",
				Description:   "Security checks that reference encoded characters may not catch all encoding variations. Attackers can use double-encoding or alternate encoding schemes to bypass these filters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Fully decode input before applying security checks. Never check for specific encoded patterns.",
				CWEID:         "CWE-177",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"encoding", "bypass", "url-encoding"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-ENC-005: Base64 used as encryption
// ---------------------------------------------------------------------------

type Base64AsEncryption struct{}

func (r *Base64AsEncryption) ID() string                     { return "BATOU-ENC-005" }
func (r *Base64AsEncryption) Name() string                   { return "Base64AsEncryption" }
func (r *Base64AsEncryption) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *Base64AsEncryption) Description() string {
	return "Detects use of Base64 encoding in contexts that suggest it is being used as encryption. Base64 is an encoding scheme, not encryption, and provides zero confidentiality."
}
func (r *Base64AsEncryption) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp}
}

func (r *Base64AsEncryption) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var m string
		if loc := reBase64AsEncrypt.FindString(line); loc != "" {
			m = loc
		} else if loc := reBase64FuncCrypto.FindString(line); loc != "" {
			m = loc
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Base64 encoding used as encryption",
				Description:   "Base64 is a reversible encoding, not encryption. It provides zero confidentiality. Any sensitive data \"encrypted\" with Base64 can be trivially decoded by anyone.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use proper encryption (AES-256-GCM or ChaCha20-Poly1305) for confidentiality. Base64 is only appropriate for transport encoding of binary data.",
				CWEID:         "CWE-326",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"encoding", "crypto", "base64"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-ENC-006: Unicode normalization bypass
// ---------------------------------------------------------------------------

type UnicodeNormBypass struct{}

func (r *UnicodeNormBypass) ID() string                     { return "BATOU-ENC-006" }
func (r *UnicodeNormBypass) Name() string                   { return "UnicodeNormBypass" }
func (r *UnicodeNormBypass) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UnicodeNormBypass) Description() string {
	return "Detects security checks that may be bypassable via Unicode normalization or homoglyph attacks, where visually similar Unicode characters bypass character-based filters."
}
func (r *UnicodeNormBypass) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangRuby}
}

func (r *UnicodeNormBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if file has security checks but no normalization
	hasSecurityCheck := reSecurityCheckAfterNorm.MatchString(ctx.Content)
	hasNormalization := reUnicodeNormCheck.MatchString(ctx.Content)

	if !hasSecurityCheck {
		return nil
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if reHomoglyphPattern.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unicode homoglyph or special character detected",
				Description:   "Fullwidth or confusable Unicode characters detected. These can bypass security filters that only check ASCII characters. For example, fullwidth '<' (U+FF1C) may bypass XSS filters.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Apply Unicode normalization (NFKC) before security checks. Restrict input to expected character ranges. Use allowlists instead of blocklists.",
				CWEID:         "CWE-176",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"encoding", "unicode", "homoglyph"},
			})
		}
	}

	// Also flag security checks without normalization in files that handle user input
	if !hasNormalization && strings.Contains(strings.ToLower(ctx.Content), "request") {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if reSecurityCheckAfterNorm.MatchString(line) && strings.Contains(strings.ToLower(line), "unicode") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Unicode normalization missing before security check",
					Description:   "Security check references Unicode but no normalization (NFC/NFKC) is applied. Attackers can use different Unicode representations of the same character to bypass filters.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(trimmed, 120),
					Suggestion:    "Apply NFKC normalization to user input before performing security checks.",
					CWEID:         "CWE-176",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"encoding", "unicode", "normalization"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-ENC-007: Mixed encoding in SQL query
// ---------------------------------------------------------------------------

type MixedEncodingSQL struct{}

func (r *MixedEncodingSQL) ID() string                     { return "BATOU-ENC-007" }
func (r *MixedEncodingSQL) Name() string                   { return "MixedEncodingSQL" }
func (r *MixedEncodingSQL) DefaultSeverity() rules.Severity { return rules.High }
func (r *MixedEncodingSQL) Description() string {
	return "Detects SQL queries that use encoding functions (CHAR, CHR, UNHEX, hex literals) to construct values, which is a common SQL injection obfuscation technique."
}
func (r *MixedEncodingSQL) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *MixedEncodingSQL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var m string
		var desc string
		if loc := reSQLCharConcat.FindString(line); loc != "" {
			m = loc
			desc = "CHAR()/CHR() concatenation in SQL (common injection obfuscation)"
		} else if loc := reMixedEncodingSQL.FindString(line); loc != "" {
			m = loc
			desc = "SQL query uses encoding functions (CHAR/CHR/UNHEX/hex) to construct values"
		} else if loc := reSQLHexLiteral.FindString(line); loc != "" {
			// Only flag hex literals if they appear in a SQL context
			lower := strings.ToLower(line)
			if strings.Contains(lower, "select") || strings.Contains(lower, "insert") ||
				strings.Contains(lower, "update") || strings.Contains(lower, "where") ||
				strings.Contains(lower, "union") {
				m = loc
				desc = "Hex literal in SQL query (potential encoded injection payload)"
			}
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Mixed encoding in SQL query",
				Description:   desc + ". Attackers use CHAR()/CHR()/UNHEX()/hex to bypass SQL injection filters by encoding the payload in a form the filter does not recognize.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use parameterized queries to prevent SQL injection. If reviewing queries, be aware that CHAR/CHR/UNHEX/hex can encode malicious payloads.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"encoding", "sql-injection", "obfuscation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-ENC-008: Null byte injection via encoding
// ---------------------------------------------------------------------------

type NullByteInjection struct{}

func (r *NullByteInjection) ID() string                     { return "BATOU-ENC-008" }
func (r *NullByteInjection) Name() string                   { return "NullByteInjection" }
func (r *NullByteInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *NullByteInjection) Description() string {
	return "Detects null byte sequences (%00, \\x00, \\0) in file operations or security checks, which can truncate strings in C-based runtimes to bypass file extension and path checks."
}
func (r *NullByteInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangPHP, rules.LangRuby, rules.LangC, rules.LangCPP, rules.LangPerl}
}

func (r *NullByteInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var m string
		var conf string
		if loc := reNullByteInPath.FindString(line); loc != "" {
			m = loc
			conf = "high"
		} else if loc := reNullByteInCheck.FindString(line); loc != "" {
			m = loc
			conf = "high"
		} else if loc := reNullByteInInput.FindString(line); loc != "" {
			m = loc
			conf = "high"
		} else if loc := reNullByteParam.FindString(line); loc != "" {
			// Only flag generic null bytes in security-relevant contexts
			lower := strings.ToLower(line)
			if strings.Contains(lower, "file") || strings.Contains(lower, "path") ||
				strings.Contains(lower, "include") || strings.Contains(lower, "require") ||
				strings.Contains(lower, "open") || strings.Contains(lower, "read") {
				m = loc
				conf = "medium"
			}
		}
		if m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Null byte injection via encoding",
				Description:   "Null bytes (%00, \\x00, \\0) in file paths or security checks can truncate strings at the C level, bypassing file extension validation and path restrictions. For example, 'malicious.php%00.jpg' passes a .jpg check but the server processes it as .php.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Strip or reject null bytes from all user input. Use language-level path validation that is not affected by null bytes.",
				CWEID:         "CWE-626",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    conf,
				Tags:          []string{"encoding", "null-byte", "path-traversal"},
			})
		}
	}
	return findings
}
