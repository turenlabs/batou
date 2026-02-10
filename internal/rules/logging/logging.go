package logging

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// LOG-001: Unsanitized user input in log calls

// Python
var (
	reLogPyLogging = regexp.MustCompile(`(?i)logging\.(info|warning|error|debug|critical)\s*\(.*(?:request\.|req\.|params|query|body|user_input|form\[)`)
	reLogPyLogger  = regexp.MustCompile(`(?i)logger\.(info|warning|error|debug|critical)\s*\(.*(?:request\.|req\.|params\[|query|body|user_input|form\[)`)
)

// Java
var (
	reLogJavaLogger     = regexp.MustCompile(`(?i)(?:log|logger|LOG)\.\w+\s*\(.*(?:request\.getParameter|req\.getParameter|getHeader)\s*\(`)
	reLogJavaSlf4j      = regexp.MustCompile(`(?i)(?:log|logger|LOG)\.(?:info|warn|error|debug|trace)\s*\(.*(?:request\.getParameter|HttpServletRequest|getHeader|getQueryString)`)
	reLogJavaSysOut     = regexp.MustCompile(`(?i)System\.(?:out|err)\.print(?:ln)?\s*\(.*(?:request\.getParameter|req\.getParameter|getHeader)`)
)

// Go
var (
	reLogGoLog  = regexp.MustCompile(`(?i)(?:log|slog)\.(?:Print|Fatal|Panic|Info|Warn|Error|Debug)(?:f|ln|w|Context)?\s*\(.*(?:r\.URL|r\.Form|r\.Header|r\.Body|c\.Query|c\.Param|r\.FormValue|r\.PostFormValue)`)
	reLogGoZap  = regexp.MustCompile(`(?i)(?:zap|logger|sugar)\.(?:Info|Warn|Error|Debug|Fatal|Panic)(?:f|w)?\s*\(.*(?:r\.URL|r\.Form|r\.Header|c\.Query|c\.Param|r\.FormValue)`)
)

// JS/TS
var (
	reLogJSConsole = regexp.MustCompile(`(?i)(?:console|logger|winston|pino|bunyan)\.(?:log|warn|error|info|debug|trace)\s*\(.*(?:req\.body|req\.query|req\.params|req\.headers|request\.body|request\.query|request\.params)`)
)

// PHP
var (
	reLogPHP = regexp.MustCompile(`(?i)(?:error_log|syslog|Log::(?:info|warning|error|debug|critical|emergency|notice))\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)`)
)

// Ruby
var (
	reLogRuby = regexp.MustCompile(`(?i)(?:logger|Rails\.logger)\.(?:info|warn|error|debug|fatal)\s*[\(\s].*(?:params\[|request\.|cookies\[)`)
)

// LOG-002: CRLF injection in log messages
var (
	// Log call with string concat/interpolation from request/user variable without newline stripping
	reLogCRLFConcat   = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|pino|bunyan|Rails\.logger|slog|zap)\.\w+\s*\(.*[\+].*(?:req|request|params|query|body|user|input|header)`)
	reLogCRLFFString  = regexp.MustCompile(`(?i)(?:logger|logging)\.\w+\s*\(\s*f["'].*\{.*(?:request|req|params|query|body|user|input)`)
	reLogCRLFTemplate = regexp.MustCompile("(?i)(?:console|logger|winston|pino|bunyan)\\.\\w+\\s*\\(\\s*`[^`]*\\$\\{.*(?:req|request|params|query|body|user|input)")
	reLogCRLFFormat   = regexp.MustCompile(`(?i)(?:log|logger|LOG)\.\w+\s*\(\s*String\.format\s*\(.*(?:request\.getParameter|getHeader|getQueryString)`)
	reLogCRLFSprintf  = regexp.MustCompile(`(?i)(?:log|slog)\.\w+\s*\(\s*fmt\.Sprintf\s*\(.*(?:r\.URL|r\.Form|r\.Header|r\.Body|c\.Query)`)
	reLogCRLFPHP      = regexp.MustCompile(`(?i)(?:error_log|syslog|Log::)\s*\(.*\.\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)`)
	reLogCRLFRuby     = regexp.MustCompile(`(?i)(?:logger|Rails\.logger)\.\w+\s*[\(\s].*#\{.*(?:params|request|cookies)`)
)

// LOG-003: Sensitive data in logs
var (
	reLogSensitiveGeneric = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|pino|bunyan|Rails\.logger|slog|zap|error_log|syslog|System\.out\.print|System\.err\.print|LOG)\.\w+\s*\(.*\b(password|passwd|pwd|secret|api_key|apikey|api_secret|token|access_token|refresh_token|auth_token|credit.?card|card.?number|cvv|ssn|social.?security|private.?key|secret.?key)\b`)
	reLogSensitivePHP     = regexp.MustCompile(`(?i)(?:error_log|syslog|Log::)\s*\(.*\b(password|passwd|pwd|secret|api_key|apikey|token|credit.?card|ssn|private.?key)\b`)
)

// ---------------------------------------------------------------------------
// Comment detection (false positive reduction)
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*(?://|#|--|;|%|/\*|\*\s)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// GTSS-LOG-001: Unsanitized User Input in Log Calls
// ---------------------------------------------------------------------------

type UnsanitizedLogInput struct{}

func (r UnsanitizedLogInput) ID() string              { return "GTSS-LOG-001" }
func (r UnsanitizedLogInput) Name() string            { return "Unsanitized User Input in Log Calls" }
func (r UnsanitizedLogInput) DefaultSeverity() rules.Severity { return rules.High }
func (r UnsanitizedLogInput) Description() string {
	return "Detects user-controlled input (request parameters, query strings, headers, form data) passed directly to logging functions without sanitization, enabling log injection attacks (CWE-117)."
}
func (r UnsanitizedLogInput) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJava, rules.LangGo,
		rules.LangJavaScript, rules.LangTypeScript,
		rules.LangPHP, rules.LangRuby,
	}
}

func (r UnsanitizedLogInput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	var patterns []pattern
	switch ctx.Language {
	case rules.LangPython:
		patterns = []pattern{
			{reLogPyLogging, "high", "logging module with unsanitized request/user input"},
			{reLogPyLogger, "high", "logger with unsanitized request/user input"},
		}
	case rules.LangJava:
		patterns = []pattern{
			{reLogJavaLogger, "high", "logger with unsanitized request parameter"},
			{reLogJavaSlf4j, "high", "SLF4J/Log4j logger with unsanitized request data"},
			{reLogJavaSysOut, "medium", "System.out/err.print with unsanitized request data"},
		}
	case rules.LangGo:
		patterns = []pattern{
			{reLogGoLog, "high", "log/slog with unsanitized HTTP request data"},
			{reLogGoZap, "high", "zap logger with unsanitized HTTP request data"},
		}
	case rules.LangJavaScript, rules.LangTypeScript:
		patterns = []pattern{
			{reLogJSConsole, "high", "console/logger with unsanitized request data"},
		}
	case rules.LangPHP:
		patterns = []pattern{
			{reLogPHP, "high", "error_log/syslog/Log with unsanitized superglobal"},
		}
	case rules.LangRuby:
		patterns = []pattern{
			{reLogRuby, "high", "logger/Rails.logger with unsanitized params/request"},
		}
	default:
		return findings
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Log Injection: " + p.desc,
					Description:   "User-controlled input is passed directly to a logging function without sanitization. Attackers can inject newlines and control characters to forge log entries, hide malicious activity, or exploit log analysis tools.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Sanitize user input before logging: strip newlines (\\n, \\r), control characters, and ANSI escape sequences. Use structured logging with parameterized fields (e.g., logger.info(\"msg\", extra={\"user\": sanitized_input}) in Python, slog.Info(\"msg\", \"user\", sanitized) in Go).",
					CWEID:         "CWE-117",
					OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"logging", "injection", "cwe-117"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-002: CRLF Injection in Log Messages
// ---------------------------------------------------------------------------

type CRLFLogInjection struct{}

func (r CRLFLogInjection) ID() string              { return "GTSS-LOG-002" }
func (r CRLFLogInjection) Name() string            { return "CRLF Injection in Log Messages" }
func (r CRLFLogInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r CRLFLogInjection) Description() string {
	return "Detects log calls using string concatenation or interpolation with user-controlled variables, which enables CRLF injection to forge log entries."
}
func (r CRLFLogInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJava, rules.LangGo,
		rules.LangJavaScript, rules.LangTypeScript,
		rules.LangPHP, rules.LangRuby,
	}
}

func (r CRLFLogInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	var patterns []pattern
	switch ctx.Language {
	case rules.LangPython:
		patterns = []pattern{
			{reLogCRLFFString, "high", "f-string interpolation of user input in log call"},
			{reLogCRLFConcat, "medium", "string concatenation of user input in log call"},
		}
	case rules.LangJava:
		patterns = []pattern{
			{reLogCRLFFormat, "high", "String.format with request data in log call"},
			{reLogCRLFConcat, "medium", "string concatenation of user input in log call"},
		}
	case rules.LangGo:
		patterns = []pattern{
			{reLogCRLFSprintf, "high", "fmt.Sprintf with request data in log call"},
			{reLogCRLFConcat, "medium", "string concatenation of user input in log call"},
		}
	case rules.LangJavaScript, rules.LangTypeScript:
		patterns = []pattern{
			{reLogCRLFTemplate, "high", "template literal interpolation of request data in log call"},
			{reLogCRLFConcat, "medium", "string concatenation of user input in log call"},
		}
	case rules.LangPHP:
		patterns = []pattern{
			{reLogCRLFPHP, "high", "string concatenation of superglobal in log call"},
		}
	case rules.LangRuby:
		patterns = []pattern{
			{reLogCRLFRuby, "high", "string interpolation of params/request in log call"},
		}
	default:
		return findings
	}

	// Check for presence of sanitization on the same line
	reSanitized := regexp.MustCompile(`(?i)(?:\.replace\s*\(\s*[/'"]\s*[\[\\].*[rn]|\.replaceAll\s*\(\s*["']\\[rn]|\.gsub\s*\(\s*[/].*[rn]|strings\.Replace.+\\n|strip|sanitize|escape|encode|htmlspecialchars|htmlentities|CGI\.escape|ERB::Util\.html_escape)`)

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		// Skip lines that already sanitize
		if reSanitized.MatchString(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "CRLF Log Injection: " + p.desc,
					Description:   "Log message is constructed via string concatenation or interpolation with user-controlled input. Attackers can inject CR/LF characters (\\r\\n) to create forged log entries, obscure attack traces, or corrupt log analysis.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Strip newline characters (\\r, \\n) and control characters from user input before logging. Use structured logging with separate key-value fields instead of string interpolation.",
					CWEID:         "CWE-117",
					OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"logging", "injection", "crlf", "cwe-117"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-003: Sensitive Data in Logs
// ---------------------------------------------------------------------------

type SensitiveDataInLogs struct{}

func (r SensitiveDataInLogs) ID() string              { return "GTSS-LOG-003" }
func (r SensitiveDataInLogs) Name() string            { return "Sensitive Data in Logs" }
func (r SensitiveDataInLogs) DefaultSeverity() rules.Severity { return rules.Medium }
func (r SensitiveDataInLogs) Description() string {
	return "Detects logging of sensitive data such as passwords, tokens, API keys, credit card numbers, and SSNs. Sensitive data in logs can lead to credential leakage and regulatory violations."
}
func (r SensitiveDataInLogs) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJava, rules.LangGo,
		rules.LangJavaScript, rules.LangTypeScript,
		rules.LangPHP, rules.LangRuby,
	}
}

func (r SensitiveDataInLogs) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
	}

	var patterns []pattern
	switch ctx.Language {
	case rules.LangPHP:
		patterns = []pattern{
			{reLogSensitivePHP, "medium"},
			{reLogSensitiveGeneric, "medium"},
		}
	default:
		patterns = []pattern{
			{reLogSensitiveGeneric, "medium"},
		}
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Sensitive Data in Logs: potential credential/secret logged",
					Description:   "A logging statement appears to include sensitive data (passwords, tokens, API keys, credit card numbers, SSNs, or private keys). Sensitive data in logs can lead to credential leakage, regulatory violations (PCI-DSS, GDPR), and privilege escalation.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Never log sensitive data. Mask or redact credentials, tokens, and PII before logging. Use structured logging and ensure sensitive fields are excluded from log output.",
					CWEID:         "CWE-532",
					OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"logging", "sensitive-data", "cwe-532", "pii"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(UnsanitizedLogInput{})
	rules.Register(CRLFLogInjection{})
	rules.Register(SensitiveDataInLogs{})
}
