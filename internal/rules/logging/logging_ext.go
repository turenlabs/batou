package logging

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended logging rules
// ---------------------------------------------------------------------------

// GTSS-LOG-004: Logging passwords/secrets/tokens in plaintext
var (
	reLogPasswordVar = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|pino|bunyan|Rails\.logger|slog|zap|error_log|syslog|System\.out|System\.err|LOG|print|puts|fmt\.Print)\b[^;{}\n]*\b(?:password|passwd|pwd|secret_key|api_key|apikey|api_secret|auth_token|access_token|refresh_token|private_key|secret|client_secret|session_token|bearer_token)\b`)
)

// GTSS-LOG-005: Logging PII
var (
	reLogPII = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|pino|bunyan|Rails\.logger|slog|zap|error_log|syslog|System\.out|System\.err|LOG|print|puts|fmt\.Print)\b[^;{}\n]*\b(?:email_address|email_addr|user_email|ssn|social_security|credit_card|card_number|card_num|phone_number|phone_num|date_of_birth|dob|national_id|passport_number|driver_license)\b`)
)

// GTSS-LOG-006: Log injection via user input
var (
	reLogNewlineConcat = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|pino|bunyan|Rails\.logger|slog|zap|LOG)\.\w+\s*\([^)]*(?:\+|,|\$\{|%s|%v|%d|\{[^}]*\}).*(?:user|input|name|param|query|header|cookie|referer|agent)\w*`)
	reNewlineStrip     = regexp.MustCompile(`(?i)(?:\.replace\s*\(\s*[/'"]\s*[\[\\].*[rn]|\.replaceAll\s*\(\s*["']\\[rn]|strings\.Replace.*\\n|\.gsub.*\\n|strip|sanitize_log)`)
)

// GTSS-LOG-007: Logging full stack traces to client
var (
	reStackToClient = regexp.MustCompile(`(?i)(?:res\.(?:send|json|status|write)|response\.(?:write|send|body)|render|HttpResponse|JsonResponse|jsonify)\s*\([^)]*(?:stack_?trace|\.stack|traceback|stackTrace|getStackTrace|backtrace|format_exc)`)
)

// GTSS-LOG-008: Debug logging enabled in production
var (
	reDebugLogLevel = regexp.MustCompile(`(?i)(?:log_?level|logging\.level|LOG_LEVEL|log\.level|logger\.level|setLevel|basicConfig)\s*(?:[:=]\s*|\(\s*)(?:['"]?(?:DEBUG|TRACE|ALL|VERBOSE)['"]?)`)
	reProdContext   = regexp.MustCompile(`(?i)(?:production|prod\.|\.prod|deploy|release)`)
)

// GTSS-LOG-009: Logging HTTP request bodies
var (
	reLogRequestBody = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|pino|bunyan|Rails\.logger|slog|zap|LOG|System\.out)\.\w+\s*\([^)]*(?:req(?:uest)?\.body|request\.data|request\.POST|request\.content|r\.Body|getInputStream|getReader|request\.get_data)`)
)

// GTSS-LOG-010: Excessive logging
var (
	reLogEveryRequest = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|LOG)\.\w+\s*\([^)]*(?:every|all)\s+(?:request|req)`)
	reLogFullObject   = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|LOG)\.\w+\s*\(\s*(?:JSON\.stringify\s*\(\s*(?:req|request)|util\.inspect\s*\(\s*(?:req|request)|%\+v.*(?:req|request)|repr\s*\(\s*request)`)
)

// GTSS-LOG-011: Missing audit logging for security events
var (
	reSecurityEvent    = regexp.MustCompile(`(?i)(?:login|sign_?in|authenticate|authorize|change_?password|reset_?password|delete_?(?:account|user)|grant_?(?:role|permission)|revoke|escalat|admin_?access|mfa|two_?factor)`)
	reAuditLog         = regexp.MustCompile(`(?i)(?:audit|security)[\._]?(?:log|event|record|trail)`)
	reLogCall          = regexp.MustCompile(`(?i)(?:log|logger|logging|console|winston|slog|zap|LOG)\.\w+\s*\(`)
)

// ---------------------------------------------------------------------------
// GTSS-LOG-004: Logging Passwords/Secrets/Tokens in Plaintext
// ---------------------------------------------------------------------------

type LoggingSecrets struct{}

func (r *LoggingSecrets) ID() string                     { return "GTSS-LOG-004" }
func (r *LoggingSecrets) Name() string                   { return "LoggingSecrets" }
func (r *LoggingSecrets) DefaultSeverity() rules.Severity { return rules.High }
func (r *LoggingSecrets) Description() string {
	return "Detects logging statements that include password, secret, token, or API key variables in plaintext."
}
func (r *LoggingSecrets) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *LoggingSecrets) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reLogPasswordVar.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Logging password/secret/token in plaintext",
				Description:   "A logging statement references a variable containing a password, secret, token, or API key. Secrets in logs can be exposed through log aggregation systems, monitoring dashboards, and log files.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Never log secrets. Redact sensitive fields before logging: log only '[REDACTED]' or a hash of the value. Use structured logging with field exclusion lists.",
				CWEID:         "CWE-532",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"logging", "secrets", "password", "cwe-532"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-005: Logging PII
// ---------------------------------------------------------------------------

type LoggingPII struct{}

func (r *LoggingPII) ID() string                     { return "GTSS-LOG-005" }
func (r *LoggingPII) Name() string                   { return "LoggingPII" }
func (r *LoggingPII) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LoggingPII) Description() string {
	return "Detects logging statements that include personally identifiable information such as email addresses, SSN, credit card numbers, or phone numbers."
}
func (r *LoggingPII) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *LoggingPII) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reLogPII.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Logging personally identifiable information (PII)",
				Description:   "A logging statement references a variable containing PII such as email, SSN, credit card number, or phone number. Logging PII violates GDPR, PCI-DSS, and HIPAA regulations.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Mask or redact PII before logging. For emails: log only the domain portion. For credit cards: log only the last 4 digits. For SSN: log only 'XXX-XX-' prefix. Use a PII detection library for automated redaction.",
				CWEID:         "CWE-532",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"logging", "pii", "gdpr", "cwe-532"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-006: Log Injection via User Input
// ---------------------------------------------------------------------------

type LogInjectionUserInput struct{}

func (r *LogInjectionUserInput) ID() string                     { return "GTSS-LOG-006" }
func (r *LogInjectionUserInput) Name() string                   { return "LogInjectionUserInput" }
func (r *LogInjectionUserInput) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LogInjectionUserInput) Description() string {
	return "Detects log statements that include user-controlled input without newline stripping, enabling log injection and log forging attacks."
}
func (r *LogInjectionUserInput) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *LogInjectionUserInput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reLogNewlineConcat.FindStringIndex(line); loc != nil {
			if reNewlineStrip.MatchString(line) {
				continue
			}
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Log injection via user-controlled input without newline stripping",
				Description:   "User input containing newline characters (\\r\\n) is included in log messages. Attackers can forge log entries, inject fake audit records, or corrupt log analysis systems.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Strip newline characters (\\r, \\n) and control characters from user input before logging. Use structured logging (JSON format) where fields are properly escaped.",
				CWEID:         "CWE-117",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"logging", "injection", "crlf", "cwe-117"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-007: Logging Full Stack Traces to Client
// ---------------------------------------------------------------------------

type StackTraceToClient struct{}

func (r *StackTraceToClient) ID() string                     { return "GTSS-LOG-007" }
func (r *StackTraceToClient) Name() string                   { return "StackTraceToClient" }
func (r *StackTraceToClient) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *StackTraceToClient) Description() string {
	return "Detects stack traces or detailed error information being sent in HTTP responses to clients, leaking internal implementation details."
}
func (r *StackTraceToClient) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP}
}

func (r *StackTraceToClient) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reStackToClient.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Stack trace sent to client in HTTP response",
				Description:   "A full stack trace or detailed error information is included in an HTTP response. Stack traces reveal internal file paths, library versions, database schema, and other details useful for crafting targeted attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Log the full stack trace server-side for debugging. Return only a generic error message and a correlation ID to the client: {error: 'Internal server error', requestId: 'abc123'}.",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"logging", "stack-trace", "information-disclosure", "cwe-209"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-008: Debug Logging Enabled in Production Config
// ---------------------------------------------------------------------------

type DebugLoggingInProd struct{}

func (r *DebugLoggingInProd) ID() string                     { return "GTSS-LOG-008" }
func (r *DebugLoggingInProd) Name() string                   { return "DebugLoggingInProd" }
func (r *DebugLoggingInProd) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DebugLoggingInProd) Description() string {
	return "Detects debug or trace log level enabled in production configuration files, which can leak sensitive information through verbose logging."
}
func (r *DebugLoggingInProd) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *DebugLoggingInProd) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reDebugLogLevel.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			// Higher confidence if file path or content suggests production
			confidence := "medium"
			if reProdContext.MatchString(ctx.FilePath) || reProdContext.MatchString(ctx.Content) {
				confidence = "high"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Debug log level enabled (potential production misconfiguration)",
				Description:   "The log level is set to DEBUG or TRACE, which produces verbose output including internal state, query parameters, request bodies, and other sensitive data. In production, this creates excessive log volume and information disclosure risks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set log level to INFO or WARN in production. Use environment variables to control log levels: LOG_LEVEL=INFO in production, LOG_LEVEL=DEBUG in development only.",
				CWEID:         "CWE-215",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"logging", "debug", "misconfiguration", "cwe-215"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-009: Logging HTTP Request Bodies
// ---------------------------------------------------------------------------

type LoggingRequestBodies struct{}

func (r *LoggingRequestBodies) ID() string                     { return "GTSS-LOG-009" }
func (r *LoggingRequestBodies) Name() string                   { return "LoggingRequestBodies" }
func (r *LoggingRequestBodies) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LoggingRequestBodies) Description() string {
	return "Detects logging of HTTP request bodies which may contain sensitive data such as passwords, tokens, or personal information."
}
func (r *LoggingRequestBodies) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *LoggingRequestBodies) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reLogRequestBody.FindStringIndex(line); loc != nil {
			matched := line[loc[0]:loc[1]]
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Logging HTTP request body (may contain sensitive data)",
				Description:   "HTTP request bodies are being logged, which may contain passwords, authentication tokens, credit card numbers, personal data, and other sensitive information submitted through forms or APIs.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Do not log full request bodies. If request logging is needed, redact sensitive fields (password, token, credit_card, ssn) before logging. Use a middleware that filters known sensitive field names.",
				CWEID:         "CWE-532",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"logging", "request-body", "sensitive-data", "cwe-532"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-010: Excessive Logging Causing Information Disclosure
// ---------------------------------------------------------------------------

type ExcessiveLogging struct{}

func (r *ExcessiveLogging) ID() string                     { return "GTSS-LOG-010" }
func (r *ExcessiveLogging) Name() string                   { return "ExcessiveLogging" }
func (r *ExcessiveLogging) DefaultSeverity() rules.Severity { return rules.Low }
func (r *ExcessiveLogging) Description() string {
	return "Detects patterns of excessive logging such as logging every request or serializing entire request objects, which can cause information disclosure and performance issues."
}
func (r *ExcessiveLogging) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangGo}
}

func (r *ExcessiveLogging) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		matched := ""
		if loc := reLogFullObject.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		} else if loc := reLogEveryRequest.FindStringIndex(line); loc != nil {
			matched = line[loc[0]:loc[1]]
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Excessive logging (full request object serialized)",
				Description:   "Full request objects are being serialized into logs. This can expose headers (including Authorization), cookies, body content, and other sensitive data. It also impacts performance and increases log storage costs.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Log only specific fields needed for debugging or auditing. Use structured logging to select relevant fields: {method, path, status, duration}. Never serialize entire request objects.",
				CWEID:         "CWE-532",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"logging", "excessive", "information-disclosure", "cwe-532"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-LOG-011: Missing Audit Logging for Security Events
// ---------------------------------------------------------------------------

type MissingAuditLogging struct{}

func (r *MissingAuditLogging) ID() string                     { return "GTSS-LOG-011" }
func (r *MissingAuditLogging) Name() string                   { return "MissingAuditLogging" }
func (r *MissingAuditLogging) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingAuditLogging) Description() string {
	return "Detects security-critical functions (login, password change, role assignment) that lack audit logging, making it impossible to detect or investigate security incidents."
}
func (r *MissingAuditLogging) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *MissingAuditLogging) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only check files that contain security-related functions
	if !reSecurityEvent.MatchString(ctx.Content) {
		return nil
	}

	// If audit logging is present anywhere in the file, skip
	if reAuditLog.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reSecurityEvent.FindStringIndex(line); loc != nil {
			// Check if there's a log call within a window after this line
			hasLogging := false
			end := i + 15
			if end > len(lines) {
				end = len(lines)
			}
			for _, subsequent := range lines[i:end] {
				if reLogCall.MatchString(subsequent) {
					hasLogging = true
					break
				}
			}
			if !hasLogging {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Missing audit logging for security-critical operation",
					Description:   "A security-critical operation (authentication, authorization, password change, role assignment) does not appear to have audit logging. Without audit trails, security incidents cannot be detected, investigated, or attributed.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Add audit logging for all security events: login attempts (success/failure), password changes, permission changes, account modifications. Include user identity, timestamp, IP address, and action details.",
					CWEID:         "CWE-778",
					OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
					Language:      ctx.Language,
					Confidence:    "low",
					Tags:          []string{"logging", "audit", "security-events", "cwe-778"},
				})
				return findings // one finding per file
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&LoggingSecrets{})
	rules.Register(&LoggingPII{})
	rules.Register(&LogInjectionUserInput{})
	rules.Register(&StackTraceToClient{})
	rules.Register(&DebugLoggingInProd{})
	rules.Register(&LoggingRequestBodies{})
	rules.Register(&ExcessiveLogging{})
	rules.Register(&MissingAuditLogging{})
}
