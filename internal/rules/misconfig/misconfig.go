package misconfig

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled regex patterns ---

// GTSS-MISC-001: Debug mode enabled
var (
	// Python/Django: DEBUG = True
	reDjangoDebug     = regexp.MustCompile(`\bDEBUG\s*=\s*True\b`)
	// Python/Flask: app.debug = True or app.run(debug=True)
	reFlaskDebug      = regexp.MustCompile(`\bapp\.debug\s*=\s*True\b`)
	reFlaskRunDebug   = regexp.MustCompile(`\bapp\.run\s*\([^)]*debug\s*=\s*True`)
	// Ruby/Rails: config.consider_all_requests_local = true
	reRailsDebug      = regexp.MustCompile(`config\.consider_all_requests_local\s*=\s*true`)
	// PHP: display_errors = On, or ini_set('display_errors', '1')
	rePHPDisplayErrors = regexp.MustCompile(`(?i)display_errors\s*=\s*['"]?(?:On|1|true)['"]?`)
	rePHPIniDisplay    = regexp.MustCompile(`ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"](?:1|On|true)['"]`)
	rePHPErrorReporting = regexp.MustCompile(`error_reporting\s*\(\s*E_ALL\s*\)`)
	// JS/Express: NODE_ENV !== 'production' or explicit debug flags
	reNodeEnvDev       = regexp.MustCompile(`NODE_ENV\s*=\s*['"](?:development|dev)['"]`)
	// Generic debug flags
	reGenericDebugTrue = regexp.MustCompile(`(?i)\bdebug[_\-]?mode\s*[:=]\s*(?:true|1|['"]true['"]|['"]1['"])`)
)

// GTSS-MISC-002: Verbose error disclosure
var (
	// JS/Node: res.send(err.stack) or res.status(500).send(err.stack)
	reJSErrStack       = regexp.MustCompile(`res\.(?:\w+\s*\([^)]*\)\s*\.)*\w+\s*\(\s*(?:err|error)\.stack\b`)
	reJSErrMessage     = regexp.MustCompile(`res\.(?:json|send)\s*\(\s*\{[^}]*(?:err|error)\.(?:message|stack)`)
	reJSSendErr        = regexp.MustCompile(`res\.(?:send|json|status\s*\(\s*\d+\s*\)\s*\.(?:send|json))\s*\(\s*(?:err|error)\s*\)`)
	// Python: traceback.format_exc() in response, or returning str(e)
	rePyTracebackResp  = regexp.MustCompile(`(?:return|response|Response)\s*.*traceback\.format_exc\s*\(`)
	rePyStrException   = regexp.MustCompile(`(?:return|response|Response|jsonify)\s*.*str\s*\(\s*(?:e|ex|exc|err|error)\s*\)`)
	// Java: printStackTrace() or e.getMessage() in response
	reJavaPrintStack   = regexp.MustCompile(`\.printStackTrace\s*\(`)
	reJavaErrInResp    = regexp.MustCompile(`(?:response|resp|res|writer)\.\w+\(.*(?:\.getMessage|\.getStackTrace|\.toString)\s*\(`)
	// PHP: var_dump or print_r of exceptions
	rePHPVarDumpErr    = regexp.MustCompile(`(?:var_dump|print_r|var_export)\s*\(\s*\$(?:e|ex|err|error|exception)`)
	// Generic: stack trace patterns in HTTP responses
	reStackTraceResp   = regexp.MustCompile(`(?i)(?:response|res|resp)\.\w+\(.*(?:stack_?trace|stackTrace|full_?error)`)
)

func init() {
	rules.Register(&DebugMode{})
	rules.Register(&ErrorDisclosure{})
}

// --- GTSS-MISC-001: DebugMode ---

type DebugMode struct{}

func (r *DebugMode) ID() string                    { return "GTSS-MISC-001" }
func (r *DebugMode) Name() string                  { return "DebugMode" }
func (r *DebugMode) DefaultSeverity() rules.Severity { return rules.Medium }

func (r *DebugMode) Description() string {
	return "Detects debug mode enabled in web frameworks (Django, Flask, Rails, PHP, Express), which can leak sensitive information in production."
}

func (r *DebugMode) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangRuby, rules.LangPHP, rules.LangJavaScript, rules.LangTypeScript, rules.LangAny}
}

func (r *DebugMode) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		var matched string
		var detail string
		var suggestion string

		switch ctx.Language {
		case rules.LangPython:
			if loc := reDjangoDebug.FindString(line); loc != "" {
				matched = loc
				detail = "Django DEBUG = True"
				suggestion = "Set DEBUG = False in production settings. Use environment variables to configure: DEBUG = os.environ.get('DEBUG', 'False') == 'True'."
			} else if loc := reFlaskDebug.FindString(line); loc != "" {
				matched = loc
				detail = "Flask debug mode enabled"
				suggestion = "Set app.debug = False in production. Use environment variables: app.debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'."
			} else if loc := reFlaskRunDebug.FindString(line); loc != "" {
				matched = loc
				detail = "Flask app.run(debug=True)"
				suggestion = "Remove debug=True from app.run() in production. Use a proper WSGI server (gunicorn, uwsgi) instead of the development server."
			}
		case rules.LangRuby:
			if loc := reRailsDebug.FindString(line); loc != "" {
				matched = loc
				detail = "Rails consider_all_requests_local = true"
				suggestion = "Set config.consider_all_requests_local = false in config/environments/production.rb."
			}
		case rules.LangPHP:
			if loc := rePHPDisplayErrors.FindString(line); loc != "" {
				matched = loc
				detail = "PHP display_errors enabled"
				suggestion = "Set display_errors = Off in php.ini for production. Log errors to a file instead: log_errors = On."
			} else if loc := rePHPIniDisplay.FindString(line); loc != "" {
				matched = loc
				detail = "PHP display_errors enabled via ini_set"
				suggestion = "Remove ini_set('display_errors', '1') in production code. Configure error logging in php.ini."
			} else if loc := rePHPErrorReporting.FindString(line); loc != "" {
				matched = loc
				detail = "PHP error_reporting(E_ALL) in production context"
				suggestion = "Use error_reporting(0) or a restricted level in production. Log errors to a file instead of displaying them."
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reNodeEnvDev.FindString(line); loc != "" {
				// Only flag if it looks like a hardcoded setting, not a check
				if !strings.Contains(line, "if") && !strings.Contains(line, "===") && !strings.Contains(line, "!==") {
					matched = loc
					detail = "NODE_ENV set to development"
					suggestion = "Ensure NODE_ENV is set to 'production' in production environments. Use environment variables, not hardcoded values."
				}
			}
		}

		// Generic debug mode flag for all languages
		if matched == "" {
			if loc := reGenericDebugTrue.FindString(line); loc != "" {
				// Skip if in a comment
				if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "#") {
					matched = loc
					detail = "Debug mode flag enabled"
					suggestion = "Disable debug mode in production. Use environment variables to control debug settings."
				}
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Debug mode enabled: " + detail,
			Description:   "Debug mode exposes detailed error messages, stack traces, internal paths, and configuration details that help attackers understand the application's internals and find vulnerabilities.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   trimmed,
			Suggestion:    suggestion,
			CWEID:         "CWE-215",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"misconfig", "debug"},
		})
	}

	return findings
}

// --- GTSS-MISC-002: ErrorDisclosure ---

type ErrorDisclosure struct{}

func (r *ErrorDisclosure) ID() string                    { return "GTSS-MISC-002" }
func (r *ErrorDisclosure) Name() string                  { return "ErrorDisclosure" }
func (r *ErrorDisclosure) DefaultSeverity() rules.Severity { return rules.Low }

func (r *ErrorDisclosure) Description() string {
	return "Detects verbose error messages, stack traces, and exception details being sent in HTTP responses, which leak internal implementation details."
}

func (r *ErrorDisclosure) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangPHP}
}

func (r *ErrorDisclosure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		var matched string
		var detail string
		var suggestion string

		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := reJSErrStack.FindString(line); loc != "" {
				matched = loc
				detail = "Error stack trace sent in response"
				suggestion = "Log the full error server-side and return a generic error message to the client: res.status(500).json({error: 'Internal server error'})."
			} else if loc := reJSErrMessage.FindString(line); loc != "" {
				matched = loc
				detail = "Error details sent in response"
				suggestion = "Log the full error server-side and return a generic error message to the client."
			} else if loc := reJSSendErr.FindString(line); loc != "" {
				matched = loc
				detail = "Raw error object sent in response"
				suggestion = "Never send raw error objects to clients. Log errors server-side and return a generic message."
			}
		case rules.LangPython:
			if loc := rePyTracebackResp.FindString(line); loc != "" {
				matched = loc
				detail = "Traceback sent in HTTP response"
				suggestion = "Log tracebacks server-side using logging.exception(). Return a generic error message to clients."
			} else if loc := rePyStrException.FindString(line); loc != "" {
				matched = loc
				detail = "Exception details sent in response"
				suggestion = "Log exceptions server-side. Return a generic error message: return jsonify({'error': 'Internal server error'}), 500."
			}
		case rules.LangJava:
			if loc := reJavaPrintStack.FindString(line); loc != "" {
				matched = loc
				detail = "printStackTrace() called (may leak to client)"
				suggestion = "Use a logging framework (SLF4J, Log4j) instead of printStackTrace(). Never expose stack traces in HTTP responses."
			} else if loc := reJavaErrInResp.FindString(line); loc != "" {
				matched = loc
				detail = "Exception details written to HTTP response"
				suggestion = "Log exception details server-side. Return a generic error message to clients."
			}
		case rules.LangPHP:
			if loc := rePHPVarDumpErr.FindString(line); loc != "" {
				matched = loc
				detail = "Exception dumped to output"
				suggestion = "Use error_log() for server-side logging. Return a generic error message to clients."
			}
		}

		// Generic stack trace in response
		if matched == "" {
			if loc := reStackTraceResp.FindString(line); loc != "" {
				matched = loc
				detail = "Stack trace or error details in response"
				suggestion = "Log detailed errors server-side. Return generic error messages to clients."
			}
		}

		if matched == "" {
			continue
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Verbose error disclosure: " + detail,
			Description:   "Sending detailed error messages, stack traces, or exception details to clients reveals internal implementation details (file paths, library versions, database structure) that attackers can use to craft targeted exploits.",
			FilePath:      ctx.FilePath,
			LineNumber:    lineNum,
			MatchedText:   trimmed,
			Suggestion:    suggestion,
			CWEID:         "CWE-209",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"misconfig", "error-disclosure"},
		})
	}

	return findings
}
