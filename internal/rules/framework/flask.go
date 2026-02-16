package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns — Flask
// ---------------------------------------------------------------------------

// Flask Misconfiguration (BATOU-FW-FLASK-001)
var (
	// app.run(debug=True) or app.run(..., debug=True, ...)
	reFlaskDebugRun = regexp.MustCompile(`(?i)\.run\s*\([^)]*debug\s*=\s*True`)
	// app.secret_key = 'hardcoded' or "hardcoded" (short/weak keys)
	reFlaskSecretKey = regexp.MustCompile(`(?i)(?:app\.secret_key|app\.config\s*\[\s*["']SECRET_KEY["']\s*\])\s*=\s*["'][^"']+["']`)
	// app.config['SESSION_COOKIE_SECURE'] = False
	reFlaskSessionCookieInsecure = regexp.MustCompile(`(?i)app\.config\s*\[\s*["']SESSION_COOKIE_SECURE["']\s*\]\s*=\s*False`)
)

// Flask SSTI (BATOU-FW-FLASK-002)
var (
	// render_template_string(user_input) — variable, not a string literal
	reFlaskRenderTemplateString = regexp.MustCompile(`(?i)\brender_template_string\s*\(\s*(?:f["']|[^"'\s)][^)]*\+|[^"'\s)][^)]*\.format\s*\(|[^"'\s)][^)]*%|request\.)`)
	// render_template_string with any non-static argument (catch broader pattern)
	reFlaskRenderTemplateStringVar = regexp.MustCompile(`(?i)\brender_template_string\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
)

// Flask Path Traversal (BATOU-FW-FLASK-003)
var (
	// send_file(user_input) — variable argument without validation
	reFlaskSendFile = regexp.MustCompile(`(?i)\bsend_file\s*\(\s*(?:request\.|[a-zA-Z_]\w*\s*[,)])`)
	// send_from_directory with user-controlled filename
	reFlaskSendFromDir = regexp.MustCompile(`(?i)\bsend_from_directory\s*\([^)]*request\.`)
)

// Flask XSS (BATOU-FW-FLASK-004)
var (
	// Markup(user_input) — marks string as safe HTML
	reFlaskMarkup = regexp.MustCompile(`(?i)\bMarkup\s*\(\s*(?:f["']|[^"'\s)][^)]*\+|[^"'\s)][^)]*\.format\s*\(|[^"'\s)][^)]*%|request\.)`)
	// Markup with variable argument
	reFlaskMarkupVar = regexp.MustCompile(`(?i)\bMarkup\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
)

// ---------------------------------------------------------------------------
// BATOU-FW-FLASK-001: Flask Misconfiguration
// ---------------------------------------------------------------------------

type FlaskMisconfiguration struct{}

func (r FlaskMisconfiguration) ID() string              { return "BATOU-FW-FLASK-001" }
func (r FlaskMisconfiguration) Name() string            { return "Flask Misconfiguration" }
func (r FlaskMisconfiguration) DefaultSeverity() rules.Severity { return rules.Medium }
func (r FlaskMisconfiguration) Description() string {
	return "Detects insecure Flask configurations such as debug mode enabled, hardcoded secret keys, and disabled cookie security."
}
func (r FlaskMisconfiguration) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r FlaskMisconfiguration) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re         *regexp.Regexp
		severity   rules.Severity
		confidence string
		title      string
		desc       string
		suggestion string
		cwe        string
	}

	patterns := []pattern{
		{
			re:         reFlaskDebugRun,
			severity:   rules.Medium,
			confidence: "high",
			title:      "Flask app.run() with debug=True",
			desc:       "Running Flask with debug=True enables the interactive debugger which allows arbitrary code execution via the Werkzeug debugger console. Never use in production.",
			suggestion: "Remove debug=True from app.run(). Use environment variables: app.run(debug=os.environ.get('FLASK_DEBUG', False))",
			cwe:        "CWE-489",
		},
		{
			re:         reFlaskSecretKey,
			severity:   rules.Critical,
			confidence: "high",
			title:      "Flask hardcoded secret key",
			desc:       "The Flask secret key is hardcoded in source code. This key is used to sign session cookies; if compromised, attackers can forge sessions and gain unauthorized access.",
			suggestion: "Load secret key from environment: app.secret_key = os.environ['SECRET_KEY'] or use a secrets manager.",
			cwe:        "CWE-798",
		},
		{
			re:         reFlaskSessionCookieInsecure,
			severity:   rules.Medium,
			confidence: "medium",
			title:      "Flask SESSION_COOKIE_SECURE disabled",
			desc:       "SESSION_COOKIE_SECURE=False allows session cookies to be transmitted over unencrypted HTTP connections.",
			suggestion: "Set app.config['SESSION_COOKIE_SECURE'] = True in production to restrict cookies to HTTPS.",
			cwe:        "CWE-614",
		},
	}

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		for _, p := range patterns {
			if p.re.MatchString(line) {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      p.severity,
					SeverityLabel: p.severity.String(),
					Title:         p.title,
					Description:   p.desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    p.suggestion,
					CWEID:         p.cwe,
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    p.confidence,
					Tags:          []string{"flask", "misconfiguration", "framework"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FLASK-002: Flask SSTI (Server-Side Template Injection)
// ---------------------------------------------------------------------------

type FlaskSSTI struct{}

func (r FlaskSSTI) ID() string              { return "BATOU-FW-FLASK-002" }
func (r FlaskSSTI) Name() string            { return "Flask Server-Side Template Injection" }
func (r FlaskSSTI) DefaultSeverity() rules.Severity { return rules.Critical }
func (r FlaskSSTI) Description() string {
	return "Detects Flask render_template_string() with user-controlled input, which leads to server-side template injection and remote code execution."
}
func (r FlaskSSTI) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r FlaskSSTI) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}

		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}

		if reFlaskRenderTemplateString.MatchString(line) || reFlaskRenderTemplateStringVar.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Flask render_template_string() with dynamic input (SSTI)",
				Description:   "render_template_string() renders a Jinja2 template from a string. If the string contains user input, attackers can inject template expressions like {{config}} or {{''.__class__.__mro__}} to achieve remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use render_template() with a template file and pass user data as context variables: render_template('page.html', name=user_input)",
				CWEID:         "CWE-1336",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"flask", "ssti", "injection", "framework"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FLASK-003: Flask Path Traversal via send_file
// ---------------------------------------------------------------------------

type FlaskPathTraversal struct{}

func (r FlaskPathTraversal) ID() string              { return "BATOU-FW-FLASK-003" }
func (r FlaskPathTraversal) Name() string            { return "Flask Path Traversal" }
func (r FlaskPathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r FlaskPathTraversal) Description() string {
	return "Detects Flask send_file() and send_from_directory() with user-controlled paths that may allow directory traversal."
}
func (r FlaskPathTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r FlaskPathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}

		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}

		if reFlaskSendFile.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Flask send_file() with user-controlled path",
				Description:   "send_file() with a user-controlled path allows attackers to read arbitrary files via directory traversal (e.g., ../../etc/passwd).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use send_from_directory() with a fixed base directory and validate the filename with secure_filename(): send_from_directory(UPLOAD_DIR, secure_filename(filename))",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"flask", "traversal", "framework"},
			})
			continue
		}

		if reFlaskSendFromDir.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Flask send_from_directory() with user-controlled filename",
				Description:   "send_from_directory() with request data as the filename can allow path traversal if not validated with secure_filename().",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate filename with secure_filename(): send_from_directory(directory, secure_filename(request.args.get('file')))",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"flask", "traversal", "framework"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FLASK-004: Flask Markup XSS
// ---------------------------------------------------------------------------

type FlaskMarkupXSS struct{}

func (r FlaskMarkupXSS) ID() string              { return "BATOU-FW-FLASK-004" }
func (r FlaskMarkupXSS) Name() string            { return "Flask Markup XSS" }
func (r FlaskMarkupXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r FlaskMarkupXSS) Description() string {
	return "Detects Flask/Jinja2 Markup() with user-controlled input that marks strings as safe HTML, bypassing auto-escaping."
}
func (r FlaskMarkupXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r FlaskMarkupXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}

		matched := strings.TrimSpace(line)
		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}

		if reFlaskMarkup.MatchString(line) || reFlaskMarkupVar.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Flask Markup() with dynamic content (XSS)",
				Description:   "Markup() marks a string as safe HTML, bypassing Jinja2 auto-escaping. If the argument contains user input, attackers can inject arbitrary HTML and JavaScript.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use Markup.escape() to sanitize user input before wrapping in Markup(), or use Jinja2 auto-escaping by passing data as template variables.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"flask", "xss", "framework"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(FlaskMisconfiguration{})
	rules.Register(FlaskSSTI{})
	rules.Register(FlaskPathTraversal{})
	rules.Register(FlaskMarkupXSS{})
}
