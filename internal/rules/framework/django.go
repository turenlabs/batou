package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns — Django
// ---------------------------------------------------------------------------

// Django Settings Misconfiguration (BATOU-FW-DJANGO-001)
var (
	// DEBUG = True in settings
	reDjangoDebugTrue = regexp.MustCompile(`(?i)\bDEBUG\s*=\s*True\b`)
	// ALLOWED_HOSTS = ['*'] or ["*"]
	reDjangoAllowedHostsStar = regexp.MustCompile(`(?i)\bALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]`)
	// SECURE_SSL_REDIRECT = False
	reDjangoSSLRedirectFalse = regexp.MustCompile(`(?i)\bSECURE_SSL_REDIRECT\s*=\s*False\b`)
	// SESSION_COOKIE_SECURE = False
	reDjangoSessionCookieInsecure = regexp.MustCompile(`(?i)\bSESSION_COOKIE_SECURE\s*=\s*False\b`)
	// CSRF_COOKIE_SECURE = False
	reDjangoCsrfCookieInsecure = regexp.MustCompile(`(?i)\bCSRF_COOKIE_SECURE\s*=\s*False\b`)
	// SESSION_COOKIE_HTTPONLY = False
	reDjangoSessionHTTPOnlyFalse = regexp.MustCompile(`(?i)\bSESSION_COOKIE_HTTPONLY\s*=\s*False\b`)
	// CORS_ALLOW_ALL_ORIGINS = True or CORS_ORIGIN_ALLOW_ALL = True
	reDjangoCorsAllowAll = regexp.MustCompile(`(?i)\bCORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True\b`)
)

// Django ORM/View Vulnerabilities (BATOU-FW-DJANGO-002)
var (
	// Model.objects.raw with f-string / format / % / concat
	reDjangoRawSQL = regexp.MustCompile(`(?i)\.objects\.raw\s*\(\s*(?:f["']|"[^"]*"\s*%|'[^']*'\s*%|"[^"]*"\s*\.format\s*\(|'[^']*'\s*\.format\s*\(|[^"'\s)][^)]*\+)`)
	// Model.objects.extra with f-string / format / % / concat in where clause
	reDjangoExtraSQL = regexp.MustCompile(`(?i)\.objects\.extra\s*\(`)
	// cursor.execute with f-string / format / % / concat (Django-specific)
	reDjangoCursorExec = regexp.MustCompile(`(?i)\bcursor\.execute\s*\(\s*(?:f["']|"[^"]*"\s*%|'[^']*'\s*%|"[^"]*"\s*\.format\s*\(|'[^']*'\s*\.format\s*\()`)
)

// Django Template/View XSS (BATOU-FW-DJANGO-003)
var (
	// {{ variable|safe }} — Jinja2/Django safe filter
	reDjangoSafeFilter = regexp.MustCompile(`\{\{\s*\w[^}]*\|\s*safe\s*\}\}`)
	// mark_safe(variable) — marks user data as safe HTML
	// Matches: mark_safe(f"..."), mark_safe("..." + var), mark_safe(var), mark_safe(request....)
	reDjangoMarkSafe = regexp.MustCompile(`\bmark_safe\s*\(\s*(?:f["']|["'][^"']*["']\s*\+|request\.|[a-zA-Z_]\w*\s*[,)\.])`)
)

// Django CSRF Exemption (BATOU-FW-DJANGO-004)
var (
	// @csrf_exempt decorator
	reDjangoCsrfExempt = regexp.MustCompile(`@csrf_exempt\b`)
)

// Django Mass Assignment (BATOU-FW-DJANGO-005)
var (
	// Model.objects.create(**request.POST) or (**request.data) or (**request.GET)
	reDjangoMassAssign = regexp.MustCompile(`(?i)\.(?:objects\.create|update|create)\s*\(\s*\*\*\s*request\.(?:POST|GET|data)\b`)
	// form = ModelForm(request.POST) without explicit fields
	reDjangoFormBindAll = regexp.MustCompile(`(?i)=\s*\w+Form\s*\(\s*request\.(?:POST|GET|data)\b`)
)

// Comment detector for Python
var rePyComment = regexp.MustCompile(`^\s*#`)

func isPyComment(line string) bool {
	return rePyComment.MatchString(line)
}

// ---------------------------------------------------------------------------
// BATOU-FW-DJANGO-001: Django Settings Misconfiguration
// ---------------------------------------------------------------------------

type DjangoSettingsMisconfig struct{}

func (r DjangoSettingsMisconfig) ID() string              { return "BATOU-FW-DJANGO-001" }
func (r DjangoSettingsMisconfig) Name() string            { return "Django Settings Misconfiguration" }
func (r DjangoSettingsMisconfig) DefaultSeverity() rules.Severity { return rules.Medium }
func (r DjangoSettingsMisconfig) Description() string {
	return "Detects insecure Django settings such as DEBUG=True, ALLOWED_HOSTS=['*'], disabled cookie security, and overly permissive CORS."
}
func (r DjangoSettingsMisconfig) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r DjangoSettingsMisconfig) Scan(ctx *rules.ScanContext) []rules.Finding {
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
	}

	patterns := []pattern{
		{
			re:         reDjangoDebugTrue,
			severity:   rules.Medium,
			confidence: "high",
			title:      "Django DEBUG=True in production",
			desc:       "DEBUG=True exposes detailed error pages with stack traces, settings, and environment variables to end users. This must be False in production.",
			suggestion: "Set DEBUG=False and use environment variables: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
		},
		{
			re:         reDjangoAllowedHostsStar,
			severity:   rules.High,
			confidence: "high",
			title:      "Django ALLOWED_HOSTS accepts all hosts",
			desc:       "ALLOWED_HOSTS=['*'] allows any Host header, enabling host header attacks and cache poisoning. Restrict to your actual domain(s).",
			suggestion: "Set ALLOWED_HOSTS to specific domains: ALLOWED_HOSTS = ['example.com', 'www.example.com']",
		},
		{
			re:         reDjangoSSLRedirectFalse,
			severity:   rules.Medium,
			confidence: "medium",
			title:      "Django SECURE_SSL_REDIRECT disabled",
			desc:       "SECURE_SSL_REDIRECT=False allows HTTP connections which can expose sensitive data in transit.",
			suggestion: "Set SECURE_SSL_REDIRECT=True to force HTTPS in production.",
		},
		{
			re:         reDjangoSessionCookieInsecure,
			severity:   rules.Medium,
			confidence: "medium",
			title:      "Django SESSION_COOKIE_SECURE disabled",
			desc:       "SESSION_COOKIE_SECURE=False allows session cookies to be sent over unencrypted HTTP connections.",
			suggestion: "Set SESSION_COOKIE_SECURE=True to restrict session cookies to HTTPS.",
		},
		{
			re:         reDjangoCsrfCookieInsecure,
			severity:   rules.Medium,
			confidence: "medium",
			title:      "Django CSRF_COOKIE_SECURE disabled",
			desc:       "CSRF_COOKIE_SECURE=False allows the CSRF token cookie to be sent over HTTP, weakening CSRF protection.",
			suggestion: "Set CSRF_COOKIE_SECURE=True to restrict CSRF cookies to HTTPS.",
		},
		{
			re:         reDjangoSessionHTTPOnlyFalse,
			severity:   rules.Medium,
			confidence: "medium",
			title:      "Django SESSION_COOKIE_HTTPONLY disabled",
			desc:       "SESSION_COOKIE_HTTPONLY=False allows JavaScript to access session cookies, increasing the impact of XSS attacks.",
			suggestion: "Set SESSION_COOKIE_HTTPONLY=True (this is Django's default) to prevent JavaScript access to session cookies.",
		},
		{
			re:         reDjangoCorsAllowAll,
			severity:   rules.High,
			confidence: "high",
			title:      "Django CORS allows all origins",
			desc:       "CORS_ALLOW_ALL_ORIGINS=True allows any origin to make cross-origin requests, potentially exposing sensitive data or APIs.",
			suggestion: "Set CORS_ALLOW_ALL_ORIGINS=False and specify allowed origins in CORS_ALLOWED_ORIGINS list.",
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
					CWEID:         "CWE-16",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    p.confidence,
					Tags:          []string{"django", "misconfiguration", "framework"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-DJANGO-002: Django ORM SQL Injection
// ---------------------------------------------------------------------------

type DjangoORMSQLInjection struct{}

func (r DjangoORMSQLInjection) ID() string              { return "BATOU-FW-DJANGO-002" }
func (r DjangoORMSQLInjection) Name() string            { return "Django ORM SQL Injection" }
func (r DjangoORMSQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r DjangoORMSQLInjection) Description() string {
	return "Detects Django ORM methods (objects.raw, objects.extra, cursor.execute) used with string formatting instead of parameterized queries."
}
func (r DjangoORMSQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r DjangoORMSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re         *regexp.Regexp
		confidence string
		title      string
		desc       string
		suggestion string
	}

	patterns := []pattern{
		{
			re:         reDjangoRawSQL,
			confidence: "high",
			title:      "Django objects.raw() with string formatting (SQL injection)",
			desc:       "Model.objects.raw() with f-strings, .format(), or % formatting allows SQL injection. Use parameterized queries with the params argument.",
			suggestion: "Use parameterized queries: Model.objects.raw('SELECT * FROM app_model WHERE id = %s', [user_id])",
		},
		{
			re:         reDjangoExtraSQL,
			confidence: "medium",
			title:      "Django objects.extra() usage (potential SQL injection)",
			desc:       "objects.extra() is deprecated and prone to SQL injection. The where parameter is particularly dangerous with string formatting.",
			suggestion: "Replace objects.extra() with ORM expressions, annotations, or RawSQL with params: RawSQL('field = %s', [value])",
		},
		{
			re:         reDjangoCursorExec,
			confidence: "high",
			title:      "Django cursor.execute() with string formatting (SQL injection)",
			desc:       "cursor.execute() with f-strings, .format(), or % formatting instead of parameterized queries allows SQL injection.",
			suggestion: "Use parameterized queries: cursor.execute('SELECT * FROM table WHERE id = %s', [user_id])",
		},
	}

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         p.title,
					Description:   p.desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    p.suggestion,
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.confidence,
					Tags:          []string{"django", "injection", "sql", "framework"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-DJANGO-003: Django Template XSS
// ---------------------------------------------------------------------------

type DjangoTemplateXSS struct{}

func (r DjangoTemplateXSS) ID() string              { return "BATOU-FW-DJANGO-003" }
func (r DjangoTemplateXSS) Name() string            { return "Django Template XSS" }
func (r DjangoTemplateXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r DjangoTemplateXSS) Description() string {
	return "Detects Django template |safe filter and mark_safe() with user-controlled input that bypass auto-escaping."
}
func (r DjangoTemplateXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r DjangoTemplateXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
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

		if reDjangoSafeFilter.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django |safe filter bypasses auto-escaping",
				Description:   "The |safe template filter marks content as safe HTML, bypassing Django's auto-escaping. If the variable contains user input, this creates an XSS vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove |safe and let Django auto-escape the content. If HTML output is needed, sanitize with bleach.clean() before passing to the template.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"django", "xss", "template", "framework"},
			})
			continue
		}

		if reDjangoMarkSafe.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django mark_safe() with dynamic content",
				Description:   "mark_safe() marks a string as safe HTML, bypassing Django's auto-escaping. If the argument includes user input or formatted strings, this creates an XSS vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Do not pass user input to mark_safe(). Use format_html() instead, which escapes arguments while preserving the format string.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"django", "xss", "template", "framework"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-DJANGO-004: Django CSRF Exemption
// ---------------------------------------------------------------------------

type DjangoCsrfExempt struct{}

func (r DjangoCsrfExempt) ID() string              { return "BATOU-FW-DJANGO-004" }
func (r DjangoCsrfExempt) Name() string            { return "Django CSRF Exemption" }
func (r DjangoCsrfExempt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r DjangoCsrfExempt) Description() string {
	return "Detects @csrf_exempt decorator which disables Django's built-in CSRF protection on views."
}
func (r DjangoCsrfExempt) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r DjangoCsrfExempt) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isPyComment(line) {
			continue
		}
		if reDjangoCsrfExempt.MatchString(line) {
			matched := strings.TrimSpace(line)
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django @csrf_exempt disables CSRF protection",
				Description:   "@csrf_exempt disables Cross-Site Request Forgery protection on this view. This allows attackers to forge requests on behalf of authenticated users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove @csrf_exempt and use proper CSRF tokens. For API endpoints, use token-based authentication (e.g., Django REST framework's TokenAuthentication).",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"django", "csrf", "framework"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-DJANGO-005: Django Mass Assignment
// ---------------------------------------------------------------------------

type DjangoMassAssignment struct{}

func (r DjangoMassAssignment) ID() string              { return "BATOU-FW-DJANGO-005" }
func (r DjangoMassAssignment) Name() string            { return "Django Mass Assignment" }
func (r DjangoMassAssignment) DefaultSeverity() rules.Severity { return rules.High }
func (r DjangoMassAssignment) Description() string {
	return "Detects Django model operations that pass request data directly using ** unpacking, which may allow mass assignment of unintended fields."
}
func (r DjangoMassAssignment) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r DjangoMassAssignment) Scan(ctx *rules.ScanContext) []rules.Finding {
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

		if reDjangoMassAssign.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django mass assignment via **request.POST/data",
				Description:   "Passing **request.POST or **request.data directly to model create/update allows attackers to set any model field, including is_admin, is_staff, or other privileged fields.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use Django forms with explicit field lists, or manually extract and validate expected fields: Model.objects.create(name=request.POST['name'])",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"django", "mass-assignment", "framework"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(DjangoSettingsMisconfig{})
	rules.Register(DjangoORMSQLInjection{})
	rules.Register(DjangoTemplateXSS{})
	rules.Register(DjangoCsrfExempt{})
	rules.Register(DjangoMassAssignment{})
}
