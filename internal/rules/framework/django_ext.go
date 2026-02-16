package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Django extended security rule patterns (DJANGO-006 through DJANGO-011)
// ---------------------------------------------------------------------------

var (
	// GTSS-FW-DJANGO-006: mark_safe with user input
	reDjangoExtMarkSafe = regexp.MustCompile(`\bmark_safe\s*\(\s*(?:f["']|["'][^"']*["']\s*%|["'][^"']*["']\s*\.format\s*\(|request\.|user_input|input\b)`)

	// GTSS-FW-DJANGO-007: CSRF_COOKIE_SECURE not set
	reDjangoExtCsrfCookieSecureFalse = regexp.MustCompile(`\bCSRF_COOKIE_SECURE\s*=\s*False\b`)

	// GTSS-FW-DJANGO-008: raw() queryset with user input
	reDjangoExtRawQuery = regexp.MustCompile(`\.raw\s*\(\s*(?:f["']|"[^"]*"\s*%|'[^']*'\s*%|"[^"]*"\s*\.format\s*\(|'[^']*'\s*\.format\s*\()`)
	reDjangoExtRawConcat = regexp.MustCompile(`\.raw\s*\(\s*["'][^"']*["']\s*\+`)

	// GTSS-FW-DJANGO-009: Session serializer using pickle
	reDjangoExtPickleSerializer = regexp.MustCompile(`SESSION_SERIALIZER\s*=\s*["']django\.contrib\.sessions\.serializers\.PickleSerializer["']`)

	// GTSS-FW-DJANGO-010: SECURE_SSL_REDIRECT not enabled
	reDjangoExtSSLRedirectFalse = regexp.MustCompile(`\bSECURE_SSL_REDIRECT\s*=\s*False\b`)

	// GTSS-FW-DJANGO-011: Default admin URL
	reDjangoExtDefaultAdmin = regexp.MustCompile(`(?:url|path)\s*\(\s*["']admin/["']`)
	reDjangoExtAdminSiteUrls = regexp.MustCompile(`admin\.site\.urls`)
)

func init() {
	rules.Register(&DjangoMarkSafeExt{})
	rules.Register(&DjangoCsrfCookieSecure{})
	rules.Register(&DjangoRawQueryExt{})
	rules.Register(&DjangoPickleSerializer{})
	rules.Register(&DjangoSSLRedirectExt{})
	rules.Register(&DjangoDefaultAdmin{})
}

// ---------------------------------------------------------------------------
// GTSS-FW-DJANGO-006: mark_safe with user input
// ---------------------------------------------------------------------------

type DjangoMarkSafeExt struct{}

func (r *DjangoMarkSafeExt) ID() string                      { return "GTSS-FW-DJANGO-006" }
func (r *DjangoMarkSafeExt) Name() string                    { return "DjangoMarkSafeExt" }
func (r *DjangoMarkSafeExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *DjangoMarkSafeExt) Description() string {
	return "Detects Django mark_safe() used with f-strings, string formatting, or request data, which bypasses auto-escaping and enables XSS."
}
func (r *DjangoMarkSafeExt) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *DjangoMarkSafeExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if m := reDjangoExtMarkSafe.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django mark_safe() with dynamic user input (XSS)",
				Description:   "mark_safe() marks a string as safe HTML, bypassing Django's automatic output escaping. When used with f-strings, string formatting, or request data, this allows attackers to inject malicious scripts.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use format_html() instead of mark_safe() with formatting. format_html() escapes its arguments while preserving the format string: format_html('<b>{}</b>', user_input).",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "django", "xss", "mark_safe"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-DJANGO-007: CSRF_COOKIE_SECURE not set
// ---------------------------------------------------------------------------

type DjangoCsrfCookieSecure struct{}

func (r *DjangoCsrfCookieSecure) ID() string                      { return "GTSS-FW-DJANGO-007" }
func (r *DjangoCsrfCookieSecure) Name() string                    { return "DjangoCsrfCookieSecure" }
func (r *DjangoCsrfCookieSecure) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DjangoCsrfCookieSecure) Description() string {
	return "Detects Django CSRF_COOKIE_SECURE set to False, allowing the CSRF token cookie to be sent over unencrypted HTTP."
}
func (r *DjangoCsrfCookieSecure) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *DjangoCsrfCookieSecure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reDjangoExtCsrfCookieSecureFalse.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django CSRF_COOKIE_SECURE=False",
				Description:   "CSRF_COOKIE_SECURE=False allows the CSRF token cookie to be transmitted over unencrypted HTTP connections. An attacker performing a man-in-the-middle attack can steal the CSRF token and bypass CSRF protection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set CSRF_COOKIE_SECURE=True in production settings to ensure the CSRF cookie is only sent over HTTPS.",
				CWEID:         "CWE-352",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "django", "csrf", "cookie"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-DJANGO-008: raw() queryset with user input
// ---------------------------------------------------------------------------

type DjangoRawQueryExt struct{}

func (r *DjangoRawQueryExt) ID() string                      { return "GTSS-FW-DJANGO-008" }
func (r *DjangoRawQueryExt) Name() string                    { return "DjangoRawQueryExt" }
func (r *DjangoRawQueryExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *DjangoRawQueryExt) Description() string {
	return "Detects Django raw() queryset method with string formatting or concatenation instead of parameterized queries."
}
func (r *DjangoRawQueryExt) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *DjangoRawQueryExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		var matched string
		if m := reDjangoExtRawQuery.FindString(line); m != "" {
			matched = m
		} else if m := reDjangoExtRawConcat.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django raw() SQL with string formatting (SQL injection)",
				Description:   "The raw() queryset method uses f-strings, % formatting, .format(), or string concatenation to build SQL. This bypasses Django's ORM protections and enables SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use parameterized queries with the params argument: Model.objects.raw('SELECT * FROM app_model WHERE id = %s', [user_id]). Never format user input into raw SQL.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "django", "sql-injection", "raw-query"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-DJANGO-009: Session serializer using pickle
// ---------------------------------------------------------------------------

type DjangoPickleSerializer struct{}

func (r *DjangoPickleSerializer) ID() string                      { return "GTSS-FW-DJANGO-009" }
func (r *DjangoPickleSerializer) Name() string                    { return "DjangoPickleSerializer" }
func (r *DjangoPickleSerializer) DefaultSeverity() rules.Severity { return rules.High }
func (r *DjangoPickleSerializer) Description() string {
	return "Detects Django SESSION_SERIALIZER set to PickleSerializer, which is vulnerable to remote code execution via deserialization attacks."
}
func (r *DjangoPickleSerializer) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *DjangoPickleSerializer) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reDjangoExtPickleSerializer.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django session serializer uses Pickle (RCE risk)",
				Description:   "SESSION_SERIALIZER is set to PickleSerializer. Python's pickle module can execute arbitrary code during deserialization. If an attacker can modify session data (e.g., via a known SECRET_KEY), they can achieve remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use the default JSONSerializer: SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'. JSON serialization does not allow code execution during deserialization.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "django", "deserialization", "pickle", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-DJANGO-010: SECURE_SSL_REDIRECT not enabled
// ---------------------------------------------------------------------------

type DjangoSSLRedirectExt struct{}

func (r *DjangoSSLRedirectExt) ID() string                      { return "GTSS-FW-DJANGO-010" }
func (r *DjangoSSLRedirectExt) Name() string                    { return "DjangoSSLRedirectExt" }
func (r *DjangoSSLRedirectExt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DjangoSSLRedirectExt) Description() string {
	return "Detects Django SECURE_SSL_REDIRECT explicitly set to False, allowing unencrypted HTTP connections."
}
func (r *DjangoSSLRedirectExt) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *DjangoSSLRedirectExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reDjangoExtSSLRedirectFalse.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django SECURE_SSL_REDIRECT disabled",
				Description:   "SECURE_SSL_REDIRECT=False allows HTTP connections without redirecting to HTTPS. Sensitive data (session cookies, credentials, personal information) may be transmitted in cleartext.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set SECURE_SSL_REDIRECT=True in production settings to force all HTTP requests to redirect to HTTPS. Ensure HTTPS is properly configured on the web server.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "django", "ssl", "transport-security"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-DJANGO-011: Default admin URL not changed
// ---------------------------------------------------------------------------

type DjangoDefaultAdmin struct{}

func (r *DjangoDefaultAdmin) ID() string                      { return "GTSS-FW-DJANGO-011" }
func (r *DjangoDefaultAdmin) Name() string                    { return "DjangoDefaultAdmin" }
func (r *DjangoDefaultAdmin) DefaultSeverity() rules.Severity { return rules.Low }
func (r *DjangoDefaultAdmin) Description() string {
	return "Detects Django admin interface at the default /admin/ URL, which is commonly targeted by automated attacks."
}
func (r *DjangoDefaultAdmin) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *DjangoDefaultAdmin) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reDjangoExtDefaultAdmin.MatchString(line) && reDjangoExtAdminSiteUrls.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Django admin at default /admin/ URL",
				Description:   "The Django admin interface is registered at the default /admin/ path. This well-known URL is frequently targeted by automated bots and brute-force login attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Change the admin URL to a non-default path: path('my-secret-panel/', admin.site.urls). Combine with django-axes or django-defender for brute-force protection. Consider restricting admin access by IP.",
				CWEID:         "CWE-16",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "django", "admin", "security-hardening"},
			})
		}
	}
	return findings
}
