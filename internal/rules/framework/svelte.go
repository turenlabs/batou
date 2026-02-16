package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Svelte/SvelteKit-specific security rule patterns
// ---------------------------------------------------------------------------

var (
	// GTSS-FW-SVELTE-001: {@html} tag with user input
	reSvelteHtmlTag = regexp.MustCompile(`\{@html\s+`)

	// GTSS-FW-SVELTE-002: SvelteKit load function exposing secrets
	reSvelteLoadFunction    = regexp.MustCompile(`export\s+(?:async\s+)?function\s+load\s*\(`)
	reSvelteLoadArrow       = regexp.MustCompile(`export\s+const\s+load\s*[=:]\s*(?:async\s*)?\(`)
	reSvelteSecretPattern   = regexp.MustCompile(`(?i)(?:process\.env\.|import\.meta\.env\.)(?:SECRET|PRIVATE|API_KEY|DATABASE|DB_|TOKEN|PASSWORD|AUTH)`)
	reSveltePrivateEnv      = regexp.MustCompile(`\$env/static/private|\$env/dynamic/private`)

	// GTSS-FW-SVELTE-003: SvelteKit form action without CSRF
	reSvelteFormAction = regexp.MustCompile(`export\s+const\s+actions\s*[=:]`)

	// GTSS-FW-SVELTE-004: SvelteKit API route without auth
	reSvelteApiHandler = regexp.MustCompile(`export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\(`)

	// GTSS-FW-SVELTE-005: Svelte store with sensitive data
	reSvelteWritableStore  = regexp.MustCompile(`writable\s*\(`)
	reSvelteStoreSensitive = regexp.MustCompile(`(?i)(?:token|secret|password|apiKey|api_key|auth|credential|session|jwt)`)

	// GTSS-FW-SVELTE-006: SvelteKit env leaked to client
	reSveltePublicEnvImport = regexp.MustCompile(`\$env/static/public|\$env/dynamic/public`)
	reSvelteEnvSensitive    = regexp.MustCompile(`(?i)(?:SECRET|PRIVATE|KEY|TOKEN|PASSWORD|CREDENTIAL|DATABASE|DB_)`)
)

func init() {
	rules.Register(&SvelteHtmlTag{})
	rules.Register(&SvelteLoadSecrets{})
	rules.Register(&SvelteFormCSRF{})
	rules.Register(&SvelteAPINoAuth{})
	rules.Register(&SvelteStoreSensitive{})
	rules.Register(&SvelteEnvLeak{})
}

// ---------------------------------------------------------------------------
// GTSS-FW-SVELTE-001: {@html} tag with user input (XSS)
// ---------------------------------------------------------------------------

type SvelteHtmlTag struct{}

func (r *SvelteHtmlTag) ID() string                      { return "GTSS-FW-SVELTE-001" }
func (r *SvelteHtmlTag) Name() string                    { return "SvelteHtmlTag" }
func (r *SvelteHtmlTag) DefaultSeverity() rules.Severity { return rules.High }
func (r *SvelteHtmlTag) Description() string {
	return "Detects Svelte {@html} tags that render unescaped HTML, which can lead to XSS if the content includes user input."
}
func (r *SvelteHtmlTag) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *SvelteHtmlTag) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "<!--") {
			continue
		}
		if m := reSvelteHtmlTag.FindString(line); m != "" {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Svelte {@html} tag renders unescaped content (XSS risk)",
				Description:   "The {@html} tag in Svelte renders raw HTML without escaping. If the expression contains user-provided data, an attacker can inject malicious scripts.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Avoid {@html} with user input. Use DOMPurify to sanitize HTML before rendering: {@html DOMPurify.sanitize(content)}. Prefer text interpolation {content} which auto-escapes.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "svelte", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SVELTE-002: SvelteKit load function exposing secrets
// ---------------------------------------------------------------------------

type SvelteLoadSecrets struct{}

func (r *SvelteLoadSecrets) ID() string                      { return "GTSS-FW-SVELTE-002" }
func (r *SvelteLoadSecrets) Name() string                    { return "SvelteLoadSecrets" }
func (r *SvelteLoadSecrets) DefaultSeverity() rules.Severity { return rules.High }
func (r *SvelteLoadSecrets) Description() string {
	return "Detects SvelteKit load functions that may expose secrets or private environment variables to the client."
}
func (r *SvelteLoadSecrets) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *SvelteLoadSecrets) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check files that contain a load function
	hasLoad := reSvelteLoadFunction.MatchString(ctx.Content) || reSvelteLoadArrow.MatchString(ctx.Content)
	if !hasLoad {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reSvelteSecretPattern.MatchString(line) || (reSveltePrivateEnv.MatchString(line) && strings.Contains(ctx.FilePath, "+page.")) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SvelteKit load function exposing secrets to client",
				Description:   "A SvelteKit load function accesses secret or private environment variables. Data returned from a +page.js load function is serialized and sent to the client, potentially exposing secrets.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Move secret access to +page.server.js (server-only load function). Only return non-sensitive data from load functions. Use $env/static/private only in server-side code.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "svelte", "sveltekit", "secrets"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SVELTE-003: SvelteKit form action without CSRF
// ---------------------------------------------------------------------------

type SvelteFormCSRF struct{}

func (r *SvelteFormCSRF) ID() string                      { return "GTSS-FW-SVELTE-003" }
func (r *SvelteFormCSRF) Name() string                    { return "SvelteFormCSRF" }
func (r *SvelteFormCSRF) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SvelteFormCSRF) Description() string {
	return "Detects SvelteKit form actions that may lack CSRF protection when the default SvelteKit CSRF check is disabled."
}
func (r *SvelteFormCSRF) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *SvelteFormCSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if CSRF check is disabled in svelte config
	hasCSRFDisable := strings.Contains(ctx.Content, "csrf") && (strings.Contains(ctx.Content, "false") || strings.Contains(ctx.Content, "checkOrigin"))

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reSvelteFormAction.MatchString(line) && hasCSRFDisable {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SvelteKit form action with CSRF check disabled",
				Description:   "SvelteKit form actions are defined in a file that appears to disable CSRF origin checking. Without CSRF protection, attackers can forge form submissions from other sites.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Keep SvelteKit's built-in CSRF protection enabled (checkOrigin: true in svelte.config.js). If you must disable it, implement your own CSRF token validation.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "svelte", "sveltekit", "csrf"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SVELTE-004: SvelteKit API route without authentication
// ---------------------------------------------------------------------------

type SvelteAPINoAuth struct{}

func (r *SvelteAPINoAuth) ID() string                      { return "GTSS-FW-SVELTE-004" }
func (r *SvelteAPINoAuth) Name() string                    { return "SvelteAPINoAuth" }
func (r *SvelteAPINoAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SvelteAPINoAuth) Description() string {
	return "Detects SvelteKit API route handlers (GET, POST, etc.) without authentication checks."
}
func (r *SvelteAPINoAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *SvelteAPINoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check +server.js/ts files
	if !strings.Contains(ctx.FilePath, "+server.") {
		return nil
	}
	// Skip if there's an auth check in the file
	lower := strings.ToLower(ctx.Content)
	if strings.Contains(lower, "auth") || strings.Contains(lower, "session") ||
		strings.Contains(lower, "token") || strings.Contains(lower, "locals.user") ||
		strings.Contains(lower, "getSession") || strings.Contains(lower, "jwt") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reSvelteApiHandler.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SvelteKit API route without authentication",
				Description:   "A SvelteKit API route handler (GET/POST/PUT/DELETE) does not appear to perform any authentication or authorization checks. This endpoint may be accessible to unauthenticated users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add authentication checks in the handler using event.locals.user or a session check. Use SvelteKit hooks (handle) for global authentication middleware.",
				CWEID:         "CWE-306",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "svelte", "sveltekit", "authentication"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SVELTE-005: Svelte store with sensitive data
// ---------------------------------------------------------------------------

type SvelteStoreSensitive struct{}

func (r *SvelteStoreSensitive) ID() string                      { return "GTSS-FW-SVELTE-005" }
func (r *SvelteStoreSensitive) Name() string                    { return "SvelteStoreSensitive" }
func (r *SvelteStoreSensitive) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SvelteStoreSensitive) Description() string {
	return "Detects Svelte writable stores that appear to hold sensitive data (tokens, secrets, passwords), which is accessible client-side."
}
func (r *SvelteStoreSensitive) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *SvelteStoreSensitive) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reSvelteWritableStore.MatchString(line) && reSvelteStoreSensitive.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Svelte store with sensitive data (client-side accessible)",
				Description:   "A Svelte writable store appears to contain sensitive data (tokens, secrets, passwords). Svelte stores are client-side state and their contents are accessible via JavaScript in the browser.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Do not store secrets, API keys, or long-lived tokens in client-side stores. Use HttpOnly cookies for session management. If a token must be stored client-side, use short-lived tokens with proper refresh mechanisms.",
				CWEID:         "CWE-922",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "svelte", "client-side-storage", "secrets"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SVELTE-006: SvelteKit environment variable leaked to client
// ---------------------------------------------------------------------------

type SvelteEnvLeak struct{}

func (r *SvelteEnvLeak) ID() string                      { return "GTSS-FW-SVELTE-006" }
func (r *SvelteEnvLeak) Name() string                    { return "SvelteEnvLeak" }
func (r *SvelteEnvLeak) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SvelteEnvLeak) Description() string {
	return "Detects SvelteKit $env/static/public or $env/dynamic/public imports that may accidentally expose secrets named with sensitive keywords."
}
func (r *SvelteEnvLeak) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *SvelteEnvLeak) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reSveltePublicEnvImport.MatchString(line) && reSvelteEnvSensitive.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SvelteKit public env import with sensitive variable name",
				Description:   "A variable with a sensitive name (SECRET, KEY, TOKEN, PASSWORD, etc.) is imported from $env/static/public or $env/dynamic/public. Public env variables are exposed to the client browser.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Move sensitive environment variables to private env: import from '$env/static/private' instead. Only use PUBLIC_ prefixed variables for public env. SvelteKit enforces PUBLIC_ prefix for public env by default.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "svelte", "sveltekit", "env-leak"},
			})
		}
	}
	return findings
}
