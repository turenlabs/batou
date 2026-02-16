package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Nuxt-specific security rule patterns
// ---------------------------------------------------------------------------

var (
	// BATOU-FW-NUXT-001: v-html directive with user data
	reNuxtVHtml = regexp.MustCompile(`v-html\s*=\s*["']`)

	// BATOU-FW-NUXT-002: runtimeConfig exposing secrets
	reNuxtPublicRuntime   = regexp.MustCompile(`(?:publicRuntimeConfig|public\s*:\s*\{)`)
	reNuxtRuntimeSensitive = regexp.MustCompile(`(?i)(?:secret|key|token|password|credential|api_key|apiKey|private|database|db_)`)

	// BATOU-FW-NUXT-003: Server API without authentication
	reNuxtDefineHandler     = regexp.MustCompile(`defineEventHandler\s*\(`)
	reNuxtDefineHandlerOld  = regexp.MustCompile(`export\s+default\s+defineEventHandler\s*\(`)

	// BATOU-FW-NUXT-004: SSR injection via user-controlled meta/head
	reNuxtUseHead       = regexp.MustCompile(`useHead\s*\(\s*\{`)
	reNuxtUseSeoMeta    = regexp.MustCompile(`useSeoMeta\s*\(\s*\{`)
	reNuxtHeadDynamic   = regexp.MustCompile(`(?:title|description|innerHTML|content)\s*:\s*(?:route\.|query\.|params\.|req\.|event\.|useRoute)`)

	// BATOU-FW-NUXT-005: Proxy/redirect with user input
	reNuxtSendRedirect  = regexp.MustCompile(`sendRedirect\s*\(\s*event\s*,\s*(?:query\.|getQuery|getRouterParam|event\.(?:context|node)\.)`)
	reNuxtProxyRequest  = regexp.MustCompile(`proxyRequest\s*\(\s*event\s*,\s*(?:query\.|getQuery|getRouterParam|event\.)`)
	reNuxtNavigateTo    = regexp.MustCompile(`navigateTo\s*\(\s*(?:route\.|useRoute|query\.|to\.|params\.)`)

	// BATOU-FW-NUXT-006: Middleware bypass via direct API access
	reNuxtMiddlewareDef = regexp.MustCompile(`defineNuxtRouteMiddleware\s*\(`)
)

func init() {
	rules.Register(&NuxtVHtml{})
	rules.Register(&NuxtPublicRuntimeSecrets{})
	rules.Register(&NuxtServerAPINoAuth{})
	rules.Register(&NuxtSSRInjection{})
	rules.Register(&NuxtOpenRedirect{})
	rules.Register(&NuxtMiddlewareBypass{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-NUXT-001: v-html directive with user data (XSS)
// ---------------------------------------------------------------------------

type NuxtVHtml struct{}

func (r *NuxtVHtml) ID() string                      { return "BATOU-FW-NUXT-001" }
func (r *NuxtVHtml) Name() string                    { return "NuxtVHtml" }
func (r *NuxtVHtml) DefaultSeverity() rules.Severity { return rules.High }
func (r *NuxtVHtml) Description() string {
	return "Detects Nuxt/Vue v-html directive which renders unescaped HTML and can lead to XSS if used with user data."
}
func (r *NuxtVHtml) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NuxtVHtml) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "<!--") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reNuxtVHtml.FindString(line); m != "" {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Nuxt/Vue v-html directive (XSS risk)",
				Description:   "The v-html directive renders raw HTML without escaping. If the bound expression contains user input, this creates a Cross-Site Scripting vulnerability. Vue/Nuxt template interpolation {{ }} auto-escapes, but v-html does not.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Replace v-html with {{ }} text interpolation which auto-escapes. If raw HTML is required, sanitize the content first using DOMPurify: v-html=\"DOMPurify.sanitize(content)\".",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nuxt", "vue", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NUXT-002: runtimeConfig exposing secrets to client
// ---------------------------------------------------------------------------

type NuxtPublicRuntimeSecrets struct{}

func (r *NuxtPublicRuntimeSecrets) ID() string                      { return "BATOU-FW-NUXT-002" }
func (r *NuxtPublicRuntimeSecrets) Name() string                    { return "NuxtPublicRuntimeSecrets" }
func (r *NuxtPublicRuntimeSecrets) DefaultSeverity() rules.Severity { return rules.High }
func (r *NuxtPublicRuntimeSecrets) Description() string {
	return "Detects Nuxt publicRuntimeConfig or runtimeConfig.public containing sensitive values (secrets, API keys, tokens) that are exposed to the client."
}
func (r *NuxtPublicRuntimeSecrets) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NuxtPublicRuntimeSecrets) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reNuxtPublicRuntime.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inPublicBlock := false
	braceDepth := 0

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		if reNuxtPublicRuntime.MatchString(line) {
			inPublicBlock = true
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inPublicBlock {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if reNuxtRuntimeSensitive.MatchString(line) {
				matched := t
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Nuxt publicRuntimeConfig exposes sensitive value to client",
					Description:   "A value with a sensitive name (secret, key, token, password) is in publicRuntimeConfig or runtimeConfig.public. These values are serialized into the HTML payload and accessible to any client-side JavaScript.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Move sensitive values to runtimeConfig (server-only) instead of publicRuntimeConfig. Access server-only config via useRuntimeConfig() in server routes and API handlers.",
					CWEID:         "CWE-200",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"framework", "nuxt", "secrets", "information-disclosure"},
				})
			}

			if braceDepth <= 0 {
				inPublicBlock = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NUXT-003: Nuxt server API without authentication
// ---------------------------------------------------------------------------

type NuxtServerAPINoAuth struct{}

func (r *NuxtServerAPINoAuth) ID() string                      { return "BATOU-FW-NUXT-003" }
func (r *NuxtServerAPINoAuth) Name() string                    { return "NuxtServerAPINoAuth" }
func (r *NuxtServerAPINoAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NuxtServerAPINoAuth) Description() string {
	return "Detects Nuxt server API handlers (defineEventHandler) without authentication or authorization checks."
}
func (r *NuxtServerAPINoAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NuxtServerAPINoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check server API route files
	if !strings.Contains(ctx.FilePath, "server/api") && !strings.Contains(ctx.FilePath, "server/routes") {
		return nil
	}
	// Skip if there's an auth check
	lower := strings.ToLower(ctx.Content)
	if strings.Contains(lower, "auth") || strings.Contains(lower, "session") ||
		strings.Contains(lower, "token") || strings.Contains(lower, "requireauth") ||
		strings.Contains(lower, "getserversession") || strings.Contains(lower, "jwt") ||
		strings.Contains(lower, "getuser") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reNuxtDefineHandler.MatchString(line) || reNuxtDefineHandlerOld.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Nuxt server API handler without authentication",
				Description:   "A Nuxt server API handler (defineEventHandler) does not appear to perform authentication or authorization checks. The endpoint may be accessible to unauthenticated users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add authentication middleware or check the session/token in the handler. Use Nuxt server middleware for global auth or implement per-route checks with getServerSession().",
				CWEID:         "CWE-306",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nuxt", "authentication"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NUXT-004: SSR injection via user-controlled meta/head
// ---------------------------------------------------------------------------

type NuxtSSRInjection struct{}

func (r *NuxtSSRInjection) ID() string                      { return "BATOU-FW-NUXT-004" }
func (r *NuxtSSRInjection) Name() string                    { return "NuxtSSRInjection" }
func (r *NuxtSSRInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *NuxtSSRInjection) Description() string {
	return "Detects Nuxt useHead/useSeoMeta with user-controlled values that could enable HTML injection in SSR-rendered pages."
}
func (r *NuxtSSRInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NuxtSSRInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasHeadComposable := reNuxtUseHead.MatchString(ctx.Content) || reNuxtUseSeoMeta.MatchString(ctx.Content)
	if !hasHeadComposable {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reNuxtHeadDynamic.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Nuxt SSR head injection via user-controlled data",
				Description:   "useHead() or useSeoMeta() uses values from route params, query strings, or request data. During SSR, these values are rendered directly into the HTML <head>, potentially enabling script injection or meta tag manipulation.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Sanitize and escape all user-derived values before passing them to useHead(). For title and meta content, strip HTML tags and encode special characters.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nuxt", "ssr", "xss", "head-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NUXT-005: Proxy/redirect with user input
// ---------------------------------------------------------------------------

type NuxtOpenRedirect struct{}

func (r *NuxtOpenRedirect) ID() string                      { return "BATOU-FW-NUXT-005" }
func (r *NuxtOpenRedirect) Name() string                    { return "NuxtOpenRedirect" }
func (r *NuxtOpenRedirect) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NuxtOpenRedirect) Description() string {
	return "Detects Nuxt sendRedirect, proxyRequest, or navigateTo with user-controlled URLs that could enable open redirect attacks."
}
func (r *NuxtOpenRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NuxtOpenRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		var title string
		if m := reNuxtSendRedirect.FindString(line); m != "" {
			matched = m
			title = "Nuxt sendRedirect with user-controlled URL (open redirect)"
		} else if m := reNuxtProxyRequest.FindString(line); m != "" {
			matched = m
			title = "Nuxt proxyRequest with user-controlled target (SSRF/redirect)"
		} else if m := reNuxtNavigateTo.FindString(line); m != "" {
			matched = m
			title = "Nuxt navigateTo with user-controlled URL (open redirect)"
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "A redirect or proxy function uses a URL derived from user input (query parameters, route params). An attacker can craft a URL that redirects users to a malicious site for phishing or credential theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate redirect URLs against an allowlist of trusted domains. Reject absolute URLs and only allow relative paths, or parse the URL and check the hostname before redirecting.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nuxt", "open-redirect"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NUXT-006: Middleware bypass via direct API access
// ---------------------------------------------------------------------------

type NuxtMiddlewareBypass struct{}

func (r *NuxtMiddlewareBypass) ID() string                      { return "BATOU-FW-NUXT-006" }
func (r *NuxtMiddlewareBypass) Name() string                    { return "NuxtMiddlewareBypass" }
func (r *NuxtMiddlewareBypass) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NuxtMiddlewareBypass) Description() string {
	return "Detects Nuxt route middleware definitions that may be bypassed when server API routes are accessed directly."
}
func (r *NuxtMiddlewareBypass) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NuxtMiddlewareBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check middleware files
	if !strings.Contains(ctx.FilePath, "middleware/") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if this middleware handles auth but only on the client side
	hasAuth := false
	hasClientOnly := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "auth") || strings.Contains(lower, "session") || strings.Contains(lower, "login") {
			hasAuth = true
		}
		if strings.Contains(line, "process.client") || strings.Contains(line, "import.meta.client") {
			hasClientOnly = true
		}
	}

	if !hasAuth {
		return nil
	}

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reNuxtMiddlewareDef.MatchString(line) && hasClientOnly {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Nuxt auth middleware with client-only check (bypassable)",
				Description:   "This Nuxt route middleware performs authentication checks only on the client side (process.client). Server API routes (/api/*) are not protected by page middleware, and client-only checks can be bypassed by directly accessing the API.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Implement authentication in Nuxt server middleware (server/middleware/) which runs on every server request. Duplicate auth checks in both client middleware and server API handlers.",
				CWEID:         "CWE-285",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nuxt", "middleware", "authorization"},
			})
		}
	}
	return findings
}
