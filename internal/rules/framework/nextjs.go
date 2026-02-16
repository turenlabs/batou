package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- Next.js
// ---------------------------------------------------------------------------

// BATOU-FW-NEXTJS-001: dangerouslySetInnerHTML with user data
var reNextDangerousHTML = regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:props\.|params\.|query\.|searchParams\.|req\.|request\.|data\.|user)`)

// BATOU-FW-NEXTJS-002: API route without auth
var reNextAPIHandler = regexp.MustCompile(`export\s+(?:default\s+)?(?:async\s+)?function\s+(?:handler|GET|POST|PUT|DELETE|PATCH)\s*\(`)
var reNextAPIRoute = regexp.MustCompile(`(?:req\s*:\s*NextApiRequest|request\s*:\s*NextRequest|NextResponse)`)
var reNextAuthCheck = regexp.MustCompile(`(?:getSession|getServerSession|getToken|auth\s*\(|verify|jwt|authenticate|isAuthenticated|requireAuth|withAuth|cookies\(\)\.get\s*\(\s*['"](?:token|session|auth))`)

// BATOU-FW-NEXTJS-003: getServerSideProps exposing secrets
var reNextGSSP = regexp.MustCompile(`(?:getServerSideProps|getStaticProps)\b`)
var reNextPropsSecret = regexp.MustCompile(`(?:process\.env\.(?:SECRET|PRIVATE|KEY|PASSWORD|TOKEN|API_KEY|DATABASE_URL|DB_)|secret|private_key|apiKey|api_key)`)
var reNextPropsReturn = regexp.MustCompile(`return\s*\{[^}]*props\s*:`)

// BATOU-FW-NEXTJS-004: Rewrites/redirects with user input
var reNextRewriteUserInput = regexp.MustCompile(`(?:destination|source)\s*:\s*(?:` + "`" + `[^` + "`" + `]*\$\{(?:req\.|query\.|params\.)` + `|['"][^'"]*['"]\s*\+\s*(?:req\.|query\.|params\.))`)

// BATOU-FW-NEXTJS-005: Image domain wildcard
var reNextImageDomainWildcard = regexp.MustCompile(`(?:domains|remotePatterns)\s*:\s*\[\s*['"]?\*['"]?\s*\]`)
var reNextImagePermissive = regexp.MustCompile(`remotePatterns\s*:\s*\[\s*\{[^}]*hostname\s*:\s*['"]?\*\*['"]?`)

// BATOU-FW-NEXTJS-006: Middleware bypass
var reNextMiddlewareSkip = regexp.MustCompile(`config\s*=\s*\{[^}]*matcher\s*:\s*\[`)
var reNextMiddlewarePathCheck = regexp.MustCompile(`request\.nextUrl\.pathname\.startsWith\s*\(`)
var reNextMiddlewareBypass = regexp.MustCompile(`(?:_next|static|favicon|api|_vercel)\b`)

// BATOU-FW-NEXTJS-007: NEXT_PUBLIC with sensitive data
var reNextPublicSensitive = regexp.MustCompile(`NEXT_PUBLIC_(?:SECRET|PRIVATE|KEY|PASSWORD|TOKEN|API_SECRET|DATABASE|DB_PASS|STRIPE_SECRET|AWS_SECRET)`)

// BATOU-FW-NEXTJS-008: CSP not configured
var reNextHeaders = regexp.MustCompile(`(?:headers\s*\(\s*\)|headers\s*:\s*\[|Content-Security-Policy)`)

func init() {
	rules.Register(&NextJSDangerousHTML{})
	rules.Register(&NextJSAPINoAuth{})
	rules.Register(&NextJSPropsSecrets{})
	rules.Register(&NextJSRewriteInjection{})
	rules.Register(&NextJSImagePermissive{})
	rules.Register(&NextJSMiddlewareBypass{})
	rules.Register(&NextJSPublicSecret{})
	rules.Register(&NextJSNoCSP{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-001: dangerouslySetInnerHTML with user data
// ---------------------------------------------------------------------------

type NextJSDangerousHTML struct{}

func (r *NextJSDangerousHTML) ID() string                      { return "BATOU-FW-NEXTJS-001" }
func (r *NextJSDangerousHTML) Name() string                    { return "NextJSDangerousHTML" }
func (r *NextJSDangerousHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *NextJSDangerousHTML) Description() string {
	return "Detects Next.js dangerouslySetInnerHTML with user-controlled data."
}
func (r *NextJSDangerousHTML) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSDangerousHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reNextDangerousHTML.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Next.js dangerouslySetInnerHTML with user data (XSS)",
				Description:   "dangerouslySetInnerHTML is used with data from props, params, query, or request objects. This renders raw HTML without escaping, creating a Cross-Site Scripting vulnerability if the data originates from user input.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Sanitize HTML content with DOMPurify before using dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(content) }. Prefer React's built-in text rendering which auto-escapes.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nextjs", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-002: API route without authentication
// ---------------------------------------------------------------------------

type NextJSAPINoAuth struct{}

func (r *NextJSAPINoAuth) ID() string                      { return "BATOU-FW-NEXTJS-002" }
func (r *NextJSAPINoAuth) Name() string                    { return "NextJSAPINoAuth" }
func (r *NextJSAPINoAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NextJSAPINoAuth) Description() string {
	return "Detects Next.js API routes without authentication checks."
}
func (r *NextJSAPINoAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSAPINoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Must be an API route file
	if !strings.Contains(ctx.FilePath, "/api/") && !strings.Contains(ctx.FilePath, "route.ts") && !strings.Contains(ctx.FilePath, "route.js") {
		return nil
	}
	if !reNextAPIHandler.MatchString(ctx.Content) && !reNextAPIRoute.MatchString(ctx.Content) {
		return nil
	}
	if reNextAuthCheck.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reNextAPIHandler.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Next.js API route without authentication",
				Description:   "This Next.js API route handler does not contain authentication checks (getSession, getToken, jwt verification, etc.). Without authentication, the endpoint is accessible to anyone.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add authentication: const session = await getServerSession(req, res, authOptions); if (!session) return res.status(401).json({ error: 'Unauthorized' });",
				CWEID:         "CWE-306",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nextjs", "authentication"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-003: getServerSideProps exposing secrets to client
// ---------------------------------------------------------------------------

type NextJSPropsSecrets struct{}

func (r *NextJSPropsSecrets) ID() string                      { return "BATOU-FW-NEXTJS-003" }
func (r *NextJSPropsSecrets) Name() string                    { return "NextJSPropsSecrets" }
func (r *NextJSPropsSecrets) DefaultSeverity() rules.Severity { return rules.High }
func (r *NextJSPropsSecrets) Description() string {
	return "Detects getServerSideProps/getStaticProps returning sensitive data (secrets, keys) as props to the client."
}
func (r *NextJSPropsSecrets) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSPropsSecrets) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reNextGSSP.MatchString(ctx.Content) {
		return nil
	}
	if !reNextPropsReturn.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inGSSP := false
	braceDepth := 0

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		if reNextGSSP.MatchString(line) {
			inGSSP = true
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inGSSP {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			if reNextPropsSecret.MatchString(line) && strings.Contains(line, "props") {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Next.js server props exposing secrets to client",
					Description:   "getServerSideProps or getStaticProps returns what appears to be sensitive data (secrets, API keys, database URLs) as props. Props are serialized to the client-side HTML and visible in the page source.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Never pass secrets as props. Fetch sensitive data server-side and only return the processed result. Use Server Components or API routes for operations requiring secrets.",
					CWEID:         "CWE-200",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"framework", "nextjs", "information-disclosure"},
				})
			}

			if braceDepth <= 0 {
				inGSSP = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-004: Rewrites/redirects with user input
// ---------------------------------------------------------------------------

type NextJSRewriteInjection struct{}

func (r *NextJSRewriteInjection) ID() string                      { return "BATOU-FW-NEXTJS-004" }
func (r *NextJSRewriteInjection) Name() string                    { return "NextJSRewriteInjection" }
func (r *NextJSRewriteInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NextJSRewriteInjection) Description() string {
	return "Detects Next.js rewrites or redirects with user-controlled destination."
}
func (r *NextJSRewriteInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSRewriteInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reNextRewriteUserInput.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Next.js rewrite/redirect with user-controlled input",
				Description:   "A Next.js rewrite or redirect destination includes user-controlled input from request parameters or query strings. This can lead to open redirect attacks or SSRF if the destination is an external URL.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate redirect destinations against an allowlist of permitted URLs. Use relative paths instead of absolute URLs. Never construct redirect targets from user input.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nextjs", "open-redirect"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-005: Image domain whitelist too permissive
// ---------------------------------------------------------------------------

type NextJSImagePermissive struct{}

func (r *NextJSImagePermissive) ID() string                      { return "BATOU-FW-NEXTJS-005" }
func (r *NextJSImagePermissive) Name() string                    { return "NextJSImagePermissive" }
func (r *NextJSImagePermissive) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NextJSImagePermissive) Description() string {
	return "Detects Next.js Image component with overly permissive domain configuration."
}
func (r *NextJSImagePermissive) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSImagePermissive) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reNextImageDomainWildcard.FindString(line); m != "" {
			matched = m
		} else if m := reNextImagePermissive.FindString(line); m != "" {
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
				Title:         "Next.js Image domain configuration too permissive",
				Description:   "The Next.js image optimization configuration uses wildcard domains or overly broad remote patterns. This allows the Image component to proxy and optimize images from any external source, which can be abused for SSRF or serving malicious content.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Specify exact domains: images: { domains: ['cdn.example.com'] } or use remotePatterns with specific hostnames and protocols.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nextjs", "image-optimization"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-006: Middleware bypass via path manipulation
// ---------------------------------------------------------------------------

type NextJSMiddlewareBypass struct{}

func (r *NextJSMiddlewareBypass) ID() string                      { return "BATOU-FW-NEXTJS-006" }
func (r *NextJSMiddlewareBypass) Name() string                    { return "NextJSMiddlewareBypass" }
func (r *NextJSMiddlewareBypass) DefaultSeverity() rules.Severity { return rules.High }
func (r *NextJSMiddlewareBypass) Description() string {
	return "Detects Next.js middleware with path exclusions that could allow bypass via path manipulation."
}
func (r *NextJSMiddlewareBypass) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSMiddlewareBypass) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check middleware files
	if !strings.Contains(ctx.FilePath, "middleware") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reNextMiddlewarePathCheck.MatchString(line) && reNextMiddlewareBypass.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Next.js middleware bypass via path exclusion",
				Description:   "Next.js middleware uses path-based exclusions (startsWith checks) to skip authentication. Attackers may exploit path traversal, URL encoding, or case sensitivity to bypass these checks and access protected routes.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use Next.js matcher config instead of manual path checks. Normalize paths before comparison. Use a deny-by-default approach where all routes require auth unless explicitly public.",
				CWEID:         "CWE-285",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nextjs", "middleware", "bypass"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-007: NEXT_PUBLIC exposing sensitive env vars
// ---------------------------------------------------------------------------

type NextJSPublicSecret struct{}

func (r *NextJSPublicSecret) ID() string                      { return "BATOU-FW-NEXTJS-007" }
func (r *NextJSPublicSecret) Name() string                    { return "NextJSPublicSecret" }
func (r *NextJSPublicSecret) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NextJSPublicSecret) Description() string {
	return "Detects NEXT_PUBLIC_ environment variables that appear to contain sensitive data."
}
func (r *NextJSPublicSecret) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSPublicSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "#") {
			continue
		}
		if m := reNextPublicSensitive.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Next.js NEXT_PUBLIC_ variable exposes sensitive data",
				Description:   "A NEXT_PUBLIC_ prefixed environment variable contains what appears to be sensitive data (secret, password, private key, database URL). NEXT_PUBLIC_ variables are embedded in the client-side JavaScript bundle and visible to all users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove the NEXT_PUBLIC_ prefix from sensitive variables. Access them only server-side via process.env in API routes, getServerSideProps, or Server Components.",
				CWEID:         "CWE-200",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nextjs", "environment-variable", "information-disclosure"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-008: CSP not configured
// ---------------------------------------------------------------------------

type NextJSNoCSP struct{}

func (r *NextJSNoCSP) ID() string                      { return "BATOU-FW-NEXTJS-008" }
func (r *NextJSNoCSP) Name() string                    { return "NextJSNoCSP" }
func (r *NextJSNoCSP) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NextJSNoCSP) Description() string {
	return "Detects Next.js configuration files without Content-Security-Policy headers."
}
func (r *NextJSNoCSP) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSNoCSP) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check next.config files
	if !strings.Contains(ctx.FilePath, "next.config") {
		return nil
	}
	if strings.Contains(ctx.Content, "Content-Security-Policy") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if strings.Contains(line, "module.exports") || strings.Contains(line, "export default") || strings.Contains(line, "nextConfig") {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Next.js configuration without Content-Security-Policy",
				Description:   "The Next.js configuration file does not set a Content-Security-Policy header. CSP is a critical defense-in-depth mechanism against XSS attacks by restricting which scripts, styles, and resources can be loaded.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add CSP headers in next.config.js: headers() { return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: \"default-src 'self'; script-src 'self'\" }] }] }.",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nextjs", "csp", "security-headers"},
			})
			break
		}
	}
	return findings
}
