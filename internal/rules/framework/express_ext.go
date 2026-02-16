package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Express extended security rule patterns (EXPRESS-009 through EXPRESS-014)
// ---------------------------------------------------------------------------

var (
	// BATOU-FW-EXPRESS-009: app.use without rate limiting
	reExpressExtAppListen   = regexp.MustCompile(`(?:app|server)\s*\.\s*listen\s*\(`)
	reExpressExtRateLimit   = regexp.MustCompile(`(?i)(?:rateLimit|rate[_-]?limit|express[_-]?rate[_-]?limit|slowDown|express[_-]?slow[_-]?down)`)
	reExpressExtThrottle    = regexp.MustCompile(`(?i)(?:throttle|limiter|rateLimiter)`)

	// BATOU-FW-EXPRESS-010: res.send with user input (XSS)
	reExpressExtResSendInput = regexp.MustCompile(`res\s*\.\s*send\s*\(\s*(?:req\s*\.\s*(?:params|query|body)\s*\.\s*\w+|req\s*\.\s*(?:params|query|body)\s*\[)`)
	reExpressExtResWriteInput = regexp.MustCompile(`res\s*\.\s*write\s*\(\s*(?:req\s*\.\s*(?:params|query|body)\s*\.\s*\w+|req\s*\.\s*(?:params|query|body)\s*\[)`)

	// BATOU-FW-EXPRESS-011: Session secret hardcoded
	reExpressExtSessionSecret = regexp.MustCompile(`secret\s*:\s*["'][^"']{1,}["']`)
	reExpressExtSessionBlock  = regexp.MustCompile(`session\s*\(\s*\{`)

	// BATOU-FW-EXPRESS-012: Morgan logging sensitive data
	reExpressExtMorganCustom = regexp.MustCompile(`morgan\s*\(\s*(?:function|["'][^"']*(?:password|token|secret|authorization|cookie|session|credit|ssn)[^"']*["'])`)
	reExpressExtMorganReq    = regexp.MustCompile(`morgan\.token\s*\([^)]*(?:req\.(?:body|headers\.authorization|cookies))`)

	// BATOU-FW-EXPRESS-013: Multer file upload without filter
	reExpressExtMulterUpload  = regexp.MustCompile(`multer\s*\(\s*\{`)
	reExpressExtMulterNoFilter = regexp.MustCompile(`fileFilter\s*:`)
	reExpressExtMulterLimits  = regexp.MustCompile(`limits\s*:`)

	// BATOU-FW-EXPRESS-014: Express trust proxy misconfigured
	reExpressExtTrustProxyTrue = regexp.MustCompile(`(?:app|server)\s*\.\s*set\s*\(\s*["']trust\s+proxy["']\s*,\s*true\s*\)`)
)

func init() {
	rules.Register(&ExpressNoRateLimit{})
	rules.Register(&ExpressResSendXSS{})
	rules.Register(&ExpressHardcodedSecret{})
	rules.Register(&ExpressMorganSensitive{})
	rules.Register(&ExpressMulterNoFilter{})
	rules.Register(&ExpressTrustProxyExt{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-EXPRESS-009: Express app without rate limiting
// ---------------------------------------------------------------------------

type ExpressNoRateLimit struct{}

func (r *ExpressNoRateLimit) ID() string                      { return "BATOU-FW-EXPRESS-009" }
func (r *ExpressNoRateLimit) Name() string                    { return "ExpressNoRateLimit" }
func (r *ExpressNoRateLimit) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ExpressNoRateLimit) Description() string {
	return "Detects Express applications without rate limiting middleware, making them vulnerable to brute-force and DoS attacks."
}
func (r *ExpressNoRateLimit) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExpressNoRateLimit) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !isExpressApp(ctx.Content) {
		return nil
	}
	// Skip if rate limiting is present
	if reExpressExtRateLimit.MatchString(ctx.Content) || reExpressExtThrottle.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reExpressExtAppListen.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Express application without rate limiting middleware",
				Description:   "This Express application does not appear to use rate limiting middleware (express-rate-limit, express-slow-down, etc.). Without rate limiting, the application is vulnerable to brute-force attacks, credential stuffing, and denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Install and configure express-rate-limit: const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }); app.use(limiter). Apply stricter limits to authentication endpoints.",
				CWEID:         "CWE-770",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "express", "rate-limiting", "dos"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-EXPRESS-010: res.send with user input (XSS)
// ---------------------------------------------------------------------------

type ExpressResSendXSS struct{}

func (r *ExpressResSendXSS) ID() string                      { return "BATOU-FW-EXPRESS-010" }
func (r *ExpressResSendXSS) Name() string                    { return "ExpressResSendXSS" }
func (r *ExpressResSendXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExpressResSendXSS) Description() string {
	return "Detects Express res.send() or res.write() with direct user input from req.params/query/body, enabling reflected XSS."
}
func (r *ExpressResSendXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExpressResSendXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reExpressExtResSendInput.FindString(line); m != "" {
			matched = m
		} else if m := reExpressExtResWriteInput.FindString(line); m != "" {
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
				Title:         "Express res.send() with user input (reflected XSS)",
				Description:   "User input from req.params, req.query, or req.body is sent directly in the response without encoding. If the Content-Type is text/html (Express default for strings), this creates a reflected XSS vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "HTML-encode user input before including in responses: res.send(escapeHtml(req.query.name)). Or set Content-Type to application/json: res.json({ name: req.query.name }). Use res.type('text/plain') for plain text.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "express", "xss", "reflected"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-EXPRESS-011: Session secret hardcoded
// ---------------------------------------------------------------------------

type ExpressHardcodedSecret struct{}

func (r *ExpressHardcodedSecret) ID() string                      { return "BATOU-FW-EXPRESS-011" }
func (r *ExpressHardcodedSecret) Name() string                    { return "ExpressHardcodedSecret" }
func (r *ExpressHardcodedSecret) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExpressHardcodedSecret) Description() string {
	return "Detects Express session middleware with hardcoded secret strings instead of environment variables."
}
func (r *ExpressHardcodedSecret) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExpressHardcodedSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inSessionBlock := false
	braceDepth := 0

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		if reExpressExtSessionBlock.MatchString(line) {
			inSessionBlock = true
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
		}

		if inSessionBlock {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if reExpressExtSessionSecret.MatchString(line) {
				// Skip if it references process.env
				if strings.Contains(line, "process.env") {
					continue
				}
				matched := t
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Express session secret hardcoded",
					Description:   "The session secret is hardcoded as a string literal. If this secret is committed to source control, anyone with access can forge session cookies and impersonate users.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use an environment variable for the session secret: secret: process.env.SESSION_SECRET. Generate a strong random secret: require('crypto').randomBytes(64).toString('hex').",
					CWEID:         "CWE-798",
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"framework", "express", "session", "hardcoded-secret"},
				})
			}
			if braceDepth <= 0 {
				inSessionBlock = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-EXPRESS-012: Morgan logging sensitive data
// ---------------------------------------------------------------------------

type ExpressMorganSensitive struct{}

func (r *ExpressMorganSensitive) ID() string                      { return "BATOU-FW-EXPRESS-012" }
func (r *ExpressMorganSensitive) Name() string                    { return "ExpressMorganSensitive" }
func (r *ExpressMorganSensitive) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ExpressMorganSensitive) Description() string {
	return "Detects Express morgan logging middleware configured to log sensitive data (passwords, tokens, authorization headers)."
}
func (r *ExpressMorganSensitive) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExpressMorganSensitive) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reExpressExtMorganCustom.FindString(line); m != "" {
			matched = m
		} else if m := reExpressExtMorganReq.FindString(line); m != "" {
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
				Title:         "Express morgan logs sensitive data",
				Description:   "The morgan logging middleware is configured with a custom format that includes sensitive data (passwords, tokens, authorization headers, cookies, or request bodies). This data will appear in log files and log aggregation services.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use standard morgan formats ('combined', 'common', 'short') that only log safe request metadata. Never log request bodies, authorization headers, or cookies. Redact sensitive fields before logging.",
				CWEID:         "CWE-532",
				OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "express", "logging", "sensitive-data"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-EXPRESS-013: Multer file upload without filter
// ---------------------------------------------------------------------------

type ExpressMulterNoFilter struct{}

func (r *ExpressMulterNoFilter) ID() string                      { return "BATOU-FW-EXPRESS-013" }
func (r *ExpressMulterNoFilter) Name() string                    { return "ExpressMulterNoFilter" }
func (r *ExpressMulterNoFilter) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExpressMulterNoFilter) Description() string {
	return "Detects Express multer file upload configuration without file type filtering, allowing unrestricted file uploads."
}
func (r *ExpressMulterNoFilter) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExpressMulterNoFilter) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if !reExpressExtMulterUpload.MatchString(line) {
			continue
		}

		// Look forward in the multer config for fileFilter
		end := i + 20
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[i:end], "\n")

		if !reExpressExtMulterNoFilter.MatchString(block) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Express multer upload without file type filter",
				Description:   "Multer is configured without a fileFilter, allowing any file type to be uploaded. An attacker can upload executable files, web shells, or malicious content that could be executed on the server or served to other users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add a fileFilter to validate file types: fileFilter: (req, file, cb) => { const allowed = /jpeg|jpg|png|gif/; const ok = allowed.test(file.mimetype); cb(null, ok); }. Also add limits: { fileSize: maxSize }.",
				CWEID:         "CWE-434",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "express", "file-upload", "multer"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-EXPRESS-014: Express trust proxy misconfigured
// ---------------------------------------------------------------------------

type ExpressTrustProxyExt struct{}

func (r *ExpressTrustProxyExt) ID() string                      { return "BATOU-FW-EXPRESS-014" }
func (r *ExpressTrustProxyExt) Name() string                    { return "ExpressTrustProxyExt" }
func (r *ExpressTrustProxyExt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *ExpressTrustProxyExt) Description() string {
	return "Detects Express trust proxy set to true (trusts all proxies), allowing IP spoofing via X-Forwarded-For."
}
func (r *ExpressTrustProxyExt) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExpressTrustProxyExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reExpressExtTrustProxyTrue.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Express trust proxy set to true (IP spoofing risk)",
				Description:   "Setting trust proxy to true makes Express trust X-Forwarded-For headers from any source. An attacker can forge their IP address, bypassing IP-based rate limiting, access controls, and geo-restrictions.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set trust proxy to a specific number of hops or subnet: app.set('trust proxy', 1) or app.set('trust proxy', 'loopback, 10.0.0.0/8'). Only trust known proxy addresses.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "express", "trust-proxy", "ip-spoofing"},
			})
		}
	}
	return findings
}
