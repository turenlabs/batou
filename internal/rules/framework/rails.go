package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Rails-specific security rule patterns
// ---------------------------------------------------------------------------

var (
	// GTSS-FW-RAILS-001: html_safe on dynamic/user content (broader than XSS-008 which requires user-input indicators)
	// Matches variable.html_safe and "string#{interp}".html_safe
	reRailsHTMLSafe = regexp.MustCompile(`\.html_safe\b`)
	// Safe: string literal without interpolation .html_safe (e.g., "<br>".html_safe)
	reRailsHTMLSafeLiteral = regexp.MustCompile(`["'][^"'#]*["']\s*\.html_safe\b`)

	// GTSS-FW-RAILS-002: render inline with dynamic content (SSTI)
	reRailsRenderInline = regexp.MustCompile(`\brender\s+inline\s*:\s*[^"'\s]`)
	// render inline: with string interpolation
	reRailsRenderInlineInterp = regexp.MustCompile(`\brender\s+inline\s*:\s*"[^"]*#\{`)

	// GTSS-FW-RAILS-003: constantize / safe_constantize with user input
	reRailsConstantize = regexp.MustCompile(`\.(?:constantize|safe_constantize)\b`)
	// Indicators that the string being constantized comes from user input
	reRailsConstantizeParams = regexp.MustCompile(`params\s*\[.*\]\s*\.(?:constantize|safe_constantize)`)

	// GTSS-FW-RAILS-004: params.permit! mass assignment bypass
	reRailsPermitBang = regexp.MustCompile(`\bparams\s*\.permit!`)

	// GTSS-FW-RAILS-005: Rails misconfigurations
	reRailsDebugTrue     = regexp.MustCompile(`config\.consider_all_requests_local\s*=\s*true`)
	reRailsForceSSLFalse = regexp.MustCompile(`config\.force_ssl\s*=\s*false`)
	reRailsNullSession   = regexp.MustCompile(`protect_from_forgery\s+.*:null_session`)
	reRailsSkipCSRF      = regexp.MustCompile(`skip_before_action\s+:verify_authenticity_token`)

	// GTSS-FW-RAILS-006: SQL interpolation in ActiveRecord (complementing INJ-001)
	// User.where("name = '#{params[:name]}'") — explicit params interpolation in where
	reRailsWhereParamsInterp = regexp.MustCompile(`\.where\(\s*"[^"]*#\{\s*params\s*\[`)
	// User.where(params[:conditions]) — hash injection
	reRailsWhereParamsHash = regexp.MustCompile(`\.where\(\s*params\s*\[`)
	// .order with string interpolation from params
	reRailsOrderInterp = regexp.MustCompile(`\.order\(\s*"[^"]*#\{`)
	reRailsOrderParams = regexp.MustCompile(`\.order\(\s*params\s*\[`)
)

// ---------------------------------------------------------------------------
// GTSS-FW-RAILS-001: html_safe on dynamic content
// ---------------------------------------------------------------------------

type RailsHTMLSafe struct{}

func (r *RailsHTMLSafe) ID() string                      { return "GTSS-FW-RAILS-001" }
func (r *RailsHTMLSafe) Name() string                    { return "RailsHTMLSafe" }
func (r *RailsHTMLSafe) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsHTMLSafe) Description() string {
	return "Detects .html_safe called on dynamic content in Rails, which bypasses auto-escaping and can lead to XSS."
}
func (r *RailsHTMLSafe) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsHTMLSafe) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reRailsHTMLSafe.MatchString(line) {
			continue
		}
		// Skip string literal without interpolation .html_safe (safe pattern like "<br>".html_safe)
		if reRailsHTMLSafeLiteral.MatchString(line) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails .html_safe on dynamic content",
			Description:   "Calling .html_safe on a variable or interpolated string bypasses Rails auto-escaping. If the content includes user input, this creates an XSS vulnerability.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use the sanitize() helper instead of .html_safe, or ensure the content is fully sanitized before marking as safe. Prefer ERB auto-escaping (<%= %>).",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"rails", "xss", "html_safe"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-RAILS-002: render inline with dynamic content (SSTI)
// ---------------------------------------------------------------------------

type RailsRenderInline struct{}

func (r *RailsRenderInline) ID() string                      { return "GTSS-FW-RAILS-002" }
func (r *RailsRenderInline) Name() string                    { return "RailsRenderInline" }
func (r *RailsRenderInline) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RailsRenderInline) Description() string {
	return "Detects render inline: with dynamic content in Rails, which can lead to server-side template injection (SSTI) and remote code execution."
}
func (r *RailsRenderInline) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsRenderInline) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		var matched bool
		if reRailsRenderInline.MatchString(line) || reRailsRenderInlineInterp.MatchString(line) {
			matched = true
		}
		if matched {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails render inline: with dynamic content (SSTI risk)",
				Description:   "render inline: evaluates ERB templates from a string. If the string contains user input, an attacker can inject ERB tags (<%= %>) to execute arbitrary Ruby code on the server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Never pass user input to render inline:. Use render with a template file and pass data as local variables instead.",
				CWEID:         "CWE-1336",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rails", "ssti", "template-injection", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-RAILS-003: constantize / safe_constantize
// ---------------------------------------------------------------------------

type RailsConstantize struct{}

func (r *RailsConstantize) ID() string                      { return "GTSS-FW-RAILS-003" }
func (r *RailsConstantize) Name() string                    { return "RailsConstantize" }
func (r *RailsConstantize) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RailsConstantize) Description() string {
	return "Detects use of constantize/safe_constantize in Rails, which converts strings to class names and can lead to arbitrary class instantiation and RCE."
}
func (r *RailsConstantize) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsConstantize) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !reRailsConstantize.MatchString(line) {
			continue
		}
		confidence := "medium"
		severity := rules.High
		if reRailsConstantizeParams.MatchString(line) ||
			strings.Contains(line, "params") ||
			strings.Contains(line, "input") ||
			strings.Contains(line, "user") {
			confidence = "high"
			severity = rules.Critical
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      severity,
			SeverityLabel: severity.String(),
			Title:         "Rails constantize/safe_constantize usage",
			Description:   "constantize converts a string to a Ruby class constant. If the string is user-controlled, an attacker can instantiate arbitrary classes, potentially leading to remote code execution via gadget chains.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use an allowlist of permitted class names instead of constantize. Example: ALLOWED_TYPES.include?(type) && type.constantize",
			CWEID:         "CWE-470",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    confidence,
			Tags:          []string{"rails", "rce", "constantize", "unsafe-reflection"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-RAILS-004: params.permit! mass assignment
// ---------------------------------------------------------------------------

type RailsPermitBang struct{}

func (r *RailsPermitBang) ID() string                      { return "GTSS-FW-RAILS-004" }
func (r *RailsPermitBang) Name() string                    { return "RailsPermitBang" }
func (r *RailsPermitBang) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsPermitBang) Description() string {
	return "Detects params.permit! in Rails, which permits all parameters and bypasses strong parameter protection, enabling mass assignment attacks."
}
func (r *RailsPermitBang) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsPermitBang) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if reRailsPermitBang.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails params.permit! bypasses strong parameters",
				Description:   "params.permit! permits all parameters without filtering, defeating Rails strong parameter protection. An attacker can set any model attribute, including admin flags, foreign keys, or other sensitive fields.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Use params.require(:model).permit(:field1, :field2) to explicitly whitelist allowed parameters.",
				CWEID:         "CWE-915",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"rails", "mass-assignment", "strong-params"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-RAILS-005: Rails misconfigurations
// ---------------------------------------------------------------------------

type RailsMisconfig struct{}

func (r *RailsMisconfig) ID() string                      { return "GTSS-FW-RAILS-005" }
func (r *RailsMisconfig) Name() string                    { return "RailsMisconfig" }
func (r *RailsMisconfig) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RailsMisconfig) Description() string {
	return "Detects insecure Rails configuration settings that weaken security in production."
}
func (r *RailsMisconfig) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsMisconfig) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type check struct {
		re         *regexp.Regexp
		title      string
		desc       string
		suggestion string
		cwe        string
	}

	checks := []check{
		{
			re:         reRailsDebugTrue,
			title:      "Rails consider_all_requests_local = true",
			desc:       "Setting consider_all_requests_local to true in production exposes detailed error pages with stack traces, environment variables, and source code to all users.",
			suggestion: "Set config.consider_all_requests_local = false in production.rb.",
			cwe:        "CWE-209",
		},
		{
			re:         reRailsForceSSLFalse,
			title:      "Rails force_ssl disabled",
			desc:       "Disabling force_ssl allows HTTP connections, exposing session cookies, credentials, and user data to network interception.",
			suggestion: "Set config.force_ssl = true in production.rb to enforce HTTPS.",
			cwe:        "CWE-319",
		},
		{
			re:         reRailsNullSession,
			title:      "Rails CSRF protection weakened with :null_session",
			desc:       "protect_from_forgery with: :null_session nullifies the session on CSRF failure instead of raising an error, which may weaken CSRF protection for session-based authentication.",
			suggestion: "Use protect_from_forgery with: :exception for traditional web apps. Only use :null_session for stateless API controllers.",
			cwe:        "CWE-352",
		},
		{
			re:         reRailsSkipCSRF,
			title:      "Rails CSRF verification skipped",
			desc:       "Skipping verify_authenticity_token disables CSRF protection for the controller, making it vulnerable to cross-site request forgery attacks.",
			suggestion: "Do not skip CSRF verification for actions that modify state. If needed for APIs, use token-based authentication (JWT) instead of session cookies.",
			cwe:        "CWE-352",
		},
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		for _, c := range checks {
			if c.re.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         c.title,
					Description:   c.desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    c.suggestion,
					CWEID:         c.cwe,
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"rails", "misconfiguration"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-RAILS-006: ActiveRecord SQL injection with params
// ---------------------------------------------------------------------------

type RailsSQLParams struct{}

func (r *RailsSQLParams) ID() string                      { return "GTSS-FW-RAILS-006" }
func (r *RailsSQLParams) Name() string                    { return "RailsSQLParams" }
func (r *RailsSQLParams) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RailsSQLParams) Description() string {
	return "Detects Rails ActiveRecord methods called with params interpolation or direct params hash, enabling SQL injection."
}
func (r *RailsSQLParams) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsSQLParams) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type check struct {
		re         *regexp.Regexp
		title      string
		desc       string
		confidence string
	}

	checks := []check{
		{
			re:         reRailsWhereParamsInterp,
			title:      "Rails .where() with params string interpolation (SQLi)",
			desc:       "ActiveRecord .where() uses string interpolation with params, allowing an attacker to inject arbitrary SQL.",
			confidence: "high",
		},
		{
			re:         reRailsWhereParamsHash,
			title:      "Rails .where() with raw params hash (SQLi)",
			desc:       "Passing params directly to .where() allows an attacker to inject SQL operators. Use hash conditions: .where(name: params[:name]).",
			confidence: "high",
		},
		{
			re:         reRailsOrderInterp,
			title:      "Rails .order() with string interpolation (SQLi)",
			desc:       "ActiveRecord .order() with string interpolation allows SQL injection through the ORDER BY clause.",
			confidence: "medium",
		},
		{
			re:         reRailsOrderParams,
			title:      "Rails .order() with raw params (SQLi)",
			desc:       "Passing params directly to .order() allows SQL injection through the ORDER BY clause.",
			confidence: "high",
		},
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		for _, c := range checks {
			if c.re.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         c.title,
					Description:   c.desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use parameterized queries: .where(name: params[:name]) or .where('name = ?', params[:name]). For .order(), use an allowlist of column names.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    c.confidence,
					Tags:          []string{"rails", "sql-injection", "activerecord"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
