package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// ASP.NET-specific security rule patterns
// ---------------------------------------------------------------------------

var (
	// GTSS-FW-ASPNET-001: [AllowAnonymous] on sensitive endpoints
	reAspnetAllowAnonymous = regexp.MustCompile(`\[AllowAnonymous\]`)
	// Sensitive endpoint indicators (admin, account, user, payment, etc.)
	reAspnetSensitiveEndpoint = regexp.MustCompile(`(?i)(?:admin|account|user|payment|billing|password|credential|secret|token|auth|profile|settings|manage)`)

	// GTSS-FW-ASPNET-002: Missing ValidateAntiForgeryToken on POST
	reAspnetHttpPost           = regexp.MustCompile(`\[Http(?:Post|Put|Delete|Patch)\]`)
	reAspnetAntiForgery        = regexp.MustCompile(`\[ValidateAntiForgeryToken\]`)
	reAspnetAutoAntiForgery    = regexp.MustCompile(`\[AutoValidateAntiforgeryToken\]`)
	reAspnetIgnoreAntiForgery  = regexp.MustCompile(`\[IgnoreAntiforgeryToken\]`)

	// GTSS-FW-ASPNET-003: Html.Raw with user input
	reAspnetHtmlRaw = regexp.MustCompile(`Html\.Raw\s*\(\s*(?:Model\.|ViewBag\.|ViewData\[|TempData\[|Request\.|[a-zA-Z_]\w*\s*[,)])`)

	// GTSS-FW-ASPNET-004: Connection string with password in config
	reAspnetConnStrPassword = regexp.MustCompile(`(?i)(?:connectionString|connection\s*string)\s*[=:]\s*["'][^"']*(?:Password|Pwd)\s*=\s*[^;'"]+`)

	// GTSS-FW-ASPNET-005: Custom errors disabled
	reAspnetCustomErrorsOff = regexp.MustCompile(`(?i)<customErrors\s+mode\s*=\s*["']Off["']`)
	reAspnetDevExceptionPage = regexp.MustCompile(`\.UseDeveloperExceptionPage\s*\(`)

	// GTSS-FW-ASPNET-006: ViewState MAC disabled
	reAspnetViewStateMacOff = regexp.MustCompile(`(?i)(?:enableViewStateMac\s*=\s*["']?false|ViewStateEncryptionMode\s*=\s*["']?Never)`)

	// GTSS-FW-ASPNET-007: Request validation disabled
	reAspnetReqValidationOff = regexp.MustCompile(`(?i)(?:validateRequest\s*=\s*["']?false|\[ValidateInput\s*\(\s*false\s*\)\])`)
	reAspnetReqFilterOff     = regexp.MustCompile(`(?i)requestValidationMode\s*=\s*["']2\.0["']`)

	// GTSS-FW-ASPNET-008: CORS allowing all origins
	reAspnetCorsAllowAny = regexp.MustCompile(`\.AllowAnyOrigin\s*\(`)
	reAspnetCorsPolicyAll = regexp.MustCompile(`(?i)WithOrigins\s*\(\s*["']\*["']\s*\)`)
	reAspnetCorsEnableAll = regexp.MustCompile(`EnableCors\s*\(\s*["']\*["']\s*\)`)

	// GTSS-FW-ASPNET-009: Weak password settings in Identity
	reAspnetWeakPwdLength    = regexp.MustCompile(`RequiredLength\s*=\s*([1-5])\b`)
	reAspnetPwdDigitFalse    = regexp.MustCompile(`RequireDigit\s*=\s*false`)
	reAspnetPwdUpperFalse    = regexp.MustCompile(`RequireUppercase\s*=\s*false`)
	reAspnetPwdNonAlphaFalse = regexp.MustCompile(`RequireNonAlphanumeric\s*=\s*false`)

	// GTSS-FW-ASPNET-010: Session cookie without SameSite
	reAspnetCookieSameSiteNone = regexp.MustCompile(`(?i)SameSite\s*=\s*(?:SameSiteMode\s*\.\s*)?None`)
	reAspnetCookieOptions      = regexp.MustCompile(`(?i)CookieOptions|CookieBuilder|CookiePolicyOptions`)
)

func init() {
	rules.Register(&AspnetAllowAnonymous{})
	rules.Register(&AspnetMissingAntiForgery{})
	rules.Register(&AspnetHtmlRaw{})
	rules.Register(&AspnetConnStringPassword{})
	rules.Register(&AspnetCustomErrorsOff{})
	rules.Register(&AspnetViewStateMacOff{})
	rules.Register(&AspnetReqValidationOff{})
	rules.Register(&AspnetCorsAllowAll{})
	rules.Register(&AspnetWeakPassword{})
	rules.Register(&AspnetCookieSameSite{})
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-001: AllowAnonymous on sensitive endpoint
// ---------------------------------------------------------------------------

type AspnetAllowAnonymous struct{}

func (r *AspnetAllowAnonymous) ID() string                      { return "GTSS-FW-ASPNET-001" }
func (r *AspnetAllowAnonymous) Name() string                    { return "AspnetAllowAnonymous" }
func (r *AspnetAllowAnonymous) DefaultSeverity() rules.Severity { return rules.High }
func (r *AspnetAllowAnonymous) Description() string {
	return "Detects [AllowAnonymous] attribute on sensitive endpoints (admin, account, payment, etc.) in ASP.NET."
}
func (r *AspnetAllowAnonymous) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *AspnetAllowAnonymous) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if !reAspnetAllowAnonymous.MatchString(line) {
			continue
		}
		// Look at surrounding lines for sensitive endpoint indicators
		start := i - 3
		if start < 0 {
			start = 0
		}
		end := i + 5
		if end > len(lines) {
			end = len(lines)
		}
		context := strings.Join(lines[start:end], "\n")
		if reAspnetSensitiveEndpoint.MatchString(context) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "[AllowAnonymous] on sensitive endpoint",
				Description:   "[AllowAnonymous] bypasses all authentication requirements on an endpoint that appears to handle sensitive operations (admin, account, payment, etc.). This may expose privileged functionality to unauthenticated users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove [AllowAnonymous] from sensitive endpoints. Use [Authorize] with appropriate roles or policies instead. If anonymous access is intentional, document the reason.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "authentication", "authorization"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-002: Missing ValidateAntiForgeryToken on POST
// ---------------------------------------------------------------------------

type AspnetMissingAntiForgery struct{}

func (r *AspnetMissingAntiForgery) ID() string                      { return "GTSS-FW-ASPNET-002" }
func (r *AspnetMissingAntiForgery) Name() string                    { return "AspnetMissingAntiForgery" }
func (r *AspnetMissingAntiForgery) DefaultSeverity() rules.Severity { return rules.High }
func (r *AspnetMissingAntiForgery) Description() string {
	return "Detects ASP.NET MVC [HttpPost] actions without [ValidateAntiForgeryToken], leaving them vulnerable to CSRF."
}
func (r *AspnetMissingAntiForgery) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *AspnetMissingAntiForgery) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if file has [AutoValidateAntiforgeryToken] (class-level protection)
	if reAspnetAutoAntiForgery.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if !reAspnetHttpPost.MatchString(line) {
			continue
		}
		// Check surrounding lines (above) for [ValidateAntiForgeryToken]
		start := i - 3
		if start < 0 {
			start = 0
		}
		hasToken := false
		for j := start; j <= i; j++ {
			if reAspnetAntiForgery.MatchString(lines[j]) || reAspnetIgnoreAntiForgery.MatchString(lines[j]) {
				hasToken = true
				break
			}
		}
		if !hasToken {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET [HttpPost] without [ValidateAntiForgeryToken]",
				Description:   "A POST/PUT/DELETE/PATCH action lacks [ValidateAntiForgeryToken]. Without CSRF protection, an attacker can forge requests from another site using an authenticated user's session.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add [ValidateAntiForgeryToken] to this action, or add [AutoValidateAntiforgeryToken] at the controller level. For API controllers using token auth, CSRF protection may not be needed.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "aspnet", "csrf"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-003: Html.Raw with user input
// ---------------------------------------------------------------------------

type AspnetHtmlRaw struct{}

func (r *AspnetHtmlRaw) ID() string                      { return "GTSS-FW-ASPNET-003" }
func (r *AspnetHtmlRaw) Name() string                    { return "AspnetHtmlRaw" }
func (r *AspnetHtmlRaw) DefaultSeverity() rules.Severity { return rules.High }
func (r *AspnetHtmlRaw) Description() string {
	return "Detects ASP.NET MVC Html.Raw() with model data or user input, which bypasses output encoding and enables XSS."
}
func (r *AspnetHtmlRaw) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *AspnetHtmlRaw) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reAspnetHtmlRaw.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET Html.Raw() with dynamic data (XSS risk)",
				Description:   "Html.Raw() renders content without HTML encoding. If the argument contains user input (Model, ViewBag, Request data), this creates a Cross-Site Scripting vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use @Model.Property instead of @Html.Raw(Model.Property) to let Razor auto-encode output. If raw HTML is needed, sanitize the input with an HTML sanitizer library (e.g., HtmlSanitizer NuGet package).",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-004: Connection string with password in config
// ---------------------------------------------------------------------------

type AspnetConnStringPassword struct{}

func (r *AspnetConnStringPassword) ID() string                      { return "GTSS-FW-ASPNET-004" }
func (r *AspnetConnStringPassword) Name() string                    { return "AspnetConnStringPassword" }
func (r *AspnetConnStringPassword) DefaultSeverity() rules.Severity { return rules.High }
func (r *AspnetConnStringPassword) Description() string {
	return "Detects ASP.NET connection strings with hardcoded passwords in configuration files."
}
func (r *AspnetConnStringPassword) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp, rules.LangAny}
}

func (r *AspnetConnStringPassword) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "<!--") {
			continue
		}
		if m := reAspnetConnStrPassword.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET connection string with hardcoded password",
				Description:   "A database connection string contains a hardcoded password. This exposes credentials in source control, build artifacts, and deployment logs.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use environment variables, Azure Key Vault, AWS Secrets Manager, or the Secret Manager tool. For local development, use User Secrets (dotnet user-secrets). Use Integrated Security=true for Windows Authentication.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "secrets", "connection-string"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-005: Custom errors disabled
// ---------------------------------------------------------------------------

type AspnetCustomErrorsOff struct{}

func (r *AspnetCustomErrorsOff) ID() string                      { return "GTSS-FW-ASPNET-005" }
func (r *AspnetCustomErrorsOff) Name() string                    { return "AspnetCustomErrorsOff" }
func (r *AspnetCustomErrorsOff) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *AspnetCustomErrorsOff) Description() string {
	return "Detects ASP.NET custom errors disabled or developer exception page enabled, exposing stack traces to users."
}
func (r *AspnetCustomErrorsOff) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp, rules.LangAny}
}

func (r *AspnetCustomErrorsOff) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "<!--") {
			continue
		}

		if m := reAspnetCustomErrorsOff.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET custom errors disabled (stack trace exposure)",
				Description:   "<customErrors mode=\"Off\"> disables custom error pages, exposing detailed stack traces, source code paths, and configuration details to end users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set <customErrors mode=\"RemoteOnly\"> or mode=\"On\" with a defaultRedirect to a custom error page. Never use mode=\"Off\" in production.",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "information-disclosure"},
			})
		}

		if m := reAspnetDevExceptionPage.FindString(line); m != "" {
			// Check if guarded by IsDevelopment()
			start := i - 5
			if start < 0 {
				start = 0
			}
			context := strings.Join(lines[start:i+1], "\n")
			if strings.Contains(context, "IsDevelopment") {
				continue
			}
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET Core UseDeveloperExceptionPage without environment check",
				Description:   "UseDeveloperExceptionPage() is called without an IsDevelopment() guard. In production, this exposes detailed exception information including stack traces, request details, and source code.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Wrap UseDeveloperExceptionPage() in an environment check: if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "aspnet", "information-disclosure"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-006: ViewState MAC validation disabled
// ---------------------------------------------------------------------------

type AspnetViewStateMacOff struct{}

func (r *AspnetViewStateMacOff) ID() string                      { return "GTSS-FW-ASPNET-006" }
func (r *AspnetViewStateMacOff) Name() string                    { return "AspnetViewStateMacOff" }
func (r *AspnetViewStateMacOff) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *AspnetViewStateMacOff) Description() string {
	return "Detects disabled ViewState MAC validation in ASP.NET, which allows ViewState tampering and potential remote code execution."
}
func (r *AspnetViewStateMacOff) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp, rules.LangAny}
}

func (r *AspnetViewStateMacOff) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "<!--") {
			continue
		}
		if m := reAspnetViewStateMacOff.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET ViewState MAC validation disabled (RCE risk)",
				Description:   "Disabling ViewState MAC validation allows attackers to tamper with serialized ViewState data. This can lead to remote code execution via deserialization attacks (CVE-2020-0688 class).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Never disable ViewState MAC validation. Remove enableViewStateMac=false. If ViewState is not needed, disable ViewState entirely with EnableViewState=false rather than removing MAC protection.",
				CWEID:         "CWE-642",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "viewstate", "deserialization"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-007: Request validation disabled
// ---------------------------------------------------------------------------

type AspnetReqValidationOff struct{}

func (r *AspnetReqValidationOff) ID() string                      { return "GTSS-FW-ASPNET-007" }
func (r *AspnetReqValidationOff) Name() string                    { return "AspnetReqValidationOff" }
func (r *AspnetReqValidationOff) DefaultSeverity() rules.Severity { return rules.High }
func (r *AspnetReqValidationOff) Description() string {
	return "Detects disabled ASP.NET request validation, which removes built-in XSS protection."
}
func (r *AspnetReqValidationOff) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp, rules.LangAny}
}

func (r *AspnetReqValidationOff) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "<!--") {
			continue
		}

		var matched string
		if m := reAspnetReqValidationOff.FindString(line); m != "" {
			matched = m
		} else if m := reAspnetReqFilterOff.FindString(line); m != "" {
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
				Title:         "ASP.NET request validation disabled",
				Description:   "Request validation is disabled, removing ASP.NET's built-in protection against potentially dangerous input (HTML, script tags). This increases the risk of XSS attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Keep request validation enabled. If you need to accept HTML input, use [AllowHtml] on specific model properties instead of disabling validation entirely. Sanitize all HTML input with a whitelist-based sanitizer.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "input-validation", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-008: CORS allowing all origins
// ---------------------------------------------------------------------------

type AspnetCorsAllowAll struct{}

func (r *AspnetCorsAllowAll) ID() string                      { return "GTSS-FW-ASPNET-008" }
func (r *AspnetCorsAllowAll) Name() string                    { return "AspnetCorsAllowAll" }
func (r *AspnetCorsAllowAll) DefaultSeverity() rules.Severity { return rules.High }
func (r *AspnetCorsAllowAll) Description() string {
	return "Detects ASP.NET CORS policies that allow all origins, enabling cross-origin attacks."
}
func (r *AspnetCorsAllowAll) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *AspnetCorsAllowAll) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reAspnetCorsAllowAny.FindString(line); m != "" {
			matched = m
		} else if m := reAspnetCorsPolicyAll.FindString(line); m != "" {
			matched = m
		} else if m := reAspnetCorsEnableAll.FindString(line); m != "" {
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
				Title:         "ASP.NET CORS policy allows all origins",
				Description:   "The CORS policy allows requests from any origin. This permits any website to make cross-origin requests to the API, potentially exposing sensitive data or enabling CSRF-like attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Specify trusted origins explicitly: builder.WithOrigins(\"https://trusted-domain.com\"). Avoid AllowAnyOrigin() especially when AllowCredentials() is also used.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "cors"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-009: Identity weak password settings
// ---------------------------------------------------------------------------

type AspnetWeakPassword struct{}

func (r *AspnetWeakPassword) ID() string                      { return "GTSS-FW-ASPNET-009" }
func (r *AspnetWeakPassword) Name() string                    { return "AspnetWeakPassword" }
func (r *AspnetWeakPassword) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *AspnetWeakPassword) Description() string {
	return "Detects ASP.NET Identity password settings that are too weak (short length, missing complexity requirements)."
}
func (r *AspnetWeakPassword) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *AspnetWeakPassword) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		if m := reAspnetWeakPwdLength.FindString(line); m != "" {
			if len(m) > 120 {
				m = m[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET Identity weak password length requirement",
				Description:   "The minimum password length is set to 5 or fewer characters. Short passwords are easily brute-forced and vulnerable to dictionary attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   m,
				Suggestion:    "Set RequiredLength to at least 8, preferably 12 or more. NIST SP 800-63B recommends supporting passwords up to 64 characters.",
				CWEID:         "CWE-521",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "identity", "password-policy"},
			})
		}

		// Check for multiple complexity requirements disabled together
		if reAspnetPwdDigitFalse.MatchString(line) || reAspnetPwdUpperFalse.MatchString(line) || reAspnetPwdNonAlphaFalse.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET Identity password complexity requirement disabled",
				Description:   "A password complexity requirement (digit, uppercase, or non-alphanumeric character) is explicitly disabled, weakening the password policy.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Keep complexity requirements enabled. At minimum, require digits and uppercase letters. Consider using a password strength estimator (e.g., zxcvbn) instead of character-class rules.",
				CWEID:         "CWE-521",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "aspnet", "identity", "password-policy"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ASPNET-010: Session cookie without SameSite
// ---------------------------------------------------------------------------

type AspnetCookieSameSite struct{}

func (r *AspnetCookieSameSite) ID() string                      { return "GTSS-FW-ASPNET-010" }
func (r *AspnetCookieSameSite) Name() string                    { return "AspnetCookieSameSite" }
func (r *AspnetCookieSameSite) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *AspnetCookieSameSite) Description() string {
	return "Detects ASP.NET session cookies configured with SameSite=None, weakening CSRF protection."
}
func (r *AspnetCookieSameSite) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *AspnetCookieSameSite) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reAspnetCookieSameSiteNone.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ASP.NET cookie with SameSite=None",
				Description:   "Setting SameSite=None allows the cookie to be sent in cross-site requests, weakening CSRF protection. The cookie will be sent when any third-party website makes requests to your application.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use SameSite=Strict or SameSite=Lax unless cross-site cookie access is required (e.g., OAuth/SSO flows). When using None, ensure the Secure flag is also set.",
				CWEID:         "CWE-1275",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "aspnet", "cookie", "csrf"},
			})
		}
	}
	return findings
}
