package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- Angular
// ---------------------------------------------------------------------------

// GTSS-FW-ANGULAR-001: bypassSecurityTrustHtml with user input
var reAngularBypassTrust = regexp.MustCompile(`bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(`)
var reAngularUserInput = regexp.MustCompile(`(?:this\.\w*[Ii]nput|this\.route|this\.activatedRoute|params\[|queryParams\[|req\.|request\.|formControl|\.value\b|user[Ii]nput|\.nativeElement)`)

// GTSS-FW-ANGULAR-002: [innerHTML] binding
var reAngularInnerHTMLBind = regexp.MustCompile(`\[innerHTML\]\s*=\s*["']`)
var reAngularInnerHTMLUserData = regexp.MustCompile(`\[innerHTML\]\s*=\s*["'](?:\w*[Uu]ser\w*|\w*[Ii]nput\w*|\w*[Dd]ata\w*|\w*[Cc]ontent\w*|\w*[Hh]tml\w*|\w*[Mm]essage\w*)["']`)

// GTSS-FW-ANGULAR-003: Disabled route guards
var reAngularCanActivate = regexp.MustCompile(`canActivate\s*:\s*\[\s*\]`)
var reAngularCanDeactivate = regexp.MustCompile(`canDeactivate\s*:\s*\[\s*\]`)
var reAngularGuardReturnTrue = regexp.MustCompile(`canActivate\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{[^}]*return\s+true\s*;?\s*\}`)

// GTSS-FW-ANGULAR-004: HTTP interceptor missing token refresh
var reAngularInterceptor = regexp.MustCompile(`(?:implements\s+HttpInterceptor|@Injectable)`)
var reAngularIntercept = regexp.MustCompile(`intercept\s*\(\s*\w+\s*:\s*HttpRequest`)
var reAngularTokenRefresh = regexp.MustCompile(`(?:refresh[Tt]oken|refreshAuth|tokenRefresh|401|isTokenExpired|jwt.*expir|expir.*jwt)`)

// GTSS-FW-ANGULAR-005: JSONP callback with user input
var reAngularJSONP = regexp.MustCompile(`\.jsonp\s*\(`)
var reAngularJSONPUserInput = regexp.MustCompile(`\.jsonp\s*\(\s*(?:` + "`" + `[^` + "`" + `]*\$\{|['"][^'"]*['"]\s*\+\s*(?:this\.\w*[Ii]nput|this\.\w*[Pp]aram|user))`)

// GTSS-FW-ANGULAR-006: Template injection via component template
var reAngularTemplateInterp = regexp.MustCompile(`template\s*:\s*(?:` + "`" + `[^` + "`" + `]*\$\{|['"][^'"]*['"]\s*\+)`)
var reAngularTemplateUserData = regexp.MustCompile(`template\s*:\s*(?:` + "`" + `[^` + "`" + `]*\$\{(?:this\.\w*[Uu]ser|this\.\w*[Ii]nput|this\.\w*[Dd]ata|this\.\w*[Pp]aram)` + `|['"][^'"]*['"]\s*\+\s*(?:this\.\w*[Uu]ser|this\.\w*[Ii]nput))`)

func init() {
	rules.Register(&AngularBypassTrust{})
	rules.Register(&AngularInnerHTML{})
	rules.Register(&AngularDisabledGuard{})
	rules.Register(&AngularInterceptorNoRefresh{})
	rules.Register(&AngularJSONPInjection{})
	rules.Register(&AngularTemplateInjection{})
}

// ---------------------------------------------------------------------------
// GTSS-FW-ANGULAR-001: bypassSecurityTrustHtml with user input
// ---------------------------------------------------------------------------

type AngularBypassTrust struct{}

func (r *AngularBypassTrust) ID() string                      { return "GTSS-FW-ANGULAR-001" }
func (r *AngularBypassTrust) Name() string                    { return "AngularBypassTrust" }
func (r *AngularBypassTrust) DefaultSeverity() rules.Severity { return rules.High }
func (r *AngularBypassTrust) Description() string {
	return "Detects Angular DomSanitizer.bypassSecurityTrustHtml() with user-controlled input."
}
func (r *AngularBypassTrust) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *AngularBypassTrust) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasUserInput := reAngularUserInput.MatchString(ctx.Content)

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reAngularBypassTrust.FindString(line); m != "" {
			confidence := "medium"
			if hasUserInput {
				confidence = "high"
			}
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Angular bypassSecurityTrust with potential user input (XSS)",
				Description:   "DomSanitizer.bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl() explicitly disables Angular's built-in XSS protection. If the bypassed content contains user input, this creates a Cross-Site Scripting vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Avoid bypassSecurityTrust methods. Use Angular's built-in sanitization. If raw HTML is needed, sanitize server-side or use DOMPurify before bypassing trust.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"framework", "angular", "xss", "sanitizer-bypass"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ANGULAR-002: [innerHTML] binding with user data
// ---------------------------------------------------------------------------

type AngularInnerHTML struct{}

func (r *AngularInnerHTML) ID() string                      { return "GTSS-FW-ANGULAR-002" }
func (r *AngularInnerHTML) Name() string                    { return "AngularInnerHTML" }
func (r *AngularInnerHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *AngularInnerHTML) Description() string {
	return "Detects Angular [innerHTML] binding with user-controlled data."
}
func (r *AngularInnerHTML) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *AngularInnerHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "<!--") {
			continue
		}
		if m := reAngularInnerHTMLUserData.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Angular [innerHTML] binding with user data (XSS risk)",
				Description:   "[innerHTML] binding renders raw HTML content. While Angular sanitizes it by default, combining it with bypassSecurityTrustHtml or if the sanitizer is misconfigured can lead to XSS. Variables named with user/input/data suggest user-controlled content.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Prefer text interpolation {{ }} over [innerHTML]. If HTML rendering is needed, ensure the content is sanitized and never bypasses Angular's DomSanitizer.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "angular", "xss", "innerHTML"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ANGULAR-003: Disabled route guards
// ---------------------------------------------------------------------------

type AngularDisabledGuard struct{}

func (r *AngularDisabledGuard) ID() string                      { return "GTSS-FW-ANGULAR-003" }
func (r *AngularDisabledGuard) Name() string                    { return "AngularDisabledGuard" }
func (r *AngularDisabledGuard) DefaultSeverity() rules.Severity { return rules.High }
func (r *AngularDisabledGuard) Description() string {
	return "Detects Angular routes with empty canActivate guards or guards that always return true."
}
func (r *AngularDisabledGuard) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *AngularDisabledGuard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		var title string

		if m := reAngularCanActivate.FindString(line); m != "" {
			matched = m
			title = "Angular route with empty canActivate guard"
		} else if m := reAngularGuardReturnTrue.FindString(line); m != "" {
			matched = m
			title = "Angular guard always returns true (effectively disabled)"
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
				Description:   "An Angular route guard is either empty (canActivate: []) or always returns true, providing no actual access control. This allows any user, including unauthenticated users, to access the protected route.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Implement proper authentication checks in route guards. Check for valid tokens/sessions: canActivate() { return this.authService.isAuthenticated(); }. Remove empty guard arrays.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "angular", "route-guard", "authentication"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ANGULAR-004: HTTP interceptor missing auth token refresh
// ---------------------------------------------------------------------------

type AngularInterceptorNoRefresh struct{}

func (r *AngularInterceptorNoRefresh) ID() string { return "GTSS-FW-ANGULAR-004" }
func (r *AngularInterceptorNoRefresh) Name() string {
	return "AngularInterceptorNoRefresh"
}
func (r *AngularInterceptorNoRefresh) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *AngularInterceptorNoRefresh) Description() string {
	return "Detects Angular HTTP interceptors that handle auth tokens but do not implement token refresh logic."
}
func (r *AngularInterceptorNoRefresh) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *AngularInterceptorNoRefresh) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reAngularInterceptor.MatchString(ctx.Content) {
		return nil
	}
	if !reAngularIntercept.MatchString(ctx.Content) {
		return nil
	}
	// Only flag interceptors that handle auth tokens
	if !strings.Contains(ctx.Content, "Authorization") && !strings.Contains(ctx.Content, "Bearer") && !strings.Contains(ctx.Content, "token") {
		return nil
	}
	if reAngularTokenRefresh.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reAngularIntercept.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Angular HTTP interceptor without token refresh handling",
				Description:   "This Angular HTTP interceptor handles authentication tokens but does not implement token refresh logic for expired tokens (401 responses). Without token refresh, users will be unexpectedly logged out when tokens expire, leading to poor session management.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Handle 401 responses in the interceptor by attempting a token refresh: catchError(err => { if (err.status === 401) { return this.authService.refreshToken().pipe(switchMap(() => next.handle(clonedReq))); } }).",
				CWEID:         "CWE-613",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "angular", "interceptor", "token-refresh"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ANGULAR-005: JSONP callback with user input
// ---------------------------------------------------------------------------

type AngularJSONPInjection struct{}

func (r *AngularJSONPInjection) ID() string                      { return "GTSS-FW-ANGULAR-005" }
func (r *AngularJSONPInjection) Name() string                    { return "AngularJSONPInjection" }
func (r *AngularJSONPInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *AngularJSONPInjection) Description() string {
	return "Detects Angular JSONP requests with user-controlled URL or callback parameters."
}
func (r *AngularJSONPInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *AngularJSONPInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reAngularJSONPUserInput.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Angular JSONP request with user-controlled URL (XSS risk)",
				Description:   "An Angular JSONP request constructs its URL using user-controlled input. JSONP executes the response as JavaScript, so an attacker who controls the URL can point it to a malicious endpoint that returns arbitrary JavaScript code.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Avoid JSONP; use CORS-enabled HTTP requests instead. If JSONP is required, validate the URL against an allowlist of trusted endpoints. Never construct JSONP URLs from user input.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "angular", "jsonp", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-ANGULAR-006: Template injection via user input in component
// ---------------------------------------------------------------------------

type AngularTemplateInjection struct{}

func (r *AngularTemplateInjection) ID() string { return "GTSS-FW-ANGULAR-006" }
func (r *AngularTemplateInjection) Name() string {
	return "AngularTemplateInjection"
}
func (r *AngularTemplateInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *AngularTemplateInjection) Description() string {
	return "Detects Angular component templates dynamically constructed from user input."
}
func (r *AngularTemplateInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *AngularTemplateInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reAngularTemplateUserData.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Angular template injection via user input",
				Description:   "An Angular component template is dynamically constructed using string interpolation or concatenation with user-controlled data. This can lead to client-side template injection, allowing attackers to execute arbitrary expressions in the Angular context.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Never construct Angular templates dynamically from user input. Use data binding ({{ }}) in static templates instead. If dynamic templates are needed, sanitize the input and compile templates securely.",
				CWEID:         "CWE-1336",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "angular", "template-injection"},
			})
		}
	}
	return findings
}
