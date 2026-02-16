package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Spring extended security rule patterns (SPRING-011 through SPRING-018)
// ---------------------------------------------------------------------------

var (
	// GTSS-FW-SPRING-011: Actuator endpoints exposed without auth (config-level)
	reSpringExtActuatorExpose = regexp.MustCompile(`management\.endpoints\.web\.exposure\.include\s*[=:]\s*\*`)
	reSpringExtActuatorBase   = regexp.MustCompile(`management\.endpoint\.\w+\.enabled\s*[=:]\s*true`)

	// GTSS-FW-SPRING-012: Spring Data REST without authorization
	reSpringExtDataRest       = regexp.MustCompile(`@RepositoryRestResource`)
	reSpringExtDataRestExport = regexp.MustCompile(`exported\s*=\s*true`)

	// GTSS-FW-SPRING-013: Spring Security CSRF disabled (lambda DSL, newer style)
	reSpringExtCsrfDisable    = regexp.MustCompile(`\.csrf\s*\(\s*(?:csrf\s*->|AbstractHttpConfigurer::)\s*(?:csrf\.)?disable`)
	reSpringExtCsrfCustomizer = regexp.MustCompile(`\.csrf\s*\(\s*CsrfConfigurer::disable\s*\)`)

	// GTSS-FW-SPRING-014: DevTools in production
	reSpringExtDevToolsDep  = regexp.MustCompile(`spring-boot-devtools`)
	reSpringExtDevToolsConf = regexp.MustCompile(`spring\.devtools\.`)

	// GTSS-FW-SPRING-015: @ResponseBody with unescaped user data
	reSpringExtResponseBody    = regexp.MustCompile(`@ResponseBody`)
	reSpringExtReturnUserInput = regexp.MustCompile(`return\s+(?:request\.getParameter|params\.get|input|userInput|req\.)`)
	reSpringExtProducesHTML    = regexp.MustCompile(`produces\s*=\s*(?:"text/html"|MediaType\.TEXT_HTML)`)

	// GTSS-FW-SPRING-016: Profile-specific secrets in application.yml
	reSpringExtSecretInYml   = regexp.MustCompile(`(?i)(?:password|secret|api[_-]?key|token|credential)\s*:\s*["']?[A-Za-z0-9+/=@#$%^&*]{8,}`)
	reSpringExtYmlProfile    = regexp.MustCompile(`(?i)spring\.profiles\.active|---`)

	// GTSS-FW-SPRING-017: OAuth2 redirect_uri not restricted
	reSpringExtOAuth2Redirect = regexp.MustCompile(`redirect[_-]?uri\s*[=:]\s*(?:["']\*["']|.*\.\*)`)
	reSpringExtOAuth2Any      = regexp.MustCompile(`\.redirectUriTemplate\s*\(\s*["']\{`)

	// GTSS-FW-SPRING-018: Method security not enabled
	reSpringExtEnableMethodSec  = regexp.MustCompile(`@EnableGlobalMethodSecurity|@EnableMethodSecurity`)
	reSpringExtPreAuthorize     = regexp.MustCompile(`@PreAuthorize|@Secured|@RolesAllowed`)
)

func init() {
	rules.Register(&SpringActuatorNoAuth{})
	rules.Register(&SpringDataRESTNoAuth{})
	rules.Register(&SpringCSRFDisabledExt{})
	rules.Register(&SpringDevToolsProd{})
	rules.Register(&SpringResponseBodyXSS{})
	rules.Register(&SpringYmlSecrets{})
	rules.Register(&SpringOAuth2Redirect{})
	rules.Register(&SpringMethodSecMissing{})
}

// ---------------------------------------------------------------------------
// GTSS-FW-SPRING-011: Actuator endpoints exposed without auth
// ---------------------------------------------------------------------------

type SpringActuatorNoAuth struct{}

func (r *SpringActuatorNoAuth) ID() string                      { return "GTSS-FW-SPRING-011" }
func (r *SpringActuatorNoAuth) Name() string                    { return "SpringActuatorNoAuth" }
func (r *SpringActuatorNoAuth) DefaultSeverity() rules.Severity { return rules.High }
func (r *SpringActuatorNoAuth) Description() string {
	return "Detects Spring Boot Actuator endpoints exposed with wildcard include (*) which may expose sensitive operational data without authentication."
}
func (r *SpringActuatorNoAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangYAML, rules.LangAny}
}

func (r *SpringActuatorNoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reSpringExtActuatorExpose.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring Actuator exposes all endpoints via wildcard",
				Description:   "management.endpoints.web.exposure.include=* exposes all actuator endpoints (env, heapdump, shutdown, etc.) over HTTP. These endpoints reveal secrets, environment variables, and allow heap dumps.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Expose only necessary endpoints: management.endpoints.web.exposure.include=health,info. Protect actuator endpoints with Spring Security requiring admin roles.",
				CWEID:         "CWE-200",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "spring", "actuator", "information-disclosure"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SPRING-012: Spring Data REST without authorization
// ---------------------------------------------------------------------------

type SpringDataRESTNoAuth struct{}

func (r *SpringDataRESTNoAuth) ID() string                      { return "GTSS-FW-SPRING-012" }
func (r *SpringDataRESTNoAuth) Name() string                    { return "SpringDataRESTNoAuth" }
func (r *SpringDataRESTNoAuth) DefaultSeverity() rules.Severity { return rules.High }
func (r *SpringDataRESTNoAuth) Description() string {
	return "Detects Spring Data REST repositories exposed without authorization annotations, automatically creating CRUD endpoints."
}
func (r *SpringDataRESTNoAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *SpringDataRESTNoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reSpringExtDataRest.MatchString(ctx.Content) {
		return nil
	}
	// Skip if file has security annotations
	if strings.Contains(ctx.Content, "@PreAuthorize") || strings.Contains(ctx.Content, "@Secured") ||
		strings.Contains(ctx.Content, "@RolesAllowed") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reSpringExtDataRest.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring Data REST repository exposed without authorization",
				Description:   "@RepositoryRestResource automatically exposes CRUD endpoints (GET, POST, PUT, DELETE) for the repository. Without @PreAuthorize or @Secured annotations, all operations are accessible to any authenticated user.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add @PreAuthorize annotations to the repository interface methods, or set exported=false and create explicit controller endpoints with proper authorization. Use @RepositoryRestResource(exported = false) for sensitive entities.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "spring", "data-rest", "authorization"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SPRING-013: Spring Security CSRF disabled
// ---------------------------------------------------------------------------

type SpringCSRFDisabledExt struct{}

func (r *SpringCSRFDisabledExt) ID() string                      { return "GTSS-FW-SPRING-013" }
func (r *SpringCSRFDisabledExt) Name() string                    { return "SpringCSRFDisabledExt" }
func (r *SpringCSRFDisabledExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *SpringCSRFDisabledExt) Description() string {
	return "Detects Spring Security CSRF protection disabled using newer lambda DSL or customizer syntax."
}
func (r *SpringCSRFDisabledExt) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *SpringCSRFDisabledExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reSpringExtCsrfDisable.FindString(line); m != "" {
			matched = m
		} else if m := reSpringExtCsrfCustomizer.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			confidence := "high"
			// Check for REST/API/stateless context
			lower := strings.ToLower(ctx.Content)
			if strings.Contains(lower, "stateless") || strings.Contains(lower, "bearer") || strings.Contains(lower, "jwt") {
				confidence = "medium"
			}
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring Security CSRF protection disabled",
				Description:   "CSRF protection is explicitly disabled in the Spring Security configuration. This makes session-based web applications vulnerable to Cross-Site Request Forgery attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Keep CSRF enabled for session-based web apps. For stateless REST APIs using Bearer/JWT tokens, disabling CSRF is acceptable. Consider using CsrfTokenRequestAttributeHandler for SPA support.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"framework", "spring", "csrf", "security-config"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SPRING-014: DevTools in production
// ---------------------------------------------------------------------------

type SpringDevToolsProd struct{}

func (r *SpringDevToolsProd) ID() string                      { return "GTSS-FW-SPRING-014" }
func (r *SpringDevToolsProd) Name() string                    { return "SpringDevToolsProd" }
func (r *SpringDevToolsProd) DefaultSeverity() rules.Severity { return rules.High }
func (r *SpringDevToolsProd) Description() string {
	return "Detects Spring Boot DevTools dependency or configuration which should not be present in production builds."
}
func (r *SpringDevToolsProd) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangAny}
}

func (r *SpringDevToolsProd) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "<!--") {
			continue
		}
		if reSpringExtDevToolsDep.MatchString(line) {
			// Skip if scope is limited to development
			if strings.Contains(line, "<scope>") || strings.Contains(line, "developmentOnly") || strings.Contains(line, "compileOnly") {
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
				Title:         "Spring Boot DevTools included without development scope",
				Description:   "spring-boot-devtools is included without a development-only scope. DevTools enables automatic restarts, remote debugging, and H2 console access. If included in production, it creates a significant attack surface.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add <scope>runtime</scope> and <optional>true</optional> in Maven, or use developmentOnly in Gradle: developmentOnly 'org.springframework.boot:spring-boot-devtools'.",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "spring", "devtools", "misconfiguration"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SPRING-015: @ResponseBody with unescaped user data
// ---------------------------------------------------------------------------

type SpringResponseBodyXSS struct{}

func (r *SpringResponseBodyXSS) ID() string                      { return "GTSS-FW-SPRING-015" }
func (r *SpringResponseBodyXSS) Name() string                    { return "SpringResponseBodyXSS" }
func (r *SpringResponseBodyXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *SpringResponseBodyXSS) Description() string {
	return "Detects Spring @ResponseBody methods that return user input directly, which can lead to reflected XSS when content type is HTML."
}
func (r *SpringResponseBodyXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *SpringResponseBodyXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	hasResponseBody := reSpringExtResponseBody.MatchString(ctx.Content) || strings.Contains(ctx.Content, "@RestController")
	if !hasResponseBody {
		return nil
	}
	hasHTMLProduces := reSpringExtProducesHTML.MatchString(ctx.Content)
	if !hasHTMLProduces {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reSpringExtReturnUserInput.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring @ResponseBody returns user input as HTML (reflected XSS)",
				Description:   "A @ResponseBody or @RestController method returns user input directly with an HTML content type. This reflects user-controlled data in the response, enabling XSS attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Return JSON instead of HTML for API responses. If HTML is needed, encode the output with HtmlUtils.htmlEscape() or use a template engine. Set Content-Type to application/json.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "spring", "xss", "response-body"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SPRING-016: Profile-specific secrets in application.yml
// ---------------------------------------------------------------------------

type SpringYmlSecrets struct{}

func (r *SpringYmlSecrets) ID() string                      { return "GTSS-FW-SPRING-016" }
func (r *SpringYmlSecrets) Name() string                    { return "SpringYmlSecrets" }
func (r *SpringYmlSecrets) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SpringYmlSecrets) Description() string {
	return "Detects hardcoded secrets (passwords, API keys, tokens) in Spring application.yml or application.properties files."
}
func (r *SpringYmlSecrets) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangYAML, rules.LangAny}
}

func (r *SpringYmlSecrets) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check configuration files
	lower := strings.ToLower(ctx.FilePath)
	if !strings.Contains(lower, "application") && !strings.Contains(lower, "bootstrap") {
		return nil
	}
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".properties") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		if m := reSpringExtSecretInYml.FindString(line); m != "" {
			// Skip if it references environment variables
			if strings.Contains(line, "${") || strings.Contains(line, "ENC(") {
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
				Title:         "Hardcoded secret in Spring configuration file",
				Description:   "A sensitive value (password, API key, token, etc.) appears to be hardcoded in a Spring configuration file. These values are committed to source control and exposed in build artifacts.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use environment variables: ${DB_PASSWORD} or Spring Cloud Config/Vault for secret management. For Jasypt encryption, use ENC(encryptedValue).",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "spring", "secrets", "configuration"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SPRING-017: OAuth2 redirect_uri not restricted
// ---------------------------------------------------------------------------

type SpringOAuth2Redirect struct{}

func (r *SpringOAuth2Redirect) ID() string                      { return "GTSS-FW-SPRING-017" }
func (r *SpringOAuth2Redirect) Name() string                    { return "SpringOAuth2Redirect" }
func (r *SpringOAuth2Redirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *SpringOAuth2Redirect) Description() string {
	return "Detects Spring OAuth2 configurations with unrestricted redirect_uri patterns that enable authorization code theft."
}
func (r *SpringOAuth2Redirect) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangYAML, rules.LangAny}
}

func (r *SpringOAuth2Redirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reSpringExtOAuth2Redirect.FindString(line); m != "" {
			matched = m
		} else if m := reSpringExtOAuth2Any.FindString(line); m != "" {
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
				Title:         "Spring OAuth2 redirect_uri wildcard or unrestricted",
				Description:   "The OAuth2 redirect_uri is configured with a wildcard or unrestricted pattern. An attacker can steal authorization codes by redirecting the OAuth flow to their own server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Restrict redirect_uri to exact URLs: redirect-uri: https://app.example.com/login/oauth2/code/provider. Never use wildcards in redirect URIs.",
				CWEID:         "CWE-601",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "spring", "oauth2", "open-redirect"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-SPRING-018: Method security not enabled
// ---------------------------------------------------------------------------

type SpringMethodSecMissing struct{}

func (r *SpringMethodSecMissing) ID() string                      { return "GTSS-FW-SPRING-018" }
func (r *SpringMethodSecMissing) Name() string                    { return "SpringMethodSecMissing" }
func (r *SpringMethodSecMissing) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SpringMethodSecMissing) Description() string {
	return "Detects @PreAuthorize/@Secured annotations used without @EnableGlobalMethodSecurity or @EnableMethodSecurity, which means the annotations have no effect."
}
func (r *SpringMethodSecMissing) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *SpringMethodSecMissing) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only flag if method security annotations are present but not enabled
	if !reSpringExtPreAuthorize.MatchString(ctx.Content) {
		return nil
	}
	if reSpringExtEnableMethodSec.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reSpringExtPreAuthorize.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Spring @PreAuthorize/@Secured used without @EnableMethodSecurity",
				Description:   "Method security annotations (@PreAuthorize, @Secured, @RolesAllowed) are present but @EnableGlobalMethodSecurity or @EnableMethodSecurity is not found in this file. If method security is not enabled in any configuration class, these annotations are silently ignored and provide no protection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add @EnableMethodSecurity (Spring Security 6+) or @EnableGlobalMethodSecurity(prePostEnabled = true) to a @Configuration class. Verify it is enabled project-wide.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "spring", "method-security", "authorization"},
			})
			break // One finding per file is sufficient
		}
	}
	return findings
}
