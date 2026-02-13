package framework

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// --- Compiled patterns ---

// GTSS-FW-SPRING-001: CSRF Disabled
var (
	// Legacy: http.csrf().disable()
	csrfDisableLegacy = regexp.MustCompile(`\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(`)
	// Lambda DSL: csrf(csrf -> csrf.disable()) or csrf(AbstractHttpConfigurer::disable)
	csrfDisableLambda = regexp.MustCompile(`\.csrf\s*\(\s*(?:\w+\s*->\s*\w+\s*\.\s*disable|AbstractHttpConfigurer\s*::\s*disable)\s*`)
	// Kotlin-style: csrf { disable() }
	csrfDisableKotlin = regexp.MustCompile(`\.csrf\s*\{[^}]*disable\s*\(`)
)

// GTSS-FW-SPRING-002: Overly Permissive Access (permitAll on wide paths)
var (
	// antMatchers("/**").permitAll() or requestMatchers("/**").permitAll()
	permitAllWildcard = regexp.MustCompile(`(?:antMatchers|requestMatchers|mvcMatchers)\s*\(\s*"\/\*\*"\s*\)\s*\.\s*permitAll\s*\(`)
	// authorize(requests -> requests.anyRequest().permitAll())
	anyRequestPermitAll = regexp.MustCompile(`\.anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(`)
)

// GTSS-FW-SPRING-003: Insecure CORS Configuration
var (
	// setAllowedOrigins(Arrays.asList("*")) or addAllowedOrigin("*")
	corsAllowAllOrigins    = regexp.MustCompile(`(?:setAllowedOrigins|addAllowedOrigin)\s*\([^)]*"\s*\*\s*"`)
	corsAllowCredentials   = regexp.MustCompile(`setAllowCredentials\s*\(\s*true\s*\)`)
	// @CrossOrigin(origins = "*") or @CrossOrigin without restrictions
	crossOriginWildcard    = regexp.MustCompile(`@CrossOrigin\s*\(\s*(?:origins\s*=\s*(?:"\s*\*\s*"|\{[^}]*"\s*\*\s*"[^}]*\}))?[^)]*\)`)
	crossOriginNoArgs      = regexp.MustCompile(`@CrossOrigin\s*$`)
)

// GTSS-FW-SPRING-004: Actuator Exposure
var (
	// permitAll() on actuator paths
	actuatorPermitAll = regexp.MustCompile(`(?:antMatchers|requestMatchers|mvcMatchers)\s*\([^)]*(?:\/actuator|actuator)[^)]*\)\s*\.\s*permitAll\s*\(`)
	// management.endpoints.web.exposure.include=* in properties/yaml
	actuatorExposeAll = regexp.MustCompile(`management\.endpoints\.web\.exposure\.include\s*[=:]\s*\*`)
	// management.security.enabled=false
	actuatorSecurityOff = regexp.MustCompile(`management\.security\.enabled\s*[=:]\s*false`)
)

// GTSS-FW-SPRING-005: Native Query Injection
var (
	// @Query with nativeQuery=true and string concat/interpolation
	nativeQueryAnnotation = regexp.MustCompile(`@Query\s*\([^)]*nativeQuery\s*=\s*true`)
	// String concat in @Query value
	queryStringConcat = regexp.MustCompile(`@Query\s*\(\s*(?:value\s*=\s*)?"[^"]*"\s*\+`)
	queryStringConcatReverse = regexp.MustCompile(`\+\s*"[^"]*"\s*[,)].*nativeQuery\s*=\s*true`)
	// EntityManager.createNativeQuery with concat
	emNativeQueryConcat = regexp.MustCompile(`(?:entityManager|em)\s*\.\s*createNativeQuery\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+)`)
	// createQuery with concat (HQL injection)
	emCreateQueryConcat = regexp.MustCompile(`(?:entityManager|em|session)\s*\.\s*create(?:Query|SQLQuery)\s*\(\s*(?:"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+)`)
)

// GTSS-FW-SPRING-006: Mass Assignment via @ModelAttribute
var (
	modelAttributeAnnotation = regexp.MustCompile(`@ModelAttribute`)
	initBinderAnnotation     = regexp.MustCompile(`@InitBinder`)
	// WebDataBinder.setAllowedFields or setDisallowedFields
	binderFieldRestriction = regexp.MustCompile(`(?:setAllowedFields|setDisallowedFields)\s*\(`)
)

// GTSS-FW-SPRING-007: Insecure Cookie Configuration
var (
	cookieHttpOnlyFalse = regexp.MustCompile(`\.setHttpOnly\s*\(\s*false\s*\)`)
	cookieSecureFalse   = regexp.MustCompile(`\.setSecure\s*\(\s*false\s*\)`)
	// new Cookie(...) without subsequent setHttpOnly/setSecure
	newCookie = regexp.MustCompile(`new\s+Cookie\s*\(`)
)

// GTSS-FW-SPRING-008: Frame Options Disabled (clickjacking)
var (
	frameOptionsDisable  = regexp.MustCompile(`\.frameOptions\s*\(\s*\)\s*\.\s*disable\s*\(`)
	frameOptionsLambda   = regexp.MustCompile(`\.frameOptions\s*\(\s*\w+\s*->\s*\w+\s*\.\s*disable`)
	headersDisable       = regexp.MustCompile(`\.headers\s*\(\s*\)\s*\.\s*disable\s*\(`)
	headersLambdaDisable = regexp.MustCompile(`\.headers\s*\(\s*\w+\s*->\s*\w+\s*\.\s*disable`)
)

// GTSS-FW-SPRING-009: Request Dispatcher Forward with User Input
var (
	dispatcherForward = regexp.MustCompile(`getRequestDispatcher\s*\(\s*[a-zA-Z_]\w*\s*\)\s*\.\s*forward\s*\(`)
	// ModelAndView with user input in view name
	modelAndViewUserInput = regexp.MustCompile(`new\s+ModelAndView\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
)

// GTSS-FW-SPRING-010: Session Fixation
var (
	sessionFixationNone = regexp.MustCompile(`\.sessionFixation\s*\(\s*\)\s*\.\s*none\s*\(`)
	sessionFixationLambda = regexp.MustCompile(`\.sessionFixation\s*\(\s*\w+\s*->\s*\w+\s*\.\s*none`)
)

func init() {
	rules.Register(&CSRFDisabled{})
	rules.Register(&OverlyPermissiveAccess{})
	rules.Register(&InsecureCORS{})
	rules.Register(&ActuatorExposure{})
	rules.Register(&NativeQueryInjection{})
	rules.Register(&MassAssignment{})
	rules.Register(&InsecureCookie{})
	rules.Register(&FrameOptionsDisabled{})
	rules.Register(&DispatcherForward{})
	rules.Register(&SessionFixation{})
}

// --- GTSS-FW-SPRING-001: CSRF Disabled ---

type CSRFDisabled struct{}

func (r *CSRFDisabled) ID() string                      { return "GTSS-FW-SPRING-001" }
func (r *CSRFDisabled) Name() string                    { return "CSRFDisabled" }
func (r *CSRFDisabled) Description() string             { return "Detects Spring Security configurations that disable CSRF protection." }
func (r *CSRFDisabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSRFDisabled) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *CSRFDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		if loc := csrfDisableLegacy.FindString(line); loc != "" {
			matched = loc
		} else if loc := csrfDisableLambda.FindString(line); loc != "" {
			matched = loc
		} else if loc := csrfDisableKotlin.FindString(line); loc != "" {
			matched = loc
		}

		if matched != "" {
			// Check if there's a comment justifying it (REST API, stateless)
			confidence := "high"
			context := surroundingContext(lines, i, 5)
			if containsAny(context, "stateless", "REST", "restful", "api-only", "token-based", "bearer", "JWT") {
				confidence = "medium"
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "CSRF protection disabled in Spring Security",
				Description:   "CSRF protection is explicitly disabled. This makes the application vulnerable to Cross-Site Request Forgery attacks where attackers can trick authenticated users into performing unintended actions.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Keep CSRF protection enabled for session-based web applications. If this is a stateless REST API using token auth (Bearer/JWT), disabling CSRF may be acceptable but should be limited to specific paths.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"spring", "csrf", "security-config"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-002: Overly Permissive Access ---

type OverlyPermissiveAccess struct{}

func (r *OverlyPermissiveAccess) ID() string                      { return "GTSS-FW-SPRING-002" }
func (r *OverlyPermissiveAccess) Name() string                    { return "OverlyPermissiveAccess" }
func (r *OverlyPermissiveAccess) Description() string             { return "Detects overly broad permitAll() rules that bypass authentication on all endpoints." }
func (r *OverlyPermissiveAccess) DefaultSeverity() rules.Severity { return rules.High }
func (r *OverlyPermissiveAccess) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *OverlyPermissiveAccess) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		var title string

		if loc := permitAllWildcard.FindString(line); loc != "" {
			matched = loc
			title = "permitAll() on wildcard path '/**' bypasses all authentication"
		} else if loc := anyRequestPermitAll.FindString(line); loc != "" {
			matched = loc
			title = "anyRequest().permitAll() disables authentication for all endpoints"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "An overly broad access rule allows unauthenticated access to all endpoints. This effectively disables Spring Security's authentication for the entire application.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Restrict permitAll() to specific public paths (e.g., /login, /public/**). Use authenticated() or hasRole() for protected endpoints. Apply the principle of least privilege.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "authorization", "security-config"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-003: Insecure CORS Configuration ---

type InsecureCORS struct{}

func (r *InsecureCORS) ID() string                      { return "GTSS-FW-SPRING-003" }
func (r *InsecureCORS) Name() string                    { return "InsecureCORS" }
func (r *InsecureCORS) Description() string             { return "Detects insecure CORS configurations that allow all origins with credentials." }
func (r *InsecureCORS) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureCORS) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *InsecureCORS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// File-level checks for dangerous CORS combos
	hasAllowAllOrigins := corsAllowAllOrigins.MatchString(ctx.Content)
	hasAllowCredentials := corsAllowCredentials.MatchString(ctx.Content)

	if hasAllowAllOrigins && hasAllowCredentials {
		// Find the line with allow-all origins
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if loc := corsAllowAllOrigins.FindString(line); loc != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.High,
					SeverityLabel: rules.High.String(),
					Title:         "CORS allows all origins with credentials enabled",
					Description:   "The CORS configuration allows any origin ('*') while also enabling credentials. This combination allows any website to make authenticated cross-origin requests, potentially stealing user data or performing unauthorized actions.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(loc, 120),
					Suggestion:    "Specify an explicit list of trusted origins instead of '*'. If credentials are needed, each origin must be explicitly whitelisted. Use setAllowedOriginPatterns() for dynamic patterns.",
					CWEID:         "CWE-942",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"spring", "cors", "security-config"},
				})
				break
			}
		}
	} else if hasAllowAllOrigins {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if isComment(trimmed) {
				continue
			}
			if loc := corsAllowAllOrigins.FindString(line); loc != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Medium,
					SeverityLabel: rules.Medium.String(),
					Title:         "CORS allows all origins",
					Description:   "The CORS configuration permits requests from any origin. While less dangerous without credentials, this still expands the attack surface unnecessarily.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(loc, 120),
					Suggestion:    "Specify an explicit list of trusted origins instead of allowing all origins.",
					CWEID:         "CWE-942",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"spring", "cors", "security-config"},
				})
				break
			}
		}
	}

	// Check for @CrossOrigin without origin restrictions
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if crossOriginNoArgs.MatchString(trimmed) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Medium,
				SeverityLabel: rules.Medium.String(),
				Title:         "@CrossOrigin without origin restrictions",
				Description:   "@CrossOrigin with no arguments defaults to allowing all origins. This permits any website to make cross-origin requests to this endpoint.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Specify allowed origins explicitly: @CrossOrigin(origins = \"https://trusted-domain.com\").",
				CWEID:         "CWE-942",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"spring", "cors", "annotation"},
			})
		} else if strings.Contains(trimmed, "@CrossOrigin") && strings.Contains(line, "\"*\"") {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Medium,
				SeverityLabel: rules.Medium.String(),
				Title:         "@CrossOrigin allows all origins via wildcard",
				Description:   "@CrossOrigin is configured with origins=\"*\", allowing any website to make cross-origin requests to this endpoint.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Replace the wildcard with specific trusted origins: @CrossOrigin(origins = \"https://trusted-domain.com\").",
				CWEID:         "CWE-942",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "cors", "annotation"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-004: Actuator Exposure ---

type ActuatorExposure struct{}

func (r *ActuatorExposure) ID() string                      { return "GTSS-FW-SPRING-004" }
func (r *ActuatorExposure) Name() string                    { return "ActuatorExposure" }
func (r *ActuatorExposure) Description() string             { return "Detects exposed Spring Boot Actuator endpoints without authentication." }
func (r *ActuatorExposure) DefaultSeverity() rules.Severity { return rules.High }
func (r *ActuatorExposure) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangYAML, rules.LangAny}
}

func (r *ActuatorExposure) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if loc := actuatorPermitAll.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Actuator endpoints accessible without authentication",
				Description:   "Spring Boot Actuator endpoints are configured with permitAll(), exposing sensitive operational data (health, env, beans, heap dumps) to unauthenticated users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Restrict actuator endpoints to authenticated users with an admin role. Use management.endpoints.web.exposure.include to limit exposed endpoints to only health and info.",
				CWEID:         "CWE-200",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "actuator", "information-disclosure"},
			})
		}

		if loc := actuatorExposeAll.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "All actuator endpoints exposed via configuration",
				Description:   "management.endpoints.web.exposure.include=* exposes all actuator endpoints including env (environment variables/secrets), heapdump (memory contents), and shutdown.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Expose only necessary endpoints: management.endpoints.web.exposure.include=health,info. Never expose env, heapdump, or shutdown in production.",
				CWEID:         "CWE-200",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "actuator", "configuration"},
			})
		}

		if loc := actuatorSecurityOff.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Actuator security explicitly disabled",
				Description:   "management.security.enabled=false disables security for all actuator endpoints, exposing sensitive operational information to anyone.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Remove this property. Actuator endpoints should always require authentication in production environments.",
				CWEID:         "CWE-200",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "actuator", "configuration"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-005: Native Query Injection ---

type NativeQueryInjection struct{}

func (r *NativeQueryInjection) ID() string                      { return "GTSS-FW-SPRING-005" }
func (r *NativeQueryInjection) Name() string                    { return "NativeQueryInjection" }
func (r *NativeQueryInjection) Description() string             { return "Detects SQL injection via native JPA queries with string concatenation." }
func (r *NativeQueryInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *NativeQueryInjection) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *NativeQueryInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		// @Query with string concat and nativeQuery=true
		if nativeQueryAnnotation.MatchString(line) && (queryStringConcat.MatchString(line) || queryStringConcatReverse.MatchString(line)) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "SQL injection in native JPA query with string concatenation",
				Description:   "A @Query annotation with nativeQuery=true uses string concatenation to build the SQL query. This is vulnerable to SQL injection attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Use parameterized queries with named parameters (:paramName) or indexed parameters (?1). Never concatenate user input into native queries.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "jpa", "sql-injection", "native-query"},
			})
			continue
		}

		// Also check multi-line: @Query on one line, concat on next
		if nativeQueryAnnotation.MatchString(line) && i+1 < len(lines) {
			nextLine := lines[i+1]
			if strings.Contains(nextLine, "+") && (strings.Contains(nextLine, "\"") || strings.Contains(line, "+")) {
				// Look for string concatenation pattern in the query value
				combined := line + " " + nextLine
				if strings.Contains(combined, "\"") && strings.Contains(combined, "+") {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      rules.Critical,
						SeverityLabel: rules.Critical.String(),
						Title:         "SQL injection in native JPA query with string concatenation",
						Description:   "A @Query annotation with nativeQuery=true uses string concatenation. This is vulnerable to SQL injection attacks.",
						FilePath:      ctx.FilePath,
						LineNumber:    i + 1,
						MatchedText:   truncate(trimmed, 120),
						Suggestion:    "Use parameterized queries with named parameters (:paramName) or indexed parameters (?1). Never concatenate user input into native queries.",
						CWEID:         "CWE-89",
						OWASPCategory: "A03:2021-Injection",
						Language:      ctx.Language,
						Confidence:    "high",
						Tags:          []string{"spring", "jpa", "sql-injection", "native-query"},
					})
					continue
				}
			}
		}

		// EntityManager.createNativeQuery with concatenation
		if loc := emNativeQueryConcat.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "SQL injection via EntityManager.createNativeQuery with concatenation",
				Description:   "EntityManager.createNativeQuery() is called with string concatenation, creating a SQL injection vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use parameterized queries: em.createNativeQuery(\"SELECT ... WHERE id = ?1\").setParameter(1, value). Never concatenate user input.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "jpa", "sql-injection", "entity-manager"},
			})
		}

		// EntityManager.createQuery (HQL injection)
		if loc := emCreateQueryConcat.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "HQL/JPQL injection via EntityManager.createQuery with concatenation",
				Description:   "EntityManager.createQuery() is called with string concatenation, creating an HQL/JPQL injection vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use parameterized JPQL queries: em.createQuery(\"SELECT u FROM User u WHERE u.name = :name\").setParameter(\"name\", value).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "jpa", "hql-injection", "entity-manager"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-006: Mass Assignment ---

type MassAssignment struct{}

func (r *MassAssignment) ID() string                      { return "GTSS-FW-SPRING-006" }
func (r *MassAssignment) Name() string                    { return "MassAssignment" }
func (r *MassAssignment) Description() string             { return "Detects @ModelAttribute usage without field binding restrictions." }
func (r *MassAssignment) DefaultSeverity() rules.Severity { return rules.High }
func (r *MassAssignment) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *MassAssignment) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag if @ModelAttribute exists but no @InitBinder with field restrictions
	if !modelAttributeAnnotation.MatchString(ctx.Content) {
		return nil
	}

	hasFieldRestriction := initBinderAnnotation.MatchString(ctx.Content) &&
		binderFieldRestriction.MatchString(ctx.Content)

	if hasFieldRestriction {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if modelAttributeAnnotation.MatchString(line) {
			// Only flag @ModelAttribute on method parameters (in controller methods)
			if strings.Contains(line, "(") || (i+1 < len(lines) && strings.Contains(lines[i+1], "(")) {
				continue // Likely a method-level annotation for model population
			}

			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "@ModelAttribute without field binding restrictions (mass assignment)",
				Description:   "@ModelAttribute binds all HTTP request parameters to object fields. Without @InitBinder restricting allowed fields, an attacker can set unintended fields (e.g., isAdmin, role, price).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(trimmed, 120),
				Suggestion:    "Add an @InitBinder method with binder.setAllowedFields() or binder.setDisallowedFields() to restrict which fields can be bound. Alternatively, use a dedicated DTO that only contains the fields you want to accept.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"spring", "mass-assignment", "model-binding"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-007: Insecure Cookie Configuration ---

type InsecureCookie struct{}

func (r *InsecureCookie) ID() string                      { return "GTSS-FW-SPRING-007" }
func (r *InsecureCookie) Name() string                    { return "InsecureCookie" }
func (r *InsecureCookie) Description() string             { return "Detects cookies created without HttpOnly or Secure flags." }
func (r *InsecureCookie) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureCookie) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *InsecureCookie) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if loc := cookieHttpOnlyFalse.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Cookie HttpOnly flag explicitly disabled",
				Description:   "setHttpOnly(false) allows JavaScript to access this cookie, making it vulnerable to XSS-based cookie theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Set cookie.setHttpOnly(true) to prevent JavaScript access. Only disable HttpOnly if the cookie must be accessible to client-side scripts and contains no sensitive data.",
				CWEID:         "CWE-1004",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "cookie", "httponly"},
			})
		}

		if loc := cookieSecureFalse.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Cookie Secure flag explicitly disabled",
				Description:   "setSecure(false) allows the cookie to be sent over unencrypted HTTP connections, exposing it to network interception.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Set cookie.setSecure(true) to ensure the cookie is only sent over HTTPS connections.",
				CWEID:         "CWE-614",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "cookie", "secure-flag"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-008: Frame Options Disabled ---

type FrameOptionsDisabled struct{}

func (r *FrameOptionsDisabled) ID() string                      { return "GTSS-FW-SPRING-008" }
func (r *FrameOptionsDisabled) Name() string                    { return "FrameOptionsDisabled" }
func (r *FrameOptionsDisabled) Description() string             { return "Detects disabled X-Frame-Options header allowing clickjacking attacks." }
func (r *FrameOptionsDisabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FrameOptionsDisabled) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *FrameOptionsDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		if loc := frameOptionsDisable.FindString(line); loc != "" {
			matched = loc
		} else if loc := frameOptionsLambda.FindString(line); loc != "" {
			matched = loc
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "X-Frame-Options disabled (clickjacking risk)",
				Description:   "Frame options are disabled in Spring Security, removing protection against clickjacking attacks where the application can be embedded in a malicious iframe.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use .frameOptions().sameOrigin() instead of .disable() to allow framing from the same origin only. If embedding is required, use Content-Security-Policy frame-ancestors directive.",
				CWEID:         "CWE-1021",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "clickjacking", "headers"},
			})
		}

		// Also detect disabling all headers
		if loc := headersDisable.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "All security headers disabled",
				Description:   "All Spring Security HTTP headers are disabled, removing XSS protection, content type sniffing protection, clickjacking protection, and other security headers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Do not disable all headers. Configure individual headers as needed instead of disabling the entire header chain.",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "security-headers", "headers"},
			})
		} else if loc := headersLambdaDisable.FindString(line); loc != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "All security headers disabled",
				Description:   "All Spring Security HTTP headers are disabled, removing XSS protection, content type sniffing protection, clickjacking protection, and other security headers.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Do not disable all headers. Configure individual headers as needed instead of disabling the entire header chain.",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "security-headers", "headers"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-009: Dispatcher Forward with User Input ---

type DispatcherForward struct{}

func (r *DispatcherForward) ID() string                      { return "GTSS-FW-SPRING-009" }
func (r *DispatcherForward) Name() string                    { return "DispatcherForward" }
func (r *DispatcherForward) Description() string             { return "Detects request dispatcher forward and ModelAndView with user-controlled paths." }
func (r *DispatcherForward) DefaultSeverity() rules.Severity { return rules.High }
func (r *DispatcherForward) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *DispatcherForward) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasUserInput := strings.Contains(ctx.Content, "request.getParameter") ||
		strings.Contains(ctx.Content, "@RequestParam") ||
		strings.Contains(ctx.Content, "@PathVariable")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		if loc := dispatcherForward.FindString(line); loc != "" {
			confidence := "medium"
			if hasUserInput {
				confidence = "high"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Request dispatcher forward with variable path",
				Description:   "getRequestDispatcher() is called with a variable argument then forwarded. If the path is user-controlled, this can lead to unauthorized access to internal resources or path traversal.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Validate the forward path against an allowlist of permitted internal paths. Never forward to a user-supplied path directly.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"spring", "forward", "path-traversal"},
			})
		}

		if loc := modelAndViewUserInput.FindString(line); loc != "" && hasUserInput {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ModelAndView with variable view name (template injection risk)",
				Description:   "A ModelAndView is constructed with a variable view name in a controller that handles user input. If the view name is user-controlled, this could lead to server-side template injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(loc, 120),
				Suggestion:    "Use a fixed view name or validate the view name against an allowlist. Never pass user input directly as a view name.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"spring", "template-injection", "model-view"},
			})
		}
	}

	return findings
}

// --- GTSS-FW-SPRING-010: Session Fixation ---

type SessionFixation struct{}

func (r *SessionFixation) ID() string                      { return "GTSS-FW-SPRING-010" }
func (r *SessionFixation) Name() string                    { return "SessionFixation" }
func (r *SessionFixation) Description() string             { return "Detects Spring Security session fixation protection being disabled." }
func (r *SessionFixation) DefaultSeverity() rules.Severity { return rules.High }
func (r *SessionFixation) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }

func (r *SessionFixation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}

		var matched string
		if loc := sessionFixationNone.FindString(line); loc != "" {
			matched = loc
		} else if loc := sessionFixationLambda.FindString(line); loc != "" {
			matched = loc
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Session fixation protection disabled",
				Description:   "Session fixation protection is set to 'none', allowing attackers to fix a session ID before authentication and then hijack the session after the user logs in.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use .sessionFixation().migrateSession() or .newSession() instead of .none(). These create a new session (or migrate attributes) after authentication, preventing session fixation attacks.",
				CWEID:         "CWE-384",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"spring", "session", "session-fixation"},
			})
		}
	}

	return findings
}

// --- Helpers ---

func surroundingContext(lines []string, idx, radius int) string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
