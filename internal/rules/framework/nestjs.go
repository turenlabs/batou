package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- NestJS
// ---------------------------------------------------------------------------

// BATOU-FW-NESTJS-001: Guard not applied
var reNestController = regexp.MustCompile(`@Controller\s*\(`)
var reNestUseGuards = regexp.MustCompile(`@UseGuards\s*\(`)
var reNestAuthGuard = regexp.MustCompile(`(?:AuthGuard|JwtAuthGuard|RolesGuard|CanActivate)`)

// BATOU-FW-NESTJS-002: CORS wildcard
var reNestCORSWildcard = regexp.MustCompile(`(?:enableCors|cors)\s*\(\s*\{[^}]*origin\s*:\s*(?:true|\[?\s*['"]?\*['"]?\s*\]?)`)
var reNestCORSNoArgs = regexp.MustCompile(`\.enableCors\s*\(\s*\)`)

// BATOU-FW-NESTJS-003: TypeORM raw query interpolation
var reNestTypeORMRaw = regexp.MustCompile(`(?:\.query|\.createQueryBuilder|getRepository|manager\.query)\s*\(\s*` + "`" + `[^` + "`" + `]*\$\{`)
var reNestTypeORMConcat = regexp.MustCompile(`(?:\.query|manager\.query)\s*\(\s*(?:['"][^'"]*['"]\s*\+|[a-zA-Z_]\w*\s*\+)`)

// BATOU-FW-NESTJS-004: @Body without ValidationPipe
var reNestBodyDecorator = regexp.MustCompile(`@Body\s*\(\s*\)`)
var reNestValidationPipe = regexp.MustCompile(`(?:ValidationPipe|ValidateNested|IsString|IsNumber|IsEmail|class-validator|IsNotEmpty)`)

// BATOU-FW-NESTJS-005: JWT secret in source code
var reNestJWTSecret = regexp.MustCompile(`(?:secret|secretOrKey|secretKey)\s*:\s*['"][^'"]{4,}['"]`)
var reNestJWTModule = regexp.MustCompile(`JwtModule\.register`)

// BATOU-FW-NESTJS-006: GraphQL introspection
var reNestGraphQLIntrospection = regexp.MustCompile(`introspection\s*:\s*true`)
var reNestGraphQLPlayground = regexp.MustCompile(`playground\s*:\s*true`)

// BATOU-FW-NESTJS-007: Helmet not used
var reNestHelmetImport = regexp.MustCompile(`(?:require\s*\(\s*['"]helmet['"]\s*\)|import\s+.*helmet.*from\s+['"]helmet['"])`)
var reNestAppUseHelmet = regexp.MustCompile(`app\.use\s*\(\s*helmet\s*\(`)

// BATOU-FW-NESTJS-008: Rate limiting
var reNestThrottler = regexp.MustCompile(`(?:ThrottlerModule|ThrottlerGuard|@Throttle|@SkipThrottle|rateLimit)`)

// BATOU-FW-NESTJS-009: File upload without filter
var reNestFileUpload = regexp.MustCompile(`@(?:UploadedFile|UploadedFiles)\s*\(`)
var reNestFileFilter = regexp.MustCompile(`(?:fileFilter|FileInterceptor.*\{|FilesInterceptor.*\{|ParseFilePipe|FileValidator|FileTypeValidator|MaxFileSizeValidator)`)

// BATOU-FW-NESTJS-010: Exception filter exposing internals
var reNestExceptionFilter = regexp.MustCompile(`(?:@Catch|ExceptionFilter|BaseExceptionFilter)`)
var reNestExceptionExpose = regexp.MustCompile(`(?:exception\.stack|exception\.message|error\.stack|err\.stack|\.getResponse\s*\(\s*\)\s*\.(?:json|send)\s*\(\s*(?:exception|error|err))`)

func init() {
	rules.Register(&NestJSNoGuard{})
	rules.Register(&NestJSCORSWildcard{})
	rules.Register(&NestJSRawQuery{})
	rules.Register(&NestJSBodyNoValidation{})
	rules.Register(&NestJSJWTSecret{})
	rules.Register(&NestJSGraphQLIntrospection{})
	rules.Register(&NestJSNoHelmet{})
	rules.Register(&NestJSNoRateLimit{})
	rules.Register(&NestJSFileUpload{})
	rules.Register(&NestJSExceptionExpose{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-001: Guard not applied to controller
// ---------------------------------------------------------------------------

type NestJSNoGuard struct{}

func (r *NestJSNoGuard) ID() string                      { return "BATOU-FW-NESTJS-001" }
func (r *NestJSNoGuard) Name() string                    { return "NestJSNoGuard" }
func (r *NestJSNoGuard) DefaultSeverity() rules.Severity { return rules.High }
func (r *NestJSNoGuard) Description() string {
	return "Detects NestJS controllers without authentication guards applied."
}
func (r *NestJSNoGuard) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSNoGuard) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reNestController.MatchString(ctx.Content) {
		return nil
	}
	if reNestUseGuards.MatchString(ctx.Content) && reNestAuthGuard.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reNestController.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "NestJS controller without authentication guard",
				Description:   "This NestJS controller does not have @UseGuards(AuthGuard) applied at the controller or method level. Without a guard, all routes in this controller are accessible without authentication.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Apply an authentication guard: @UseGuards(JwtAuthGuard) at the controller level, or apply guards to individual routes that need protection. Use @Public() decorator to explicitly mark public routes.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nestjs", "authentication"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-002: CORS wildcard
// ---------------------------------------------------------------------------

type NestJSCORSWildcard struct{}

func (r *NestJSCORSWildcard) ID() string                      { return "BATOU-FW-NESTJS-002" }
func (r *NestJSCORSWildcard) Name() string                    { return "NestJSCORSWildcard" }
func (r *NestJSCORSWildcard) DefaultSeverity() rules.Severity { return rules.High }
func (r *NestJSCORSWildcard) Description() string {
	return "Detects NestJS CORS configuration with wildcard or overly permissive origin settings."
}
func (r *NestJSCORSWildcard) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSCORSWildcard) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reNestCORSWildcard.FindString(line); m != "" {
			matched = m
		} else if m := reNestCORSNoArgs.FindString(line); m != "" {
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
				Title:         "NestJS CORS allows all origins",
				Description:   "The NestJS CORS configuration allows requests from any origin via wildcard or enableCors() without origin restrictions. This permits untrusted websites to make cross-origin requests to your API.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Configure specific origins: app.enableCors({ origin: ['https://example.com'] }). Never use wildcard origins in production.",
				CWEID:         "CWE-346",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nestjs", "cors"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-003: TypeORM raw query with interpolation
// ---------------------------------------------------------------------------

type NestJSRawQuery struct{}

func (r *NestJSRawQuery) ID() string                      { return "BATOU-FW-NESTJS-003" }
func (r *NestJSRawQuery) Name() string                    { return "NestJSRawQuery" }
func (r *NestJSRawQuery) DefaultSeverity() rules.Severity { return rules.High }
func (r *NestJSRawQuery) Description() string {
	return "Detects NestJS/TypeORM raw queries with template literal interpolation or string concatenation."
}
func (r *NestJSRawQuery) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSRawQuery) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reNestTypeORMRaw.FindString(line); m != "" {
			matched = m
		} else if m := reNestTypeORMConcat.FindString(line); m != "" {
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
				Title:         "NestJS TypeORM raw query with interpolation (SQL injection)",
				Description:   "A TypeORM raw query or query builder uses template literal interpolation (${}) or string concatenation (+) to build SQL. This allows SQL injection if the interpolated values come from user input.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use parameterized queries: manager.query('SELECT * FROM users WHERE id = $1', [userId]). Use QueryBuilder with .where('user.id = :id', { id: userId }).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nestjs", "sql-injection", "typeorm"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-004: @Body without ValidationPipe
// ---------------------------------------------------------------------------

type NestJSBodyNoValidation struct{}

func (r *NestJSBodyNoValidation) ID() string                      { return "BATOU-FW-NESTJS-004" }
func (r *NestJSBodyNoValidation) Name() string                    { return "NestJSBodyNoValidation" }
func (r *NestJSBodyNoValidation) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NestJSBodyNoValidation) Description() string {
	return "Detects NestJS @Body() usage without class-validator/ValidationPipe integration."
}
func (r *NestJSBodyNoValidation) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSBodyNoValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reNestBodyDecorator.MatchString(ctx.Content) {
		return nil
	}
	if reNestValidationPipe.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reNestBodyDecorator.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "NestJS @Body() without validation",
				Description:   "@Body() is used to bind request data without class-validator decorators or ValidationPipe. Without validation, any data structure is accepted, allowing malformed or malicious input.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Create a DTO class with class-validator decorators (@IsString, @IsEmail, @IsNotEmpty) and use ValidationPipe: @Body(new ValidationPipe()) or enable it globally in main.ts.",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nestjs", "validation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-005: JWT secret in source code
// ---------------------------------------------------------------------------

type NestJSJWTSecret struct{}

func (r *NestJSJWTSecret) ID() string                      { return "BATOU-FW-NESTJS-005" }
func (r *NestJSJWTSecret) Name() string                    { return "NestJSJWTSecret" }
func (r *NestJSJWTSecret) DefaultSeverity() rules.Severity { return rules.High }
func (r *NestJSJWTSecret) Description() string {
	return "Detects JWT secrets hardcoded in NestJS source code."
}
func (r *NestJSJWTSecret) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSJWTSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reNestJWTSecret.FindString(line); m != "" {
			// Skip if using env variables
			if strings.Contains(line, "process.env") || strings.Contains(line, "configService") || strings.Contains(line, "ConfigService") {
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
				Title:         "NestJS JWT secret hardcoded in source code",
				Description:   "A JWT secret key is hardcoded as a string literal. Anyone with access to the source code can forge valid JWT tokens, impersonating any user and bypassing authentication.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Load JWT secrets from environment variables: secret: configService.get('JWT_SECRET') or secret: process.env.JWT_SECRET. Use a strong, randomly generated secret of at least 256 bits.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nestjs", "jwt", "hardcoded-secret"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-006: GraphQL introspection in production
// ---------------------------------------------------------------------------

type NestJSGraphQLIntrospection struct{}

func (r *NestJSGraphQLIntrospection) ID() string                      { return "BATOU-FW-NESTJS-006" }
func (r *NestJSGraphQLIntrospection) Name() string                    { return "NestJSGraphQLIntrospection" }
func (r *NestJSGraphQLIntrospection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NestJSGraphQLIntrospection) Description() string {
	return "Detects NestJS GraphQL with introspection or playground enabled unconditionally."
}
func (r *NestJSGraphQLIntrospection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSGraphQLIntrospection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		// Skip if behind environment check
		if strings.Contains(line, "NODE_ENV") || strings.Contains(line, "process.env") {
			continue
		}

		var matched string
		var title string
		if m := reNestGraphQLIntrospection.FindString(line); m != "" {
			matched = m
			title = "NestJS GraphQL introspection enabled"
		} else if m := reNestGraphQLPlayground.FindString(line); m != "" {
			matched = m
			title = "NestJS GraphQL playground enabled"
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
				Description:   "GraphQL introspection or playground is unconditionally enabled. Introspection exposes the entire API schema including types, fields, and queries, which helps attackers understand the API surface. Playground provides an interactive query interface.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Disable introspection and playground in production: introspection: process.env.NODE_ENV !== 'production', playground: process.env.NODE_ENV !== 'production'.",
				CWEID:         "CWE-200",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nestjs", "graphql", "information-disclosure"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-007: Helmet not used
// ---------------------------------------------------------------------------

type NestJSNoHelmet struct{}

func (r *NestJSNoHelmet) ID() string                      { return "BATOU-FW-NESTJS-007" }
func (r *NestJSNoHelmet) Name() string                    { return "NestJSNoHelmet" }
func (r *NestJSNoHelmet) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NestJSNoHelmet) Description() string {
	return "Detects NestJS application bootstrap without helmet middleware for security headers."
}
func (r *NestJSNoHelmet) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSNoHelmet) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check main.ts / bootstrap files
	if !strings.Contains(ctx.Content, "NestFactory.create") {
		return nil
	}
	if reNestHelmetImport.MatchString(ctx.Content) || reNestAppUseHelmet.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if strings.Contains(line, "NestFactory.create") {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "NestJS application without helmet security headers",
				Description:   "The NestJS bootstrap file does not use helmet middleware. Helmet sets important security headers including Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and X-Frame-Options.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Install helmet (npm install helmet) and add app.use(helmet()) in your bootstrap function before app.listen().",
				CWEID:         "CWE-693",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nestjs", "helmet", "security-headers"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-008: Rate limiting not configured
// ---------------------------------------------------------------------------

type NestJSNoRateLimit struct{}

func (r *NestJSNoRateLimit) ID() string                      { return "BATOU-FW-NESTJS-008" }
func (r *NestJSNoRateLimit) Name() string                    { return "NestJSNoRateLimit" }
func (r *NestJSNoRateLimit) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NestJSNoRateLimit) Description() string {
	return "Detects NestJS application modules without rate limiting configuration."
}
func (r *NestJSNoRateLimit) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSNoRateLimit) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only check app module files
	if !strings.Contains(ctx.Content, "@Module") {
		return nil
	}
	if !strings.Contains(ctx.Content, "NestFactory") && !strings.Contains(ctx.FilePath, "app.module") {
		return nil
	}
	if reNestThrottler.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if strings.Contains(line, "@Module") {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "NestJS application without rate limiting",
				Description:   "The NestJS application module does not configure rate limiting. Without rate limiting, the API is vulnerable to brute force attacks, credential stuffing, and denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Install @nestjs/throttler and configure it: ThrottlerModule.forRoot([{ ttl: 60000, limit: 10 }]). Apply ThrottlerGuard globally or to sensitive routes.",
				CWEID:         "CWE-770",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nestjs", "rate-limiting"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-009: File upload without filter
// ---------------------------------------------------------------------------

type NestJSFileUpload struct{}

func (r *NestJSFileUpload) ID() string                      { return "BATOU-FW-NESTJS-009" }
func (r *NestJSFileUpload) Name() string                    { return "NestJSFileUpload" }
func (r *NestJSFileUpload) DefaultSeverity() rules.Severity { return rules.High }
func (r *NestJSFileUpload) Description() string {
	return "Detects NestJS file upload endpoints without file type or size validation filters."
}
func (r *NestJSFileUpload) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSFileUpload) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reNestFileUpload.MatchString(ctx.Content) {
		return nil
	}
	if reNestFileFilter.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if reNestFileUpload.MatchString(line) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "NestJS file upload without validation filter",
				Description:   "@UploadedFile() is used without a file filter for type or size validation. Without validation, users can upload malicious files (executables, web shells) or oversized files that cause denial of service.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use ParseFilePipe with validators: @UploadedFile(new ParseFilePipe({ validators: [new FileTypeValidator({ fileType: 'image/png' }), new MaxFileSizeValidator({ maxSize: 1024*1024 })] })). Or add fileFilter to FileInterceptor options.",
				CWEID:         "CWE-434",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "nestjs", "file-upload"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NESTJS-010: Exception filter exposing internal errors
// ---------------------------------------------------------------------------

type NestJSExceptionExpose struct{}

func (r *NestJSExceptionExpose) ID() string                      { return "BATOU-FW-NESTJS-010" }
func (r *NestJSExceptionExpose) Name() string                    { return "NestJSExceptionExpose" }
func (r *NestJSExceptionExpose) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NestJSExceptionExpose) Description() string {
	return "Detects NestJS exception filters that expose internal error details to clients."
}
func (r *NestJSExceptionExpose) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NestJSExceptionExpose) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reNestExceptionFilter.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}
		if m := reNestExceptionExpose.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "NestJS exception filter exposes internal error details",
				Description:   "A NestJS exception filter sends internal error details (stack traces, error messages) directly in the response. This reveals internal implementation details that help attackers understand the application structure.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Return generic error messages to clients. Log full errors server-side: response.status(status).json({ statusCode: status, message: 'Internal server error' }). Only include details in development.",
				CWEID:         "CWE-209",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "nestjs", "error-handling", "information-disclosure"},
			})
		}
	}
	return findings
}
