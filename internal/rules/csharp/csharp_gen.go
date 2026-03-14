package csharp

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns (generated rules CS-031 through CS-040)
// ---------------------------------------------------------------------------

// CS-031: BinaryFormatter usage
var reGenBinaryFormatter = regexp.MustCompile(`new\s+BinaryFormatter\s*\(`)

// CS-032: JSON.NET TypeNameHandling unsafe
var reGenTypeNameHandling = regexp.MustCompile(`(?i)TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)`)

// CS-033: Blazor MarkupString with user input
var (
	reGenMarkupString     = regexp.MustCompile(`new\s+MarkupString\s*\(`)
	reGenMarkupStringUser = regexp.MustCompile(`(?i)(?:param|input|request|query|form|user|arg|data|body|payload)`)
)

// CS-034: EF Core FromSqlRaw injection
var (
	reGenFromSqlRawInterp  = regexp.MustCompile(`\.FromSqlRaw\s*\(\s*\$"`)
	reGenFromSqlRawConcat  = regexp.MustCompile(`\.FromSqlRaw\s*\(\s*["'][^"']*["']\s*\+`)
	reGenFromSqlRawSafe    = regexp.MustCompile(`(?i)FromSqlInterpolated|FromSqlRaw\s*\([^,]+,\s*new`)
)

// CS-035: Minimal API missing auth
var (
	reGenMapEndpoint  = regexp.MustCompile(`app\.(?:MapGet|MapPost|MapPut|MapDelete|MapPatch)\s*\(`)
	reGenRequireAuth  = regexp.MustCompile(`\.RequireAuthorization\s*\(`)
	reGenAllowAnon    = regexp.MustCompile(`\.AllowAnonymous\s*\(`)
)

// CS-036: gRPC channel without TLS
var reGenGrpcInsecure = regexp.MustCompile(`GrpcChannel\.ForAddress\s*\(\s*"http://`)

// CS-037: Missing anti-forgery on HttpPost
var (
	reGenHttpPost              = regexp.MustCompile(`\[HttpPost\]|\[HttpPut\]|\[HttpDelete\]`)
	reGenValidateAntiForgery   = regexp.MustCompile(`\[ValidateAntiForgeryToken\]|\[AutoValidateAntiforgeryToken\]|\[IgnoreAntiforgeryToken\]`)
)

// CS-038: Regex without timeout
var (
	reGenNewRegex      = regexp.MustCompile(`new\s+Regex\s*\(`)
	reGenRegexTimeout  = regexp.MustCompile(`(?i)(?:MatchTimeout|TimeSpan|RegexOptions)`)
)

// CS-039: Developer exception page in production
var (
	reGenDevExPage     = regexp.MustCompile(`\.UseDeveloperExceptionPage\s*\(`)
	reGenDevExGuard    = regexp.MustCompile(`(?i)(?:IsDevelopment|#if\s+DEBUG|\.IsEnvironment)`)
)

// CS-040: Weak password hashing
var (
	reGenWeakHash     = regexp.MustCompile(`(?:MD5|SHA1|SHA256)\.Create\s*\(`)
	reGenPasswordCtx  = regexp.MustCompile(`(?i)(?:password|passwd|pwd|credential|hash.*pass|pass.*hash)`)
)

// ---------------------------------------------------------------------------
// CS-031: BinaryFormatter Usage
// ---------------------------------------------------------------------------

type BinaryFormatterUsage struct{}

func (r *BinaryFormatterUsage) ID() string                      { return "BATOU-CS-031" }
func (r *BinaryFormatterUsage) Name() string                    { return "CSharpBinaryFormatterUsage" }
func (r *BinaryFormatterUsage) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *BinaryFormatterUsage) Description() string {
	return "Detects use of BinaryFormatter which is inherently insecure and enables remote code execution via deserialization of untrusted data."
}
func (r *BinaryFormatterUsage) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *BinaryFormatterUsage) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenBinaryFormatter.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "BinaryFormatter usage detected",
				Description:   "BinaryFormatter is inherently insecure and has been deprecated in .NET 5+. It deserializes arbitrary types, enabling remote code execution when processing untrusted data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use System.Text.Json or JsonSerializer instead of BinaryFormatter. For binary serialization, consider MessagePack or protobuf with explicit type allowlists.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "deserialization", "binary-formatter"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-032: JSON.NET TypeNameHandling Unsafe
// ---------------------------------------------------------------------------

type JSONNetTypeNameHandling struct{}

func (r *JSONNetTypeNameHandling) ID() string                      { return "BATOU-CS-032" }
func (r *JSONNetTypeNameHandling) Name() string                    { return "CSharpJSONNetTypeNameHandling" }
func (r *JSONNetTypeNameHandling) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JSONNetTypeNameHandling) Description() string {
	return "Detects unsafe JSON.NET TypeNameHandling settings (All, Auto, Objects, Arrays) which enable deserialization of arbitrary types and remote code execution."
}
func (r *JSONNetTypeNameHandling) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *JSONNetTypeNameHandling) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenTypeNameHandling.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe JSON.NET TypeNameHandling setting",
				Description:   "TypeNameHandling.All/Auto/Objects/Arrays allows deserialization of arbitrary .NET types, enabling remote code execution via crafted JSON payloads with $type metadata.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Set TypeNameHandling = TypeNameHandling.None (the default). If type discrimination is needed, use a custom SerializationBinder with a strict allowlist of permitted types.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "deserialization", "json-net"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-033: Blazor MarkupString XSS
// ---------------------------------------------------------------------------

type BlazorMarkupStringXSS struct{}

func (r *BlazorMarkupStringXSS) ID() string                      { return "BATOU-CS-033" }
func (r *BlazorMarkupStringXSS) Name() string                    { return "CSharpBlazorMarkupStringXSS" }
func (r *BlazorMarkupStringXSS) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *BlazorMarkupStringXSS) Description() string {
	return "Detects Blazor MarkupString usage with user-controlled input, which renders raw HTML and enables cross-site scripting."
}
func (r *BlazorMarkupStringXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *BlazorMarkupStringXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	hasUserInput := reGenMarkupStringUser.MatchString(ctx.Content)

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenMarkupString.MatchString(line) && hasUserInput {
			confidence := "medium"
			if reGenMarkupStringUser.MatchString(line) {
				confidence = "high"
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Blazor MarkupString with potential user input",
				Description:   "MarkupString renders raw HTML in Blazor components without encoding. If user-controlled data is included, attackers can inject malicious scripts.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Sanitize HTML input before wrapping in MarkupString. Use a library like HtmlSanitizer to strip dangerous tags/attributes, or render user content as plain text.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"csharp", "blazor", "xss", "markup-string"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-034: EF Core FromSqlRaw Injection
// ---------------------------------------------------------------------------

type EFCoreFromSqlRawInjection struct{}

func (r *EFCoreFromSqlRawInjection) ID() string                      { return "BATOU-CS-034" }
func (r *EFCoreFromSqlRawInjection) Name() string                    { return "CSharpEFCoreFromSqlRawInjection" }
func (r *EFCoreFromSqlRawInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *EFCoreFromSqlRawInjection) Description() string {
	return "Detects EF Core FromSqlRaw with string interpolation or concatenation, which bypasses parameterization and enables SQL injection."
}
func (r *EFCoreFromSqlRawInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *EFCoreFromSqlRawInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenFromSqlRawSafe.MatchString(line) {
			continue
		}
		var matched string
		if loc := reGenFromSqlRawInterp.FindString(line); loc != "" {
			matched = loc
		} else if loc := reGenFromSqlRawConcat.FindString(line); loc != "" {
			matched = loc
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "EF Core FromSqlRaw with string interpolation/concatenation",
				Description:   "FromSqlRaw does not parameterize interpolated strings. Using $\"...\" or string concatenation with FromSqlRaw passes raw SQL, enabling injection attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use FromSqlInterpolated($\"SELECT ... WHERE Id = {id}\") which auto-parameterizes, or pass parameters explicitly: FromSqlRaw(\"SELECT ... WHERE Id = {0}\", id).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "ef-core", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-035: Minimal API Missing Auth
// ---------------------------------------------------------------------------

type MinimalAPIMissingAuth struct{}

func (r *MinimalAPIMissingAuth) ID() string                      { return "BATOU-CS-035" }
func (r *MinimalAPIMissingAuth) Name() string                    { return "CSharpMinimalAPIMissingAuth" }
func (r *MinimalAPIMissingAuth) DefaultSeverity() rules.Severity { return rules.High }
func (r *MinimalAPIMissingAuth) Description() string {
	return "Detects ASP.NET Core minimal API endpoints (MapGet/MapPost/MapPut/MapDelete) without RequireAuthorization(), potentially exposing endpoints to unauthenticated access."
}
func (r *MinimalAPIMissingAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *MinimalAPIMissingAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenMapEndpoint.MatchString(line) {
			// Check current and nearby lines for auth requirements
			hasAuth := reGenRequireAuth.MatchString(line) || reGenAllowAnon.MatchString(line)
			if !hasAuth && i+1 < len(lines) {
				hasAuth = reGenRequireAuth.MatchString(lines[i+1]) || reGenAllowAnon.MatchString(lines[i+1])
			}
			if !hasAuth && i+2 < len(lines) {
				hasAuth = reGenRequireAuth.MatchString(lines[i+2]) || reGenAllowAnon.MatchString(lines[i+2])
			}
			if !hasAuth {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Minimal API endpoint without authorization",
					Description:   "This minimal API endpoint does not chain .RequireAuthorization(). Without explicit authorization, the endpoint is accessible to unauthenticated users.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Chain .RequireAuthorization() on the endpoint, or use .AllowAnonymous() if intentional. Consider applying a global authorization policy via builder.Services.AddAuthorization().",
					CWEID:         "CWE-862",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"csharp", "minimal-api", "authorization"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-036: gRPC Channel Without TLS
// ---------------------------------------------------------------------------

type GrpcChannelWithoutTLS struct{}

func (r *GrpcChannelWithoutTLS) ID() string                      { return "BATOU-CS-036" }
func (r *GrpcChannelWithoutTLS) Name() string                    { return "CSharpGrpcChannelWithoutTLS" }
func (r *GrpcChannelWithoutTLS) DefaultSeverity() rules.Severity { return rules.High }
func (r *GrpcChannelWithoutTLS) Description() string {
	return "Detects gRPC channels created with plaintext HTTP instead of HTTPS, exposing communications to eavesdropping and tampering."
}
func (r *GrpcChannelWithoutTLS) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *GrpcChannelWithoutTLS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenGrpcInsecure.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "gRPC channel without TLS",
				Description:   "GrpcChannel.ForAddress is configured with an HTTP (plaintext) URL. gRPC traffic should use HTTPS to protect data in transit from interception and modification.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use \"https://\" in the gRPC channel address. If plaintext is required for local development, guard it with an environment check.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "grpc", "cleartext"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-037: Missing Anti-Forgery Token
// ---------------------------------------------------------------------------

type MissingAntiForgeryGen struct{}

func (r *MissingAntiForgeryGen) ID() string                      { return "BATOU-CS-037" }
func (r *MissingAntiForgeryGen) Name() string                    { return "CSharpMissingAntiForgeryGen" }
func (r *MissingAntiForgeryGen) DefaultSeverity() rules.Severity { return rules.High }
func (r *MissingAntiForgeryGen) Description() string {
	return "Detects [HttpPost]/[HttpPut]/[HttpDelete] controller actions without [ValidateAntiForgeryToken], making them vulnerable to CSRF attacks."
}
func (r *MissingAntiForgeryGen) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *MissingAntiForgeryGen) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenHttpPost.MatchString(line) {
			// Check surrounding lines for ValidateAntiForgeryToken
			hasToken := false
			start := i - 3
			if start < 0 {
				start = 0
			}
			end := i + 3
			if end > len(lines) {
				end = len(lines)
			}
			for _, nearby := range lines[start:end] {
				if reGenValidateAntiForgery.MatchString(nearby) {
					hasToken = true
					break
				}
			}
			if !hasToken {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Missing anti-forgery token on state-changing action",
					Description:   "Controller action with [HttpPost]/[HttpPut]/[HttpDelete] lacks [ValidateAntiForgeryToken]. Without CSRF protection, attackers can forge requests from authenticated user sessions.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Add [ValidateAntiForgeryToken] attribute to the action, or apply [AutoValidateAntiforgeryToken] at the controller level. In .NET Core, use services.AddControllersWithViews(o => o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute())).",
					CWEID:         "CWE-352",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"csharp", "csrf", "anti-forgery"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-038: Regex Without Timeout
// ---------------------------------------------------------------------------

type RegexWithoutTimeout struct{}

func (r *RegexWithoutTimeout) ID() string                      { return "BATOU-CS-038" }
func (r *RegexWithoutTimeout) Name() string                    { return "CSharpRegexWithoutTimeout" }
func (r *RegexWithoutTimeout) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RegexWithoutTimeout) Description() string {
	return "Detects new Regex() instantiation without a MatchTimeout, which can lead to catastrophic backtracking (ReDoS) on user-supplied input."
}
func (r *RegexWithoutTimeout) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *RegexWithoutTimeout) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenNewRegex.MatchString(line) && !reGenRegexTimeout.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Regex instantiation without timeout",
				Description:   "Creating a Regex without specifying a MatchTimeout can cause catastrophic backtracking, leading to denial of service when processing attacker-controlled input.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Pass a TimeSpan timeout: new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1)). In .NET 7+, use the [GeneratedRegex] source generator for compile-time safety.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "regex", "redos"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-039: Developer Exception Page in Production
// ---------------------------------------------------------------------------

type DevExceptionPage struct{}

func (r *DevExceptionPage) ID() string                      { return "BATOU-CS-039" }
func (r *DevExceptionPage) Name() string                    { return "CSharpDevExceptionPage" }
func (r *DevExceptionPage) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DevExceptionPage) Description() string {
	return "Detects UseDeveloperExceptionPage() without an IsDevelopment or #if DEBUG guard, which can leak stack traces, source code, and environment details in production."
}
func (r *DevExceptionPage) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *DevExceptionPage) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenDevExPage.MatchString(line) {
			// Check surrounding context for development guard
			hasGuard := false
			start := i - 5
			if start < 0 {
				start = 0
			}
			end := i + 2
			if end > len(lines) {
				end = len(lines)
			}
			for _, nearby := range lines[start:end] {
				if reGenDevExGuard.MatchString(nearby) {
					hasGuard = true
					break
				}
			}
			if !hasGuard {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Developer exception page without environment check",
					Description:   "UseDeveloperExceptionPage() exposes detailed error information including stack traces and source code. Without an IsDevelopment() guard, this information leaks in production.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Wrap in an environment check: if (app.Environment.IsDevelopment()) { app.UseDeveloperExceptionPage(); }. Use app.UseExceptionHandler(\"/Error\") for production.",
					CWEID:         "CWE-209",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"csharp", "error-handling", "information-disclosure"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// CS-040: Weak Password Hashing
// ---------------------------------------------------------------------------

type WeakPasswordHashing struct{}

func (r *WeakPasswordHashing) ID() string                      { return "BATOU-CS-040" }
func (r *WeakPasswordHashing) Name() string                    { return "CSharpWeakPasswordHashing" }
func (r *WeakPasswordHashing) DefaultSeverity() rules.Severity { return rules.High }
func (r *WeakPasswordHashing) Description() string {
	return "Detects use of MD5, SHA1, or SHA256 for password hashing. These are fast hash functions not designed for passwords and are vulnerable to brute-force and rainbow table attacks."
}
func (r *WeakPasswordHashing) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *WeakPasswordHashing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reGenPasswordCtx.MatchString(ctx.Content) {
		return findings
	}
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if reGenWeakHash.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Weak hash function used in password context",
				Description:   "MD5, SHA1, and SHA256 are fast cryptographic hashes not suitable for password storage. They lack salting and key stretching, making passwords vulnerable to brute-force and rainbow table attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use a purpose-built password hashing algorithm: Rfc2898DeriveBytes (PBKDF2), BCrypt.Net, or Microsoft.AspNetCore.Identity.PasswordHasher<T> which handles salting and iteration count.",
				CWEID:         "CWE-916",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "crypto", "password-hashing"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&BinaryFormatterUsage{})
	rules.Register(&JSONNetTypeNameHandling{})
	rules.Register(&BlazorMarkupStringXSS{})
	rules.Register(&EFCoreFromSqlRawInjection{})
	rules.Register(&MinimalAPIMissingAuth{})
	rules.Register(&GrpcChannelWithoutTLS{})
	rules.Register(&MissingAntiForgeryGen{})
	rules.Register(&RegexWithoutTimeout{})
	rules.Register(&DevExceptionPage{})
	rules.Register(&WeakPasswordHashing{})
}
