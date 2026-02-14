package csharp

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// GTSS-CS-001: SQL Injection (SqlCommand/SqlConnection with string concat/interpolation)
var (
	// SqlCommand with string concatenation
	reSQLCommandConcat = regexp.MustCompile(`(?i)new\s+SqlCommand\s*\(\s*(?:["'][^"']*["']\s*\+|\$"[^"]*\{|[a-zA-Z_]\w*\s*[,)])`)
	// CommandText assignment with concatenation or interpolation
	reCommandTextConcat = regexp.MustCompile(`(?i)\.CommandText\s*=\s*(?:["'][^"']*["']\s*\+|\$"|[a-zA-Z_]\w*\s*;)`)
	// String concat with SQL keywords (C# specific patterns)
	// Match lines with SQL keyword in a string literal followed by + variable concatenation
	reSQLStringConcat = regexp.MustCompile(`(?i)["'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b.*["']\s*\+\s*\w`)
	// String interpolation with SQL keywords
	reSQLInterpolation = regexp.MustCompile(`(?i)\$"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*\{`)
	// FromSqlRaw with variable (not interpolated string handled by EF)
	reFromSqlRawVar = regexp.MustCompile(`(?i)\.FromSqlRaw\(\s*(?:[a-zA-Z_]\w*|["'][^"']*["']\s*\+|\$")`)
	// ExecuteSqlRaw with variable
	reExecuteSqlRawVar = regexp.MustCompile(`(?i)\.ExecuteSqlRaw\(\s*(?:[a-zA-Z_]\w*|["'][^"']*["']\s*\+|\$")`)
	// Safe: SqlParameter, FromSqlInterpolated, ExecuteSqlInterpolated, Parameters.Add
	reSQLSafe = regexp.MustCompile(`(?i)(?:SqlParameter|\.Parameters\.Add|\.Parameters\.AddWithValue|FromSqlInterpolated|ExecuteSqlInterpolated)`)
)

// GTSS-CS-003: Insecure deserialization
var (
	// BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter, ObjectStateFormatter
	reInsecureDeserializer = regexp.MustCompile(`\b(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\s*(?:\(\s*\)|[^(])`)
	// Deserialize call on known insecure deserializers
	reInsecureDeserialize = regexp.MustCompile(`\b(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter).*\.Deserialize\s*\(`)
	// JavaScriptSerializer with TypeNameHandling or SimpleTypeResolver
	reJavaScriptSerializerUnsafe = regexp.MustCompile(`(?i)new\s+JavaScriptSerializer\s*\(\s*new\s+SimpleTypeResolver`)
	// JSON.NET TypeNameHandling set to anything other than None
	reTypeNameHandlingUnsafe = regexp.MustCompile(`(?i)TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)`)
)

// GTSS-CS-004: Command injection (Process.Start with user-controlled args)
var (
	// Process.Start with variable as first arg, or with string concat/interpolation
	reProcessStart = regexp.MustCompile(`Process\.Start\s*\(\s*(?:[a-zA-Z_]\w*|["'][^"']*["']\s*\+|\$")`)
	// Process.Start with hardcoded command but variable second arg: Process.Start("cmd", userInput)
	reProcessStartWithArgs = regexp.MustCompile(`Process\.Start\s*\(\s*["'][^"']+["']\s*,\s*[a-zA-Z_]\w*`)
	reProcessStartInfo     = regexp.MustCompile(`(?:\.FileName\s*=\s*(?:[a-zA-Z_]\w*|["'][^"']*["']\s*\+|\$")|\.Arguments\s*=\s*(?:[a-zA-Z_]\w*|["'][^"']*["']\s*\+|\$"))`)
	// new ProcessStartInfo with variable arguments
	reNewProcessStartInfo = regexp.MustCompile(`new\s+ProcessStartInfo\s*\(\s*(?:[a-zA-Z_]\w*|\$"|["'][^"']*["']\s*\+)`)
	// Safe: hardcoded command with no other arguments
	reProcessSafe = regexp.MustCompile(`Process\.Start\s*\(\s*["'][^"']+["']\s*\)`)
)

// GTSS-CS-005: Path traversal
var (
	reFileOpsUserInput = regexp.MustCompile(`(?:File\.(?:ReadAllText|ReadAllBytes|ReadAllLines|WriteAllText|WriteAllBytes|WriteAllLines|Delete|Copy|Move|Exists|Open|Create|AppendAllText)|Directory\.(?:Delete|CreateDirectory|GetFiles|GetDirectories|EnumerateFiles))\s*\(`)
	rePathCombine      = regexp.MustCompile(`Path\.Combine\s*\(`)
	// Safe: Path.GetFileName strips directory components, GetFullPath+StartsWith validates path,
	// .ToString() indicates non-string source (e.g., integer ID)
	rePathSafe = regexp.MustCompile(`(?:Path\.GetFileName\s*\(|\.StartsWith\s*\(|Path\.GetFullPath\s*\(|\.ToString\s*\(\s*\))`)
)

// GTSS-CS-006: LDAP injection
var (
	reLDAPFilterConcat     = regexp.MustCompile(`(?i)(?:DirectorySearcher|searcher)\s*(?:\(\s*|\.Filter\s*=\s*)(?:["'][^"']*["']\s*\+|\$"|[a-zA-Z_]\w*\s*[;)])`)
	reLDAPNewSearcherConcat = regexp.MustCompile(`(?i)new\s+DirectorySearcher\s*\(\s*(?:["'][^"']*["']\s*\+|\$")`)
)

// GTSS-CS-008: Hardcoded connection strings
var (
	reHardcodedConnString = regexp.MustCompile(`(?i)(?:connectionString|connStr|conn_str|connection)\s*=\s*["'][^"']*(?:password|pwd|Password|PWD)\s*=\s*[^"']+["']`)
)

// GTSS-CS-009: Insecure cookie
var (
	reCookieNoSecure   = regexp.MustCompile(`(?i)new\s+CookieOptions\s*\{`)
	reCookieSecureTrue = regexp.MustCompile(`(?i)Secure\s*=\s*true`)
	reCookieHttpOnly   = regexp.MustCompile(`(?i)HttpOnly\s*=\s*true`)
	reCookieSameSite   = regexp.MustCompile(`(?i)SameSite\s*=`)
)

// GTSS-CS-010: CORS misconfiguration
var (
	reAllowAnyOrigin    = regexp.MustCompile(`\.AllowAnyOrigin\s*\(`)
	reAllowCredentials  = regexp.MustCompile(`\.AllowCredentials\s*\(`)
	reWithOriginsStar   = regexp.MustCompile(`\.WithOrigins\s*\(\s*["']\*["']\s*\)`)
	reCORSPolicyStar    = regexp.MustCompile(`(?i)policy\.WithOrigins\s*\(\s*["']\*["']\s*\)`)
)

// GTSS-CS-011: Blazor JS interop injection
var (
	reJSRuntimeInvoke = regexp.MustCompile(`(?i)(?:JSRuntime|jsRuntime|_jsRuntime|IJSRuntime)\.InvokeAsync\s*(?:<[^>]*>\s*)?\(\s*["']eval["']`)
	reJSRuntimeInterp = regexp.MustCompile(`(?i)(?:JSRuntime|jsRuntime|_jsRuntime|IJSRuntime)\.Invoke(?:Async|Void(?:Async)?)\s*(?:<[^>]*>\s*)?\(\s*\$"`)
)

// GTSS-CS-012: Mass assignment (no [Bind] or DTO, direct model binding)
var (
	// TryUpdateModelAsync without property list
	reTryUpdateModel    = regexp.MustCompile(`TryUpdateModelAsync\s*<`)
	reUpdateModelFields = regexp.MustCompile(`TryUpdateModelAsync\s*<[^>]*>\s*\([^)]*,\s*["']`)
)

// GTSS-CS-013: Regex DoS (new Regex with user input without timeout)
var (
	reNewRegex        = regexp.MustCompile(`new\s+Regex\s*\(`)
	reRegexTimeout    = regexp.MustCompile(`(?:RegexOptions\s*\.\s*None|TimeSpan|matchTimeout|RegexOptions\.[^)]*,\s*TimeSpan)`)
	reRegexIsMatch    = regexp.MustCompile(`Regex\.(?:IsMatch|Match|Matches|Replace|Split)\s*\(`)
	reRegexStaticSafe = regexp.MustCompile(`Regex\.(?:IsMatch|Match|Matches|Replace|Split)\s*\([^,)]*,[^,)]*,\s*RegexOptions`)
)

// GTSS-CS-014: Insecure random (System.Random for security)
var (
	reSystemRandom     = regexp.MustCompile(`new\s+Random\s*\(`)
	reRandomNext       = regexp.MustCompile(`\b(?:rand|random|rng|rnd)\s*\.\s*Next(?:Bytes|Double)?\s*\(`)
	reSecurityContext  = regexp.MustCompile(`(?i)(?:password|token|secret|key|nonce|salt|otp|verification|csrf|session|auth)`)
	reSecureRandomSafe = regexp.MustCompile(`(?:RandomNumberGenerator|RNGCryptoServiceProvider)`)
)

// GTSS-CS-015: ViewData/ViewBag XSS
var (
	reViewDataAssign = regexp.MustCompile(`(?:ViewData|ViewBag)\s*\[?\s*["']?\w*["']?\]?\s*=`)
	reHtmlRaw        = regexp.MustCompile(`@?Html\.Raw\s*\(`)
)

// GTSS-CS-016: Open redirect
var (
	reRedirectUserInput = regexp.MustCompile(`(?:Redirect|RedirectToAction|RedirectPermanent)\s*\(\s*(?:[a-zA-Z_]\w*|Request\.|returnUrl|redirectUrl|url|next|goto|return_to)`)
	reRedirectSafe      = regexp.MustCompile(`(?i)(?:Url\.IsLocalUrl|IsLocalUrl|LocalRedirect|RedirectToAction\s*\(\s*["']|RedirectToPage\s*\(\s*["'])`)
)

// GTSS-CS-017: SSRF via HttpClient
var (
	reHttpClientRequest = regexp.MustCompile(`(?:HttpClient|_httpClient|_client|client)\s*\.\s*(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync)\s*\(\s*(?:[a-zA-Z_]\w*|\$")`)
	reHttpClientSafe    = regexp.MustCompile(`(?i)(?:new\s+Uri\s*\(\s*["']https?://|\.BaseAddress\s*=|AllowedHosts|IsAllowedUrl|ValidateUrl|WhitelistUrl)`)
)

// GTSS-CS-018: Insecure XML (XmlDocument without XmlResolver=null)
var (
	reXmlDocument    = regexp.MustCompile(`new\s+XmlDocument\s*\(`)
	reXmlReaderLoad  = regexp.MustCompile(`\.(?:LoadXml|Load)\s*\(`)
	reXmlResolverNull = regexp.MustCompile(`XmlResolver\s*=\s*null`)
	reXmlDtdProc     = regexp.MustCompile(`DtdProcessing\s*=\s*DtdProcessing\.Prohibit`)
)

// GTSS-CS-019: Expression injection (dynamic LINQ with user input)
var (
	reDynamicLinq = regexp.MustCompile(`\.(?:Where|OrderBy|Select|GroupBy)\s*\(\s*(?:[a-zA-Z_]\w*\s*\+|\$"|[a-zA-Z_]\w*\s*\))\s*`)
	reDynamicLinqLib = regexp.MustCompile(`(?:System\.Linq\.Dynamic|DynamicQueryable)`)
)

// GTSS-CS-020: Missing [ValidateAntiForgeryToken] on POST endpoints
var (
	reHttpPostAttr         = regexp.MustCompile(`\[\s*Http(?:Post|Put|Delete|Patch)\s*\]`)
	reAntiForgeryToken     = regexp.MustCompile(`\[\s*ValidateAntiForgeryToken\s*\]`)
	reAutoAntiForgery      = regexp.MustCompile(`(?:AutoValidateAntiforgeryToken|IgnoreAntiforgeryToken|\[ApiController\])`)
)

// GTSS-CS-021: Hardcoded secrets (API keys, tokens in code)
var (
	reHardcodedSecret = regexp.MustCompile(`(?i)(?:apiKey|api_key|secret|secretKey|secret_key|accessKey|access_key|privateKey|private_key|clientSecret|client_secret)\s*=\s*["'][a-zA-Z0-9+/=_\-]{16,}["']`)
	reHardcodedSecretConst = regexp.MustCompile(`(?i)(?:const|static\s+readonly)\s+string\s+\w*(?:Key|Secret|Token|Password)\w*\s*=\s*["'][^"']{8,}["']`)
)

// GTSS-CS-022: Unsafe reflection (Type.GetType/Activator.CreateInstance with user input)
var (
	reTypeGetType          = regexp.MustCompile(`Type\.GetType\s*\(\s*[a-zA-Z_]\w*`)
	reActivatorCreate      = regexp.MustCompile(`Activator\.CreateInstance\s*\(\s*(?:Type\.GetType|[a-zA-Z_]\w*Type|[a-zA-Z_]\w*\))`)
	reAssemblyLoad         = regexp.MustCompile(`Assembly\.(?:Load|LoadFrom|LoadFile)\s*\(\s*[a-zA-Z_]\w*`)
	reReflectionSafe       = regexp.MustCompile(`(?i)(?:typeof\s*\(|nameof\s*\(|allowedTypes|typeWhitelist|validTypes)`)
)

// ---------------------------------------------------------------------------
// Comment detection
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*(?://|/\*|\*)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func hasNearbySafe(lines []string, idx int, pat *regexp.Regexp) bool {
	start := idx - 10
	if start < 0 {
		start = 0
	}
	end := idx + 10
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if pat.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GTSS-CS-001: SQL Injection
// ---------------------------------------------------------------------------

type SQLInjection struct{}

func (r *SQLInjection) ID() string                      { return "GTSS-CS-001" }
func (r *SQLInjection) Name() string                    { return "CSharpSQLInjection" }
func (r *SQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *SQLInjection) Description() string {
	return "Detects SQL injection in C# via SqlCommand, Entity Framework FromSqlRaw/ExecuteSqlRaw with string concatenation or interpolation."
}
func (r *SQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *SQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Skip if file uses parameterized queries extensively
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var confidence string

		if hasNearbySafe(lines, i, reSQLSafe) {
			continue
		}

		if loc := reSQLInterpolation.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
		} else if loc := reSQLStringConcat.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
		} else if loc := reFromSqlRawVar.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
		} else if loc := reExecuteSqlRawVar.FindString(line); loc != "" {
			matched = loc
			confidence = "high"
		} else if loc := reCommandTextConcat.FindString(line); loc != "" {
			matched = loc
			confidence = "medium"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SQL Injection via string concatenation/interpolation in C#",
				Description:   "SQL queries built with string concatenation or interpolation are vulnerable to SQL injection. Use parameterized queries with SqlParameter, FromSqlInterpolated, or ExecuteSqlInterpolated.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized queries: command.Parameters.AddWithValue(\"@param\", value) or context.Users.FromSqlInterpolated($\"...\").",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"csharp", "sql-injection", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-003: Insecure Deserialization
// ---------------------------------------------------------------------------

type InsecureDeserialization struct{}

func (r *InsecureDeserialization) ID() string                      { return "GTSS-CS-003" }
func (r *InsecureDeserialization) Name() string                    { return "CSharpInsecureDeserialization" }
func (r *InsecureDeserialization) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *InsecureDeserialization) Description() string {
	return "Detects insecure deserialization via BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter, ObjectStateFormatter, and JSON.NET TypeNameHandling."
}
func (r *InsecureDeserialization) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *InsecureDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var detail string
		sev := r.DefaultSeverity()

		if m := reInsecureDeserialize.FindString(line); m != "" {
			matched = m
			detail = "BinaryFormatter/SoapFormatter/NetDataContractSerializer/LosFormatter/ObjectStateFormatter deserialization is inherently insecure and allows arbitrary code execution. Microsoft recommends not using these serializers with untrusted data."
		} else if m := reInsecureDeserializer.FindString(line); m != "" {
			matched = m
			detail = "Instantiation of an insecure deserializer (BinaryFormatter, SoapFormatter, etc.). These serializers can execute arbitrary code during deserialization of untrusted data."
		} else if m := reJavaScriptSerializerUnsafe.FindString(line); m != "" {
			matched = m
			detail = "JavaScriptSerializer with SimpleTypeResolver allows type-discriminated deserialization, enabling remote code execution via crafted JSON payloads."
		} else if m := reTypeNameHandlingUnsafe.FindString(line); m != "" {
			matched = m
			detail = "JSON.NET TypeNameHandling set to All/Auto/Objects/Arrays allows type-discriminated deserialization, enabling remote code execution via crafted JSON payloads."
			sev = rules.High
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title:         "Insecure deserialization in C#",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use System.Text.Json or DataContractSerializer with known types. For JSON.NET, use TypeNameHandling.None or a custom SerializationBinder with an allowlist.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "deserialization", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-004: Command Injection
// ---------------------------------------------------------------------------

type CommandInjection struct{}

func (r *CommandInjection) ID() string                      { return "GTSS-CS-004" }
func (r *CommandInjection) Name() string                    { return "CSharpCommandInjection" }
func (r *CommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CommandInjection) Description() string {
	return "Detects command injection via Process.Start or ProcessStartInfo with user-controlled arguments."
}
func (r *CommandInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var detail string
		confidence := "high"

		// Skip safe Process.Start with hardcoded string
		if reProcessSafe.MatchString(line) {
			continue
		}

		if m := reProcessStartWithArgs.FindString(line); m != "" {
			matched = m
			detail = "Process.Start with a variable argument may allow command injection if the argument is user-controlled."
		} else if m := reProcessStart.FindString(line); m != "" {
			matched = m
			detail = "Process.Start with dynamic argument may allow command injection if the argument is user-controlled."
		} else if m := reProcessStartInfo.FindString(line); m != "" {
			matched = m
			detail = "ProcessStartInfo FileName or Arguments set with dynamic value may allow command injection."
			confidence = "medium"
		} else if m := reNewProcessStartInfo.FindString(line); m != "" {
			matched = m
			detail = "ProcessStartInfo constructed with dynamic arguments may allow command injection."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Command injection via Process.Start in C#",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate and sanitize all arguments before passing to Process.Start. Use an allowlist for permitted commands. Avoid shell interpreters (cmd.exe /c, bash -c).",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"csharp", "command-injection", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-005: Path Traversal
// ---------------------------------------------------------------------------

type PathTraversal struct{}

func (r *PathTraversal) ID() string                      { return "GTSS-CS-005" }
func (r *PathTraversal) Name() string                    { return "CSharpPathTraversal" }
func (r *PathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *PathTraversal) Description() string {
	return "Detects file/directory operations with potentially user-controlled paths and Path.Combine without validation."
}
func (r *PathTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *PathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check if file has user input sources
	hasUserInput := strings.Contains(ctx.Content, "Request.") ||
		strings.Contains(ctx.Content, "[FromQuery]") ||
		strings.Contains(ctx.Content, "[FromBody]") ||
		strings.Contains(ctx.Content, "[FromRoute]") ||
		strings.Contains(ctx.Content, "[FromForm]") ||
		strings.Contains(ctx.Content, "IFormFile") ||
		strings.Contains(ctx.Content, "Console.ReadLine") ||
		strings.Contains(ctx.Content, "[HttpGet]") ||
		strings.Contains(ctx.Content, "[HttpPost]") ||
		strings.Contains(ctx.Content, "[HttpPut]") ||
		strings.Contains(ctx.Content, "[HttpDelete]") ||
		strings.Contains(ctx.Content, "ControllerBase") ||
		strings.Contains(ctx.Content, ": Controller")

	if !hasUserInput {
		return nil
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Skip lines with Path.GetFileName (safe pattern)
		if rePathSafe.MatchString(line) {
			continue
		}

		var matched string
		var detail string

		if m := rePathCombine.FindString(line); m != "" {
			// Path.Combine is vulnerable to traversal if user input contains absolute path
			if hasNearbySafe(lines, i, rePathSafe) {
				continue
			}
			matched = m
			detail = "Path.Combine with user-controlled input is vulnerable to path traversal. If the second argument is an absolute path (e.g., starts with / or C:\\), it ignores the base path entirely."
		} else if m := reFileOpsUserInput.FindString(line); m != "" {
			// Check if there's path sanitization nearby
			if hasNearbySafe(lines, i, rePathSafe) {
				continue
			}
			matched = m
			detail = "File or directory operation with potentially user-controlled path. An attacker could use ../ sequences to access files outside the intended directory."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Path traversal in file operation",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use Path.GetFileName() to strip directory components from user input. Validate that the resolved path starts with the expected base directory using Path.GetFullPath() and StartsWith().",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "path-traversal", "file-access"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-006: LDAP Injection
// ---------------------------------------------------------------------------

type LDAPInjection struct{}

func (r *LDAPInjection) ID() string                      { return "GTSS-CS-006" }
func (r *LDAPInjection) Name() string                    { return "CSharpLDAPInjection" }
func (r *LDAPInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *LDAPInjection) Description() string {
	return "Detects LDAP injection via DirectorySearcher.Filter with string concatenation or interpolation."
}
func (r *LDAPInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *LDAPInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if m := reLDAPFilterConcat.FindString(line); m != "" {
			matched = m
		} else if m := reLDAPNewSearcherConcat.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "LDAP injection via DirectorySearcher with string concatenation",
				Description:   "LDAP filters constructed with string concatenation or interpolation allow attackers to modify filter logic and access unauthorized directory entries.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Escape LDAP special characters in user input before constructing filters. Use parameterized LDAP searches or encode with a dedicated LDAP filter escaping function.",
				CWEID:         "CWE-90",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "ldap-injection", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-008: Hardcoded Connection Strings
// ---------------------------------------------------------------------------

type HardcodedConnectionString struct{}

func (r *HardcodedConnectionString) ID() string                      { return "GTSS-CS-008" }
func (r *HardcodedConnectionString) Name() string                    { return "CSharpHardcodedConnectionString" }
func (r *HardcodedConnectionString) DefaultSeverity() rules.Severity { return rules.High }
func (r *HardcodedConnectionString) Description() string {
	return "Detects hardcoded database connection strings with embedded passwords in C# source code."
}
func (r *HardcodedConnectionString) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *HardcodedConnectionString) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if m := reHardcodedConnString.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded database connection string with password",
				Description:   "A connection string with an embedded password is hardcoded in the source code. This exposes database credentials in version control and compiled binaries.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Store connection strings in configuration files (appsettings.json) or environment variables. Use Azure Key Vault, AWS Secrets Manager, or similar secrets management for production credentials.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "hardcoded-credentials", "secrets"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-009: Insecure Cookie
// ---------------------------------------------------------------------------

type InsecureCookie struct{}

func (r *InsecureCookie) ID() string                      { return "GTSS-CS-009" }
func (r *InsecureCookie) Name() string                    { return "CSharpInsecureCookie" }
func (r *InsecureCookie) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *InsecureCookie) Description() string {
	return "Detects CookieOptions without Secure, HttpOnly, or SameSite flags in ASP.NET Core."
}
func (r *InsecureCookie) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *InsecureCookie) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if !reCookieNoSecure.MatchString(line) {
			continue
		}

		// Check surrounding lines for cookie security flags
		start := i
		end := i + 15
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[start:end], "\n")

		hasSecure := reCookieSecureTrue.MatchString(block)
		hasHttpOnly := reCookieHttpOnly.MatchString(block)
		hasSameSite := reCookieSameSite.MatchString(block)

		if hasSecure && hasHttpOnly && hasSameSite {
			continue
		}

		missing := []string{}
		if !hasSecure {
			missing = append(missing, "Secure")
		}
		if !hasHttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if !hasSameSite {
			missing = append(missing, "SameSite")
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Cookie missing security flags: " + strings.Join(missing, ", "),
			Description:   "CookieOptions is missing security flags. Without Secure, cookies are sent over HTTP. Without HttpOnly, cookies are accessible to JavaScript (XSS). Without SameSite, cookies are vulnerable to CSRF.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Set Secure = true, HttpOnly = true, and SameSite = SameSiteMode.Strict (or Lax) on all cookies containing sensitive data.",
			CWEID:         "CWE-614",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"csharp", "cookie", "security-config"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-010: CORS Misconfiguration
// ---------------------------------------------------------------------------

type CORSMisconfiguration struct{}

func (r *CORSMisconfiguration) ID() string                      { return "GTSS-CS-010" }
func (r *CORSMisconfiguration) Name() string                    { return "CSharpCORSMisconfiguration" }
func (r *CORSMisconfiguration) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CORSMisconfiguration) Description() string {
	return "Detects insecure CORS configurations in ASP.NET Core, including AllowAnyOrigin with AllowCredentials and wildcard origins."
}
func (r *CORSMisconfiguration) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CORSMisconfiguration) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasAnyOrigin := reAllowAnyOrigin.MatchString(ctx.Content)
	hasCreds := reAllowCredentials.MatchString(ctx.Content)
	hasWildcardOrigins := reWithOriginsStar.MatchString(ctx.Content) || reCORSPolicyStar.MatchString(ctx.Content)

	if hasAnyOrigin && hasCreds {
		for i, line := range lines {
			if isCommentLine(line) {
				continue
			}
			if reAllowAnyOrigin.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.High,
					SeverityLabel: rules.High.String(),
					Title:         "CORS: AllowAnyOrigin with AllowCredentials",
					Description:   "ASP.NET Core CORS policy allows any origin and also enables credentials. This combination is rejected by browsers but indicates a dangerous misconfiguration that may evolve into a reflected origin vulnerability.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use WithOrigins() with an explicit list of trusted domains instead of AllowAnyOrigin(). If credentials are needed, each origin must be specified explicitly.",
					CWEID:         "CWE-942",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"csharp", "cors", "security-config"},
				})
				break
			}
		}
	} else if hasAnyOrigin || hasWildcardOrigins {
		for i, line := range lines {
			if isCommentLine(line) {
				continue
			}
			if reAllowAnyOrigin.MatchString(line) || reWithOriginsStar.MatchString(line) || reCORSPolicyStar.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "CORS: wildcard origin configured",
					Description:   "The CORS policy allows all origins. While acceptable for fully public APIs, it may expose endpoints to unintended cross-origin access.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Use WithOrigins() with specific trusted domains instead of AllowAnyOrigin() or WithOrigins(\"*\").",
					CWEID:         "CWE-942",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"csharp", "cors", "security-config"},
				})
				break
			}
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-011: Blazor JS Interop Injection
// ---------------------------------------------------------------------------

type BlazorJSInteropInjection struct{}

func (r *BlazorJSInteropInjection) ID() string                      { return "GTSS-CS-011" }
func (r *BlazorJSInteropInjection) Name() string                    { return "CSharpBlazorJSInteropInjection" }
func (r *BlazorJSInteropInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *BlazorJSInteropInjection) Description() string {
	return "Detects Blazor JSRuntime.InvokeAsync with eval or string interpolation, which can lead to JavaScript injection."
}
func (r *BlazorJSInteropInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *BlazorJSInteropInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var detail string

		if m := reJSRuntimeInvoke.FindString(line); m != "" {
			matched = m
			detail = "JSRuntime.InvokeAsync with 'eval' as the function name executes arbitrary JavaScript. If user input reaches the eval argument, this enables XSS."
		} else if m := reJSRuntimeInterp.FindString(line); m != "" {
			matched = m
			detail = "JSRuntime.InvokeAsync/InvokeVoidAsync with string interpolation in the function identifier may allow JavaScript injection if user input is interpolated into the function name."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Blazor JS interop injection",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use fixed JavaScript function names in JSRuntime calls. Pass user data as arguments to the JavaScript function, not as part of the function name. Never use 'eval' with JSRuntime.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "blazor", "xss", "js-interop"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-012: Mass Assignment
// ---------------------------------------------------------------------------

type MassAssignment struct{}

func (r *MassAssignment) ID() string                      { return "GTSS-CS-012" }
func (r *MassAssignment) Name() string                    { return "CSharpMassAssignment" }
func (r *MassAssignment) DefaultSeverity() rules.Severity { return rules.High }
func (r *MassAssignment) Description() string {
	return "Detects mass assignment vulnerabilities in ASP.NET Core where domain models are bound directly from request data without [Bind] attribute or DTO pattern."
}
func (r *MassAssignment) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *MassAssignment) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for TryUpdateModelAsync without field restrictions
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reTryUpdateModel.MatchString(line) && !reUpdateModelFields.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "TryUpdateModelAsync without field restrictions (mass assignment)",
				Description:   "TryUpdateModelAsync binds all model properties from request data. Without specifying included properties, an attacker can set unintended fields like IsAdmin, Role, or Price.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Specify included properties: TryUpdateModelAsync(model, \"\", m => m.Name, m => m.Email). Or use a dedicated DTO/ViewModel with only the fields you want to accept.",
				CWEID:         "CWE-915",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "mass-assignment", "model-binding"},
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-013: Regex DoS
// ---------------------------------------------------------------------------

type RegexDoS struct{}

func (r *RegexDoS) ID() string                      { return "GTSS-CS-013" }
func (r *RegexDoS) Name() string                    { return "CSharpRegexDoS" }
func (r *RegexDoS) DefaultSeverity() rules.Severity { return rules.High }
func (r *RegexDoS) Description() string {
	return "Detects Regex usage without timeout, which can lead to ReDoS (Regular Expression Denial of Service) when processing user-controlled input."
}
func (r *RegexDoS) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *RegexDoS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if m := reNewRegex.FindString(line); m != "" {
			// Check if timeout is specified nearby
			context := strings.Join(getSurrounding(lines, i, 3), "\n")
			if reRegexTimeout.MatchString(context) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Regex without timeout (ReDoS risk)",
				Description:   "new Regex() without a timeout parameter is vulnerable to Regular Expression Denial of Service (ReDoS). Malicious input with catastrophic backtracking can cause the regex engine to hang indefinitely.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Specify a timeout: new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1)). In .NET 7+, use the [GeneratedRegex] source generator for compile-time safety.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "regex", "dos", "redos"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-014: Insecure Random
// ---------------------------------------------------------------------------

type InsecureRandom struct{}

func (r *InsecureRandom) ID() string                      { return "GTSS-CS-014" }
func (r *InsecureRandom) Name() string                    { return "CSharpInsecureRandom" }
func (r *InsecureRandom) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureRandom) Description() string {
	return "Detects System.Random used in security-sensitive contexts (tokens, passwords, keys). System.Random is not cryptographically secure."
}
func (r *InsecureRandom) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *InsecureRandom) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if file uses secure random
	if reSecureRandomSafe.MatchString(ctx.Content) {
		return nil
	}

	// Only flag in security contexts
	if !reSecurityContext.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		if m := reSystemRandom.FindString(line); m != "" {
			matched = m
		} else if m := reRandomNext.FindString(line); m != "" {
			// Check if this line or nearby lines involve security
			context := strings.Join(getSurrounding(lines, i, 5), "\n")
			if reSecurityContext.MatchString(context) {
				matched = m
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "System.Random used in security-sensitive context",
				Description:   "System.Random is a pseudorandom number generator that is predictable. An attacker who knows the seed can predict all generated values. Using it for tokens, passwords, keys, or nonces compromises security.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use System.Security.Cryptography.RandomNumberGenerator for security-sensitive random values: RandomNumberGenerator.GetBytes(buffer) or RandomNumberGenerator.GetInt32(maxValue).",
				CWEID:         "CWE-330",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "random", "crypto"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-015: ViewData/ViewBag XSS
// ---------------------------------------------------------------------------

type ViewDataXSS struct{}

func (r *ViewDataXSS) ID() string                      { return "GTSS-CS-015" }
func (r *ViewDataXSS) Name() string                    { return "CSharpViewDataXSS" }
func (r *ViewDataXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *ViewDataXSS) Description() string {
	return "Detects Html.Raw() usage with ViewData/ViewBag which bypasses Razor's automatic HTML encoding, leading to XSS."
}
func (r *ViewDataXSS) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *ViewDataXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if m := reHtmlRaw.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Html.Raw() bypasses Razor HTML encoding (XSS risk)",
				Description:   "Html.Raw() disables Razor's automatic HTML encoding. If the value contains user input (directly or via ViewData/ViewBag/Model), it creates a cross-site scripting (XSS) vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Remove Html.Raw() and let Razor's default encoding handle output. If raw HTML is necessary, sanitize with a library like HtmlSanitizer before passing to Html.Raw().",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "xss", "razor", "viewdata"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-016: Open Redirect
// ---------------------------------------------------------------------------

type OpenRedirect struct{}

func (r *OpenRedirect) ID() string                      { return "GTSS-CS-016" }
func (r *OpenRedirect) Name() string                    { return "CSharpOpenRedirect" }
func (r *OpenRedirect) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *OpenRedirect) Description() string {
	return "Detects Redirect() with user-controlled input (returnUrl, next, goto) without URL validation, enabling open redirect attacks."
}
func (r *OpenRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *OpenRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if m := reRedirectUserInput.FindString(line); m != "" {
			// Skip if safe redirect pattern nearby
			if hasNearbySafe(lines, i, reRedirectSafe) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Open redirect via Redirect() with user-controlled URL",
				Description:   "Redirect() with a user-supplied URL (returnUrl, next, goto) without validation allows attackers to redirect users to malicious sites, enabling phishing and credential theft.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Use Url.IsLocalUrl() to validate the URL is local before redirecting, or use LocalRedirect() which only allows local URLs. Example: if (Url.IsLocalUrl(returnUrl)) return Redirect(returnUrl);",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "open-redirect", "redirect"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-017: SSRF via HttpClient
// ---------------------------------------------------------------------------

type SSRFHttpClient struct{}

func (r *SSRFHttpClient) ID() string                      { return "GTSS-CS-017" }
func (r *SSRFHttpClient) Name() string                    { return "CSharpSSRFHttpClient" }
func (r *SSRFHttpClient) DefaultSeverity() rules.Severity { return rules.High }
func (r *SSRFHttpClient) Description() string {
	return "Detects HttpClient requests with user-controlled URLs that could enable Server-Side Request Forgery (SSRF)."
}
func (r *SSRFHttpClient) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *SSRFHttpClient) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Check if file has user input sources
	hasUserInput := strings.Contains(ctx.Content, "Request.") ||
		strings.Contains(ctx.Content, "[FromQuery]") ||
		strings.Contains(ctx.Content, "[FromBody]") ||
		strings.Contains(ctx.Content, "[FromRoute]") ||
		strings.Contains(ctx.Content, "[FromForm]") ||
		strings.Contains(ctx.Content, "Console.ReadLine") ||
		strings.Contains(ctx.Content, "[HttpGet]") ||
		strings.Contains(ctx.Content, "[HttpPost]") ||
		strings.Contains(ctx.Content, ": Controller") ||
		strings.Contains(ctx.Content, "ControllerBase")

	if !hasUserInput {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if m := reHttpClientRequest.FindString(line); m != "" {
			if hasNearbySafe(lines, i, reHttpClientSafe) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "SSRF via HttpClient with user-controlled URL",
				Description:   "HttpClient request with a user-controlled URL enables Server-Side Request Forgery (SSRF). An attacker can access internal services, cloud metadata endpoints (169.254.169.254), or scan internal networks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Validate and restrict URLs to an allowlist of permitted domains. Block private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x). Use a URL parser to verify the scheme and host before making requests.",
				CWEID:         "CWE-918",
				OWASPCategory: "A10:2021-Server-Side Request Forgery",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "ssrf", "httpclient"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-018: Insecure XML Processing
// ---------------------------------------------------------------------------

type InsecureXML struct{}

func (r *InsecureXML) ID() string                      { return "GTSS-CS-018" }
func (r *InsecureXML) Name() string                    { return "CSharpInsecureXML" }
func (r *InsecureXML) DefaultSeverity() rules.Severity { return rules.High }
func (r *InsecureXML) Description() string {
	return "Detects XmlDocument usage without XmlResolver=null, which is vulnerable to XML External Entity (XXE) injection in .NET Framework."
}
func (r *InsecureXML) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *InsecureXML) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reXmlDocument.MatchString(line) {
			// Check if XmlResolver is set to null or DtdProcessing is prohibited nearby
			context := strings.Join(getSurrounding(lines, i, 10), "\n")
			if reXmlResolverNull.MatchString(context) || reXmlDtdProc.MatchString(context) {
				continue
			}
			// Check if Load/LoadXml is called (otherwise just instantiation may be benign)
			if !reXmlReaderLoad.MatchString(context) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XmlDocument without XmlResolver=null (XXE risk)",
				Description:   "XmlDocument with the default XmlResolver processes external entities and DTDs. In .NET Framework (< 4.5.2), this allows XXE attacks: reading local files, SSRF, and denial of service via entity expansion (Billion Laughs).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Set XmlResolver to null: var doc = new XmlDocument() { XmlResolver = null }; Or use XmlReader with DtdProcessing.Prohibit for safer XML parsing.",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "xxe", "xml", "injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-019: Expression Injection (Dynamic LINQ)
// ---------------------------------------------------------------------------

type ExpressionInjection struct{}

func (r *ExpressionInjection) ID() string                      { return "GTSS-CS-019" }
func (r *ExpressionInjection) Name() string                    { return "CSharpExpressionInjection" }
func (r *ExpressionInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExpressionInjection) Description() string {
	return "Detects dynamic LINQ expression injection with user-controlled input via System.Linq.Dynamic."
}
func (r *ExpressionInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *ExpressionInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only flag if Dynamic LINQ is in use
	if !reDynamicLinqLib.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if m := reDynamicLinq.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Dynamic LINQ expression injection",
				Description:   "Dynamic LINQ (System.Linq.Dynamic) Where/OrderBy/Select with user-controlled strings allows expression injection. Attackers can access arbitrary properties, call methods, or cause denial of service via crafted expressions.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Validate dynamic LINQ expressions against an allowlist of permitted field names. Use strongly-typed LINQ queries instead of dynamic string-based queries where possible.",
				CWEID:         "CWE-917",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "expression-injection", "dynamic-linq"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-020: Missing Anti-Forgery Token
// ---------------------------------------------------------------------------

type MissingAntiForgeryToken struct{}

func (r *MissingAntiForgeryToken) ID() string                      { return "GTSS-CS-020" }
func (r *MissingAntiForgeryToken) Name() string                    { return "CSharpMissingAntiForgeryToken" }
func (r *MissingAntiForgeryToken) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *MissingAntiForgeryToken) Description() string {
	return "Detects [HttpPost/Put/Delete/Patch] endpoints without [ValidateAntiForgeryToken], making them vulnerable to CSRF."
}
func (r *MissingAntiForgeryToken) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *MissingAntiForgeryToken) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Skip if auto-validation is enabled at class level
	if reAutoAntiForgery.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reHttpPostAttr.MatchString(line) {
			// Check surrounding lines for ValidateAntiForgeryToken
			context := strings.Join(getSurrounding(lines, i, 3), "\n")
			if reAntiForgeryToken.MatchString(context) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Missing [ValidateAntiForgeryToken] on state-changing endpoint",
				Description:   "An [HttpPost/Put/Delete/Patch] action method lacks [ValidateAntiForgeryToken]. Without CSRF protection, an attacker can trick authenticated users into submitting malicious requests.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Add [ValidateAntiForgeryToken] to the action method, or apply [AutoValidateAntiforgeryToken] at the controller or global level. For API controllers, use [ApiController] which has its own CSRF mitigation.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "csrf", "anti-forgery"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-021: Hardcoded Secrets
// ---------------------------------------------------------------------------

type HardcodedSecret struct{}

func (r *HardcodedSecret) ID() string                      { return "GTSS-CS-021" }
func (r *HardcodedSecret) Name() string                    { return "CSharpHardcodedSecret" }
func (r *HardcodedSecret) DefaultSeverity() rules.Severity { return rules.High }
func (r *HardcodedSecret) Description() string {
	return "Detects hardcoded API keys, secrets, and tokens assigned directly in C# source code."
}
func (r *HardcodedSecret) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *HardcodedSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if m := reHardcodedSecret.FindString(line); m != "" {
			matched = m
		} else if m := reHardcodedSecretConst.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			// Mask the actual secret value in the output
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Hardcoded secret (API key, token, or password) in source code",
				Description:   "A secret value (API key, token, password, or private key) is hardcoded in the source code. This exposes credentials in version control history and compiled binaries, enabling unauthorized access if the repository is compromised.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Store secrets in environment variables, appsettings.json (excluded from source control), Azure Key Vault, AWS Secrets Manager, or a similar secrets management solution. Use IConfiguration to inject secrets at runtime.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "hardcoded-secret", "credentials"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-022: Unsafe Reflection
// ---------------------------------------------------------------------------

type UnsafeReflection struct{}

func (r *UnsafeReflection) ID() string                      { return "GTSS-CS-022" }
func (r *UnsafeReflection) Name() string                    { return "CSharpUnsafeReflection" }
func (r *UnsafeReflection) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnsafeReflection) Description() string {
	return "Detects Type.GetType(), Activator.CreateInstance(), or Assembly.Load() with user-controlled type names, enabling arbitrary type instantiation."
}
func (r *UnsafeReflection) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *UnsafeReflection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Check if file has user input sources
	hasUserInput := strings.Contains(ctx.Content, "Request.") ||
		strings.Contains(ctx.Content, "[FromQuery]") ||
		strings.Contains(ctx.Content, "[FromBody]") ||
		strings.Contains(ctx.Content, "[FromRoute]") ||
		strings.Contains(ctx.Content, "[FromForm]") ||
		strings.Contains(ctx.Content, "Console.ReadLine") ||
		strings.Contains(ctx.Content, "[HttpGet]") ||
		strings.Contains(ctx.Content, "[HttpPost]") ||
		strings.Contains(ctx.Content, ": Controller") ||
		strings.Contains(ctx.Content, "ControllerBase")

	if !hasUserInput {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// Skip if there's a type allowlist check nearby
		if hasNearbySafe(lines, i, reReflectionSafe) {
			continue
		}

		var matched string
		var detail string

		if m := reTypeGetType.FindString(line); m != "" {
			matched = m
			detail = "Type.GetType() with a user-controlled type name allows instantiation of arbitrary types. An attacker can load dangerous types to achieve remote code execution or bypass security controls."
		} else if m := reActivatorCreate.FindString(line); m != "" {
			matched = m
			detail = "Activator.CreateInstance() with a user-controlled type allows arbitrary object creation. Combined with Type.GetType(), this enables loading and instantiating any type in the runtime."
		} else if m := reAssemblyLoad.FindString(line); m != "" {
			matched = m
			detail = "Assembly.Load/LoadFrom/LoadFile with a user-controlled path allows loading arbitrary .NET assemblies, enabling remote code execution."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unsafe reflection with user-controlled type name",
				Description:   detail,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate type names against an explicit allowlist of permitted types. Never pass user input directly to Type.GetType() or Activator.CreateInstance(). Use a factory pattern with a dictionary of allowed types.",
				CWEID:         "CWE-470",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "reflection", "unsafe-reflection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helper: getSurrounding
// ---------------------------------------------------------------------------

func getSurrounding(lines []string, idx int, radius int) []string {
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	return lines[start:end]
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&SQLInjection{})
	rules.Register(&InsecureDeserialization{})
	rules.Register(&CommandInjection{})
	rules.Register(&PathTraversal{})
	rules.Register(&LDAPInjection{})
	rules.Register(&HardcodedConnectionString{})
	rules.Register(&InsecureCookie{})
	rules.Register(&CORSMisconfiguration{})
	rules.Register(&BlazorJSInteropInjection{})
	rules.Register(&MassAssignment{})
	rules.Register(&RegexDoS{})
	rules.Register(&InsecureRandom{})
	rules.Register(&ViewDataXSS{})
	rules.Register(&OpenRedirect{})
	rules.Register(&SSRFHttpClient{})
	rules.Register(&InsecureXML{})
	rules.Register(&ExpressionInjection{})
	rules.Register(&MissingAntiForgeryToken{})
	rules.Register(&HardcodedSecret{})
	rules.Register(&UnsafeReflection{})
}
