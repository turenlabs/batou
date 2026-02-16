package csharp

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for C# extension rules (GTSS-CS-023 .. GTSS-CS-030)
// ---------------------------------------------------------------------------

// CS-023: SQL injection via string interpolation in EF Core
var (
	reEFFromSqlInterp   = regexp.MustCompile(`\.FromSqlRaw\s*\(\s*\$"`)
	reEFExecuteInterp   = regexp.MustCompile(`\.ExecuteSqlRaw\s*\(\s*\$"`)
	reEFSqlQueryInterp  = regexp.MustCompile(`\.SqlQuery\s*<[^>]+>\s*\(\s*\$"`)
	reEFRawSqlConcat    = regexp.MustCompile(`\.(?:FromSqlRaw|ExecuteSqlRaw|SqlQuery)\s*\(\s*"[^"]*"\s*\+`)
)

// CS-024: XML serialization without type restriction
var (
	reXmlSerializerType  = regexp.MustCompile(`new\s+XmlSerializer\s*\(\s*(?:Type\.GetType|typeof)\s*\(\s*[a-zA-Z_]\w*`)
	reBinaryFormatter    = regexp.MustCompile(`new\s+BinaryFormatter\s*\(\s*\)`)
	reSoapFormatter      = regexp.MustCompile(`new\s+SoapFormatter\s*\(\s*\)`)
	reDeserializeCall    = regexp.MustCompile(`\.Deserialize\s*\(`)
)

// CS-025: LDAP injection via DirectorySearcher
var (
	reDirectorySearcher      = regexp.MustCompile(`new\s+DirectorySearcher\s*\(`)
	reSearchFilterConcat     = regexp.MustCompile(`\.Filter\s*=\s*(?:\$"|"[^"]*"\s*\+|[a-zA-Z_]\w*\s*\+)`)
	reSearchFilterInterp     = regexp.MustCompile(`\.Filter\s*=\s*\$"[^"]*\{`)
	reLdapSearchConcat       = regexp.MustCompile(`(?i)DirectorySearcher\s*\(\s*(?:\$"|"[^"]*"\s*\+)`)
)

// CS-026: Server.MapPath with user input
var (
	reServerMapPath      = regexp.MustCompile(`Server\.MapPath\s*\(\s*(?:Request|[a-zA-Z_]\w*\s*\+|\$")`)
	reHostEnvironmentPath = regexp.MustCompile(`\.ContentRootPath\s*\+\s*(?:Request|[a-zA-Z_]\w*)`)
	rePathCombineUser    = regexp.MustCompile(`Path\.Combine\s*\([^,]*,\s*(?:Request|Input|model\.\w+)`)
)

// CS-027: Response.Write with user input (XSS)
var (
	reResponseWrite     = regexp.MustCompile(`Response\.Write\s*\(\s*(?:Request|Input|model\.\w+|ViewBag\.\w+|ViewData\[)`)
	reResponseWriteInterp = regexp.MustCompile(`Response\.Write\s*\(\s*\$"[^"]*\{(?:Request|Input|model\.\w+)`)
	reHtmlRawUser       = regexp.MustCompile(`Html\.Raw\s*\(\s*(?:Model\.\w+|ViewBag\.\w+|ViewData\[)`)
)

// CS-028: Regex without timeout (ReDoS)
var (
	reNewRegexNoTimeout = regexp.MustCompile(`new\s+Regex\s*\(\s*(?:[a-zA-Z_]\w*|"[^"]*")\s*\)`)
	reNewRegexOptions   = regexp.MustCompile(`new\s+Regex\s*\(\s*(?:[a-zA-Z_]\w*|"[^"]*")\s*,\s*RegexOptions\.\w+\s*\)`)
	reRegexMatch        = regexp.MustCompile(`Regex\.(?:Match|IsMatch|Replace|Matches)\s*\(`)
	reRegexTimeoutExt   = regexp.MustCompile(`TimeSpan|matchTimeout|MatchTimeout`)
)

// CS-029: TypeNameHandling.All in JSON deserialization
var (
	reTypeNameAll     = regexp.MustCompile(`TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)`)
	reJsonDeserialize = regexp.MustCompile(`JsonConvert\.DeserializeObject|JsonSerializer\.Deserialize`)
	reSerializerBinder = regexp.MustCompile(`SerializationBinder|ISerializationBinder`)
)

// CS-030: ViewBag/ViewData used in raw HTML
var (
	reViewBagInRazor    = regexp.MustCompile(`@Html\.Raw\s*\(\s*(?:ViewBag\.\w+|ViewData\[)`)
	reViewBagUnescaped  = regexp.MustCompile(`@ViewBag\.\w+`)
	reRazorHTMLContext  = regexp.MustCompile(`<\w+[^>]*@ViewBag\.\w+`)
)

func init() {
	rules.Register(&CSharpEFSqlInterp{})
	rules.Register(&CSharpXmlDeser{})
	rules.Register(&CSharpLDAPInjection{})
	rules.Register(&CSharpServerMapPath{})
	rules.Register(&CSharpResponseWriteXSS{})
	rules.Register(&CSharpRegexNoTimeout{})
	rules.Register(&CSharpTypeNameHandling{})
	rules.Register(&CSharpViewBagRawHTML{})
}

// ---------------------------------------------------------------------------
// GTSS-CS-023: C# SQL injection via string interpolation in EF Core
// ---------------------------------------------------------------------------

type CSharpEFSqlInterp struct{}

func (r *CSharpEFSqlInterp) ID() string                      { return "GTSS-CS-023" }
func (r *CSharpEFSqlInterp) Name() string                    { return "CSharpEFSqlInterp" }
func (r *CSharpEFSqlInterp) Description() string             { return "Detects C# SQL injection via string interpolation ($\"\") or concatenation in EF Core FromSqlRaw/ExecuteSqlRaw." }
func (r *CSharpEFSqlInterp) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpEFSqlInterp) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }

func (r *CSharpEFSqlInterp) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reEFFromSqlInterp.FindString(line); m != "" {
			matched = m
			desc = "FromSqlRaw() with string interpolation ($\"\"). Interpolated values bypass parameterization."
		} else if m := reEFExecuteInterp.FindString(line); m != "" {
			matched = m
			desc = "ExecuteSqlRaw() with string interpolation ($\"\"). Interpolated values bypass parameterization."
		} else if m := reEFSqlQueryInterp.FindString(line); m != "" {
			matched = m
			desc = "SqlQuery() with string interpolation ($\"\"). User input is embedded directly in the SQL string."
		} else if m := reEFRawSqlConcat.FindString(line); m != "" {
			matched = m
			desc = "FromSqlRaw/ExecuteSqlRaw with string concatenation. Concatenated values bypass parameterization."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "C# EF Core SQL injection: " + desc,
				Description:   "Using string interpolation ($\"\") or concatenation with FromSqlRaw/ExecuteSqlRaw embeds values directly into the SQL string, bypassing EF Core's parameterization. This enables SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use FromSqlInterpolated or ExecuteSqlInterpolated which auto-parameterize interpolated strings. Or use FromSqlRaw with explicit parameters: FromSqlRaw(\"SELECT * FROM Users WHERE Id = {0}\", userId).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "efcore", "sql-injection", "interpolation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-024: C# XML serialization without type restriction
// ---------------------------------------------------------------------------

type CSharpXmlDeser struct{}

func (r *CSharpXmlDeser) ID() string                      { return "GTSS-CS-024" }
func (r *CSharpXmlDeser) Name() string                    { return "CSharpXmlDeser" }
func (r *CSharpXmlDeser) Description() string             { return "Detects C# BinaryFormatter and SoapFormatter deserialization which allow arbitrary type instantiation and code execution." }
func (r *CSharpXmlDeser) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpXmlDeser) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }

func (r *CSharpXmlDeser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string
		sev := r.DefaultSeverity()

		if m := reBinaryFormatter.FindString(line); m != "" {
			matched = m
			desc = "BinaryFormatter is inherently insecure and can execute arbitrary code during deserialization. Microsoft has deprecated it and recommends against its use."
			sev = rules.Critical
		} else if m := reSoapFormatter.FindString(line); m != "" {
			matched = m
			desc = "SoapFormatter is inherently insecure like BinaryFormatter and allows arbitrary type instantiation during deserialization."
			sev = rules.Critical
		} else if m := reXmlSerializerType.FindString(line); m != "" {
			matched = m
			desc = "XmlSerializer constructed with a variable type. If the type comes from user input, an attacker can deserialize arbitrary types."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title:         "C# insecure deserialization",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Replace BinaryFormatter/SoapFormatter with System.Text.Json or XmlSerializer with a fixed, known type. For XmlSerializer, always use a compile-time-known type: new XmlSerializer(typeof(MyClass)).",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "deserialization", "binaryformatter"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-025: C# LDAP injection via DirectorySearcher
// ---------------------------------------------------------------------------

type CSharpLDAPInjection struct{}

func (r *CSharpLDAPInjection) ID() string                      { return "GTSS-CS-025" }
func (r *CSharpLDAPInjection) Name() string                    { return "CSharpLDAPInjection" }
func (r *CSharpLDAPInjection) Description() string             { return "Detects C# LDAP injection via DirectorySearcher.Filter with string concatenation or interpolation." }
func (r *CSharpLDAPInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpLDAPInjection) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }

func (r *CSharpLDAPInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reDirectorySearcher.MatchString(ctx.Content) && !strings.Contains(ctx.Content, "DirectorySearcher") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if m := reSearchFilterInterp.FindString(line); m != "" {
			matched = m
		} else if m := reSearchFilterConcat.FindString(line); m != "" {
			matched = m
		} else if m := reLdapSearchConcat.FindString(line); m != "" {
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
				Title:         "C# LDAP injection via DirectorySearcher",
				Description:   "The LDAP search filter is built using string concatenation or interpolation. An attacker can inject LDAP filter operators (*, |, &, \\) to modify the search query, potentially bypassing authentication or extracting directory data.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Escape LDAP special characters in user input before embedding in filters. Use a library function to sanitize LDAP filter values: replace *, (, ), \\, NUL with their escaped equivalents (\\2a, \\28, \\29, \\5c, \\00).",
				CWEID:         "CWE-90",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "ldap-injection", "directory-searcher"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-026: C# Server.MapPath with user input
// ---------------------------------------------------------------------------

type CSharpServerMapPath struct{}

func (r *CSharpServerMapPath) ID() string                      { return "GTSS-CS-026" }
func (r *CSharpServerMapPath) Name() string                    { return "CSharpServerMapPath" }
func (r *CSharpServerMapPath) Description() string             { return "Detects C# Server.MapPath, Path.Combine, or ContentRootPath with user-controlled input, enabling path traversal." }
func (r *CSharpServerMapPath) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpServerMapPath) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }

func (r *CSharpServerMapPath) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reServerMapPath.FindString(line); m != "" {
			matched = m
			desc = "Server.MapPath() maps a virtual path to a physical path. With user input, an attacker can use ../ traversal to access files outside the web root."
		} else if m := reHostEnvironmentPath.FindString(line); m != "" {
			matched = m
			desc = "ContentRootPath concatenated with user input allows path traversal via ../ sequences to access arbitrary files on the server."
		} else if m := rePathCombineUser.FindString(line); m != "" {
			matched = m
			desc = "Path.Combine with user input can be exploited: an absolute path in the user input replaces the base path entirely, or ../ sequences traverse directories."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "C# path traversal via " + desc[:strings.Index(desc, "(")],
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate and sanitize file paths: use Path.GetFullPath() and verify the result starts with the allowed base directory. Reject paths containing '..' segments or absolute paths in user input.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "path-traversal", "file-access"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-027: C# Response.Write with user input (XSS)
// ---------------------------------------------------------------------------

type CSharpResponseWriteXSS struct{}

func (r *CSharpResponseWriteXSS) ID() string                      { return "GTSS-CS-027" }
func (r *CSharpResponseWriteXSS) Name() string                    { return "CSharpResponseWriteXSS" }
func (r *CSharpResponseWriteXSS) Description() string             { return "Detects C# Response.Write or Html.Raw with user input or model data, enabling cross-site scripting (XSS)." }
func (r *CSharpResponseWriteXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpResponseWriteXSS) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }

func (r *CSharpResponseWriteXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reResponseWrite.FindString(line); m != "" {
			matched = m
			desc = "Response.Write() outputs content directly to the HTTP response without encoding. User input embedded this way enables cross-site scripting attacks."
		} else if m := reResponseWriteInterp.FindString(line); m != "" {
			matched = m
			desc = "Response.Write() with interpolated user input outputs unencoded content, enabling XSS."
		} else if m := reHtmlRawUser.FindString(line); m != "" {
			matched = m
			desc = "Html.Raw() renders content without HTML encoding. Model data or ViewBag values rendered this way can contain malicious scripts if the data originates from user input."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "C# XSS via unencoded output",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use HttpUtility.HtmlEncode() before Response.Write: Response.Write(HttpUtility.HtmlEncode(userInput)). In Razor views, use @Model.Property (auto-encoded) instead of @Html.Raw(). Never use Html.Raw with user-controlled data.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "xss", "response-write", "html-raw"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-028: C# Regex without timeout (ReDoS)
// ---------------------------------------------------------------------------

type CSharpRegexNoTimeout struct{}

func (r *CSharpRegexNoTimeout) ID() string                      { return "GTSS-CS-028" }
func (r *CSharpRegexNoTimeout) Name() string                    { return "CSharpRegexNoTimeout" }
func (r *CSharpRegexNoTimeout) Description() string             { return "Detects C# Regex usage without a timeout, which can lead to ReDoS (regular expression denial of service)." }
func (r *CSharpRegexNoTimeout) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSharpRegexNoTimeout) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }

func (r *CSharpRegexNoTimeout) Scan(ctx *rules.ScanContext) []rules.Finding {
	// If a timeout is configured globally or in the file, skip
	if reRegexTimeoutExt.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if m := reNewRegexNoTimeout.FindString(line); m != "" {
			matched = m
		} else if m := reNewRegexOptions.FindString(line); m != "" {
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
				Title:         "C# Regex without timeout (ReDoS risk)",
				Description:   "A Regex is created without specifying a match timeout. If the regex processes user-controlled input, a crafted string can cause catastrophic backtracking (ReDoS), consuming CPU for minutes or hours.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Always specify a timeout: new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1)). Or set AppDomain.CurrentDomain.SetData(\"REGEX_DEFAULT_MATCH_TIMEOUT\", TimeSpan.FromSeconds(2)) globally.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"csharp", "regex", "redos", "timeout"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-029: C# TypeNameHandling.All in JSON deserialization
// ---------------------------------------------------------------------------

type CSharpTypeNameHandling struct{}

func (r *CSharpTypeNameHandling) ID() string                      { return "GTSS-CS-029" }
func (r *CSharpTypeNameHandling) Name() string                    { return "CSharpTypeNameHandling" }
func (r *CSharpTypeNameHandling) Description() string             { return "Detects C# Newtonsoft.Json TypeNameHandling set to All/Auto/Objects/Arrays without a SerializationBinder, enabling deserialization attacks." }
func (r *CSharpTypeNameHandling) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *CSharpTypeNameHandling) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }

func (r *CSharpTypeNameHandling) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reTypeNameAll.MatchString(ctx.Content) {
		return nil
	}

	// If a custom SerializationBinder is configured, the risk is mitigated
	if reSerializerBinder.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if m := reTypeNameAll.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "C# TypeNameHandling enables deserialization attacks",
				Description:   "Newtonsoft.Json TypeNameHandling (All, Auto, Objects, or Arrays) without a custom SerializationBinder allows an attacker to specify arbitrary .NET types in the JSON $type property. This can instantiate dangerous types (System.IO.FileInfo, System.Diagnostics.Process) leading to remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use TypeNameHandling.None (the default). If type metadata is needed, implement a custom ISerializationBinder that restricts allowed types to a safe allowlist. Consider migrating to System.Text.Json which does not support polymorphic type names by default.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "json", "deserialization", "type-handling", "rce"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-CS-030: C# ViewBag/ViewData used in raw HTML
// ---------------------------------------------------------------------------

type CSharpViewBagRawHTML struct{}

func (r *CSharpViewBagRawHTML) ID() string                      { return "GTSS-CS-030" }
func (r *CSharpViewBagRawHTML) Name() string                    { return "CSharpViewBagRawHTML" }
func (r *CSharpViewBagRawHTML) Description() string             { return "Detects C# ViewBag/ViewData rendered via Html.Raw or in HTML attribute contexts without encoding." }
func (r *CSharpViewBagRawHTML) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpViewBagRawHTML) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }

func (r *CSharpViewBagRawHTML) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reViewBagInRazor.FindString(line); m != "" {
			matched = m
			desc = "@Html.Raw() is used with ViewBag or ViewData values. Html.Raw bypasses Razor's auto-encoding, and if the ViewBag value contains user-controlled data, it enables XSS."
		} else if m := reRazorHTMLContext.FindString(line); m != "" {
			matched = m
			desc = "ViewBag value is used directly inside an HTML tag attribute. While Razor auto-encodes in text contexts, certain attribute contexts (event handlers, href, src) can still be exploited for XSS."
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "C# ViewBag/ViewData in raw HTML context",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use @Model.Property instead of @Html.Raw(ViewBag.Property) to leverage Razor auto-encoding. If raw HTML is required, sanitize the content with HtmlSanitizer before rendering. Use strongly-typed views instead of ViewBag.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"csharp", "xss", "viewbag", "razor", "html-raw"},
			})
		}
	}
	return findings
}
