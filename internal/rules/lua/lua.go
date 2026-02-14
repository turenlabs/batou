package lua

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// LUA-001: Command Injection
var (
	reOsExecute      = regexp.MustCompile(`os\.execute\s*\(`)
	reIoPopen        = regexp.MustCompile(`io\.popen\s*\(`)
	reCmdConcat      = regexp.MustCompile(`os\.execute\s*\(\s*[a-zA-Z_]\w*|os\.execute\s*\(\s*["'].*["']\s*\.\.\s*`)
	reCmdPopConcat   = regexp.MustCompile(`io\.popen\s*\(\s*[a-zA-Z_]\w*|io\.popen\s*\(\s*["'].*["']\s*\.\.\s*`)
	reCmdStaticStr   = regexp.MustCompile(`os\.execute\s*\(\s*["'][^"']*["']\s*\)|io\.popen\s*\(\s*["'][^"']*["']\s*\)`)
)

// LUA-002: Code Injection
var (
	reLoadstring     = regexp.MustCompile(`loadstring\s*\(`)
	reLoadFunc       = regexp.MustCompile(`\bload\s*\(\s*[a-zA-Z_]`)
	reDofileVar      = regexp.MustCompile(`dofile\s*\(\s*[a-zA-Z_]`)
	reLoadfileVar    = regexp.MustCompile(`loadfile\s*\(\s*[a-zA-Z_]`)
	reDofileStatic   = regexp.MustCompile(`dofile\s*\(\s*["'][^"']+["']\s*\)`)
	reLoadfileStatic = regexp.MustCompile(`loadfile\s*\(\s*["'][^"']+["']\s*\)`)
)

// LUA-003: SQL Injection
var (
	reSQLConcat    = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\.\.\s*[a-zA-Z_]`)
	reSQLFormat    = regexp.MustCompile(`(?i)string\.format\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+`)
	reSQLQuery     = regexp.MustCompile(`:query\s*\(`)
)

// LUA-004: Path Traversal
var (
	reIoOpenVar    = regexp.MustCompile(`io\.open\s*\(\s*[a-zA-Z_]\w*`)
	reIoOpenConcat = regexp.MustCompile(`io\.open\s*\(\s*.*\.\.\s*`)
	reIoOpenStatic = regexp.MustCompile(`io\.open\s*\(\s*["'][^"']*["']\s*[,)]`)
)

// LUA-005: XSS via ngx.say/ngx.print
var (
	reNgxSay       = regexp.MustCompile(`ngx\.say\s*\(`)
	reNgxPrint     = regexp.MustCompile(`ngx\.print\s*\(`)
	reNgxSayConcat = regexp.MustCompile(`ngx\.(?:say|print)\s*\(\s*.*\.\.\s*[a-zA-Z_]`)
	reNgxSayVar    = regexp.MustCompile(`ngx\.(?:say|print)\s*\(\s*[a-zA-Z_]\w*\s*\)`)
)

// LUA-006: Insecure Deserialization
var (
	reLoadstringNet  = regexp.MustCompile(`loadstring\s*\(.*(?:receive|socket|tcp|data|body|payload)`)
	reSerpentLoad    = regexp.MustCompile(`serpent\.load\s*\(`)
	reLoadNetContext  = regexp.MustCompile(`(?:receive|socket|tcp|data|body|payload|network|remote)`)
)

// LUA-007: Open Redirect
var (
	reNgxRedirect    = regexp.MustCompile(`ngx\.redirect\s*\(`)
	reNgxRedirectVar = regexp.MustCompile(`ngx\.redirect\s*\(\s*[a-zA-Z_]\w*`)
	reNgxRedirectConcat = regexp.MustCompile(`ngx\.redirect\s*\(\s*.*\.\.\s*`)
)

// LUA-008: Debug library in production
var (
	reDebugGetinfo   = regexp.MustCompile(`debug\.getinfo\s*\(`)
	reDebugSethook   = regexp.MustCompile(`debug\.sethook\s*\(`)
	reDebugSetmeta   = regexp.MustCompile(`debug\.setmetatable\s*\(`)
	reDebugGetlocal  = regexp.MustCompile(`debug\.getlocal\s*\(`)
	reDebugSetlocal  = regexp.MustCompile(`debug\.setlocal\s*\(`)
	reDebugGetupval  = regexp.MustCompile(`debug\.getupvalue\s*\(`)
	reDebugSetupval  = regexp.MustCompile(`debug\.setupvalue\s*\(`)
	reDebugUpvalueid = regexp.MustCompile(`debug\.upvalueid\s*\(`)
)

// --- Comment detection ---

var reLuaComment = regexp.MustCompile(`^\s*--`)

func isCommentLine(line string) bool {
	return reLuaComment.MatchString(line)
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// hasUserInputContext checks if the file has OpenResty or other user input sources.
func hasUserInputContext(content string) bool {
	return strings.Contains(content, "ngx.req") ||
		strings.Contains(content, "ngx.var") ||
		strings.Contains(content, "io.read") ||
		strings.Contains(content, "arg[") ||
		strings.Contains(content, "KEYS[") ||
		strings.Contains(content, "ARGV[") ||
		strings.Contains(content, ":receive(") ||
		strings.Contains(content, "get_uri_args") ||
		strings.Contains(content, "get_post_args") ||
		strings.Contains(content, "get_body_data")
}

// ---------------------------------------------------------------------------
// LUA-001: Command Injection
// ---------------------------------------------------------------------------

type CommandInjection struct{}

func (r CommandInjection) ID() string                      { return "GTSS-LUA-001" }
func (r CommandInjection) Name() string                    { return "Command Injection" }
func (r CommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r CommandInjection) Description() string {
	return "Detects os.execute() and io.popen() with string concatenation or variable input that may allow command injection."
}
func (r CommandInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangLua}
}

func (r CommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// os.execute with variable or concat
		if reOsExecute.MatchString(line) && !reCmdStaticStr.MatchString(line) {
			if reCmdConcat.MatchString(line) || strings.Contains(line, "..") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "os.execute() with dynamic input",
					Description:   "os.execute() is called with string concatenation or a variable. User-controlled data in the command string enables arbitrary command execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Avoid os.execute() with user input. Use a whitelist of allowed commands, or use separate argument passing where possible.",
					CWEID:         "CWE-78",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"lua", "command-injection", "os.execute"},
				})
				continue
			}
		}

		// io.popen with variable or concat
		if reIoPopen.MatchString(line) && !reCmdStaticStr.MatchString(line) {
			if reCmdPopConcat.MatchString(line) || strings.Contains(line, "..") {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "io.popen() with dynamic input",
					Description:   "io.popen() is called with string concatenation or a variable. User-controlled data enables arbitrary command execution via a shell pipe.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Avoid io.popen() with user input. Validate and whitelist allowed commands. Consider using a restricted execution wrapper.",
					CWEID:         "CWE-78",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"lua", "command-injection", "io.popen"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-002: Code Injection
// ---------------------------------------------------------------------------

type CodeInjection struct{}

func (r CodeInjection) ID() string                      { return "GTSS-LUA-002" }
func (r CodeInjection) Name() string                    { return "Code Injection" }
func (r CodeInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r CodeInjection) Description() string {
	return "Detects loadstring()/load() with variable input and dofile()/loadfile() with dynamic paths, which allow arbitrary Lua code execution."
}
func (r CodeInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangLua}
}

func (r CodeInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// loadstring() with any argument (always dangerous with variable input)
		if reLoadstring.MatchString(line) {
			// Check if it's a static string literal like loadstring("return 1")
			if matched, _ := regexp.MatchString(`loadstring\s*\(\s*["'][^"']*["']\s*\)`, line); matched {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "loadstring() with dynamic input",
				Description:   "loadstring() compiles and returns a Lua chunk from a string. If the string contains user-controlled data, an attacker can execute arbitrary Lua code including os.execute(), io.popen(), and file operations.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Never pass user-controlled data to loadstring(). Use a data format like JSON (cjson.decode) instead. If dynamic code execution is required, use a sandboxed environment with restricted globals.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "code-injection", "loadstring"},
			})
			continue
		}

		// load() with variable argument
		if reLoadFunc.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "load() with variable input",
				Description:   "load() compiles a Lua chunk from a string or function. With user-controlled input, this enables arbitrary code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Avoid load() with user input. Use structured data formats (JSON) for data exchange. If needed, sandbox the loaded code with a restricted environment via setfenv/upvalues.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "code-injection", "load"},
			})
			continue
		}

		// dofile() with variable path
		if reDofileVar.MatchString(line) && !reDofileStatic.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "dofile() with variable path",
				Description:   "dofile() executes a Lua file at the given path. A user-controlled path allows execution of arbitrary Lua files, potentially leading to remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Never pass user input to dofile(). Use a whitelist of allowed file paths. Validate and canonicalize the path before use.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "code-injection", "dofile"},
			})
			continue
		}

		// loadfile() with variable path
		if reLoadfileVar.MatchString(line) && !reLoadfileStatic.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "loadfile() with variable path",
				Description:   "loadfile() loads a Lua file for execution. A user-controlled path allows loading arbitrary Lua code.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Never pass user input to loadfile(). Use a whitelist of allowed file paths.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "code-injection", "loadfile"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-003: SQL Injection
// ---------------------------------------------------------------------------

type SQLInjection struct{}

func (r SQLInjection) ID() string                      { return "GTSS-LUA-003" }
func (r SQLInjection) Name() string                    { return "SQL Injection" }
func (r SQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r SQLInjection) Description() string {
	return "Detects SQL queries built with string concatenation in lua-resty-mysql, ngx_postgres, or generic database calls."
}
func (r SQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangLua}
}

func (r SQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for SQL quoting sanitizers in the file
	hasQuoting := strings.Contains(ctx.Content, "quote_sql_str") ||
		strings.Contains(ctx.Content, "ndk.set_var.set_quote_sql_str") ||
		strings.Contains(ctx.Content, "ngx.quote_sql_str")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// SQL string with concatenation: "SELECT ... " .. variable
		if reSQLConcat.MatchString(line) {
			if hasQuoting {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "SQL query with string concatenation",
				Description:   "A SQL query is built by concatenating user input with the .. operator. This enables SQL injection attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use parameterized queries or quote_sql_str() to escape user input: ngx.quote_sql_str(user_input) or ndk.set_var.set_quote_sql_str(user_input).",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "sql-injection", "string-concat"},
			})
			continue
		}

		// string.format with SQL keywords
		if reSQLFormat.MatchString(line) {
			if hasQuoting {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "SQL query with string.format()",
				Description:   "A SQL query is built using string.format() with format specifiers. User-controlled values interpolated via %s enable SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use parameterized queries or escape user input with quote_sql_str() before interpolation.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "sql-injection", "string-format"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-004: Path Traversal
// ---------------------------------------------------------------------------

type PathTraversal struct{}

func (r PathTraversal) ID() string                      { return "GTSS-LUA-004" }
func (r PathTraversal) Name() string                    { return "Path Traversal" }
func (r PathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r PathTraversal) Description() string {
	return "Detects io.open() with user-controlled paths that may allow directory traversal to read or write arbitrary files."
}
func (r PathTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangLua}
}

func (r PathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Check for path sanitization patterns
	hasSanitization := strings.Contains(ctx.Content, "gsub") && strings.Contains(ctx.Content, "%.%.") ||
		strings.Contains(ctx.Content, "string.find") && strings.Contains(ctx.Content, "%.%.") ||
		strings.Contains(ctx.Content, "sanitize") ||
		strings.Contains(ctx.Content, "clean_path")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// io.open with variable (not static string)
		if (reIoOpenVar.MatchString(line) || reIoOpenConcat.MatchString(line)) && !reIoOpenStatic.MatchString(line) {
			if hasSanitization {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "io.open() with user-controlled path",
				Description:   "io.open() is called with a variable or concatenated path. An attacker can use ../ sequences to access files outside the intended directory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Validate the path before use: reject paths containing '..' or '/', use a whitelist of allowed filenames, or resolve to an absolute path and verify it starts with the allowed base directory.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "path-traversal", "io.open"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-005: XSS via ngx.say/ngx.print
// ---------------------------------------------------------------------------

type XSSOutput struct{}

func (r XSSOutput) ID() string                      { return "GTSS-LUA-005" }
func (r XSSOutput) Name() string                    { return "XSS via OpenResty Response" }
func (r XSSOutput) DefaultSeverity() rules.Severity { return rules.High }
func (r XSSOutput) Description() string {
	return "Detects ngx.say() and ngx.print() with unescaped user input from ngx.req or ngx.var, enabling cross-site scripting."
}
func (r XSSOutput) Languages() []rules.Language {
	return []rules.Language{rules.LangLua}
}

func (r XSSOutput) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Only check files that have OpenResty output functions
	if !reNgxSay.MatchString(ctx.Content) && !reNgxPrint.MatchString(ctx.Content) {
		return nil
	}

	// Check if file has user input sources
	if !hasUserInputContext(ctx.Content) {
		return nil
	}

	// Check for HTML escaping in the file
	hasEscape := strings.Contains(ctx.Content, "ngx.escape_uri") ||
		strings.Contains(ctx.Content, "html_escape") ||
		strings.Contains(ctx.Content, "template.escape") ||
		strings.Contains(ctx.Content, "encode_base64")

	if hasEscape {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// ngx.say/ngx.print with concatenation or variable
		if reNgxSayConcat.MatchString(line) || reNgxSayVar.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Unescaped output via ngx.say/ngx.print",
				Description:   "User input is written to the HTTP response via ngx.say() or ngx.print() without HTML escaping. If the response Content-Type is text/html, this enables cross-site scripting (XSS).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Escape user input before output: ngx.say(ngx.escape_uri(user_input)) or use a template engine with auto-escaping (lua-resty-template). Set Content-Type to application/json for API responses.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "xss", "openresty", "ngx.say"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-006: Insecure Deserialization
// ---------------------------------------------------------------------------

type InsecureDeserialization struct{}

func (r InsecureDeserialization) ID() string                      { return "GTSS-LUA-006" }
func (r InsecureDeserialization) Name() string                    { return "Insecure Deserialization" }
func (r InsecureDeserialization) DefaultSeverity() rules.Severity { return rules.High }
func (r InsecureDeserialization) Description() string {
	return "Detects loadstring() used to deserialize network data and serpent.load() from untrusted sources, which enable arbitrary code execution."
}
func (r InsecureDeserialization) Languages() []rules.Language {
	return []rules.Language{rules.LangLua}
}

func (r InsecureDeserialization) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		// loadstring with network/data context
		if reLoadstringNet.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "loadstring() used for deserialization of network data",
				Description:   "loadstring() is used to deserialize data received from a network source. An attacker can inject arbitrary Lua code in the data stream to achieve remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use a safe serialization format like JSON (cjson.decode) or MessagePack. Never use loadstring() to parse untrusted data.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "deserialization", "loadstring", "rce"},
			})
			continue
		}

		// loadstring in file with network context (cross-line check)
		if reLoadstring.MatchString(line) && reLoadNetContext.MatchString(ctx.Content) {
			// Already handled by LUA-002 for general loadstring; check for
			// deserialization patterns specifically near network code
			start := i - 10
			if start < 0 {
				start = 0
			}
			end := i + 5
			if end > len(lines) {
				end = len(lines)
			}
			hasNetNearby := false
			for j := start; j < end; j++ {
				if reLoadNetContext.MatchString(lines[j]) && j != i {
					hasNetNearby = true
					break
				}
			}
			if hasNetNearby {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      rules.High,
					SeverityLabel: rules.High.String(),
					Title:         "loadstring() near network data handling",
					Description:   "loadstring() is used near code that handles network data. If the loaded string originates from network input, this enables remote code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Use cjson.decode() or another safe parser instead of loadstring() for network data. If serialization is needed, use MessagePack (lua-cmsgpack).",
					CWEID:         "CWE-502",
					OWASPCategory: "A08:2021-Software and Data Integrity Failures",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"lua", "deserialization", "loadstring"},
				})
			}
			continue
		}

		// serpent.load from potentially untrusted source
		if reSerpentLoad.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "serpent.load() with potentially untrusted input",
				Description:   "serpent.load() deserializes Lua data. While safer than loadstring(), it can still be exploited with crafted input in some configurations. If the input is from an untrusted source, prefer a safer format.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Use cjson.decode() for untrusted data. If serpent is required, ensure safe mode is enabled: serpent.load(data, {safe = true}).",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "deserialization", "serpent"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-007: Open Redirect
// ---------------------------------------------------------------------------

type OpenRedirect struct{}

func (r OpenRedirect) ID() string                      { return "GTSS-LUA-007" }
func (r OpenRedirect) Name() string                    { return "Open Redirect" }
func (r OpenRedirect) DefaultSeverity() rules.Severity { return rules.Medium }
func (r OpenRedirect) Description() string {
	return "Detects ngx.redirect() with user-controlled URL parameters, enabling open redirect attacks for phishing."
}
func (r OpenRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangLua}
}

func (r OpenRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	if !reNgxRedirect.MatchString(ctx.Content) {
		return nil
	}

	if !hasUserInputContext(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		if reNgxRedirectVar.MatchString(line) || reNgxRedirectConcat.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "ngx.redirect() with user-controlled URL",
				Description:   "ngx.redirect() is called with a variable or concatenated URL. If the URL comes from user input (e.g., ngx.var.arg_url), an attacker can redirect users to a malicious site for phishing.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(line, 120),
				Suggestion:    "Validate redirect URLs against an allowlist of trusted domains. Use relative paths instead of full URLs. Check that the URL starts with '/' or matches your domain.",
				CWEID:         "CWE-601",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "open-redirect", "openresty"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// LUA-008: Debug Library in Production
// ---------------------------------------------------------------------------

type DebugLibrary struct{}

func (r DebugLibrary) ID() string                      { return "GTSS-LUA-008" }
func (r DebugLibrary) Name() string                    { return "Debug Library in Production" }
func (r DebugLibrary) DefaultSeverity() rules.Severity { return rules.Medium }
func (r DebugLibrary) Description() string {
	return "Detects use of the debug library (debug.getinfo, debug.sethook, debug.setmetatable, etc.) which can be used to bypass sandbox restrictions and inspect/modify internal state."
}
func (r DebugLibrary) Languages() []rules.Language {
	return []rules.Language{rules.LangLua}
}

func (r DebugLibrary) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re    *regexp.Regexp
		title string
		desc  string
		sev   rules.Severity
	}

	patterns := []pattern{
		{
			reDebugSetmeta,
			"debug.setmetatable() usage",
			"debug.setmetatable() can modify metatables of any value, including protected ones. This can bypass sandbox restrictions and modify core type behavior.",
			rules.High,
		},
		{
			reDebugSethook,
			"debug.sethook() usage",
			"debug.sethook() installs a debug hook that fires on function calls, returns, and line execution. In production, this enables monitoring of all code execution and can be used for sandbox escape.",
			rules.Medium,
		},
		{
			reDebugSetupval,
			"debug.setupvalue() usage",
			"debug.setupvalue() modifies upvalues of a function, allowing modification of variables in enclosing scopes. This can bypass access controls and modify security-critical state.",
			rules.High,
		},
		{
			reDebugSetlocal,
			"debug.setlocal() usage",
			"debug.setlocal() modifies local variables in a running function's stack frame. This can alter control flow and bypass security checks.",
			rules.Medium,
		},
		{
			reDebugGetinfo,
			"debug.getinfo() usage",
			"debug.getinfo() exposes internal function metadata including source file paths, line numbers, and upvalue counts. This information can aid exploitation.",
			rules.Medium,
		},
		{
			reDebugGetlocal,
			"debug.getlocal() usage",
			"debug.getlocal() reads local variables from a running function's stack frame, potentially exposing sensitive data like passwords or tokens.",
			rules.Medium,
		},
		{
			reDebugGetupval,
			"debug.getupvalue() usage",
			"debug.getupvalue() reads upvalues of a function, potentially exposing variables from enclosing scopes including security-sensitive state.",
			rules.Medium,
		},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		for _, p := range patterns {
			if p.re.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      p.sev,
					SeverityLabel: p.sev.String(),
					Title:         p.title,
					Description:   p.desc,
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(line, 120),
					Suggestion:    "Remove debug library usage in production code. Set debug = nil in your sandbox environment. If debug functionality is needed, use logging instead.",
					CWEID:         "CWE-489",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"lua", "debug-library", "sandbox-escape"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(CommandInjection{})
	rules.Register(CodeInjection{})
	rules.Register(SQLInjection{})
	rules.Register(PathTraversal{})
	rules.Register(XSSOutput{})
	rules.Register(InsecureDeserialization{})
	rules.Register(OpenRedirect{})
	rules.Register(DebugLibrary{})
}
