package injection

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// SQL Injection patterns (GTSS-INJ-001)
var (
	// Go: fmt.Sprintf with SQL keywords
	reSQLSprintfGo = regexp.MustCompile(`(?i)fmt\.Sprintf\(\s*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*%[svdq]`)
	// Go: string concat with SQL keywords
	reSQLConcatGo = regexp.MustCompile(`(?i)(?:"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*"\s*\+|\+\s*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b)`)
	// Python: f-string with SQL keywords
	reSQLFStringPy = regexp.MustCompile(`(?i)f["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"']*\{`)
	// Python: % formatting with SQL keywords
	reSQLPercentPy = regexp.MustCompile(`(?i)["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"']*["']\s*%\s*[(\w]`)
	// Python: .format() with SQL keywords
	reSQLFormatPy = regexp.MustCompile(`(?i)["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"']*["']\s*\.format\(`)
	// Python: cursor.execute with string concat/format
	reSQLExecConcatPy = regexp.MustCompile(`(?i)(?:cursor|conn|connection|db)\s*\.\s*execute\(\s*(?:f["']|["'][^"']*["']\s*%|["'][^"']*["']\s*\.format|[^"',)]+\+)`)
	// Java/JS/C#: string concat with SQL keywords
	reSQLConcatGeneric = regexp.MustCompile(`(?i)["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"']*["']\s*\+\s*\w`)
	// JS/Java: .query() / .execute() with concat
	reSQLQueryConcat = regexp.MustCompile(`(?i)\.(?:query|execute|exec|prepare)\(\s*["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"']*["']\s*\+`)
	// JS template literal with SQL keywords
	reSQLTemplateLiteral = regexp.MustCompile("(?i)`[^`]*\\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\\b[^`]*\\$\\{")
	// PHP: SQL with variable interpolation (double-quoted strings)
	reSQLPHP = regexp.MustCompile(`(?i)"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*\$\w+`)
	// Ruby: SQL with interpolation (double-quoted strings)
	reSQLRuby = regexp.MustCompile(`(?i)"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|FROM|WHERE|SET|INTO|VALUES)\b[^"]*#\{`)
	// Ruby: ActiveRecord .where with string interpolation
	reSQLRubyWhere = regexp.MustCompile(`(?i)\.where\(\s*"[^"]*#\{`)
)

// Command Injection patterns (GTSS-INJ-002)
var (
	// Python: os.system / os.popen with variable
	reCmdOsSystem = regexp.MustCompile(`(?i)\bos\.(system|popen|popen2|popen3|popen4)\s*\((?:\s*f["']|[^)"']*\+|[^)"']*%|.*\.format\()`)
	// Python: subprocess with shell=True
	reCmdSubprocessShell = regexp.MustCompile(`(?i)\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True`)
	// Python: subprocess with string (not list) and shell=True
	reCmdSubprocessStr = regexp.MustCompile(`(?i)\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\(\s*f?["']`)
	// Go: exec.Command("sh", "-c", ...) or exec.Command("bash", "-c", ...)
	reCmdExecCommandShell = regexp.MustCompile(`(?i)\bexec\.Command(?:Context)?\(\s*["'](?:sh|bash|cmd|/bin/sh|/bin/bash|cmd\.exe)["']\s*,\s*["']-c["']`)
	// Go: exec.Command with variable concat
	reCmdExecCommandConcat = regexp.MustCompile(`(?i)\bexec\.Command(?:Context)?\(\s*[^"'\s)][^,)]*[+]`)
	// JS: child_process.exec/execSync with variable
	reCmdChildProcess = regexp.MustCompile(`(?i)\b(?:child_process\s*\.\s*)?(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:` + "`[^`]*\\$\\{" + `|[^"'\x60\s,)]+\s*[+]|f?["'][^"']*["']\s*\+)`)
	// JS: require("child_process").exec with concat
	reCmdChildProcessExec = regexp.MustCompile(`(?i)require\(\s*["']child_process["']\s*\)\s*\.exec\s*\(`)
	// Shell: backtick or $() with variable
	reCmdShellInterp = regexp.MustCompile("(?i)(?:`[^`]*\\$[{(]|\\$\\([^)]*\\$[{(])")
	// Java: Runtime.exec with concat
	reCmdRuntimeExec = regexp.MustCompile(`(?i)\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*(?:["'][^"']*["']\s*\+|\w+[^"')]+\+)`)
	// Java: ProcessBuilder with concat
	reCmdProcessBuilder = regexp.MustCompile(`(?i)\bnew\s+ProcessBuilder\s*\(`)
	// PHP: system/exec/passthru/shell_exec with variable
	reCmdPHP = regexp.MustCompile(`(?i)\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$`)
	// Ruby: system/exec/backtick with interpolation
	reCmdRuby = regexp.MustCompile("(?i)(?:\\b(?:system|exec|%x)\\s*\\(\\s*[\"'][^\"']*#\\{|`[^`]*#\\{)")
)

// Code Injection patterns (GTSS-INJ-003)
var (
	// eval() with variable argument (not a string literal)
	reCodeEval = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:[^"'\x60\s);][^);]*|f["']|["'][^"']*["']\s*[+%]|["'][^"']*["']\s*\.format)`)
	// exec() with variable (Python)
	reCodeExecPy = regexp.MustCompile(`(?i)\bexec\s*\(\s*(?:[^"'\s);][^);]*|f["']|["'][^"']*["']\s*[+%]|["'][^"']*["']\s*\.format)`)
	// JS: new Function() constructor with variable
	reCodeFunctionCtor = regexp.MustCompile(`(?i)\bnew\s+Function\s*\(`)
	// Python: compile() with variable
	reCodeCompile = regexp.MustCompile(`(?i)\bcompile\s*\(\s*(?:[^"'\s);][^);]*|f["'])`)
	// JS: setTimeout/setInterval with string
	reCodeTimerString = regexp.MustCompile(`(?i)\b(?:setTimeout|setInterval)\s*\(\s*["'\x60]`)
	// Safe patterns to exclude
	reCodeSafeAstLiteral = regexp.MustCompile(`(?i)\bast\.literal_eval\b`)
	reCodeSafeJsonParse  = regexp.MustCompile(`(?i)\bJSON\.parse\b`)
)

// LDAP Injection patterns (GTSS-INJ-004)
var (
	// LDAP filter with string concat
	reLDAPConcat = regexp.MustCompile(`(?i)(?:["']\s*\(\s*(?:&|\|)\s*\(\s*\w+\s*=\s*["']\s*\+|["']\(\w+=["']\s*\+)`)
	// LDAP search with format string
	reLDAPFormat = regexp.MustCompile(`(?i)(?:ldap|ldap3|python-ldap)\S*\.\s*(?:search|search_s|search_ext|search_ext_s|bind)\s*\([^)]*(?:\+|%[sv]|\.format\(|f["'])`)
	// Direct LDAP filter construction
	reLDAPFilter = regexp.MustCompile(`(?i)(?:search_filter|ldap_filter|filter)\s*=\s*(?:f["'][^"']*\{|["'][^"']*["']\s*[+%]|["'][^"']*["']\s*\.format)`)
)

// Template Injection patterns (GTSS-INJ-005)
var (
	// Python: render_template_string with variable
	reTemplateRenderString = regexp.MustCompile(`(?i)\brender_template_string\s*\(\s*[^"'\s)]`)
	// Python: Template() with variable
	reTemplateCtorVar = regexp.MustCompile(`(?i)\b(?:Template|Jinja2)\s*\(\s*(?:[^"'\s)][^)]*|f["']|["'][^"']*["']\s*[+%]|["'][^"']*["']\s*\.format)`)
	// Python: jinja2 from_string with variable
	reTemplateFromString = regexp.MustCompile(`(?i)\.from_string\s*\(\s*[^"'\s)]`)
	// JS: template engines with variable
	reTemplateJSRender = regexp.MustCompile(`(?i)(?:ejs|pug|nunjucks|handlebars|mustache)\s*\.\s*(?:render|compile|renderString)\s*\(\s*[^"'\s)]`)
	// PHP: Twig/Blade raw user input
	reTemplatePHP = regexp.MustCompile(`(?i)\$(?:twig|blade|smarty)\s*->\s*(?:render|display|createTemplate)\s*\(\s*\$`)
	// Ruby: ERB with variable
	reTemplateRuby = regexp.MustCompile(`(?i)\bERB\.new\s*\(\s*[^"'\s)]`)
	// Go: text/template or html/template Parse with variable (not a string literal or backtick)
	reTemplateGoParse = regexp.MustCompile("(?i)\\.\\s*Parse\\s*\\(\\s*[^\"'`\\s)]")
	// Java: Thymeleaf/Freemarker/Velocity templateEngine.process with variable
	reTemplateJavaEngine = regexp.MustCompile(`(?i)(?:templateEngine|template|engine)\s*\.\s*(?:process|evaluate|merge)\s*\(\s*[^"'\s)]`)
)

// XPath Injection patterns (GTSS-INJ-006)
var (
	// XPath with string concat
	reXPathConcat = regexp.MustCompile(`(?i)(?:xpath|selectNodes|selectSingleNode|evaluate|querySelector)\s*\(\s*(?:"[^"]*"|'[^']*')\s*\+`)
	// XPath with format string
	reXPathFormat = regexp.MustCompile(`(?i)(?:xpath|selectNodes|selectSingleNode|evaluate)\s*\(\s*(?:f["']|.*\.format\(|fmt\.Sprintf)`)
	// XPath query construction
	reXPathBuild = regexp.MustCompile(`(?i)(?:xpath_expr|xpath_query|xpath_string)\s*=\s*(?:f["'][^"']*\{|["'][^"']*["']\s*[+%]|["'][^"']*["']\s*\.format)`)
	// Generic XPath pattern
	reXPathGeneric = regexp.MustCompile(`(?i)["'][^"']*(?://|/)\w+\s*\[\s*@?\w+\s*=\s*["']\s*\+`)
)

// NoSQL Injection patterns (GTSS-INJ-007)
var (
	// MongoDB: $where with string
	reNoSQLWhere = regexp.MustCompile(`(?i)['"]\$where['"]\s*:\s*(?:f?["'][^"']*\{|"[^"]*"\s*\+|'[^']*'\s*\+|[^"'\s][^,}]*)`)
	// MongoDB: $regex with user input
	reNoSQLRegex = regexp.MustCompile(`(?i)['"]\$regex['"]\s*:\s*(?:[^"'\s{][^,}]*|f["'])`)
	// JSON.parse in query
	reNoSQLJSONParse = regexp.MustCompile(`(?i)\.(?:find|findOne|aggregate|updateOne|updateMany|deleteOne|deleteMany|remove|count|countDocuments)\s*\(\s*JSON\.parse\s*\(`)
	// MongoDB query with concat
	reNoSQLQueryConcat = regexp.MustCompile(`(?i)\.(?:find|findOne|aggregate|updateOne|updateMany|deleteOne|deleteMany|remove|count|countDocuments)\s*\(\s*(?:["'][^"']*["']\s*\+|\{[^}]*:\s*[^"'\s{][^,}]*\+)`)
	// Eval-like in MongoDB
	reNoSQLEval = regexp.MustCompile(`(?i)\.(?:mapReduce|group)\s*\([^)]*(?:function|=>)`)
	// Direct pass-through of req.body/req.query/req.params to MongoDB query methods
	reNoSQLDirectPassthrough = regexp.MustCompile(`(?i)\.(?:find|findOne|aggregate|updateOne|updateMany|deleteOne|deleteMany|remove|count|countDocuments)\s*\(\s*req\.(?:body|query|params)\b`)
)

// ---------------------------------------------------------------------------
// Comment / string detection (false positive reduction)
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*(?://|#|--|;|%|/\*)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// truncate ensures matched text doesn't exceed maxLen characters.
func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// GTSS-INJ-001: SQL Injection
// ---------------------------------------------------------------------------

type SQLInjection struct{}

func (r SQLInjection) ID() string              { return "GTSS-INJ-001" }
func (r SQLInjection) Name() string            { return "SQL Injection" }
func (r SQLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r SQLInjection) Description() string {
	return "Detects SQL queries constructed via string concatenation or formatting, which may allow SQL injection attacks."
}
func (r SQLInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp,
	}
}

func (r SQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		lang rules.Language // rules.LangAny means all languages
	}

	patterns := []pattern{
		{reSQLSprintfGo, "high", rules.LangGo},
		{reSQLConcatGo, "high", rules.LangAny},
		{reSQLFStringPy, "high", rules.LangPython},
		{reSQLPercentPy, "high", rules.LangPython},
		{reSQLFormatPy, "high", rules.LangPython},
		{reSQLExecConcatPy, "high", rules.LangPython},
		{reSQLConcatGeneric, "high", rules.LangAny},
		{reSQLQueryConcat, "high", rules.LangAny},
		{reSQLTemplateLiteral, "high", rules.LangAny},
		{reSQLPHP, "medium", rules.LangPHP},
		{reSQLRuby, "medium", rules.LangRuby},
		{reSQLRubyWhere, "high", rules.LangRuby},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if p.lang != rules.LangAny && p.lang != ctx.Language {
				continue
			}
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SQL Injection: query built with string concatenation/formatting",
					Description:   "SQL queries should use parameterized queries or prepared statements, never string concatenation or formatting with user-controlled input.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use parameterized queries (e.g., db.Query(\"SELECT ... WHERE id = ?\", id)) instead of string concatenation.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "sql"},
				})
				break // one finding per line
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-INJ-002: Command Injection
// ---------------------------------------------------------------------------

type CommandInjection struct{}

func (r CommandInjection) ID() string              { return "GTSS-INJ-002" }
func (r CommandInjection) Name() string            { return "Command Injection" }
func (r CommandInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r CommandInjection) Description() string {
	return "Detects shell command construction with unsanitized variables, which may allow OS command injection."
}
func (r CommandInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangShell, rules.LangCSharp,
	}
}

func (r CommandInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	patterns := []pattern{
		{reCmdOsSystem, "high", "os.system/os.popen with dynamic argument"},
		{reCmdSubprocessShell, "high", "subprocess call with shell=True"},
		{reCmdExecCommandShell, "high", "exec.Command with shell interpreter and -c flag"},
		{reCmdExecCommandConcat, "medium", "exec.Command with string concatenation"},
		{reCmdChildProcess, "high", "child_process exec with dynamic argument"},
		{reCmdChildProcessExec, "medium", "child_process.exec usage (verify input is sanitized)"},
		{reCmdShellInterp, "high", "shell command with variable interpolation inside backticks/$()"},
		{reCmdRuntimeExec, "high", "Runtime.exec with string concatenation"},
		{reCmdProcessBuilder, "low", "ProcessBuilder usage (verify arguments are sanitized)"},
		{reCmdPHP, "high", "PHP shell function with variable argument"},
		{reCmdRuby, "high", "Ruby shell execution with string interpolation"},
		{reCmdSubprocessStr, "medium", "subprocess with string command (use list form instead)"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Command Injection: " + p.desc,
					Description:   "Shell commands must not be built from unsanitized input. An attacker could inject arbitrary OS commands.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use parameterized command execution (e.g., exec.Command with separate args) and validate/sanitize all inputs.",
					CWEID:         "CWE-78",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "command"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-INJ-003: Code Injection
// ---------------------------------------------------------------------------

type CodeInjection struct{}

func (r CodeInjection) ID() string              { return "GTSS-INJ-003" }
func (r CodeInjection) Name() string            { return "Code Injection" }
func (r CodeInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r CodeInjection) Description() string {
	return "Detects use of eval(), exec(), Function() constructor, and similar dynamic code execution with potentially untrusted input."
}
func (r CodeInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangRuby, rules.LangPHP,
	}
}

func (r CodeInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	patterns := []pattern{
		{reCodeEval, "high", "eval() with dynamic argument"},
		{reCodeExecPy, "high", "exec() with dynamic argument"},
		{reCodeFunctionCtor, "high", "new Function() constructor (equivalent to eval)"},
		{reCodeCompile, "medium", "compile() with dynamic source"},
		{reCodeTimerString, "medium", "setTimeout/setInterval with string argument (implicit eval)"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		// Skip safe patterns
		if reCodeSafeAstLiteral.MatchString(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				// Additional filter: skip JSON.parse inside eval detection
				if p.re == reCodeEval && reCodeSafeJsonParse.MatchString(line) {
					continue
				}
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Code Injection: " + p.desc,
					Description:   "Dynamic code execution with untrusted input can lead to arbitrary code execution. Avoid eval/exec with user-controlled data.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Avoid eval/exec. Use safe alternatives like ast.literal_eval (Python), JSON.parse (JS), or refactor to avoid dynamic code execution.",
					CWEID:         "CWE-94",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "code-execution"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-INJ-004: LDAP Injection
// ---------------------------------------------------------------------------

type LDAPInjection struct{}

func (r LDAPInjection) ID() string              { return "GTSS-INJ-004" }
func (r LDAPInjection) Name() string            { return "LDAP Injection" }
func (r LDAPInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r LDAPInjection) Description() string {
	return "Detects LDAP queries built with string concatenation or formatting, which may allow LDAP injection."
}
func (r LDAPInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangCSharp, rules.LangRuby,
	}
}

func (r LDAPInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
	}

	patterns := []pattern{
		{reLDAPConcat, "high"},
		{reLDAPFormat, "high"},
		{reLDAPFilter, "high"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "LDAP Injection: query built with string concatenation/formatting",
					Description:   "LDAP queries must not be built from unsanitized input. Use parameterized LDAP filters or escape special characters.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use LDAP filter escaping functions (e.g., ldap.EscapeFilter in Go, ldap3.utils.escape_filter_chars in Python) or parameterized queries.",
					CWEID:         "CWE-90",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "ldap"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-INJ-005: Template Injection (SSTI)
// ---------------------------------------------------------------------------

type TemplateInjection struct{}

func (r TemplateInjection) ID() string              { return "GTSS-INJ-005" }
func (r TemplateInjection) Name() string            { return "Server-Side Template Injection" }
func (r TemplateInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r TemplateInjection) Description() string {
	return "Detects server-side template injection where user input is rendered directly in templates."
}
func (r TemplateInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangRuby,
	}
}

func (r TemplateInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	patterns := []pattern{
		{reTemplateRenderString, "high", "render_template_string() with dynamic argument"},
		{reTemplateCtorVar, "high", "Template() constructor with dynamic argument"},
		{reTemplateFromString, "high", "from_string() with dynamic argument"},
		{reTemplateJSRender, "medium", "template engine render with dynamic argument"},
		{reTemplatePHP, "high", "PHP template engine with variable argument"},
		{reTemplateRuby, "high", "ERB.new with dynamic argument"},
		{reTemplateGoParse, "high", "template Parse() with dynamic argument"},
		{reTemplateJavaEngine, "high", "template engine process/evaluate with dynamic argument"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Template Injection: " + p.desc,
					Description:   "User-controlled input passed directly to template engines can lead to server-side template injection (SSTI) and remote code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Never pass user input as the template source. Use render_template with a file path and pass user data as template variables.",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "ssti", "template"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-INJ-006: XPath Injection
// ---------------------------------------------------------------------------

type XPathInjection struct{}

func (r XPathInjection) ID() string              { return "GTSS-INJ-006" }
func (r XPathInjection) Name() string            { return "XPath Injection" }
func (r XPathInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r XPathInjection) Description() string {
	return "Detects XPath queries built with string concatenation, which may allow XPath injection."
}
func (r XPathInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangCSharp, rules.LangRuby,
	}
}

func (r XPathInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
	}

	patterns := []pattern{
		{reXPathConcat, "high"},
		{reXPathFormat, "high"},
		{reXPathBuild, "high"},
		{reXPathGeneric, "medium"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "XPath Injection: query built with string concatenation",
					Description:   "XPath queries built with string concatenation can allow attackers to modify query logic and access unauthorized data.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use parameterized XPath queries or XPath variable resolution. Escape special XPath characters in user input.",
					CWEID:         "CWE-643",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "xpath"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-INJ-007: NoSQL Injection
// ---------------------------------------------------------------------------

type NoSQLInjection struct{}

func (r NoSQLInjection) ID() string              { return "GTSS-INJ-007" }
func (r NoSQLInjection) Name() string            { return "NoSQL Injection" }
func (r NoSQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r NoSQLInjection) Description() string {
	return "Detects NoSQL/MongoDB queries with unsafe patterns such as $where with string concatenation, unsanitized $regex, or JSON.parse of user input in queries."
}
func (r NoSQLInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript, rules.LangPython,
		rules.LangJava, rules.LangGo, rules.LangRuby, rules.LangPHP,
	}
}

func (r NoSQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	patterns := []pattern{
		{reNoSQLWhere, "high", "$where operator with dynamic string"},
		{reNoSQLRegex, "medium", "$regex with unsanitized input"},
		{reNoSQLJSONParse, "high", "JSON.parse of user input in database query"},
		{reNoSQLQueryConcat, "medium", "NoSQL query with string concatenation"},
		{reNoSQLEval, "medium", "mapReduce/group with function (potential code injection)"},
		{reNoSQLDirectPassthrough, "high", "req.body/req.query/req.params passed directly to MongoDB query (NoSQL injection)"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "NoSQL Injection: " + p.desc,
					Description:   "NoSQL queries with unsanitized user input can allow query manipulation, data exfiltration, or server-side code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Sanitize and validate all query inputs. Avoid $where with user input. Use MongoDB driver's built-in query builders with typed parameters.",
					CWEID:         "CWE-943",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "nosql", "mongodb"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(SQLInjection{})
	rules.Register(CommandInjection{})
	rules.Register(CodeInjection{})
	rules.Register(LDAPInjection{})
	rules.Register(TemplateInjection{})
	rules.Register(XPathInjection{})
	rules.Register(NoSQLInjection{})
}
