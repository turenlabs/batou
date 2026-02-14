package injection

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
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
	// Requires template/tmpl context to avoid matching jwt.Parse, url.Parse, etc.
	reTemplateGoParse = regexp.MustCompile("(?i)(?:template|tmpl|tpl)(?:\\.[^.]*)*\\.\\s*Parse\\s*\\(\\s*[^\"'`\\s)]")
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

	// Indirect passthrough: MongoDB query method with object literal + nearby req input
	reNoSQLQueryMethodBrace = regexp.MustCompile(`(?i)\.(?:find|findOne|aggregate|updateOne|updateMany|deleteOne|deleteMany|remove|count|countDocuments)\s*\(\s*\{`)
	reNoSQLReqInputNearby   = regexp.MustCompile(`(?i)\breq\.(?:body|query|params)\b`)

	// MongoDB aggregation pipeline: $lookup with user-controlled "from" field
	reNoSQLAggLookup = regexp.MustCompile(
		`(?i)['"]\$lookup['"]\s*:\s*\{[^}]*['"]from['"]\s*:\s*` +
			`(?:[^"'\s{][^,}]*\+|req\.(?:body|query|params)|f["']|[^"'\s{,}]+\.(?:body|query|params|input|data))`)
	// MongoDB aggregation pipeline: $merge/$out with user-controlled collection
	reNoSQLAggMergeOut = regexp.MustCompile(
		`(?i)['"]\$` + `(?:merge|out)['"]\s*:\s*` +
			`(?:[^"'\s{][^,}]*\+|req\.(?:body|query|params)|f["']|[^"'\s{,}]+\.(?:body|query|params|input|data))`)
	// MongoDB aggregation pipeline: $group with user-controlled _id expression
	reNoSQLAggGroup = regexp.MustCompile(
		`(?i)['"]\$group['"]\s*:\s*\{[^}]*['"]\s*_id\s*['"]\s*:\s*` +
			`(?:[^"'\s{][^,}]*\+|req\.(?:body|query|params)|f["']|[^"'\s{,}]+\.(?:body|query|params|input|data))`)
	// MongoDB aggregation pipeline: $addFields with user-controlled expression
	reNoSQLAggAddFields = regexp.MustCompile(
		`(?i)['"]\$addFields['"]\s*:\s*` +
			`(?:req\.(?:body|query|params)|[^"'\s{,}]+\.(?:body|query|params|input|data))`)
)

// GraphQL Injection patterns (GTSS-INJ-008)
//
// Note: patterns use (?:[^"'\\]|\\.)* instead of [^"']* to correctly
// handle escaped quotes (e.g., \") inside string literals.
var (
	// String concat in GraphQL query string (all languages)
	reGQLConcatQuery = regexp.MustCompile(
		"(?i)(?:[\"']\\s*(?:query|mutation|subscription)\\s*(?:\\w+\\s*)?\\{(?:[^\"'\\\\]|\\\\.)*[\"']\\s*\\+)")
	// JS/TS: template literal with interpolation in GraphQL query
	reGQLTemplateLiteral = regexp.MustCompile(
		"(?i)`\\s*(?:query|mutation|subscription)[^`]*\\$" + "\\{")
	// Python: f-string in GraphQL query
	reGQLFStringPy = regexp.MustCompile(
		"(?i)f[\"']\\s*(?:query|mutation|subscription)\\s*(?:\\w+\\s*)?\\{(?:[^\"'\\\\]|\\\\.)*\\{")
	// Python: .format() in GraphQL query
	reGQLFormatPy = regexp.MustCompile(
		"(?i)[\"']\\s*(?:query|mutation|subscription)\\s*(?:\\w+\\s*)?\\{(?:[^\"'\\\\]|\\\\.)*[\"']\\s*\\.format\\(")
	// Python: % formatting in GraphQL query
	reGQLPercentPy = regexp.MustCompile(
		"(?i)[\"']\\s*(?:query|mutation|subscription)\\s*(?:\\w+\\s*)?\\{(?:[^\"'\\\\]|\\\\.)*%[sv](?:[^\"'\\\\]|\\\\.)*[\"']\\s*%")
	// Go: fmt.Sprintf in GraphQL query
	reGQLSprintfGo = regexp.MustCompile(
		"(?i)fmt\\.Sprintf\\(\\s*[\"']\\s*(?:query|mutation|subscription)\\s*(?:\\w+\\s*)?\\{(?:[^\"'\\\\]|\\\\.)*%[sv]")
	// Generic: graphql function/method call with string concat
	reGQLExecConcat = regexp.MustCompile(
		"(?i)(?:graphql|execute_query|execute_async|execute_sync|run_query)\\s*\\(\\s*(?:[\"'](?:[^\"'\\\\]|\\\\.)*[\"']\\s*\\+|[^\"'\\s,)]+\\s*\\+)")
	// Generic: gql tag or function with concat/interpolation (template literal)
	reGQLTagConcat = regexp.MustCompile(
		"(?i)(?:gql|graphql)\\s*\\(\\s*`[^`]*\\$" + "\\{")
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
		re      *regexp.Regexp
		conf    string
		desc    string
		skipFor []rules.Language // languages where this pattern should not apply
	}

	patterns := []pattern{
		{re: reCmdOsSystem, conf: "high", desc: "os.system/os.popen with dynamic argument"},
		{re: reCmdSubprocessShell, conf: "high", desc: "subprocess call with shell=True"},
		{re: reCmdExecCommandShell, conf: "high", desc: "exec.Command with shell interpreter and -c flag"},
		{re: reCmdExecCommandConcat, conf: "medium", desc: "exec.Command with string concatenation"},
		{re: reCmdChildProcess, conf: "high", desc: "child_process exec with dynamic argument"},
		{re: reCmdChildProcessExec, conf: "medium", desc: "child_process.exec usage (verify input is sanitized)"},
		{re: reCmdShellInterp, conf: "high", desc: "shell command with variable interpolation inside backticks/$()", skipFor: []rules.Language{rules.LangJavaScript, rules.LangTypeScript}},
		{re: reCmdRuntimeExec, conf: "high", desc: "Runtime.exec with string concatenation"},
		{re: reCmdProcessBuilder, conf: "low", desc: "ProcessBuilder usage (verify arguments are sanitized)"},
		{re: reCmdPHP, conf: "high", desc: "PHP shell function with variable argument"},
		{re: reCmdRuby, conf: "high", desc: "Ruby shell execution with string interpolation"},
		{re: reCmdSubprocessStr, conf: "medium", desc: "subprocess with string command (use list form instead)"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if len(p.skipFor) > 0 {
				skip := false
				for _, lang := range p.skipFor {
					if ctx.Language == lang {
						skip = true
						break
					}
				}
				if skip {
					continue
				}
			}
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
		{reNoSQLAggLookup, "high", "$lookup with user-controlled 'from' collection (aggregation pipeline injection)"},
		{reNoSQLAggMergeOut, "high", "$merge/$out with user-controlled collection name (aggregation pipeline injection)"},
		{reNoSQLAggGroup, "medium", "$group with user-controlled _id expression (aggregation pipeline injection)"},
		{reNoSQLAggAddFields, "medium", "$addFields with user-controlled expression (aggregation pipeline injection)"},
	}

	flaggedLines := make(map[int]bool)
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
				flaggedLines[i+1] = true
				break
			}
		}
	}

	// Indirect passthrough: MongoDB query methods with object literal where
	// req.body/req.query/req.params is destructured into variables nearby.
	if ctx.Language == rules.LangJavaScript || ctx.Language == rules.LangTypeScript {
		for i, line := range lines {
			if flaggedLines[i+1] || isCommentLine(line) {
				continue
			}
			if reNoSQLQueryMethodBrace.MatchString(line) && hasNearbyReqInput(lines, i) {
				matched := truncate(strings.TrimSpace(line), 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "NoSQL Injection: user input from request object used in MongoDB query",
					Description:   "Variables assigned from request body/query/params are used in a MongoDB query object. An attacker can inject query operators to manipulate the query logic.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Validate and sanitize all query inputs. Cast to expected types (e.g., String(value)) or use a schema validator to prevent operator injection.",
					CWEID:         "CWE-943",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"injection", "nosql", "mongodb"},
				})
			}
		}
	}

	return findings
}

// hasNearbyReqInput checks if req.body/req.query/req.params appears within
// 20 lines before the current line (typically within the same function scope).
func hasNearbyReqInput(lines []string, idx int) bool {
	start := idx - 20
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start : idx+1] {
		if reNoSQLReqInputNearby.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GTSS-INJ-008: GraphQL Injection
// ---------------------------------------------------------------------------

type GraphQLInjection struct{}

func (r GraphQLInjection) ID() string              { return "GTSS-INJ-008" }
func (r GraphQLInjection) Name() string            { return "GraphQL Injection" }
func (r GraphQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r GraphQLInjection) Description() string {
	return "Detects GraphQL queries constructed via string concatenation or formatting instead of using parameterized variables, which may allow GraphQL injection attacks."
}
func (r GraphQLInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangRuby, rules.LangPHP,
	}
}

func (r GraphQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
		lang rules.Language
	}

	patterns := []pattern{
		{reGQLConcatQuery, "high", "GraphQL query built with string concatenation", rules.LangAny},
		{reGQLTemplateLiteral, "high", "GraphQL query with template literal interpolation", rules.LangAny},
		{reGQLFStringPy, "high", "GraphQL query built with Python f-string", rules.LangPython},
		{reGQLFormatPy, "high", "GraphQL query built with .format()", rules.LangPython},
		{reGQLPercentPy, "high", "GraphQL query built with % formatting", rules.LangPython},
		{reGQLSprintfGo, "high", "GraphQL query built with fmt.Sprintf", rules.LangGo},
		{reGQLExecConcat, "medium", "GraphQL execute function with string concatenation", rules.LangAny},
		{reGQLTagConcat, "high", "gql/graphql tagged template with interpolation", rules.LangAny},
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
					Title:         "GraphQL Injection: " + p.desc,
					Description:   "GraphQL queries should use parameterized variables ($var syntax) instead of string concatenation or formatting with user-controlled input.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use GraphQL variables (e.g., query($id: ID!) { user(id: $id) { ... } }) and pass user input via the variables parameter.",
					CWEID:         "CWE-943",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "graphql"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-INJ-009: HTTP Header Injection
// ---------------------------------------------------------------------------

// HTTP Header Injection patterns
var (
	// Go: w.Header().Set/Add with r.URL.Query/r.FormValue/r.Header.Get
	reHeaderGoSet = regexp.MustCompile(`\bw\.Header\(\)\.(?:Set|Add)\s*\([^,]+,\s*r\.(?:URL\.Query\(\)\.Get|FormValue|Header\.Get|PostFormValue)\s*\(`)
	// Go: http.SetCookie or w.Header().Set("Set-Cookie", ...) with user input
	reHeaderGoSetCookie = regexp.MustCompile(`\bw\.Header\(\)\.(?:Set|Add)\s*\(\s*["']Set-Cookie["']`)
	// Node/Express: res.set/res.header/res.setHeader with req.query/req.params/req.body
	reHeaderJSSet = regexp.MustCompile(`\bres\.(?:set|header|setHeader)\s*\(\s*[^,]+,\s*req\.(?:query|params|body|headers)\s*[\[.]`)
	// Node/Express: res.set/header with variable that may come from request
	reHeaderJSSetVar = regexp.MustCompile(`\bres\.(?:set|header|setHeader)\s*\(\s*[^,]+,\s*[a-zA-Z_]\w*\s*\)`)
	// Python: response[header] = request.GET/POST/etc
	reHeaderPySet = regexp.MustCompile(`\bresponse\s*\[\s*["'][^"']+["']\s*\]\s*=\s*request\.(?:GET|POST|META|headers|args|form|values)\s*[\[.]`)
	// Python: Django/Flask set header with user input
	reHeaderPySetMethod = regexp.MustCompile(`\bresponse(?:\[["'][^"']+["']\]|\.headers\[["'][^"']+["']\])\s*=\s*(?:request\.|user_input|param|data)`)
	// Java: response.setHeader/addHeader with request.getParameter
	reHeaderJavaSet = regexp.MustCompile(`\bresponse\.(?:setHeader|addHeader)\s*\(\s*["'][^"']+["']\s*,\s*request\.(?:getParameter|getHeader)\s*\(`)
	// Java: HttpServletResponse header with user input
	reHeaderJavaSetVar = regexp.MustCompile(`\bresponse\.(?:setHeader|addHeader)\s*\(\s*["'][^"']+["']\s*,\s*[a-zA-Z_]\w*\s*\)`)
	// PHP: header() with user input
	reHeaderPHPSet = regexp.MustCompile(`\bheader\s*\(\s*(?:["'][^"']*["']\s*\.\s*\$(?:_GET|_POST|_REQUEST|_SERVER|input|param)|.*\$(?:_GET|_POST|_REQUEST)\s*\[)`)
)

type HTTPHeaderInjection struct{}

func (r HTTPHeaderInjection) ID() string              { return "GTSS-INJ-009" }
func (r HTTPHeaderInjection) Name() string            { return "HTTP Header Injection" }
func (r HTTPHeaderInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r HTTPHeaderInjection) Description() string {
	return "Detects HTTP response headers set with user-controlled input, which may allow header injection or response splitting via CRLF sequences."
}
func (r HTTPHeaderInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangGo, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangPython, rules.LangJava, rules.LangPHP,
	}
}

func (r HTTPHeaderInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
		lang rules.Language
	}

	patterns := []pattern{
		{reHeaderGoSet, "high", "HTTP header set with request parameter value", rules.LangGo},
		{reHeaderJSSet, "high", "HTTP header set with req.query/params/body value", rules.LangAny},
		{reHeaderPySet, "high", "HTTP response header set with request input", rules.LangPython},
		{reHeaderPySetMethod, "high", "HTTP response header set with request input", rules.LangPython},
		{reHeaderJavaSet, "high", "HTTP response header set with request.getParameter()", rules.LangJava},
		{reHeaderPHPSet, "high", "PHP header() with user input variable", rules.LangPHP},
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
				// Check for CRLF sanitization nearby
				if hasHeaderSanitization(lines, i) {
					continue
				}
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "HTTP Header Injection: " + p.desc,
					Description:   "HTTP response headers set with user-controlled input can allow header injection via CRLF (\\r\\n) sequences. An attacker can inject arbitrary headers or split the HTTP response.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Sanitize header values by stripping or rejecting \\r and \\n characters. Use framework-provided header setting methods that auto-sanitize. Never pass raw user input as header values.",
					CWEID:         "CWE-113",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "header-injection", "crlf", "response-splitting"},
				})
				break
			}
		}
	}
	return findings
}

// hasHeaderSanitization checks for CRLF sanitization patterns near the given line.
func hasHeaderSanitization(lines []string, idx int) bool {
	start := idx - 10
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		// Check for CRLF stripping/replacing
		if strings.Contains(l, `\r`) || strings.Contains(l, `\n`) ||
			strings.Contains(l, "\\r") || strings.Contains(l, "\\n") {
			if strings.Contains(l, "Replace") || strings.Contains(l, "replace") ||
				strings.Contains(l, "strip") || strings.Contains(l, "sanitize") ||
				strings.Contains(l, "reject") || strings.Contains(l, "Split") {
				return true
			}
		}
		// Framework-level sanitization
		if strings.Contains(l, "encodeURIComponent") || strings.Contains(l, "url.QueryEscape") ||
			strings.Contains(l, "urllib.parse.quote") || strings.Contains(l, "URLEncoder.encode") {
			return true
		}
	}
	return false
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
	rules.Register(GraphQLInjection{})
	rules.Register(HTTPHeaderInjection{})
}
