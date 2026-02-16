package lua

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for Lua extension rules (BATOU-LUA-009 .. BATOU-LUA-014)
// ---------------------------------------------------------------------------

// LUA-009: loadstring with user input (explicit user-input pattern)
var (
	reLoadstringUserInput = regexp.MustCompile(`loadstring\s*\(\s*(?:ngx\.(?:var|req)|arg\[|io\.read|KEYS\[|ARGV\[|get_body_data|get_uri_args)`)
	reLoadstringConcat    = regexp.MustCompile(`loadstring\s*\(\s*.*\.\.\s*(?:ngx\.(?:var|req)|arg\[|io\.read|KEYS\[|ARGV\[)`)
)

// LUA-010: os.execute with variable concatenation (more specific patterns)
var (
	reOsExecVarConcat  = regexp.MustCompile(`os\.execute\s*\(\s*[a-zA-Z_]\w*\s*\.\.\s*`)
	reOsExecFormatUser = regexp.MustCompile(`os\.execute\s*\(\s*string\.format\s*\(`)
)

// LUA-011: io.popen with user input
var (
	reIoPopenUserInput = regexp.MustCompile(`io\.popen\s*\(\s*(?:ngx\.(?:var|req)|arg\[|io\.read|KEYS\[|ARGV\[)`)
	reIoPopenConcat    = regexp.MustCompile(`io\.popen\s*\(\s*[a-zA-Z_]\w*\s*\.\.\s*`)
	reIoPopenFormat    = regexp.MustCompile(`io\.popen\s*\(\s*string\.format\s*\(`)
)

// LUA-012: dofile/loadfile with user-controlled path
var (
	reDofileUserInput   = regexp.MustCompile(`dofile\s*\(\s*(?:ngx\.(?:var|req)|arg\[|io\.read|KEYS\[|ARGV\[)`)
	reLoadfileUserInput = regexp.MustCompile(`loadfile\s*\(\s*(?:ngx\.(?:var|req)|arg\[|io\.read|KEYS\[|ARGV\[)`)
	reDofileConcat      = regexp.MustCompile(`dofile\s*\(\s*[a-zA-Z_]\w*\s*\.\.\s*`)
	reLoadfileConcat    = regexp.MustCompile(`loadfile\s*\(\s*[a-zA-Z_]\w*\s*\.\.\s*`)
)

// LUA-013: SQL query string concat (common in game servers)
var (
	reSQLConcatGame    = regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*["']\s*\.\.\s*(?:player|user|name|id|input|data|param)`)
	reSQLQueryExec     = regexp.MustCompile(`(?i)(?:query|execute|exec)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\s+.*["']\s*\.\.\s*`)
	reSQLFormatGame    = regexp.MustCompile(`(?i)string\.format\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*%s`)
)

// LUA-014: debug library enabled in production
var (
	reDebugRequire     = regexp.MustCompile(`require\s*\(\s*["']debug["']\s*\)`)
	reDebugLibUse      = regexp.MustCompile(`debug\.(?:getregistry|traceback|getfenv|setfenv)\s*\(`)
	reDebugProdCheck   = regexp.MustCompile(`(?i)(?:production|prod|release|deploy)`)
)

func init() {
	rules.Register(&LuaLoadstringUser{})
	rules.Register(&LuaOsExecVar{})
	rules.Register(&LuaIoPopenUser{})
	rules.Register(&LuaDofileLoadfileUser{})
	rules.Register(&LuaSQLConcatGame{})
	rules.Register(&LuaDebugProd{})
}

// ---------------------------------------------------------------------------
// BATOU-LUA-009: Lua loadstring with user input
// ---------------------------------------------------------------------------

type LuaLoadstringUser struct{}

func (r LuaLoadstringUser) ID() string                      { return "BATOU-LUA-009" }
func (r LuaLoadstringUser) Name() string                    { return "LuaLoadstringUser" }
func (r LuaLoadstringUser) Description() string             { return "Detects Lua loadstring() with explicit user input sources (ngx.var, ngx.req, arg[], io.read), enabling arbitrary code execution." }
func (r LuaLoadstringUser) DefaultSeverity() rules.Severity { return rules.Critical }
func (r LuaLoadstringUser) Languages() []rules.Language     { return []rules.Language{rules.LangLua} }

func (r LuaLoadstringUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if m := reLoadstringUserInput.FindString(line); m != "" {
			matched = m
		} else if m := reLoadstringConcat.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Lua loadstring() with user input",
				Description:   "loadstring() is called with data from a known user input source (ngx.var, ngx.req, arg[], io.read, Redis KEYS/ARGV). An attacker can inject arbitrary Lua code including os.execute(), file operations, and network calls.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never pass user input to loadstring(). Use cjson.decode() for data parsing. For dynamic behavior, use a dispatch table: local actions = {action1 = func1}; actions[user_action](). Sandbox loadstring with setfenv if unavoidable.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "loadstring", "code-injection", "user-input"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-LUA-010: Lua os.execute with variable concatenation
// ---------------------------------------------------------------------------

type LuaOsExecVar struct{}

func (r LuaOsExecVar) ID() string                      { return "BATOU-LUA-010" }
func (r LuaOsExecVar) Name() string                    { return "LuaOsExecVar" }
func (r LuaOsExecVar) Description() string             { return "Detects Lua os.execute() with variable concatenation or string.format, enabling command injection." }
func (r LuaOsExecVar) DefaultSeverity() rules.Severity { return rules.High }
func (r LuaOsExecVar) Languages() []rules.Language     { return []rules.Language{rules.LangLua} }

func (r LuaOsExecVar) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reOsExecVarConcat.FindString(line); m != "" {
			matched = m
			desc = "os.execute() with variable concatenation via .. operator. If the variable contains shell metacharacters, an attacker can inject arbitrary commands."
		} else if m := reOsExecFormatUser.FindString(line); m != "" {
			matched = m
			desc = "os.execute() with string.format(). The format specifiers (%s) embed variables into the command string without shell escaping."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Lua os.execute() with variable concatenation",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Avoid os.execute() with dynamic input. Use a whitelist of allowed commands. If shell execution is necessary, validate and escape all interpolated values. Consider using lua-resty-shell for OpenResty.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "os-execute", "command-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-LUA-011: Lua io.popen with user input
// ---------------------------------------------------------------------------

type LuaIoPopenUser struct{}

func (r LuaIoPopenUser) ID() string                      { return "BATOU-LUA-011" }
func (r LuaIoPopenUser) Name() string                    { return "LuaIoPopenUser" }
func (r LuaIoPopenUser) Description() string             { return "Detects Lua io.popen() with user input or variable concatenation, enabling command injection via shell pipe." }
func (r LuaIoPopenUser) DefaultSeverity() rules.Severity { return rules.High }
func (r LuaIoPopenUser) Languages() []rules.Language     { return []rules.Language{rules.LangLua} }

func (r LuaIoPopenUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if m := reIoPopenUserInput.FindString(line); m != "" {
			matched = m
		} else if m := reIoPopenConcat.FindString(line); m != "" {
			matched = m
		} else if m := reIoPopenFormat.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Lua io.popen() with user input",
				Description:   "io.popen() executes a shell command and returns a file handle. User-controlled data in the command string allows injection of arbitrary commands via shell metacharacters (;, |, &&, $()).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Avoid io.popen() with user input. Validate and whitelist allowed commands. For OpenResty, use ngx.pipe or lua-resty-shell with separate argument lists.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "io-popen", "command-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-LUA-012: Lua dofile/loadfile with user-controlled path
// ---------------------------------------------------------------------------

type LuaDofileLoadfileUser struct{}

func (r LuaDofileLoadfileUser) ID() string                      { return "BATOU-LUA-012" }
func (r LuaDofileLoadfileUser) Name() string                    { return "LuaDofileLoadfileUser" }
func (r LuaDofileLoadfileUser) Description() string             { return "Detects Lua dofile()/loadfile() with user-controlled path, enabling arbitrary Lua file execution." }
func (r LuaDofileLoadfileUser) DefaultSeverity() rules.Severity { return rules.High }
func (r LuaDofileLoadfileUser) Languages() []rules.Language     { return []rules.Language{rules.LangLua} }

func (r LuaDofileLoadfileUser) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var title string

		if m := reDofileUserInput.FindString(line); m != "" {
			matched = m
			title = "Lua dofile() with user-controlled path"
		} else if m := reLoadfileUserInput.FindString(line); m != "" {
			matched = m
			title = "Lua loadfile() with user-controlled path"
		} else if m := reDofileConcat.FindString(line); m != "" {
			matched = m
			title = "Lua dofile() with concatenated path"
		} else if m := reLoadfileConcat.FindString(line); m != "" {
			matched = m
			title = "Lua loadfile() with concatenated path"
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "dofile()/loadfile() with a user-controlled path allows an attacker to load and execute arbitrary Lua files from the filesystem. Combined with path traversal (../), this can execute Lua files outside the intended directory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use a whitelist of allowed file paths. Validate that the resolved path starts with the allowed base directory. Never pass user input directly to dofile/loadfile.",
				CWEID:         "CWE-94",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "dofile", "loadfile", "code-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-LUA-013: Lua SQL query string concat (common in game servers)
// ---------------------------------------------------------------------------

type LuaSQLConcatGame struct{}

func (r LuaSQLConcatGame) ID() string                      { return "BATOU-LUA-013" }
func (r LuaSQLConcatGame) Name() string                    { return "LuaSQLConcatGame" }
func (r LuaSQLConcatGame) Description() string             { return "Detects Lua SQL query string concatenation with player/user variables, common in game server Lua scripting." }
func (r LuaSQLConcatGame) DefaultSeverity() rules.Severity { return rules.High }
func (r LuaSQLConcatGame) Languages() []rules.Language     { return []rules.Language{rules.LangLua} }

func (r LuaSQLConcatGame) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string

		if m := reSQLConcatGame.FindString(line); m != "" {
			matched = m
		} else if m := reSQLQueryExec.FindString(line); m != "" {
			matched = m
		} else if m := reSQLFormatGame.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Lua SQL query with string concatenation",
				Description:   "A SQL query is built by concatenating player/user variables using the .. operator or string.format(%s). In game server environments, player names or input can contain SQL injection payloads that modify the query.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use parameterized queries or escape user input with the database driver's escape function. For lua-resty-mysql, use ngx.quote_sql_str(). For game servers, validate player input against a strict character whitelist.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"lua", "sql-injection", "game-server", "concat"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-LUA-014: Lua debug library enabled in production
// ---------------------------------------------------------------------------

type LuaDebugProd struct{}

func (r LuaDebugProd) ID() string                      { return "BATOU-LUA-014" }
func (r LuaDebugProd) Name() string                    { return "LuaDebugProd" }
func (r LuaDebugProd) Description() string             { return "Detects Lua debug library require/usage in production-like code, which can be used for sandbox escape and information disclosure." }
func (r LuaDebugProd) DefaultSeverity() rules.Severity { return rules.Medium }
func (r LuaDebugProd) Languages() []rules.Language     { return []rules.Language{rules.LangLua} }

func (r LuaDebugProd) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}

		var matched string
		var desc string

		if m := reDebugRequire.FindString(line); m != "" {
			matched = m
			desc = "The debug library is explicitly required. The debug library provides access to internal state (getupvalue, setlocal, sethook) that can bypass sandboxes and access sensitive data."
		} else if m := reDebugLibUse.FindString(line); m != "" {
			matched = m
			desc = "A debug library function (getregistry, traceback, getfenv, setfenv) is used. These functions expose internal Lua state and can be exploited to escape sandboxed environments."
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Lua debug library enabled in production",
				Description:   desc,
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Remove the debug library in production. Set debug = nil in your sandbox environment. If stack traces are needed, use xpcall with a custom error handler instead of debug.traceback.",
				CWEID:         "CWE-489",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"lua", "debug-library", "sandbox-escape", "production"},
			})
		}
	}
	return findings
}
