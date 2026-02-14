package luaast

import (
	"strings"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

// LuaASTAnalyzer performs AST-based security analysis of Lua source code.
type LuaASTAnalyzer struct{}

func init() {
	rules.Register(&LuaASTAnalyzer{})
}

func (l *LuaASTAnalyzer) ID() string                        { return "GTSS-LUA-AST" }
func (l *LuaASTAnalyzer) Name() string                      { return "Lua AST Security Analyzer" }
func (l *LuaASTAnalyzer) DefaultSeverity() rules.Severity   { return rules.High }
func (l *LuaASTAnalyzer) Languages() []rules.Language        { return []rules.Language{rules.LangLua} }
func (l *LuaASTAnalyzer) Description() string {
	return "AST-based analysis of Lua code for OS command injection, code injection via loadstring, debug library usage, and OpenResty SQL injection."
}

func (l *LuaASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangLua {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &luaChecker{
		tree:     tree,
		filePath: ctx.FilePath,
		content:  ctx.Content,
	}
	c.walk()
	return c.findings
}

type luaChecker struct {
	tree     *ast.Tree
	filePath string
	content  string
	findings []rules.Finding
}

func (c *luaChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "function_call" {
			c.checkOsExecute(n)
			c.checkLoadstring(n)
			c.checkDofileLoadfile(n)
			c.checkDebugLibrary(n)
			c.checkNgxSQLInjection(n)
		}
		return true
	})
}

// getLuaFuncName extracts the function name from a Lua function_call node.
// Lua tree-sitter uses identifier children for dotted names (os.execute -> "os", "execute").
// Note: Lua tree-sitter may include leading whitespace in identifier text, so we trim.
func getLuaFuncName(n *ast.Node) (string, string) {
	identifiers := make([]string, 0, 3)
	for _, child := range n.NamedChildren() {
		if child.Type() == "identifier" {
			identifiers = append(identifiers, strings.TrimSpace(child.Text()))
		}
	}
	switch len(identifiers) {
	case 0:
		return "", ""
	case 1:
		return "", identifiers[0]
	default:
		return identifiers[0], identifiers[len(identifiers)-1]
	}
}

// hasVariableArgument checks if the function_arguments of a function_call
// contain any variable (non-literal) arguments.
func hasVariableArgument(n *ast.Node) bool {
	for _, child := range n.NamedChildren() {
		if child.Type() == "function_arguments" {
			found := false
			child.Walk(func(inner *ast.Node) bool {
				if found {
					return false
				}
				if inner.Type() == "identifier" {
					found = true
					return false
				}
				if inner.Type() == "binary_operation" {
					// String concatenation with ..
					found = true
					return false
				}
				return true
			})
			return found
		}
	}
	return false
}

// hasSQLInArguments checks if function arguments contain SQL keywords.
func hasSQLInArguments(n *ast.Node) bool {
	for _, child := range n.NamedChildren() {
		if child.Type() == "function_arguments" {
			found := false
			child.Walk(func(inner *ast.Node) bool {
				if found {
					return false
				}
				if inner.Type() == "string" {
					upper := strings.ToUpper(inner.Text())
					keywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"}
					for _, kw := range keywords {
						if strings.Contains(upper, kw) {
							found = true
							return false
						}
					}
				}
				return true
			})
			return found
		}
	}
	return false
}

// checkOsExecute detects os.execute() and io.popen() with variable arguments.
func (c *luaChecker) checkOsExecute(n *ast.Node) {
	pkg, method := getLuaFuncName(n)

	dangerousFuncs := map[string]map[string]string{
		"os": {
			"execute": "os.execute runs shell commands. Variable arguments enable command injection.",
		},
		"io": {
			"popen": "io.popen opens a process with a shell command. Variable arguments enable command injection.",
		},
	}

	methods, ok := dangerousFuncs[pkg]
	if !ok {
		return
	}
	desc, ok := methods[method]
	if !ok {
		return
	}

	if hasVariableArgument(n) {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-LUA-AST-001",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Command injection via " + pkg + "." + method,
			Description:   desc,
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Validate and sanitize all inputs. Avoid passing user-controlled data to shell commands.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangLua,
			Confidence:    "high",
			Tags:          []string{"command-injection", "injection", "rce"},
		})
	}
}

// checkLoadstring detects loadstring/load with variable arguments (code injection).
func (c *luaChecker) checkLoadstring(n *ast.Node) {
	_, method := getLuaFuncName(n)
	if method != "loadstring" && method != "load" {
		return
	}

	if hasVariableArgument(n) {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-LUA-AST-002",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Code injection via " + method + "()",
			Description:   method + "() compiles and returns Lua code from a string. Passing variable input enables arbitrary code execution.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Avoid " + method + "() with user input. Use data formats (JSON, MessagePack) instead of evaluating code.",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangLua,
			Confidence:    "high",
			Tags:          []string{"code-injection", "injection", "rce"},
		})
	}
}

// checkDofileLoadfile detects dofile/loadfile with variable paths.
func (c *luaChecker) checkDofileLoadfile(n *ast.Node) {
	_, method := getLuaFuncName(n)
	if method != "dofile" && method != "loadfile" {
		return
	}

	if hasVariableArgument(n) {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-LUA-AST-003",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Path injection via " + method + "()",
			Description:   method + "() loads and executes a Lua file from disk. Variable paths enable loading arbitrary files including malicious code.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use a fixed allowlist of loadable files. Validate paths against directory traversal.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      rules.LangLua,
			Confidence:    "high",
			Tags:          []string{"path-injection", "traversal", "rce"},
		})
	}
}

// checkDebugLibrary detects usage of the Lua debug library.
func (c *luaChecker) checkDebugLibrary(n *ast.Node) {
	pkg, method := getLuaFuncName(n)
	if pkg != "debug" {
		return
	}

	dangerousMethods := map[string]bool{
		"getinfo":      true,
		"sethook":      true,
		"getlocal":     true,
		"setlocal":     true,
		"getupvalue":   true,
		"setupvalue":   true,
		"getmetatable": true,
		"setmetatable": true,
		"getregistry":  true,
	}

	if !dangerousMethods[method] {
		return
	}

	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-LUA-AST-004",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Debug library usage: debug." + method,
		Description:   "The debug library provides low-level access to Lua internals. In production, it can be used to bypass sandboxes, inspect/modify local variables, and access restricted data.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Remove debug library usage in production code. Disable debug library access in sandboxed environments.",
		CWEID:         "CWE-489",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      rules.LangLua,
		Confidence:    "high",
		Tags:          []string{"debug", "sandbox-escape"},
	})
}

// checkNgxSQLInjection detects OpenResty ngx.* patterns with SQL and variable concatenation.
func (c *luaChecker) checkNgxSQLInjection(n *ast.Node) {
	pkg, method := getLuaFuncName(n)

	// Check for ngx.say, ngx.print, ngx.exec with SQL
	isNgxOutput := pkg == "ngx" && (method == "say" || method == "print" || method == "exec" || method == "location")
	// Also check for db:query or conn:query patterns
	isDBQuery := method == "query" || method == "execute"

	if !isNgxOutput && !isDBQuery {
		return
	}

	// Check if the arguments contain SQL keywords and variable concatenation
	if hasSQLInArguments(n) && hasVariableArgument(n) {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-LUA-AST-005",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL injection in OpenResty/Lua",
			Description:   "SQL query built with string concatenation in " + pkg + "." + method + ". This enables SQL injection in OpenResty applications.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use parameterized queries with ngx.quote_sql_str() or prepared statements.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangLua,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection", "openresty"},
		})
	}
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
