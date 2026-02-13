package phpast

import (
	"strings"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

// PHPASTAnalyzer performs AST-based security analysis of PHP source code.
type PHPASTAnalyzer struct{}

func init() {
	rules.Register(&PHPASTAnalyzer{})
}

func (p *PHPASTAnalyzer) ID() string                      { return "GTSS-PHPAST" }
func (p *PHPASTAnalyzer) Name() string                    { return "PHP AST Security Analyzer" }
func (p *PHPASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (p *PHPASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangPHP} }
func (p *PHPASTAnalyzer) Description() string {
	return "AST-based analysis of PHP source for eval/exec/system/passthru injection, SQL concatenation injection, include/require path injection, unserialize deserialization, and preg_replace /e code execution."
}

func (p *PHPASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPHP {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &phpChecker{
		filePath: ctx.FilePath,
		tree:     tree,
	}
	c.walk()
	return c.findings
}

type phpChecker struct {
	filePath string
	tree     *ast.Tree
	findings []rules.Finding
}

// dangerousFuncs maps function names to their security metadata.
var dangerousFuncs = map[string]struct {
	ruleID     string
	title      string
	desc       string
	suggestion string
	cwe        string
	severity   rules.Severity
	tags       []string
}{
	"eval": {
		ruleID:     "GTSS-PHPAST-001",
		title:      "Code injection via eval()",
		desc:       "eval() executes a string as PHP code. If the argument is user-controlled, an attacker can execute arbitrary code on the server.",
		suggestion: "Avoid eval() entirely. Use a safe alternative appropriate for your use case.",
		cwe:        "CWE-95",
		severity:   rules.Critical,
		tags:       []string{"injection", "eval", "rce", "ast"},
	},
	"exec": {
		ruleID:     "GTSS-PHPAST-002",
		title:      "Command injection via exec()",
		desc:       "exec() executes a system command. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		suggestion: "Use escapeshellarg() and escapeshellcmd() on all user input, or avoid shell commands entirely.",
		cwe:        "CWE-78",
		severity:   rules.Critical,
		tags:       []string{"command-injection", "injection", "rce", "ast"},
	},
	"system": {
		ruleID:     "GTSS-PHPAST-002",
		title:      "Command injection via system()",
		desc:       "system() executes a command and displays output. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		suggestion: "Use escapeshellarg() and escapeshellcmd() on all user input, or avoid shell commands entirely.",
		cwe:        "CWE-78",
		severity:   rules.Critical,
		tags:       []string{"command-injection", "injection", "rce", "ast"},
	},
	"passthru": {
		ruleID:     "GTSS-PHPAST-002",
		title:      "Command injection via passthru()",
		desc:       "passthru() executes a command and passes raw output. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		suggestion: "Use escapeshellarg() and escapeshellcmd() on all user input, or avoid shell commands entirely.",
		cwe:        "CWE-78",
		severity:   rules.Critical,
		tags:       []string{"command-injection", "injection", "rce", "ast"},
	},
	"shell_exec": {
		ruleID:     "GTSS-PHPAST-002",
		title:      "Command injection via shell_exec()",
		desc:       "shell_exec() executes a command via the shell. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		suggestion: "Use escapeshellarg() and escapeshellcmd() on all user input, or avoid shell commands entirely.",
		cwe:        "CWE-78",
		severity:   rules.Critical,
		tags:       []string{"command-injection", "injection", "rce", "ast"},
	},
	"popen": {
		ruleID:     "GTSS-PHPAST-002",
		title:      "Command injection via popen()",
		desc:       "popen() opens a process with a shell command. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		suggestion: "Use escapeshellarg() and escapeshellcmd() on all user input, or avoid shell commands entirely.",
		cwe:        "CWE-78",
		severity:   rules.Critical,
		tags:       []string{"command-injection", "injection", "rce", "ast"},
	},
	"proc_open": {
		ruleID:     "GTSS-PHPAST-002",
		title:      "Command injection via proc_open()",
		desc:       "proc_open() opens a process with a shell command. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		suggestion: "Use escapeshellarg() and escapeshellcmd() on all user input, or avoid shell commands entirely.",
		cwe:        "CWE-78",
		severity:   rules.Critical,
		tags:       []string{"command-injection", "injection", "rce", "ast"},
	},
	"unserialize": {
		ruleID:     "GTSS-PHPAST-004",
		title:      "Unsafe deserialization via unserialize()",
		desc:       "unserialize() on untrusted data can trigger arbitrary object instantiation, leading to code execution via PHP magic methods (__wakeup, __destruct).",
		suggestion: "Use json_decode() instead. If unserialize() is needed, use the allowed_classes option: unserialize($data, ['allowed_classes' => false]).",
		cwe:        "CWE-502",
		severity:   rules.Critical,
		tags:       []string{"deserialization", "rce", "ast"},
	},
}

func (c *phpChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "function_call_expression":
			c.checkFunctionCall(n)
		case "include_expression", "include_once_expression":
			c.checkInclude(n, "include")
		case "require_expression", "require_once_expression":
			c.checkInclude(n, "require")
		case "assignment_expression":
			c.checkSQLAssignment(n)
		}
		return true
	})
}

// checkFunctionCall inspects function calls for dangerous patterns.
func (c *phpChecker) checkFunctionCall(n *ast.Node) {
	funcName := phpFuncName(n)

	// Dangerous function calls
	if info, ok := dangerousFuncs[funcName]; ok {
		args := findChild(n, "arguments")
		if args == nil {
			return
		}
		firstArg := firstArgument(args)
		if firstArg == nil || isPHPLiteral(firstArg) {
			return
		}
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        info.ruleID,
			Severity:      info.severity,
			SeverityLabel: info.severity.String(),
			Title:         info.title,
			Description:   info.desc,
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    info.suggestion,
			CWEID:         info.cwe,
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangPHP,
			Confidence:    "high",
			Tags:          info.tags,
		})
		return
	}

	// preg_replace with /e modifier
	if funcName == "preg_replace" {
		c.checkPregReplace(n)
	}

	// SQL query methods
	if funcName == "mysql_query" || funcName == "mysqli_query" || funcName == "pg_query" {
		c.checkSQLQueryFunc(n, funcName)
	}
}

// checkInclude detects include/require with variable paths.
func (c *phpChecker) checkInclude(n *ast.Node, keyword string) {
	// In tree-sitter PHP, include_expression contains the path as a child
	named := n.NamedChildren()
	for _, child := range named {
		if child.Type() == "parenthesized_expression" {
			inner := firstNamedChild(child)
			if inner != nil && !isPHPLiteral(inner) {
				line := int(n.StartRow()) + 1
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-PHPAST-003",
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "Local file inclusion via " + keyword + "()",
					Description:   keyword + "() is called with a non-literal path. If the path is user-controlled, an attacker can include arbitrary files, leading to code execution or information disclosure.",
					FilePath:      c.filePath,
					LineNumber:    line,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Never pass user input directly to " + keyword + "(). Use an allowlist of permitted files.",
					CWEID:         "CWE-98",
					OWASPCategory: "A03:2021-Injection",
					Language:      rules.LangPHP,
					Confidence:    "high",
					Tags:          []string{"lfi", "file-inclusion", "ast"},
				})
				return
			}
		}
		if child.Type() == "variable_name" || child.Type() == "member_access_expression" {
			line := int(n.StartRow()) + 1
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "GTSS-PHPAST-003",
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "Local file inclusion via " + keyword + "()",
				Description:   keyword + "() is called with a variable path. If the path is user-controlled, an attacker can include arbitrary files.",
				FilePath:      c.filePath,
				LineNumber:    line,
				MatchedText:   truncate(n.Text(), 200),
				Suggestion:    "Never pass user input directly to " + keyword + "(). Use an allowlist of permitted files.",
				CWEID:         "CWE-98",
				OWASPCategory: "A03:2021-Injection",
				Language:      rules.LangPHP,
				Confidence:    "high",
				Tags:          []string{"lfi", "file-inclusion", "ast"},
			})
			return
		}
	}
}

// checkPregReplace detects preg_replace with /e modifier.
func (c *phpChecker) checkPregReplace(n *ast.Node) {
	args := findChild(n, "arguments")
	if args == nil {
		return
	}
	firstArg := firstArgument(args)
	if firstArg == nil {
		return
	}
	text := firstArg.Text()
	// Check for /e modifier in the pattern
	if strings.Contains(text, "/e") {
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-PHPAST-005",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Code execution via preg_replace() with /e modifier",
			Description:   "preg_replace() with the /e modifier evaluates the replacement string as PHP code. This is deprecated and extremely dangerous with user input.",
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use preg_replace_callback() instead of the /e modifier.",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangPHP,
			Confidence:    "high",
			Tags:          []string{"code-injection", "injection", "ast"},
		})
	}
}

// checkSQLQueryFunc detects SQL query functions with concatenated strings.
func (c *phpChecker) checkSQLQueryFunc(n *ast.Node, funcName string) {
	args := findChild(n, "arguments")
	if args == nil {
		return
	}
	// mysql_query takes query as first arg, mysqli_query takes conn, query
	argIdx := 0
	if funcName == "mysqli_query" {
		argIdx = 1
	}
	argNodes := getArguments(args)
	if argIdx >= len(argNodes) {
		return
	}
	queryArg := argNodes[argIdx]
	if queryArg.Type() == "binary_expression" && containsSQLKeyword(queryArg.Text()) {
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-PHPAST-006",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL injection via string concatenation in " + funcName + "()",
			Description:   "A SQL query is built by concatenating strings with variables and passed to " + funcName + "(). This enables SQL injection attacks.",
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use prepared statements with PDO: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangPHP,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection", "ast"},
		})
	}
}

// checkSQLAssignment detects SQL queries built with string concatenation in assignments.
func (c *phpChecker) checkSQLAssignment(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	value := named[1]
	if value.Type() == "binary_expression" {
		text := value.Text()
		if strings.Contains(text, ".") && containsSQLKeyword(text) {
			// Check it has variable parts (not all literals)
			hasVariable := false
			value.Walk(func(child *ast.Node) bool {
				if child.Type() == "variable_name" {
					hasVariable = true
					return false
				}
				return true
			})
			if hasVariable {
				line := int(n.StartRow()) + 1
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-PHPAST-006",
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "SQL injection via string concatenation",
					Description:   "A SQL query is built by concatenating strings with PHP variables. This enables SQL injection attacks.",
					FilePath:      c.filePath,
					LineNumber:    line,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Use prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?'); $stmt->execute([$name]);",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      rules.LangPHP,
					Confidence:    "high",
					Tags:          []string{"sql-injection", "injection", "ast"},
				})
			}
		}
	}
}

// --- helpers ---

func phpFuncName(n *ast.Node) string {
	if n == nil || n.Type() != "function_call_expression" {
		return ""
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return ""
	}
	funcNode := named[0]
	if funcNode.Type() == "name" {
		return funcNode.Text()
	}
	return ""
}

func findChild(n *ast.Node, nodeType string) *ast.Node {
	if n == nil {
		return nil
	}
	for _, c := range n.NamedChildren() {
		if c.Type() == nodeType {
			return c
		}
	}
	return nil
}

func firstNamedChild(n *ast.Node) *ast.Node {
	if n == nil {
		return nil
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return nil
	}
	return named[0]
}

// firstArgument gets the first argument node, unwrapping the "argument" wrapper.
func firstArgument(args *ast.Node) *ast.Node {
	if args == nil {
		return nil
	}
	for _, child := range args.NamedChildren() {
		if child.Type() == "argument" {
			return firstNamedChild(child)
		}
	}
	return firstNamedChild(args)
}

// getArguments extracts all argument values from an arguments node.
func getArguments(args *ast.Node) []*ast.Node {
	if args == nil {
		return nil
	}
	var result []*ast.Node
	for _, child := range args.NamedChildren() {
		if child.Type() == "argument" {
			inner := firstNamedChild(child)
			if inner != nil {
				result = append(result, inner)
			}
		}
	}
	return result
}

func isPHPLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "encapsed_string", "integer", "float", "boolean", "null",
		"string_content", "nowdoc_string", "heredoc_string":
		return true
	}
	return false
}

func containsSQLKeyword(s string) bool {
	upper := strings.ToUpper(s)
	return strings.Contains(upper, "SELECT") || strings.Contains(upper, "INSERT") ||
		strings.Contains(upper, "UPDATE") || strings.Contains(upper, "DELETE") ||
		strings.Contains(upper, "DROP") || strings.Contains(upper, "ALTER")
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
