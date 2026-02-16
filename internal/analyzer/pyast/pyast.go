package pyast

import (
	"strings"

	"github.com/turenlabs/batou/internal/ast"
	"github.com/turenlabs/batou/internal/rules"
)

// PythonASTAnalyzer performs AST-based security analysis of Python source code.
type PythonASTAnalyzer struct{}

func init() {
	rules.Register(&PythonASTAnalyzer{})
}

func (p *PythonASTAnalyzer) ID() string                        { return "BATOU-PYAST" }
func (p *PythonASTAnalyzer) Name() string                      { return "Python AST Security Analyzer" }
func (p *PythonASTAnalyzer) DefaultSeverity() rules.Severity   { return rules.Critical }
func (p *PythonASTAnalyzer) Languages() []rules.Language       { return []rules.Language{rules.LangPython} }
func (p *PythonASTAnalyzer) Description() string {
	return "AST-based analysis of Python source for eval/exec injection, subprocess shell injection, pickle deserialization, os.system command injection, SQL string formatting, and path traversal via open()."
}

func (p *PythonASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &pyChecker{
		filePath: ctx.FilePath,
		tree:     tree,
	}
	c.walk()
	return c.findings
}

type pyChecker struct {
	filePath string
	tree     *ast.Tree
	findings []rules.Finding
}

func (c *pyChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "call" {
			c.checkCall(n)
		}
		if n.Type() == "binary_operator" {
			c.checkSQLFormatOp(n)
		}
		if n.Type() == "string" {
			c.checkFStringSQLInjection(n)
		}
		return true
	})
}

// checkCall inspects function calls for dangerous patterns.
func (c *pyChecker) checkCall(n *ast.Node) {
	funcName := callFuncName(n)
	switch funcName {
	case "eval":
		c.checkDangerousBuiltin(n, funcName, "Code injection via eval()", "eval() executes arbitrary Python code. If the argument is user-controlled, an attacker can execute any code on the server.", "CWE-95")
	case "exec":
		c.checkDangerousBuiltin(n, funcName, "Code injection via exec()", "exec() executes arbitrary Python code. If the argument is user-controlled, an attacker can execute any code on the server.", "CWE-95")
	case "os.system":
		c.checkDangerousBuiltin(n, funcName, "Command injection via os.system()", "os.system() passes a command string to the system shell. If the argument contains user input, an attacker can inject shell commands.", "CWE-78")
	case "open":
		c.checkOpenCall(n)
	}

	// subprocess.call/run/Popen with shell=True
	if isSubprocessCall(funcName) {
		c.checkSubprocessShell(n, funcName)
	}

	// pickle.loads/load
	if funcName == "pickle.loads" || funcName == "pickle.load" {
		c.checkPickle(n, funcName)
	}
}

// checkDangerousBuiltin flags calls where the first argument is not a string literal.
func (c *pyChecker) checkDangerousBuiltin(n *ast.Node, funcName, title, desc, cwe string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-PYAST-001",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         title,
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Never pass user-controlled data to " + funcName + "(). Use a safe alternative or validate input strictly.",
		CWEID:         cwe,
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangPython,
		Confidence:    "high",
		Tags:          []string{"injection", "ast"},
	})
}

// checkSubprocessShell detects subprocess calls with shell=True and non-literal command.
func (c *pyChecker) checkSubprocessShell(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	hasShellTrue := false
	for _, child := range args.NamedChildren() {
		if child.Type() == "keyword_argument" {
			key := firstNamedChild(child)
			if key != nil && key.Text() == "shell" {
				val := lastNamedChild(child)
				if val != nil && (val.Type() == "true" || val.Text() == "True") {
					hasShellTrue = true
				}
			}
		}
	}
	if !hasShellTrue {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-PYAST-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Shell injection via " + funcName + " with shell=True",
		Description:   funcName + " is called with shell=True and a non-literal command. An attacker who controls the command string can execute arbitrary shell commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Remove shell=True and pass the command as a list: subprocess.run(['cmd', 'arg1', 'arg2']).",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangPython,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "ast"},
	})
}

// checkPickle flags pickle.loads/load with non-literal data.
func (c *pyChecker) checkPickle(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-PYAST-003",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Unsafe deserialization via " + funcName,
		Description:   funcName + " deserializes untrusted data, which can lead to arbitrary code execution. Pickle is inherently unsafe for untrusted input.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use a safe serialization format like JSON. If pickle is required, use hmac to verify data integrity before deserializing.",
		CWEID:         "CWE-502",
		OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		Language:      rules.LangPython,
		Confidence:    "high",
		Tags:          []string{"deserialization", "rce", "ast"},
	})
}

// checkOpenCall flags open() with non-literal path.
func (c *pyChecker) checkOpenCall(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-PYAST-004",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Path traversal via open() with variable path",
		Description:   "open() is called with a non-literal path argument. If the path is user-controlled, an attacker could read or write arbitrary files on the filesystem.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the path against an allowlist, use os.path.realpath() to resolve symlinks, and ensure the resolved path is within an expected directory.",
		CWEID:         "CWE-22",
		OWASPCategory: "A01:2021-Broken Access Control",
		Language:      rules.LangPython,
		Confidence:    "medium",
		Tags:          []string{"path-traversal", "ast"},
	})
}

// checkSQLFormatOp detects "SELECT ... %s" % var patterns.
func (c *pyChecker) checkSQLFormatOp(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	// Check for % operator (modulo used for string formatting)
	text := n.Text()
	if !strings.Contains(text, "%") {
		return
	}
	left := named[0]
	if left.Type() != "string" {
		return
	}
	if containsSQLKeyword(left.Text()) {
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-PYAST-005",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL injection via string % formatting",
			Description:   "A SQL query is built using Python's % string formatting operator with a variable. This enables SQL injection attacks.",
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = %s', (name,)).",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangPython,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection", "ast"},
		})
	}
}

// checkFStringSQLInjection detects f"SELECT ... {var}" patterns.
func (c *pyChecker) checkFStringSQLInjection(n *ast.Node) {
	text := n.Text()
	if !strings.HasPrefix(text, "f\"") && !strings.HasPrefix(text, "f'") {
		return
	}
	// Check for interpolation children
	hasInterpolation := false
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "interpolation" {
			hasInterpolation = true
			return false
		}
		return true
	})
	if !hasInterpolation {
		return
	}
	if containsSQLKeyword(text) {
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-PYAST-005",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL injection via f-string interpolation",
			Description:   "A SQL query is built using Python f-string interpolation with embedded variables. This enables SQL injection attacks.",
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(text, 200),
			Suggestion:    "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = %s', (name,)).",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangPython,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection", "ast"},
		})
	}
}

// --- helpers ---

func callFuncName(n *ast.Node) string {
	if n == nil || n.Type() != "call" {
		return ""
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return ""
	}
	funcNode := named[0]
	switch funcNode.Type() {
	case "identifier":
		return funcNode.Text()
	case "attribute":
		parts := funcNode.NamedChildren()
		if len(parts) == 2 {
			return parts[0].Text() + "." + parts[1].Text()
		}
	}
	return ""
}

func isSubprocessCall(name string) bool {
	return name == "subprocess.call" || name == "subprocess.run" ||
		name == "subprocess.Popen" || name == "subprocess.check_output" ||
		name == "subprocess.check_call"
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

func lastNamedChild(n *ast.Node) *ast.Node {
	if n == nil {
		return nil
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return nil
	}
	return named[len(named)-1]
}

func isLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "integer", "float", "true", "false", "none",
		"string_literal", "number_literal":
		return true
	}
	return false
}

func containsSQLKeyword(s string) bool {
	upper := strings.ToUpper(s)
	return strings.Contains(upper, "SELECT") || strings.Contains(upper, "INSERT") ||
		strings.Contains(upper, "UPDATE") || strings.Contains(upper, "DELETE") ||
		strings.Contains(upper, "DROP") || strings.Contains(upper, "ALTER") ||
		strings.Contains(upper, "CREATE TABLE") || strings.Contains(upper, "EXEC ")
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
