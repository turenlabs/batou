package jsast

import (
	"strings"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

// JSASTAnalyzer performs AST-based security analysis of JavaScript/TypeScript source.
type JSASTAnalyzer struct{}

func init() {
	rules.Register(&JSASTAnalyzer{})
}

func (j *JSASTAnalyzer) ID() string                      { return "GTSS-JSAST" }
func (j *JSASTAnalyzer) Name() string                    { return "JavaScript AST Security Analyzer" }
func (j *JSASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (j *JSASTAnalyzer) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (j *JSASTAnalyzer) Description() string {
	return "AST-based analysis of JavaScript/TypeScript source for eval injection, innerHTML XSS, child_process command injection, document.write XSS, new Function code injection, and SQL template literal injection."
}

func (j *JSASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJavaScript && ctx.Language != rules.LangTypeScript {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &jsChecker{
		filePath: ctx.FilePath,
		language: ctx.Language,
		tree:     tree,
	}
	c.walk()
	return c.findings
}

type jsChecker struct {
	filePath string
	language rules.Language
	tree     *ast.Tree
	findings []rules.Finding
}

func (c *jsChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "call_expression":
			c.checkCallExpression(n)
		case "assignment_expression":
			c.checkAssignment(n)
		case "new_expression":
			c.checkNewExpression(n)
		case "variable_declarator":
			c.checkVariableDeclarator(n)
		}
		return true
	})
}

func (c *jsChecker) checkCallExpression(n *ast.Node) {
	funcName := jsCallName(n)

	// eval(variable)
	if funcName == "eval" {
		c.checkEval(n)
	}

	// document.write(variable)
	if funcName == "document.write" || funcName == "document.writeln" {
		c.checkDocumentWrite(n)
	}

	// child_process.exec / execSync / spawn
	if isChildProcessExec(n) {
		c.checkChildProcess(n)
	}
}

// checkEval detects eval() with non-literal arguments.
func (c *jsChecker) checkEval(n *ast.Node) {
	args := findChild(n, "arguments")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJSLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JSAST-001",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Code injection via eval()",
		Description:   "eval() executes a string as JavaScript code. If the argument is user-controlled, an attacker can execute arbitrary code in the application context.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid eval() entirely. Use JSON.parse() for JSON data, or a safe expression evaluator for math expressions.",
		CWEID:         "CWE-95",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"injection", "eval", "ast"},
	})
}

// checkAssignment detects innerHTML/outerHTML assignments from variables.
func (c *jsChecker) checkAssignment(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	left := named[0]
	right := named[1]

	if left.Type() == "member_expression" {
		propName := memberProperty(left)
		if propName == "innerHTML" || propName == "outerHTML" {
			if !isJSLiteral(right) {
				line := int(n.StartRow()) + 1
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-JSAST-002",
					Severity:      rules.High,
					SeverityLabel: rules.High.String(),
					Title:         "XSS via " + propName + " assignment",
					Description:   propName + " is assigned a non-literal value. If the value contains user input, this enables cross-site scripting (XSS) attacks.",
					FilePath:      c.filePath,
					LineNumber:    line,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Use textContent instead of " + propName + " for text content, or use DOMPurify.sanitize() before setting HTML.",
					CWEID:         "CWE-79",
					OWASPCategory: "A03:2021-Injection",
					Language:      c.language,
					Confidence:    "high",
					Tags:          []string{"xss", "dom", "ast"},
				})
			}
		}
	}
}

// checkDocumentWrite detects document.write with non-literal arguments.
func (c *jsChecker) checkDocumentWrite(n *ast.Node) {
	args := findChild(n, "arguments")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJSLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JSAST-003",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "XSS via document.write()",
		Description:   "document.write() injects content directly into the DOM. If the argument contains user input, this enables cross-site scripting (XSS) attacks.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid document.write(). Use DOM manipulation methods (createElement, textContent) instead.",
		CWEID:         "CWE-79",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"xss", "dom", "ast"},
	})
}

// checkChildProcess detects child_process.exec/execSync with variable command.
func (c *jsChecker) checkChildProcess(n *ast.Node) {
	args := findChild(n, "arguments")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJSLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JSAST-004",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via child_process",
		Description:   "A child_process execution function is called with a non-literal command. If the command contains user input, an attacker can execute arbitrary system commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use child_process.execFile() or child_process.spawn() with an array of arguments instead of a command string.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "rce", "ast"},
	})
}

// checkNewExpression detects new Function(variable).
func (c *jsChecker) checkNewExpression(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) == 0 {
		return
	}
	constructor := named[0]
	if constructor.Type() == "identifier" && constructor.Text() == "Function" {
		args := findChild(n, "arguments")
		if args == nil {
			return
		}
		for _, arg := range args.NamedChildren() {
			if !isJSLiteral(arg) {
				line := int(n.StartRow()) + 1
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-JSAST-005",
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "Code injection via new Function()",
					Description:   "new Function() creates a function from a string, similar to eval(). If the argument is user-controlled, an attacker can execute arbitrary code.",
					FilePath:      c.filePath,
					LineNumber:    line,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Avoid new Function() with dynamic content. Use a safe expression evaluator or precompiled functions.",
					CWEID:         "CWE-95",
					OWASPCategory: "A03:2021-Injection",
					Language:      c.language,
					Confidence:    "high",
					Tags:          []string{"injection", "eval", "ast"},
				})
				return
			}
		}
	}
}

// checkVariableDeclarator detects SQL template literals with interpolation.
func (c *jsChecker) checkVariableDeclarator(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	value := named[1]

	// Check for template_string with SQL content and interpolation
	if value.Type() == "template_string" {
		c.checkSQLTemplateString(value)
	}

	// Check for binary_expression (string concat) with SQL content
	if value.Type() == "binary_expression" {
		c.checkSQLBinaryExpression(value)
	}
}

func (c *jsChecker) checkSQLTemplateString(n *ast.Node) {
	text := n.Text()
	if !containsSQLKeyword(text) {
		return
	}
	hasInterpolation := false
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "template_substitution" {
			hasInterpolation = true
			return false
		}
		return true
	})
	if !hasInterpolation {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JSAST-006",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "SQL injection via template literal interpolation",
		Description:   "A SQL query is built using a template literal with ${} interpolation. If the interpolated value contains user input, this enables SQL injection.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId]).",
		CWEID:         "CWE-89",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"sql-injection", "injection", "ast"},
	})
}

func (c *jsChecker) checkSQLBinaryExpression(n *ast.Node) {
	text := n.Text()
	if !containsSQLKeyword(text) {
		return
	}
	if !strings.Contains(text, "+") {
		return
	}
	// Check at least one part is not a literal
	named := n.NamedChildren()
	allLiteral := true
	for _, child := range named {
		if !isJSLiteral(child) {
			allLiteral = false
			break
		}
	}
	if allLiteral {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JSAST-006",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "SQL injection via string concatenation",
		Description:   "A SQL query is built by concatenating strings with variables. This enables SQL injection attacks.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId]).",
		CWEID:         "CWE-89",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"sql-injection", "injection", "ast"},
	})
}

// --- helpers ---

func jsCallName(n *ast.Node) string {
	if n == nil || n.Type() != "call_expression" {
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
	case "member_expression":
		obj := firstNamedChild(funcNode)
		prop := memberProperty(funcNode)
		if obj != nil && prop != "" {
			return obj.Text() + "." + prop
		}
	}
	return ""
}

func memberProperty(n *ast.Node) string {
	if n == nil || n.Type() != "member_expression" {
		return ""
	}
	named := n.NamedChildren()
	for _, child := range named {
		if child.Type() == "property_identifier" {
			return child.Text()
		}
	}
	return ""
}

func isChildProcessExec(n *ast.Node) bool {
	text := n.Text()
	if !strings.Contains(text, "exec") {
		return false
	}
	return strings.Contains(text, "child_process") ||
		strings.Contains(text, "require('child_process')") ||
		strings.Contains(text, "require(\"child_process\")")
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

func isJSLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "number", "true", "false", "null", "undefined":
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
