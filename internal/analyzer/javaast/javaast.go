package javaast

import (
	"strings"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

// JavaASTAnalyzer performs AST-based security analysis of Java source code.
type JavaASTAnalyzer struct{}

func init() {
	rules.Register(&JavaASTAnalyzer{})
}

func (j *JavaASTAnalyzer) ID() string                        { return "GTSS-JAVAAST" }
func (j *JavaASTAnalyzer) Name() string                      { return "Java AST Security Analyzer" }
func (j *JavaASTAnalyzer) DefaultSeverity() rules.Severity   { return rules.Critical }
func (j *JavaASTAnalyzer) Languages() []rules.Language       { return []rules.Language{rules.LangJava} }
func (j *JavaASTAnalyzer) Description() string {
	return "AST-based analysis of Java source for SQL injection via string concatenation, Runtime.exec command injection, ObjectInputStream deserialization, JNDI lookup injection, and unsafe reflection via Class.forName."
}

func (j *JavaASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &javaChecker{
		filePath: ctx.FilePath,
		tree:     tree,
	}
	c.walk()
	return c.findings
}

type javaChecker struct {
	filePath string
	tree     *ast.Tree
	findings []rules.Finding
}

func (c *javaChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "method_invocation" {
			c.checkMethodInvocation(n)
		}
		if n.Type() == "object_creation_expression" {
			c.checkObjectCreation(n)
		}
		return true
	})
}

// checkMethodInvocation inspects method calls for dangerous patterns.
func (c *javaChecker) checkMethodInvocation(n *ast.Node) {
	methodName := javaMethodName(n)
	objName := javaObjectName(n)

	// SQL injection: stmt.executeQuery/execute/executeUpdate with string concat
	if isSQLMethod(methodName) {
		c.checkSQLConcat(n, methodName)
	}

	// Runtime.exec with variable
	if methodName == "exec" && isRuntimeExec(n) {
		c.checkRuntimeExec(n)
	}

	// ProcessBuilder: .command(var) or new ProcessBuilder(var)
	if methodName == "exec" && objName == "Runtime" {
		c.checkRuntimeExec(n)
	}

	// readObject() deserialization
	if methodName == "readObject" {
		c.checkDeserialization(n)
	}

	// JNDI lookup
	if methodName == "lookup" {
		c.checkJNDILookup(n)
	}

	// Class.forName with variable
	if methodName == "forName" && objName == "Class" {
		c.checkUnsafeReflection(n)
	}
}

// checkObjectCreation detects ObjectInputStream construction.
func (c *javaChecker) checkObjectCreation(n *ast.Node) {
	named := n.NamedChildren()
	for _, child := range named {
		if child.Type() == "type_identifier" && child.Text() == "ObjectInputStream" {
			line := int(n.StartRow()) + 1
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "GTSS-JAVAAST-003",
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Unsafe deserialization: ObjectInputStream created",
				Description:   "ObjectInputStream deserializes Java objects from a stream. If the stream contains untrusted data, this can lead to remote code execution via gadget chains.",
				FilePath:      c.filePath,
				LineNumber:    line,
				MatchedText:   truncate(n.Text(), 200),
				Suggestion:    "Avoid deserializing untrusted data. Use a serialization filter (ObjectInputFilter) or switch to a safe format like JSON.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      rules.LangJava,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "ast"},
			})
			return
		}
	}
}

// checkSQLConcat detects SQL queries built with string concatenation.
func (c *javaChecker) checkSQLConcat(n *ast.Node, methodName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil {
		return
	}
	if firstArg.Type() == "binary_expression" && containsStringConcat(firstArg) {
		text := firstArg.Text()
		if containsSQLKeyword(text) {
			line := int(n.StartRow()) + 1
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "GTSS-JAVAAST-001",
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "SQL injection via string concatenation in " + methodName + "()",
				Description:   "A SQL query is built by concatenating strings with variables and passed to " + methodName + "(). This enables SQL injection attacks.",
				FilePath:      c.filePath,
				LineNumber:    line,
				MatchedText:   truncate(n.Text(), 200),
				Suggestion:    "Use PreparedStatement with parameterized queries: PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); ps.setString(1, userInput);",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      rules.LangJava,
				Confidence:    "high",
				Tags:          []string{"sql-injection", "injection", "ast"},
			})
		}
	}
}

// checkRuntimeExec detects Runtime.getRuntime().exec(variable).
func (c *javaChecker) checkRuntimeExec(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJavaLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JAVAAST-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via Runtime.exec()",
		Description:   "Runtime.exec() is called with a non-literal argument. If the argument is user-controlled, an attacker can execute arbitrary system commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use ProcessBuilder with a list of arguments instead of a single command string. Validate and sanitize all user input.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "rce", "ast"},
	})
}

// checkDeserialization flags readObject() calls.
func (c *javaChecker) checkDeserialization(n *ast.Node) {
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JAVAAST-003",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Unsafe deserialization via readObject()",
		Description:   "readObject() deserializes Java objects from a stream. If the stream contains untrusted data, this can lead to remote code execution.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid deserializing untrusted data. Use ObjectInputFilter to restrict allowed classes, or use a safe format like JSON.",
		CWEID:         "CWE-502",
		OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		Language:      rules.LangJava,
		Confidence:    "medium",
		Tags:          []string{"deserialization", "rce", "ast"},
	})
}

// checkJNDILookup detects JNDI lookup with variable name.
func (c *javaChecker) checkJNDILookup(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJavaLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JAVAAST-004",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "JNDI injection via lookup() with variable name",
		Description:   "A JNDI lookup is performed with a non-literal name. If the name is user-controlled, an attacker can trigger remote class loading and achieve remote code execution (Log4Shell-style attack).",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Never pass user input to JNDI lookup. Use a hardcoded JNDI name or validate against an allowlist.",
		CWEID:         "CWE-917",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"jndi-injection", "injection", "rce", "ast"},
	})
}

// checkUnsafeReflection detects Class.forName(variable).
func (c *javaChecker) checkUnsafeReflection(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJavaLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-JAVAAST-005",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Unsafe reflection via Class.forName() with variable",
		Description:   "Class.forName() is called with a non-literal class name. If the class name is user-controlled, an attacker can instantiate arbitrary classes leading to code execution.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the class name against an allowlist of permitted classes before calling Class.forName().",
		CWEID:         "CWE-470",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"reflection", "injection", "ast"},
	})
}

// --- helpers ---

func javaMethodName(n *ast.Node) string {
	if n == nil || n.Type() != "method_invocation" {
		return ""
	}
	// In tree-sitter Java, method_invocation has children:
	// [object, identifier(methodName), argument_list]
	// The method name is the last identifier before argument_list
	named := n.NamedChildren()
	for i := len(named) - 1; i >= 0; i-- {
		if named[i].Type() == "identifier" {
			// Check the next sibling is argument_list to confirm this is the method name
			if i+1 < len(named) && named[i+1].Type() == "argument_list" {
				return named[i].Text()
			}
			// If it's the last identifier, it's likely the method name
			return named[i].Text()
		}
	}
	return ""
}

func javaObjectName(n *ast.Node) string {
	if n == nil || n.Type() != "method_invocation" {
		return ""
	}
	named := n.NamedChildren()
	if len(named) > 0 && named[0].Type() == "identifier" {
		// Make sure this identifier is not the method name itself
		if len(named) > 1 && named[1].Type() == "identifier" {
			return named[0].Text()
		}
	}
	return ""
}

func isRuntimeExec(n *ast.Node) bool {
	text := n.Text()
	return strings.Contains(text, "Runtime") && strings.Contains(text, "exec")
}

func isSQLMethod(name string) bool {
	return name == "executeQuery" || name == "execute" || name == "executeUpdate"
}

func containsStringConcat(n *ast.Node) bool {
	if n == nil {
		return false
	}
	// Check for + operator in binary expressions
	text := n.Text()
	if strings.Contains(text, "+") {
		// Verify at least one side is not a literal
		named := n.NamedChildren()
		allLiteral := true
		for _, child := range named {
			if !isJavaLiteral(child) {
				allLiteral = false
				break
			}
		}
		return !allLiteral
	}
	return false
}

func isJavaLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string_literal", "decimal_integer_literal", "decimal_floating_point_literal",
		"hex_integer_literal", "octal_integer_literal", "binary_integer_literal",
		"character_literal", "true", "false", "null_literal":
		return true
	}
	return false
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
