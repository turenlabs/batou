package cast

import (
	"strings"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

// CASTAnalyzer performs AST-based security analysis of C and C++ source code.
type CASTAnalyzer struct{}

func init() {
	rules.Register(&CASTAnalyzer{})
}

func (a *CASTAnalyzer) ID() string                      { return "GTSS-CAST" }
func (a *CASTAnalyzer) Name() string                    { return "C/C++ AST Security Analyzer" }
func (a *CASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (a *CASTAnalyzer) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}
func (a *CASTAnalyzer) Description() string {
	return "AST-based analysis of C/C++ source for format string vulnerabilities, banned buffer overflow functions, system() command injection, and unsafe memory patterns."
}

func (a *CASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangC && ctx.Language != rules.LangCPP {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &cChecker{
		filePath: ctx.FilePath,
		language: ctx.Language,
		tree:     tree,
	}
	c.walk()
	return c.findings
}

type cChecker struct {
	filePath string
	language rules.Language
	tree     *ast.Tree
	findings []rules.Finding
}

// bannedFuncs maps dangerous C functions to their safe alternatives and CWEs.
var bannedFuncs = map[string]struct {
	title      string
	desc       string
	suggestion string
	cwe        string
	severity   rules.Severity
}{
	"gets": {
		title:      "Use of banned function gets()",
		desc:       "gets() reads input without bounds checking, always causing a buffer overflow if input exceeds buffer size. It has been removed from C11.",
		suggestion: "Use fgets(buf, sizeof(buf), stdin) instead.",
		cwe:        "CWE-120",
		severity:   rules.Critical,
	},
	"strcpy": {
		title:      "Use of unbounded string copy strcpy()",
		desc:       "strcpy() copies without bounds checking. If the source is longer than the destination buffer, a buffer overflow occurs.",
		suggestion: "Use strncpy(dest, src, sizeof(dest)-1) or strlcpy() where available.",
		cwe:        "CWE-120",
		severity:   rules.High,
	},
	"strcat": {
		title:      "Use of unbounded string concatenation strcat()",
		desc:       "strcat() concatenates without bounds checking. If the combined string exceeds the buffer, a buffer overflow occurs.",
		suggestion: "Use strncat(dest, src, sizeof(dest)-strlen(dest)-1) or strlcat() where available.",
		cwe:        "CWE-120",
		severity:   rules.High,
	},
	"sprintf": {
		title:      "Use of unbounded sprintf()",
		desc:       "sprintf() writes formatted output without bounds checking. If the output exceeds the buffer, a buffer overflow occurs.",
		suggestion: "Use snprintf(buf, sizeof(buf), fmt, ...) instead.",
		cwe:        "CWE-120",
		severity:   rules.High,
	},
	"vsprintf": {
		title:      "Use of unbounded vsprintf()",
		desc:       "vsprintf() writes formatted output without bounds checking, leading to potential buffer overflow.",
		suggestion: "Use vsnprintf(buf, sizeof(buf), fmt, args) instead.",
		cwe:        "CWE-120",
		severity:   rules.High,
	},
}

// formatFuncs are functions where the format string should be a literal.
var formatFuncs = map[string]int{
	"printf":   0,
	"fprintf":  1,
	"sprintf":  1,
	"snprintf": 2,
	"syslog":   1,
}

func (c *cChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "call_expression" {
			c.checkCallExpression(n)
		}
		return true
	})
}

func (c *cChecker) checkCallExpression(n *ast.Node) {
	funcName := cCallName(n)
	if funcName == "" {
		return
	}

	// Check banned functions
	if info, ok := bannedFuncs[funcName]; ok {
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-CAST-001",
			Severity:      info.severity,
			SeverityLabel: info.severity.String(),
			Title:         info.title,
			Description:   info.desc,
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    info.suggestion,
			CWEID:         info.cwe,
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
			Language:      c.language,
			Confidence:    "high",
			Tags:          []string{"buffer-overflow", "memory-safety", "ast"},
		})
	}

	// Check format string vulnerabilities
	if fmtArgIdx, ok := formatFuncs[funcName]; ok {
		c.checkFormatString(n, funcName, fmtArgIdx)
	}

	// Check system() with variable argument
	if funcName == "system" {
		c.checkSystemCall(n)
	}

	// Check popen() with variable argument
	if funcName == "popen" {
		c.checkSystemCall(n)
	}
}

// checkFormatString detects printf-family calls where the format string is not a literal.
func (c *cChecker) checkFormatString(n *ast.Node, funcName string, fmtArgIdx int) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	named := args.NamedChildren()
	if fmtArgIdx >= len(named) {
		return
	}
	fmtArg := named[fmtArgIdx]
	if isCLiteral(fmtArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-CAST-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Format string vulnerability in " + funcName + "()",
		Description:   funcName + "() is called with a non-literal format string. An attacker who controls the format string can read from or write to arbitrary memory locations.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Always use a string literal as the format string: " + funcName + "(\"...%s...\", variable). Never pass user input as the format argument.",
		CWEID:         "CWE-134",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"format-string", "memory-safety", "ast"},
	})
}

// checkSystemCall detects system()/popen() with non-literal argument.
func (c *cChecker) checkSystemCall(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isCLiteral(firstArg) {
		return
	}
	funcName := cCallName(n)
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-CAST-003",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via " + funcName + "()",
		Description:   funcName + "() passes a command to the system shell. If the argument contains user input, an attacker can inject arbitrary commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid " + funcName + "() with user input. Use exec-family functions (execve, execvp) with separate arguments.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "ast"},
	})
}

// --- helpers ---

func cCallName(n *ast.Node) string {
	if n == nil || n.Type() != "call_expression" {
		return ""
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return ""
	}
	funcNode := named[0]
	if funcNode.Type() == "identifier" {
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

func isCLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string_literal", "number_literal", "char_literal",
		"concatenated_string", "true", "false", "null":
		return true
	}
	// Check if it's a string content wrapped in quotes
	if strings.HasPrefix(n.Text(), "\"") || strings.HasPrefix(n.Text(), "'") {
		return true
	}
	return false
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
