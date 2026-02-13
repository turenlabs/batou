package rubyast

import (
	"strings"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

// RubyASTAnalyzer performs AST-based security analysis of Ruby source code.
type RubyASTAnalyzer struct{}

func init() {
	rules.Register(&RubyASTAnalyzer{})
}

func (r *RubyASTAnalyzer) ID() string                      { return "GTSS-RUBYAST" }
func (r *RubyASTAnalyzer) Name() string                    { return "Ruby AST Security Analyzer" }
func (r *RubyASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RubyASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }
func (r *RubyASTAnalyzer) Description() string {
	return "AST-based analysis of Ruby source for eval/instance_eval/class_eval code injection, system/exec/backtick command injection, send/public_send dynamic dispatch, ERB template injection, and IO.popen command injection."
}

func (r *RubyASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &rubyChecker{
		filePath: ctx.FilePath,
		tree:     tree,
	}
	c.walk()
	return c.findings
}

type rubyChecker struct {
	filePath string
	tree     *ast.Tree
	findings []rules.Finding
}

// evalFuncs are Ruby functions that execute code from strings.
var evalFuncs = map[string]bool{
	"eval":          true,
	"instance_eval": true,
	"class_eval":    true,
	"module_eval":   true,
}

// cmdFuncs are Ruby functions that execute system commands.
var cmdFuncs = map[string]bool{
	"system": true,
	"exec":   true,
}

// dynamicDispatch functions allow calling arbitrary methods.
var dynamicDispatch = map[string]bool{
	"send":        true,
	"public_send": true,
	"__send__":    true,
}

func (c *rubyChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "call" {
			c.checkCall(n)
		}
		return true
	})
}

func (c *rubyChecker) checkCall(n *ast.Node) {
	funcName, receiverName := rubyCallInfo(n)

	// eval/instance_eval/class_eval with variable
	if evalFuncs[funcName] {
		c.checkEvalCall(n, funcName)
	}

	// system/exec with variable
	if cmdFuncs[funcName] {
		c.checkCommandCall(n, funcName)
	}

	// send/public_send with variable method name
	if dynamicDispatch[funcName] {
		c.checkDynamicDispatch(n, funcName)
	}

	// IO.popen / Open with variable
	if funcName == "popen" && receiverName == "IO" {
		c.checkIOPopen(n)
	}
	if funcName == "open" && receiverName == "IO" {
		c.checkIOPopen(n)
	}

	// ERB.new with variable template
	if funcName == "new" && receiverName == "ERB" {
		c.checkERBNew(n)
	}
}

// checkEvalCall detects eval/instance_eval/class_eval with non-literal argument.
func (c *rubyChecker) checkEvalCall(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isRubyLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-RUBYAST-001",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Code injection via " + funcName + "()",
		Description:   funcName + "() executes a string as Ruby code. If the argument is user-controlled, an attacker can execute arbitrary code on the server.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid " + funcName + "() with user input. Use a safe alternative like a case/when dispatch or method allowlist.",
		CWEID:         "CWE-95",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"injection", "eval", "rce", "ast"},
	})
}

// checkCommandCall detects system/exec with non-literal argument.
func (c *rubyChecker) checkCommandCall(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isRubyLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-RUBYAST-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via " + funcName + "()",
		Description:   funcName + "() executes a system command. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use the array form: system('cmd', 'arg1', 'arg2') to avoid shell interpretation, and validate all user input.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "rce", "ast"},
	})
}

// checkDynamicDispatch detects send/public_send with non-literal method name.
func (c *rubyChecker) checkDynamicDispatch(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isRubyLiteral(firstArg) {
		return
	}
	// Also allow symbol literals
	if firstArg.Type() == "simple_symbol" {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-RUBYAST-003",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Dynamic method dispatch via " + funcName + "() with variable",
		Description:   funcName + "() calls an arbitrary method on an object. If the method name is user-controlled, an attacker can invoke dangerous methods like system, eval, or destroy.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the method name against an allowlist before calling " + funcName + "().",
		CWEID:         "CWE-470",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"injection", "dynamic-dispatch", "ast"},
	})
}

// checkIOPopen detects IO.popen with non-literal argument.
func (c *rubyChecker) checkIOPopen(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isRubyLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-RUBYAST-004",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via IO.popen()",
		Description:   "IO.popen() opens a subprocess with a shell command. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use the array form: IO.popen(['cmd', 'arg1', 'arg2']) to avoid shell interpretation.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "rce", "ast"},
	})
}

// checkERBNew detects ERB.new with non-literal template.
func (c *rubyChecker) checkERBNew(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isRubyLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-RUBYAST-005",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Template injection via ERB.new()",
		Description:   "ERB.new() creates a template from a string. If the template string is user-controlled, an attacker can execute arbitrary Ruby code via ERB template tags (<%= %>).",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Never pass user input as the ERB template source. Load templates from files and pass user data as variables.",
		CWEID:         "CWE-1336",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"template-injection", "ssti", "rce", "ast"},
	})
}

// --- helpers ---

// rubyCallInfo returns the method name and receiver name for a call node.
func rubyCallInfo(n *ast.Node) (method, receiver string) {
	if n == nil || n.Type() != "call" {
		return "", ""
	}
	named := n.NamedChildren()
	// Ruby call node structure varies:
	// Simple call: [identifier("eval"), argument_list]
	// Method call: [identifier("obj")/constant("IO"), identifier("method"), argument_list]
	for i, child := range named {
		if child.Type() == "identifier" || child.Type() == "constant" {
			// If the next named child is also identifier or argument_list
			if i+1 < len(named) {
				next := named[i+1]
				if next.Type() == "identifier" {
					receiver = child.Text()
					method = next.Text()
					return method, receiver
				}
				if next.Type() == "argument_list" {
					method = child.Text()
					return method, ""
				}
			} else {
				// Last named child and it's an identifier - it's the method name
				method = child.Text()
				return method, ""
			}
		}
	}
	return "", ""
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

func isRubyLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "integer", "float", "true", "false", "nil",
		"symbol", "simple_symbol", "hash", "array", "regex":
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
