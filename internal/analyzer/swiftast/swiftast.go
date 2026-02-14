package swiftast

import (
	"strings"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

// SwiftASTAnalyzer performs AST-based security analysis of Swift source code.
type SwiftASTAnalyzer struct{}

func init() {
	rules.Register(&SwiftASTAnalyzer{})
}

func (s *SwiftASTAnalyzer) ID() string                        { return "GTSS-SWIFT-AST" }
func (s *SwiftASTAnalyzer) Name() string                      { return "Swift AST Security Analyzer" }
func (s *SwiftASTAnalyzer) DefaultSeverity() rules.Severity   { return rules.High }
func (s *SwiftASTAnalyzer) Languages() []rules.Language        { return []rules.Language{rules.LangSwift} }
func (s *SwiftASTAnalyzer) Description() string {
	return "AST-based analysis of Swift code for SQLite injection, command injection, UIWebView usage, sensitive data in UserDefaults, and insecure URL sessions."
}

func (s *SwiftASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangSwift {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &swiftChecker{
		tree:     tree,
		filePath: ctx.FilePath,
		content:  ctx.Content,
	}
	c.walk()
	return c.findings
}

type swiftChecker struct {
	tree     *ast.Tree
	filePath string
	content  string
	findings []rules.Finding
}

func (c *swiftChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "call_expression":
			c.checkSQLiteInjection(n)
			c.checkUIWebView(n)
			c.checkUserDefaultsSensitive(n)
			c.checkProcessExecution(n)
		case "assignment":
			c.checkProcessAssignment(n)
		}
		return true
	})
}

// checkSQLiteInjection detects sqlite3_prepare_v2 with interpolated query strings
// or variable query arguments.
func (c *swiftChecker) checkSQLiteInjection(n *ast.Node) {
	funcName := getSwiftFuncName(n)
	sqliteFuncs := map[string]bool{
		"sqlite3_prepare_v2": true,
		"sqlite3_exec":      true,
		"sqlite3_prepare":   true,
	}
	if !sqliteFuncs[funcName] {
		return
	}

	// Check if any argument contains string interpolation or is a variable
	// (the query string is typically the 2nd argument for sqlite3_prepare_v2)
	args := getSwiftCallArgs(n)
	for _, arg := range args {
		if containsSwiftInterpolation(arg) {
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "GTSS-SWIFT-AST-001",
				Severity:      rules.Critical,
				SeverityLabel: rules.Critical.String(),
				Title:         "SQL injection via " + funcName,
				Description:   "Using string interpolation in SQLite query passed to " + funcName + " enables SQL injection attacks.",
				FilePath:      c.filePath,
				LineNumber:    int(n.StartRow()) + 1,
				MatchedText:   truncate(n.Text(), 200),
				Suggestion:    "Use parameterized queries with sqlite3_bind_text/sqlite3_bind_int instead of string interpolation.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      rules.LangSwift,
				Confidence:    "high",
				Tags:          []string{"sql-injection", "injection", "sqlite"},
			})
			return
		}
		// Check if arg is a bare variable identifier (query built elsewhere)
		if isSwiftVariableArg(arg) {
			argText := strings.ToLower(arg.Text())
			// Only flag if the variable name suggests SQL
			if strings.Contains(argText, "query") || strings.Contains(argText, "sql") || strings.Contains(argText, "stmt") {
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-SWIFT-AST-001",
					Severity:      rules.High,
					SeverityLabel: rules.High.String(),
					Title:         "Potential SQL injection via variable query in " + funcName,
					Description:   "A variable named '" + arg.Text() + "' is passed as the query to " + funcName + ". If built with string interpolation, this enables SQL injection.",
					FilePath:      c.filePath,
					LineNumber:    int(n.StartRow()) + 1,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Use parameterized queries with sqlite3_bind_text/sqlite3_bind_int instead of building query strings.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      rules.LangSwift,
					Confidence:    "medium",
					Tags:          []string{"sql-injection", "injection", "sqlite"},
				})
				return
			}
		}
	}
}

// checkUIWebView detects usage of UIWebView (deprecated and insecure).
func (c *swiftChecker) checkUIWebView(n *ast.Node) {
	funcName := getSwiftFuncName(n)
	if funcName != "UIWebView" {
		return
	}

	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-SWIFT-AST-002",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Deprecated UIWebView usage",
		Description:   "UIWebView is deprecated since iOS 12 and has known security vulnerabilities including XSS and insecure JavaScript execution. Apple rejects apps using UIWebView.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Replace UIWebView with WKWebView which provides better security, performance, and content blocking.",
		CWEID:         "CWE-676",
		OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Language:      rules.LangSwift,
		Confidence:    "high",
		Tags:          []string{"ios", "webview", "deprecated"},
	})
}

// checkUserDefaultsSensitive detects UserDefaults.standard.set with sensitive keys.
func (c *swiftChecker) checkUserDefaultsSensitive(n *ast.Node) {
	text := n.Text()
	if !strings.Contains(text, "UserDefaults") {
		return
	}

	funcName := getSwiftMethodName(n)
	if funcName != "set" {
		return
	}

	// Check for sensitive key names in the forKey argument specifically
	args := getSwiftCallArgs(n)
	sensitiveKeys := []string{"password", "token", "secret", "apikey", "api_key", "credential", "pin", "ssn"}
	for _, arg := range args {
		// Only check arguments that have a forKey label
		keyValue := getSwiftForKeyValue(arg)
		if keyValue == "" {
			continue
		}
		lowerKey := strings.ToLower(keyValue)
		isSensitive := false
		for _, sk := range sensitiveKeys {
			if strings.Contains(lowerKey, sk) {
				isSensitive = true
				break
			}
		}
		if isSensitive {
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "GTSS-SWIFT-AST-003",
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Sensitive data stored in UserDefaults",
				Description:   "Storing sensitive data (passwords, tokens, keys) in UserDefaults is insecure. UserDefaults are stored as unencrypted plist files and can be read from device backups.",
				FilePath:      c.filePath,
				LineNumber:    int(n.StartRow()) + 1,
				MatchedText:   truncate(n.Text(), 200),
				Suggestion:    "Use the iOS Keychain (SecItemAdd/SecItemCopyMatching) for storing sensitive data securely.",
				CWEID:         "CWE-312",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      rules.LangSwift,
				Confidence:    "high",
				Tags:          []string{"ios", "sensitive-data", "user-defaults"},
			})
			return
		}
	}
}

// checkProcessExecution detects Process() usage with variable arguments.
func (c *swiftChecker) checkProcessExecution(n *ast.Node) {
	funcName := getSwiftFuncName(n)
	if funcName != "Process" && funcName != "NSTask" {
		return
	}

	// Just flag the creation - we also check assignments to launchPath/arguments
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-SWIFT-AST-004",
		Severity:      rules.Medium,
		SeverityLabel: rules.Medium.String(),
		Title:         "Process/NSTask usage detected",
		Description:   "Process (NSTask) is used for command execution. Ensure launchPath and arguments are not derived from untrusted input.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate and sanitize all inputs to Process. Use a fixed launchPath and explicitly validate arguments.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangSwift,
		Confidence:    "low",
		Tags:          []string{"command-execution", "process"},
	})
}

// checkProcessAssignment detects task.launchPath = variable and task.arguments = [variable].
func (c *swiftChecker) checkProcessAssignment(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}

	// Look for directly_assignable_expression > navigation_expression with launchPath or arguments
	lhs := named[0]
	if lhs.Type() != "directly_assignable_expression" {
		return
	}
	lhsText := lhs.Text()

	isLaunchPath := strings.HasSuffix(lhsText, ".launchPath") || strings.HasSuffix(lhsText, ".executableURL")
	isArguments := strings.HasSuffix(lhsText, ".arguments")

	if !isLaunchPath && !isArguments {
		return
	}

	// Check if the RHS is a variable (not a literal)
	rhs := named[1]
	if rhs.Type() == "simple_identifier" {
		label := "launchPath"
		if isArguments {
			label = "arguments"
		}
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-SWIFT-AST-004",
			Severity:      rules.High,
			SeverityLabel: rules.High.String(),
			Title:         "Process " + label + " set from variable",
			Description:   "Setting Process." + label + " from a variable may enable command injection if the value is attacker-controlled.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use a hardcoded " + label + " or validate the variable against an allowlist.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangSwift,
			Confidence:    "medium",
			Tags:          []string{"command-injection", "injection"},
		})
	}
}

// getSwiftFuncName extracts the function name from a call_expression.
// Swift uses: call_expression > simple_identifier (for direct calls).
func getSwiftFuncName(n *ast.Node) string {
	for _, child := range n.NamedChildren() {
		if child.Type() == "simple_identifier" {
			return child.Text()
		}
		if child.Type() == "navigation_expression" {
			// For chained calls, get the last simple_identifier
			last := ""
			child.Walk(func(inner *ast.Node) bool {
				if inner.Type() == "simple_identifier" {
					last = inner.Text()
				}
				return true
			})
			return last
		}
	}
	return ""
}

// getSwiftMethodName extracts the method name from a navigation chain call.
func getSwiftMethodName(n *ast.Node) string {
	for _, child := range n.NamedChildren() {
		if child.Type() == "navigation_expression" {
			navChildren := child.NamedChildren()
			for i := len(navChildren) - 1; i >= 0; i-- {
				if navChildren[i].Type() == "navigation_suffix" {
					for _, sc := range navChildren[i].NamedChildren() {
						if sc.Type() == "simple_identifier" {
							return sc.Text()
						}
					}
				}
			}
		}
	}
	return ""
}

// getSwiftCallArgs returns the value_argument nodes from a Swift call_expression.
func getSwiftCallArgs(n *ast.Node) []*ast.Node {
	for _, child := range n.NamedChildren() {
		if child.Type() == "call_suffix" {
			for _, sc := range child.NamedChildren() {
				if sc.Type() == "value_arguments" {
					return sc.NamedChildren()
				}
			}
		}
	}
	return nil
}

// containsSwiftInterpolation checks if a node contains interpolated_expression nodes
// inside string literals.
func containsSwiftInterpolation(n *ast.Node) bool {
	found := false
	n.Walk(func(child *ast.Node) bool {
		if found {
			return false
		}
		if child.Type() == "interpolated_expression" {
			found = true
			return false
		}
		return true
	})
	return found
}

// isSwiftVariableArg returns true if a value_argument contains only a simple_identifier
// (i.e., it's a bare variable reference, not a literal or expression).
func isSwiftVariableArg(n *ast.Node) bool {
	named := n.NamedChildren()
	if len(named) != 1 {
		return false
	}
	return named[0].Type() == "simple_identifier"
}

// getSwiftForKeyValue extracts the string value from a forKey: "value" argument.
// Returns "" if this is not a forKey argument or has no string literal value.
func getSwiftForKeyValue(n *ast.Node) string {
	// A forKey argument looks like: value_argument > value_argument_label("forKey") + line_string_literal
	hasForKey := false
	var stringValue string
	for _, child := range n.NamedChildren() {
		if child.Type() == "value_argument_label" {
			if child.Text() == "forKey" {
				hasForKey = true
			}
		}
		if child.Type() == "line_string_literal" {
			for _, sc := range child.NamedChildren() {
				if sc.Type() == "line_str_text" {
					stringValue = sc.Text()
				}
			}
		}
	}
	if hasForKey {
		return stringValue
	}
	return ""
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
