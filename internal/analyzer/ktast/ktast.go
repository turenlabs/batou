package ktast

import (
	"strings"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

// KotlinASTAnalyzer performs AST-based security analysis of Kotlin source code.
type KotlinASTAnalyzer struct{}

func init() {
	rules.Register(&KotlinASTAnalyzer{})
}

func (k *KotlinASTAnalyzer) ID() string                        { return "GTSS-KT-AST" }
func (k *KotlinASTAnalyzer) Name() string                      { return "Kotlin AST Security Analyzer" }
func (k *KotlinASTAnalyzer) DefaultSeverity() rules.Severity   { return rules.High }
func (k *KotlinASTAnalyzer) Languages() []rules.Language        { return []rules.Language{rules.LangKotlin} }
func (k *KotlinASTAnalyzer) Description() string {
	return "AST-based analysis of Kotlin/Android code for SQL injection, JavaScript interface exposure, sensitive data in SharedPreferences, and command injection."
}

func (k *KotlinASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangKotlin {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &ktChecker{
		tree:     tree,
		filePath: ctx.FilePath,
		content:  ctx.Content,
	}
	c.walk()
	return c.findings
}

type ktChecker struct {
	tree     *ast.Tree
	filePath string
	content  string
	findings []rules.Finding
}

func (c *ktChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "call_expression" {
			c.checkRawQuery(n)
			c.checkAddJavascriptInterface(n)
			c.checkSensitiveSharedPrefs(n)
			c.checkRuntimeExec(n)
		}
		return true
	})
}

// checkRawQuery detects db.rawQuery("..." + var, ...) patterns.
func (c *ktChecker) checkRawQuery(n *ast.Node) {
	methodName := getKotlinMethodName(n)
	if methodName != "rawQuery" && methodName != "execSQL" && methodName != "compileStatement" {
		return
	}

	// Get the value_arguments
	args := getKotlinCallArgs(n)
	if len(args) == 0 {
		return
	}

	firstArg := args[0]
	if containsKotlinConcatOrTemplate(firstArg) {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-KT-AST-001",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL injection via Android " + methodName,
			Description:   "Building SQL queries with string concatenation or templates in " + methodName + " enables SQL injection attacks.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use parameterized queries: db.rawQuery(\"SELECT * FROM users WHERE id = ?\", arrayOf(userId)).",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangKotlin,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection", "android"},
		})
	}
}

// checkAddJavascriptInterface detects webView.addJavascriptInterface calls.
func (c *ktChecker) checkAddJavascriptInterface(n *ast.Node) {
	methodName := getKotlinMethodName(n)
	if methodName != "addJavascriptInterface" {
		return
	}

	c.findings = append(c.findings, rules.Finding{
		RuleID:        "GTSS-KT-AST-002",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "WebView JavaScript interface exposure",
		Description:   "addJavascriptInterface exposes Java/Kotlin objects to JavaScript, allowing untrusted web content to call native methods. On API < 17, all public methods are exposed.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use @JavascriptInterface annotation on specific methods only (API 17+). Validate all input from JavaScript. Consider using WebMessagePort for communication instead.",
		CWEID:         "CWE-749",
		OWASPCategory: "A04:2021-Insecure Design",
		Language:      rules.LangKotlin,
		Confidence:    "high",
		Tags:          []string{"android", "webview", "javascript-interface"},
	})
}

// checkSensitiveSharedPrefs detects SharedPreferences.putString with sensitive keys.
func (c *ktChecker) checkSensitiveSharedPrefs(n *ast.Node) {
	methodName := getKotlinMethodName(n)
	if methodName != "putString" && methodName != "putInt" {
		return
	}

	// Check if this is a SharedPreferences chain (look for .edit() in the call chain)
	text := n.Text()
	if !strings.Contains(text, "edit()") && !strings.Contains(text, "Editor") {
		// Also check parent context for prefs or SharedPreferences
		if !strings.Contains(text, "prefs") && !strings.Contains(text, "Prefs") && !strings.Contains(text, "sharedPref") {
			return
		}
	}

	// Check if the key is a sensitive value
	args := getKotlinCallArgs(n)
	if len(args) < 1 {
		return
	}

	firstArg := args[0]
	sensitiveKeys := []string{"password", "token", "secret", "key", "api_key", "apikey", "credential", "pin", "ssn"}
	argText := strings.ToLower(firstArg.Text())
	isSensitive := false
	for _, sk := range sensitiveKeys {
		if strings.Contains(argText, sk) {
			isSensitive = true
			break
		}
	}

	if isSensitive {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-KT-AST-003",
			Severity:      rules.High,
			SeverityLabel: rules.High.String(),
			Title:         "Sensitive data stored in SharedPreferences",
			Description:   "Storing sensitive data (passwords, tokens, keys) in SharedPreferences is insecure. SharedPreferences are stored as plain-text XML on the device filesystem.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use Android Keystore or EncryptedSharedPreferences from the AndroidX Security library for sensitive data.",
			CWEID:         "CWE-312",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      rules.LangKotlin,
			Confidence:    "high",
			Tags:          []string{"android", "sensitive-data", "shared-preferences"},
		})
	}
}

// checkRuntimeExec detects Runtime.getRuntime().exec(variable).
func (c *ktChecker) checkRuntimeExec(n *ast.Node) {
	methodName := getKotlinMethodName(n)
	if methodName != "exec" {
		return
	}

	text := n.Text()
	if !strings.Contains(text, "Runtime") && !strings.Contains(text, "getRuntime") {
		return
	}

	args := getKotlinCallArgs(n)
	if len(args) == 0 {
		return
	}

	// Check if argument is a variable (not a string literal)
	hasVarArg := false
	for _, arg := range args {
		arg.Walk(func(inner *ast.Node) bool {
			if inner.Type() == "simple_identifier" && inner.Parent() != nil && inner.Parent().Type() == "value_argument" {
				hasVarArg = true
				return false
			}
			return true
		})
	}

	if hasVarArg {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-KT-AST-004",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Command injection via Runtime.exec",
			Description:   "Passing variable arguments to Runtime.getRuntime().exec() enables command injection if the input is attacker-controlled.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(text, 200),
			Suggestion:    "Avoid Runtime.exec with user input. Use ProcessBuilder with explicit arguments instead.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangKotlin,
			Confidence:    "high",
			Tags:          []string{"command-injection", "injection", "rce"},
		})
	}
}

// getKotlinMethodName extracts the method name from a Kotlin call_expression.
// Kotlin uses navigation_expression > navigation_suffix > simple_identifier.
func getKotlinMethodName(n *ast.Node) string {
	for _, child := range n.NamedChildren() {
		if child.Type() == "navigation_expression" {
			for _, nc := range child.NamedChildren() {
				if nc.Type() == "navigation_suffix" {
					for _, sc := range nc.NamedChildren() {
						if sc.Type() == "simple_identifier" {
							return sc.Text()
						}
					}
				}
			}
		}
		// Direct function call: simple_identifier
		if child.Type() == "simple_identifier" {
			return child.Text()
		}
	}
	return ""
}

// getKotlinCallArgs returns the value_argument nodes from a Kotlin call_expression.
func getKotlinCallArgs(n *ast.Node) []*ast.Node {
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

// containsKotlinConcatOrTemplate checks if a node contains additive_expression
// or string templates.
func containsKotlinConcatOrTemplate(n *ast.Node) bool {
	found := false
	n.Walk(func(child *ast.Node) bool {
		if found {
			return false
		}
		if child.Type() == "additive_expression" {
			found = true
			return false
		}
		if child.Type() == "string_template_expression" {
			found = true
			return false
		}
		return true
	})
	return found
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
