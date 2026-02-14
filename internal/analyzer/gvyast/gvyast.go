package gvyast

import (
	"strings"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

// GroovyASTAnalyzer performs AST-based security analysis of Groovy source code.
type GroovyASTAnalyzer struct{}

func init() {
	rules.Register(&GroovyASTAnalyzer{})
}

func (g *GroovyASTAnalyzer) ID() string                        { return "GTSS-GVY-AST" }
func (g *GroovyASTAnalyzer) Name() string                      { return "Groovy AST Security Analyzer" }
func (g *GroovyASTAnalyzer) DefaultSeverity() rules.Severity   { return rules.High }
func (g *GroovyASTAnalyzer) Languages() []rules.Language        { return []rules.Language{rules.LangGroovy} }
func (g *GroovyASTAnalyzer) Description() string {
	return "AST-based analysis of Groovy code for string.execute() command injection, GroovyShell code injection, GString SQL injection, Jenkins pipeline injection, and Runtime.exec."
}

func (g *GroovyASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangGroovy {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &gvyChecker{
		tree:     tree,
		filePath: ctx.FilePath,
		content:  ctx.Content,
	}
	c.walk()
	return c.findings
}

type gvyChecker struct {
	tree     *ast.Tree
	filePath string
	content  string
	findings []rules.Finding
}

func (c *gvyChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "function_call":
			c.checkStringExecute(n)
			c.checkGroovyShellEvaluate(n)
			c.checkRuntimeExec(n)
			c.checkJenkinsPipeline(n)
			c.checkGStringSQLInjection(n)
		case "declaration":
			c.checkGStringSQLDeclaration(n)
		}
		return true
	})
}

// checkStringExecute detects "string".execute() patterns in Groovy.
// In Groovy, String.execute() runs a shell command.
func (c *gvyChecker) checkStringExecute(n *ast.Node) {
	// function_call > dotted_identifier > string + "execute"
	for _, child := range n.NamedChildren() {
		if child.Type() == "dotted_identifier" {
			hasInterpolatedString := false
			hasExecute := false

			for _, dc := range child.NamedChildren() {
				if dc.Type() == "string" {
					// Check if the string has interpolation
					for _, sc := range dc.NamedChildren() {
						if sc.Type() == "interpolation" {
							hasInterpolatedString = true
						}
					}
				}
				if dc.Type() == "identifier" && dc.Text() == "execute" {
					hasExecute = true
				}
			}

			if hasExecute && hasInterpolatedString {
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-GVY-AST-001",
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "Command injection via String.execute()",
					Description:   "Groovy's String.execute() runs the string as a shell command. Using GString interpolation with user input enables command injection.",
					FilePath:      c.filePath,
					LineNumber:    int(n.StartRow()) + 1,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Use ['command', 'arg1', 'arg2'].execute() with a list to avoid shell interpretation, and validate all inputs.",
					CWEID:         "CWE-78",
					OWASPCategory: "A03:2021-Injection",
					Language:      rules.LangGroovy,
					Confidence:    "high",
					Tags:          []string{"command-injection", "injection", "rce"},
				})
			} else if hasExecute {
				// .execute() on any variable is still potentially dangerous
				for _, dc := range child.NamedChildren() {
					if dc.Type() == "identifier" && dc.Text() != "execute" {
						c.findings = append(c.findings, rules.Finding{
							RuleID:        "GTSS-GVY-AST-001",
							Severity:      rules.High,
							SeverityLabel: rules.High.String(),
							Title:         "Command execution via .execute()",
							Description:   "Groovy's .execute() method runs the receiver string as a shell command. If the string is derived from user input, this enables command injection.",
							FilePath:      c.filePath,
							LineNumber:    int(n.StartRow()) + 1,
							MatchedText:   truncate(n.Text(), 200),
							Suggestion:    "Use ['command', 'arg1', 'arg2'].execute() with a list to avoid shell interpretation.",
							CWEID:         "CWE-78",
							OWASPCategory: "A03:2021-Injection",
							Language:      rules.LangGroovy,
							Confidence:    "medium",
							Tags:          []string{"command-injection", "injection"},
						})
						break
					}
				}
			}
		}
	}
}

// checkGroovyShellEvaluate detects GroovyShell().evaluate(variable).
func (c *gvyChecker) checkGroovyShellEvaluate(n *ast.Node) {
	methodName := getGroovyMethodName(n)
	if methodName != "evaluate" && methodName != "parse" {
		return
	}

	text := n.Text()
	if !strings.Contains(text, "GroovyShell") && !strings.Contains(text, "GroovyClassLoader") && !strings.Contains(text, "Eval") {
		return
	}

	// Check if argument is a variable
	if hasGroovyVariableArg(n) {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-GVY-AST-002",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Code injection via GroovyShell." + methodName + "()",
			Description:   "GroovyShell." + methodName + "() executes arbitrary Groovy code. Passing variable input enables remote code execution.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(text, 200),
			Suggestion:    "Avoid evaluating dynamic code. Use a sandboxed CompilerConfiguration with SecureASTCustomizer if evaluation is required.",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangGroovy,
			Confidence:    "high",
			Tags:          []string{"code-injection", "injection", "rce"},
		})
	}
}

// checkRuntimeExec detects Runtime.getRuntime().exec(variable).
func (c *gvyChecker) checkRuntimeExec(n *ast.Node) {
	methodName := getGroovyMethodName(n)
	if methodName != "exec" {
		return
	}

	text := n.Text()
	if !strings.Contains(text, "Runtime") {
		return
	}

	if hasGroovyVariableArg(n) {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-GVY-AST-003",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Command injection via Runtime.exec",
			Description:   "Passing variable arguments to Runtime.getRuntime().exec() enables command injection if the input is attacker-controlled.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(text, 200),
			Suggestion:    "Avoid Runtime.exec with user input. Use ProcessBuilder with explicit arguments.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangGroovy,
			Confidence:    "high",
			Tags:          []string{"command-injection", "injection", "rce"},
		})
	}
}

// checkJenkinsPipeline detects sh/bat commands in Jenkins pipeline with variable interpolation.
func (c *gvyChecker) checkJenkinsPipeline(n *ast.Node) {
	// In Groovy tree-sitter, Jenkins sh "..." appears as function_call
	named := n.NamedChildren()
	if len(named) == 0 {
		return
	}

	// Check for sh/bat function calls
	funcName := ""
	for _, child := range named {
		if child.Type() == "identifier" {
			funcName = child.Text()
			break
		}
		if child.Type() == "dotted_identifier" {
			ids := child.NamedChildren()
			if len(ids) > 0 && ids[0].Type() == "identifier" {
				funcName = ids[0].Text()
			}
			break
		}
	}

	if funcName != "sh" && funcName != "bat" {
		return
	}

	// Check if the arguments contain GString interpolation
	for _, child := range named {
		if child.Type() == "argument_list" {
			hasInterpolation := false
			child.Walk(func(inner *ast.Node) bool {
				if inner.Type() == "interpolation" {
					hasInterpolation = true
					return false
				}
				return true
			})
			if hasInterpolation {
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-GVY-AST-004",
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "Jenkins pipeline " + funcName + " with interpolated string",
					Description:   "Using GString interpolation in Jenkins " + funcName + " step enables command injection. Variables are expanded before shell execution.",
					FilePath:      c.filePath,
					LineNumber:    int(n.StartRow()) + 1,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Use single-quoted strings ('" + funcName + " 'echo $VAR'') or shell variable references instead of GString interpolation.",
					CWEID:         "CWE-78",
					OWASPCategory: "A03:2021-Injection",
					Language:      rules.LangGroovy,
					Confidence:    "high",
					Tags:          []string{"command-injection", "injection", "jenkins"},
				})
			}
		}
	}
}

// checkGStringSQLInjection detects SQL strings with GString interpolation
// passed to function calls (e.g., query("SELECT ... ${var}")).
func (c *gvyChecker) checkGStringSQLInjection(n *ast.Node) {
	methodName := getGroovyMethodName(n)
	sqlMethods := map[string]bool{
		"query": true, "execute": true, "executeQuery": true,
		"executeUpdate": true, "rows": true, "firstRow": true,
		"eachRow": true,
	}
	if !sqlMethods[methodName] {
		return
	}

	// Check if arguments contain SQL string with interpolation
	for _, child := range n.NamedChildren() {
		if child.Type() == "argument_list" {
			child.Walk(func(inner *ast.Node) bool {
				if inner.Type() == "string" {
					hasSql := false
					hasInterp := false
					for _, sc := range inner.NamedChildren() {
						if sc.Type() == "string_content" {
							upper := strings.ToUpper(sc.Text())
							keywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"}
							for _, kw := range keywords {
								if strings.Contains(upper, kw) {
									hasSql = true
									break
								}
							}
						}
						if sc.Type() == "interpolation" {
							hasInterp = true
						}
					}
					if hasSql && hasInterp {
						c.findings = append(c.findings, rules.Finding{
							RuleID:        "GTSS-GVY-AST-005",
							Severity:      rules.Critical,
							SeverityLabel: rules.Critical.String(),
							Title:         "SQL injection via GString interpolation",
							Description:   "SQL query built with GString interpolation in " + methodName + "(). Groovy GStrings expand variables before the query is sent, enabling SQL injection.",
							FilePath:      c.filePath,
							LineNumber:    int(inner.StartRow()) + 1,
							MatchedText:   truncate(inner.Text(), 200),
							Suggestion:    "Use parameterized queries: sql.rows('SELECT * FROM users WHERE id = ?', [userId]).",
							CWEID:         "CWE-89",
							OWASPCategory: "A03:2021-Injection",
							Language:      rules.LangGroovy,
							Confidence:    "high",
							Tags:          []string{"sql-injection", "injection"},
						})
						return false
					}
				}
				return true
			})
		}
	}
}

// checkGStringSQLDeclaration detects SQL assignments with GString interpolation
// like: def sql = "SELECT ... ${var}".
func (c *gvyChecker) checkGStringSQLDeclaration(n *ast.Node) {
	// declaration > identifier (name) + string (value)
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}

	// Check if the variable name suggests SQL
	varName := ""
	for _, child := range named {
		if child.Type() == "identifier" {
			varName = strings.ToLower(child.Text())
			break
		}
	}

	sqlNames := map[string]bool{
		"sql": true, "query": true, "stmt": true, "statement": true,
		"sqlquery": true, "sqlstmt": true,
	}
	if !sqlNames[varName] {
		return
	}

	// Check for SQL string with interpolation
	for _, child := range named {
		if child.Type() == "string" {
			hasSql := false
			hasInterp := false
			for _, sc := range child.NamedChildren() {
				if sc.Type() == "string_content" {
					upper := strings.ToUpper(sc.Text())
					keywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE"}
					for _, kw := range keywords {
						if strings.Contains(upper, kw) {
							hasSql = true
							break
						}
					}
				}
				if sc.Type() == "interpolation" {
					hasInterp = true
				}
			}
			if hasSql && hasInterp {
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-GVY-AST-005",
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "SQL injection via GString interpolation in variable",
					Description:   "Variable '" + varName + "' contains a SQL query built with GString interpolation, enabling SQL injection.",
					FilePath:      c.filePath,
					LineNumber:    int(child.StartRow()) + 1,
					MatchedText:   truncate(child.Text(), 200),
					Suggestion:    "Use parameterized queries instead of string interpolation for SQL.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      rules.LangGroovy,
					Confidence:    "high",
					Tags:          []string{"sql-injection", "injection"},
				})
			}
		}
	}
}

// getGroovyMethodName extracts the last method name from a Groovy function_call.
func getGroovyMethodName(n *ast.Node) string {
	for _, child := range n.NamedChildren() {
		if child.Type() == "dotted_identifier" {
			ids := child.NamedChildren()
			// Get the last identifier that isn't part of a function_call
			for i := len(ids) - 1; i >= 0; i-- {
				if ids[i].Type() == "identifier" {
					return ids[i].Text()
				}
			}
		}
		if child.Type() == "identifier" {
			return child.Text()
		}
	}
	return ""
}

// hasGroovyVariableArg checks if a function_call has variable arguments.
func hasGroovyVariableArg(n *ast.Node) bool {
	for _, child := range n.NamedChildren() {
		if child.Type() == "argument_list" {
			found := false
			child.Walk(func(inner *ast.Node) bool {
				if found {
					return false
				}
				if inner.Type() == "identifier" {
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

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
