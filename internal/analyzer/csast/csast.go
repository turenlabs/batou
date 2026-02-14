package csast

import (
	"strings"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

// CSharpASTAnalyzer performs AST-based security analysis of C# source code.
type CSharpASTAnalyzer struct{}

func init() {
	rules.Register(&CSharpASTAnalyzer{})
}

func (a *CSharpASTAnalyzer) ID() string                        { return "GTSS-CS-AST" }
func (a *CSharpASTAnalyzer) Name() string                      { return "C# AST Security Analyzer" }
func (a *CSharpASTAnalyzer) DefaultSeverity() rules.Severity   { return rules.High }
func (a *CSharpASTAnalyzer) Languages() []rules.Language        { return []rules.Language{rules.LangCSharp} }
func (a *CSharpASTAnalyzer) Description() string {
	return "AST-based analysis of C# code for SQL injection, insecure deserialization, command injection, ReDoS, and raw SQL in Entity Framework."
}

func (a *CSharpASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangCSharp {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &csChecker{
		tree:     tree,
		filePath: ctx.FilePath,
		content:  ctx.Content,
	}
	c.walk()
	return c.findings
}

type csChecker struct {
	tree     *ast.Tree
	filePath string
	content  string
	findings []rules.Finding
}

func (c *csChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "object_creation_expression":
			c.checkSqlCommandConcat(n)
			c.checkInsecureDeserializer(n)
			c.checkRegexWithoutTimeout(n)
		case "invocation_expression":
			c.checkProcessStart(n)
			c.checkRawSQLEntityFramework(n)
		}
		return true
	})
}

// checkSqlCommandConcat detects new SqlCommand("..." + var, conn) patterns.
func (c *csChecker) checkSqlCommandConcat(n *ast.Node) {
	// object_creation_expression: new > identifier (SqlCommand) > argument_list
	typeName := ""
	for _, child := range n.NamedChildren() {
		if child.Type() == "identifier" || child.Type() == "qualified_name" {
			typeName = child.Text()
		}
	}
	if typeName != "SqlCommand" && typeName != "SqlDataAdapter" && typeName != "OleDbCommand" && typeName != "OdbcCommand" {
		return
	}

	// Check if the first argument contains string concatenation or interpolation
	for _, child := range n.NamedChildren() {
		if child.Type() == "argument_list" {
			args := child.NamedChildren()
			if len(args) == 0 {
				return
			}
			firstArg := args[0]
			if containsConcatOrInterpolation(firstArg) {
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "GTSS-CS-AST-001",
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "SQL injection via " + typeName + " with string concatenation",
					Description:   "Building SQL queries with string concatenation or interpolation in " + typeName + " enables SQL injection attacks.",
					FilePath:      c.filePath,
					LineNumber:    int(n.StartRow()) + 1,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Use parameterized queries: new SqlCommand(\"SELECT * FROM users WHERE id = @id\", conn) with cmd.Parameters.AddWithValue(\"@id\", id).",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      rules.LangCSharp,
					Confidence:    "high",
					Tags:          []string{"sql-injection", "injection"},
				})
			}
		}
	}
}

// checkInsecureDeserializer detects instantiation of known insecure deserializers.
func (c *csChecker) checkInsecureDeserializer(n *ast.Node) {
	typeName := ""
	for _, child := range n.NamedChildren() {
		if child.Type() == "identifier" || child.Type() == "qualified_name" {
			typeName = child.Text()
		}
	}

	insecureTypes := map[string]string{
		"BinaryFormatter":       "BinaryFormatter is insecure and can lead to remote code execution via deserialization attacks.",
		"ObjectStateFormatter":  "ObjectStateFormatter is insecure and vulnerable to deserialization attacks.",
		"SoapFormatter":         "SoapFormatter is insecure and vulnerable to deserialization attacks.",
		"NetDataContractSerializer": "NetDataContractSerializer is insecure when deserializing untrusted data.",
		"LosFormatter":          "LosFormatter is insecure and vulnerable to deserialization attacks.",
	}

	if desc, ok := insecureTypes[typeName]; ok {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-CS-AST-002",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Insecure deserializer: " + typeName,
			Description:   desc,
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use System.Text.Json or Newtonsoft.Json with TypeNameHandling.None instead of " + typeName + ".",
			CWEID:         "CWE-502",
			OWASPCategory: "A08:2021-Software and Data Integrity Failures",
			Language:      rules.LangCSharp,
			Confidence:    "high",
			Tags:          []string{"deserialization", "rce"},
		})
	}
}

// checkRegexWithoutTimeout detects new Regex(pattern) without RegexOptions.
func (c *csChecker) checkRegexWithoutTimeout(n *ast.Node) {
	typeName := ""
	for _, child := range n.NamedChildren() {
		if child.Type() == "identifier" {
			typeName = child.Text()
		}
	}
	if typeName != "Regex" {
		return
	}

	// Check argument count - a Regex with a timeout has 3 args (pattern, options, timeout)
	// or at minimum 2 args with options. Single arg is vulnerable.
	for _, child := range n.NamedChildren() {
		if child.Type() == "argument_list" {
			args := child.NamedChildren()
			if len(args) == 1 {
				// Single arg: just the pattern, no timeout
				firstArg := args[0]
				isVariable := false
				firstArg.Walk(func(inner *ast.Node) bool {
					if inner.Type() == "identifier" && inner.Text() != "Regex" {
						isVariable = true
						return false
					}
					return true
				})
				if isVariable {
					c.findings = append(c.findings, rules.Finding{
						RuleID:        "GTSS-CS-AST-003",
						Severity:      rules.High,
						SeverityLabel: rules.High.String(),
						Title:         "Regex without timeout (ReDoS risk)",
						Description:   "Creating a Regex with a variable pattern and no timeout allows denial-of-service via catastrophic backtracking (ReDoS).",
						FilePath:      c.filePath,
						LineNumber:    int(n.StartRow()) + 1,
						MatchedText:   truncate(n.Text(), 200),
						Suggestion:    "Add a timeout: new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1)).",
						CWEID:         "CWE-1333",
						OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
						Language:      rules.LangCSharp,
						Confidence:    "medium",
						Tags:          []string{"redos", "dos", "regex"},
					})
				}
			}
		}
	}
}

// checkProcessStart detects Process.Start(variable).
func (c *csChecker) checkProcessStart(n *ast.Node) {
	// invocation_expression > member_access_expression + argument_list
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}

	memberAccess := named[0]
	if memberAccess.Type() != "member_access_expression" {
		return
	}

	maText := memberAccess.Text()
	if !strings.HasSuffix(maText, ".Start") {
		return
	}
	// Check it starts with Process
	if !strings.Contains(maText, "Process") {
		return
	}

	// Check if arguments contain variables (not just string literals)
	argList := named[1]
	if argList.Type() != "argument_list" {
		return
	}
	args := argList.NamedChildren()
	if len(args) == 0 {
		return
	}

	hasVarArg := false
	for _, arg := range args {
		arg.Walk(func(inner *ast.Node) bool {
			if inner.Type() == "identifier" {
				hasVarArg = true
				return false
			}
			return true
		})
	}

	if hasVarArg {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-CS-AST-004",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Command injection via Process.Start",
			Description:   "Process.Start with variable arguments enables command injection if the input is attacker-controlled.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Validate and sanitize arguments. Use ProcessStartInfo with explicit FileName and Arguments instead of passing user input directly.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangCSharp,
			Confidence:    "high",
			Tags:          []string{"command-injection", "injection", "rce"},
		})
	}
}

// checkRawSQLEntityFramework detects ExecuteSqlRaw/FromSqlRaw with interpolated strings.
func (c *csChecker) checkRawSQLEntityFramework(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}

	memberAccess := named[0]
	if memberAccess.Type() != "member_access_expression" {
		return
	}

	// Get the method name (last identifier in the member_access_expression)
	maChildren := memberAccess.NamedChildren()
	if len(maChildren) < 2 {
		return
	}
	methodName := maChildren[len(maChildren)-1].Text()

	efMethods := map[string]bool{
		"ExecuteSqlRaw":          true,
		"ExecuteSqlRawAsync":     true,
		"FromSqlRaw":            true,
		"SqlQuery":              true,
		"ExecuteSqlInterpolated": false, // safe, but we check anyway if passed concat
	}

	isUnsafe, found := efMethods[methodName]
	if !found {
		return
	}

	argList := named[1]
	if argList.Type() != "argument_list" {
		return
	}

	args := argList.NamedChildren()
	if len(args) == 0 {
		return
	}

	firstArg := args[0]
	if isUnsafe && containsConcatOrInterpolation(firstArg) {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "GTSS-CS-AST-005",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL injection via Entity Framework " + methodName,
			Description:   "Using " + methodName + " with string concatenation or interpolation enables SQL injection. EF raw SQL methods do not parameterize interpolated strings.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use ExecuteSqlInterpolated or FromSqlInterpolated which safely parameterize interpolated values, or pass parameters explicitly.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangCSharp,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection", "entity-framework"},
		})
	}
}

// containsConcatOrInterpolation checks if a node contains binary_expression with +
// or interpolated_string_expression with interpolation children.
func containsConcatOrInterpolation(n *ast.Node) bool {
	found := false
	n.Walk(func(child *ast.Node) bool {
		if found {
			return false
		}
		switch child.Type() {
		case "binary_expression":
			// Check for string concatenation with +
			text := child.Text()
			if strings.Contains(text, "+") {
				hasLiteral := false
				hasVar := false
				for _, bc := range child.NamedChildren() {
					if bc.Type() == "string_literal" || bc.Type() == "interpolated_string_expression" {
						hasLiteral = true
					} else if bc.Type() == "identifier" {
						hasVar = true
					}
				}
				if hasLiteral && hasVar {
					found = true
					return false
				}
			}
		case "interpolated_string_expression":
			// Check for interpolation nodes
			for _, ic := range child.NamedChildren() {
				if ic.Type() == "interpolation" {
					found = true
					return false
				}
			}
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
