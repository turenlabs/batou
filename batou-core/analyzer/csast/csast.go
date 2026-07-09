package csast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// CSharpASTAnalyzer performs AST-based security analysis of C# source code.
type CSharpASTAnalyzer struct{}

func init() {
	rules.Register(&CSharpASTAnalyzer{})
}

func (a *CSharpASTAnalyzer) ID() string                      { return "BATOU-CS-AST" }
func (a *CSharpASTAnalyzer) Name() string                    { return "C# AST Security Analyzer" }
func (a *CSharpASTAnalyzer) DefaultSeverity() rules.Severity { return rules.High }
func (a *CSharpASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangCSharp} }
func (a *CSharpASTAnalyzer) Description() string {
	return "AST-based analysis of C# code for SQL injection, insecure deserialization, command injection, ReDoS, raw SQL in Entity Framework, reflected XSS (Razor/Response.Write), and open redirect."
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
			c.checkHtmlStringXSS(n)
		case "invocation_expression":
			c.checkProcessStart(n)
			c.checkRawSQLEntityFramework(n)
			c.checkRazorXSSInvocation(n)
			c.checkOpenRedirect(n)
			c.checkDeserializeInvocation(n)
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
					RuleID:        "BATOU-CS-AST-001",
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
		"BinaryFormatter":           "BinaryFormatter is insecure and can lead to remote code execution via deserialization attacks.",
		"ObjectStateFormatter":      "ObjectStateFormatter is insecure and vulnerable to deserialization attacks.",
		"SoapFormatter":             "SoapFormatter is insecure and vulnerable to deserialization attacks.",
		"NetDataContractSerializer": "NetDataContractSerializer is insecure when deserializing untrusted data.",
		"LosFormatter":              "LosFormatter is insecure and vulnerable to deserialization attacks.",
	}

	if desc, ok := insecureTypes[typeName]; ok {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-CS-AST-002",
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
						RuleID:        "BATOU-CS-AST-003",
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
			RuleID:        "BATOU-CS-AST-004",
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
		"FromSqlRaw":             true,
		"SqlQuery":               true,
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
			RuleID:        "BATOU-CS-AST-005",
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

// checkRazorXSSInvocation detects reflected XSS via Razor/WebForms write sinks that
// emit unencoded output: @Html.Raw(var) and Response.Write(var) with a non-literal
// argument. Pure string-literal arguments are ignored as safe.
func (c *csChecker) checkRazorXSSInvocation(n *ast.Node) {
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Type() != "member_access_expression" {
		return
	}
	receiver, method := memberReceiverAndName(fn)
	if method == "" {
		return
	}

	// Set of (receiver.method) XSS write sinks.
	isXSSSink := false
	switch {
	case method == "Raw" && (receiver == "Html" || strings.HasSuffix(receiver, ".Html") || receiver == "@Html"):
		isXSSSink = true // @Html.Raw(...)
	case method == "Write" && (receiver == "Response" || strings.HasSuffix(receiver, ".Response")):
		isXSSSink = true // Response.Write(...)
	case method == "WriteLine" && (receiver == "Response" || strings.HasSuffix(receiver, ".Response")):
		isXSSSink = true // Response.WriteLine(...)
	case method == "Write" && receiver == "context.Response.Output":
		isXSSSink = true
	}
	if !isXSSSink {
		return
	}

	argList := n.ChildByFieldName("arguments")
	if argList == nil {
		return
	}
	if !argHasNonLiteral(argList) {
		return // only string literals -> safe
	}

	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CS-AST-006",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Reflected XSS via " + receiver + "." + method,
		Description:   "Writing a non-constant value through " + receiver + "." + method + " emits unencoded output to the response/HTML, enabling reflected cross-site scripting (XSS) when the value is attacker-controlled.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Encode output before writing it: use @Html.Encode(...) / HttpUtility.HtmlEncode(...), or render via Razor's default-encoded @value instead of Html.Raw / Response.Write.",
		CWEID:         "CWE-79",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangCSharp,
		Confidence:    "high",
		Tags:          []string{"xss", "razor"},
	})
}

// checkHtmlStringXSS detects new HtmlString(var) / new MvcHtmlString(var) /
// new RawString(var) with a non-literal argument, which marks a value as
// pre-encoded HTML and bypasses Razor auto-encoding (reflected XSS, CWE-79).
func (c *csChecker) checkHtmlStringXSS(n *ast.Node) {
	typeName := objectCreationType(n)
	switch typeName {
	case "HtmlString", "MvcHtmlString", "RawString", "HtmlText":
	default:
		return
	}

	argList := n.ChildByFieldName("arguments")
	if argList == nil {
		return
	}
	if !argHasNonLiteral(argList) {
		return
	}

	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CS-AST-007",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Reflected XSS via new " + typeName,
		Description:   "Wrapping a non-constant value in " + typeName + " marks it as trusted, pre-encoded HTML and bypasses Razor's automatic output encoding, enabling reflected XSS if the value is attacker-controlled.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Do not wrap user-controlled data in " + typeName + ". HTML-encode it (HttpUtility.HtmlEncode) and let Razor render it through the default-encoded @value syntax.",
		CWEID:         "CWE-79",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangCSharp,
		Confidence:    "high",
		Tags:          []string{"xss", "razor"},
	})
}

// checkOpenRedirect detects Redirect(var) / RedirectPermanent(var) with a
// non-literal target, where the redirect destination may be attacker-controlled
// (open redirect, CWE-601). Both bare-call (Redirect(x)) and member-call
// (Response.Redirect(x)) forms are handled.
func (c *csChecker) checkOpenRedirect(n *ast.Node) {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return
	}

	method := ""
	switch fn.Type() {
	case "identifier":
		method = fn.Text() // Redirect(x) inside a controller
	case "member_access_expression":
		_, method = memberReceiverAndName(fn)
	default:
		return
	}

	switch method {
	case "Redirect", "RedirectPermanent", "RedirectPreserveMethod", "LocalRedirect":
	default:
		return
	}

	argList := n.ChildByFieldName("arguments")
	if argList == nil {
		return
	}
	args := argList.NamedChildren()
	if len(args) == 0 {
		return
	}
	if !argHasNonLiteral(argList) {
		return // constant redirect target -> safe
	}

	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CS-AST-008",
		Severity:      rules.Medium,
		SeverityLabel: rules.Medium.String(),
		Title:         "Open redirect via " + method,
		Description:   "Passing a non-constant value to " + method + " lets an attacker control the redirect destination, enabling open-redirect / phishing attacks (CWE-601).",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the redirect target against an allow-list of known-safe local paths, or use Url.IsLocalUrl(target) / LocalRedirect(target) before redirecting.",
		CWEID:         "CWE-601",
		OWASPCategory: "A01:2021-Broken Access Control",
		Language:      rules.LangCSharp,
		Confidence:    "high",
		Tags:          []string{"open-redirect", "redirect"},
	})
}

// checkDeserializeInvocation detects x.Deserialize(stream) where x is a known
// insecure formatter constructed inline, e.g. new BinaryFormatter().Deserialize(s).
// The construction node is already flagged by checkInsecureDeserializer; this
// catches the dataflow sink (.Deserialize(...)) directly for the call site.
func (c *csChecker) checkDeserializeInvocation(n *ast.Node) {
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Type() != "member_access_expression" {
		return
	}
	_, method := memberReceiverAndName(fn)
	if method != "Deserialize" && method != "UnsafeDeserialize" && method != "DeserializeMethodResponse" {
		return
	}

	// Only flag when the receiver is (or constructs) a known-insecure formatter.
	recvExpr := fn.ChildByFieldName("expression")
	if recvExpr == nil {
		return
	}
	insecure := false
	switch recvExpr.Type() {
	case "object_creation_expression":
		switch objectCreationType(recvExpr) {
		case "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter":
			insecure = true
		}
	default:
		// Receiver text references one of the insecure formatter type names.
		rt := recvExpr.Text()
		for _, t := range []string{"BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter"} {
			if strings.Contains(rt, t) {
				insecure = true
				break
			}
		}
	}
	if !insecure {
		return
	}

	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CS-AST-009",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Insecure deserialization via " + method,
		Description:   "Calling " + method + " on an insecure formatter (BinaryFormatter/SoapFormatter/LosFormatter/etc.) deserializes untrusted data and can lead to remote code execution.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Replace the insecure formatter with System.Text.Json or Newtonsoft.Json (TypeNameHandling.None). Never deserialize untrusted input with BinaryFormatter.",
		CWEID:         "CWE-502",
		OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		Language:      rules.LangCSharp,
		Confidence:    "high",
		Tags:          []string{"deserialization", "rce"},
	})
}

// memberReceiverAndName returns the receiver text and the trailing member name
// of a member_access_expression (e.g. "Response.Write" -> "Response", "Write").
func memberReceiverAndName(ma *ast.Node) (receiver, name string) {
	expr := ma.ChildByFieldName("expression")
	nm := ma.ChildByFieldName("name")
	if expr != nil {
		receiver = expr.Text()
	}
	if nm != nil {
		name = nm.Text()
	}
	if name == "" {
		// Fallback: last named child is the member name.
		kids := ma.NamedChildren()
		if len(kids) > 0 {
			name = kids[len(kids)-1].Text()
		}
	}
	return receiver, name
}

// objectCreationType returns the type name of an object_creation_expression
// (the node tagged with field "type"), falling back to the first identifier/
// qualified_name child.
func objectCreationType(n *ast.Node) string {
	if t := n.ChildByFieldName("type"); t != nil {
		return t.Text()
	}
	for _, child := range n.NamedChildren() {
		if child.Type() == "identifier" || child.Type() == "qualified_name" {
			return child.Text()
		}
	}
	return ""
}

// argHasNonLiteral reports whether the argument_list contains at least one
// argument that is not a pure string/numeric/boolean literal — i.e. a variable,
// member access, invocation, concatenation, or interpolation. Used to suppress
// the "constant argument" safe case for XSS/redirect sinks.
func argHasNonLiteral(argList *ast.Node) bool {
	args := argList.NamedChildren()
	if len(args) == 0 {
		return false
	}
	for _, arg := range args {
		// Each "argument" node wraps the actual expression; unwrap it.
		expr := arg
		if arg.Type() == "argument" {
			kids := arg.NamedChildren()
			if len(kids) > 0 {
				expr = kids[len(kids)-1]
			}
		}
		switch expr.Type() {
		case "string_literal", "verbatim_string_literal", "raw_string_literal",
			"integer_literal", "real_literal", "boolean_literal",
			"character_literal", "null_literal":
			// pure literal -> safe, keep checking other args
			continue
		case "interpolated_string_expression":
			// Interpolated string with an interpolation hole is non-constant.
			for _, ic := range expr.NamedChildren() {
				if ic.Type() == "interpolation" {
					return true
				}
			}
			continue
		default:
			return true
		}
	}
	return false
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
