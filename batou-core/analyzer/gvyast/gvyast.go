package gvyast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// GroovyASTAnalyzer performs AST-based security analysis of Groovy source code.
type GroovyASTAnalyzer struct{}

func init() {
	rules.Register(&GroovyASTAnalyzer{})
}

func (g *GroovyASTAnalyzer) ID() string                      { return "BATOU-GVY-AST" }
func (g *GroovyASTAnalyzer) Name() string                    { return "Groovy AST Security Analyzer" }
func (g *GroovyASTAnalyzer) DefaultSeverity() rules.Severity { return rules.High }
func (g *GroovyASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangGroovy} }
func (g *GroovyASTAnalyzer) Description() string {
	return "AST-based analysis of Groovy code for string.execute() command injection, GroovyShell code injection, GString SQL injection, Jenkins pipeline injection, Runtime.exec, XXE (XmlSlurper/XmlParser without secure processing), unsafe deserialization, and SSRF."
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
	// File-level signal: if XXE-hardening is configured anywhere in the
	// file, suppress the structural XXE finding. Groovy/Java XML parsers
	// are hardened by setting FEATURE_SECURE_PROCESSING or disabling
	// external DTDs/entities via setFeature(...). We detect this once on
	// the raw content so a hardened parser in the same file doesn't fire.
	c.xxeHardened = groovyHasXXEHardening(ctx.Content)
	c.walk()
	return c.findings
}

type gvyChecker struct {
	tree        *ast.Tree
	filePath    string
	content     string
	xxeHardened bool
	ctorVars    map[string]string // varName -> constructed type (e.g. "XmlSlurper")
	findings    []rules.Finding
}

func (c *gvyChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	// First pass: map local variables to the constructor type they hold
	// (e.g. `def p = new XmlSlurper()` → p:XmlSlurper). Used so that a
	// later `p.parse(req)` / `ois.readObject()` / `conn.openConnection()`
	// can be attributed structurally even when the receiver is a variable.
	c.ctorVars = map[string]string{}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "declaration" {
			c.recordCtorVar(n)
		}
		return true
	})

	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "function_call":
			c.checkStringExecute(n)
			c.checkGroovyShellEvaluate(n)
			c.checkRuntimeExec(n)
			c.checkJenkinsPipeline(n)
			c.checkGStringSQLInjection(n)
			c.checkXXE(n)
			c.checkUnsafeDeserialization(n)
			c.checkSSRF(n)
		case "declaration":
			c.checkGStringSQLDeclaration(n)
		}
		return true
	})
}

// recordCtorVar records `def x = new <Type>(...)` assignments so later
// method calls on x can be attributed to <Type> structurally.
func (c *gvyChecker) recordCtorVar(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	varName := ""
	for _, child := range named {
		if child.Type() == "identifier" {
			varName = child.Text()
			break
		}
	}
	if varName == "" {
		return
	}
	// The RHS is typically a unary_op ("new ...") wrapping a function_call,
	// or a bare function_call. Find the constructed type name.
	t := groovyConstructedType(n)
	if t == "" {
		return
	}
	// SnakeYAML hardened with a SafeConstructor is not a deserialization
	// gadget vector — record it under a benign sentinel so the later
	// `.load()` call is not flagged. groovyIsYamlType() only matches the
	// bare "Yaml" form, so "Yaml/safe" is invisible to the deser check.
	if groovyIsYamlType(t) && strings.Contains(n.Text(), "SafeConstructor") {
		t = t + "/safe"
	}
	c.ctorVars[varName] = t
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
					RuleID:        "BATOU-GVY-AST-001",
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
				// .execute() on a variable: only flag when the variable name
				// strongly suggests a shell command. The previous branch
				// fired on EVERY .execute() call, which produced 100+
				// hits per Groovy repo because .execute() is also the SQL
				// JDBC Statement method, HTTP-client method, Future
				// resolver, etc. Without type info we can't disambiguate;
				// the name heuristic catches the obvious cases (cmd,
				// command, shell, script) while dropping the noise.
				for _, dc := range child.NamedChildren() {
					if dc.Type() != "identifier" || dc.Text() == "execute" {
						continue
					}
					if !groovyExecuteNameLikelyShell(dc.Text()) {
						break
					}
					c.findings = append(c.findings, rules.Finding{
						RuleID:        "BATOU-GVY-AST-001",
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
			RuleID:        "BATOU-GVY-AST-002",
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
			RuleID:        "BATOU-GVY-AST-003",
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
					RuleID:        "BATOU-GVY-AST-004",
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
							RuleID:        "BATOU-GVY-AST-005",
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
					RuleID:        "BATOU-GVY-AST-005",
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

// checkXXE detects XML parsing that is vulnerable to XML External Entity
// (XXE) injection (CWE-611). Groovy's XmlSlurper and XmlParser resolve
// external entities and DTDs by default; parsing untrusted XML without
// disabling external entities / enabling secure-processing exposes XXE,
// SSRF, and local file disclosure.
//
// Two structural shapes are detected:
//
//	new XmlSlurper().parse(input)            // direct chained construction
//	new XmlParser().parseText(input)
//
//	def p = new XmlSlurper(); p.parse(input) // construction recorded, then call
//
// The finding is suppressed when the file configures XXE-hardening
// (setFeature FEATURE_SECURE_PROCESSING / disallow-doctype-decl /
// external-general-entities false), tracked at the file level.
func (c *gvyChecker) checkXXE(n *ast.Node) {
	if c.xxeHardened {
		return
	}
	method := getGroovyMethodName(n)
	if method != "parse" && method != "parseText" {
		return
	}
	objType := c.groovyCallReceiverType(n)
	if !groovyIsXMLParserType(objType) {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-GVY-AST-006",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "XML External Entity (XXE) via " + objType + "." + method + "()",
		Description:   "Groovy's " + objType + " resolves external entities and DTDs by default. Parsing untrusted XML without disabling external entities enables XXE: file disclosure, SSRF, and denial of service.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Disable external entities before parsing, e.g. new XmlSlurper(false, false) or set parser.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true) and FEATURE_SECURE_PROCESSING.",
		CWEID:         "CWE-611",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      rules.LangGroovy,
		Confidence:    "high",
		Tags:          []string{"xxe", "xml"},
	})
}

// checkUnsafeDeserialization detects Java/Groovy object deserialization of
// untrusted data (CWE-502). ObjectInputStream.readObject() and SnakeYAML's
// new Yaml().load(...) reconstruct arbitrary object graphs and are a classic
// RCE gadget vector.
func (c *gvyChecker) checkUnsafeDeserialization(n *ast.Node) {
	method := getGroovyMethodName(n)
	objType := c.groovyCallReceiverType(n)

	var matched bool
	var title, desc, suggestion string
	switch {
	case method == "readObject" && (objType == "ObjectInputStream" || strings.Contains(strings.ToLower(objType), "objectinput")):
		matched = true
		title = "Unsafe deserialization via ObjectInputStream.readObject()"
		desc = "ObjectInputStream.readObject() reconstructs an arbitrary Java object graph. Deserializing untrusted bytes enables remote code execution through gadget chains."
		suggestion = "Do not deserialize untrusted data. Use a safe format (JSON) or a hardened ObjectInputFilter / allowlist of permitted classes."
	case method == "load" && groovyIsYamlType(objType) && !strings.Contains(n.Text(), "SafeConstructor"):
		// `new Yaml(new SafeConstructor()).load(x)` chained inline is not a
		// gadget vector; the var-tracked form is filtered in recordCtorVar.
		matched = true
		title = "Unsafe YAML deserialization via " + objType + ".load()"
		desc = "SnakeYAML's load() instantiates arbitrary types named in the document. Loading untrusted YAML enables remote code execution; use loadAs or a SafeConstructor."
		suggestion = "Use new Yaml(new SafeConstructor()).load(...) or yaml.loadAs(input, ExpectedType.class) to restrict instantiable types."
	}
	if !matched {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-GVY-AST-007",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         title,
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    suggestion,
		CWEID:         "CWE-502",
		OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		Language:      rules.LangGroovy,
		Confidence:    "high",
		Tags:          []string{"deserialization", "rce"},
	})
}

// checkSSRF detects server-side request forgery (CWE-918): opening a network
// connection or reading from a URL whose value is a variable (not a string
// literal). Groovy idioms:
//
//	new URL(target).openConnection()
//	new URL(target).text / .getText() / .openStream() / .newInputStream()
//	target.toURL().text / .openConnection()
func (c *gvyChecker) checkSSRF(n *ast.Node) {
	method := getGroovyMethodName(n)
	ssrfMethods := map[string]bool{
		"openConnection": true, "openStream": true,
		"getText": true, "newInputStream": true, "newReader": true,
	}
	if !ssrfMethods[method] {
		return
	}
	objType := c.groovyCallReceiverType(n)
	// Receiver must be a URL: either `new URL(...)` chained, or `x.toURL()`.
	isURL := objType == "URL" || c.groovyReceiverChainHasURL(n)
	if !isURL {
		return
	}
	// Require a non-literal URL argument somewhere in the URL construction
	// (variable / interpolation) — a hardcoded literal URL is not SSRF.
	if !c.groovyURLArgIsDynamic(n) {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-GVY-AST-008",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Server-Side Request Forgery (SSRF) via URL." + method + "()",
		Description:   "A network connection is opened to a URL built from a variable. If the URL is attacker-controlled, this enables SSRF against internal services and cloud metadata endpoints.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the URL against an allowlist of permitted hosts/schemes before fetching, and block requests to private/link-local IP ranges.",
		CWEID:         "CWE-918",
		OWASPCategory: "A10:2021-Server-Side Request Forgery",
		Language:      rules.LangGroovy,
		Confidence:    "medium",
		Tags:          []string{"ssrf"},
	})
}

// groovyCallReceiverType returns the type of the object a method is called
// on, for a function_call node. It resolves both:
//   - chained construction: `new XmlSlurper().parse(x)` → "XmlSlurper"
//   - recorded ctor vars:   `p.parse(x)` where p = new XmlSlurper() → "XmlSlurper"
//
// Returns "" when the receiver type cannot be determined.
func (c *gvyChecker) groovyCallReceiverType(n *ast.Node) string {
	for _, child := range n.NamedChildren() {
		if child.Type() != "dotted_identifier" {
			continue
		}
		ids := child.NamedChildren()
		if len(ids) == 0 {
			continue
		}
		// Receiver is the first child of the dotted_identifier.
		recv := ids[0]
		switch recv.Type() {
		case "function_call":
			// new Type().method() — recv is `Type()`; first id is the type.
			if t := groovyConstructedType(recv); t != "" {
				return t
			}
			for _, rc := range recv.NamedChildren() {
				if rc.Type() == "identifier" {
					return rc.Text()
				}
			}
		case "identifier":
			// var.method() — look up the recorded constructor type.
			if t, ok := c.ctorVars[recv.Text()]; ok {
				return t
			}
		}
		return ""
	}
	return ""
}

// groovyReceiverChainHasURL reports whether the receiver chain of a call
// contains a URL construction or a .toURL() conversion, e.g.
// `new URL(x).openConnection()` or `x.toURL().text`.
func (c *gvyChecker) groovyReceiverChainHasURL(n *ast.Node) bool {
	for _, child := range n.NamedChildren() {
		if child.Type() != "dotted_identifier" {
			continue
		}
		found := false
		child.Walk(func(inner *ast.Node) bool {
			if found {
				return false
			}
			if inner.Type() == "identifier" {
				t := inner.Text()
				if t == "URL" || t == "toURL" {
					found = true
					return false
				}
			}
			return true
		})
		return found
	}
	return false
}

// groovyURLArgIsDynamic reports whether the URL receiver is built from a
// non-literal value (variable / interpolated string), i.e. an identifier or
// interpolation appears inside a `new URL(...)` or `x.toURL()` construction.
// A URL built purely from string literals is treated as not-SSRF.
func (c *gvyChecker) groovyURLArgIsDynamic(n *ast.Node) bool {
	for _, child := range n.NamedChildren() {
		if child.Type() != "dotted_identifier" {
			continue
		}
		dynamic := false
		// Walk the receiver chain; any identifier (other than the URL/
		// method names) or interpolation means the URL value is dynamic.
		child.Walk(func(inner *ast.Node) bool {
			switch inner.Type() {
			case "interpolation":
				dynamic = true
				return false
			case "identifier":
				t := inner.Text()
				if t != "URL" && t != "toURL" && t != "openConnection" &&
					t != "openStream" && t != "getText" && t != "text" &&
					t != "newInputStream" && t != "newReader" {
					dynamic = true
					return false
				}
			}
			return true
		})
		return dynamic
	}
	return false
}

// groovyConstructedType returns the class name from a `new Type(...)`
// expression rooted at (or wrapped by) node n. Handles the tree-sitter
// shape where `new X()` is a unary_op wrapping a function_call whose first
// identifier is the type, as well as a bare function_call.
func groovyConstructedType(n *ast.Node) string {
	var fc *ast.Node
	switch n.Type() {
	case "function_call":
		fc = n
	default:
		// Search children for the nearest function_call (handles unary_op
		// "new ..." and declaration wrappers).
		n.Walk(func(inner *ast.Node) bool {
			if fc != nil {
				return false
			}
			if inner.Type() == "function_call" {
				fc = inner
				return false
			}
			return true
		})
	}
	if fc == nil {
		return ""
	}
	for _, child := range fc.NamedChildren() {
		if child.Type() == "identifier" {
			return child.Text()
		}
	}
	return ""
}

// groovyIsXMLParserType reports whether a type name is a Groovy/Java XML
// parser whose default configuration is XXE-vulnerable.
func groovyIsXMLParserType(t string) bool {
	switch t {
	case "XmlSlurper", "XmlParser", "SAXParser", "DocumentBuilder", "SAXBuilder":
		return true
	}
	return false
}

// groovyIsYamlType reports whether a type name is a SnakeYAML loader.
func groovyIsYamlType(t string) bool {
	return t == "Yaml" || strings.HasSuffix(t, "Yaml")
}

// groovyHasXXEHardening reports whether the file content configures XML
// parser hardening that mitigates XXE. Used to suppress the structural XXE
// finding when the parser is explicitly secured.
func groovyHasXXEHardening(content string) bool {
	lower := strings.ToLower(content)
	markers := []string{
		"feature_secure_processing",
		"secure-processing",
		"disallow-doctype-decl",
		"external-general-entities",
		"external-parameter-entities",
		"setexpandentityreferences",
		"access_external_dtd",
		// new XmlSlurper(false, false) disables validation + namespace;
		// the third-arg `allowDocTypeDeclaration=false` (default) hardens it.
		"new xmlslurper(false, false, false)",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
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

// groovyExecuteNameLikelyShell returns true when the variable name hints
// that .execute() will run a shell command rather than a SQL statement,
// HTTP request, or async task. Used to narrow the medium-confidence
// branch of BATOU-GVY-AST-001 which previously fired on every
// `<identifier>.execute()` call.
func groovyExecuteNameLikelyShell(varName string) bool {
	lower := strings.ToLower(varName)
	for _, hint := range []string{"cmd", "command", "shell", "script", "exec"} {
		if strings.Contains(lower, hint) {
			return true
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
