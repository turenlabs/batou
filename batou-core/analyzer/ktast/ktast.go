package ktast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// KotlinASTAnalyzer performs AST-based security analysis of Kotlin source code.
type KotlinASTAnalyzer struct{}

func init() {
	rules.Register(&KotlinASTAnalyzer{})
}

func (k *KotlinASTAnalyzer) ID() string                      { return "BATOU-KT-AST" }
func (k *KotlinASTAnalyzer) Name() string                    { return "Kotlin AST Security Analyzer" }
func (k *KotlinASTAnalyzer) DefaultSeverity() rules.Severity { return rules.High }
func (k *KotlinASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangKotlin} }
func (k *KotlinASTAnalyzer) Description() string {
	return "AST-based analysis of Kotlin/Android code for SQL injection, JavaScript interface exposure, sensitive data in SharedPreferences, command injection, unsafe deserialization, server-side template injection, and SSRF."
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
			c.checkUnsafeDeserialization(n)
			c.checkJacksonDefaultTyping(n)
			c.checkSSTI(n)
			c.checkSSRF(n)
		}
		return true
	})
}

// checkUnsafeDeserialization detects native Java/Kotlin deserialization sink
// constructors that, by their nature, deserialize an arbitrary object graph from
// an untrusted stream (CWE-502). These are gadget-chain RCE primitives and have
// no safe variant when fed an attacker-controlled stream, so the constructor call
// itself is the structural signal — independent of whether taint is proven.
//
// Detected: ObjectInputStream(...), XMLDecoder(...). The constructor is a
// call_expression whose direct simple_identifier child is the class name (no
// receiver navigation), e.g. `ObjectInputStream(req.inputStream)`.
func (c *ktChecker) checkUnsafeDeserialization(n *ast.Node) {
	ctorName := getKotlinConstructorName(n)
	if ctorName != "ObjectInputStream" && ctorName != "XMLDecoder" {
		return
	}
	// Require at least one argument (a stream/source); a no-arg call is unusual
	// and not a meaningful sink.
	if len(getKotlinCallArgs(n)) == 0 {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-KT-AST-005",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Unsafe deserialization via " + ctorName,
		Description:   ctorName + " deserializes an arbitrary object graph from the supplied stream. If the stream is attacker-controlled, gadget chains on the classpath can be triggered to achieve remote code execution.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid native Java serialization for untrusted data. Use a safe data format (JSON with explicit types) and, if ObjectInputStream is unavoidable, install a strict resolveClass allowlist (e.g. ValidatingObjectInputStream / JEP 290 ObjectInputFilter).",
		CWEID:         "CWE-502",
		OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		Language:      rules.LangKotlin,
		Confidence:    "high",
		Tags:          []string{"deserialization", "rce", "insecure-deserialization"},
	})
}

// checkJacksonDefaultTyping detects enabling Jackson polymorphic default typing,
// which turns ObjectMapper.readValue into a deserialization gadget sink (CWE-502).
// Calls like mapper.enableDefaultTyping() / mapper.activateDefaultTyping(...) are
// the structural signal — once enabled, any subsequent readValue on untrusted
// JSON is exploitable, so the enabling call itself is flagged.
func (c *ktChecker) checkJacksonDefaultTyping(n *ast.Node) {
	method := getKotlinMethodName(n)
	if method != "enableDefaultTyping" && method != "activateDefaultTyping" {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-KT-AST-006",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Jackson polymorphic default typing enabled",
		Description:   "Enabling Jackson default typing (" + method + ") embeds concrete class names in JSON and instantiates them during deserialization. On untrusted input this is a known remote-code-execution vector via gadget chains.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Do not enable default typing on untrusted JSON. Use explicit @JsonTypeInfo with a closed @JsonSubTypes set, or a strict PolymorphicTypeValidator that allowlists only the expected types.",
		CWEID:         "CWE-502",
		OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		Language:      rules.LangKotlin,
		Confidence:    "high",
		Tags:          []string{"deserialization", "jackson", "rce"},
	})
}

// checkSSTI detects server-side template injection (CWE-1336) where a template
// engine renders a DYNAMICALLY built template source string. Static literal
// template strings are safe; only a concatenated or string-interpolated template
// argument is flagged, keeping the structural check specific.
//
// Sinks: templateEngine.process / .evaluate / Velocity.evaluate /
// compileInline / compileTemplate where the first argument is the template source.
func (c *ktChecker) checkSSTI(n *ast.Node) {
	method := getKotlinMethodName(n)
	var isSink bool
	switch method {
	case "process", "evaluate", "compileInline", "createTemplate", "renderTemplate":
		isSink = true
	}
	if !isSink {
		return
	}
	args := getKotlinCallArgs(n)
	if len(args) == 0 {
		return
	}
	// The template source is the first argument. Only a dynamically constructed
	// template (concat or ${} interpolation) is an injection risk; a static
	// string literal is safe.
	if !argIsDynamicString(args[0]) {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-KT-AST-007",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Server-side template injection via " + method,
		Description:   "A dynamically built template string is passed to " + method + ". Template engines (Thymeleaf, Velocity, Freemarker, Handlebars) evaluate expressions in the template body, so concatenating untrusted input into the template source allows arbitrary expression evaluation / RCE.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Never build the template source from user input. Keep templates static and pass user data only as context/model variables that the engine escapes.",
		CWEID:         "CWE-1336",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangKotlin,
		Confidence:    "high",
		Tags:          []string{"ssti", "injection", "template-injection"},
	})
}

// checkSSRF detects server-side request forgery (CWE-918) where a java.net.URL is
// opened on a non-literal (variable / expression) target. The receiver chain of
// the call is inspected for a `URL(<arg>)` constructor whose argument is not a
// static string literal. `.openConnection()`, `.openStream()`, `.readText()` and
// `.getContent()` on such a URL all initiate the outbound request.
func (c *ktChecker) checkSSRF(n *ast.Node) {
	method := getKotlinMethodName(n)
	switch method {
	case "openConnection", "openStream", "readText", "getContent", "readBytes":
	default:
		return
	}
	// Inspect the navigation receiver for a URL(...) constructor with a
	// non-literal argument.
	recv := getKotlinNavReceiver(n)
	if recv == nil {
		return
	}
	if !receiverHasDynamicURL(recv) {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-KT-AST-008",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Server-side request forgery via URL." + method,
		Description:   "A java.net.URL constructed from a non-literal target is opened with " + method + "(). If the target is attacker-controlled, this enables SSRF — reaching internal services, cloud metadata endpoints, or arbitrary hosts.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the URL against an allowlist of permitted hosts/schemes before opening it. Reject internal/loopback/link-local addresses and disable following redirects to them.",
		CWEID:         "CWE-918",
		OWASPCategory: "A10:2021-Server-Side Request Forgery",
		Language:      rules.LangKotlin,
		Confidence:    "high",
		Tags:          []string{"ssrf", "request-forgery"},
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
			RuleID:        "BATOU-KT-AST-001",
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
		RuleID:        "BATOU-KT-AST-002",
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
			RuleID:        "BATOU-KT-AST-003",
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
			RuleID:        "BATOU-KT-AST-004",
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

// getKotlinConstructorName returns the class name when n is a constructor-style
// call_expression whose callee is a bare simple_identifier (no navigation),
// e.g. `ObjectInputStream(...)` -> "ObjectInputStream". Navigation calls
// (`mapper.readValue(...)`) return "".
func getKotlinConstructorName(n *ast.Node) string {
	children := n.NamedChildren()
	if len(children) == 0 {
		return ""
	}
	// A constructor call's first named child is the simple_identifier callee,
	// directly followed by a call_suffix. Navigation calls have a
	// navigation_expression as the first child instead.
	first := children[0]
	if first.Type() == "simple_identifier" {
		return first.Text()
	}
	return ""
}

// getKotlinNavReceiver returns the receiver node of a navigation call
// (the left side of the final `.method`), e.g. for `URL(x).openConnection()`
// it returns the `URL(x)` node. Returns nil for non-navigation calls.
func getKotlinNavReceiver(n *ast.Node) *ast.Node {
	for _, child := range n.NamedChildren() {
		if child.Type() == "navigation_expression" {
			nc := child.NamedChildren()
			if len(nc) > 0 {
				return nc[0]
			}
		}
	}
	return nil
}

// argIsDynamicString reports whether a value_argument's expression is a
// dynamically constructed string: a concatenation (additive_expression) or a
// string literal containing a Kotlin ${...} interpolation. A plain string
// literal with only static content is NOT dynamic.
func argIsDynamicString(arg *ast.Node) bool {
	found := false
	arg.Walk(func(child *ast.Node) bool {
		if found {
			return false
		}
		switch child.Type() {
		case "additive_expression":
			found = true
			return false
		case "interpolated_expression", "string_template_expression":
			found = true
			return false
		}
		return true
	})
	return found
}

// receiverHasDynamicURL reports whether the receiver chain contains a
// `URL(<arg>)` constructor whose first argument is NOT a static string literal
// (i.e. a variable or expression), the structural signal for SSRF.
func receiverHasDynamicURL(recv *ast.Node) bool {
	found := false
	recv.Walk(func(child *ast.Node) bool {
		if found {
			return false
		}
		if child.Type() != "call_expression" {
			return true
		}
		if getKotlinConstructorName(child) != "URL" {
			return true
		}
		args := getKotlinCallArgs(child)
		if len(args) == 0 {
			return true
		}
		if !argIsStaticStringLiteral(args[0]) {
			found = true
			return false
		}
		return true
	})
	return found
}

// argIsStaticStringLiteral reports whether a value_argument is exactly a static
// string literal with no interpolation (so `URL("http://x")` is treated as safe,
// while `URL(target)` or `URL("$h/x")` is treated as dynamic/non-literal).
func argIsStaticStringLiteral(arg *ast.Node) bool {
	children := arg.NamedChildren()
	if len(children) != 1 {
		return false
	}
	lit := children[0]
	if lit.Type() != "string_literal" {
		return false
	}
	// A literal that embeds an interpolation is not static.
	for _, lc := range lit.NamedChildren() {
		if lc.Type() == "interpolated_expression" || lc.Type() == "interpolation" {
			return false
		}
	}
	return true
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
