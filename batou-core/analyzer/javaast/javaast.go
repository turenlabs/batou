package javaast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// JavaASTAnalyzer performs AST-based security analysis of Java source code.
type JavaASTAnalyzer struct{}

func init() {
	rules.Register(&JavaASTAnalyzer{})
}

func (j *JavaASTAnalyzer) ID() string                      { return "BATOU-JAVAAST" }
func (j *JavaASTAnalyzer) Name() string                    { return "Java AST Security Analyzer" }
func (j *JavaASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (j *JavaASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangJava} }
func (j *JavaASTAnalyzer) Description() string {
	return "AST-based analysis of Java source for SQL injection via string concatenation, Runtime.exec command injection, ObjectInputStream deserialization, JNDI lookup injection, unsafe reflection via Class.forName, XXE via unhardened XML parser factories, reflected XSS via servlet writers, SSRF via new URL(...), and SpEL/OGNL expression injection."
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
			c.checkReflectedXSS(n)
			c.checkSpELOGNL(n)
			c.checkXXEParse(n)
			c.checkInsecureTLS(n)
		}
		if n.Type() == "object_creation_expression" {
			c.checkObjectCreation(n)
			c.checkSSRFURL(n)
			c.checkProcessBuilder(n)
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

	// Runtime.exec(var) where the receiver is a Runtime instance variable
	// (e.g. `rt.exec(cmd)` after `Runtime rt = Runtime.getRuntime()`), not the
	// chained Runtime.getRuntime().exec(...) form handled above.
	if methodName == "exec" && objName == "Runtime" {
		c.checkRuntimeExec(n)
	}

	// readObject() deserialization
	if methodName == "readObject" {
		c.checkDeserialization(n)
	}

	// JNDI lookup. Gate on the receiver looking like a JNDI Context — the
	// bare method name "lookup" collides with many enum-style static lookup
	// tables (Bouncy Castle CRLReason.lookup, ECNamedDomainParameters.lookup),
	// Apache StrLookup.lookup, Spring SpringEnvironmentLookup.lookup, etc.
	// Real JNDI receivers are Context / InitialContext / DirContext /
	// LdapContext (or instances thereof, conventionally named ctx, context,
	// initialContext, ic, ictx, jndi*, ldap*, namingContext, directory).
	if methodName == "lookup" && isJNDIReceiver(objName) {
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
				RuleID:        "BATOU-JAVAAST-003",
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
				RuleID:        "BATOU-JAVAAST-001",
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
		RuleID:        "BATOU-JAVAAST-002",
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

// checkProcessBuilder detects `new ProcessBuilder(...)` whose command list
// contains a STRING CONCATENATION that embeds a non-literal value, e.g.
// `new ProcessBuilder(new String[]{"sh","-c","ping -c 2 " + ipAddress})` or the
// varargs `new ProcessBuilder("sh","-c","ping " + ip)`. Building a shell command
// string by concatenating input directly inside the constructor is the
// canonical command-injection shape (the SasanLabs/VulnerableApp ping idiom):
// when the process is run via `sh -c`/`cmd /c`, the concatenated value is parsed
// by the shell, so attacker metacharacters inject additional commands.
//
// This is the construction-side companion to checkRuntimeExec: the javaast
// analyzer's contract advertised `new ProcessBuilder(var)` coverage but only the
// Runtime.exec() form was wired, so helper code that builds a process from a
// concatenated tainted ipAddress/filename went uncovered by the AST tier.
//
// Scope is deliberately limited to the in-constructor concatenation form. A bare
// variable / List argument (`new ProcessBuilder(argList)` / `pb.command(argList)`)
// is NOT flagged here: an argv list passed to ProcessBuilder is overwhelmingly a
// fixed command vector assembled elsewhere, and whether any element is tainted is
// a dataflow question the taint tier already answers — flagging the bare-list
// construction structurally floods false positives on safe fixed-command usage.
// A purely literal command list is likewise never flagged.
func (c *javaChecker) checkProcessBuilder(n *ast.Node) {
	if javaConstructedType(n) != "ProcessBuilder" {
		return
	}
	args := n.ChildByFieldName("arguments")
	if args == nil {
		args = findChild(n, "argument_list")
	}
	if args == nil {
		return
	}
	if !anyProcessBuilderArgIsTaintedConcat(args) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JAVAAST-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via ProcessBuilder",
		Description:   "A ProcessBuilder command element is built by concatenating a string with a non-literal value. When the process is run through a shell (sh -c / cmd /c), a user-controlled value concatenated into the command lets an attacker inject shell metacharacters and execute arbitrary system commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Never concatenate input into a shell command string. Pass a fixed argv list (no `sh -c`) and validate/allowlist any user-supplied argument (e.g. restrict an IP/hostname to a strict pattern) before adding it to the command list.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "rce", "ast"},
	})
}

// anyProcessBuilderArgIsTaintedConcat reports whether any command element in a
// ProcessBuilder constructor argument_list is a string concatenation that
// embeds a non-literal operand. It descends into array_creation_expression /
// array_initializer so the `new String[]{"sh","-c","ping "+ip}` idiom is
// inspected element-by-element.
func anyProcessBuilderArgIsTaintedConcat(args *ast.Node) bool {
	for _, arg := range args.NamedChildren() {
		if processBuilderElementIsTaintedConcat(arg) {
			return true
		}
	}
	return false
}

// processBuilderElementIsTaintedConcat reports whether a single command element
// (or an array of them) is a variable-bearing string concatenation. Bare
// variables and pure literals return false.
func processBuilderElementIsTaintedConcat(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "binary_expression":
		// "ping " + ip — flagged only when an operand is non-literal.
		return containsStringConcat(n)
	case "array_creation_expression", "array_initializer":
		for _, child := range n.NamedChildren() {
			if processBuilderElementIsTaintedConcat(child) {
				return true
			}
		}
		return false
	}
	return false
}

// checkDeserialization flags readObject() calls.
func (c *javaChecker) checkDeserialization(n *ast.Node) {
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JAVAAST-003",
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
		RuleID:        "BATOU-JAVAAST-004",
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
		RuleID:        "BATOU-JAVAAST-005",
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

// checkXXEParse detects an XML parse() call whose underlying parser factory
// (DocumentBuilderFactory / SAXParserFactory / XMLInputFactory / SchemaFactory /
// TransformerFactory) was created in the enclosing method WITHOUT any of the
// hardening flags that disable DOCTYPE/external-entity resolution. Unhardened
// factories resolve external entities by default, so parse()-ing attacker XML
// allows XXE (file read, SSRF, billion-laughs).
//
// This is a *structural misconfig* detector, not a dataflow one: the absence of
// a setFeature("...disallow-doctype-decl...", true) / setExpandEntityReferences
// (false) / XMLConstants.FEATURE_SECURE_PROCESSING call in the same method is
// the vulnerability, independent of whether the parsed argument is tainted.
// The taint tier already covers the source->parse() flow; this gives the same
// class the AST confidence tier when the factory is left in its insecure
// default state.
func (c *javaChecker) checkXXEParse(n *ast.Node) {
	methodName := javaMethodName(n)
	// XML parse entrypoints across DOM (parse), SAX (parse), StAX
	// (createXMLStreamReader/createXMLEventReader), JAXP transform/newSchema,
	// JDOM/dom4j (build/read).
	if !isXMLParseMethod(methodName) {
		return
	}
	// Confine the analysis to the enclosing method/constructor body so that a
	// hardening call elsewhere in the file does not mask a different method's
	// misconfig, and vice-versa.
	scope := enclosingBody(n)
	if scope == nil {
		return
	}
	// JAXB Unmarshaller.unmarshal(...) is a distinct XXE vector with no JAXP
	// *factory* in scope to key on: a vanilla Unmarshaller resolves external
	// entities by default. Handle it via its own discriminating shape before the
	// factory gate (which it would otherwise fail). checkJAXBUnmarshal reports
	// true once it has definitively handled a genuine JAXB unmarshal (fired or
	// recognized a safe shape), so the generic factory path is skipped.
	if methodName == "unmarshal" && c.checkJAXBUnmarshal(n, scope) {
		return
	}
	// Require an XML parser factory to be constructed in this scope; otherwise
	// "parse"/"read"/"build" is too generic (collides with JSON parsers,
	// number parsing, file builders, etc.).
	if !scopeCreatesXMLFactory(scope) {
		return
	}
	// If the scope hardens the factory on a path that unconditionally reaches
	// this parse call, it's safe — suppress. Hardening nested inside a branch
	// (e.g. `if (securityEnabled) { xif.setProperty(ACCESS_EXTERNAL_DTD, "") }`)
	// that does NOT also contain the parse call does not protect it: the
	// hardening may be skipped while the parse still runs. This is the canonical
	// "security toggle defaults off" XXE-evasion shape (WebGoat CommentsCache).
	if scopeHasXXEHardening(scope, n) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JAVAAST-006",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "XXE: XML parsed by an unhardened parser factory",
		Description:   "An XML document is parsed via a DocumentBuilderFactory/SAXParserFactory/XMLInputFactory created without disabling DOCTYPE declarations or external entity resolution. Unhardened JAXP factories resolve external entities by default, enabling XXE (arbitrary file disclosure, SSRF, and denial of service).",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Harden the factory before parsing: dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false); dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false); dbf.setExpandEntityReferences(false);",
		CWEID:         "CWE-611",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"xxe", "xml", "misconfig", "ast"},
	})
}

// checkJAXBUnmarshal detects a JAXB Unmarshaller.unmarshal(<raw input>) call
// that resolves external entities by default (CWE-611). Unlike DOM/SAX/StAX,
// JAXB exposes no JAXP factory to harden directly, so the structural detector
// above (scopeCreatesXMLFactory) never fires on it.
//
// To stay false-positive-safe at this structural tier, it fires ONLY when the
// argument is a *raw* byte/char/entity input that JAXB itself will parse with
// external entities enabled — an InputStream, File, Reader, or InputSource. It
// deliberately does NOT fire when the argument is a StAX reader
// (XMLEventReader/XMLStreamReader — the application's own XML pipeline, commonly
// fed by a hardened/defensive XMLInputFactory), a wrapped
// javax.xml.transform.Source, a DOM Node, or any argument whose type cannot be
// positively resolved to a raw input. That conservative allowlist accepts a
// tolerable false negative (a StAX/Source pipeline built from an *unhardened*
// factory) in exchange for never flagging the idiomatic safe StAX/Source forms
// used throughout real codebases (e.g. Spring's createDefensiveInputFactory()).
//
// It returns true once it has definitively handled a genuine JAXB unmarshal —
// either by emitting a finding or by recognizing a non-raw/safe shape — so the
// caller skips the generic factory path. It returns false for non-JAXB
// `.unmarshal(...)` calls (Jackson/Gson, or a JAXB unmarshal whose context is
// established outside this method scope), leaving prior behavior unchanged.
func (c *javaChecker) checkJAXBUnmarshal(n, scope *ast.Node) bool {
	// (a) Confirm this is genuinely JAXB: a JAXBContext is constructed or an
	//     Unmarshaller is established in this method scope. Without that anchor,
	//     "unmarshal" is too generic (Jackson XmlMapper, custom DTOs, etc.).
	if !scopeEstablishesJAXBUnmarshaller(scope) {
		return false
	}
	// (b) Fire only on a positively-resolved raw byte/char/entity input. StAX
	//     readers, wrapped Sources, DOM nodes, and unresolvable args are the
	//     developer's own XML pipeline — not flagged (avoids FPs on idiomatic
	//     safe code; tolerable FN).
	if !jaxbUnmarshalArgIsRawInput(n, scope) {
		return true
	}
	// (c) Even for a raw input, if the enclosing scope hardens an XML parser on a
	//     path that reaches this call, suppress — reuse the existing control-flow-
	//     aware hardening check (defense in depth; can only reduce firing).
	if scopeHasXXEHardening(scope, n) {
		return true
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JAVAAST-006",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "XXE: untrusted XML unmarshalled by an unhardened JAXB Unmarshaller",
		Description:   "A JAXB Unmarshaller.unmarshal(...) call consumes a raw InputStream/File/Reader/InputSource without disabling DOCTYPE declarations or external-entity resolution. A vanilla JAXB Unmarshaller resolves external entities by default, enabling XXE (arbitrary file disclosure, SSRF, and denial of service). The secure form unmarshals a javax.xml.transform.Source (e.g. a SAXSource) built from an XMLReader configured with disallow-doctype-decl.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Do not pass a raw stream to unmarshal(). Build a hardened SAXSource: SAXParserFactory spf = SAXParserFactory.newInstance(); spf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); spf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false); spf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false); Source src = new SAXSource(spf.newSAXParser().getXMLReader(), new InputSource(in)); unmarshaller.unmarshal(src);",
		CWEID:         "CWE-611",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"xxe", "xml", "jaxb", "ast"},
	})
	return true
}

// checkInsecureTLS detects improper TLS certificate / hostname validation
// (CWE-295): an all-accepting HostnameVerifier or an empty-bodied
// X509TrustManager wired into the JSSE / OkHttp / HttpsURLConnection stack.
// These disable the protections TLS provides against man-in-the-middle
// attacks. Detection is purely STRUCTURAL — it only fires when the supplied
// verifier/trust-manager body is provably permissive (a bare `return true`
// verifier, or empty checkServerTrusted/checkClientTrusted bodies). A verifier
// or trust manager with any real validation logic in its body is NOT flagged,
// which keeps the false-positive rate near zero (CodeQL's "NoHostnameVerification"
// / "TrustAllX509TrustManager" queries cover the same class; this is an
// independent implementation from the CWE-295 definition + JSSE API docs).
func (c *javaChecker) checkInsecureTLS(n *ast.Node) {
	methodName := javaMethodName(n)
	switch methodName {
	case "setHostnameVerifier", "setDefaultHostnameVerifier", "hostnameVerifier":
		// The verifier is the first argument. Flag only if its body always
		// returns true (lambda `-> true`, or an anonymous HostnameVerifier whose
		// verify(...) body is `return true;`).
		arg := firstCallArg(n)
		if arg == nil {
			return
		}
		if !verifierAlwaysTrue(arg) {
			return
		}
		c.appendInsecureTLS(n, "BATOU-JAVAAST-010",
			"Insecure TLS: HostnameVerifier accepts all hostnames",
			"A custom HostnameVerifier that returns true for every hostname disables TLS hostname verification, allowing a man-in-the-middle to present a certificate for any host. This defeats the purpose of HTTPS.",
			"Remove the custom verifier and rely on the default HostnameVerifier, or implement verify() to actually compare the hostname against the certificate's CN/SAN.")
	case "init":
		// SSLContext.init(KeyManager[], TrustManager[], SecureRandom): the
		// second argument carries the trust managers. Flag when it constructs an
		// X509TrustManager with empty checkServerTrusted / checkClientTrusted
		// bodies (an all-trusting trust manager).
		if scopeHasEmptyX509TrustManager(n) {
			c.appendInsecureTLS(n, "BATOU-JAVAAST-011",
				"Insecure TLS: X509TrustManager trusts all certificates",
				"An X509TrustManager whose checkServerTrusted()/checkClientTrusted() methods have empty bodies accepts any certificate without validation, including self-signed and attacker-controlled certificates. This enables man-in-the-middle attacks against every TLS connection using this context.",
				"Implement certificate-chain validation, or use the platform default TrustManagerFactory (TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())) instead of a custom all-trusting trust manager.")
		}
	}
}

// appendInsecureTLS records a CWE-295 finding.
func (c *javaChecker) appendInsecureTLS(n *ast.Node, ruleID, title, desc, fix string) {
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        ruleID,
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         title,
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    fix,
		CWEID:         "CWE-295",
		OWASPCategory: "A07:2021-Identification and Authentication Failures",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"tls", "certificate-validation", "misconfig", "ast"},
	})
}

// firstCallArg returns the first argument node of a method_invocation, skipping
// the opening paren and punctuation.
func firstCallArg(n *ast.Node) *ast.Node {
	args := n.ChildByFieldName("arguments")
	if args == nil {
		args = findChild(n, "argument_list")
	}
	if args == nil {
		return nil
	}
	return firstNamedChild(args)
}

// verifierAlwaysTrue reports whether the supplied HostnameVerifier argument is
// an unconditional accept-all: a lambda whose body is the literal `true`, or an
// anonymous HostnameVerifier class whose verify() method body is exactly
// `return true;`.
func verifierAlwaysTrue(arg *ast.Node) bool {
	switch arg.Type() {
	case "lambda_expression":
		body := arg.ChildByFieldName("body")
		if body == nil {
			return false
		}
		// Expression-bodied lambda: `(h, s) -> true`.
		if body.Type() == "true" {
			return true
		}
		// Block-bodied lambda: `(h, s) -> { return true; }`.
		if body.Type() == "block" {
			return blockJustReturnsTrue(body)
		}
		return false
	case "object_creation_expression":
		// Anonymous `new HostnameVerifier() { public boolean verify(...) {...} }`.
		body := findChild(arg, "class_body")
		if body == nil {
			return false
		}
		for _, m := range body.NamedChildren() {
			if m.Type() != "method_declaration" {
				continue
			}
			if methodDeclName(m) != "verify" {
				continue
			}
			if b := m.ChildByFieldName("body"); b != nil && blockJustReturnsTrue(b) {
				return true
			}
		}
		return false
	}
	return false
}

// methodDeclName returns the declared name of a method_declaration node (its
// `name` field). Unlike javaMethodName (which is for method_invocation call
// sites), this reads a declaration's identifier.
func methodDeclName(m *ast.Node) string {
	if m == nil {
		return ""
	}
	if id := m.ChildByFieldName("name"); id != nil {
		return id.Text()
	}
	return ""
}

// blockJustReturnsTrue reports whether a `block` node's only statement is
// `return true;` (ignoring braces). A verifier with any additional logic is not
// matched, keeping the detector precise.
func blockJustReturnsTrue(block *ast.Node) bool {
	stmts := block.NamedChildren()
	if len(stmts) != 1 {
		return false
	}
	ret := stmts[0]
	if ret.Type() != "return_statement" {
		return false
	}
	val := firstNamedChild(ret)
	return val != nil && val.Type() == "true"
}

// scopeHasEmptyX509TrustManager reports whether the argument subtree of an
// SSLContext.init call constructs an X509TrustManager (or X509ExtendedTrustManager)
// whose checkServerTrusted/checkClientTrusted method bodies are empty — i.e. an
// all-trusting trust manager. Inspecting the trust manager body (rather than
// merely the presence of the type) keeps the detector from flagging a properly
// validating custom trust manager.
func scopeHasEmptyX509TrustManager(initCall *ast.Node) bool {
	args := initCall.ChildByFieldName("arguments")
	if args == nil {
		return false
	}
	found := false
	args.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		if n.Type() != "object_creation_expression" {
			return true
		}
		t := javaConstructedType(n)
		if t != "X509TrustManager" && t != "X509ExtendedTrustManager" {
			return true
		}
		body := findChild(n, "class_body")
		if body == nil {
			return true
		}
		// An all-trusting trust manager has BOTH check methods present with
		// empty bodies. Require at least one of checkServerTrusted/
		// checkClientTrusted to be empty-bodied; flag if no non-empty check
		// method provides real validation.
		sawEmptyCheck := false
		sawNonEmptyCheck := false
		for _, m := range body.NamedChildren() {
			if m.Type() != "method_declaration" {
				continue
			}
			mn := methodDeclName(m)
			if mn != "checkServerTrusted" && mn != "checkClientTrusted" {
				continue
			}
			b := m.ChildByFieldName("body")
			if b == nil {
				continue
			}
			if len(b.NamedChildren()) == 0 {
				sawEmptyCheck = true
			} else {
				sawNonEmptyCheck = true
			}
		}
		if sawEmptyCheck && !sawNonEmptyCheck {
			found = true
			return false
		}
		return true
	})
	return found
}

// checkReflectedXSS detects writing a non-literal value directly to a servlet
// response writer/stream: response.getWriter().print(var) / .println(var) /
// .write(var) / .append(var), or out.print(var) where `out` came from
// getWriter()/getOutputStream(). Reflected, unencoded output of user input is
// classic reflected XSS.
func (c *javaChecker) checkReflectedXSS(n *ast.Node) {
	methodName := javaMethodName(n)
	if methodName != "print" && methodName != "println" &&
		methodName != "write" && methodName != "append" {
		return
	}
	obj := n.ChildByFieldName("object")
	if obj == nil {
		return
	}
	// The receiver must be (or derive from) a servlet writer/output stream.
	// Strongest structural signal: object is itself a getWriter()/
	// getOutputStream() invocation, i.e. response.getWriter().print(...).
	if !isServletWriterReceiver(obj) {
		return
	}
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJavaLiteral(firstArg) {
		return
	}
	// Precision guard: if the written identifier was assigned from a known
	// HTML/output encoder in the enclosing method (htmlEscape/escapeHtml/
	// Encode.forHtml/ESAPI.encodeForHTML/Jsoup.clean/...), the value is already
	// sanitized — don't flag. This mirrors the taint engine's neutralization so
	// the AST tier stays as precise as the catalog on sanitized flows.
	scope := enclosingBody(n)
	if firstArg.Type() == "identifier" {
		if scope != nil && c.identifierIsHTMLSanitized(scope, firstArg.Text()) {
			return
		}
	}
	// Origin gate: only flag when the written value provably derives from
	// user input — an inline request getter, a trivial assignment chain back
	// to one, or a parameter of a method that also handles servlet
	// request/response objects. Writing a value the AST tier cannot trace to
	// the request (collection reads, helper returns, computed locals) is left
	// to the taint engine, which tracks those flows with real precision.
	// Flagging every non-literal write floods servlet code that emits
	// computed-but-safe HTML.
	if !c.exprIsRequestDerived(scope, n, firstArg, 0) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JAVAAST-007",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Reflected XSS: unencoded value written to servlet response",
		Description:   "A non-literal value is written directly to the servlet response writer/output stream (" + methodName + "()). If the value contains user input, an attacker can inject HTML/JavaScript that executes in victims' browsers (reflected XSS).",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "HTML-encode untrusted output before writing it (e.g. org.owasp.encoder.Encode.forHtml(value), Apache Commons StringEscapeUtils, or your framework's auto-escaping templating).",
		CWEID:         "CWE-79",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"xss", "injection", "ast"},
	})
}

// checkSSRFURL detects `new URL(var)` / `new URI(var)` constructed from a
// non-literal argument WHOSE VALUE THEN FLOWS TO A FETCH (openConnection /
// openStream / HttpClient.send / RestTemplate / WebClient ...). URL/URI
// construction on its own is NOT SSRF — it is overwhelmingly used to PARSE a
// string (url.getHost(), uri.getPath(), redirect-URI allowlist comparison).
// The server-side request only happens when something opens a connection on
// the constructed value. Firing on the constructor alone produced a flood of
// false positives on URL-parsing / URL-validation code (Keycloak's pairwise
// subject mappers, redirect-URI validators, identity-provider profile parsers),
// none of which ever issue a request. We require the constructed value to reach
// a fetch within the enclosing method body before flagging.
func (c *javaChecker) checkSSRFURL(n *ast.Node) {
	typeName := javaConstructedType(n)
	if typeName != "URL" && typeName != "URI" {
		return
	}
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJavaLiteral(firstArg) {
		return
	}
	// A multi-arg URL(context, spec) form (base + relative path) is far less
	// likely to be a full attacker-controlled endpoint; require the
	// single-argument shape which is the classic SSRF sink.
	if len(args.NamedChildren()) != 1 {
		return
	}
	// Require the constructed URL/URI value to reach a fetch/connection within
	// the enclosing method. Construction with no subsequent connection is URL
	// parsing/validation, not SSRF — the actual request is the sink.
	if !c.urlValueReachesFetch(n) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JAVAAST-008",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "SSRF: " + typeName + " built from a non-literal address",
		Description:   "A " + typeName + " is constructed from a non-literal string. If the address is user-controlled, opening a connection (openConnection/openStream) lets an attacker make the server issue requests to internal services, cloud metadata endpoints, or arbitrary hosts (SSRF).",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the URL against an allowlist of permitted hosts/schemes before opening a connection. Reject internal/link-local addresses and disable redirects to untrusted hosts.",
		CWEID:         "CWE-918",
		OWASPCategory: "A10:2021-Server-Side Request Forgery",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"ssrf", "ast"},
	})
}

// urlFetchMethods are methods that issue a server-side request on a
// java.net.URL/URLConnection/URI — i.e. the operations that turn URL
// construction into SSRF. A call to one of these ON the constructed value (or
// on a connection opened from it) is what we require before flagging.
var urlFetchMethods = map[string]bool{
	"openConnection": true, // URL.openConnection()
	"openStream":     true, // URL.openStream()
	"getContent":     true, // URL.getContent()
	"getInputStream": true, // URLConnection.getInputStream()
	"connect":        true, // URLConnection.connect()
}

// urlFetchSinkMethods are HTTP-client send/exchange operations that take a
// URL/URI (or a request built from one) as an argument and issue the request.
// When the constructed URL/URI identifier appears anywhere in such a call's
// argument list we treat the value as reaching a fetch.
var urlFetchSinkMethods = map[string]bool{
	"send":            true, // HttpClient.send / HttpClient.sendAsync
	"sendAsync":       true,
	"exchange":        true, // RestTemplate.exchange / WebClient ... exchange
	"execute":         true, // HttpClient.execute (Apache), RestTemplate.execute
	"getForObject":    true,
	"getForEntity":    true,
	"postForObject":   true,
	"postForEntity":   true,
	"postForLocation": true,
	"newRequest":      true, // Jetty HttpClient.newRequest(uri)
	"uri":             true, // HttpRequest.newBuilder().uri(uri), WebClient ... .uri(uri)
}

// urlFetchSinkTypes are constructor types that wrap a URL/URI into an
// outbound HTTP request (Apache HttpClient verbs, OkHttp/Google request
// builders). `new HttpGet(uri)` etc. consume the value into a fetch.
var urlFetchSinkTypes = map[string]bool{
	"HttpGet":        true,
	"HttpPost":       true,
	"HttpPut":        true,
	"HttpDelete":     true,
	"HttpPatch":      true,
	"HttpHead":       true,
	"HttpUriRequest": true,
	"GenericUrl":     true,
	"URIBuilder":     true,
}

// urlValueReachesFetch reports whether the URL/URI built at construction node
// `n` flows to a fetch operation within the enclosing method body. It handles:
//   - direct chaining: new URL(x).openConnection()
//   - a local assigned then fetched: URL u = new URL(x); u.openConnection();
//   - the value passed as an argument to an HTTP send/exchange or wrapped into
//     a request constructor: client.send(req(u)), new HttpGet(uri), etc.
//
// Anything it cannot connect to a fetch is treated as URL parsing/validation
// and NOT flagged — the precise dataflow judgement belongs to the taint engine,
// which independently models the openConnection/send catalog sinks.
func (c *javaChecker) urlValueReachesFetch(n *ast.Node) bool {
	// Case 1: directly chained on the construction — new URL(x).openStream().
	// The parent method_invocation has `n` (possibly wrapped) as its object.
	if directFetchOnConstruction(n) {
		return true
	}

	// Determine the variable the construction is bound to, if any.
	varName := constructionBoundVar(n)
	body := enclosingBody(n)
	if body == nil {
		return false
	}
	if varName == "" {
		// Unbound construction (e.g. passed inline as an argument). Only a
		// direct chain (handled above) or inline-into-fetch makes it a sink;
		// check whether the construction node sits inside a fetch call's args.
		return constructionInsideFetchCall(n)
	}

	found := false
	body.Walk(func(m *ast.Node) bool {
		if found || m.Type() != "method_invocation" {
			return !found
		}
		method := javaMethodName(m)
		// u.openConnection() / u.openStream() — fetch on the URL value itself.
		if urlFetchMethods[method] && javaObjectName(m) == varName {
			found = true
			return false
		}
		// HTTP send/exchange/etc. that references the URL value in its args:
		// client.send(HttpRequest.newBuilder().uri(u).build(), ...),
		// restTemplate.exchange(u, ...).
		if urlFetchSinkMethods[method] && callArgsReference(m, varName) {
			found = true
			return false
		}
		return !found
	})
	if found {
		return true
	}

	// new HttpGet(u) / new GenericUrl(u) — wrapping the value into a request.
	body.Walk(func(m *ast.Node) bool {
		if found || m.Type() != "object_creation_expression" {
			return !found
		}
		if urlFetchSinkTypes[javaConstructedType(m)] && constructorArgsReference(m, varName) {
			found = true
			return false
		}
		return !found
	})
	return found
}

// directFetchOnConstruction reports whether the construction node is the
// receiver of an immediately-chained fetch call: new URL(x).openConnection().
// Tree-sitter nests the construction as the `object` of the outer
// method_invocation (possibly through a parenthesized_expression).
func directFetchOnConstruction(n *ast.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "parenthesized_expression":
			continue
		case "method_invocation":
			obj := p.ChildByFieldName("object")
			if obj != nil && nodeContainsConstruction(obj, n) && urlFetchMethods[javaMethodName(p)] {
				return true
			}
			return false
		default:
			return false
		}
	}
	return false
}

// constructionInsideFetchCall reports whether the construction node appears
// inside the argument list of an HTTP send/exchange call or a request-wrapping
// constructor — the inline `client.send(new HttpGet(new URI(x)))` shape.
func constructionInsideFetchCall(n *ast.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "method_invocation":
			if urlFetchSinkMethods[javaMethodName(p)] {
				return true
			}
		case "object_creation_expression":
			if urlFetchSinkTypes[javaConstructedType(p)] {
				return true
			}
		case "method_declaration", "constructor_declaration", "lambda_expression":
			return false
		}
	}
	return false
}

// nodeContainsConstruction reports whether `n` is, or transitively wraps,
// the construction node `target` (used to see through parenthesization).
// Identity is pointer equality; the byte range narrows the recursive search.
func nodeContainsConstruction(n, target *ast.Node) bool {
	if n == nil || target == nil {
		return false
	}
	if n == target {
		return true
	}
	if target.StartByte() < n.StartByte() || target.EndByte() > n.EndByte() {
		return false
	}
	for _, child := range n.NamedChildren() {
		if nodeContainsConstruction(child, target) {
			return true
		}
	}
	return false
}

// constructionBoundVar returns the local-variable / field name that the
// construction node is assigned to, or "" if it is not a simple binding.
// Handles `URL u = new URL(x)` (variable_declarator) and `u = new URL(x)`
// (assignment_expression).
func constructionBoundVar(n *ast.Node) string {
	p := n.Parent()
	// Tree-sitter may nest the value behind a parenthesized_expression.
	for p != nil && p.Type() == "parenthesized_expression" {
		p = p.Parent()
	}
	if p == nil {
		return ""
	}
	switch p.Type() {
	case "variable_declarator":
		if nm := p.ChildByFieldName("name"); nm != nil {
			return nm.Text()
		}
	case "assignment_expression":
		if left := p.ChildByFieldName("left"); left != nil && left.Type() == "identifier" {
			return left.Text()
		}
	}
	return ""
}

// callArgsReference reports whether identifier `name` appears anywhere in the
// argument list of method invocation `m`.
func callArgsReference(m *ast.Node, name string) bool {
	args := m.ChildByFieldName("arguments")
	if args == nil {
		return false
	}
	return subtreeReferencesIdent(args, name)
}

// constructorArgsReference reports whether identifier `name` appears in the
// argument list of object creation `m`.
func constructorArgsReference(m *ast.Node, name string) bool {
	args := m.ChildByFieldName("arguments")
	if args == nil {
		return false
	}
	return subtreeReferencesIdent(args, name)
}

// subtreeReferencesIdent reports whether `name` occurs as an identifier node
// anywhere under `n`.
func subtreeReferencesIdent(n *ast.Node, name string) bool {
	found := false
	n.Walk(func(m *ast.Node) bool {
		if found {
			return false
		}
		if m.Type() == "identifier" && m.Text() == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// checkSpELOGNL detects expression-language evaluation of a non-literal string:
// parser.parseExpression(var) (Spring SpEL) and Ognl.parseExpression(var) /
// Ognl.getValue(var, ...) (OGNL). Parsing+evaluating attacker-controlled
// expressions yields remote code execution (e.g. Struts2/Spring SpEL RCE).
func (c *javaChecker) checkSpELOGNL(n *ast.Node) {
	methodName := javaMethodName(n)
	objName := javaObjectName(n)
	isSpEL := methodName == "parseExpression"
	isOGNL := (methodName == "parseExpression" || methodName == "getValue" || methodName == "setValue") && objName == "Ognl"
	if !isSpEL && !isOGNL {
		return
	}
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJavaLiteral(firstArg) {
		return
	}
	engine := "Spring SpEL"
	if isOGNL {
		engine = "OGNL"
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JAVAAST-009",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Expression injection via " + engine + " (" + methodName + ")",
		Description:   engine + " parses and evaluates a non-literal expression string. If the expression is user-controlled, an attacker can invoke arbitrary methods (e.g. T(java.lang.Runtime).getRuntime().exec(...)) and achieve remote code execution.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Never evaluate user input as an expression. Use a fixed expression with a bound evaluation context, or a non-evaluating data format. For SpEL, use SimpleEvaluationContext to restrict reflection/type access.",
		CWEID:         "CWE-917",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangJava,
		Confidence:    "high",
		Tags:          []string{"expression-injection", "spel", "ognl", "injection", "rce", "ast"},
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

// isJNDIReceiver reports whether the named receiver of a `lookup(...)` call
// looks like a JNDI Context. Real JNDI types are javax.naming.Context and
// its subinterfaces (DirContext, LdapContext, EventContext) plus
// InitialContext / InitialDirContext / InitialLdapContext, and adjacent
// helpers like Spring's JndiTemplate / JndiLocatorDelegate and log4j2's
// JndiManager. We only have the receiver IDENTIFIER text from tree-sitter,
// not full type info, so match by name shape:
//   - Class names ending in Context (Context, InitialContext, DirContext,
//     LdapContext, JndiContext, NamingContext, etc.)
//   - Names containing "jndi" (JndiTemplate, jndiManager, jndiLocator)
//   - Conventional instance names: ctx, ictx, context, initialContext, ic,
//     namingContext, directory, ldap, dirCtx, ldapCtx
//
// Bare calls (empty receiver) are conservatively skipped — they collide
// with countless project-internal lookup() methods (Apache StrLookup,
// SpringEnvironmentLookup, Bouncy Castle CRLReason.lookup, etc.).
func isJNDIReceiver(recv string) bool {
	if recv == "" {
		return false
	}
	lower := strings.ToLower(recv)

	// Conventional instance names — exact match.
	switch lower {
	case "ctx", "ictx", "ic", "context", "initialcontext",
		"namingcontext", "dircontext", "ldapcontext",
		"directory", "ldap", "dirctx", "ldapctx", "jndi":
		return true
	}

	// Substring shapes: anything with "context" suffix, "jndi" anywhere,
	// "ldap"/"dir" with "context" suffix.
	if strings.HasSuffix(lower, "context") {
		return true
	}
	if strings.Contains(lower, "jndi") {
		return true
	}
	return false
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

// --- helpers for the deepened detectors (XXE / XSS / SSRF / SpEL) ---

// isXMLParseMethod reports whether a method name is an XML parse/build
// entrypoint that resolves entities on a JAXP-family parser.
func isXMLParseMethod(name string) bool {
	switch name {
	case "parse", "build", "read",
		"createXMLStreamReader", "createXMLEventReader",
		"newSchema", "transform", "unmarshal":
		return true
	}
	return false
}

// enclosingBody returns the nearest enclosing method/constructor/static-init
// body (a "block" node) for n, or nil if none. Used to confine XXE-hardening
// analysis to a single method scope.
func enclosingBody(n *ast.Node) *ast.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "method_declaration", "constructor_declaration", "static_initializer":
			if b := p.ChildByFieldName("body"); b != nil {
				return b
			}
			// static_initializer's block is its first child.
			if blk := findChild(p, "block"); blk != nil {
				return blk
			}
			return p
		}
	}
	return nil
}

// xmlFactoryTypes are the JAXP factory types whose default (unhardened)
// configuration resolves external entities / DOCTYPEs.
var xmlFactoryTypes = map[string]bool{
	"DocumentBuilderFactory": true,
	"SAXParserFactory":       true,
	"XMLInputFactory":        true,
	"SchemaFactory":          true,
	"TransformerFactory":     true,
	"SAXBuilder":             true, // JDOM
	"SAXReader":              true, // dom4j
	"XMLReader":              true,
}

// scopeCreatesXMLFactory reports whether the given scope constructs one of the
// known XML parser factories — either via `Type.newInstance()` /
// `Type.newFactory()` (factory idiom) or `new Type(...)` (JDOM/dom4j idiom),
// or declares a local/field of that type.
func scopeCreatesXMLFactory(scope *ast.Node) bool {
	found := false
	scope.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		switch n.Type() {
		case "method_invocation":
			// DocumentBuilderFactory.newInstance() etc.
			if obj := n.ChildByFieldName("object"); obj != nil &&
				obj.Type() == "identifier" && xmlFactoryTypes[obj.Text()] {
				m := javaMethodName(n)
				if m == "newInstance" || m == "newFactory" || m == "newDefaultInstance" {
					found = true
					return false
				}
			}
		case "object_creation_expression":
			if xmlFactoryTypes[javaConstructedType(n)] {
				found = true
				return false
			}
		case "type_identifier":
			if xmlFactoryTypes[n.Text()] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// scopeHasXXEHardening reports whether the scope contains a call that disables
// DOCTYPE/external-entity processing AND that call unconditionally reaches the
// parse call, i.e. the factory is genuinely hardened on the parse path.
// Recognizes the standard OWASP hardening idioms: setFeature(disallow-doctype-
// decl / no external entities / secure-processing, ...), setExpandEntity-
// References(false), setXIncludeAware(false), setProperty(ACCESS_EXTERNAL_*, ""),
// and setValidating with feature constants.
//
// A hardening call nested inside a branch (if/switch/ternary/catch) that does
// NOT also contain the parse node is ignored — it may be skipped while the
// parse still executes (the "security toggle defaults off" XXE-evasion shape,
// e.g. WebGoat's `if (securityEnabled) { xif.setProperty(...) }` parsed with
// securityEnabled=false). Hardening in the same branch as the parse, or at the
// unconditional top level of the scope, still counts (no false positive).
func scopeHasXXEHardening(scope *ast.Node, parse *ast.Node) bool {
	found := false
	scope.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		if n.Type() != "method_invocation" {
			return true
		}
		m := javaMethodName(n)
		isHardening := false
		switch m {
		case "setFeature", "setProperty", "setAttribute":
			// Inspect the argument text for known hardening feature/property URIs
			// or constants.
			if args := n.ChildByFieldName("arguments"); args != nil {
				isHardening = xxeHardeningArg(args.Text())
			}
		case "setExpandEntityReferences", "setXIncludeAware":
			// These are hardening only when passed false; check arg text.
			if args := n.ChildByFieldName("arguments"); args != nil &&
				strings.Contains(args.Text(), "false") {
				isHardening = true
			}
		}
		if isHardening && hardeningReachesParse(n, parse, scope) {
			found = true
			return false
		}
		return true
	})
	return found
}

// branchNodeTypes are the Java AST control-flow nodes that introduce a
// conditional path: a hardening call nested inside one of these (within the
// analyzed method scope) only protects the parse when the parse is inside the
// same branch.
var branchNodeTypes = map[string]bool{
	"if_statement":                 true,
	"switch_expression":            true, // tree-sitter-java models switch as switch_expression
	"switch_block":                 true,
	"switch_block_statement_group": true,
	"ternary_expression":           true,
	"catch_clause":                 true,
}

// hardeningReachesParse reports whether a hardening call unconditionally reaches
// the parse call. It walks the hardening node's ancestors up to (but not past)
// the method scope; if any ancestor is a branch node that does NOT contain the
// parse node, the hardening is on a conditional path that may be skipped while
// the parse runs, so it does not protect the parse. If parse is nil (defensive),
// hardening is credited unconditionally to preserve prior behavior.
//
// Exception (FP guard): a lazy-initialization / cache guard — `if (field ==
// null) { ...build+harden...; this.field = factory; }` — does NOT skip the
// hardening on later parses: the factory is hardened on first build and cached,
// so every parse uses a hardened factory. Such a null-check guard is excluded
// from the rejection so the canonical secure lazy-init idiom (Spring's
// SourceHttpMessageConverter) is not flagged. A boolean security toggle
// (`if (securityEnabled)`) is NOT a null-check, so it still rejects (WebGoat).
func hardeningReachesParse(hardening, parse, scope *ast.Node) bool {
	if parse == nil {
		return true
	}
	parseStart := parse.StartByte()
	for p := hardening.Parent(); p != nil && p != scope; p = p.Parent() {
		if branchNodeTypes[p.Type()] {
			// If the branch does not enclose the parse call, the hardening is
			// gated behind a condition the parse does not depend on — unless that
			// condition is a lazy-init/cache null guard (the factory is hardened
			// once and reused on every subsequent parse).
			if !p.ContainsOffset(parseStart) && !isLazyInitNullGuard(p) {
				return false
			}
		}
	}
	return true
}

// isLazyInitNullGuard reports whether an if_statement's condition is a null
// equality/inequality check (`x == null` / `x != null`), the hallmark of the
// build-once-and-cache idiom. Only `if_statement` carries a security/cache
// condition worth distinguishing; other branch nodes (catch/ternary/switch)
// are treated as plain conditionals.
func isLazyInitNullGuard(branch *ast.Node) bool {
	if branch.Type() != "if_statement" {
		return false
	}
	cond := branch.ChildByFieldName("condition")
	if cond == nil {
		return false
	}
	// condition is a parenthesized_expression; unwrap to the inner expression.
	inner := cond
	for inner != nil && inner.Type() == "parenthesized_expression" {
		if nc := firstNamedChild(inner); nc != nil {
			inner = nc
		} else {
			break
		}
	}
	if inner == nil || inner.Type() != "binary_expression" {
		return false
	}
	// A binary_expression `lhs OP rhs` where OP is == or != and one side is the
	// null literal.
	op := inner.ChildByFieldName("operator")
	if op == nil || (op.Text() != "==" && op.Text() != "!=") {
		return false
	}
	l := inner.ChildByFieldName("left")
	r := inner.ChildByFieldName("right")
	return (l != nil && l.Type() == "null_literal") ||
		(r != nil && r.Type() == "null_literal")
}

// xxeHardeningArg reports whether the (textual) argument list of a setFeature/
// setProperty/setAttribute call references a known XXE-hardening feature.
func xxeHardeningArg(argText string) bool {
	needles := []string{
		"disallow-doctype-decl",
		"external-general-entities",
		"external-parameter-entities",
		"load-external-dtd",
		"FEATURE_SECURE_PROCESSING",
		"ACCESS_EXTERNAL_DTD",
		"ACCESS_EXTERNAL_SCHEMA",
		"ACCESS_EXTERNAL_STYLESHEET",
		"XMLConstants.ACCESS_EXTERNAL", // covers all ACCESS_EXTERNAL_* constants
		"IS_SUPPORTING_EXTERNAL_ENTITIES",
		"SUPPORT_DTD",
	}
	for _, nd := range needles {
		if strings.Contains(argText, nd) {
			return true
		}
	}
	return false
}

// jaxbRawInputTypes are the raw byte/char/entity input types whose JAXB
// unmarshal(...) overloads parse XML with external entities enabled by default —
// the XXE-prone shape. Restricting the structural detector to these (rather than
// flagging everything that is not a wrapped Source) is what keeps it FP-safe:
// StAX readers (XMLEventReader/XMLStreamReader), javax.xml.transform.Source
// wrappers, and DOM nodes are the application's own XML pipeline and are never
// flagged here. These are the exact parameter types of the entity-resolving
// Unmarshaller.unmarshal overloads.
var jaxbRawInputTypes = map[string]bool{
	"InputStream": true,
	"File":        true,
	"Reader":      true,
	"InputSource": true,
}

// jaxbRawInputMethods are calls whose result is a raw entity input stream/reader
// (servlet/request accessors), recognized when used inline as the unmarshal
// argument: unmarshal(request.getInputStream()). Deliberately excludes
// createXMLEventReader/createXMLStreamReader (StAX readers) so the defensive-
// factory idiom is not flagged.
var jaxbRawInputMethods = map[string]bool{
	"getInputStream": true,
	"getReader":      true,
}

// scopeEstablishesJAXBUnmarshaller reports whether the given method/constructor
// scope constructs a JAXBContext or otherwise establishes a JAXB Unmarshaller,
// which anchors a bare `.unmarshal(...)` call as genuinely JAXB (not Jackson's
// XmlMapper, a custom DTO mapper, or some other unrelated unmarshal). Recognized
// signals: `JAXBContext.newInstance(...)`, a `.createUnmarshaller()` call, or a
// local/parameter typed `Unmarshaller`/`JAXBContext`.
func scopeEstablishesJAXBUnmarshaller(scope *ast.Node) bool {
	found := false
	scope.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		switch n.Type() {
		case "method_invocation":
			m := javaMethodName(n)
			if m == "createUnmarshaller" {
				found = true
				return false
			}
			// JAXBContext.newInstance(...) — object is the JAXBContext identifier.
			if m == "newInstance" {
				if obj := n.ChildByFieldName("object"); obj != nil &&
					obj.Type() == "identifier" && obj.Text() == "JAXBContext" {
					found = true
					return false
				}
			}
		case "type_identifier":
			if t := n.Text(); t == "Unmarshaller" || t == "JAXBContext" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// jaxbUnmarshalArgIsRawInput reports whether the first argument of a JAXB
// unmarshal call is positively resolvable to a raw byte/char/entity input
// (InputStream/File/Reader/InputSource) — the XXE-prone shape. It returns false
// (do not flag) for StAX readers, wrapped Sources, DOM nodes, and any argument
// whose type cannot be determined, keeping the detector conservative.
//
// Recognized raw shapes:
//   - direct construction: unmarshal(new FileInputStream(...)) / new InputSource(...)
//   - identifier resolved (via local-var declared type, local-var constructor
//     initializer, or formal-parameter type) to a raw input type
//   - inline raw accessor: unmarshal(request.getInputStream()) / getReader()
func jaxbUnmarshalArgIsRawInput(n, scope *ast.Node) bool {
	arg := firstCallArg(n)
	if arg == nil {
		return false
	}
	// Unwrap a leading cast / parenthesization: `(InputStream) x`, `(in)`.
	arg = unwrapCastParen(arg)
	switch arg.Type() {
	case "object_creation_expression":
		return jaxbRawInputTypes[jaxbBaseInputType(javaConstructedType(arg))]
	case "identifier":
		return jaxbRawInputTypes[resolveJaxbArgType(n, scope, arg.Text())]
	case "method_invocation":
		return jaxbRawInputMethods[javaMethodName(arg)]
	}
	return false
}

// resolveJaxbArgType resolves the (last-segment, base-normalized) declared type
// of an identifier used as a JAXB unmarshal argument: first a local variable
// declaration in the scope (by declared type, else by its constructor
// initializer), then a formal parameter of the enclosing method. Returns "" when
// the type cannot be determined, which the caller treats as not-raw (no flag).
func resolveJaxbArgType(n, scope *ast.Node, name string) string {
	if t := scopeLocalVarType(scope, name); t != "" {
		return t
	}
	return enclosingParamType(n, name)
}

// scopeLocalVarType returns the base input type of a local variable `name`
// declared in the scope — from its declared type (`InputStream in = ...`) or,
// when the declaration uses `var`, from its constructor initializer
// (`var in = new FileInputStream(...)`). Returns "" if not found.
func scopeLocalVarType(scope *ast.Node, name string) string {
	result := ""
	scope.Walk(func(n *ast.Node) bool {
		if result != "" {
			return false
		}
		if n.Type() != "local_variable_declaration" {
			return true
		}
		declType := ""
		if t := n.ChildByFieldName("type"); t != nil {
			declType = lastDottedSegment(strings.TrimSpace(t.Text()))
		}
		for _, d := range n.NamedChildren() {
			if d.Type() != "variable_declarator" {
				continue
			}
			nameNode := d.ChildByFieldName("name")
			if nameNode == nil || nameNode.Text() != name {
				continue
			}
			if declType != "" && declType != "var" {
				result = jaxbBaseInputType(declType)
				return false
			}
			// `var x = new FileInputStream(...)` — take the constructed type.
			if val := d.ChildByFieldName("value"); val != nil {
				v := unwrapCastParen(val)
				if v.Type() == "object_creation_expression" {
					result = jaxbBaseInputType(javaConstructedType(v))
					return false
				}
			}
		}
		return true
	})
	return result
}

// enclosingParamType returns the base input type of a formal parameter named
// `name` on the method/constructor enclosing `n`, or "" if none. This catches
// the Spring shape `unmarshal(Source source)` (param typed Source -> not raw ->
// not flagged) as well as `unmarshal(InputStream in)` directly on a parameter.
func enclosingParamType(n *ast.Node, name string) string {
	var params *ast.Node
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "method_declaration" || p.Type() == "constructor_declaration" {
			params = p.ChildByFieldName("parameters")
			if params == nil {
				params = findChild(p, "formal_parameters")
			}
		}
		if params != nil {
			break
		}
	}
	if params == nil {
		return ""
	}
	for _, fp := range params.NamedChildren() {
		if fp.Type() != "formal_parameter" {
			continue
		}
		nameNode := fp.ChildByFieldName("name")
		if nameNode == nil || nameNode.Text() != name {
			continue
		}
		if t := fp.ChildByFieldName("type"); t != nil {
			return jaxbBaseInputType(lastDottedSegment(strings.TrimSpace(t.Text())))
		}
	}
	return ""
}

// jaxbBaseInputType normalizes a concrete raw-input subclass to its JAXB-overload
// base type so the allowlist stays small but covers the common concrete forms:
// FileInputStream/ByteArrayInputStream/... -> InputStream, FileReader/
// BufferedReader/... -> Reader. Names not recognized as a raw subclass are
// returned unchanged (so StAX readers, Sources, etc. fall through to not-raw).
func jaxbBaseInputType(t string) string {
	switch {
	case strings.HasSuffix(t, "InputStream"):
		return "InputStream"
	case t == "File":
		return "File"
	case t == "InputSource":
		return "InputSource"
	case t == "XMLStreamReader" || t == "XMLEventReader":
		// StAX readers are explicitly NOT raw inputs — return unchanged so they
		// fall through to not-raw (no flag).
		return t
	case strings.HasSuffix(t, "Reader"):
		// Raw character readers (Reader/BufferedReader/FileReader/...).
		return "Reader"
	}
	return t
}

// unwrapCastParen strips leading cast_expression / parenthesized_expression
// layers to reach the underlying value node.
func unwrapCastParen(n *ast.Node) *ast.Node {
	for n != nil {
		switch n.Type() {
		case "parenthesized_expression":
			if inner := firstNamedChild(n); inner != nil {
				n = inner
				continue
			}
		case "cast_expression":
			if v := n.ChildByFieldName("value"); v != nil {
				n = v
				continue
			}
		}
		return n
	}
	return n
}

// lastDottedSegment returns the final segment of a possibly-qualified, possibly-
// generic type name: "javax.xml.transform.Source" -> "Source", "List<T>" ->
// "List".
func lastDottedSegment(text string) string {
	if i := strings.IndexByte(text, '<'); i >= 0 {
		text = text[:i]
	}
	if i := strings.LastIndexByte(text, '.'); i >= 0 {
		text = text[i+1:]
	}
	return strings.TrimSpace(text)
}

// isServletWriterReceiver reports whether obj is (or derives from) a servlet
// response writer/output stream — the strongest structural shape being an
// inline getWriter()/getOutputStream() invocation:
// response.getWriter().print(...).
func isServletWriterReceiver(obj *ast.Node) bool {
	if obj == nil {
		return false
	}
	// response.getWriter().X(...) / response.getOutputStream().X(...)
	if obj.Type() == "method_invocation" {
		m := javaMethodName(obj)
		return m == "getWriter" || m == "getOutputStream"
	}
	return false
}

// htmlEncoderNeedles are textual markers of HTML/JS output encoders that
// neutralize XSS — kept in sync with the Java sanitizer catalog
// (java_sanitizers.go).
var htmlEncoderNeedles = []string{
	"htmlEscape", "escapeHtml", "escapeHtml4", "escapeXml",
	"forHtml", "forHtmlContent", "forHtmlAttribute", "forJavaScript",
	"encodeForHTML", "encodeForJavaScript", "encodeForHTMLAttribute",
	"Jsoup.clean", "javaScriptEscape", "URLEncoder.encode",
	"StringEscapeUtils", "HtmlUtils",
}

func textHasHTMLEncoder(s string) bool {
	for _, nd := range htmlEncoderNeedles {
		if strings.Contains(s, nd) {
			return true
		}
	}
	return false
}

// identifierIsHTMLSanitized reports whether, within scope, the identifier `name`
// is defined from an HTML-encoded value. Two cases are recognized:
//
//  1. Direct: `name = ...htmlEscape(param)...` (encoder call in the RHS text).
//  2. Helper-return: `name = helper.foo(...)` where the helper method `foo`
//     (located anywhere in the compilation unit) returns an HTML-encoded value.
//
// This keeps the AST XSS detector as precise as the taint engine on sanitized
// flows (incl. the inner-class helper-return shape) without re-implementing full
// dataflow.
func (c *javaChecker) identifierIsHTMLSanitized(scope *ast.Node, name string) bool {
	sanitized := false
	scope.Walk(func(n *ast.Node) bool {
		if sanitized {
			return false
		}
		// Match `name = <rhs>` in a variable_declarator or assignment.
		var rhs *ast.Node
		switch n.Type() {
		case "variable_declarator":
			if nm := n.ChildByFieldName("name"); nm != nil && nm.Text() == name {
				rhs = n.ChildByFieldName("value")
			}
		case "assignment_expression":
			if lhs := n.ChildByFieldName("left"); lhs != nil && lhs.Text() == name {
				rhs = n.ChildByFieldName("right")
			}
		}
		if rhs == nil {
			return true
		}
		// Case 1: encoder applied directly in the RHS.
		if textHasHTMLEncoder(rhs.Text()) {
			sanitized = true
			return false
		}
		// Case 2: RHS is a helper invocation that returns an encoded value.
		if rhs.Type() == "method_invocation" {
			if c.helperReturnsHTMLEncoded(javaMethodName(rhs)) {
				sanitized = true
				return false
			}
		}
		return true
	})
	return sanitized
}

// helperReturnsHTMLEncoded reports whether a method named `methodName`, defined
// anywhere in the current compilation unit, returns a value produced by an HTML
// encoder. Conservative textual scan of the method body's return statement.
func (c *javaChecker) helperReturnsHTMLEncoded(methodName string) bool {
	if methodName == "" {
		return false
	}
	root := c.tree.Root()
	if root == nil {
		return false
	}
	found := false
	root.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		if n.Type() != "method_declaration" {
			return true
		}
		nm := n.ChildByFieldName("name")
		if nm == nil || nm.Text() != methodName {
			return true
		}
		body := n.ChildByFieldName("body")
		if body == nil {
			return true
		}
		// Collect variables assigned from an encoder in the body, then check if
		// any return statement returns such a variable (or the encoder directly).
		encodedVars := map[string]bool{}
		body.Walk(func(m *ast.Node) bool {
			if m.Type() == "variable_declarator" {
				if vn := m.ChildByFieldName("name"); vn != nil {
					if val := m.ChildByFieldName("value"); val != nil && textHasHTMLEncoder(val.Text()) {
						encodedVars[vn.Text()] = true
					}
				}
			}
			if m.Type() == "return_statement" {
				rt := m.Text()
				if textHasHTMLEncoder(rt) {
					found = true
					return false
				}
				for _, child := range m.NamedChildren() {
					if child.Type() == "identifier" && encodedVars[child.Text()] {
						found = true
						return false
					}
				}
			}
			return true
		})
		return false // don't descend further into this method
	})
	return found
}

// servletRequestGetters are the HttpServletRequest accessors that return
// attacker-controlled data. Matched by method name only (the AST tier has no
// type information); the names are distinctive enough that a collision with a
// non-servlet receiver is unlikely, and the call is only consulted underneath
// a confirmed servlet writer sink.
var servletRequestGetters = map[string]bool{
	"getParameter":       true,
	"getParameterValues": true,
	"getParameterNames":  true,
	"getParameterMap":    true,
	"getHeader":          true,
	"getHeaders":         true,
	"getHeaderNames":     true,
	"getCookies":         true,
	"getQueryString":     true,
	"getPathInfo":        true,
	"getRequestURI":      true,
	"getRequestURL":      true,
	"getRemoteUser":      true,
	"getReader":          true,
	"getInputStream":     true,
	"getPart":            true,
	"getParts":           true,
}

// exprIsRequestDerived reports whether an expression written to a servlet
// writer provably derives from request input. It recognises: a request getter
// called inline, an identifier whose assignment chain (bare-identifier hops
// only) reaches a request getter, a method call whose receiver chain derives
// from one (param.toCharArray()), string concatenation with a derived operand,
// and parameter names of a method that also takes servlet request/response
// objects (the delegated-writer shape: handle(HttpServletResponse resp,
// String name)). Anything it cannot resolve — collection reads, helper
// returns, computed values — is treated as NOT derived: those flows belong to
// the taint engine, which models them precisely.
func (c *javaChecker) exprIsRequestDerived(scope, sink, expr *ast.Node, depth int) bool {
	if expr == nil || depth > 6 {
		return false
	}
	switch expr.Type() {
	case "method_invocation":
		if servletRequestGetters[javaMethodName(expr)] {
			return true
		}
		// param.toCharArray(), param.toString(): a value-preserving call on a
		// derived receiver is still the same user input.
		if obj := expr.ChildByFieldName("object"); obj != nil {
			return c.exprIsRequestDerived(scope, sink, obj, depth+1)
		}
		return false
	case "identifier":
		name := expr.Text()
		if scope != nil && c.identifierChainReachesRequest(scope, name, depth) {
			return true
		}
		return c.isServletMethodParam(sink, name)
	case "binary_expression", "parenthesized_expression", "cast_expression", "ternary_expression":
		for _, child := range expr.NamedChildren() {
			if c.exprIsRequestDerived(scope, sink, child, depth+1) {
				return true
			}
		}
		return false
	}
	return false
}

// identifierChainReachesRequest reports whether any assignment to `name`
// inside scope resolves — through bare-identifier hops only — to a servlet
// request getter. A RHS the walk cannot follow (collection get, helper call,
// arithmetic) breaks the chain: the laundering may or may not preserve taint,
// and that judgement belongs to the taint engine.
func (c *javaChecker) identifierChainReachesRequest(scope *ast.Node, name string, depth int) bool {
	if depth > 6 {
		return false
	}
	derived := false
	scope.Walk(func(n *ast.Node) bool {
		if derived {
			return false
		}
		var rhs *ast.Node
		switch n.Type() {
		case "variable_declarator":
			if nm := n.ChildByFieldName("name"); nm != nil && nm.Text() == name {
				rhs = n.ChildByFieldName("value")
			}
		case "assignment_expression":
			if lhs := n.ChildByFieldName("left"); lhs != nil && lhs.Text() == name {
				rhs = n.ChildByFieldName("right")
			}
		}
		if rhs == nil {
			return true
		}
		switch rhs.Type() {
		case "method_invocation":
			if servletRequestGetters[javaMethodName(rhs)] {
				derived = true
				return false
			}
		case "identifier":
			if rhs.Text() != name && c.identifierChainReachesRequest(scope, rhs.Text(), depth+1) {
				derived = true
				return false
			}
		}
		return true
	})
	return derived
}

// isServletMethodParam reports whether `name` is a formal parameter of the
// method enclosing the sink AND that method also takes a servlet
// request/response object. A String parameter of a servlet handler is
// plausibly user input forwarded by the caller (the delegated-writer shape);
// parameters of unrelated methods are not.
func (c *javaChecker) isServletMethodParam(sink *ast.Node, name string) bool {
	var method *ast.Node
	for p := sink.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "method_declaration" || p.Type() == "constructor_declaration" {
			method = p
			break
		}
	}
	if method == nil {
		return false
	}
	params := method.ChildByFieldName("parameters")
	if params == nil {
		return false
	}
	hasServletParam := false
	isParam := false
	for _, p := range params.NamedChildren() {
		if p.Type() != "formal_parameter" && p.Type() != "spread_parameter" {
			continue
		}
		if tn := p.ChildByFieldName("type"); tn != nil && strings.Contains(tn.Text(), "Servlet") {
			hasServletParam = true
		}
		if nm := p.ChildByFieldName("name"); nm != nil && nm.Text() == name {
			isParam = true
		}
	}
	return hasServletParam && isParam
}

// javaConstructedType returns the constructed type name of an
// object_creation_expression (`new Foo(...)` -> "Foo"). Handles both bare
// type_identifier and dotted/generic scoped_type_identifier by taking the last
// segment.
func javaConstructedType(n *ast.Node) string {
	if n == nil || n.Type() != "object_creation_expression" {
		return ""
	}
	t := n.ChildByFieldName("type")
	if t == nil {
		t = findChild(n, "type_identifier")
	}
	if t == nil {
		return ""
	}
	text := strings.TrimSpace(t.Text())
	// Strip generics: "URL<...>" -> "URL".
	if i := strings.IndexByte(text, '<'); i >= 0 {
		text = text[:i]
	}
	// Take last dotted segment: "java.net.URL" -> "URL".
	if i := strings.LastIndexByte(text, '.'); i >= 0 {
		text = text[i+1:]
	}
	return strings.TrimSpace(text)
}
