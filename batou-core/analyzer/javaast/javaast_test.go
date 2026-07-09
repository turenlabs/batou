package javaast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"testing"
)

func scanJava(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangJava)
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.java",
		Content:  code,
		Language: rules.LangJava,
		Tree:     tree,
	}
	a := &JavaASTAnalyzer{}
	return a.Scan(ctx)
}

func findByRule(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestSQLConcatInExecuteQuery(t *testing.T) {
	code := `
class Handler {
    void handle(String userInput) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "BATOU-JAVAAST-001")
	if f == nil {
		t.Error("expected SQL injection finding for executeQuery with concat")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSQLPreparedStatementSafe(t *testing.T) {
	code := `
class Handler {
    void handle(String userInput) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, userInput);
    }
}
`
	findings := scanJava(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-JAVAAST-001" {
			t.Errorf("should not flag PreparedStatement: %s", f.Title)
		}
	}
}

func TestRuntimeExec(t *testing.T) {
	code := `
class Handler {
    void handle(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "BATOU-JAVAAST-002")
	if f == nil {
		t.Error("expected command injection finding for Runtime.exec")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestRuntimeExecLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void handle() throws Exception {
        Runtime.getRuntime().exec("ls -la");
    }
}
`
	findings := scanJava(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-JAVAAST-002" {
			t.Errorf("should not flag Runtime.exec with literal: %s", f.Title)
		}
	}
}

func TestObjectInputStream(t *testing.T) {
	code := `
class Handler {
    void handle(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        Object obj = ois.readObject();
    }
}
`
	findings := scanJava(code)
	// Should find both the constructor and readObject
	count := 0
	for _, f := range findings {
		if f.RuleID == "BATOU-JAVAAST-003" {
			count++
		}
	}
	if count < 1 {
		t.Errorf("expected at least 1 deserialization finding, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestJNDILookup(t *testing.T) {
	code := `
class Handler {
    void handle(String name) throws Exception {
        InitialContext ctx = new InitialContext();
        ctx.lookup(name);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "BATOU-JAVAAST-004")
	if f == nil {
		t.Error("expected JNDI injection finding for lookup with variable")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestJNDILookupLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void handle() throws Exception {
        ctx.lookup("java:comp/env/jdbc/mydb");
    }
}
`
	findings := scanJava(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-JAVAAST-004" {
			t.Errorf("should not flag lookup with literal: %s", f.Title)
		}
	}
}

// TestNonJNDILookupReceiverDoesNotFire guards against the high-volume FP
// shape observed in real-world OSS scans: enum-style static lookup tables
// (Bouncy Castle CRLReason.lookup, ECNamedDomainParameters.lookup), Apache
// StrLookup.lookup, Spring's SpringEnvironmentLookup.lookup, and other
// project-internal lookup() methods on non-JNDI receivers.
func TestNonJNDILookupReceiverDoesNotFire(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{"BouncyCastle CRLReason enum lookup", `
class Reason {
    static int lookup(int code) { return code; }
    void use(int code) { CRLReason.lookup(code); }
}`},
		{"BouncyCastle EC named parameters lookup", `
class Curve {
    void use(String oid) { ECNamedDomainParameters.lookup(oid); }
}`},
		{"Spring SpringEnvironmentLookup", `
class L {
    String lookup(String key) { return resolver.resolve(key); }
}`},
		{"Apache StrLookup", `
class L extends StrLookup {
    public String lookup(String key) { return values.get(key); }
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range scanJava(tc.code) {
				if f.RuleID == "BATOU-JAVAAST-004" {
					t.Errorf("should NOT flag non-JNDI lookup() in %s: %s",
						tc.name, f.MatchedText)
				}
			}
		})
	}
}

// TestJNDILookupOnAdjacentReceivers covers the receivers we DO want to fire
// on: the conventional ctx/context/jndi* names plus log4j2's JndiManager.
func TestJNDILookupOnAdjacentReceivers(t *testing.T) {
	cases := []string{
		`class H { void f(String n) throws Exception { ctx.lookup(n); } }`,
		`class H { void f(String n) throws Exception { context.lookup(n); } }`,
		`class H { void f(String n) throws Exception { initialContext.lookup(n); } }`,
		`class H { void f(String n) throws Exception { ictx.lookup(n); } }`,
		`class H { void f(String n) throws Exception { jndiManager.lookup(n); } }`,
		`class H { void f(String n) throws Exception { jndiTemplate.lookup(n); } }`,
		`class H { void f(String n) throws Exception { dirContext.lookup(n); } }`,
		`class H { void f(String n) throws Exception { ldapContext.lookup(n); } }`,
	}
	for _, code := range cases {
		findings := scanJava(code)
		if findByRule(findings, "BATOU-JAVAAST-004") == nil {
			t.Errorf("expected JNDI finding for %q", code)
		}
	}
}

func TestClassForName(t *testing.T) {
	code := `
class Handler {
    void handle(String className) throws Exception {
        Class.forName(className);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "BATOU-JAVAAST-005")
	if f == nil {
		t.Error("expected unsafe reflection finding for Class.forName with variable")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestClassForNameLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void handle() throws Exception {
        Class.forName("com.example.MyClass");
    }
}
`
	findings := scanJava(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-JAVAAST-005" {
			t.Errorf("should not flag Class.forName with literal: %s", f.Title)
		}
	}
}

// --- XXE factory-misconfig (CWE-611, BATOU-JAVAAST-006) ---

func TestXXEUnhardenedFactory(t *testing.T) {
	code := `
class Handler {
    void parseXml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xml);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "BATOU-JAVAAST-006")
	if f == nil {
		t.Error("expected XXE finding for unhardened DocumentBuilderFactory + parse")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
		return
	}
	if f.CWEID != "CWE-611" {
		t.Errorf("expected CWE-611, got %s", f.CWEID)
	}
}

func TestXXEHardenedFactorySafe(t *testing.T) {
	code := `
class Handler {
    void parseXml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xml);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag hardened factory: %s", f.MatchedText)
		}
	}
}

func TestXXESecureProcessingSafe(t *testing.T) {
	code := `
class Handler {
    void parseXml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(xml);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag FEATURE_SECURE_PROCESSING factory: %s", f.MatchedText)
		}
	}
}

func TestXXENoFactoryNoFire(t *testing.T) {
	// A bare parse()/build()/read() with no XML factory in scope must not fire
	// (avoid colliding with JSON parsers, number parsing, file builders).
	code := `
class Handler {
    void parse(String s) {
        Integer.parseInt(s);
        gson.parse(s);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag non-XML parse without factory: %s", f.MatchedText)
		}
	}
}

// TestXXEConditionalHardeningBypass is the load-bearing test for the WebGoat
// CommentsCache shape: the hardening calls live inside an `if (securityEnabled)`
// block while the parse runs unconditionally below it. The toggle defaults off,
// so the hardening is dead code on the parse path — this must STILL fire CWE-611
// (it was previously a false negative because the textual hardening scan ignored
// control flow).
func TestXXEConditionalHardeningBypass(t *testing.T) {
	code := `
class Handler {
    Object parseXml(String xml, boolean securityEnabled) throws Exception {
        javax.xml.stream.XMLInputFactory xif = javax.xml.stream.XMLInputFactory.newInstance();
        if (securityEnabled) {
            xif.setProperty(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
            xif.setProperty(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        }
        return xif.createXMLStreamReader(new java.io.StringReader(xml));
    }
}
`
	f := findByRule(scanJava(code), "BATOU-JAVAAST-006")
	if f == nil {
		t.Fatal("expected XXE finding: hardening gated behind if(securityEnabled) does not protect the unconditional parse")
	}
	if f.CWEID != "CWE-611" {
		t.Errorf("expected CWE-611, got %s", f.CWEID)
	}
}

// TestXXEHardeningInSameBranchSafe is the FP-guard negative: when the parse call
// is INSIDE the same branch as the hardening, the hardening does protect it, so
// no finding. This keeps the dominance check from over-firing on legitimately
// hardened-then-parsed code that happens to be conditional.
func TestXXEHardeningInSameBranchSafe(t *testing.T) {
	code := `
class Handler {
    void parseXml(String xml, boolean cond) throws Exception {
        if (cond) {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.parse(xml);
        }
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag: hardening and parse are in the same branch: %s", f.MatchedText)
		}
	}
}

// TestXXEUnconditionalHardeningSafe re-asserts that top-level (unconditional)
// hardening above a parse keeps suppressing the finding — the dominance check
// must not regress the plain hardened case.
func TestXXEUnconditionalHardeningSafe(t *testing.T) {
	code := `
class Handler {
    Object parseXml(String xml) throws Exception {
        javax.xml.stream.XMLInputFactory xif = javax.xml.stream.XMLInputFactory.newInstance();
        xif.setProperty(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
        xif.setProperty(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return xif.createXMLStreamReader(new java.io.StringReader(xml));
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag unconditionally hardened factory: %s", f.MatchedText)
		}
	}
}

// TestXXELazyInitCacheGuardSafe is the FP-guard for the build-once-and-cache
// idiom (Spring's SourceHttpMessageConverter): the factory is built and hardened
// inside `if (factory == null)`, cached to a field, and parsed below. The
// hardening is gated behind a NULL check, not a security toggle — every parse
// uses a hardened factory — so this must NOT fire (no false positive). This is
// the precise shape the dominance check must exclude to avoid regressing secure
// real-world code while still catching the `if (securityEnabled)` evasion.
func TestXXELazyInitCacheGuardSafe(t *testing.T) {
	code := `
class Handler {
    private volatile DocumentBuilderFactory dbf;
    Object parseXml(java.io.InputStream body) throws Exception {
        DocumentBuilderFactory factory = this.dbf;
        if (factory == null) {
            factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            this.dbf = factory;
        }
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(body);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag lazy-init/cache-guard hardened factory: %s", f.MatchedText)
		}
	}
}

// --- JAXB Unmarshaller XXE (CWE-611, BATOU-JAVAAST-006) ---

// TestXXEJAXBUnmarshalRawStream is the load-bearing positive: a vanilla JAXB
// Unmarshaller unmarshalling a raw request InputStream with no factory and no
// hardening in scope (SasanLabs VulnerableApp's getVulnerablePayloadLevel1).
// JAXB resolves external entities by default, so this is CWE-611. Baseline
// missed it because no JAXP factory is constructed in scope.
func TestXXEJAXBUnmarshalRawStream(t *testing.T) {
	code := `
class XXEVulnerability {
    Object getVulnerablePayloadLevel1(HttpServletRequest request) throws Exception {
        InputStream in = request.getInputStream();
        JAXBContext jc = JAXBContext.newInstance(ObjectFactory.class);
        Unmarshaller jaxbUnmarshaller = jc.createUnmarshaller();
        JAXBElement<Book> el = (JAXBElement<Book>) (jaxbUnmarshaller.unmarshal(in));
        return el.getValue();
    }
}
`
	f := findByRule(scanJava(code), "BATOU-JAVAAST-006")
	if f == nil {
		t.Fatal("expected CWE-611 for JAXB unmarshal of a raw InputStream with no hardening")
	}
	if f.CWEID != "CWE-611" {
		t.Errorf("expected CWE-611, got %s", f.CWEID)
	}
}

// TestXXEJAXBUnmarshalHardenedSAXSourceSafe is the load-bearing FP-guard: the
// secure VulnerableApp shape (saveJaxBBasedBookInformation) unmarshals a
// SAXSource the developer explicitly built, rather than a raw stream. This must
// NOT fire — the structural tier stays conservative on wrapped Sources.
func TestXXEJAXBUnmarshalHardenedSAXSourceSafe(t *testing.T) {
	code := `
class XXEVulnerability {
    Object saveJaxBBasedBookInformation(SAXParserFactory spf, InputStream in) throws Exception {
        JAXBContext jc = JAXBContext.newInstance(ObjectFactory.class);
        Source xmlSource = new SAXSource(spf.newSAXParser().getXMLReader(), new InputSource(in));
        Unmarshaller jaxbUnmarshaller = jc.createUnmarshaller();
        JAXBElement<Book> el = (JAXBElement<Book>) (jaxbUnmarshaller.unmarshal(xmlSource));
        return el.getValue();
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag JAXB unmarshal of an explicitly-built SAXSource: %s", f.MatchedText)
		}
	}
}

// TestXXEJAXBUnmarshalInScopeHardeningSafe verifies the reused control-flow-aware
// hardening check also covers JAXB: a raw stream is unmarshalled, but the scope
// hardens a SAXParserFactory with disallow-doctype-decl before the call, so the
// parser is genuinely hardened — must NOT fire.
func TestXXEJAXBUnmarshalInScopeHardeningSafe(t *testing.T) {
	code := `
class Handler {
    Object handle(InputStream in) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        XMLReader reader = spf.newSAXParser().getXMLReader();
        JAXBContext jc = JAXBContext.newInstance(ObjectFactory.class);
        Unmarshaller u = jc.createUnmarshaller();
        return u.unmarshal(new SAXSource(reader, new InputSource(in)));
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag JAXB unmarshal when the scope hardens the parser: %s", f.MatchedText)
		}
	}
}

// TestXXEJAXBUnmarshalSourceParamSafe is the FP-guard for the Spring-like shape
// where createUnmarshaller() and unmarshal(source) are co-located in one method
// but the argument is a method parameter typed javax.xml.transform.Source (a
// pre-built Source the caller controls, not a raw stream). Must NOT fire.
func TestXXEJAXBUnmarshalSourceParamSafe(t *testing.T) {
	code := `
class Jaxb2Marshaller {
    Object unmarshal(Source source) throws Exception {
        Unmarshaller unmarshaller = getJaxbContext().createUnmarshaller();
        return unmarshaller.unmarshal(source);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag JAXB unmarshal of a Source-typed parameter: %s", f.MatchedText)
		}
	}
}

// TestXXEJAXBUnmarshalStaxReaderSafe is the load-bearing FP-guard for the most
// common modern-JAXB idiom (Spring's Jaxb2XmlDecoder / Jaxb2CollectionHttp-
// MessageConverter): the unmarshal argument is a StAX reader
// (XMLStreamReader/XMLEventReader) produced by an XMLInputFactory, not a raw
// stream. These are the application's own (typically hardened/defensive) XML
// pipeline and must NOT be flagged at the structural tier — flagging them was the
// false-positive cluster found on real spring-framework code.
func TestXXEJAXBUnmarshalStaxReaderSafe(t *testing.T) {
	code := `
class Jaxb2CollectionHttpMessageConverter {
    Object readFromSource(Class clazz, XMLStreamReader streamReader) throws Exception {
        Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        return unmarshaller.unmarshal(streamReader, clazz).getValue();
    }
    Object decode(XMLEventReader eventReader) throws Exception {
        Unmarshaller unmarshaller = getJaxbContext().createUnmarshaller();
        return unmarshaller.unmarshal(eventReader);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag JAXB unmarshal of a StAX reader: %s", f.MatchedText)
		}
	}
}

// TestXXEJAXBUnmarshalStaxLocalVarSafe covers the same StAX idiom where the
// reader is a local variable built inline from a defensive XMLInputFactory.
func TestXXEJAXBUnmarshalStaxLocalVarSafe(t *testing.T) {
	code := `
class Jaxb2XmlDecoder {
    Object decodeStream(InputStream body) throws Exception {
        Unmarshaller unmarshaller = getJaxbContext().createUnmarshaller();
        XMLStreamReader streamReader = inputFactory.createXMLStreamReader(body);
        return unmarshaller.unmarshal(streamReader);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag JAXB unmarshal of a StAX reader from a factory: %s", f.MatchedText)
		}
	}
}

// TestXXENonJAXBUnmarshalNoFire guards against over-firing on a non-JAXB
// `.unmarshal(...)` (e.g. Jackson XmlMapper) where no JAXBContext/Unmarshaller is
// established in scope — must NOT fire (prior behavior unchanged).
func TestXXENonJAXBUnmarshalNoFire(t *testing.T) {
	code := `
class Handler {
    Object handle(InputStream in) throws Exception {
        XmlMapper mapper = new XmlMapper();
        return mapper.unmarshal(in);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-006" {
			t.Errorf("should NOT flag a non-JAXB unmarshal with no JAXBContext in scope: %s", f.MatchedText)
		}
	}
}

// --- Reflected XSS (CWE-79, BATOU-JAVAAST-007) ---

func TestReflectedXSS(t *testing.T) {
	code := `
class Handler {
    void handle(HttpServletResponse resp, String name) throws Exception {
        resp.getWriter().print(name);
    }
}
`
	f := findByRule(scanJava(code), "BATOU-JAVAAST-007")
	if f == nil {
		t.Error("expected reflected XSS finding for getWriter().print(var)")
	} else if f.CWEID != "CWE-79" {
		t.Errorf("expected CWE-79, got %s", f.CWEID)
	}
}

func TestReflectedXSSLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void handle(HttpServletResponse resp) throws Exception {
        resp.getWriter().print("<h1>Hello</h1>");
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-007" {
			t.Errorf("should NOT flag literal print: %s", f.MatchedText)
		}
	}
}

func TestReflectedXSSEncodedSafe(t *testing.T) {
	code := `
class Handler {
    void handle(HttpServletResponse resp, String name) throws Exception {
        String safe = org.springframework.web.util.HtmlUtils.htmlEscape(name);
        resp.getWriter().print(safe);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-007" {
			t.Errorf("should NOT flag HTML-encoded print: %s", f.MatchedText)
		}
	}
}

func TestReflectedXSSInlineRequestGetter(t *testing.T) {
	code := `
class Handler {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.getWriter().println(request.getParameter("name"));
    }
}
`
	if f := findByRule(scanJava(code), "BATOU-JAVAAST-007"); f == nil {
		t.Error("expected reflected XSS finding for inline request.getParameter write")
	}
}

func TestReflectedXSSTrivialChain(t *testing.T) {
	code := `
class Handler {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getHeader("Referer");
        String bar = param;
        response.getWriter().print(bar);
    }
}
`
	if f := findByRule(scanJava(code), "BATOU-JAVAAST-007"); f == nil {
		t.Error("expected reflected XSS finding for identifier chain back to request.getHeader")
	}
}

func TestReflectedXSSUnresolvableOriginNoFire(t *testing.T) {
	// The written value comes from a collection read / helper return — the
	// AST tier cannot prove request origin, so it must stay quiet and leave
	// the flow decision to the taint engine (which models per-index list
	// taint). This is the OWASP Benchmark safe-case shape that produced 113
	// xss false positives.
	code := `
class Handler {
    void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getHeader("Referer");
        java.util.List<String> values = new java.util.ArrayList<String>();
        values.add("safe");
        values.add(param);
        String bar = values.get(0);
        response.getWriter().print(bar);
        response.getWriter().print(bar.toCharArray());
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-007" {
			t.Errorf("should NOT flag collection-read value (taint engine's call): %s", f.MatchedText)
		}
	}
}

func TestReflectedXSSNonServletMethodParamNoFire(t *testing.T) {
	// A parameter of a method with no servlet types in its signature is not
	// presumed to be user input.
	code := `
class Renderer {
    void render(java.io.PrintWriter w, String name) {
        response.getWriter().print(name);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-007" {
			t.Errorf("should NOT flag param of non-servlet method: %s", f.MatchedText)
		}
	}
}

func TestReflectedXSSNonWriterReceiverNoFire(t *testing.T) {
	// print() on a non-servlet receiver (e.g. System.out, a logger) must not fire.
	code := `
class Handler {
    void handle(String name) {
        System.out.print(name);
        logger.print(name);
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-007" {
			t.Errorf("should NOT flag non-servlet print: %s", f.MatchedText)
		}
	}
}

// --- SSRF (CWE-918, BATOU-JAVAAST-008) ---

func TestSSRFNewURL(t *testing.T) {
	code := `
class Handler {
    void fetch(String target) throws Exception {
        URL u = new URL(target);
        u.openConnection();
    }
}
`
	f := findByRule(scanJava(code), "BATOU-JAVAAST-008")
	if f == nil {
		t.Error("expected SSRF finding for new URL(var)")
	} else if f.CWEID != "CWE-918" {
		t.Errorf("expected CWE-918, got %s", f.CWEID)
	}
}

func TestSSRFNewURLLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void fetch() throws Exception {
        URL u = new URL("https://example.com/api");
        u.openConnection();
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-008" {
			t.Errorf("should NOT flag literal URL: %s", f.MatchedText)
		}
	}
}

func TestSSRFRelativeURLNoFire(t *testing.T) {
	// new URL(base, spec) (context + relative path) is not the classic full
	// attacker-controlled-endpoint shape; require single-arg form.
	code := `
class Handler {
    void fetch(URL base, String path) throws Exception {
        URL u = new URL(base, path);
        u.openConnection();
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-008" {
			t.Errorf("should NOT flag two-arg URL(base, path): %s", f.MatchedText)
		}
	}
}

// TestSSRFURLParseOnlyNoFire reproduces the real-world false-positive class
// found scanning Keycloak: `new URL(var)` / `new URI(var)` is constructed only
// to PARSE the address (getHost / getPath / redirect-allowlist comparison),
// never to open a connection. URL construction is not SSRF — the fetch is — so
// these must stay CLEAN. Mirrors Keycloak's StackoverflowIdentityProvider
// (extractUsernameFromProfileURL) and PairwiseSubMapperUtils / redirect-URI
// validators that flooded the SSRF detector before the fetch-reachability gate.
func TestSSRFURLParseOnlyNoFire(t *testing.T) {
	code := `
class Handler {
    String extractHost(String profileURL) throws Exception {
        URL u = new URL(profileURL);
        return u.getHost();
    }
    boolean validateRedirect(String redirectUri, String allowed) throws Exception {
        URI uri = new URI(redirectUri);
        return uri.getPath().equals(allowed);
    }
    String pairwiseSub(String sectorIdentifierUri) throws Exception {
        URI uri = new URI(sectorIdentifierUri);
        return uri.getHost();
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-008" {
			t.Errorf("URL/URI parsed but never fetched must NOT flag SSRF: %s (line %d)", f.MatchedText, f.LineNumber)
		}
	}
}

// TestSSRFHttpClientSendFires is the matching true positive for the gate added
// alongside TestSSRFURLParseOnlyNoFire: a `new URI(var)` whose value reaches an
// HttpClient.send must STILL fire. This proves the fetch-reachability gate
// tightened the detector rather than disabling it.
func TestSSRFHttpClientSendFires(t *testing.T) {
	code := `
class Handler {
    void fetch(String userUrl) throws Exception {
        URI uri = new URI(userUrl);
        HttpRequest req = HttpRequest.newBuilder().uri(uri).build();
        client.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
`
	f := findByRule(scanJava(code), "BATOU-JAVAAST-008")
	if f == nil {
		t.Fatal("expected SSRF finding for new URI(var) reaching HttpClient.send")
	}
	if f.CWEID != "CWE-918" {
		t.Errorf("expected CWE-918, got %s", f.CWEID)
	}
}

// TestSSRFURLOpenStreamFires guards the directly-chained fetch shape
// (new URL(var).openStream()) and the assigned-then-fetched URI shape.
func TestSSRFURLOpenStreamFires(t *testing.T) {
	code := `
class Handler {
    void download(String target) throws Exception {
        new URL(target).openStream();
    }
}
`
	f := findByRule(scanJava(code), "BATOU-JAVAAST-008")
	if f == nil {
		t.Fatal("expected SSRF finding for new URL(var).openStream()")
	}
	if f.CWEID != "CWE-918" {
		t.Errorf("expected CWE-918, got %s", f.CWEID)
	}
}

// --- SpEL / OGNL expression injection (CWE-917, BATOU-JAVAAST-009) ---

func TestSpELParseExpression(t *testing.T) {
	code := `
class Handler {
    void eval(ExpressionParser parser, String expr) {
        parser.parseExpression(expr).getValue();
    }
}
`
	f := findByRule(scanJava(code), "BATOU-JAVAAST-009")
	if f == nil {
		t.Error("expected SpEL injection finding for parseExpression(var)")
	} else if f.CWEID != "CWE-917" {
		t.Errorf("expected CWE-917, got %s", f.CWEID)
	}
}

func TestOGNLGetValue(t *testing.T) {
	code := `
class Handler {
    void eval(String expr, Object root) throws Exception {
        Ognl.getValue(expr, root);
    }
}
`
	f := findByRule(scanJava(code), "BATOU-JAVAAST-009")
	if f == nil {
		t.Error("expected OGNL injection finding for Ognl.getValue(var, ...)")
	}
}

func TestSpELLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void eval(ExpressionParser parser) {
        parser.parseExpression("1 + 1").getValue();
    }
}
`
	for _, f := range scanJava(code) {
		if f.RuleID == "BATOU-JAVAAST-009" {
			t.Errorf("should NOT flag literal expression: %s", f.MatchedText)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.java",
		Content:  "class X {}",
		Language: rules.LangJava,
		Tree:     nil,
	}
	a := &JavaASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "class X {}",
		Language: rules.LangPython,
	}
	a := &JavaASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
// comment
class Handler {
    void handle(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "BATOU-JAVAAST-002")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 5 {
		t.Errorf("expected line 5, got %d", f.LineNumber)
	}
}
