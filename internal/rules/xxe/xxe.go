package xxe

import (
	"regexp"
	"strings"

	"github.com/turen/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// GTSS-XXE-001: Java XML Parser without Secure Configuration
var (
	// DocumentBuilderFactory.newInstance() — vulnerable unless features are set
	reDocBuilderFactory = regexp.MustCompile(`\bDocumentBuilderFactory\s*\.\s*newInstance\s*\(`)
	// SAXParserFactory.newInstance() — vulnerable unless features are set
	reSAXParserFactory = regexp.MustCompile(`\bSAXParserFactory\s*\.\s*newInstance\s*\(`)
	// XMLInputFactory.newInstance() / XMLInputFactory.newFactory()
	reXMLInputFactory = regexp.MustCompile(`\bXMLInputFactory\s*\.\s*(?:newInstance|newFactory)\s*\(`)
	// TransformerFactory.newInstance() — vulnerable unless secure processing is set
	reTransformerFactory = regexp.MustCompile(`\bTransformerFactory\s*\.\s*newInstance\s*\(`)
	// XMLReader / XMLReaderFactory.createXMLReader()
	reXMLReader = regexp.MustCompile(`\b(?:XMLReaderFactory\s*\.\s*createXMLReader|SAXParserFactory\s*\.\s*newInstance\s*\(\s*\)\s*\.\s*newSAXParser\s*\(\s*\)\s*\.\s*getXMLReader)\s*\(`)
	// SchemaFactory.newInstance()
	reSchemaFactory = regexp.MustCompile(`\bSchemaFactory\s*\.\s*newInstance\s*\(`)

	// Safe configuration patterns (features that disable XXE)
	reDisallowDoctype = regexp.MustCompile(`(?i)disallow-doctype-decl`)
	reDisableExternalEntities = regexp.MustCompile(`(?i)(?:external-general-entities|external-parameter-entities|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD)`)
	reSecureProcessing = regexp.MustCompile(`(?i)(?:FEATURE_SECURE_PROCESSING|secure-processing|XMLConstants\s*\.\s*FEATURE_SECURE_PROCESSING)`)
	reAccessExternal = regexp.MustCompile(`(?i)(?:ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_STYLESHEET|ACCESS_EXTERNAL_SCHEMA)`)
	reSetFeature = regexp.MustCompile(`\.setFeature\s*\(`)
	reSetProperty = regexp.MustCompile(`\.setProperty\s*\(`)
	reSetAttribute = regexp.MustCompile(`\.setAttribute\s*\(`)
)

// GTSS-XXE-002: JavaScript/Node XML Parser with Entity Expansion
var (
	// libxmljs.parseXml with noent: true (explicit entity expansion)
	reLibxmlNoent = regexp.MustCompile(`\blibxml(?:js)?\s*\.\s*parseXml\s*\([^)]*\bnoent\s*:\s*true`)
	// libxmljs.parseXml with user input (general detection)
	reLibxmlParse = regexp.MustCompile(`\blibxml(?:js)?\s*\.\s*parseXml(?:String)?\s*\(`)
	// xml2js.parseString / xml2js.Parser
	reXml2js = regexp.MustCompile(`\bxml2js\s*\.\s*(?:parseString|Parser)\s*\(`)
	// DOMParser().parseFromString
	reDOMParser = regexp.MustCompile(`\bnew\s+DOMParser\s*\(\s*\)`)
	// fast-xml-parser with processEntities: true
	reFastXMLParser = regexp.MustCompile(`\bnew\s+(?:XMLParser|FastXMLParser)\s*\([^)]*\bprocessEntities\s*:\s*true`)
	// Generic XML parse with user input from request
	reXMLParseReqInput = regexp.MustCompile(`(?:parse(?:Xml|XML|String)?|parseFromString)\s*\(\s*(?:req\s*\.\s*(?:body|query|params)|request\s*\.\s*(?:body|input))`)
)

// GTSS-XXE-003: Python XML Parser (unsafe by default)
var (
	// Python: xml.etree.ElementTree.parse / fromstring
	rePyElementTree = regexp.MustCompile(`\b(?:ET|ElementTree|xml\.etree\.ElementTree)\s*\.\s*(?:parse|fromstring|XML|iterparse)\s*\(`)
	// Python: xml.dom.minidom.parse / parseString
	rePyMinidom = regexp.MustCompile(`\b(?:minidom|xml\.dom\.minidom)\s*\.\s*(?:parse|parseString)\s*\(`)
	// Python: xml.sax.parse / make_parser
	rePySAX = regexp.MustCompile(`\b(?:xml\.sax|sax)\s*\.\s*(?:parse|parseString|make_parser)\s*\(`)
	// Python: lxml.etree.parse / fromstring without resolve_entities=False
	rePyLxml = regexp.MustCompile(`\b(?:lxml\.etree|etree)\s*\.\s*(?:parse|fromstring|XML|iterparse)\s*\(`)
	// Python: pulldom
	rePyPulldom = regexp.MustCompile(`\b(?:xml\.dom\.pulldom|pulldom)\s*\.\s*(?:parse|parseString)\s*\(`)
	// Safe: defusedxml usage
	reDefusedXML = regexp.MustCompile(`\bdefusedxml\b`)
	// Safe: resolve_entities=False
	rePyResolveEntitiesFalse = regexp.MustCompile(`resolve_entities\s*=\s*False`)
)

// GTSS-XXE-004: C#/.NET XML Parser without Secure Configuration
var (
	// XmlDocument.Load / LoadXml
	reCSharpXmlDocument = regexp.MustCompile(`\bXmlDocument\s*\(\s*\)|\.Load(?:Xml)?\s*\(`)
	// XmlTextReader
	reCSharpXmlTextReader = regexp.MustCompile(`\bnew\s+XmlTextReader\s*\(`)
	// XmlReader.Create without settings
	reCSharpXmlReader = regexp.MustCompile(`\bXmlReader\s*\.\s*Create\s*\(`)
	// Safe: XmlReaderSettings with DtdProcessing.Prohibit
	reCSharpDtdProhibit = regexp.MustCompile(`DtdProcessing\s*\.\s*Prohibit`)
	reCSharpXmlResolver = regexp.MustCompile(`XmlResolver\s*=\s*null`)
)

// ---------------------------------------------------------------------------
// Comment detection
// ---------------------------------------------------------------------------

var reLineComment = regexp.MustCompile(`^\s*(?://|#|--|;|%|/\*)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// hasSecureXMLConfig checks surrounding lines for XXE prevention patterns.
func hasSecureXMLConfig(lines []string, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 15
	if end > len(lines) {
		end = len(lines)
	}

	for _, l := range lines[start:end] {
		if reDisallowDoctype.MatchString(l) ||
			reDisableExternalEntities.MatchString(l) ||
			reSecureProcessing.MatchString(l) ||
			reAccessExternal.MatchString(l) {
			return true
		}
	}
	return false
}

// hasSecureXMLConfigWithSetters checks for both feature constants AND
// the setter methods (setFeature/setProperty/setAttribute) in surrounding lines.
func hasSecureXMLConfigWithSetters(lines []string, idx int) bool {
	if hasSecureXMLConfig(lines, idx) {
		return true
	}
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 15
	if end > len(lines) {
		end = len(lines)
	}
	hasFeatureSetter := false
	for _, l := range lines[start:end] {
		if reSetFeature.MatchString(l) || reSetProperty.MatchString(l) || reSetAttribute.MatchString(l) {
			hasFeatureSetter = true
			break
		}
	}
	return hasFeatureSetter
}

// ---------------------------------------------------------------------------
// GTSS-XXE-001: Java XML Parser without Secure Configuration
// ---------------------------------------------------------------------------

type JavaXXE struct{}

func (r JavaXXE) ID() string                       { return "GTSS-XXE-001" }
func (r JavaXXE) Name() string                     { return "Java XXE Vulnerability" }
func (r JavaXXE) DefaultSeverity() rules.Severity  { return rules.Critical }
func (r JavaXXE) Description() string {
	return "Detects Java XML parsers (DocumentBuilderFactory, SAXParserFactory, XMLInputFactory, TransformerFactory) instantiated without disabling external entity processing, which allows XXE attacks."
}
func (r JavaXXE) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r JavaXXE) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	patterns := []pattern{
		{reDocBuilderFactory, "high", "DocumentBuilderFactory.newInstance() without disabling external entities"},
		{reSAXParserFactory, "high", "SAXParserFactory.newInstance() without disabling external entities"},
		{reXMLInputFactory, "high", "XMLInputFactory.newInstance() without disabling external entities"},
		{reTransformerFactory, "high", "TransformerFactory.newInstance() without secure processing"},
		{reXMLReader, "high", "XMLReader created without disabling external entities"},
		{reSchemaFactory, "medium", "SchemaFactory.newInstance() without disabling external entities"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				// Check if secure configuration is present nearby
				if hasSecureXMLConfigWithSetters(lines, i) {
					continue
				}
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "XXE: " + p.desc,
					Description:   "Java XML parsers are vulnerable to XML External Entity (XXE) attacks by default. Without explicitly disabling external entities, an attacker can read arbitrary files, perform SSRF, or cause denial of service.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Disable external entities: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) or set XMLConstants.ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_SCHEMA to empty strings.",
					CWEID:         "CWE-611",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"xxe", "xml", "injection"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XXE-002: JavaScript/Node XML Parser with Entity Expansion
// ---------------------------------------------------------------------------

type JavaScriptXXE struct{}

func (r JavaScriptXXE) ID() string                       { return "GTSS-XXE-002" }
func (r JavaScriptXXE) Name() string                     { return "JavaScript XXE Vulnerability" }
func (r JavaScriptXXE) DefaultSeverity() rules.Severity  { return rules.Critical }
func (r JavaScriptXXE) Description() string {
	return "Detects JavaScript/Node.js XML parsing with external entity expansion enabled (e.g., libxmljs with noent:true, xml2js, DOMParser with user input), which allows XXE attacks."
}
func (r JavaScriptXXE) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r JavaScriptXXE) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
		sev  rules.Severity
	}

	patterns := []pattern{
		{reLibxmlNoent, "high", "libxmljs.parseXml with noent:true enables external entity expansion", rules.Critical},
		{reXMLParseReqInput, "high", "XML parsing with request body input (potential XXE)", rules.High},
		{reDOMParser, "medium", "DOMParser instantiation (verify external entities are not processed)", rules.Medium},
		{reFastXMLParser, "high", "fast-xml-parser with processEntities:true enables entity expansion", rules.High},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      p.sev,
					SeverityLabel: p.sev.String(),
					Title:         "XXE: " + p.desc,
					Description:   "XML parsers with entity expansion enabled allow attackers to read files, perform SSRF, or cause denial of service via crafted XML with external entity declarations.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Disable entity expansion: for libxmljs use {noent: false, nonet: true}, avoid parsing untrusted XML with DOMParser, or use a safe XML parser like fast-xml-parser with processEntities: false.",
					CWEID:         "CWE-611",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"xxe", "xml", "injection"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-XXE-003: Python XML Parser (unsafe by default)
// ---------------------------------------------------------------------------

type PythonXXE struct{}

func (r PythonXXE) ID() string                       { return "GTSS-XXE-003" }
func (r PythonXXE) Name() string                     { return "Python XXE Vulnerability" }
func (r PythonXXE) DefaultSeverity() rules.Severity  { return rules.High }
func (r PythonXXE) Description() string {
	return "Detects Python XML parsers (xml.etree, minidom, sax, lxml) that may be vulnerable to XXE attacks. Python's stdlib XML modules are unsafe by default."
}
func (r PythonXXE) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r PythonXXE) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip files that import defusedxml (safe replacement)
	if reDefusedXML.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	patterns := []pattern{
		{rePyElementTree, "medium", "xml.etree.ElementTree usage (vulnerable to XXE by default)"},
		{rePyMinidom, "medium", "xml.dom.minidom usage (vulnerable to XXE by default)"},
		{rePySAX, "medium", "xml.sax usage (vulnerable to XXE by default)"},
		{rePyLxml, "medium", "lxml.etree usage (check resolve_entities setting)"},
		{rePyPulldom, "medium", "xml.dom.pulldom usage (vulnerable to XXE by default)"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				// For lxml, check if resolve_entities=False is set nearby
				if p.re == rePyLxml && hasPySecureXMLConfig(lines, i) {
					continue
				}
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "XXE: " + p.desc,
					Description:   "Python's standard library XML modules (xml.etree, minidom, sax) are vulnerable to XXE attacks by default. Use defusedxml as a drop-in safe replacement.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Replace with defusedxml: import defusedxml.ElementTree as ET (drop-in replacement). For lxml, set resolve_entities=False in the parser.",
					CWEID:         "CWE-611",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"xxe", "xml", "injection"},
				})
				break
			}
		}
	}
	return findings
}

func hasPySecureXMLConfig(lines []string, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 10
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if rePyResolveEntitiesFalse.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// GTSS-XXE-004: C#/.NET XML Parser without Secure Configuration
// ---------------------------------------------------------------------------

type CSharpXXE struct{}

func (r CSharpXXE) ID() string                       { return "GTSS-XXE-004" }
func (r CSharpXXE) Name() string                     { return "C# XXE Vulnerability" }
func (r CSharpXXE) DefaultSeverity() rules.Severity  { return rules.High }
func (r CSharpXXE) Description() string {
	return "Detects C#/.NET XML parsers (XmlDocument, XmlTextReader, XmlReader) without secure DTD processing configuration, which may allow XXE attacks."
}
func (r CSharpXXE) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r CSharpXXE) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
	}

	patterns := []pattern{
		{reCSharpXmlTextReader, "high", "XmlTextReader without DtdProcessing.Prohibit"},
		{reCSharpXmlReader, "medium", "XmlReader.Create (verify DtdProcessing is set to Prohibit)"},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				if hasCSharpSecureConfig(lines, i) {
					continue
				}
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "XXE: " + p.desc,
					Description:   "C#/.NET XML parsers may be vulnerable to XXE attacks if DTD processing is not explicitly disabled. Set DtdProcessing = DtdProcessing.Prohibit and XmlResolver = null.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Set DtdProcessing = DtdProcessing.Prohibit and XmlResolver = null on XmlReaderSettings. For XmlDocument, set XmlResolver = null.",
					CWEID:         "CWE-611",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"xxe", "xml", "injection"},
				})
				break
			}
		}
	}
	return findings
}

func hasCSharpSecureConfig(lines []string, idx int) bool {
	start := idx - 5
	if start < 0 {
		start = 0
	}
	end := idx + 10
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if reCSharpDtdProhibit.MatchString(l) || reCSharpXmlResolver.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(JavaXXE{})
	rules.Register(JavaScriptXXE{})
	rules.Register(PythonXXE{})
	rules.Register(CSharpXXE{})
}
