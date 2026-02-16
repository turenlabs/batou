package xxe

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended XXE detection
// ---------------------------------------------------------------------------

var (
	// BATOU-XXE-005: XML parsing without disabling DTD (C#/.NET)
	reExtCSharpXmlDoc      = regexp.MustCompile(`\bnew\s+XmlDocument\s*\(`)
	reExtCSharpXmlLoad     = regexp.MustCompile(`\.Load(?:Xml)?\s*\(`)
	reExtCSharpDtdParse    = regexp.MustCompile(`DtdProcessing\s*=\s*DtdProcessing\.Parse`)
	reExtCSharpProhibitDTD = regexp.MustCompile(`(?:DtdProcessing\s*=\s*DtdProcessing\.Prohibit|XmlResolver\s*=\s*null|ProhibitDtd\s*=\s*true)`)

	// BATOU-XXE-006: XSLT processing with external entities
	reExtXSLTProcess    = regexp.MustCompile(`(?i)(?:XslCompiledTransform|XslTransform|TransformerFactory|newTransformer|xsltproc|lxml\.etree\.XSLT|XsltProcessor)\s*[\(.]`)
	reExtXSLTSafe       = regexp.MustCompile(`(?i)(?:FEATURE_SECURE_PROCESSING|setFeature|ACCESS_EXTERNAL|resolve_entities\s*=\s*False)`)

	// BATOU-XXE-007: XInclude processing enabled
	reExtXInclude       = regexp.MustCompile(`(?i)(?:xinclude|xi:include|XIncludeAware|setXIncludeAware\s*\(\s*true|process_?xincludes|parse.*xinclude)`)
	reExtXIncludeNS     = regexp.MustCompile(`xmlns:xi\s*=\s*["']http://www\.w3\.org/2001/XInclude["']`)

	// BATOU-XXE-008: SOAP XML parsing without protection
	reExtSOAPParse      = regexp.MustCompile(`(?i)(?:SOAPMessage|SoapClient|suds|zeep|savon|MessageFactory\.newInstance|SOAPConnectionFactory|soap_client|SoapServer|nusoap)`)
	reExtSOAPWithInput  = regexp.MustCompile(`(?i)(?:SOAPMessage|SoapClient|suds|zeep|savon|soap_client|SoapServer|nusoap).*(?:req\.|request\.|input|body|param|\$_)`)

	// BATOU-XXE-009: XML parsing in mobile app (Android/iOS)
	reExtAndroidXML     = regexp.MustCompile(`(?i)(?:XmlPullParser|SAXParser|DocumentBuilder|XMLReader)\s*(?:\.|\.newInstance|\.newSAXParser)`)
	reExtIOSXML         = regexp.MustCompile(`(?i)(?:XMLParser|NSXMLParser|NSXMLDocument)\s*(?:alloc|init|\.init)`)
	reExtAndroidFactory = regexp.MustCompile(`(?i)(?:XmlPullParserFactory|SAXParserFactory|DocumentBuilderFactory)\.newInstance\s*\(`)

	// BATOU-XXE-010: SVG/RSS/Atom feed XML parsing
	reExtFeedParse      = regexp.MustCompile(`(?i)(?:feedparser|rss|atom|svg).*(?:parse|read|load|from_?string)\s*\(`)
	reExtSVGParse       = regexp.MustCompile(`(?i)(?:svg|image/svg).*(?:parse|render|load|process|convert|transform)\s*\(`)
	reExtFeedLib        = regexp.MustCompile(`(?i)(?:feedparser|rss-parser|atom-parser|xml-rss|simplepie|rome|SyndFeedInput)`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&CSharpXMLDTD{})
	rules.Register(&XSLTExtEntities{})
	rules.Register(&XIncludeProcessing{})
	rules.Register(&SOAPXMLParsing{})
	rules.Register(&MobileXMLParsing{})
	rules.Register(&FeedXMLParsing{})
}

// ========================================================================
// BATOU-XXE-005: XML Parsing without Disabling DTD (C#/.NET)
// ========================================================================

type CSharpXMLDTD struct{}

func (r *CSharpXMLDTD) ID() string                     { return "BATOU-XXE-005" }
func (r *CSharpXMLDTD) Name() string                   { return "CSharpXMLDTD" }
func (r *CSharpXMLDTD) DefaultSeverity() rules.Severity { return rules.High }
func (r *CSharpXMLDTD) Description() string {
	return "Detects C#/.NET XmlDocument instantiation without disabling DTD processing, enabling XXE attacks."
}
func (r *CSharpXMLDTD) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *CSharpXMLDTD) Scan(ctx *rules.ScanContext) []rules.Finding {
	// If file has DTD prohibit settings, skip
	if reExtCSharpProhibitDTD.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		if m := reExtCSharpXmlDoc.FindString(line); m != "" {
			matched = m
		} else if m := reExtCSharpDtdParse.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XXE: C# XmlDocument without DTD protection",
				Description:   "XmlDocument is instantiated without setting DtdProcessing.Prohibit or XmlResolver = null. This allows XXE attacks via crafted XML that defines external entities.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Set XmlResolver = null on XmlDocument instances. For XmlReaderSettings, set DtdProcessing = DtdProcessing.Prohibit.",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"xxe", "xml", "csharp", "dtd"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-XXE-006: XSLT Processing with External Entities
// ========================================================================

type XSLTExtEntities struct{}

func (r *XSLTExtEntities) ID() string                     { return "BATOU-XXE-006" }
func (r *XSLTExtEntities) Name() string                   { return "XSLTExtEntities" }
func (r *XSLTExtEntities) DefaultSeverity() rules.Severity { return rules.High }
func (r *XSLTExtEntities) Description() string {
	return "Detects XSLT processing that may allow external entity resolution, enabling XXE via XSLT stylesheets."
}
func (r *XSLTExtEntities) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangCSharp, rules.LangPython, rules.LangAny}
}

func (r *XSLTExtEntities) Scan(ctx *rules.ScanContext) []rules.Finding {
	if reExtXSLTSafe.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtXSLTProcess.FindString(line); m != "" {
			if hasSecureXMLConfig(lines, i) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XXE: XSLT processing without entity protection",
				Description:   "XSLT processing can resolve external entities defined in XSL stylesheets. If the stylesheet is user-controlled, this enables XXE attacks including file read and SSRF.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Set FEATURE_SECURE_PROCESSING on TransformerFactory. Set ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_STYLESHEET to empty strings. For lxml, set resolve_entities=False.",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"xxe", "xslt", "external-entity"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-XXE-007: XInclude Processing Enabled
// ========================================================================

type XIncludeProcessing struct{}

func (r *XIncludeProcessing) ID() string                     { return "BATOU-XXE-007" }
func (r *XIncludeProcessing) Name() string                   { return "XIncludeProcessing" }
func (r *XIncludeProcessing) DefaultSeverity() rules.Severity { return rules.High }
func (r *XIncludeProcessing) Description() string {
	return "Detects XInclude processing being enabled, which can include external XML documents and enable XXE."
}
func (r *XIncludeProcessing) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *XIncludeProcessing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		if m := reExtXInclude.FindString(line); m != "" {
			matched = m
		} else if m := reExtXIncludeNS.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XXE: XInclude processing enabled",
				Description:   "XInclude processing allows XML documents to include content from other XML documents or files. If user-controlled XML is parsed with XInclude enabled, attackers can read arbitrary files.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Disable XInclude processing: factory.setXIncludeAware(false) in Java. For lxml, do not call xinclude(). Remove xi:include elements from untrusted XML.",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"xxe", "xinclude", "injection"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-XXE-008: SOAP XML Parsing without Protection
// ========================================================================

type SOAPXMLParsing struct{}

func (r *SOAPXMLParsing) ID() string                     { return "BATOU-XXE-008" }
func (r *SOAPXMLParsing) Name() string                   { return "SOAPXMLParsing" }
func (r *SOAPXMLParsing) DefaultSeverity() rules.Severity { return rules.High }
func (r *SOAPXMLParsing) Description() string {
	return "Detects SOAP/WSDL client/server usage that parses XML without explicit XXE protection."
}
func (r *SOAPXMLParsing) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangPHP, rules.LangPython, rules.LangRuby}
}

func (r *SOAPXMLParsing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if m := reExtSOAPWithInput.FindString(line); m != "" {
			if hasSecureXMLConfigWithSetters(lines, i) {
				continue
			}
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XXE: SOAP XML parsing with user input",
				Description:   "SOAP/WSDL processing parses XML messages which may contain external entity declarations. If the SOAP message body comes from user input, this enables XXE attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Configure the underlying XML parser to disable external entities. In Java, set secure processing features on the SOAPMessage factory. In PHP, use libxml_disable_entity_loader(true).",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"xxe", "soap", "wsdl"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-XXE-009: XML Parsing in Mobile App (Android/iOS)
// ========================================================================

type MobileXMLParsing struct{}

func (r *MobileXMLParsing) ID() string                     { return "BATOU-XXE-009" }
func (r *MobileXMLParsing) Name() string                   { return "MobileXMLParsing" }
func (r *MobileXMLParsing) DefaultSeverity() rules.Severity { return rules.High }
func (r *MobileXMLParsing) Description() string {
	return "Detects XML parsing in Android/iOS applications without disabling external entities."
}
func (r *MobileXMLParsing) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangKotlin, rules.LangSwift}
}

func (r *MobileXMLParsing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		if m := reExtAndroidXML.FindString(line); m != "" {
			matched = m
		} else if m := reExtIOSXML.FindString(line); m != "" {
			matched = m
		} else if m := reExtAndroidFactory.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			if hasSecureXMLConfigWithSetters(lines, i) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XXE: Mobile app XML parsing without entity protection",
				Description:   "XML parsing in a mobile application without disabling external entities. If the XML comes from a server response or file, a man-in-the-middle attacker or malicious server can exploit XXE to read local files.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Android: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true). iOS: set shouldResolveExternalEntities = false on NSXMLParser.",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"xxe", "mobile", "android", "ios"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-XXE-010: SVG/RSS/Atom Feed XML Parsing without Protection
// ========================================================================

type FeedXMLParsing struct{}

func (r *FeedXMLParsing) ID() string                     { return "BATOU-XXE-010" }
func (r *FeedXMLParsing) Name() string                   { return "FeedXMLParsing" }
func (r *FeedXMLParsing) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FeedXMLParsing) Description() string {
	return "Detects SVG, RSS, or Atom feed XML parsing that may be vulnerable to XXE if processing untrusted content."
}
func (r *FeedXMLParsing) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *FeedXMLParsing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	hasFeedLib := reExtFeedLib.MatchString(ctx.Content)

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		var matched string
		if m := reExtFeedParse.FindString(line); m != "" {
			matched = m
		} else if m := reExtSVGParse.FindString(line); m != "" {
			matched = m
		}
		if matched == "" && hasFeedLib {
			if strings.Contains(line, "parse") || strings.Contains(line, "read") || strings.Contains(line, "load") {
				if reExtFeedLib.MatchString(line) {
					matched = reExtFeedLib.FindString(line)
				}
			}
		}
		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "XXE: SVG/RSS/Atom feed XML parsing without protection",
				Description:   "Parsing SVG images or RSS/Atom feeds involves XML parsing that may process external entities. If the content is from untrusted sources (user uploads, external feeds), this can enable XXE.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use a safe XML parser with external entities disabled. Sanitize SVG files by stripping external references. For RSS/Atom, use feedparser with sanitize_html=True or equivalent.",
				CWEID:         "CWE-611",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "low",
				Tags:          []string{"xxe", "svg", "rss", "feed"},
			})
		}
	}
	return findings
}
