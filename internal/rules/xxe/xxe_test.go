package xxe

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// ---------------------------------------------------------------------------
// GTSS-XXE-001: Java XML Parser without Secure Configuration
// ---------------------------------------------------------------------------

func TestXXE001_DocumentBuilderFactory(t *testing.T) {
	content := `public class XmlHandler {
    public void parse(InputStream input) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(input);
    }
}`
	result := testutil.ScanContent(t, "/app/XmlHandler.java", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-001")
}

func TestXXE001_SAXParserFactory(t *testing.T) {
	content := `public class SaxHandler {
    public void parse(InputStream input) {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(input, handler);
    }
}`
	result := testutil.ScanContent(t, "/app/SaxHandler.java", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-001")
}

func TestXXE001_XMLInputFactory(t *testing.T) {
	content := `public class StaxHandler {
    public void parse(InputStream input) {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(input);
    }
}`
	result := testutil.ScanContent(t, "/app/StaxHandler.java", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-001")
}

func TestXXE001_TransformerFactory(t *testing.T) {
	content := `public class XslHandler {
    public void transform(Source source) {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer(source);
    }
}`
	result := testutil.ScanContent(t, "/app/XslHandler.java", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-001")
}

func TestXXE001_Safe_DisallowDoctype(t *testing.T) {
	content := `public class SafeXmlHandler {
    public void parse(InputStream input) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(input);
    }
}`
	result := testutil.ScanContent(t, "/app/SafeXmlHandler.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-XXE-001")
}

func TestXXE001_Safe_DisableExternalEntities(t *testing.T) {
	content := `public class SafeStaxHandler {
    public void parse(InputStream input) {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(input);
    }
}`
	result := testutil.ScanContent(t, "/app/SafeStaxHandler.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-XXE-001")
}

func TestXXE001_Safe_SecureProcessing(t *testing.T) {
	content := `public class SafeTransformer {
    public void transform(Source source) {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = tf.newTransformer(source);
    }
}`
	result := testutil.ScanContent(t, "/app/SafeTransformer.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-XXE-001")
}

func TestXXE001_Fixture_Java(t *testing.T) {
	content := testutil.LoadFixture(t, "java/vulnerable/XxeBasic.java")
	result := testutil.ScanContent(t, "/app/XxeBasic.java", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-001")
}

// ---------------------------------------------------------------------------
// GTSS-XXE-002: JavaScript/Node XML Parser with Entity Expansion
// ---------------------------------------------------------------------------

func TestXXE002_LibxmlNoent(t *testing.T) {
	content := `const xmlData = req.body.xml;
const doc = libxmljs.parseXml(xmlData, { noent: true, nonet: false });
const name = doc.get('//name').text();`
	result := testutil.ScanContent(t, "/app/parser.ts", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-002")
}

func TestXXE002_LibxmlNoentShort(t *testing.T) {
	content := `const doc = libxml.parseXml(data, { noent: true });`
	result := testutil.ScanContent(t, "/app/parser.js", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-002")
}

func TestXXE002_DOMParser(t *testing.T) {
	content := `const parser = new DOMParser();
const doc = parser.parseFromString(xmlInput, 'text/xml');`
	result := testutil.ScanContent(t, "/app/parser.ts", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-002")
}

func TestXXE002_FastXMLParserEntities(t *testing.T) {
	content := `const parser = new XMLParser({ processEntities: true, allowBooleanAttributes: true });
const result = parser.parse(xmlString);`
	result := testutil.ScanContent(t, "/app/parser.ts", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-002")
}

func TestXXE002_ParseFromStringReqBody(t *testing.T) {
	content := `const doc = parser.parseFromString(req.body.xml, 'text/xml');`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-002")
}

func TestXXE002_Fixture_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/xml_xxe.ts")
	result := testutil.ScanContent(t, "/app/xml_xxe.ts", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-002")
}

// ---------------------------------------------------------------------------
// GTSS-XXE-003: Python XML Parser
// ---------------------------------------------------------------------------

func TestXXE003_ElementTree(t *testing.T) {
	content := `import xml.etree.ElementTree as ET
tree = ET.parse(user_input_file)
root = tree.getroot()`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-003")
}

func TestXXE003_Minidom(t *testing.T) {
	content := `from xml.dom.minidom import parseString
doc = minidom.parseString(xml_data)`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-003")
}

func TestXXE003_SAX(t *testing.T) {
	content := `import xml.sax
parser = xml.sax.make_parser()
parser.parse(input_file)`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-003")
}

func TestXXE003_Lxml(t *testing.T) {
	content := `from lxml import etree
doc = etree.parse(xml_file)
root = doc.getroot()`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-003")
}

func TestXXE003_Safe_DefusedXML(t *testing.T) {
	content := `import defusedxml.ElementTree as ET
tree = ET.parse(user_input_file)
root = tree.getroot()`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-XXE-003")
}

func TestXXE003_Safe_LxmlResolveEntitiesFalse(t *testing.T) {
	content := `from lxml import etree
parser = etree.XMLParser(resolve_entities=False)
doc = etree.parse(xml_file, parser)
root = doc.getroot()`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-XXE-003")
}

// ---------------------------------------------------------------------------
// GTSS-XXE-004: C#/.NET XML Parser
// ---------------------------------------------------------------------------

func TestXXE004_XmlTextReader(t *testing.T) {
	content := `public void Parse(string xml) {
    var reader = new XmlTextReader(new StringReader(xml));
    while (reader.Read()) { }
}`
	result := testutil.ScanContent(t, "/app/Parser.cs", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-004")
}

func TestXXE004_XmlReaderCreate(t *testing.T) {
	content := `public void Parse(string xml) {
    var reader = XmlReader.Create(new StringReader(xml));
    while (reader.Read()) { }
}`
	result := testutil.ScanContent(t, "/app/Parser.cs", content)
	testutil.MustFindRule(t, result, "GTSS-XXE-004")
}

func TestXXE004_Safe_DtdProhibit(t *testing.T) {
	content := `public void Parse(string xml) {
    var settings = new XmlReaderSettings();
    settings.DtdProcessing = DtdProcessing.Prohibit;
    var reader = XmlReader.Create(new StringReader(xml), settings);
    while (reader.Read()) { }
}`
	result := testutil.ScanContent(t, "/app/Parser.cs", content)
	testutil.MustNotFindRule(t, result, "GTSS-XXE-004")
}

func TestXXE004_Safe_XmlResolverNull(t *testing.T) {
	content := `public void Parse(string xml) {
    var settings = new XmlReaderSettings();
    settings.XmlResolver = null;
    var reader = XmlReader.Create(new StringReader(xml), settings);
    while (reader.Read()) { }
}`
	result := testutil.ScanContent(t, "/app/Parser.cs", content)
	testutil.MustNotFindRule(t, result, "GTSS-XXE-004")
}
