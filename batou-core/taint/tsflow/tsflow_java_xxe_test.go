package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// XXE sinks are categorized as SnkXPath (CWE-611) following the existing
// java.xml.documentbuilder.parse / java.xml.saxparser.parse convention.

func TestJava_XXE_XMLReader_Parse(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.xml.sax.*;
import org.xml.sax.helpers.XMLReaderFactory;
import java.io.StringReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        XMLReader xmlReader = XMLReaderFactory.createXMLReader();
        xmlReader.parse(new InputSource(new StringReader(xml)));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XXE flow for getParameter -> XMLReader.parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_XXE_XMLInputFactory_StreamReader(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.stream.*;
import java.io.StringReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        XMLStreamReader sr = xmlInputFactory.createXMLStreamReader(new StringReader(xml));
        while (sr.hasNext()) { sr.next(); }
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XXE flow for getParameter -> XMLInputFactory.createXMLStreamReader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_XXE_XMLInputFactory_EventReader(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.stream.*;
import java.io.StringReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        XMLEventReader er = xmlInputFactory.createXMLEventReader(new StringReader(xml));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XXE flow for getParameter -> XMLInputFactory.createXMLEventReader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_XXE_Transformer_Transform(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import java.io.StringReader;
import java.io.StringWriter;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(new StreamSource(new StringReader(xml)), new StreamResult(new StringWriter()));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XXE flow for getParameter -> Transformer.transform")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_XXE_SchemaFactory_NewSchema(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.*;
import javax.xml.validation.*;
import javax.xml.transform.stream.*;
import java.io.StringReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String schemaXml = request.getParameter("schema");
        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        Schema schema = schemaFactory.newSchema(new StreamSource(new StringReader(schemaXml)));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XXE flow for getParameter -> SchemaFactory.newSchema")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_XXE_JDOM_SAXBuilder_Build(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.jdom2.*;
import org.jdom2.input.SAXBuilder;
import java.io.StringReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        SAXBuilder saxBuilder = new SAXBuilder();
        Document doc = saxBuilder.build(new StringReader(xml));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XXE flow for getParameter -> SAXBuilder.build (JDOM)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_XXE_DOM4J_SAXReader_Read(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.dom4j.*;
import org.dom4j.io.SAXReader;
import java.io.StringReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        SAXReader saxReader = new SAXReader();
        Document doc = saxReader.read(new StringReader(xml));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XXE flow for getParameter -> SAXReader.read (DOM4J)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative test: StAX with external entities disabled should still produce a flow
// because we only mark sanitization at the sanitizer pattern. The point of this
// fixture is to confirm the XXE prevention sanitizer pattern is recognized
// alongside the new sink. (Existing TestJava_XXE_*_Sanitized cover the sanitizer
// behavior in tsflow_java_sanitizers_test.go.)
