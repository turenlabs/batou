package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Apache Avro deserialization sinks (CWE-502).
//
// CVE-2024-47561 (Apache Avro Java SDK < 1.11.4): tainted JSON schema
// reaching Schema.parse() / Schema.Parser().parse() leads to arbitrary code
// execution via custom logical-type and class-instantiation paths. Avro
// DataFileReader / DataFileStream read an embedded schema from a container
// file, so reading a tainted file is equivalent to parsing a tainted schema.
// ReflectDatumReader additionally uses reflection to instantiate classes
// named in the schema, which is unsafe whenever the schema is attacker-
// controlled.

func TestJava_Avro_SchemaParse_Static_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.avro.Schema;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String json = request.getParameter("schema");
        Schema schema = Schema.parse(json);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for getParameter -> Schema.parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Avro_SchemaParser_Parse_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.avro.Schema;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String json = request.getParameter("schema");
        Schema.Parser parser = new Schema.Parser();
        Schema schema = parser.parse(json);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for getParameter -> Schema.Parser.parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Avro_DataFileReader_New_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.File;
import org.apache.avro.file.DataFileReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String path = request.getParameter("path");
        DataFileReader reader = new DataFileReader(path, null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for getParameter -> new DataFileReader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Avro_DataFileStream_New_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.InputStream;
import org.apache.avro.file.DataFileStream;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        InputStream in = request.getInputStream();
        DataFileStream stream = new DataFileStream(in, null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for getInputStream -> new DataFileStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Avro_ReflectDatumReader_New_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.avro.reflect.ReflectDatumReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String schema = request.getParameter("schema");
        ReflectDatumReader reader = new ReflectDatumReader(schema);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for getParameter -> new ReflectDatumReader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe: hardcoded schema literal should NOT trigger.
func TestJava_Avro_HardcodedSchema_NoFlow(t *testing.T) {
	code := `
import org.apache.avro.Schema;

public class Handler {
    public void run() {
        Schema.Parser parser = new Schema.Parser();
        Schema schema = parser.parse("{\"type\":\"record\",\"name\":\"User\",\"fields\":[]}");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialize flow for hardcoded Avro schema literal")
	}
}
