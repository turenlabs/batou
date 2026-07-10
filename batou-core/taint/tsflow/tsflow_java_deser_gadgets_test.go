package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the deserialization gadget sinks added to java_sinks.go:
// Apache Commons Lang SerializationUtils, json-io (legacy JsonReader.jsonToJava
// and modern JsonIo.toObjects/toJava), and Genson. Each verifies that a
// user-controlled value reaching the sink produces a CWE-502 flow.
// See GrrrDog/Java-Deserialization-Cheat-Sheet and github.com/mbechler/marshalsec.

func TestJavaDeser_CommonsSerializationUtils(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.lang3.SerializationUtils;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String p = request.getParameter("data");
        byte[] raw = p.getBytes();
        Object obj = SerializationUtils.deserialize(raw);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow: request.getParameter -> SerializationUtils.deserialize")
		logDeserFlows(t, flows)
	}
}

func TestJavaDeser_JsonIoJsonReader(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.cedarsoftware.util.io.JsonReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String json = request.getParameter("json");
        Object obj = JsonReader.jsonToJava(json);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow: request.getParameter -> JsonReader.jsonToJava")
		logDeserFlows(t, flows)
	}
}

func TestJavaDeser_JsonIoToObjects(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.cedarsoftware.io.JsonIo;
import com.cedarsoftware.io.ReadOptions;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String json = request.getParameter("json");
        Object obj = JsonIo.toObjects(json, new ReadOptions(), Object.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow: request.getParameter -> JsonIo.toObjects")
		logDeserFlows(t, flows)
	}
}

func TestJavaDeser_JsonIoToJava(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.cedarsoftware.io.JsonIo;
import com.cedarsoftware.io.ReadOptions;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String json = request.getParameter("json");
        Object obj = JsonIo.toJava(json, new ReadOptions()).asClass(Object.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow: request.getParameter -> JsonIo.toJava")
		logDeserFlows(t, flows)
	}
}

func TestJavaDeser_Genson(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.owlike.genson.Genson;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String json = request.getParameter("json");
        Genson genson = new Genson();
        Object obj = genson.deserialize(json, Object.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow: request.getParameter -> Genson.deserialize")
		logDeserFlows(t, flows)
	}
}

// Negative control: constant inputs must not produce a deserialization flow.
func TestJavaDeser_Safe_NoFlow(t *testing.T) {
	code := `
import org.apache.commons.lang3.SerializationUtils;
import com.cedarsoftware.util.io.JsonReader;
import com.owlike.genson.Genson;

public class Handler {
    public void run() {
        byte[] raw = "trusted".getBytes();
        Object a = SerializationUtils.deserialize(raw);
        Object b = JsonReader.jsonToJava("{\"k\":\"v\"}");
        Genson genson = new Genson();
        Object c = genson.deserialize("{\"k\":\"v\"}", Object.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialization flow for constant/literal inputs")
		logDeserFlows(t, flows)
	}
}

func logDeserFlows(t *testing.T, flows []taint.TaintFlow) {
	t.Helper()
	for _, f := range flows {
		t.Logf("  flow: %s -> %s [%s] (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
	}
}
