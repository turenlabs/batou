package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
)

func TestFPESAPIEncodeForHTML(t *testing.T) {
	code := `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Test extends javax.servlet.http.HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("Test");
        String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
        response.setHeader("X-XSS-Protection", "0");
        response.getWriter().println(bar);
    }
}
`
	flows := Analyze(code, "/app/Test.java", rules.LangJava)
	t.Logf("ESAPI encodeForHTML flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
	}
	if len(flows) > 0 {
		t.Errorf("Expected 0 flows after ESAPI HTML encoding, got %d", len(flows))
	}
}

func TestFPSanitizerInterproc(t *testing.T) {
	// doSomething calls encodeForHTML internally and returns sanitized value.
	// XSS sink should NOT fire, but SQLi sink (if present) SHOULD fire because
	// encodeForHTML only neutralizes SnkHTMLOutput, not SnkSQLQuery.
	code := `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Test extends javax.servlet.http.HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("Test");
        String bar = doSomething(param);
        response.getWriter().println(bar);
    }

    private static String doSomething(String val) {
        return org.owasp.esapi.ESAPI.encoder().encodeForHTML(val);
    }
}
`
	flows := Analyze(code, "/app/Test.java", rules.LangJava)
	t.Logf("Interproc sanitizer flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s (CWE=%s) conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Sink.CWEID, f.Confidence)
	}
	// XSS flows should be eliminated (encodeForHTML neutralizes html_output).
	for _, f := range flows {
		if f.Sink.CWEID == "CWE-79" {
			t.Errorf("Should NOT have XSS flow after interprocedural HTML encoding, got sink=%s", f.Sink.ID)
		}
	}
}

func TestFPEscapeHtml(t *testing.T) {
	code := `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Test extends javax.servlet.http.HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("Test");
        String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);
        response.setHeader("X-XSS-Protection", "0");
        response.getWriter().println(bar);
    }
}
`
	flows := Analyze(code, "/app/Test.java", rules.LangJava)
	t.Logf("escapeHtml flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
	}
	if len(flows) > 0 {
		t.Errorf("Expected 0 flows after escapeHtml, got %d", len(flows))
	}
}
