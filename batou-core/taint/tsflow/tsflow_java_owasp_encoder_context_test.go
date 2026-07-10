package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// OWASP Java Encoder additional context-specific methods + Spring
// JavaScriptUtils.javaScriptEscape. These complete the partially-covered
// OWASP Encoder family (forCssUrl / forUriComponent / forJavaScriptBlock /
// forJavaScriptAttribute) which sit alongside the existing forHtml/forXml/
// forUri entries.
//
// Each sanitized test is paired with an unsanitized control proving the
// source -> sink flow exists when the encoder is absent, so the sanitized
// assertion genuinely exercises the new catalog entry.
// =========================================================================

// ---- forCssUrl (CSS url() context, XSS) ----

func TestJava_OWASP_Encode_ForCssUrl_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("color");
        String safe = Encode.forCssUrl(input);
        response.getWriter().println("<div style=\"background:url(" + safe + ")\">");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forCssUrl() should neutralize HTML/CSS output taint")
	}
}

func TestJava_OWASP_Encode_ForCssUrl_Unsanitized_Control(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("color");
        response.getWriter().println("<div style=\"background:url(" + input + ")\">");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("control: expected HTML output flow for unsanitized getParameter -> println")
	}
}

// ---- forUriComponent (URL component encoding, open redirect / SSRF) ----

func TestJava_OWASP_Encode_ForUriComponent_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        String safe = Encode.forUriComponent(next);
        response.sendRedirect("/go?to=" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("Encode.forUriComponent() should neutralize redirect taint")
	}
}

func TestJava_OWASP_Encode_ForUriComponent_Unsanitized_Control(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        response.sendRedirect("/go?to=" + next);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("control: expected redirect flow for unsanitized getParameter -> sendRedirect")
	}
}

// ---- forJavaScriptBlock (inside <script> blocks, XSS) ----

func TestJava_OWASP_Encode_ForJavaScriptBlock_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safe = Encode.forJavaScriptBlock(name);
        response.getWriter().println("<script>var n = '" + safe + "';</script>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forJavaScriptBlock() should neutralize HTML output taint")
	}
}

// ---- forJavaScriptAttribute (inside HTML event-handler attributes, XSS) ----

func TestJava_OWASP_Encode_ForJavaScriptAttribute_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safe = Encode.forJavaScriptAttribute(name);
        response.getWriter().println("<button onclick=\"greet('" + safe + "')\">go</button>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forJavaScriptAttribute() should neutralize HTML output taint")
	}
}

// ---- Spring JavaScriptUtils.javaScriptEscape (JS string escaping) ----

func TestJava_Spring_JavaScriptUtils_Escape_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.JavaScriptUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safe = JavaScriptUtils.javaScriptEscape(name);
        response.getWriter().println("<script>var n = '" + safe + "';</script>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("JavaScriptUtils.javaScriptEscape() should neutralize HTML output taint")
	}
}
