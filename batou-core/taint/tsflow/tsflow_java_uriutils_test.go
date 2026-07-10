package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Spring UriUtils component percent-encoders +
// OWASP Java Encoder forJavaScriptSource / forXmlComment / forCDATA.
//
// UriUtils (org.springframework.web.util.UriUtils) percent-encodes user
// input embedded into a constructed URL, neutralizing CR/LF header
// injection and open-redirect breakout. It is the Spring analog of
// URLEncoder.encode / Encode.forUriComponent.
//
// The three OWASP Encoder methods complete the Encode.* family alongside
// the existing forJavaScript*/forXml*/forCDATA-less entries.
//
// Each sanitized test is paired with an unsanitized control proving the
// source -> sink flow exists when the encoder is absent, so the sanitized
// assertion genuinely exercises the new catalog entry.
// =========================================================================

// ---- Spring UriUtils: redirect (open redirect / header injection) ----

func TestJava_Spring_UriUtils_Encode_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.UriUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        String safe = UriUtils.encode(next, "UTF-8");
        response.sendRedirect("/go?to=" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("UriUtils.encode() should neutralize redirect taint")
	}
}

func TestJava_Spring_UriUtils_EncodePath_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.UriUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        String safe = UriUtils.encodePath(next, "UTF-8");
        response.sendRedirect("/files/" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("UriUtils.encodePath() should neutralize redirect taint")
	}
}

func TestJava_Spring_UriUtils_EncodePathSegment_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.UriUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        String safe = UriUtils.encodePathSegment(next, "UTF-8");
        response.sendRedirect("/files/" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("UriUtils.encodePathSegment() should neutralize redirect taint")
	}
}

func TestJava_Spring_UriUtils_EncodeQuery_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.UriUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        String safe = UriUtils.encodeQuery(next, "UTF-8");
        response.sendRedirect("/go?" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("UriUtils.encodeQuery() should neutralize redirect taint")
	}
}

func TestJava_Spring_UriUtils_EncodeQueryParam_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.UriUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        String safe = UriUtils.encodeQueryParam(next, "UTF-8");
        response.sendRedirect("/go?to=" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("UriUtils.encodeQueryParam() should neutralize redirect taint")
	}
}

func TestJava_Spring_UriUtils_EncodeFragment_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.UriUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        String safe = UriUtils.encodeFragment(next, "UTF-8");
        response.sendRedirect("/go#" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("UriUtils.encodeFragment() should neutralize redirect taint")
	}
}

func TestJava_Spring_UriUtils_Unsanitized_Control(t *testing.T) {
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

// ---- OWASP Encoder: forJavaScriptSource (string-literal in <script>, XSS) ----

func TestJava_OWASP_Encode_ForJavaScriptSource_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safe = Encode.forJavaScriptSource(name);
        response.getWriter().println("<script>var n = '" + safe + "';</script>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forJavaScriptSource() should neutralize HTML output taint")
	}
}

// ---- OWASP Encoder: forXmlComment (inside <!-- --> XML comments) ----

func TestJava_OWASP_Encode_ForXmlComment_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String note = request.getParameter("note");
        String safe = Encode.forXmlComment(note);
        response.getWriter().println("<!-- " + safe + " -->");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forXmlComment() should neutralize HTML output taint")
	}
}

// ---- OWASP Encoder: forCDATA (inside <![CDATA[ ]]> sections) ----

func TestJava_OWASP_Encode_ForCDATA_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String data = request.getParameter("data");
        String safe = Encode.forCDATA(data);
        response.getWriter().println("<![CDATA[" + safe + "]]>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forCDATA() should neutralize HTML output taint")
	}
}

func TestJava_OWASP_Encode_XmlContexts_Unsanitized_Control(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String data = request.getParameter("data");
        response.getWriter().println("<![CDATA[" + data + "]]>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("control: expected HTML output flow for unsanitized getParameter -> println")
	}
}
