package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Java Guava + Apache Commons Text sanitizer parity tests
//
// Java had no Guava HtmlEscapers / UrlEscapers entry and no Apache Commons
// Text escapeJson / escapeXml11 entries. Kotlin (kotlin.guava.htmlescapers,
// kotlin.guava.urlescapers, kotlin.apache.stringescapeutils.escapejson,
// kotlin.apache.stringescapeutils.escapexml11) and Groovy (matching set)
// already cover these via merged PRs.
//
// All four entries use a class-name ObjectType (HtmlEscapers / UrlEscapers /
// StringEscapeUtils) so the tsflow matcher requires the receiver chain to
// contain the class name — generic `.escape(`/`.escapeJson(` calls on
// unrelated objects do NOT fire the sanitizer.
// =========================================================================

func TestJava_GuavaCommonsText_SanitizersRegistered(t *testing.T) {
	cat := taint.GetCatalog(rules.LangJava)
	if cat == nil {
		t.Fatal("Java catalog not loaded")
	}
	want := []string{
		"java.guava.htmlescapers",
		"java.guava.urlescapers",
		"java.commons.text.stringescapeutils.escapejson",
		"java.commons.text.stringescapeutils.escapexml11",
	}
	found := map[string]bool{}
	for _, s := range cat.Sanitizers() {
		found[s.ID] = true
	}
	for _, id := range want {
		if !found[id] {
			t.Errorf("missing expected sanitizer: %s", id)
		}
	}
}

// --- Guava HtmlEscapers (XSS via response.getWriter().println) ---

func TestJava_GuavaHtmlEscapers_NeutralizesXSS(t *testing.T) {
	code := `
import com.google.common.html.HtmlEscapers;
import javax.servlet.http.*;

public class Handler {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safe = HtmlEscapers.htmlEscaper().escape(name);
        response.getWriter().println("<h1>Hello " + safe + "</h1>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-conf XSS flow when HtmlEscapers.htmlEscaper().escape() sanitizes input, got conf %.2f (%s -> %s)", f.Confidence, f.Source.ID, f.Sink.ID)
		}
	}
}

// Negative control — without the sanitizer the same code MUST flag.
func TestJava_GuavaHtmlEscapers_NegativeControl(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        response.getWriter().println("<h1>Hello " + name + "</h1>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow when no sanitizer is applied (negative control)")
	}
}

// --- Guava UrlEscapers (SSRF / open redirect) ---

func TestJava_GuavaUrlEscapers_PathSegment_NeutralizesRedirect(t *testing.T) {
	code := `
import com.google.common.net.UrlEscapers;
import javax.servlet.http.*;

public class Handler {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String dest = request.getParameter("dest");
        String safe = UrlEscapers.urlPathSegmentEscaper().escape(dest);
        response.sendRedirect("/items/" + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.5 {
			t.Errorf("expected no high-conf redirect flow when UrlEscapers.urlPathSegmentEscaper().escape() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestJava_GuavaUrlEscapers_FormParameter_NeutralizesURLFetch(t *testing.T) {
	code := `
import com.google.common.net.UrlEscapers;
import java.net.URL;
import javax.servlet.http.*;

public class Handler {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        String safe = UrlEscapers.urlFormParameterEscaper().escape(q);
        URL u = new URL("https://api.example.com/search?q=" + safe);
        u.openStream();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Errorf("expected no high-conf URL-fetch flow when UrlEscapers.urlFormParameterEscaper().escape() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- Apache Commons Text escapeJson ---

func TestJava_CommonsText_EscapeJson_NeutralizesXSS(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils;
import javax.servlet.http.*;

public class Handler {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safe = StringEscapeUtils.escapeJson(name);
        response.getWriter().println("{\"name\":\"" + safe + "\"}");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-conf XSS flow when StringEscapeUtils.escapeJson() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- Apache Commons Text escapeXml11 ---

func TestJava_CommonsText_EscapeXml11_NeutralizesXSS(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils;
import javax.servlet.http.*;

public class Handler {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        String safe = StringEscapeUtils.escapeXml11(name);
        response.getWriter().println("<user>" + safe + "</user>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-conf XSS flow when StringEscapeUtils.escapeXml11() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- Receiver-scoping check: a non-Guava .escape() call must NOT be
// treated as the Guava sanitizer (over-broadness regression). The Java
// matcher requires the receiver chain to contain "HtmlEscapers"; an
// unrelated object's .escape() should fall through to no sanitizer.
func TestJava_GuavaHtmlEscapers_DoesNotMatchUnrelatedEscape(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        // Some random user-defined builder with a method also called escape().
        // This must NOT be treated as a sanitizer (different class, not Guava).
        MyOwnBuilder b = new MyOwnBuilder();
        String fake = b.escape(name);
        response.getWriter().println("<h1>" + fake + "</h1>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow to STILL fire when a non-Guava .escape() was used (sanitizer must be receiver-scoped)")
	}
}
