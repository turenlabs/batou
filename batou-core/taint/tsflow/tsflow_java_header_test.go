package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- JAX-RS Response builder header injection (CWE-113) ---

func TestJava_HeaderInjection_JAXRSResponseBuilder(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.ws.rs.*;
import javax.ws.rs.core.*;

@Path("/api")
public class ApiResource {
    @GET
    public Response getUser(@QueryParam("token") String token) {
        return Response.ok("data").header("X-Auth-Token", token).build();
    }
}
`
	flows := Analyze(code, "/app/ApiResource.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for @QueryParam -> Response.ok().header()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_HeaderInjection_JAXRSResponseStatus(t *testing.T) {
	code := `
import javax.ws.rs.*;
import javax.ws.rs.core.*;

@Path("/api")
public class ApiResource {
    @GET
    public Response redirect(@QueryParam("url") String url) {
        return Response.status(302).header("Location", url).build();
    }
}
`
	flows := Analyze(code, "/app/ApiResource.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for @QueryParam -> Response.status().header()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spark Java response header injection (CWE-113) ---

func TestJava_HeaderInjection_SparkFramework(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getParameter("origin");
        response.header("Access-Control-Allow-Origin", origin);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getParameter -> response.header()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- HttpURLConnection request header injection (CWE-113) ---

func TestJava_HeaderInjection_HttpURLConnection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.net.*;

public class ProxyServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String forwardedFor = request.getParameter("ip");
        URL url = new URL("http://internal-api/data");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("X-Forwarded-For", forwardedFor);
        conn.getInputStream();
    }
}
`
	flows := Analyze(code, "/app/ProxyServlet.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getParameter -> setRequestProperty()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JavaMail MimeMessage header injection (CWE-93) ---

func TestJava_HeaderInjection_JavaMailMimeMessage(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.mail.*;
import javax.mail.internet.*;

public class MailServlet extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String replyTo = request.getParameter("replyTo");
        MimeMessage mimeMessage = new MimeMessage(null);
        mimeMessage.setHeader("Reply-To", replyTo);
        Transport.send(mimeMessage);
    }
}
`
	flows := Analyze(code, "/app/MailServlet.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getParameter -> mimeMessage.setHeader()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Servlet with alternate variable names (CWE-113) ---

func TestJava_HeaderInjection_ServletAlternateVarName(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String token = req.getParameter("token");
        resp.setHeader("X-Auth-Token", token);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getParameter -> resp.setHeader()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: sanitized header value (no flow expected) ---

func TestJava_HeaderInjection_Safe_URLEncoded(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.net.URLEncoder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String value = request.getParameter("value");
        String safe = URLEncoder.encode(value, "UTF-8");
        response.setHeader("X-Custom", safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected NO header injection flow when value is URL-encoded")
	}
}

func TestJava_HeaderInjection_Safe_SpringResponseCookie(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.http.ResponseCookie;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String value = request.getParameter("pref");
        ResponseCookie cookie = ResponseCookie.from("pref", value).build();
        response.addHeader("Set-Cookie", cookie.toString());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected NO header injection flow when cookie built via ResponseCookie.from()")
	}
}

func TestJava_HeaderInjection_Safe_CommonsTextEscapeJava(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.text.StringEscapeUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String value = request.getParameter("value");
        String safe = StringEscapeUtils.escapeJava(value);
        response.setHeader("X-Custom", safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected NO header injection flow when value is escaped via StringEscapeUtils.escapeJava()")
	}
}
