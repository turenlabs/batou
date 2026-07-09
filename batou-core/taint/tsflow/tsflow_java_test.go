package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Command Injection (CWE-78) ---

func TestJava_CommandInjection_RuntimeExec(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getParameter -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_CommandInjection_ProcessBuilder(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String prog = request.getParameter("program");
        ProcessBuilder pb = new ProcessBuilder(prog);
        pb.start();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getParameter -> ProcessBuilder")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_CommandInjection_Sanitized_Allowlist(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.util.*;

public class Handler extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("ls", "pwd", "date");
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String cmd = request.getParameter("cmd");
        if (ALLOWED.contains(cmd)) {
            Runtime.getRuntime().exec(cmd);
        }
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO command injection flow when validated by allowlist")
	}
}

// --- XSS / HTML Output (CWE-79) ---

func TestJava_XSS_PrintWriter(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        response.getWriter().println("<h1>Hello " + name + "</h1>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for getParameter -> response.getWriter().println")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_XSS_Sanitized_HtmlEscape(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;
import org.springframework.web.util.HtmlUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        String safe = HtmlUtils.htmlEscape(name);
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + safe + "</h1>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO XSS flow when sanitized by HtmlUtils.htmlEscape")
	}
}

// --- Path Traversal / File Read (CWE-22) ---

func TestJava_FileRead_FileInputStream(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");
        FileInputStream fis = new FileInputStream(filename);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	// FileInputStream is categorized as SnkFileWrite in the catalog (path traversal)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file path traversal flow for getParameter -> new FileInputStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_FileRead_NioFiles(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.nio.file.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String path = request.getParameter("path");
        byte[] data = Files.readAllBytes(Paths.get(path));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for getParameter -> Files.readAllBytes")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// File.getCanonicalPath() alone is NOT a sanitizer: it resolves
// "../../etc/passwd" to "/etc/passwd" — a real path OUTSIDE the safe base;
// it does not reject escapes. The taint flow must survive. (This test
// previously asserted the opposite, which was unsound — see the
// filepath.Clean note in go_sanitizers.go and the os.path.normpath/realpath
// note in python_sanitizers.go; only canonicalize + containment, e.g.
// canonical.startsWith(BASE_DIR), is a defence.)
func TestJava_FileRead_CanonicalPath_NotASanitizer(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");
        File f = new File(filename);
        String safe = f.getCanonicalPath();
        FileInputStream fis = new FileInputStream(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	// Assert on the FileInputStream sink specifically: the `new File(...)`
	// constructor is itself a (file_write-categorised) sink that fires
	// before the canonicalize call, so a bare category check would be
	// vacuous. The FileInputStream flow is the one the old sanitizer entry
	// used to suppress.
	found := false
	for _, f := range flows {
		if f.Sink.MethodName == "FileInputStream" {
			found = true
		}
	}
	if !found {
		t.Error("getCanonicalPath() alone must NOT neutralize file taint — expected the FileInputStream flow to still fire")
	}
}

// --- File Write (CWE-73) ---

func TestJava_FileWrite(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String path = request.getParameter("path");
        String content = request.getParameter("content");
        FileWriter fw = new FileWriter(path);
        fw.write(content);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for getParameter -> FileWriter")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- SSRF / URL Fetch (CWE-918) ---

func TestJava_SSRF_HttpURLConnection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.net.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("url");
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> URL -> openConnection")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_SSRF_RestTemplate(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.client.RestTemplate;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String target = request.getParameter("url");
        RestTemplate restTemplate = new RestTemplate();
        String result = restTemplate.getForObject(target, String.class);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> RestTemplate.getForObject")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Open Redirect (CWE-601) ---

func TestJava_OpenRedirect(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("redirect");
        response.sendRedirect(target);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for getParameter -> sendRedirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- LDAP Injection (CWE-90) ---

func TestJava_LDAPInjection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String filter = "(uid=" + user + ")";
        InitialDirContext ctx = new InitialDirContext();
        ctx.search("ou=users", filter, null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for getParameter -> ctx.search")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Log Injection (CWE-117) ---

func TestJava_LogInjection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Handler extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(Handler.class);
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String user = request.getParameter("username");
        logger.info("Login attempt for user: " + user);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getParameter -> logger.info")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Eval / Code Injection (CWE-94) ---

func TestJava_ScriptEngineEval(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.script.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expression");
        ScriptEngine scriptEngine = new ScriptEngineManager().getEngineByName("js");
        scriptEngine.eval(expr);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> ScriptEngine.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Template Injection / SSTI (CWE-94) ---

func TestJava_TemplateInjection_Freemarker(t *testing.T) {
	code := `
import javax.servlet.http.*;
import freemarker.template.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tmpl = request.getParameter("template");
        Template template = new Template("test", tmpl, null);
        template.process(null, response.getWriter());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for getParameter -> Template.process")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Header Injection (CWE-113) ---

func TestJava_HeaderInjection(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String value = request.getParameter("lang");
        response.setHeader("Content-Language", value);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getParameter -> response.setHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_HeaderInjection_AddHeader(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String redirect = request.getParameter("url");
        response.addHeader("Location", redirect);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getParameter -> response.addHeader")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Trust Boundary Violation (CWE-501) ---

func TestJava_TrustBoundary_SessionAttribute(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String role = request.getParameter("role");
        HttpSession session = request.getSession();
        session.setAttribute("userRole", role);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary violation for getParameter -> session.setAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TrustBoundary_SessionPutValue(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String data = request.getParameter("data");
        HttpSession session = request.getSession();
        session.putValue("userData", data);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary violation for getParameter -> session.putValue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- XPath Injection (CWE-643) ---

func TestJava_XPathInjection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.xpath.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "//users/user[@name='" + user + "']";
        xpath.evaluate(expr, doc);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XPath injection flow for getParameter -> xpath.evaluate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Weak Crypto (CWE-327/328) ---

func TestJava_WeakCrypto_VariableAlgorithm(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.security.MessageDigest;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String algo = request.getParameter("algorithm");
        MessageDigest md = MessageDigest.getInstance(algo);
        byte[] hash = md.digest("data".getBytes());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for getParameter -> MessageDigest.getInstance(variable)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- XXE (CWE-611) ---

func TestJava_XXE_DocumentBuilder(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        documentBuilder.parse(new InputSource(new StringReader(xml)));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	// DocumentBuilder.parse is categorized as SnkXPath (CWE-611 XXE)
	if !hasTaintFlow(flows, taint.SnkXPath) {
		t.Error("expected XXE flow for getParameter -> DocumentBuilder.parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JNDI Injection (CWE-074) ---

func TestJava_JNDIInjection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("resource");
        InitialContext ctx = new InitialContext();
        ctx.lookup(name);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected JNDI injection flow for getParameter -> InitialContext.lookup")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spring-specific sources ---

func TestJava_Spring_RequestParam_SQLInjection(t *testing.T) {
	code := `
import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
public class UserController {
    @GetMapping("/users")
    public String getUser(@RequestParam String name, Connection conn) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/UserController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for @RequestParam -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Spring_PathVariable_CommandInjection(t *testing.T) {
	code := `
import org.springframework.web.bind.annotation.*;

@RestController
public class AdminController {
    @GetMapping("/exec/{cmd}")
    public String exec(@PathVariable String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/AdminController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for @PathVariable -> Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Sanitized flows (should produce NO findings) ---

func TestJava_SQL_Sanitized_PreparedStatement(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.sql.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when using PreparedStatement")
	}
}

func TestJava_XSS_Sanitized_OWASPEncode(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        String safe = Encode.forHtml(name);
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + safe + "</h1>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected NO XSS flow when sanitized by OWASP Encode.forHtml")
	}
}

func TestJava_LDAP_Sanitized_SpringEncoder(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;
import org.springframework.ldap.support.LdapEncoder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String safe = LdapEncoder.filterEncode(user);
        String filter = "(uid=" + safe + ")";
        InitialDirContext ctx = new InitialDirContext();
        ctx.search("ou=users", filter, null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected NO LDAP injection flow when sanitized by LdapEncoder.filterEncode")
	}
}

// --- JAX-RS sources ---

func TestJava_JAXRS_QueryParam_SQLInjection(t *testing.T) {
	code := `
import javax.ws.rs.*;
import java.sql.*;

@Path("/users")
public class UserResource {
    @GET
    public String getUser(@QueryParam("name") String name) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/UserResource.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for @QueryParam -> executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Multi-hop taint propagation ---

func TestJava_MultiHop_Reassignment(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("cmd");
        String a = input;
        String b = a;
        String c = b;
        Runtime.getRuntime().exec(c);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection through multi-hop variable reassignment")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Reflection-based code execution ---

func TestJava_Reflection_ClassForName(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String className = request.getParameter("class");
        Class.forName(className);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> Class.forName (arbitrary class loading)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Spring / JAX-RS Open Redirect (CWE-601) ---

func TestJava_OpenRedirect_SpringRedirectView(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.servlet.view.RedirectView;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("next");
        RedirectView rv = new RedirectView(url);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for getParameter -> new RedirectView")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_OpenRedirect_JAXRSSeeOther(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.ws.rs.core.Response;
import java.net.URI;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("url");
        Response.seeOther(new URI(target));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for getParameter -> Response.seeOther")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_OpenRedirect_JAXRSTemporaryRedirect(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.ws.rs.core.Response;
import java.net.URI;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("returnUrl");
        Response.temporaryRedirect(new URI(target));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for getParameter -> Response.temporaryRedirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_OpenRedirect_SpringHttpHeadersSetLocation(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.http.HttpHeaders;
import java.net.URI;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("redirect");
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(new URI(target));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for getParameter -> HttpHeaders.setLocation")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_OpenRedirect_SpringResponseEntityCreated(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.http.ResponseEntity;
import java.net.URI;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String location = request.getParameter("location");
        ResponseEntity.created(new URI(location));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for getParameter -> ResponseEntity.created")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Template Injection / SSTI (CWE-1336) — additional engines ---

func TestJava_TemplateInjection_Thymeleaf(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

public class Handler extends HttpServlet {
    private TemplateEngine templateEngine = new TemplateEngine();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String page = request.getParameter("page");
        Context ctx = new Context();
        String result = templateEngine.process(page, ctx);
        response.getWriter().write(result);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for getParameter -> TemplateEngine.process (Thymeleaf)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TemplateInjection_Handlebars(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.github.jknack.handlebars.Handlebars;
import com.github.jknack.handlebars.Template;

public class Handler extends HttpServlet {
    private Handlebars handlebars = new Handlebars();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tmpl = request.getParameter("template");
        Template template = handlebars.compile(tmpl);
        String result = template.apply(null);
        response.getWriter().write(result);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for getParameter -> Handlebars.compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TemplateInjection_Mustache(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.MustacheFactory;
import com.github.mustachejava.Mustache;

public class Handler extends HttpServlet {
    private MustacheFactory mustacheFactory = new DefaultMustacheFactory();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String tmpl = request.getParameter("template");
        Mustache mustache = mustacheFactory.compile(tmpl);
        mustache.execute(response.getWriter(), null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for getParameter -> MustacheFactory.compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_TemplateInjection_JTE(t *testing.T) {
	code := `
import javax.servlet.http.*;
import gg.jte.TemplateEngine;
import gg.jte.output.StringOutput;

public class Handler extends HttpServlet {
    private TemplateEngine templateEngine = TemplateEngine.createPrecompiled(null);
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String page = request.getParameter("page");
        StringOutput output = new StringOutput();
        templateEngine.render(page, null, output);
        response.getWriter().write(output.toString());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for getParameter -> TemplateEngine.render (JTE)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe redirect (sanitized) ---

func TestJava_OpenRedirect_Safe_UriComponentsBuilder(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.servlet.view.RedirectView;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("next");
        String safe = UriComponentsBuilder.fromUriString(url).build().toUriString();
        RedirectView rv = new RedirectView(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected NO redirect flow when URL is sanitized via UriComponentsBuilder")
	}
}
