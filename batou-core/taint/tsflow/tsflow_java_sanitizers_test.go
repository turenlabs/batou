package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Java sanitizer tests — command injection prevention
// =========================================================================

func TestJava_ESAPI_EncodeForOS_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.esapi.ESAPI;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("input");
        String safe = encodeForOS(input);
        Runtime.getRuntime().exec("echo " + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("encodeForOS() should neutralize command injection taint")
	}
}

func TestJava_Command_Unsanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getParameter -> Runtime.exec")
	}
}

// =========================================================================
// Java sanitizer tests — log injection prevention
// =========================================================================

func TestJava_Log_CRLF_Replace_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Handler extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(Handler.class);
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("user");
        String safe = input.replace("\n", "").replace("\r", "");
        log.info("User login: " + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("CRLF replace() should neutralize log injection taint")
	}
}

func TestJava_Log_Unsanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Handler extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(Handler.class);
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("user");
        log.info("User login: " + input);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for getParameter -> log.info")
	}
}

// =========================================================================
// Java sanitizer tests — XXE prevention
// =========================================================================

func TestJava_XXE_SecureProcessing_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.parsers.*;
import javax.xml.XMLConstants;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(request.getInputStream());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("DocumentBuilderFactory.setFeature(FEATURE_SECURE_PROCESSING) should neutralize XXE taint")
	}
}

func TestJava_XXE_DisallowDoctype_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.parsers.*;

public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(request.getInputStream());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("DocumentBuilderFactory disallow-doctype-decl should neutralize XXE taint")
	}
}

// =========================================================================
// Java sanitizer tests — OWASP Encoder additional methods
// =========================================================================

func TestJava_OWASP_Encode_ForUri_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String url = request.getParameter("url");
        String safe = Encode.forUri(url);
        response.sendRedirect(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("Encode.forUri() should neutralize redirect taint")
	}
}

func TestJava_OWASP_Encode_ForXml_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("data");
        String safe = Encode.forXml(input);
        response.getWriter().println(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forXml() should neutralize HTML output taint")
	}
}

// =========================================================================
// Java sanitizer tests — header injection prevention
// =========================================================================

func TestJava_Spring_ResponseEntity_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.http.ResponseEntity;

public class Controller {
    public ResponseEntity<String> handle(HttpServletRequest request) {
        String value = request.getParameter("data");
        return ResponseEntity.ok(value);
    }
}
`
	flows := Analyze(code, "/app/Controller.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("ResponseEntity.ok() should neutralize header injection taint")
	}
}

// =========================================================================
// Java sanitizer tests — type coercion
// =========================================================================

func TestJava_Boolean_ParseBoolean_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Handler extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(Handler.class);
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String flag = request.getParameter("enabled");
        boolean enabled = Boolean.parseBoolean(flag);
        log.info("Feature enabled: " + enabled);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("Boolean.parseBoolean() should neutralize log injection taint")
	}
}

// =========================================================================
// Java sanitizer tests — Spring UriComponentsBuilder
// =========================================================================

func TestJava_Spring_UriComponentsBuilder_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.util.UriComponentsBuilder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("redirect");
        String safe = UriComponentsBuilder.fromUriString(target).build().toUriString();
        response.sendRedirect(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("UriComponentsBuilder.fromUriString() should neutralize redirect taint")
	}
}

// =========================================================================
// Java sanitizer tests — StringEscapeUtils.escapeJava for command
// =========================================================================

func TestJava_StringEscapeUtils_EscapeJava_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.text.StringEscapeUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("name");
        String safe = StringEscapeUtils.escapeJava(input);
        Runtime.getRuntime().exec("echo " + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("StringEscapeUtils.escapeJava() should neutralize command injection taint")
	}
}

// =========================================================================
// Java sanitizer tests — SSRF prevention (SnkURLFetch)
// =========================================================================

func TestJava_SSRF_Unsanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.net.URL;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("url");
        URL url = new URL(target);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParameter -> new URL")
	}
}

func TestJava_SSRF_URI_GetScheme_Sanitized(t *testing.T) {
	// getScheme() is a zero-arg receiver method. The taint engine checks
	// receiver taint: uri is tainted via propagation through parseUri(),
	// so the sanitizer fires and marks "scheme" as sanitized for URLFetch.
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("url");
        Object uri = parseUri(target);
        String scheme = uri.getScheme();
        response.sendRedirect(scheme);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("URI.getScheme() should neutralize redirect taint via protocol extraction")
	}
}

func TestJava_SSRF_URL_GetProtocol_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("url");
        Object url = parseUrl(target);
        String protocol = url.getProtocol();
        response.sendRedirect(protocol);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("URL.getProtocol() should neutralize redirect taint via protocol extraction")
	}
}

func TestJava_SSRF_URI_GetAuthority_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("url");
        Object uri = parseUri(target);
        String authority = uri.getAuthority();
        response.sendRedirect(authority);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("URI.getAuthority() should neutralize redirect taint via authority extraction")
	}
}

func TestJava_SSRF_Guava_InternetDomainName_Sanitized(t *testing.T) {
	// InternetDomainName.from() takes a tainted string as its argument.
	// The sanitizer fires because the first arg is tainted.
	code := `
import javax.servlet.http.*;
import com.google.common.net.InternetDomainName;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String host = request.getParameter("host");
        String validDomain = InternetDomainName.from(host).toString();
        URL url = new URL("https://" + validDomain);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("InternetDomainName.from() should neutralize SSRF taint via domain validation")
	}
}

// =========================================================================
// Java sanitizer tests — path traversal prevention (SnkFileWrite/SnkFileRead)
// =========================================================================

// Path.toRealPath() alone is NOT a sanitizer: it resolves
// "/uploads/../../etc/passwd" to "/etc/passwd" — a real path OUTSIDE the
// safe base; it does not reject escapes (the unsound java.path.torealpath
// entry was removed). The taint flow must survive. See the filepath.Clean
// note in go_sanitizers.go and the os.path.normpath/realpath note in
// python_sanitizers.go; only canonicalize + containment (e.g.
// real.startsWith(BASE_DIR)) is a defence.
func TestJava_Path_ToRealPath_NotASanitizer(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.nio.file.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filename = request.getParameter("file");
        Path path = Paths.get("/uploads", filename);
        Path real = path.toRealPath();
        Files.readAllBytes(real);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("Path.toRealPath() alone must NOT neutralize FileRead taint — expected the traversal flow to still fire")
	}
}

// Path.toAbsolutePath() only prepends the CWD — it does NOT resolve or strip
// `..` segments, so it is NOT a path-traversal sanitizer (the unsound
// java.path.toabsolutepath entry was removed). The tainted write must still fire.
func TestJava_Path_ToAbsolutePath_NotSanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.nio.file.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filename = request.getParameter("file");
        Path path = Paths.get("/uploads", filename);
        Path abs = path.toAbsolutePath();
        Files.write(abs, "data".getBytes());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("Path.toAbsolutePath() does NOT resolve `..`, so the tainted file write must still be detected")
	}
}

func TestJava_File_GetName_Sanitized(t *testing.T) {
	// Use a helper function to create the File object so that "new File()"
	// (which is itself a SnkFileWrite sink) doesn't fire first.
	code := `
import javax.servlet.http.*;
import java.io.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filename = request.getParameter("file");
        File file = parseFile(filename);
        String safeName = file.getName();
        new FileOutputStream("/uploads/" + safeName);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("File.getName() should neutralize path traversal taint by stripping directory")
	}
}

func TestJava_Path_Traversal_Unsanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filename = request.getParameter("file");
        new FileOutputStream("/uploads/" + filename);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path traversal flow for getParameter -> FileOutputStream")
	}
}

// =========================================================================
// Java sanitizer tests — SpEL injection prevention (SnkEval)
// =========================================================================

func TestJava_SpEL_SimpleEvaluationContext_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        SpelExpressionParser parser = new SpelExpressionParser();
        SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        parser.parseExpression(expr).getValue(context);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("SimpleEvaluationContext.forReadOnlyDataBinding() should neutralize SpEL eval taint")
	}
}

// =========================================================================
// Java sanitizer tests — OWASP Encode.forJava (log/header/eval prevention)
// =========================================================================

func TestJava_OWASP_Encode_ForJava_Log_Sanitized(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Handler extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(Handler.class);
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("user");
        String safe = Encode.forJava(input);
        log.info("User login: " + safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("Encode.forJava() should neutralize log injection taint")
	}
}

// =========================================================================
// Java sanitizer tests — LDAP injection prevention (CWE-90)
// =========================================================================

func TestJava_LDAP_Sanitized_UnboundID_EncodeValue(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;
import com.unboundid.ldap.sdk.Filter;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String safe = Filter.encodeValue(user);
        String filter = "(uid=" + safe + ")";
        InitialDirContext ctx = new InitialDirContext();
        ctx.search("ou=users", filter, null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("Filter.encodeValue() should neutralize LDAP injection taint")
	}
}

func TestJava_LDAP_Sanitized_SpringLdapNameBuilder(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.ldap.support.LdapNameBuilder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String ou = request.getParameter("ou");
        javax.naming.ldap.LdapName dn = LdapNameBuilder.newInstance("dc=example,dc=com").add("ou", ou).build();
        InitialDirContext ctx = new InitialDirContext();
        ctx.search(dn.toString(), "(objectClass=*)", null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("LdapNameBuilder.newInstance() should neutralize LDAP injection taint")
	}
}

func TestJava_LDAP_Sanitized_SpringLdapUtils(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;
import org.springframework.ldap.support.LdapUtils;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String dn = request.getParameter("dn");
        javax.naming.ldap.LdapName safeDn = LdapUtils.newLdapName(dn);
        InitialDirContext ctx = new InitialDirContext();
        ctx.search(safeDn.toString(), "(objectClass=*)", null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("LdapUtils.newLdapName() should neutralize LDAP injection taint")
	}
}

func TestJava_LDAP_Sanitized_SpringNameEncode(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;
import org.springframework.ldap.support.LdapEncoder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String cn = request.getParameter("cn");
        String safeCn = LdapEncoder.nameEncode(cn);
        String dn = "cn=" + safeCn + ",ou=users,dc=example,dc=com";
        InitialDirContext ctx = new InitialDirContext();
        ctx.search(dn, "(objectClass=*)", null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("LdapEncoder.nameEncode() should neutralize LDAP injection taint")
	}
}

func TestJava_LDAP_Sanitized_ApacheEncodeFilterValue(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;
import org.apache.directory.api.ldap.model.filter.FilterEncoder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String safe = FilterEncoder.encodeFilterValue(user);
        String filter = "(uid=" + safe + ")";
        InitialDirContext ctx = new InitialDirContext();
        ctx.search("ou=users", filter, null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("FilterEncoder.encodeFilterValue() should neutralize LDAP injection taint")
	}
}

func TestJava_LDAP_Sanitized_ApacheFilterBuilder(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;
import org.apache.directory.ldap.client.api.search.FilterBuilder;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String filter = FilterBuilder.equal("uid", user).toString();
        InitialDirContext ctx = new InitialDirContext();
        ctx.search("ou=users", filter, null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("FilterBuilder.equal() should neutralize LDAP injection taint")
	}
}

func TestJava_LDAP_Sanitized_RdnConstructor(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.naming.directory.*;
import javax.naming.ldap.Rdn;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String cn = request.getParameter("cn");
        Rdn rdn = new Rdn("cn", cn);
        String dn = rdn.toString() + ",ou=users,dc=example,dc=com";
        InitialDirContext ctx = new InitialDirContext();
        ctx.search(dn, "(objectClass=*)", null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("new Rdn() constructor should neutralize LDAP injection taint")
	}
}

func TestJava_LDAP_Unsanitized_DirectConcat(t *testing.T) {
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
		t.Error("expected LDAP injection flow for unsanitized getParameter -> ctx.search")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// =========================================================================
// Java SpEL + OGNL sink tests (CVE-2022-22963 / CVE-2017-5638 catalog gaps)
// =========================================================================

func TestJava_SpEL_ParseExpression_Tainted(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getHeader("X-Expr");
        SpelExpressionParser parser = new SpelExpressionParser();
        parser.parseExpression(expr);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SpEL code-eval flow for getHeader -> parser.parseExpression (CVE-2022-22963 shape)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_OGNL_GetValue_Tainted(t *testing.T) {
	code := `
import javax.servlet.http.*;
import ognl.Ognl;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getHeader("Content-Type");
        Ognl.getValue(expr, new java.util.HashMap<>(), new Object());
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected OGNL code-eval flow for getHeader -> Ognl.getValue (CVE-2017-5638 shape)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_OGNL_BareGetValue_NotFired(t *testing.T) {
	// Bare `.getValue()` on a non-OGNL receiver (e.g. JsonNode, Optional, Map)
	// must NOT fire as OGNL eval. The RequireModule constraint on the Ognl
	// sink anchors to the "Ognl" receiver class.
	code := `
import javax.servlet.http.*;
import java.util.Optional;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String key = request.getParameter("key");
        Optional<String> opt = Optional.ofNullable(key);
        String result = opt.getValue();
        response.getWriter().write(result);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.MethodName == "Ognl.getValue" {
			t.Errorf("Optional.getValue() must not fire as OGNL eval sink")
		}
	}
}

// =========================================================================
// Java receiver-state hardening tests (XStream + DocumentBuilderFactory)
// =========================================================================

func TestJava_XStream_AllowTypes_Sanitizes(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.io.InputStream body = request.getInputStream();
        XStream xs = new XStream();
        xs.addPermission(NoTypePermission.NONE);
        xs.allowTypes(new Class[]{String.class});
        Object o = xs.fromXML(body);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("XStream.allowTypes(...) on the same receiver should neutralize fromXML SnkDeserialize")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s on %s", f.Source.Category, f.Sink.Category, f.Sink.MethodName)
		}
	}
}

func TestJava_XStream_NoHardening_FiresSink(t *testing.T) {
	// Negative: without allowTypes/addPermission the SnkDeserialize must fire.
	code := `
import javax.servlet.http.*;
import com.thoughtworks.xstream.XStream;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.io.InputStream body = request.getInputStream();
        XStream xs = new XStream();
        Object o = xs.fromXML(body);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow on unhardened XStream.fromXML")
	}
}

func TestJava_DocumentBuilderFactory_DisableDoctype_Sanitizes(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.io.InputStream body = request.getInputStream();
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(body);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkXPath {
			t.Errorf("DocumentBuilderFactory hardened with disallow-doctype-decl must not fire SnkXPath: %s", f.Sink.MethodName)
		}
	}
}

// =========================================================================
// Java SSRF body-scope allowlist suppression
// =========================================================================

func TestJava_SSRF_HostAllowlist_Suppresses(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.net.URI;
import java.util.Set;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.*;

public class Handler extends HttpServlet {
    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String raw = request.getParameter("url");
        URI uri = URI.create(raw);
        String host = uri.getHost();
        if (host == null || !ALLOWED_HOSTS.contains(host)) {
            response.sendError(403);
            return;
        }
        CloseableHttpClient client = HttpClients.createDefault();
        client.execute(new HttpGet(uri));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Errorf("SSRF host-allowlist guard in body must suppress SnkURLFetch: %s", f.Sink.MethodName)
		}
	}
}

func TestJava_SSRF_NoGuard_FiresSink(t *testing.T) {
	// Negative: without the allowlist guard the SnkURLFetch must fire.
	code := `
import javax.servlet.http.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String url = request.getParameter("url");
        CloseableHttpClient client = HttpClients.createDefault();
        client.execute(new HttpGet(url));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SnkURLFetch flow on unguarded HttpGet")
	}
}
