package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Quarkus RESTEasy Reactive: @RestQuery -> SQL injection (CWE-89) ---

func TestJava_Quarkus_RestQuery_SQLInjection(t *testing.T) {
	code := `
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import org.jboss.resteasy.reactive.RestQuery;
import java.sql.Connection;

@Path("/users")
public class UserResource {
    Connection conn;
    @GET
    public String search(@RestQuery String name) {
        conn.prepareStatement("SELECT * FROM users WHERE name = '" + name + "'");
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/UserResource.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for @RestQuery -> prepareStatement()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Quarkus @RestPath -> Command injection (CWE-78) ---

func TestJava_Quarkus_RestPath_CommandInjection(t *testing.T) {
	code := `
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import org.jboss.resteasy.reactive.RestPath;

@Path("/files/{filename}")
public class FileResource {
    @GET
    public String get(@RestPath String filename) {
        Runtime.getRuntime().exec("cat /data/" + filename);
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/FileResource.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for @RestPath -> exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Micronaut @QueryValue -> SQL injection (CWE-89) ---

func TestJava_Micronaut_QueryValue_XSS(t *testing.T) {
	code := `
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.QueryValue;
import javax.servlet.http.*;

@Controller("/api")
public class SearchController {
    @Get("/search")
    public void search(@QueryValue String query, HttpServletResponse response) throws Exception {
        response.getWriter().write("<p>Results for: " + query + "</p>");
    }
}
`
	flows := Analyze(code, "/app/SearchController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for @QueryValue -> response.write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Cookie.getValue() -> XSS (CWE-79) ---

func TestJava_Cookie_GetValue_XSS(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class CookieServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("username")) {
                String value = cookie.getValue();
                response.getWriter().write("<p>Welcome " + value + "</p>");
            }
        }
    }
}
`
	flows := Analyze(code, "/app/CookieServlet.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for cookie.getValue() -> response.write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Part.getSubmittedFileName() -> File write path traversal (CWE-22) ---

func TestJava_Part_GetSubmittedFileName_PathTraversal(t *testing.T) {
	code := `
import javax.servlet.http.*;
import javax.servlet.annotation.MultipartConfig;
import java.io.*;

@MultipartConfig
public class UploadServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        File dest = new File("/uploads/" + fileName);
        filePart.write(dest.getAbsolutePath());
    }
}
`
	flows := Analyze(code, "/app/UploadServlet.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for Part.getSubmittedFileName() -> File()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Gson.fromJson() -> XSS via second-order (CWE-79) ---

func TestJava_Gson_FromJson_XSS(t *testing.T) {
	code := `
import com.google.gson.Gson;
import javax.servlet.http.*;
import java.io.*;

public class ApiServlet extends HttpServlet {
    Gson gson = new Gson();
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String body = request.getReader().readLine();
        Map data = gson.fromJson(body, Map.class);
        String name = (String) data.get("name");
        response.getWriter().write("<h1>Hello " + name + "</h1>");
    }
}
`
	flows := Analyze(code, "/app/ApiServlet.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for gson.fromJson() -> response.write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- SnakeYAML.load() -> eval via deserialization (CWE-502) ---

func TestJava_SnakeYAML_Load_Deserialized_Source(t *testing.T) {
	code := `
import org.yaml.snakeyaml.Yaml;
import javax.servlet.http.*;
import java.io.*;

public class YamlServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String body = request.getReader().readLine();
        Yaml yaml = new Yaml();
        Object data = yaml.load(body);
        response.getWriter().write("<pre>" + data.toString() + "</pre>");
    }
}
`
	flows := Analyze(code, "/app/YamlServlet.java", rules.LangJava)
	// Should detect both: SnkDeserialize (yaml.load sink) AND SnkHTMLOutput (XSS via deserialized data)
	hasDeser := hasTaintFlow(flows, taint.SnkDeserialize)
	hasXSS := hasTaintFlow(flows, taint.SnkHTMLOutput)
	if !hasDeser && !hasXSS {
		t.Error("expected deserialization or XSS flow for yaml.load() + response.write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- JNDI lookup result as tainted source ---

func TestJava_JNDI_Lookup_Result_Tainted(t *testing.T) {
	code := `
import javax.naming.InitialContext;
import javax.servlet.http.*;
import java.io.*;

public class JndiServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        InitialContext ctx = new InitialContext();
        Object result = ctx.lookup("java:comp/env/myObject");
        response.getWriter().write(result.toString());
    }
}
`
	flows := Analyze(code, "/app/JndiServlet.java", rules.LangJava)
	// JNDI lookup is both a sink (SnkEval) and source (SrcExternal)
	hasEval := hasTaintFlow(flows, taint.SnkEval)
	hasXSS := hasTaintFlow(flows, taint.SnkHTMLOutput)
	if !hasEval && !hasXSS {
		t.Error("expected eval or XSS flow for JNDI lookup")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
