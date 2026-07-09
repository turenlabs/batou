package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Vert.x XSS (CWE-79) ---

func TestJava_Vertx_XSS_ResponseEnd(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;

public class Handler {
    public void handle(RoutingContext ctx) {
        String name = ctx.pathParam("name");
        ctx.response().end("<h1>Hello " + name + "</h1>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for pathParam -> response().end()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Vertx_XSS_ResponseWrite(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;

public class Handler {
    public void handle(RoutingContext ctx) {
        String input = ctx.request().getParam("q");
        ctx.response().write("<div>" + input + "</div>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for getParam -> response().write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Vert.x SQL Injection (CWE-89) ---

func TestJava_Vertx_SQLInjection_Query(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;
import io.vertx.sqlclient.Pool;

public class Handler {
    private Pool pool;
    public void handle(RoutingContext ctx) {
        String id = ctx.request().getParam("id");
        pool.query("SELECT * FROM users WHERE id = " + id).execute();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParam -> pool.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Vertx_SQLInjection_Sanitized_PreparedQuery(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Tuple;

public class Handler {
    private Pool pool;
    public void handle(RoutingContext ctx) {
        String id = ctx.request().getParam("id");
        pool.preparedQuery("SELECT * FROM users WHERE id = $1")
            .execute(Tuple.of(id));
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when using preparedQuery")
	}
}

// --- Vert.x Path Traversal (CWE-22) ---

func TestJava_Vertx_PathTraversal_SendFile(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;

public class Handler {
    public void handle(RoutingContext ctx) {
        String file = ctx.pathParam("file");
        ctx.response().sendFile("uploads/" + file);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected path traversal flow for pathParam -> response().sendFile()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Vert.x Header Injection (CWE-113) ---

func TestJava_Vertx_HeaderInjection_PutHeader(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;

public class Handler {
    public void handle(RoutingContext ctx) {
        String value = ctx.request().getHeader("X-Custom");
        ctx.response().putHeader("X-Forwarded", value);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for getHeader -> response().putHeader()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Vert.x Open Redirect (CWE-601) ---

func TestJava_Vertx_OpenRedirect(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;

public class Handler {
    public void handle(RoutingContext ctx) {
        String url = ctx.request().getParam("next");
        ctx.redirect(url);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open redirect flow for getParam -> ctx.redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Vert.x SSRF (CWE-918) ---

func TestJava_Vertx_SSRF_WebClient(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.WebClient;

public class Handler {
    private WebClient webClient;
    public void handle(RoutingContext ctx) {
        String target = ctx.request().getParam("url");
        webClient.getAbs(target).send();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for getParam -> webClient.getAbs()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Vert.x Body Sources ---

func TestJava_Vertx_XSS_BodyAsString(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;

public class Handler {
    public void handle(RoutingContext ctx) {
        String body = ctx.body().asString();
        ctx.response().end(body);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for body().asString() -> response().end()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_Vertx_XSS_BodyAsJsonObject(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;
import io.vertx.core.json.JsonObject;

public class Handler {
    public void handle(RoutingContext ctx) {
        JsonObject json = ctx.body().asJsonObject();
        String data = json.getString("name");
        ctx.response().end("<p>" + data + "</p>");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for body().asJsonObject() -> response().end()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Vert.x Form Attributes ---

func TestJava_Vertx_SQLInjection_FormAttribute(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext;
import io.vertx.sqlclient.Pool;

public class Handler {
    private Pool pool;
    public void handle(RoutingContext ctx) {
        String username = ctx.request().getFormAttribute("username");
        pool.query("SELECT * FROM users WHERE name = '" + username + "'").execute();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getFormAttribute -> pool.query()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
