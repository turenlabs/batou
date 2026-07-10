package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for Vert.x Web framework (io.vertx.ext.web.RoutingContext +
// io.vertx.core.http.HttpServerRequest / HttpServerResponse) sources and
// sinks. Vert.x has first-class Kotlin support via vertx-lang-kotlin and
// vertx-lang-kotlin-coroutines (used by Hibernate Reactive, Eclipse
// Vert.x, etc.). Handlers receive a RoutingContext conventionally named
// `ctx`. Each test flows a Vert.x source method's return value into a
// known Kotlin sink and asserts the expected sink category fires.

func TestKotlin_Vertx_PathParam_SQLInjection(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext
import java.sql.DriverManager

fun handler(ctx: RoutingContext) {
    val name = ctx.pathParam("name")
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from ctx.pathParam() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_QueryParam_CommandInjection(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext

fun handler(ctx: RoutingContext) {
    val target = ctx.queryParam("host")
    Runtime.getRuntime().exec("ping " + target.toString())
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from ctx.queryParam() to Runtime.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_GetBodyAsString_SQLInjection(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext
import java.sql.DriverManager

fun handler(ctx: RoutingContext) {
    val payload = ctx.getBodyAsString()
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM logs WHERE msg = '" + payload + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from ctx.getBodyAsString() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_GetBodyAsJson_FileWrite(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext
import java.io.File

fun handler(ctx: RoutingContext) {
    val payload = ctx.getBodyAsJson()
    val f = File("/data/" + payload.toString())
    f.writeText("ok")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-traversal flow from ctx.getBodyAsJson() to File()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_FileUploads_FileWrite(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext
import java.io.File

fun handler(ctx: RoutingContext) {
    val uploads = ctx.fileUploads()
    val f = File("/uploads/" + uploads.toString())
    f.writeText("payload")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow from ctx.fileUploads() to File()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_Request_GetParam_SQLInjection(t *testing.T) {
	code := `
import io.vertx.core.http.HttpServerRequest
import java.sql.DriverManager

fun handler(request: HttpServerRequest) {
    val name = request.getParam("name")
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from request.getParam() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_Request_GetHeader_CommandInjection(t *testing.T) {
	code := `
import io.vertx.core.http.HttpServerRequest

fun handler(request: HttpServerRequest) {
    val ua = request.getHeader("User-Agent")
    Runtime.getRuntime().exec("logger " + ua)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from request.getHeader() to Runtime.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_Request_GetFormAttribute_FileWrite(t *testing.T) {
	code := `
import io.vertx.core.http.HttpServerRequest
import java.io.File

fun handler(request: HttpServerRequest) {
    val name = request.getFormAttribute("filename")
    val f = File("/uploads/" + name)
    f.writeText("data")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-traversal flow from request.getFormAttribute() to File()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Sink-side tests: tainted data flowing into Vert.x response APIs.

func TestKotlin_Vertx_Sink_Response_End_XSS(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext

fun handler(ctx: RoutingContext) {
    val name = ctx.pathParam("name")
    val response = ctx.response()
    response.end("<h1>Hello " + name + "</h1>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from ctx.pathParam() to response.end()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_Sink_Response_Write_XSS(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext

fun handler(ctx: RoutingContext) {
    val name = ctx.queryParam("name")
    val response = ctx.response()
    response.write("Hi " + name.toString())
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from ctx.queryParam() to response.write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_Sink_Response_SendFile_PathTraversal(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext

fun handler(ctx: RoutingContext) {
    val filename = ctx.pathParam("file")
    val response = ctx.response()
    response.sendFile("/var/www/" + filename)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected path-traversal flow from ctx.pathParam() to response.sendFile()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_Sink_Response_PutHeader_HeaderInjection(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext

fun handler(ctx: RoutingContext) {
    val redirectTarget = ctx.queryParam("next")
    val response = ctx.response()
    response.putHeader("Location", redirectTarget.toString())
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header-injection flow from ctx.queryParam() to response.putHeader()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Vertx_Sink_RoutingContext_Redirect_OpenRedirect(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext

fun handler(ctx: RoutingContext) {
    val next = ctx.queryParam("next")
    ctx.redirect(next.toString())
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow from ctx.queryParam() to ctx.redirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: a Vert.x handler that uses a hard-coded constant should
// NOT produce a taint flow (no source seeded). This guards against an
// over-broad "every ctx.* matches" regression on the new entries.
func TestKotlin_Vertx_NoTaint_Constant(t *testing.T) {
	code := `
import io.vertx.ext.web.RoutingContext
import java.sql.DriverManager

fun handler(ctx: RoutingContext) {
    val name = "alice"
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SQL injection flow when Vert.x RoutingContext is unused")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
