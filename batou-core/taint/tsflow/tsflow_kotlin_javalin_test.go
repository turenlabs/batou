package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for Javalin (io.javalin.http.Context) request input sources.
// Javalin handlers receive a Context conventionally named `ctx`. Each test
// flows a Context method's return value into a known Kotlin sink and
// asserts the expected sink category fires.

func TestKotlin_Javalin_QueryParam_SQLInjection(t *testing.T) {
	code := `
import io.javalin.http.Context
import java.sql.DriverManager

fun handler(ctx: Context) {
    val name = ctx.queryParam("name")
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from ctx.queryParam() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Javalin_PathParam_CommandInjection(t *testing.T) {
	code := `
import io.javalin.http.Context

fun handler(ctx: Context) {
    val target = ctx.pathParam("host")
    Runtime.getRuntime().exec("ping " + target)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from ctx.pathParam() to Runtime.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Javalin_FormParam_FileWrite_PathTraversal(t *testing.T) {
	code := `
import io.javalin.http.Context
import java.io.File

fun handler(ctx: Context) {
    val name = ctx.formParam("file")
    val f = File("/uploads/" + name)
    f.writeText("payload")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write/path-traversal flow from ctx.formParam() to File()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Javalin_Body_SQLInjection(t *testing.T) {
	code := `
import io.javalin.http.Context
import java.sql.DriverManager

fun handler(ctx: Context) {
    val payload = ctx.body()
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM logs WHERE msg = '" + payload + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from ctx.body() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Javalin_Header_CommandInjection(t *testing.T) {
	code := `
import io.javalin.http.Context

fun handler(ctx: Context) {
    val ua = ctx.header("User-Agent")
    Runtime.getRuntime().exec("logger " + ua)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from ctx.header() to Runtime.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Javalin_Cookie_SQLInjection(t *testing.T) {
	code := `
import io.javalin.http.Context
import java.sql.DriverManager

fun handler(ctx: Context) {
    val token = ctx.cookie("session")
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM sessions WHERE token = '" + token + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from ctx.cookie() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Javalin_QueryParamMap_FileWrite(t *testing.T) {
	code := `
import io.javalin.http.Context
import java.io.File

fun handler(ctx: Context) {
    val all = ctx.queryParamMap()
    val f = File("/data/" + all.toString())
    f.writeText("ok")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-traversal flow from ctx.queryParamMap() to File()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Javalin_BodyAsBytes_FileWrite(t *testing.T) {
	code := `
import io.javalin.http.Context
import java.io.File

fun handler(ctx: Context) {
    val raw = ctx.bodyAsBytes()
    val f = File("/uploads/" + raw.toString())
    f.writeText("data")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write/path-traversal flow from ctx.bodyAsBytes() to File()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: a Javalin handler that uses a hard-coded constant should
// NOT produce a taint flow (no source seeded). This guards against an
// over-broad "every ctx.* matches" regression.
func TestKotlin_Javalin_NoTaint_Constant(t *testing.T) {
	code := `
import io.javalin.http.Context
import java.sql.DriverManager

fun handler(ctx: Context) {
    val name = "alice"
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SQL injection flow when Javalin Context is unused")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
