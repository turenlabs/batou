package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func TestKotlin_XSS_Ktor_Respond(t *testing.T) {
	code := `
fun handler() {
    val name = call.request.queryParameters["name"]
    call.respond("<h1>Hello, " + name + "</h1>")
}
`
	flows := Analyze(code, "/app/Routes.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for queryParameters -> call.respond()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_XSS_Ktor_RespondOutputStream(t *testing.T) {
	code := `
fun handler() {
    val userInput = readLine()
    call.respondOutputStream(userInput)
}
`
	flows := Analyze(code, "/app/Routes.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for readLine -> call.respondOutputStream()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_XSS_Ktor_RespondTextWriter(t *testing.T) {
	code := `
fun handler() {
    val userInput = readLine()
    call.respondTextWriter(userInput)
}
`
	flows := Analyze(code, "/app/Routes.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for readLine -> call.respondTextWriter()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_XSS_Servlet_WriterWrite(t *testing.T) {
	code := `
fun handleRequest() {
    val name = readLine()
    val writer = response.writer
    writer.write("<html><body>Hello, " + name + "</body></html>")
}
`
	flows := Analyze(code, "/app/Servlet.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for readLine -> writer.write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_XSS_Servlet_WriterPrintln(t *testing.T) {
	code := `
fun handleRequest() {
    val input = readLine()
    val writer = response.writer
    writer.println("<p>" + input + "</p>")
}
`
	flows := Analyze(code, "/app/Servlet.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for readLine -> writer.println()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_XSS_Servlet_WriterPrint(t *testing.T) {
	code := `
fun handleRequest() {
    val comment = readLine()
    val writer = response.writer
    writer.print("<div>" + comment + "</div>")
}
`
	flows := Analyze(code, "/app/Servlet.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for readLine -> writer.print()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TestKotlin_XSS_Servlet_WriterWriteDirect covers the idiomatic Kotlin
// property-access getter form `response.writer.write(...)` with NO intermediate
// local — the receiver of write() is the navigation chain `response.writer`.
// Before the fix the servlet writer sinks carried ObjectType "HttpServletResponse"
// (which the matcher's getWriter()/.writer receiver bridge can't reach) and a
// dotted MethodName, so this common shape produced ZERO dataflow findings.
func TestKotlin_XSS_Servlet_WriterWriteDirect(t *testing.T) {
	code := `
fun handleRequest(request: Any, response: Any) {
    val name = request.getParameter("name")
    response.writer.write("<html><body>Hello, " + name + "</body></html>")
}
`
	flows := Analyze(code, "/app/Servlet.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for getParameter -> response.writer.write() (direct property access)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TestKotlin_XSS_Servlet_GetWriterDirect covers the Java-style getter-call form
// `response.getWriter().write(...)` in Kotlin (no intermediate local). The
// receiver is the chained call `response.getWriter()`; the fix routes it via the
// PrintWriter ObjectType + the matcher's getWriter() bridge.
func TestKotlin_XSS_Servlet_GetWriterDirect(t *testing.T) {
	code := `
fun handleRequest(request: Any, response: Any) {
    val name = request.getParameter("name")
    response.getWriter().write("<html>" + name + "</html>")
}
`
	flows := Analyze(code, "/app/Servlet.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for getParameter -> response.getWriter().write()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TestKotlin_XSS_Servlet_TemplateDirect covers the Kotlin string-template form
// `response.writer.write("...$name...")` reaching the now-live servlet sink.
func TestKotlin_XSS_Servlet_TemplateDirect(t *testing.T) {
	code := `
fun handleRequest(request: Any, response: Any) {
    val name = request.getParameter("name")
    response.writer.println("<h1>$name</h1>")
}
`
	flows := Analyze(code, "/app/Servlet.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for getParameter -> response.writer.println() (string template)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TestKotlin_XSS_Servlet_WriterConstSafe verifies the widened .writer receiver
// bridge does NOT fire on a constant (untainted) write — a benign writer.write
// of a literal must stay clean.
func TestKotlin_XSS_Servlet_WriterConstSafe(t *testing.T) {
	code := `
fun handleRequest(response: Any) {
    response.writer.write("<html>static content</html>")
}
`
	flows := Analyze(code, "/app/Servlet.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected no XSS flow for constant writer.write(); got %s -> %s (conf %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_HtmlEscape(t *testing.T) {
	code := `
fun handler() {
    val name = call.request.queryParameters["name"]
    val safe = StringEscapeUtils.escapeHtml4(name)
    call.respond("<h1>Hello, " + safe + "</h1>")
}
`
	flows := Analyze(code, "/app/Routes.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Error("expected no high-confidence XSS flow when escapeHtml4 sanitizer is used")
		}
	}
}
