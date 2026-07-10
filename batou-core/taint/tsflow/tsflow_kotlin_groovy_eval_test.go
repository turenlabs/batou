package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Kotlin GroovyShell().evaluate()/parse() is a CWE-94 RCE sink. The catalog
// entry is anchored on the GroovyShell CONSTRUCTOR (its receiver varies:
// `GroovyShell()`, a `groovyShell`/`shell` handle), which previously forced an
// empty ObjectType — making the tsflow matcher register the bare method names
// `evaluate`/`parse` as match-ANYTHING wildcard sinks. Those names are
// ubiquitous benign calls, so the sink fired CWE-94 at conf 1.0 (a hard BLOCK)
// on safe code such as `SimpleDateFormat.parse(s)` / `StatusLine.parse(line)`
// (verified as a real false positive on okhttp). The entry now carries
// ObjectType "GroovyShell" and the matcher recognises the constructor / shell
// receiver via groovyShellReceiverMatch.

// Positive: a real request-sourced script reaching the GroovyShell sink must
// still flag, for both the named-handle (.evaluate) and fresh-constructor
// (.parse) receiver shapes.
func TestKotlin_GroovyShell_Injection_Fires(t *testing.T) {
	code := `
import groovy.lang.GroovyShell
import javax.servlet.http.HttpServletRequest

class Handler {
    fun doGet(request: HttpServletRequest) {
        val userScript = request.getParameter("script")
        val groovyShell = GroovyShell()
        groovyShell.evaluate(userScript)
    }
    fun doPost(request: HttpServletRequest) {
        val code = request.getParameter("code")
        GroovyShell().parse(code)
    }
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> GroovyShell.evaluate/parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative: benign `.parse()` / `.evaluate()` on unrelated receivers must NOT
// be flagged as a GroovyShell code-eval sink. These are the exact okhttp false
// positives that hard-blocked at conf 1.0 before the receiver anchor was added.
func TestKotlin_BenignParseEvaluate_NoEvalFlow(t *testing.T) {
	code := `
import java.text.SimpleDateFormat

class Adapters {
    fun decodeTime(string: String): Long {
        val dateFormat = SimpleDateFormat("yyyyMMddHHmmss'Z'")
        val parsed = dateFormat.parse(string)
        return parsed.time
    }
    fun readStatus(source: String): String {
        val statusLine = StatusLine.parse(source)
        return statusLine.message
    }
    fun render(template: String, ctx: Context): String {
        return ctx.expression(template).evaluate()
    }
}
`
	flows := Analyze(code, "/app/Adapters.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("benign .parse()/.evaluate() on non-GroovyShell receivers must not flag CWE-94 code-eval")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.MethodName)
		}
	}
}
