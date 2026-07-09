package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Kotlin destructuring declarations (`val (a, b) = expr`) parse as a
// property_declaration whose binding is a multi_variable_declaration.
// extractVarDeclParts can't name that shape, so before this fix every
// destructured local silently lost taint and these flows produced ZERO
// findings. These tests pin the recall fix: each name bound by the
// destructuring inherits the taint of the whole RHS.

// raw user input is split and destructured, then a component reaches
// Runtime.getRuntime().exec — classic OS command injection.
func TestKotlin_Destructure_CommandInjection(t *testing.T) {
	code := `
fun handle(call: ApplicationCall) {
    val raw = call.receiveText()
    val (cmd, arg) = raw.split(" ")
    Runtime.getRuntime().exec(cmd)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from destructured `cmd`")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// The SECOND destructured component is equally tainted — each name is a
// componentN() projection of the user-controlled value.
func TestKotlin_Destructure_SecondComponentTainted(t *testing.T) {
	code := `
fun handle(call: ApplicationCall) {
    val raw = call.receiveText()
    val (cmd, arg) = raw.split(" ")
    Runtime.getRuntime().exec(arg)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow from destructured `arg` (second component)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Destructured component flows into a JDBC query string — SQL injection.
func TestKotlin_Destructure_SQLInjection(t *testing.T) {
	code := `
fun handle(call: ApplicationCall) {
    val raw = call.receiveText()
    val (id, name) = raw.split(",")
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow from destructured `id`")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: destructuring a constant Pair must NOT taint the locals.
func TestKotlin_Destructure_ConstantPair_NoFlow(t *testing.T) {
	code := `
fun handle(call: ApplicationCall) {
    val (a, b) = Pair("ls", "-la")
    Runtime.getRuntime().exec(a)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command flow from a constant-Pair destructuring")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// A fresh destructuring declaration shadows a prior tainted single binding of
// the same name when its RHS is untainted (stale taint must be cleared).
func TestKotlin_Destructure_ShadowsPriorTaint_NoFlow(t *testing.T) {
	code := `
fun handle(call: ApplicationCall) {
    val cmd = call.receiveText()
    val (cmd, label) = Pair("ls", "safe")
    Runtime.getRuntime().exec(cmd)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command flow after the constant destructuring shadowed the tainted `cmd`")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
