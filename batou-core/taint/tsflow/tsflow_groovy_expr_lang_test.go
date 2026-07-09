package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy JVM expression-language injection tests (OGNL / MVEL / JEXL)
//
// Groovy code (Grails controllers, Jenkins pipelines, Gradle scripts,
// Struts/Spring integrations) calls these JVM expression libraries via
// interop. Evaluating a tainted expression string is arbitrary-code
// execution (CWE-917 / CWE-94):
//   - OGNL  — Apache Commons OGNL / Struts2 ValueStack (CVE-2017-5638
//             "Equifax", CVE-2018-11776 family)
//   - MVEL  — org.mvel2 (Drools / business-rule engines; CVE-2019-10171)
//   - JEXL  — org.apache.commons.jexl3 (sandbox-escape RCE chains)
//
// Java and Kotlin already model these; this file covers the Groovy gap.
// =========================================================================

// --- OGNL (ognl.Ognl static methods) ---

func TestGroovy_Ognl_GetValue_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def root = new Object()
    return Ognl.getValue(userInput, root)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> Ognl.getValue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Ognl_SetValue_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def root = new Object()
    Ognl.setValue(userInput, root, "value")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> Ognl.setValue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Ognl_ParseExpression_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def expr = Ognl.parseExpression(userInput)
    return expr
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> Ognl.parseExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- MVEL (org.mvel2.MVEL static methods) ---

func TestGroovy_Mvel_Eval_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    return MVEL.eval(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> MVEL.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Mvel_EvalToString_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    return MVEL.evalToString(userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> MVEL.evalToString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Mvel_ExecuteExpression_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    return MVEL.executeExpression(userInput, [:])
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> MVEL.executeExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Mvel_CompileExpression_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def compiled = MVEL.compileExpression(userInput)
    return compiled
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> MVEL.compileExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- JEXL (org.apache.commons.jexl3.JexlEngine) ---

func TestGroovy_Jexl_CreateExpression_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def jexl = new JexlBuilder().create()
    def expr = jexl.createExpression(userInput)
    return expr
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> JexlEngine.createExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Jexl_CreateScript_Tainted(t *testing.T) {
	code := `
def handler(userInput) {
    def jexl = new JexlBuilder().create()
    def script = jexl.createScript(userInput)
    return script
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected EL-injection flow for userInput -> JexlEngine.createScript")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative control: constant expression must NOT flow ---

func TestGroovy_ExprLang_ConstantExpression_Safe(t *testing.T) {
	code := `
def handler(userInput) {
    def constExpr = "name == 'admin'"
    return MVEL.eval(constExpr)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("did NOT expect EL-injection flow for a constant expression -> MVEL.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
