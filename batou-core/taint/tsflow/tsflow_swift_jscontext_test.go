package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — JavaScriptCore JSContext.evaluateScript eval injection (CWE-95)
// =========================================================================
//
// Apple's JavaScriptCore framework (bundled with iOS/macOS SDK) executes
// arbitrary JavaScript via JSContext.evaluateScript. When the script
// argument flows from user-controlled input and the JSContext exposes
// native bridges (via JSExport or setObject), this is RCE-equivalent.

func TestSwift_JSContext_EvaluateScript_FromVaporQuery_EvalInjection(t *testing.T) {
	code := `
import JavaScriptCore
import Vapor

func handler(req: Request) {
    let userScript = req.query["code"]
    let context = JSContext()!
    context.evaluateScript(userScript)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for req.query -> JSContext.evaluateScript")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_JSContext_EvaluateScript_WithSourceURL_EvalInjection(t *testing.T) {
	// Verify the two-argument overload evaluateScript(_:withSourceURL:)
	// is caught by the same Pattern.
	code := `
import JavaScriptCore
import Vapor

func handler(req: Request) {
    let userScript = req.query["plugin"]
    let context = JSContext()!
    context.evaluateScript(userScript, withSourceURL: URL(string: "x://plugin")!)
}
`
	flows := Analyze(code, "/app/runner.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for req.query -> JSContext.evaluateScript(withSourceURL:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_JSContext_EvaluateScript_HardcodedScript_NoFlow(t *testing.T) {
	// Safe usage: script is a hardcoded literal, not tainted.
	code := `
import JavaScriptCore

func compute() -> JSValue? {
    let context = JSContext()!
    return context.evaluateScript("1 + 2 * 3")
}
`
	flows := Analyze(code, "/app/safe.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Errorf("did not expect eval flow for hardcoded script literal, got: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestSwift_JSValue_InvokeMethod_TaintedMethodName_EvalInjection(t *testing.T) {
	code := `
import JavaScriptCore
import Vapor

func handler(req: Request) {
    let methodName = req.query["fn"]
    let context = JSContext()!
    context.evaluateScript("var api = { hello: function(n) { return 'hi ' + n; } }; api;")
    let api = context.objectForKeyedSubscript("api")!
    api.invokeMethod(methodName, withArguments: ["world"])
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for req.query -> JSValue.invokeMethod method name")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
