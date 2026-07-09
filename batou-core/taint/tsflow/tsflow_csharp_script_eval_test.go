package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# embedded-script / expression-evaluation code injection (CWE-94 / CWE-95)
//
// .NET has several libraries that execute attacker-controllable code or
// expression strings:
//   - Jint / Microsoft.ClearScript  : engine.Execute(js) / engine.Evaluate(js)
//   - NCalc                          : new Expression(formula)
//   - Flee                           : context.CompileDynamic(expr)
//
// A tainted script/expression reaching these is code/expression injection.
// ===========================================================================

func TestCSharp_Sink_Jint_Execute(t *testing.T) {
	code := `
using System;
using Jint;
using Microsoft.AspNetCore.Mvc;

public class ScriptController : Controller {
    private readonly Engine engine;
    public IActionResult Run() {
        string userScript = Request.QueryString.Value;
        engine.Execute(userScript);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ScriptController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Request.QueryString -> engine.Execute (Jint code injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_Jint_Evaluate(t *testing.T) {
	code := `
using System;
using Jint;
using Microsoft.AspNetCore.Mvc;

public class ScriptController : Controller {
    private readonly Engine engine;
    public IActionResult Run() {
        string expr = Request.Body.ToString();
        var result = engine.Evaluate(expr);
        return Ok(result.ToString());
    }
}
`
	flows := Analyze(code, "/app/ScriptController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Request.Body -> engine.Evaluate (Jint expression injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_NCalc_Expression_New(t *testing.T) {
	code := `
using System;
using NCalc;
using Microsoft.AspNetCore.Mvc;

public class CalcController : Controller {
    public IActionResult Run() {
        string formula = Request.QueryString.Value;
        var e = new Expression(formula);
        return Ok(e.Evaluate().ToString());
    }
}
`
	flows := Analyze(code, "/app/CalcController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Request.QueryString -> new Expression (NCalc expression injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_Flee_CompileDynamic(t *testing.T) {
	code := `
using System;
using Ciloci.Flee;
using Microsoft.AspNetCore.Mvc;

public class FleeController : Controller {
    public IActionResult Run() {
        string expr = Request.QueryString.Value;
        var context = new ExpressionContext();
        var e = context.CompileDynamic(expr);
        return Ok(e.Evaluate().ToString());
    }
}
`
	flows := Analyze(code, "/app/FleeController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Request.QueryString -> context.CompileDynamic (Flee expression injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: the script/expression body is a literal — only data values come from
// untrusted input. No eval-injection flow should be reported.
func TestCSharp_Sink_ScriptEval_Safe_LiteralBody(t *testing.T) {
	code := `
using System;
using Jint;
using Microsoft.AspNetCore.Mvc;

public class ScriptController : Controller {
    private readonly Engine engine;
    public IActionResult Run() {
        string userName = Request.QueryString.Value;
        engine.SetValue("name", userName);
        engine.Execute("var greeting = 'hello ' + name;");
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ScriptController.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Errorf("did not expect SnkEval flow when the script body is a literal (only a data value is tainted); got flow: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
