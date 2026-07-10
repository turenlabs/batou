package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for MVEL2 expression and template injection sinks (CWE-94 / CWE-1336).
//
// The Java catalog already covered MVEL.eval / executeExpression / compileExpression,
// but missed the other MVEL execution entry points that take the tainted expression
// or template text as their first argument:
//   - MVEL.evalToString / evalToBoolean        (typed convenience eval)
//   - MVEL.compileGetExpression / compileSetExpression (accessor compilation)
//   - TemplateRuntime.eval / TemplateCompiler.compileTemplate (MVEL2 templating, SSTI -> RCE)
//
// MVEL powers Drools/BRMS, Activiti/Camunda, OpenL Tablets and the Apache Camel
// `mvel:` language, so user-controlled expressions reaching any of these is RCE.

// --- MVEL convenience eval methods (CWE-94) ---

func TestJava_MVEL_EvalToString_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.mvel2.MVEL;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        String result = MVEL.evalToString(expr);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> MVEL.evalToString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_MVEL_EvalToBoolean_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.mvel2.MVEL;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        boolean ok = MVEL.evalToBoolean(expr, this);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> MVEL.evalToBoolean")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_MVEL_CompileGetExpression_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.Serializable;
import org.mvel2.MVEL;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        Serializable compiled = MVEL.compileGetExpression(expr);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> MVEL.compileGetExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_MVEL_CompileSetExpression_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.Serializable;
import org.mvel2.MVEL;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        Serializable compiled = MVEL.compileSetExpression(expr);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> MVEL.compileSetExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- MVEL2 templating (CWE-1336, SSTI -> RCE) ---

func TestJava_MVEL_TemplateRuntime_Eval_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.mvel2.templates.TemplateRuntime;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String template = request.getParameter("tpl");
        Object out = TemplateRuntime.eval(template, this);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template flow for getParameter -> TemplateRuntime.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_MVEL_TemplateCompiler_CompileTemplate_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.mvel2.templates.CompiledTemplate;
import org.mvel2.templates.TemplateCompiler;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String template = request.getParameter("tpl");
        CompiledTemplate compiled = TemplateCompiler.compileTemplate(template);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template flow for getParameter -> TemplateCompiler.compileTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Negative control: hardcoded expression must NOT flow ---

func TestJava_MVEL_EvalToString_Hardcoded_NoFlow(t *testing.T) {
	code := `
import org.mvel2.MVEL;

public class Handler {
    public void run() {
        String result = MVEL.evalToString("2 + 2");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected NO eval flow for hardcoded MVEL.evalToString expression")
	}
}
