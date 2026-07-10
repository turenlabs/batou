package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for dynamic code evaluation sinks: Groovy, Commons JEXL, MVEL, BeanShell.
// These JVM libraries are major RCE vectors (Jenkins, Drools, Apache Camel, etc.)
// and were missing from the Java taint catalog prior to these entries.

// --- Apache Groovy (CWE-94) ---

func TestJava_GroovyShell_Evaluate_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import groovy.lang.GroovyShell;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String script = request.getParameter("script");
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(script);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> GroovyShell.evaluate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_GroovyShell_Parse_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import groovy.lang.GroovyShell;
import groovy.lang.Script;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String code = request.getParameter("code");
        GroovyShell groovyShell = new GroovyShell();
        Script parsed = groovyShell.parse(code);
        parsed.run();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> GroovyShell.parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_GroovyClassLoader_ParseClass_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import groovy.lang.GroovyClassLoader;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String source = request.getParameter("source");
        GroovyClassLoader groovyClassLoader = new GroovyClassLoader();
        Class<?> cls = groovyClassLoader.parseClass(source);
        cls.newInstance();
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> GroovyClassLoader.parseClass")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Apache Commons JEXL (CVE-2024-29133, CWE-94) ---

func TestJava_JEXL_CreateScript_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jexl3.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        JexlEngine jexlEngine = new JexlBuilder().create();
        JexlScript script = jexlEngine.createScript(expr);
        script.execute(null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JexlEngine.createScript")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JEXL_CreateExpression_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jexl3.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        JexlEngine jexlEngine = new JexlBuilder().create();
        JexlExpression e = jexlEngine.createExpression(expr);
        e.evaluate(null);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JexlEngine.createExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- MVEL (Drools/BRMS, CWE-94) ---

func TestJava_MVEL_Eval_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.mvel2.MVEL;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        Object result = MVEL.eval(expr);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> MVEL.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_MVEL_CompileExpression_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.mvel2.MVEL;
import java.io.Serializable;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String expr = request.getParameter("expr");
        Serializable compiled = MVEL.compileExpression(expr);
        MVEL.executeExpression(compiled);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> MVEL.compileExpression")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- BeanShell (Jenkins CVE-2016-2510, CWE-94) ---

func TestJava_BeanShell_Interpreter_Eval_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import bsh.Interpreter;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String script = request.getParameter("script");
        Interpreter interpreter = new Interpreter();
        interpreter.eval(script);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> Interpreter.eval (BeanShell)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: hardcoded expression should NOT trigger ---

func TestJava_GroovyShell_HardcodedScript_NoFlow(t *testing.T) {
	code := `
import groovy.lang.GroovyShell;

public class Handler {
    public void run() {
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate("1 + 1");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected NO eval flow for hardcoded Groovy expression")
	}
}

func TestJava_MVEL_HardcodedExpression_NoFlow(t *testing.T) {
	code := `
import org.mvel2.MVEL;

public class Handler {
    public void run() {
        MVEL.eval("2 + 2");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected NO eval flow for hardcoded MVEL expression")
	}
}
