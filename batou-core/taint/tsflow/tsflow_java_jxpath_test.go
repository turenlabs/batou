package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Apache Commons JXPath RCE sinks (CVE-2022-41852, CWE-94).
//
// JXPath evaluates XPath expressions over Java beans and supports extension
// function calls of the form `java.lang.Runtime.getRuntime().exec(...)` directly
// inside the XPath expression. Any tainted XPath reaching a JXPathContext
// method yields remote code execution.

func TestJava_JXPath_Eval_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        Object bean = new Object();
        JXPathContext context = JXPathContext.newContext(bean);
        Object result = context.eval(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_GetValue_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        Object result = context.getValue(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.getValue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_Iterate_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;
import java.util.Iterator;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        Iterator it = context.iterate(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.iterate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_IteratePointers_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;
import java.util.Iterator;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        Iterator ptrs = context.iteratePointers(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.iteratePointers")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_SelectNodes_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;
import java.util.List;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        List nodes = context.selectNodes(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.selectNodes")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_SelectSingleNode_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        Object node = context.selectSingleNode(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.selectSingleNode")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_GetPointer_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;
import org.apache.commons.jxpath.Pointer;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        Pointer p = context.getPointer(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.getPointer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_CreatePath_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;
import org.apache.commons.jxpath.Pointer;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        Pointer p = context.createPath(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.createPath")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_CreatePathAndSetValue_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        context.createPathAndSetValue(xpath, "newValue");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.createPathAndSetValue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_SetValue_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        context.setValue(xpath, "newValue");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.setValue")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_RemovePath_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        context.removePath(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.removePath")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestJava_JXPath_RemoveAll_Injection(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.jxpath.JXPathContext;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xpath = request.getParameter("xpath");
        JXPathContext context = JXPathContext.newContext(new Object());
        context.removeAll(xpath);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getParameter -> JXPathContext.removeAll")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe: hardcoded XPath should NOT trigger.
func TestJava_JXPath_HardcodedExpression_NoFlow(t *testing.T) {
	code := `
import org.apache.commons.jxpath.JXPathContext;

public class Handler {
    public void run() {
        JXPathContext context = JXPathContext.newContext(new Object());
        Object result = context.getValue("/items/item[1]/name");
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected NO eval flow for hardcoded JXPath expression")
	}
}
