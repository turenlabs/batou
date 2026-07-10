package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func TestDebugJavaMapPutGet(t *testing.T) {
	// Safe key retrieval — should produce 0 flows.
	code := `
import javax.servlet.http.HttpServletRequest;

public class Test {
    public void doPost(HttpServletRequest request) {
        String param = request.getHeader("X-Test");
        java.util.HashMap<String, Object> map = new java.util.HashMap<>();
        map.put("keyA", "safe");
        map.put("keyB", param);
        String bar = (String) map.get("keyA");
        System.out.println(bar);
    }
}
`
	flows := Analyze(code, "/app/Test.java", rules.LangJava)
	t.Logf("Safe key flows: %d", len(flows))
	if len(flows) > 0 {
		t.Errorf("Expected 0 flows for safe key get, got %d", len(flows))
	}

	// Tainted key retrieval — should produce flows.
	code2 := `
import javax.servlet.http.HttpServletRequest;

public class Test {
    public void doPost(HttpServletRequest request) {
        String param = request.getHeader("X-Test");
        java.util.HashMap<String, Object> map = new java.util.HashMap<>();
        map.put("keyA", "safe");
        map.put("keyB", param);
        String bar = (String) map.get("keyB");
        System.out.println(bar);
    }
}
`
	flows2 := Analyze(code2, "/app/Test.java", rules.LangJava)
	t.Logf("Tainted key flows: %d", len(flows2))
	if len(flows2) == 0 {
		t.Errorf("Expected flows for tainted key get, got 0")
	}
}

func TestDebugJavaMapLastWriteWins(t *testing.T) {
	code := `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest extends javax.servlet.http.HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("BenchmarkTest");
        String bar = "safe!";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put("keyB", param);
        map.put("keyC", "another_Value");
        bar = (String) map.get("keyB");
        bar = (String) map.get("keyA");

        String fileName = "/testfiles/" + bar;
        java.io.File fileTarget = new java.io.File(fileName);
        response.getWriter().println(fileTarget.toString());
    }
}
`
	flows := Analyze(code, "/app/BenchmarkTest.java", rules.LangJava)
	t.Logf("OWASP map pattern flows: %d", len(flows))
	if len(flows) > 0 {
		t.Errorf("Expected 0 flows for OWASP map FP pattern, got %d", len(flows))
	}
}

func TestDebugJavaDoSomethingList(t *testing.T) {
	// Mimics BenchmarkTest02557: doSomething with list operations.
	code := `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest extends javax.servlet.http.HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("BenchmarkTest");
        String bar = doSomething(request, param);
        java.io.File fileTarget = new java.io.File(bar, "/Test.txt");
        response.getWriter().println(fileTarget.toString());
    }

    private static String doSomething(HttpServletRequest request, String param) {
        String bar = "alsosafe";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");
            valuesList.remove(0);
            bar = valuesList.get(1);
        }
        return bar;
    }
}
`
	// Test Pass 1: check if doSomething is recognized as taint-propagating.
	cfg := getConfig(rules.LangJava)
	tree := ast.Parse([]byte(code), rules.LangJava)
	if tree == nil {
		t.Fatal("failed to parse Java code")
	}
	root := tree.Root()
	funcNodes := ast.FindByTypes(root, cfg.funcTypes)

	t.Logf("Found %d functions:", len(funcNodes))
	for _, fn := range funcNodes {
		t.Logf("  %s (type=%s)", cfg.extractFuncName(fn), fn.Type())
	}

	cat := taint.GetCatalog(rules.LangJava)
	if cat == nil {
		t.Fatal("no Java taint catalog")
	}
	matcher := newTSMatcher(cat.Sources(), cat.Sinks(), cat.Sanitizers(), cfg)

	summaries := buildTaintSummaries(funcNodes, cfg, matcher)
	t.Logf("summaries: %v", summaries)
	if s, ok := summaries["doSomething"]; ok && s.anyParamPropagates() {
		t.Errorf("doSomething should NOT be taint-propagating (list returns safe index)")
	}

	// Test full analysis.
	flows := Analyze(code, "/app/BenchmarkTest.java", rules.LangJava)
	t.Logf("doSomething list pattern flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s srcLine=%d sinkLine=%d conf=%.2f scope=%s",
			i, f.Source.ID, f.Sink.ID, f.SourceLine, f.SinkLine, f.Confidence, f.ScopeName)
		for _, step := range f.Steps {
			t.Logf("    Step: line=%d var=%s desc=%s", step.Line, step.VarName, step.Description)
		}
	}
}

func TestDebugJavaTernaryConstant(t *testing.T) {
	// OWASP pattern: constant ternary condition that always selects safe value.
	code := `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest extends javax.servlet.http.HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("BenchmarkTest");
        int num = 106;
        String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
        String fileName = "/testfiles/" + bar;
        java.io.File fileTarget = new java.io.File(fileName);
        response.getWriter().println(fileTarget.toString());
    }
}
`
	flows := Analyze(code, "/app/BenchmarkTest.java", rules.LangJava)
	t.Logf("Ternary constant flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
	}
	if len(flows) > 0 {
		t.Errorf("Expected 0 flows for constant ternary (always-true condition), got %d", len(flows))
	}
}

func TestDebugJavaIfConstant(t *testing.T) {
	// OWASP pattern: constant if-condition that always takes safe branch.
	code := `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest extends javax.servlet.http.HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("BenchmarkTest");
        int num = 106;
        String bar;
        if ((7 * 18) + num > 200) {
            bar = "This_should_always_happen";
        } else {
            bar = param;
        }
        String fileName = "/testfiles/" + bar;
        java.io.File fileTarget = new java.io.File(fileName);
        response.getWriter().println(fileTarget.toString());
    }
}
`
	flows := Analyze(code, "/app/BenchmarkTest.java", rules.LangJava)
	t.Logf("If constant flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
	}
	if len(flows) > 0 {
		t.Errorf("Expected 0 flows for constant if-condition (always-true), got %d", len(flows))
	}
}

func TestDebugTaintReassign(t *testing.T) {
	code := `
from flask import redirect, request

def handler():
    a = request.args.get("x")
    b = a
    return redirect(b)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	t.Logf("Flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s conf=%.2f scope=%s", i, f.Source.ID, f.Sink.ID, f.Confidence, f.ScopeName)
		for _, step := range f.Steps {
			t.Logf("    Step: line=%d var=%s desc=%s", step.Line, step.VarName, step.Description)
		}
	}
}

func TestDebugTaintDirect(t *testing.T) {
	code := `
from flask import redirect, request

def handler():
    param = request.args.get("x")
    return redirect(param)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	t.Logf("Flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s conf=%.2f scope=%s", i, f.Source.ID, f.Sink.ID, f.Confidence, f.ScopeName)
		for _, step := range f.Steps {
			t.Logf("    Step: line=%d var=%s desc=%s", step.Line, step.VarName, step.Description)
		}
	}
}
