package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// TestSummary_ParamSpecificPropagation verifies that only the parameter that
// actually propagates to return is marked in the summary.
func TestSummary_ParamSpecificPropagation(t *testing.T) {
	code := `
def propagates_first(a, b):
    return a

def propagates_second(a, b):
    return b

def propagates_neither(a, b):
    return "safe"

def propagates_both(a, b):
    return a + b
`
	cfg := getConfig(rules.LangPython)
	tree := parseForTest(code, rules.LangPython)
	if tree == nil {
		t.Fatal("failed to parse")
	}
	root := tree.Root()
	funcNodes := findFuncNodes(root, cfg)
	cat := taint.GetCatalog(rules.LangPython)
	matcher := newTSMatcher(cat.Sources(), cat.Sinks(), cat.Sanitizers(), cfg)

	summaries := buildTaintSummaries(funcNodes, cfg, matcher)

	// propagates_first: param 0 propagates, param 1 does not.
	if s := summaries["propagates_first"]; s == nil {
		t.Fatal("missing summary for propagates_first")
	} else {
		if !s.paramPropagates(0) {
			t.Error("propagates_first: param 0 should propagate")
		}
		if s.paramPropagates(1) {
			t.Error("propagates_first: param 1 should NOT propagate")
		}
	}

	// propagates_second: param 1 propagates, param 0 does not.
	if s := summaries["propagates_second"]; s == nil {
		t.Fatal("missing summary for propagates_second")
	} else {
		if s.paramPropagates(0) {
			t.Error("propagates_second: param 0 should NOT propagate")
		}
		if !s.paramPropagates(1) {
			t.Error("propagates_second: param 1 should propagate")
		}
	}

	// propagates_neither: no params propagate.
	if s := summaries["propagates_neither"]; s == nil {
		t.Fatal("missing summary for propagates_neither")
	} else {
		if s.anyParamPropagates() {
			t.Error("propagates_neither: should have no propagating params")
		}
		if !s.IsPure {
			t.Error("propagates_neither: should be marked as pure")
		}
	}

	// propagates_both: both params propagate.
	if s := summaries["propagates_both"]; s == nil {
		t.Fatal("missing summary for propagates_both")
	} else {
		if !s.paramPropagates(0) {
			t.Error("propagates_both: param 0 should propagate")
		}
		if !s.paramPropagates(1) {
			t.Error("propagates_both: param 1 should propagate")
		}
	}
}

// TestSummary_ContextSensitiveCallPropagation verifies that call sites only
// propagate taint through the parameter that actually flows to return.
func TestSummary_ContextSensitiveCallPropagation(t *testing.T) {
	// identity returns its first param; second is ignored.
	// handler passes tainted data as second arg → should NOT propagate.
	code := `
def identity(x, ignored):
    return x

def handler():
    safe = "hello"
    tainted = input()
    result = identity(safe, tainted)
    cursor.execute(result)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow — tainted arg passed to non-propagating param")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f, scope: %s)", f.Source.Category, f.Sink.Category, f.Confidence, f.ScopeName)
		}
	}
}

// TestSummary_ContextSensitivePropagatingParam verifies that when tainted data
// is passed to the propagating parameter, taint is correctly tracked.
func TestSummary_ContextSensitivePropagatingParam(t *testing.T) {
	code := `
def identity(x, ignored):
    return x

def handler():
    safe = "hello"
    tainted = input()
    result = identity(tainted, safe)
    cursor.execute(result)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow — tainted arg passed to propagating param")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// TestSummary_NoParamFunction verifies functions with no parameters are
// registered as local (non-propagating) without crashing.
func TestSummary_NoParamFunction(t *testing.T) {
	code := `
def no_params():
    return "safe"

def handler():
    val = input()
    result = no_params()
    cursor.execute(result)
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection — no_params() returns safe literal")
	}
}

// TestSummary_JavaContextSensitive verifies summaries work across languages.
func TestSummary_JavaContextSensitive(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    private String safe(String x, String y) {
        return "constant";
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("name");
        String result = safe(param, "hello");
        response.getWriter().println(result);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.ScopeName == "doGet" {
			// safe() returns a constant — should not propagate taint.
			t.Errorf("expected NO XSS flow through safe() — it returns a constant. Got: src=%s sink=%s conf=%.2f",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- helpers ---

func parseForTest(code string, lang rules.Language) *ast.Tree {
	return ast.Parse([]byte(code), lang)
}

func findFuncNodes(root *ast.Node, cfg *langConfig) []*ast.Node {
	return ast.FindByTypes(root, cfg.funcTypes)
}
