package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// hasFlowOfCategory reports whether any flow reaches the given sink category.
func hasFlowOfCategory(flows []taint.TaintFlow, cat taint.SinkCategory) bool {
	for _, f := range flows {
		if f.Sink.Category == cat {
			return true
		}
	}
	return false
}

// TestReturnTaint_ChainedReceiverInHelper_Java is the focused regression guard
// for the return-taint fix. A same-file helper (an instance method on a
// freshly-constructed nested class) returns one of its tainted parameters after
// routing it through a chained-receiver builder expression
// (`new StringBuilder(param).append("_x").toString()`).
//
// Before the fix, callReceiverTainted could not resolve the receiver subtree of
// a Java method_invocation chain (the receiver lives on the call node's `object`
// field, not under a `function`/`name` child), so `bar` never became tainted
// inside the helper, the helper's ReturnTaint summary stayed empty, and the
// source→sink flow was severed. This case yields ZERO flows without the fix.
func TestReturnTaint_ChainedReceiverInHelper_Java(t *testing.T) {
	code := `package org.owasp.benchmark.testcode;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class H extends javax.servlet.http.HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = new Test().doSomething(request, param);
    response.getWriter().print(bar);
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      StringBuilder sb = new StringBuilder(param);
      String bar = sb.append("_SafeStuff").toString();
      return bar;
    }
  }
}`
	flows := Analyze(code, "/srv/app/H.java", rules.LangJava)
	if !hasFlowOfCategory(flows, taint.SnkHTMLOutput) {
		t.Fatalf("expected an html_output flow through the builder-chain helper return, got %d flows", len(flows))
	}
}

// TestReturnTaint_ChainedReceiverInHelper_FreeFunction covers the free-function
// variant `bar = doSomething(param)` (no `new X()` receiver) with the same
// builder chain in the body — confirming the fix is not specific to the
// instance-method idiom.
func TestReturnTaint_ChainedReceiverInHelper_FreeFunction(t *testing.T) {
	code := `package org.owasp.benchmark.testcode;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class H extends javax.servlet.http.HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    java.util.Map<String, String[]> map = request.getParameterMap();
    String param = "";
    String[] vals = map.get("p");
    if (vals != null) param = vals[0];
    String bar = doSomething(request, param);
    response.getWriter().print(bar);
  }
  private static String doSomething(HttpServletRequest request, String param) {
    StringBuilder sb = new StringBuilder(param);
    String bar = sb.append("_SafeStuff").toString();
    return bar;
  }
}`
	flows := Analyze(code, "/srv/app/H.java", rules.LangJava)
	if !hasFlowOfCategory(flows, taint.SnkHTMLOutput) {
		t.Fatalf("expected an html_output flow through the free-function builder-chain helper return, got %d flows", len(flows))
	}
}

// TestReturnTaint_HelperSanitizes_NoFlow is the precision guard: the helper
// returns the param after a CRLF-stripping replace() chain (a sanitizer the
// catalog only models at the direct-RHS position). The broadened
// chained-receiver propagation must NOT carry log/header taint past that
// in-chain sanitizer — the gate in callReceiverTaintedForPropagation declines.
func TestReturnTaint_HelperSanitizes_NoFlow(t *testing.T) {
	code := `package org.owasp.benchmark.testcode;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class H extends javax.servlet.http.HttpServlet {
  private static final Logger log = LoggerFactory.getLogger(H.class);
  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("user");
    String bar = new Test().doSomething(request, param);
    log.info("User login: " + bar);
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      String bar = param.replace("\n", "").replace("\r", "");
      return bar;
    }
  }
}`
	flows := Analyze(code, "/srv/app/H.java", rules.LangJava)
	if hasFlowOfCategory(flows, taint.SnkLog) {
		t.Errorf("CRLF-stripping helper return should NOT produce a log-injection flow")
	}
}
