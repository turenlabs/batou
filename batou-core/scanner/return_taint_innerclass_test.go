package scanner_test

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taintrule"
	"github.com/turenlabs/batou-core/testutil"
)

// These tests drive the FULL scan pipeline (regex → AST → taint → call graph)
// for the OWASP-Benchmark "dataflow through inner class" idiom that the tsflow
// return-taint fix targets:
//
//	String bar = new Test().doSomething(request, param);   // instance method on a
//	                                                        // freshly-constructed
//	                                                        // nested-class object
//
// where the helper returns one of its tainted parameters AFTER routing it
// through a chained-receiver builder expression
// (`new StringBuilder(param).append("_x").toString()`). Before the fix, taint
// died at the `sb.append(...).toString()` receiver-chain boundary inside the
// helper, so the helper's return-taint summary was empty and the source→sink
// flow was severed. See tsflow.callReceiverNode / callReceiverTaintedForPropagation.

func scanFiresCWE(t *testing.T, name, cwe, src string) bool {
	t.Helper()
	// Non-test, neutral path: a "testcode"/"test" path is dropped by isTestFile,
	// which would suppress every finding regardless of the analysis result.
	res := testutil.ScanContent(t, "/srv/app/handler/"+name+".java", src)
	for _, f := range res.Findings {
		if f.CWEID == cwe {
			return true
		}
	}
	return false
}

// TestReturnTaint_InnerClassBuilderChain_Vulnerable asserts the SQLi/XSS/cmdi
// flow now fires end-to-end for the inner-class builder-chain idiom.
func TestReturnTaint_InnerClassBuilderChain_Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		cwe  string
		src  string
	}{
		{
			name: "Sqli",
			cwe:  "CWE-89",
			src: `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class Sqli extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = new Test().doSomething(request, param);
    String sql = "SELECT * FROM users WHERE name = '" + bar + "'";
    java.sql.Connection c = org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
    java.sql.Statement st = c.createStatement();
    st.executeQuery(sql);
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      StringBuilder sb = new StringBuilder(param);
      String bar = sb.append("_x").toString();
      return bar;
    }
  }
}`,
		},
		{
			name: "Xss",
			cwe:  "CWE-79",
			src: `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class Xss extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = "";
    if (request.getHeader("Referer") != null) { param = request.getHeader("Referer"); }
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
}`,
		},
		{
			name: "Cmdi",
			cwe:  "CWE-78",
			src: `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class Cmdi extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = new Test().doSomething(request, param);
    String[] args = {"sh", "-c", bar};
    Runtime.getRuntime().exec(args);
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      StringBuilder sb = new StringBuilder(param);
      String bar = sb.append("_x").toString();
      return bar;
    }
  }
}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !scanFiresCWE(t, tc.name, tc.cwe, tc.src) {
				t.Errorf("expected %s flow through inner-class builder-chain helper, got none", tc.cwe)
			}
		})
	}
}

// TestReturnTaint_InnerClassSanitized_Clean asserts the broadened
// chained-receiver propagation does NOT blanket-taint: when the helper routes
// the param through a CRLF-stripping replace() chain or an HTML escaper, the
// corresponding flow must stay clean. This guards the precision requirement —
// only genuine taint-returning helpers light up, sanitizing ones do not.
func TestReturnTaint_InnerClassSanitized_Clean(t *testing.T) {
	// Helper escapes the param for HTML, so the XSS sink is safe.
	escaped := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class XssSafe extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = "";
    if (request.getHeader("Referer") != null) { param = request.getHeader("Referer"); }
    String bar = new Test().doSomething(request, param);
    response.getWriter().print(bar);
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      String bar = org.springframework.web.util.HtmlUtils.htmlEscape(param);
      return bar;
    }
  }
}`
	if scanFiresCWE(t, "XssSafe", "CWE-79", escaped) {
		t.Error("htmlEscape() helper return should NOT produce an XSS flow")
	}

	// Helper strips CRLF, so the log/header sink is safe — exercises the
	// in-chain-sanitizer gate on the broadened propagation.
	crlf := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class LogSafe extends HttpServlet {
  private static final Logger log = LoggerFactory.getLogger(LogSafe.class);
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
	// CWE-117 is log injection; CWE-93 CRLF. Neither should fire.
	if scanFiresCWE(t, "LogSafe", "CWE-117", crlf) || scanFiresCWE(t, "LogSafe", "CWE-93", crlf) {
		t.Error("CRLF replace() chain in helper return should NOT produce a log/CRLF flow")
	}
}
