package scanner_test

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taintrule"
	"github.com/turenlabs/batou-core/testutil"
)

func scanFires78(t *testing.T, name, src string) bool {
	res := testutil.ScanContent(t, "/app/handler/"+name+".java", src)
	for _, f := range res.Findings {
		if f.CWEID == "CWE-78" {
			return true
		}
	}
	return false
}

// TestCmdiRepro isolates which structural element severs taint in 02429.
func TestCmdiRepro(t *testing.T) {
	// Variant A: bare static helper that returns param directly.
	a := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class A extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = doSomething(request, param);
    String[] args = {"sh","-c",bar};
    Runtime.getRuntime().exec(args);
  }
  private static String doSomething(HttpServletRequest request, String param) {
    return param;
  }
}`
	t.Logf("VariantA (bare static helper, return param): fires=%v", scanFires78(t, "A", a))

	// Variant B: helper returns through thing.doSomething(param) inner call.
	b := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class B extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    String bar = doSomething(request, param);
    String[] args = {"sh","-c",bar};
    Runtime.getRuntime().exec(args);
  }
  private static String doSomething(HttpServletRequest request, String param) {
    org.owasp.benchmark.helpers.ThingInterface thing = org.owasp.benchmark.helpers.ThingFactory.createThing();
    String bar = thing.doSomething(param);
    return bar;
  }
}`
	t.Logf("VariantB (helper via thing.doSomething(param)): fires=%v", scanFires78(t, "B", b))

	// Variant C: like B but using SeparateClassRequest source.
	c := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class C extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheParameter("p");
    String bar = doSomething(request, param);
    String[] args = {"sh","-c",bar};
    Runtime.getRuntime().exec(args);
  }
  private static String doSomething(HttpServletRequest request, String param) {
    org.owasp.benchmark.helpers.ThingInterface thing = org.owasp.benchmark.helpers.ThingFactory.createThing();
    String bar = thing.doSomething(param);
    return bar;
  }
}`
	t.Logf("VariantC (SeparateClassRequest + thing.doSomething): fires=%v", scanFires78(t, "C", c))

	// Variant D: direct param into args (no helper) using SeparateClassRequest.
	d := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class D extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheParameter("p");
    String[] args = {"sh","-c",param};
    Runtime.getRuntime().exec(args);
  }
}`
	t.Logf("VariantD (SeparateClassRequest direct to exec): fires=%v", scanFires78(t, "D", d))

	// Variant E: full 02429 shape — branch-assigned args declared null, helper return.
	e := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class E extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheParameter("p");
    if (param == null) param = "";
    String bar = doSomething(request, param);
    String cmd = "";
    String a1 = "";
    String a2 = "";
    String[] args = null;
    String osName = System.getProperty("os.name");
    if (osName.indexOf("Windows") != -1) {
      a1 = "cmd.exe";
      a2 = "/c";
      cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
      args = new String[] {a1, a2, cmd, bar};
    } else {
      a1 = "sh";
      a2 = "-c";
      cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("ping -c1 ");
      args = new String[] {a1, a2, cmd + bar};
    }
    Runtime r = Runtime.getRuntime();
    Process p = r.exec(args);
  }
  private static String doSomething(HttpServletRequest request, String param) {
    org.owasp.benchmark.helpers.ThingInterface thing = org.owasp.benchmark.helpers.ThingFactory.createThing();
    String bar = thing.doSomething(param);
    return bar;
  }
}`
	t.Logf("VariantE (full 02429 branch shape): fires=%v", scanFires78(t, "E", e))

	// Variant F: like E but helper returns param directly (no thing indirection).
	f := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class F extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    if (param == null) param = "";
    String bar = doSomething(request, param);
    String[] args = null;
    String osName = System.getProperty("os.name");
    if (osName.indexOf("Windows") != -1) {
      args = new String[] {"cmd.exe", "/c", "echo", bar};
    } else {
      args = new String[] {"sh", "-c", "ping " + bar};
    }
    Runtime r = Runtime.getRuntime();
    Process p = r.exec(args);
  }
  private static String doSomething(HttpServletRequest request, String param) {
    return param;
  }
}`
	t.Logf("VariantF (branch shape, direct return): fires=%v", scanFires78(t, "F", f))
}

// TestCmdiFPRepro reproduces the const-true if-guard SAFE FP (00396 shape).
func TestCmdiFPRepro(t *testing.T) {
	// G: exact 00396 shape — const-true if-guard, param in ELSE (dead) branch.
	g := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class G extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    if (param == null) param = "";
    String bar;
    int num = 86;
    if ((7 * 42) - num > 200) bar = "This_should_always_happen";
    else bar = param;
    String a1 = "sh";
    String a2 = "-c";
    String[] args = {a1, a2, "echo " + bar};
    ProcessBuilder pb = new ProcessBuilder();
    pb.command(args);
    Process p = pb.start();
  }
}`
	gres := testutil.ScanContent(t, "/app/handler/G.java", g)
	t.Logf("VariantG (00396 const-true if-guard, SAFE): %d findings", len(gres.Findings))
	for _, f := range gres.Findings {
		t.Logf("  G: rule=%s cwe=%s line=%d conf=%.2f", f.RuleID, f.CWEID, f.LineNumber, f.ConfidenceScore)
	}

	// H: const-false guard — param in ELSE which IS taken → VULN (want true).
	h := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class H extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    if (param == null) param = "";
    String bar;
    int num = 106;
    bar = (7 * 42) - num > 200 ? "This should never happen" : param;
    String[] args = {"sh", "-c", "echo " + bar};
    ProcessBuilder pb = new ProcessBuilder();
    pb.command(args);
    Process p = pb.start();
  }
}`
	t.Logf("VariantH (00294 const-false ternary, VULN): fires=%v (want true)", scanFires78(t, "H", h))

	// I: const-true ternary SAFE (00396/00814 ternary form).
	i := `package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class I extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("p");
    if (param == null) param = "";
    String bar;
    int num = 86;
    bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    String[] args = {"sh", "-c", "echo " + bar};
    ProcessBuilder pb = new ProcessBuilder();
    pb.command(args);
    Process p = pb.start();
  }
}`
	t.Logf("VariantI (const-true ternary, SAFE): fires=%v (want false)", scanFires78(t, "I", i))
}
