package scanner_test

import (
	"testing"

	"github.com/turenlabs/batou-core/taint/tsflow"
	"github.com/turenlabs/batou-rules/rules"
)

// TestCmdiTaintOnly checks whether the tsflow taint engine alone detects the
// List-fed ProcessBuilder vuln shape (00006) and stays clean on the safe shape.
func TestCmdiTaintOnly(t *testing.T) {
	vuln := `class V {
  void m(javax.servlet.http.HttpServletRequest request) {
    String param = request.getParameter("p");
    java.util.List<String> argList = new java.util.ArrayList<String>();
    argList.add("sh");
    argList.add("-c");
    argList.add("echo " + param);
    ProcessBuilder pb = new ProcessBuilder();
    pb.command(argList);
  }
}`
	vf := tsflow.Analyze(vuln, "/app/V.java", rules.LangJava)
	t.Logf("VULN List->pb.command(argList): taint flows=%d", len(vf))
	for _, f := range vf {
		t.Logf("  sink=%s cat=%v conf=%.2f", f.Sink.MethodName, f.Sink.Category, f.Confidence)
	}

	vuln2 := `class V2 {
  void m(javax.servlet.http.HttpServletRequest request) {
    String param = request.getParameter("p");
    java.util.List<String> argList = new java.util.ArrayList<String>();
    argList.add("echo " + param);
    ProcessBuilder pb = new ProcessBuilder(argList);
    pb.start();
  }
}`
	vf2 := tsflow.Analyze(vuln2, "/app/V2.java", rules.LangJava)
	t.Logf("VULN new ProcessBuilder(argList): taint flows=%d", len(vf2))

	safe := `class S {
  void m(javax.servlet.http.HttpServletRequest request) {
    String param = request.getParameter("p");
    String bar;
    int num = 86;
    if ((7 * 42) - num > 200) bar = "safe";
    else bar = param;
    java.util.List<String> argList = new java.util.ArrayList<String>();
    argList.add("echo " + bar);
    ProcessBuilder pb = new ProcessBuilder(argList);
    pb.start();
  }
}`
	sf := tsflow.Analyze(safe, "/app/S.java", rules.LangJava)
	t.Logf("SAFE const-true bar into list: taint flows=%d (want 0)", len(sf))
}

func TestCmdiCommandSink(t *testing.T) {
	src2 := `class C2 {
  void m(javax.servlet.http.HttpServletRequest request) {
    String param = request.getParameter("p");
    ProcessBuilder pb = new ProcessBuilder();
    pb.command("sh","-c",param);
  }
}`
	f2 := tsflow.Analyze(src2, "/app/C2.java", rules.LangJava)
	t.Logf("pb.command(lit,lit,param) direct scalar: flows=%d", len(f2))

	src3 := `class C3 {
  void m(javax.servlet.http.HttpServletRequest request) {
    String param = request.getParameter("p");
    java.util.List<String> argList = new java.util.ArrayList<String>();
    argList.add("echo " + param);
    ProcessBuilder pb = new ProcessBuilder();
    pb.command(argList);
  }
}`
	f3 := tsflow.Analyze(src3, "/app/C3.java", rules.LangJava)
	t.Logf("single add then pb.command(argList): flows=%d", len(f3))

	src4 := `class C4 {
  void m(javax.servlet.http.HttpServletRequest request) {
    String param = request.getParameter("p");
    String tainted = "echo " + param;
    ProcessBuilder pb = new ProcessBuilder();
    pb.command(tainted);
  }
}`
	f4 := tsflow.Analyze(src4, "/app/C4.java", rules.LangJava)
	t.Logf("scalar tainted var into pb.command(tainted): flows=%d", len(f4))
}
