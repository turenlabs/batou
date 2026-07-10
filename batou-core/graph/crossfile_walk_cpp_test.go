package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// The C/C++ cross-file caller-impact walker (crossfile_walk_cpp.go) is the live
// path the finalize/cross-file pass uses to connect a tainted argument (or a
// tainted return value) across a C/C++ function-call boundary for
// rules.LangC / rules.LangCPP. It had ZERO graph-package unit coverage. These
// tests exercise the pure helpers (cppAssignEq, cppBindingName,
// cppSinkLineSanitizerNeutralises, loadCPPSinkPatterns, scanCPPBodyForSinks,
// scanCPPBodyForTaintedReturn) and the AnalyzeCallerImpactCPP entry point
// (constructed caller/callee FuncNodes, mirroring crossfile_walk_go_samepkg).

func TestCPPCrossFile_AssignEq(t *testing.T) {
	cases := []struct {
		line string
		want bool // want a real assignment '=' (index >= 0)
	}{
		{"std::string n = req.query(\"a\")", true},
		{"int x = 5", true},
		{"a == b", false},        // equality
		{"x += 1", false},        // compound
		{"y != z", false},        // not-equal
		{"if (a >= b) return;", false},
		{"foo(bar)", false},      // no '='
	}
	for _, c := range cases {
		got := cppAssignEq(c.line) >= 0
		if got != c.want {
			t.Errorf("cppAssignEq(%q) >= 0 = %v, want %v (idx=%d)", c.line, got, c.want, cppAssignEq(c.line))
		}
	}
}

func TestCPPCrossFile_BindingName(t *testing.T) {
	cases := map[string]string{
		"std::string n": "n",
		"const char* p": "p",
		"auto x":        "x",
		"int count":     "count",
	}
	for lhs, want := range cases {
		if got := cppBindingName(lhs); got != want {
			t.Errorf("cppBindingName(%q) = %q, want %q", lhs, got, want)
		}
	}
}

func TestCPPCrossFile_SinkLineSanitizerNeutralises(t *testing.T) {
	// Injection-class sink categories: a same-line sanitizer call suppresses.
	for _, c := range []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkFileRead, taint.SnkFileWrite, taint.SnkURLFetch} {
		if !cppSinkLineSanitizerNeutralises(c) {
			t.Errorf("cppSinkLineSanitizerNeutralises(%v) = false, want true", c)
		}
	}
	// Crypto is NOT a same-line-sanitizer-suppressible category here.
	if cppSinkLineSanitizerNeutralises(taint.SnkCrypto) {
		t.Errorf("cppSinkLineSanitizerNeutralises(SnkCrypto) = true, want false")
	}
}

func TestCPPCrossFile_LoadSinkPatterns(t *testing.T) {
	for _, lang := range []rules.Language{rules.LangCPP, rules.LangC} {
		if got := loadCPPSinkPatterns(lang); len(got) == 0 {
			t.Errorf("loadCPPSinkPatterns(%v) returned 0 patterns, want > 0", lang)
		}
	}
}

func TestCPPCrossFile_ScanBodyForTaintedReturn(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"direct source return", `std::string getName() { return getenv("X"); }`, true},
		{"bound-then-return", "std::string f(const Request& req) {\n  std::string n = req.query(\"a\");\n  return n;\n}", true},
		{"literal return", `std::string f() { return "static"; }`, false},
		{"sanitized return", `int f() { return std::stoi(getenv("X")); }`, false},
	}
	for _, c := range cases {
		_, got := scanCPPBodyForTaintedReturn(c.body)
		if got != c.want {
			t.Errorf("%s: scanCPPBodyForTaintedReturn returned %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCPPCrossFile_ScanBodyForSinks(t *testing.T) {
	// A body with a command-exec sink yields at least one SinkRef, with a
	// file-absolute line number (startLine offset applied).
	body := "void run(const char* p) {\n  system(p);\n}"
	sinks := scanCPPBodyForSinks(body, 10, rules.LangCPP)
	if len(sinks) == 0 {
		t.Fatalf("scanCPPBodyForSinks found no sink for system(p); patterns=%d", len(loadCPPSinkPatterns(rules.LangCPP)))
	}
	foundCmd := false
	for _, s := range sinks {
		if s.Line < 10 {
			t.Errorf("SinkRef.Line %d < startLine 10 (offset not applied)", s.Line)
		}
		if s.SinkCategory == taint.SnkCommand {
			foundCmd = true
		}
	}
	if !foundCmd {
		t.Errorf("expected a SnkCommand SinkRef for system(p); got %+v", sinks)
	}
}

// TestCPPCrossFile_AnalyzeCallerImpact_PassesTaintToCalleeSink: the end-to-end
// walk — a caller that reads a request source into a local and passes it to a
// callee whose signature records a sink on that parameter yields a finding.
func TestCPPCrossFile_AnalyzeCallerImpact_PassesTaintToCalleeSink(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	callerPath := filepath.Join(root, "handler.cpp")
	calleePath := filepath.Join(root, "helper.cpp")

	caller := &FuncNode{
		ID:        FuncID(callerPath, "handle"),
		FilePath:  callerPath,
		Name:      "handle",
		Language:  rules.LangCPP,
		StartLine: 1,
		EndLine:   4,
	}
	callee := &FuncNode{
		ID:        FuncID(calleePath, "runQuery"),
		FilePath:  calleePath,
		Name:      "runQuery",
		Language:  rules.LangCPP,
		StartLine: 1,
		EndLine:   3,
		// Pre-populate the callee signature so ensureCPPCalleeSinks short-circuits
		// (no on-disk file read needed): param 0 reaches a command sink.
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "system", Line: 2, ArgFromParam: 0}},
		},
	}
	cg.AddNode(caller)
	cg.AddNode(callee)

	callerContent := "void handle(const Request& req) {\n" +
		"  std::string c = req.query(\"c\");\n" +
		"  runQuery(c);\n" +
		"}\n"

	findings := AnalyzeCallerImpactCPP(cg, caller, callee, callerContent)
	if len(findings) == 0 {
		t.Errorf("expected a cross-file finding for req.query -> runQuery(c) -> system param; got none")
	}
}
