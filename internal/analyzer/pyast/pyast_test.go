package pyast

import (
	"testing"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

func scanPython(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangPython)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  code,
		Language: rules.LangPython,
		Tree:     tree,
	}
	a := &PythonASTAnalyzer{}
	return a.Scan(ctx)
}

func findByRule(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestEvalExec(t *testing.T) {
	code := `
def handler(request):
    name = request.args.get('name')
    eval(name)
    exec(name)
`
	findings := scanPython(code)
	count := 0
	for _, f := range findings {
		if f.RuleID == "GTSS-PYAST-001" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 eval/exec findings, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestEvalLiteralSafe(t *testing.T) {
	code := `
eval("1 + 2")
exec("print('hello')")
`
	findings := scanPython(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-PYAST-001" {
			t.Errorf("should not flag literal eval/exec: %s", f.Title)
		}
	}
}

func TestOsSystem(t *testing.T) {
	code := `
import os
def handler(name):
    os.system("rm " + name)
`
	findings := scanPython(code)
	f := findByRule(findings, "GTSS-PYAST-001")
	if f == nil {
		t.Error("expected finding for os.system with variable")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestSubprocessShellTrue(t *testing.T) {
	code := `
import subprocess
def handler(cmd):
    subprocess.call(cmd, shell=True)
    subprocess.run(cmd, shell=True)
`
	findings := scanPython(code)
	count := 0
	for _, f := range findings {
		if f.RuleID == "GTSS-PYAST-002" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 subprocess shell=True findings, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSubprocessNoShellSafe(t *testing.T) {
	code := `
import subprocess
subprocess.call(["ls", "-la"])
subprocess.run(cmd, shell=False)
`
	findings := scanPython(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-PYAST-002" {
			t.Errorf("should not flag subprocess without shell=True: %s", f.Title)
		}
	}
}

func TestPickleLoads(t *testing.T) {
	code := `
import pickle
data = pickle.loads(request.data)
`
	findings := scanPython(code)
	f := findByRule(findings, "GTSS-PYAST-003")
	if f == nil {
		t.Error("expected finding for pickle.loads with variable")
	}
}

func TestOpenVariable(t *testing.T) {
	code := `
def handler(path):
    f = open(path)
`
	findings := scanPython(code)
	f := findByRule(findings, "GTSS-PYAST-004")
	if f == nil {
		t.Error("expected finding for open() with variable path")
	}
}

func TestOpenLiteralSafe(t *testing.T) {
	code := `
f = open("/etc/config.yaml")
`
	findings := scanPython(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-PYAST-004" {
			t.Errorf("should not flag open() with literal path: %s", f.Title)
		}
	}
}

func TestSQLPercentFormat(t *testing.T) {
	code := `
def handler(name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
`
	findings := scanPython(code)
	f := findByRule(findings, "GTSS-PYAST-005")
	if f == nil {
		t.Error("expected finding for SQL % formatting")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestSQLFString(t *testing.T) {
	code := `
def handler(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
`
	findings := scanPython(code)
	f := findByRule(findings, "GTSS-PYAST-005")
	if f == nil {
		t.Error("expected finding for SQL f-string injection")
		for _, f := range findings {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "eval(x)",
		Language: rules.LangPython,
		Tree:     nil,
	}
	a := &PythonASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.go",
		Content:  "eval(x)",
		Language: rules.LangGo,
	}
	a := &PythonASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
# comment
def handler(x):
    eval(x)
`
	findings := scanPython(code)
	f := findByRule(findings, "GTSS-PYAST-001")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}
