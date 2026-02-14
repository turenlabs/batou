package jsast

import (
	"testing"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

func scanJS(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangJavaScript)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.js",
		Content:  code,
		Language: rules.LangJavaScript,
		Tree:     tree,
	}
	a := &JSASTAnalyzer{}
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

func TestEval(t *testing.T) {
	code := `
function handler(input) {
    eval(input);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "GTSS-JSAST-001")
	if f == nil {
		t.Error("expected eval finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestEvalLiteralSafe(t *testing.T) {
	code := `eval("1 + 2");`
	findings := scanJS(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-JSAST-001" {
			t.Errorf("should not flag eval with literal: %s", f.Title)
		}
	}
}

func TestInnerHTML(t *testing.T) {
	code := `
function handler(input) {
    element.innerHTML = input;
}
`
	findings := scanJS(code)
	f := findByRule(findings, "GTSS-JSAST-002")
	if f == nil {
		t.Error("expected innerHTML XSS finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestInnerHTMLLiteralSafe(t *testing.T) {
	code := `element.innerHTML = "<p>Hello</p>";`
	findings := scanJS(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-JSAST-002" {
			t.Errorf("should not flag innerHTML with literal: %s", f.Title)
		}
	}
}

func TestDocumentWrite(t *testing.T) {
	code := `
function handler(input) {
    document.write(input);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "GTSS-JSAST-003")
	if f == nil {
		t.Error("expected document.write XSS finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestChildProcessExec(t *testing.T) {
	code := `
var exec = require('child_process').exec;
function handler(cmd) {
    require('child_process').exec(cmd);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "GTSS-JSAST-004")
	if f == nil {
		t.Error("expected child_process.exec finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestNewFunction(t *testing.T) {
	code := `
function handler(code) {
    new Function(code);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "GTSS-JSAST-005")
	if f == nil {
		t.Error("expected new Function finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestNewFunctionLiteralSafe(t *testing.T) {
	code := `new Function("return 42");`
	findings := scanJS(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-JSAST-005" {
			t.Errorf("should not flag new Function with literal: %s", f.Title)
		}
	}
}

func TestSQLTemplateLiteral(t *testing.T) {
	code := "function handler(input) {\n" +
		"    var query = `SELECT * FROM users WHERE name = '${input}'`;\n" +
		"}\n"
	findings := scanJS(code)
	f := findByRule(findings, "GTSS-JSAST-006")
	if f == nil {
		t.Error("expected SQL template literal injection finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSQLStringConcat(t *testing.T) {
	code := `
function handler(input) {
    var query = "SELECT * FROM users WHERE name = '" + input + "'";
}
`
	findings := scanJS(code)
	f := findByRule(findings, "GTSS-JSAST-006")
	if f == nil {
		t.Error("expected SQL string concat injection finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.js",
		Content:  "eval(x)",
		Language: rules.LangJavaScript,
		Tree:     nil,
	}
	a := &JSASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "eval(x)",
		Language: rules.LangPython,
	}
	a := &JSASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestTypeScript(t *testing.T) {
	code := `
function handler(input: string) {
    eval(input);
}
`
	tree := ast.Parse([]byte(code), rules.LangTypeScript)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.ts",
		Content:  code,
		Language: rules.LangTypeScript,
		Tree:     tree,
	}
	a := &JSASTAnalyzer{}
	findings := a.Scan(ctx)
	f := findByRule(findings, "GTSS-JSAST-001")
	if f == nil {
		t.Error("expected eval finding for TypeScript")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
// comment
function handler(input) {
    eval(input);
}
`
	findings := scanJS(code)
	f := findByRule(findings, "GTSS-JSAST-001")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}
