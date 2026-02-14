package rubyast

import (
	"testing"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

func scanRuby(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangRuby)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.rb",
		Content:  code,
		Language: rules.LangRuby,
		Tree:     tree,
	}
	a := &RubyASTAnalyzer{}
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

func TestEvalVariable(t *testing.T) {
	code := `
def handler(input)
    eval(input)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "GTSS-RUBYAST-001")
	if f == nil {
		t.Error("expected eval finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestInstanceEval(t *testing.T) {
	code := `
def handler(input)
    instance_eval(input)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "GTSS-RUBYAST-001")
	if f == nil {
		t.Error("expected instance_eval finding")
	}
}

func TestEvalLiteralSafe(t *testing.T) {
	code := `eval("1 + 2")`
	findings := scanRuby(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-RUBYAST-001" {
			t.Errorf("should not flag eval with literal: %s", f.Title)
		}
	}
}

func TestSystemVariable(t *testing.T) {
	code := `
def handler(cmd)
    system(cmd)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "GTSS-RUBYAST-002")
	if f == nil {
		t.Error("expected command injection finding for system()")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestExecVariable(t *testing.T) {
	code := `
def handler(cmd)
    exec(cmd)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "GTSS-RUBYAST-002")
	if f == nil {
		t.Error("expected command injection finding for exec()")
	}
}

func TestSystemLiteralSafe(t *testing.T) {
	code := `system("ls -la")`
	findings := scanRuby(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-RUBYAST-002" {
			t.Errorf("should not flag system with literal: %s", f.Title)
		}
	}
}

func TestSendVariable(t *testing.T) {
	code := `
def handler(input)
    send(input.to_sym, arg)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "GTSS-RUBYAST-003")
	if f == nil {
		t.Error("expected dynamic dispatch finding for send()")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestIOPopen(t *testing.T) {
	code := `
def handler(cmd)
    IO.popen(cmd)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "GTSS-RUBYAST-004")
	if f == nil {
		t.Error("expected IO.popen finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestERBNew(t *testing.T) {
	code := `
def handler(template)
    ERB.new(template).result
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "GTSS-RUBYAST-005")
	if f == nil {
		t.Error("expected ERB.new finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestERBNewLiteralSafe(t *testing.T) {
	code := `ERB.new("<p>Hello</p>").result`
	findings := scanRuby(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-RUBYAST-005" {
			t.Errorf("should not flag ERB.new with literal: %s", f.Title)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.rb",
		Content:  "eval(x)",
		Language: rules.LangRuby,
		Tree:     nil,
	}
	a := &RubyASTAnalyzer{}
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
	a := &RubyASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
# comment
def handler(input)
    eval(input)
end
`
	findings := scanRuby(code)
	f := findByRule(findings, "GTSS-RUBYAST-001")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}
