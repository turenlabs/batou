package gvyast

import (
	"strings"
	"testing"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

func scanGvy(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangGroovy)
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.groovy",
		Content:  code,
		Language: rules.LangGroovy,
		Tree:     tree,
	}
	a := &GroovyASTAnalyzer{}
	return a.Scan(ctx)
}

func TestStringExecuteInterpolation(t *testing.T) {
	code := `
class Foo {
    def doStuff(userInput) {
        "ls ${userInput}".execute()
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-GVY-AST-001" && f.Severity == rules.Critical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected critical command injection finding for string.execute() with interpolation")
	}
}

func TestStringExecuteVariable(t *testing.T) {
	code := `
class Foo {
    def doStuff() {
        def cmd = getCommand()
        cmd.execute()
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-GVY-AST-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for variable.execute()")
	}
}

func TestGroovyShellEvaluate(t *testing.T) {
	code := `
class Foo {
    def doStuff(userInput) {
        new GroovyShell().evaluate(userInput)
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-GVY-AST-002" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected code injection finding for GroovyShell.evaluate()")
	}
}

func TestRuntimeExec(t *testing.T) {
	code := `
class Foo {
    def doStuff(userInput) {
        Runtime.getRuntime().exec(userInput)
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-GVY-AST-003" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for Runtime.exec")
	}
}

func TestGStringSQLDeclaration(t *testing.T) {
	code := `
class Foo {
    def doStuff(userId) {
        def sql = "SELECT * FROM users WHERE id = ${userId}"
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-GVY-AST-005" && strings.Contains(f.Title, "variable") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for GString SQL variable declaration")
	}
}

func TestGStringSQLSafe(t *testing.T) {
	code := `
class Foo {
    def doStuff() {
        def query = "SELECT * FROM users WHERE id = 1"
    }
}
`
	findings := scanGvy(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-GVY-AST-005" {
			t.Error("unexpected SQL injection finding for safe query without interpolation")
		}
	}
}

func TestSafeCode(t *testing.T) {
	code := `
class Foo {
    def greet(name) {
        return "Hello, ${name}"
    }
}
`
	findings := scanGvy(t, code)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe code, got %d", len(findings))
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.groovy",
		Content:  "class Foo {}",
		Language: rules.LangGroovy,
		Tree:     nil,
	}
	a := &GroovyASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/main.go",
		Content:  "package main",
		Language: rules.LangGo,
	}
	a := &GroovyASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}
