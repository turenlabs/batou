package cast

import (
	"testing"

	"github.com/turenlabs/batou/internal/ast"
	"github.com/turenlabs/batou/internal/rules"
)

func scanC(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangC)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.c",
		Content:  code,
		Language: rules.LangC,
		Tree:     tree,
	}
	a := &CASTAnalyzer{}
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

func countByRule(findings []rules.Finding, ruleID string) int {
	count := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			count++
		}
	}
	return count
}

func TestBannedFunctions(t *testing.T) {
	code := `
#include <string.h>
void handler(char *input) {
    char buf[64];
    gets(buf);
    strcpy(buf, input);
    strcat(buf, input);
}
`
	findings := scanC(code)
	count := countByRule(findings, "BATOU-CAST-001")
	if count != 3 {
		t.Errorf("expected 3 banned function findings, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSprintfBanned(t *testing.T) {
	code := `
void handler(char *input) {
    char buf[64];
    sprintf(buf, "%s", input);
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-001")
	if f == nil {
		t.Error("expected banned function finding for sprintf")
	}
}

func TestFormatStringVulnerability(t *testing.T) {
	code := `
void handler(char *input) {
    printf(input);
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-002")
	if f == nil {
		t.Error("expected format string vulnerability finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestFormatStringLiteralSafe(t *testing.T) {
	code := `
void handler(char *input) {
    printf("%s\n", input);
}
`
	findings := scanC(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-CAST-002" {
			t.Errorf("should not flag printf with literal format: %s", f.Title)
		}
	}
}

func TestSystemVariable(t *testing.T) {
	code := `
void handler(char *cmd) {
    system(cmd);
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-003")
	if f == nil {
		t.Error("expected command injection finding for system()")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSystemLiteralSafe(t *testing.T) {
	code := `
void handler() {
    system("ls -la");
}
`
	findings := scanC(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-CAST-003" {
			t.Errorf("should not flag system with literal: %s", f.Title)
		}
	}
}

func TestPopenVariable(t *testing.T) {
	code := `
void handler(char *cmd) {
    FILE *fp = popen(cmd, "r");
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-003")
	if f == nil {
		t.Error("expected command injection finding for popen()")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestCPP(t *testing.T) {
	code := `
#include <cstdlib>
void handler(char *cmd) {
    system(cmd);
}
`
	tree := ast.Parse([]byte(code), rules.LangCPP)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.cpp",
		Content:  code,
		Language: rules.LangCPP,
		Tree:     tree,
	}
	a := &CASTAnalyzer{}
	findings := a.Scan(ctx)
	f := findByRule(findings, "BATOU-CAST-003")
	if f == nil {
		t.Error("expected finding for C++ system()")
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.c",
		Content:  "void f() { system(x); }",
		Language: rules.LangC,
		Tree:     nil,
	}
	a := &CASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "system(x)",
		Language: rules.LangPython,
	}
	a := &CASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
/* comment */
void handler(char *input) {
    printf(input);
}
`
	findings := scanC(code)
	f := findByRule(findings, "BATOU-CAST-002")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}
