package rustast

import (
	"strings"
	"testing"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

func scanRust(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangRust)
	ctx := &rules.ScanContext{
		FilePath: "/app/src/main.rs",
		Content:  code,
		Language: rules.LangRust,
		Tree:     tree,
	}
	a := &RustASTAnalyzer{}
	return a.Scan(ctx)
}

func TestUnsafeTransmute(t *testing.T) {
	code := `
fn convert(x: u32) -> f32 {
    unsafe {
        std::mem::transmute::<u32, f32>(x)
    }
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-001" && strings.Contains(f.Title, "transmute") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for transmute in unsafe block")
	}
}

func TestUnsafeRawPointerDeref(t *testing.T) {
	code := `
fn deref_raw(p: *const i32) -> i32 {
    unsafe {
        *p
    }
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-001" && strings.Contains(f.Title, "Raw pointer") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for raw pointer dereference in unsafe block")
	}
}

func TestSafeCodeNoUnsafeFindings(t *testing.T) {
	code := `
fn add(a: i32, b: i32) -> i32 {
    a + b
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-001" {
			t.Error("unexpected unsafe finding in safe code")
		}
	}
}

func TestFormatSQLInjection(t *testing.T) {
	code := `
fn get_user(id: &str) -> String {
    let query = format!("SELECT * FROM users WHERE id = {}", id);
    query
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-002" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for format!()")
	}
}

func TestFormatNonSQL(t *testing.T) {
	code := `
fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-002" {
			t.Error("unexpected SQL injection finding for non-SQL format!()")
		}
	}
}

func TestCommandInjectionShell(t *testing.T) {
	code := `
fn run_cmd(input: &str) {
    let cmd = std::process::Command::new("sh").arg("-c").arg(input).spawn();
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-003" && f.Severity == rules.Critical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected critical command injection finding for shell execution")
	}
}

func TestCommandInjectionVarArg(t *testing.T) {
	code := `
fn run_cmd(filename: &str) {
    let cmd = std::process::Command::new("ls").arg(filename).spawn();
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for variable argument")
	}
}

func TestSafeCommand(t *testing.T) {
	code := `
fn list_files() {
    let cmd = std::process::Command::new("ls").arg("-la").spawn();
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-003" && f.Severity == rules.Critical {
			t.Error("unexpected critical finding for command with literal args")
		}
	}
}

func TestUnsafeUnwrapOnParse(t *testing.T) {
	code := `
fn parse_input(s: &str) -> i32 {
    s.parse::<i32>().unwrap()
}
`
	findings := scanRust(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-004" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for .unwrap() on parse()")
	}
}

func TestSafeUnwrapOnVec(t *testing.T) {
	code := `
fn first() -> i32 {
    let v = vec![1, 2, 3];
    v.first().unwrap()
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-004" {
			t.Error("unexpected finding for unwrap on non-network call")
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/src/main.rs",
		Content:  "fn main() {}",
		Language: rules.LangRust,
		Tree:     nil,
	}
	a := &RustASTAnalyzer{}
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
	a := &RustASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `fn main() {
    unsafe {
        std::mem::transmute::<u32, f32>(0);
    }
}
`
	findings := scanRust(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-RUST-AST-001" && f.LineNumber < 1 {
			t.Errorf("expected positive line number, got %d", f.LineNumber)
		}
	}
}
