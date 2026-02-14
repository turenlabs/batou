package csast

import (
	"strings"
	"testing"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

func scanCS(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangCSharp)
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.cs",
		Content:  code,
		Language: rules.LangCSharp,
		Tree:     tree,
	}
	a := &CSharpASTAnalyzer{}
	return a.Scan(ctx)
}

func TestSqlCommandConcat(t *testing.T) {
	code := `
using System.Data.SqlClient;
class Foo {
    void Bar(string userId) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + userId, conn);
    }
}
`
	findings := scanCS(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-001" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for SqlCommand with concat")
	}
}

func TestSqlCommandSafe(t *testing.T) {
	code := `
using System.Data.SqlClient;
class Foo {
    void Bar() {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
    }
}
`
	findings := scanCS(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-001" {
			t.Error("unexpected SQL injection finding for parameterized query")
		}
	}
}

func TestBinaryFormatter(t *testing.T) {
	code := `
using System.Runtime.Serialization.Formatters.Binary;
class Foo {
    void Bar() {
        var bf = new BinaryFormatter();
    }
}
`
	findings := scanCS(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-002" && strings.Contains(f.Title, "BinaryFormatter") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected insecure deserializer finding for BinaryFormatter")
	}
}

func TestObjectStateFormatter(t *testing.T) {
	code := `
class Foo {
    void Bar() {
        var osf = new ObjectStateFormatter();
    }
}
`
	findings := scanCS(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-002" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected insecure deserializer finding for ObjectStateFormatter")
	}
}

func TestSafeSerializer(t *testing.T) {
	code := `
class Foo {
    void Bar() {
        var json = new JsonSerializer();
    }
}
`
	findings := scanCS(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-002" {
			t.Error("unexpected deserializer finding for JsonSerializer")
		}
	}
}

func TestRegexWithoutTimeout(t *testing.T) {
	code := `
using System.Text.RegularExpressions;
class Foo {
    void Bar(string pattern) {
        var r = new Regex(pattern);
    }
}
`
	findings := scanCS(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ReDoS finding for Regex without timeout")
	}
}

func TestRegexWithLiteral(t *testing.T) {
	code := `
using System.Text.RegularExpressions;
class Foo {
    void Bar() {
        var r = new Regex("^[a-z]+$");
    }
}
`
	findings := scanCS(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-003" {
			t.Error("unexpected ReDoS finding for Regex with literal pattern")
		}
	}
}

func TestProcessStart(t *testing.T) {
	code := `
using System.Diagnostics;
class Foo {
    void Bar(string userCmd) {
        Process.Start(userCmd);
    }
}
`
	findings := scanCS(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-004" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for Process.Start")
	}
}

func TestExecuteSqlRawInterpolation(t *testing.T) {
	code := `
class Foo {
    void Bar(int id) {
        context.Database.ExecuteSqlRaw($"DELETE FROM users WHERE id = {id}");
    }
}
`
	findings := scanCS(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-005" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected EF SQL injection finding for ExecuteSqlRaw with interpolation")
	}
}

func TestExecuteSqlRawSafe(t *testing.T) {
	code := `
class Foo {
    void Bar() {
        context.Database.ExecuteSqlRaw("DELETE FROM temp_table");
    }
}
`
	findings := scanCS(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-CS-AST-005" {
			t.Error("unexpected EF SQL injection finding for literal query")
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.cs",
		Content:  "class Foo {}",
		Language: rules.LangCSharp,
		Tree:     nil,
	}
	a := &CSharpASTAnalyzer{}
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
	a := &CSharpASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}
