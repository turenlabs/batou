package javaast

import (
	"testing"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

func scanJava(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangJava)
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.java",
		Content:  code,
		Language: rules.LangJava,
		Tree:     tree,
	}
	a := &JavaASTAnalyzer{}
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

func TestSQLConcatInExecuteQuery(t *testing.T) {
	code := `
class Handler {
    void handle(String userInput) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "GTSS-JAVAAST-001")
	if f == nil {
		t.Error("expected SQL injection finding for executeQuery with concat")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestSQLPreparedStatementSafe(t *testing.T) {
	code := `
class Handler {
    void handle(String userInput) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, userInput);
    }
}
`
	findings := scanJava(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-JAVAAST-001" {
			t.Errorf("should not flag PreparedStatement: %s", f.Title)
		}
	}
}

func TestRuntimeExec(t *testing.T) {
	code := `
class Handler {
    void handle(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "GTSS-JAVAAST-002")
	if f == nil {
		t.Error("expected command injection finding for Runtime.exec")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestRuntimeExecLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void handle() throws Exception {
        Runtime.getRuntime().exec("ls -la");
    }
}
`
	findings := scanJava(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-JAVAAST-002" {
			t.Errorf("should not flag Runtime.exec with literal: %s", f.Title)
		}
	}
}

func TestObjectInputStream(t *testing.T) {
	code := `
class Handler {
    void handle(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        Object obj = ois.readObject();
    }
}
`
	findings := scanJava(code)
	// Should find both the constructor and readObject
	count := 0
	for _, f := range findings {
		if f.RuleID == "GTSS-JAVAAST-003" {
			count++
		}
	}
	if count < 1 {
		t.Errorf("expected at least 1 deserialization finding, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestJNDILookup(t *testing.T) {
	code := `
class Handler {
    void handle(String name) throws Exception {
        InitialContext ctx = new InitialContext();
        ctx.lookup(name);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "GTSS-JAVAAST-004")
	if f == nil {
		t.Error("expected JNDI injection finding for lookup with variable")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestJNDILookupLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void handle() throws Exception {
        ctx.lookup("java:comp/env/jdbc/mydb");
    }
}
`
	findings := scanJava(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-JAVAAST-004" {
			t.Errorf("should not flag lookup with literal: %s", f.Title)
		}
	}
}

func TestClassForName(t *testing.T) {
	code := `
class Handler {
    void handle(String className) throws Exception {
        Class.forName(className);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "GTSS-JAVAAST-005")
	if f == nil {
		t.Error("expected unsafe reflection finding for Class.forName with variable")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestClassForNameLiteralSafe(t *testing.T) {
	code := `
class Handler {
    void handle() throws Exception {
        Class.forName("com.example.MyClass");
    }
}
`
	findings := scanJava(code)
	for _, f := range findings {
		if f.RuleID == "GTSS-JAVAAST-005" {
			t.Errorf("should not flag Class.forName with literal: %s", f.Title)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.java",
		Content:  "class X {}",
		Language: rules.LangJava,
		Tree:     nil,
	}
	a := &JavaASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "class X {}",
		Language: rules.LangPython,
	}
	a := &JavaASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `
// comment
class Handler {
    void handle(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
`
	findings := scanJava(code)
	f := findByRule(findings, "GTSS-JAVAAST-002")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 5 {
		t.Errorf("expected line 5, got %d", f.LineNumber)
	}
}
