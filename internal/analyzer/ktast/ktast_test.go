package ktast

import (
	"strings"
	"testing"

	"github.com/turen/gtss/internal/ast"
	"github.com/turen/gtss/internal/rules"
)

func scanKt(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangKotlin)
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.kt",
		Content:  code,
		Language: rules.LangKotlin,
		Tree:     tree,
	}
	a := &KotlinASTAnalyzer{}
	return a.Scan(ctx)
}

func TestRawQueryConcat(t *testing.T) {
	code := `
fun getUser(db: SQLiteDatabase, userId: String) {
    db.rawQuery("SELECT * FROM users WHERE id = " + userId, null)
}
`
	findings := scanKt(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-KT-AST-001" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for rawQuery with concat")
	}
}

func TestRawQuerySafe(t *testing.T) {
	code := `
fun getUser(db: SQLiteDatabase, userId: String) {
    db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))
}
`
	findings := scanKt(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-KT-AST-001" {
			t.Error("unexpected SQL injection finding for parameterized query")
		}
	}
}

func TestAddJavascriptInterface(t *testing.T) {
	code := `
fun setupWebView(webView: WebView) {
    webView.addJavascriptInterface(bridge, "Android")
}
`
	findings := scanKt(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-KT-AST-002" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for addJavascriptInterface")
	}
}

func TestSensitiveSharedPrefs(t *testing.T) {
	code := `
fun save(prefs: SharedPreferences) {
    prefs.edit().putString("password", password).apply()
}
`
	findings := scanKt(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-KT-AST-003" {
			found = true
			if !strings.Contains(f.Title, "SharedPreferences") {
				t.Errorf("expected SharedPreferences in title, got %s", f.Title)
			}
			break
		}
	}
	if !found {
		t.Error("expected finding for sensitive data in SharedPreferences")
	}
}

func TestNonSensitiveSharedPrefs(t *testing.T) {
	code := `
fun save(prefs: SharedPreferences) {
    prefs.edit().putString("theme", "dark").apply()
}
`
	findings := scanKt(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-KT-AST-003" {
			t.Error("unexpected finding for non-sensitive SharedPreferences key")
		}
	}
}

func TestRuntimeExec(t *testing.T) {
	code := `
fun runCommand(cmd: String) {
    Runtime.getRuntime().exec(cmd)
}
`
	findings := scanKt(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-KT-AST-004" {
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

func TestSafeCode(t *testing.T) {
	code := `
fun greet(name: String): String {
    return "Hello, $name!"
}
`
	findings := scanKt(t, code)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe code, got %d", len(findings))
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.kt",
		Content:  "fun main() {}",
		Language: rules.LangKotlin,
		Tree:     nil,
	}
	a := &KotlinASTAnalyzer{}
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
	a := &KotlinASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}
