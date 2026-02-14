package swiftast

import (
	"strings"
	"testing"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

func scanSwift(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangSwift)
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.swift",
		Content:  code,
		Language: rules.LangSwift,
		Tree:     tree,
	}
	a := &SwiftASTAnalyzer{}
	return a.Scan(ctx)
}

func TestSQLiteInjection(t *testing.T) {
	code := `
import SQLite3
func getUser(db: OpaquePointer, userId: String) {
    let query = "SELECT * FROM users WHERE id = \(userId)"
    sqlite3_prepare_v2(db, query, -1, &stmt, nil)
}
`
	findings := scanSwift(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-SWIFT-AST-001" {
			found = true
			if f.Severity != rules.Critical && f.Severity != rules.High {
				t.Errorf("expected Critical or High severity, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for sqlite3_prepare_v2 with interpolation")
	}
}

func TestSQLiteSafe(t *testing.T) {
	code := `
import SQLite3
func getUser(db: OpaquePointer) {
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, nil)
}
`
	findings := scanSwift(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-SWIFT-AST-001" {
			t.Error("unexpected SQL injection finding for safe parameterized query")
		}
	}
}

func TestUIWebView(t *testing.T) {
	code := `
import UIKit
func setup() {
    let webView = UIWebView()
}
`
	findings := scanSwift(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-SWIFT-AST-002" {
			found = true
			if !strings.Contains(f.Title, "UIWebView") {
				t.Errorf("expected UIWebView in title, got %s", f.Title)
			}
			break
		}
	}
	if !found {
		t.Error("expected finding for UIWebView usage")
	}
}

func TestWKWebViewSafe(t *testing.T) {
	code := `
import WebKit
func setup() {
    let webView = WKWebView()
}
`
	findings := scanSwift(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-SWIFT-AST-002" {
			t.Error("unexpected UIWebView finding for WKWebView")
		}
	}
}

func TestUserDefaultsSensitive(t *testing.T) {
	code := `
func save(password: String) {
    UserDefaults.standard.set(password, forKey: "password")
}
`
	findings := scanSwift(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-SWIFT-AST-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for sensitive data in UserDefaults")
	}
}

func TestUserDefaultsNonSensitive(t *testing.T) {
	code := `
func save() {
    UserDefaults.standard.set("dark", forKey: "theme")
}
`
	findings := scanSwift(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-SWIFT-AST-003" {
			t.Error("unexpected finding for non-sensitive UserDefaults key")
		}
	}
}

func TestProcessLaunchPathVariable(t *testing.T) {
	code := `
func run(userPath: String) {
    let task = Process()
    task.launchPath = userPath
}
`
	findings := scanSwift(t, code)
	foundProcess := false
	foundAssignment := false
	for _, f := range findings {
		if f.RuleID == "GTSS-SWIFT-AST-004" {
			if strings.Contains(f.Title, "launchPath") {
				foundAssignment = true
			}
			if strings.Contains(f.Title, "Process") {
				foundProcess = true
			}
		}
	}
	if !foundProcess {
		t.Error("expected finding for Process usage")
	}
	if !foundAssignment {
		t.Error("expected finding for launchPath assignment from variable")
	}
}

func TestSafeCode(t *testing.T) {
	code := `
func greet(name: String) -> String {
    return "Hello, \(name)!"
}
`
	findings := scanSwift(t, code)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe code, got %d", len(findings))
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.swift",
		Content:  "func main() {}",
		Language: rules.LangSwift,
		Tree:     nil,
	}
	a := &SwiftASTAnalyzer{}
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
	a := &SwiftASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}
