package luaast

import (
	"strings"
	"testing"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
)

func scanLua(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangLua)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.lua",
		Content:  code,
		Language: rules.LangLua,
		Tree:     tree,
	}
	a := &LuaASTAnalyzer{}
	return a.Scan(ctx)
}

func TestOsExecuteInjection(t *testing.T) {
	code := `
local input = get_input()
os.execute("rm -rf " .. input)
`
	findings := scanLua(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-001" && strings.Contains(f.Title, "os.execute") {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for os.execute")
	}
}

func TestIoPopenInjection(t *testing.T) {
	code := `
local input = get_input()
io.popen("ls " .. input)
`
	findings := scanLua(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-001" && strings.Contains(f.Title, "io.popen") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for io.popen")
	}
}

func TestOsExecuteSafe(t *testing.T) {
	code := `
os.execute("ls -la")
`
	findings := scanLua(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-001" {
			t.Error("unexpected command injection finding for safe literal command")
		}
	}
}

func TestLoadstringInjection(t *testing.T) {
	code := `
local input = get_input()
loadstring("return " .. input)
`
	findings := scanLua(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-002" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected code injection finding for loadstring")
	}
}

func TestLoadstringSafe(t *testing.T) {
	code := `
loadstring("return 42")
`
	findings := scanLua(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-002" {
			t.Error("unexpected code injection finding for safe loadstring")
		}
	}
}

func TestDofileInjection(t *testing.T) {
	code := `
local path = get_path()
dofile(path)
`
	findings := scanLua(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-003" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected path injection finding for dofile")
	}
}

func TestDofileSafe(t *testing.T) {
	code := `
dofile("config.lua")
`
	findings := scanLua(t, code)
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-003" {
			t.Error("unexpected path injection finding for safe dofile")
		}
	}
}

func TestDebugLibrary(t *testing.T) {
	code := `
debug.getinfo(1)
`
	findings := scanLua(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-004" {
			found = true
			if f.Severity != rules.High {
				t.Errorf("expected High, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected finding for debug library usage")
	}
}

func TestDebugSetHook(t *testing.T) {
	code := `
debug.sethook(handler, "c")
`
	findings := scanLua(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-004" && strings.Contains(f.Title, "sethook") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for debug.sethook")
	}
}

func TestNgxSQLInjection(t *testing.T) {
	code := `
local args = ngx.req.get_uri_args()
ngx.say("SELECT * FROM users WHERE id = " .. args.id)
`
	findings := scanLua(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "GTSS-LUA-AST-005" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for OpenResty pattern")
	}
}

func TestSafeCode(t *testing.T) {
	code := `
local x = 42
print("hello world")
`
	findings := scanLua(t, code)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe code, got %d", len(findings))
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.lua",
		Content:  "print('hi')",
		Language: rules.LangLua,
		Tree:     nil,
	}
	a := &LuaASTAnalyzer{}
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
	a := &LuaASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}
