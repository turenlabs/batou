package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Neovim plugin eval/RCE sink coverage — Lua tsflow (cycle #859)
//
// The pre-existing tsflow_lua_neovim_test.go covers the four shell-execution
// sinks (vim.fn.system / systemlist / jobstart / termopen) plus three Ex-command
// sinks (vim.cmd / vim.api.nvim_exec / nvim_command). The full Neovim plugin
// surface also exposes:
//
//   - vim.api.nvim_exec_lua  — runs an arbitrary Lua chunk
//   - vim.api.nvim_eval      — evaluates a Vimscript expression
//   - vim.api.nvim_exec2     — multiline Vimscript execution (post-0.10)
//   - vim.fn.execute         — Ex-command (or list) execution
//   - vim.fn.eval            — Vimscript expression evaluation
//   - vim.fn.luaeval         — Lua expression evaluation
//
// All six are real Neovim APIs and are routinely called by plugins from
// buffer text, clipboard, LSP responses, and :input prompts. These tests
// verify each fires SnkEval when fed user-controlled input via vim.fn.input.
//
// The bonus SSRF entry below covers ngx.location.capture_multi, the
// multi-URI variant of the existing ngx.location.capture sink.
// =========================================================================

// --- Neovim Lua/Vimscript eval sinks (CWE-94) ---------------------------

func TestLua_Neovim_Eval_NvimExecLua_FromInput(t *testing.T) {
	code := `
function run_snippet()
    local snip = vim.fn.input("lua: ")
    vim.api.nvim_exec_lua(snip, {})
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.api.nvim_exec_lua")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Eval_NvimEval_FromInput(t *testing.T) {
	code := `
function run_expr()
    local expr = vim.fn.input("expr: ")
    return vim.api.nvim_eval(expr)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.api.nvim_eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Eval_NvimExec2_FromInput(t *testing.T) {
	code := `
function run_block()
    local block = vim.fn.input("vim block: ")
    vim.api.nvim_exec2(block, { output = false })
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.api.nvim_exec2")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Eval_VimFnExecute_FromInput(t *testing.T) {
	code := `
function run_ex()
    local cmd = vim.fn.input("ex command: ")
    vim.fn.execute(cmd)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.fn.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Eval_VimFnEval_FromInput(t *testing.T) {
	code := `
function run_eval()
    local expr = vim.fn.input("vimscript expr: ")
    local out = vim.fn.eval(expr)
    return out
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.fn.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Eval_VimFnLuaeval_FromInput(t *testing.T) {
	code := `
function run_luaeval()
    local expr = vim.fn.input("lua expr: ")
    return vim.fn.luaeval(expr)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.fn.luaeval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- OpenResty multi-subrequest SSRF (CWE-918) --------------------------

func TestLua_OpenResty_SSRF_NgxLocationCaptureMulti_FromInput(t *testing.T) {
	code := `
function fanout()
    local uri = vim.fn.input("uri: ")
    local results = ngx.location.capture_multi({ { uri }, { "/static" } })
    return results
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for vim.fn.input -> ngx.location.capture_multi")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative regression: hardcoded args must NOT flow ------------------

func TestLua_Neovim_Safe_NvimExecLua_Hardcoded(t *testing.T) {
	// Hardcoded Lua chunk with no taint — must not produce SnkEval flow.
	code := `
function init()
    vim.api.nvim_exec_lua("print('hello world')", {})
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval flow for hardcoded vim.api.nvim_exec_lua argument")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_OpenResty_Safe_NgxLocationCaptureMulti_Hardcoded(t *testing.T) {
	// Hardcoded URI table — must not produce SnkURLFetch flow.
	code := `
function fanout()
    local results = ngx.location.capture_multi({ { "/foo" }, { "/bar" } })
    return results
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow for hardcoded ngx.location.capture_multi argument")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
