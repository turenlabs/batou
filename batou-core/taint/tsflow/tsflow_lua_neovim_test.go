package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Neovim plugin taint surface — Lua tsflow
//
// Neovim plugins are written in Lua and routinely pipe user-controlled data
// (config values, LSP responses, file contents, :input prompts) into shell
// execution APIs. These tests cover the vim.fn.* and vim.api.* sinks plus
// the vim.fn.input source.
// =========================================================================

// --- Command injection sinks (CWE-78) -----------------------------------

func TestLua_Neovim_Command_VimFnSystem_FromInput(t *testing.T) {
	code := `
function build(target)
    local name = vim.fn.input("target: ")
    vim.fn.system("gcc " .. name)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow for vim.fn.input -> vim.fn.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Command_VimFnSystemlist_FromInput(t *testing.T) {
	code := `
function run_formatter()
    local path = vim.fn.input("path: ")
    local lines = vim.fn.systemlist("prettier " .. path)
    return lines
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow for vim.fn.input -> vim.fn.systemlist")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Command_VimFnJobstart_FromInput(t *testing.T) {
	code := `
function start_job()
    local cmd = vim.fn.input("command: ")
    vim.fn.jobstart(cmd)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow for vim.fn.input -> vim.fn.jobstart")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Command_VimFnTermopen_FromInput(t *testing.T) {
	code := `
function open_shell()
    local user_cmd = vim.fn.input("cmd: ")
    vim.fn.termopen(user_cmd)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command flow for vim.fn.input -> vim.fn.termopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ex-command / code injection sinks (CWE-94) -------------------------

func TestLua_Neovim_Eval_VimCmd_FromInput(t *testing.T) {
	code := `
function run_ex()
    local raw = vim.fn.input("ex command: ")
    vim.cmd(raw)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.cmd")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Eval_NvimExec_FromInput(t *testing.T) {
	code := `
function apply_script()
    local user_script = vim.fn.input("script: ")
    vim.api.nvim_exec(user_script, false)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.api.nvim_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Neovim_Eval_NvimCommand_FromInput(t *testing.T) {
	code := `
function run_cmd()
    local c = vim.fn.input("cmd: ")
    vim.api.nvim_command(c)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> vim.api.nvim_command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe / sanitized patterns -----------------------------------------

func TestLua_Neovim_Safe_VimFnSystem_HardcodedCommand(t *testing.T) {
	// Hardcoded command string with no tainted input — must not flow.
	code := `
function version()
    local out = vim.fn.system("git --version")
    return out
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO command flow for hardcoded vim.fn.system argument")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
