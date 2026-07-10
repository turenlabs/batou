package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua native-loading + Neovim filesystem-mutation sink coverage (cycle #917)
//
// New sinks added in lua_sinks.go:
//
//   - package.loadlib(libname, funcname)  — links a C dynamic library into
//       the process and returns one of its functions. Tainted libname ⇒
//       arbitrary native code execution (SnkEval, CWE-829). The Lua analogue
//       of C dlopen() / Python ctypes.CDLL().
//   - vim.fn.writefile({lines}, fname)    — arbitrary file write at a tainted
//       path (SnkFileWrite, CWE-22).
//   - vim.fn.delete(fname, {flags})       — arbitrary file/dir delete; with
//       the "rf" flag, recursive (SnkFileWrite, CWE-22).
//   - vim.fn.rename(from, to)             — arbitrary file move / clobber
//       (SnkFileWrite, CWE-22).
//   - vim.fn.readfile(fname)              — arbitrary file read / disclosure
//       (SnkFileRead, CWE-22).
//
// The Neovim plugin ecosystem routinely derives filesystem paths from data it
// does not control (LSP workspace-edit / showDocument requests, package
// registry manifests, downloaded archives, project-local config). Each test
// feeds vim.fn.input (an existing Lua SrcUserInput source) into the new sink
// and verifies the expected flow fires; negative tests confirm hardcoded
// arguments do NOT flow.
//
// Per the Lua tsflow walker limitations, all fixtures wrap statements in a
// `function ... end` block and use the source's return value directly (no
// table indexing).
// =========================================================================

// --- package.loadlib: native code loading (CWE-829, SnkEval) -------------

func TestLua_PackageLoadlib_FromInput(t *testing.T) {
	code := `
function load_native_plugin()
    local libpath = vim.fn.input("native lib path: ")
    local fn = package.loadlib(libpath, "luaopen_myplugin")
    return fn
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for vim.fn.input -> package.loadlib")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_PackageLoadlib_Safe_Hardcoded(t *testing.T) {
	code := `
function init()
    local fn = package.loadlib("/usr/lib/lua/5.1/cjson.so", "luaopen_cjson")
    return fn
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval flow for hardcoded package.loadlib argument")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- vim.fn.writefile: arbitrary file write (CWE-22, SnkFileWrite) -------

func TestLua_VimFnWritefile_FromInput(t *testing.T) {
	code := `
function save_snippet()
    local dest = vim.fn.input("save to: ")
    vim.fn.writefile({"local x = 1"}, dest)
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow for vim.fn.input -> vim.fn.writefile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- vim.fn.delete: arbitrary file delete (CWE-22, SnkFileWrite) --------

func TestLua_VimFnDelete_FromInput(t *testing.T) {
	code := `
function purge()
    local target = vim.fn.input("delete path: ")
    vim.fn.delete(target, "rf")
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow for vim.fn.input -> vim.fn.delete")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- vim.fn.rename: arbitrary file move (CWE-22, SnkFileWrite) ----------

func TestLua_VimFnRename_FromInput(t *testing.T) {
	code := `
function move_file()
    local src = vim.fn.input("from: ")
    vim.fn.rename(src, "/tmp/out.txt")
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow for vim.fn.input -> vim.fn.rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- vim.fn.readfile: arbitrary file read (CWE-22, SnkFileRead) ---------

func TestLua_VimFnReadfile_FromInput(t *testing.T) {
	code := `
function show_file()
    local path = vim.fn.input("read path: ")
    local lines = vim.fn.readfile(path)
    return lines
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file-read flow for vim.fn.input -> vim.fn.readfile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative regressions: hardcoded paths must NOT flow ----------------

func TestLua_VimFnFilesystem_Safe_Hardcoded(t *testing.T) {
	code := `
function fixed_paths()
    vim.fn.writefile({"data"}, "/tmp/known.txt")
    vim.fn.delete("/tmp/known.txt")
    vim.fn.rename("/tmp/a.txt", "/tmp/b.txt")
    local lines = vim.fn.readfile("/etc/hostname")
    return lines
end
`
	flows := Analyze(code, "/app/plugin.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO file-write/read flow for hardcoded vim.fn filesystem arguments")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
