package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Fennel embedded-language code injection (CWE-94)
//
// Fennel (https://fennel-lang.org) is a Lisp that compiles to Lua, widely
// used in Neovim config and LÖVE2D game dev. fennel.eval / fennel.compileString
// take a string of Fennel source and compile/run it — handing user input to
// either is arbitrary code execution, exactly like loadstring() on raw Lua.
// =========================================================================

func TestLua_FennelEval_CodeInjection(t *testing.T) {
	code := `
local fennel = require("fennel")
function run_user_code()
    local args = ngx.req.get_uri_args()
    local src = args["code"]
    return fennel.eval(src)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for ngx.req.get_uri_args -> fennel.eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

func TestLua_FennelCompileString_CodeInjection(t *testing.T) {
	code := `
local fennel = require("fennel")
function compile_user_code()
    local args = ngx.req.get_uri_args()
    local src = args["code"]
    local lua_src = fennel.compileString(src)
    return lua_src
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for ngx.req.get_uri_args -> fennel.compileString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative control: a constant Fennel program (no tainted input) must not
// produce a taint flow.
func TestLua_FennelEval_ConstantNoFlow(t *testing.T) {
	code := `
local fennel = require("fennel")
function run_static()
    return fennel.eval("(+ 1 2)")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("did not expect a SnkEval flow for a constant fennel.eval argument")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f) sinkID=%s", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
