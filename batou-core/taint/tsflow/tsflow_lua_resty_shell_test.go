package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua — lua-resty-shell command injection sinks (CWE-78)
//
// Repo: https://github.com/openresty/lua-resty-shell
// API:  ok, stdout, stderr, reason, status = shell.run(cmd, stdin, timeout, max_size)
//
// When `cmd` is a string, it is dispatched through `sh -c`, so shell
// metacharacters in user input are interpreted. The argv-table form is
// safer (execvp, no shell), but tainted args still permit path traversal
// and flag injection.
// =========================================================================

func TestLua_RestyShell_Run_TaintedConcat(t *testing.T) {
	code := `
local shell = require "resty.shell"
function handler()
    local args = ngx.req.get_uri_args()
    local target = args["target"]
    local ok, stdout, stderr = shell.run("ls -la " .. target)
    ngx.say(stdout)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for ngx.req.get_uri_args -> shell.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_RestyShell_Run_TaintedDirect(t *testing.T) {
	code := `
local shell = require "resty.shell"
function handler()
    local cmd = ngx.req.get_post_args()["cmd"]
    shell.run(cmd)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for ngx.req.get_post_args -> shell.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_RestyShell_Run_LiteralSafe(t *testing.T) {
	// No user input flows into shell.run — only static strings.
	code := `
local shell = require "resty.shell"
function periodic()
    local ok, stdout, stderr = shell.run("uptime")
    ngx.log(ngx.INFO, stdout)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect command-injection flow for literal shell.run('uptime')")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
