package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — SQL / SQLite second-order DB-read sources.
//
// Values returned by lua-resty-mysql db:read_result(), LuaSQL cursor:fetch(),
// LuaDBI statement:fetch()/rows(), and lsqlite3 stmt:get_value(s)/
// get_named_values()/get_uvalues() carry data that was previously written to
// the database by application or external code. Treating them as taint
// sources catches second-order injection — stored XSS via leaderboard names,
// SQLi via queued search terms, command injection via stored job names.
//
// The query/prepare calls that *produce* these handles are already modeled
// as SQLi sinks in lua_sinks.go; here we exercise the read side.
// =========================================================================

func TestLua_RestyMysql_ReadResult_XSS(t *testing.T) {
	code := `
function handler()
    local row = db:read_result()
    ngx.say("<p>" .. row .. "</p>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for db:read_result -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_LuaSQL_CursorFetch_CommandInjection(t *testing.T) {
	code := `
function handler()
    local row = cur:fetch({}, "a")
    os.execute("backup " .. row)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for cur:fetch -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_LuaSQL_CursorFetch_FullName_XSS(t *testing.T) {
	code := `
function handler()
    local row = cursor:fetch()
    ngx.say(row)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for cursor:fetch -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_LuaDBI_StatementFetch_XSS(t *testing.T) {
	code := `
function handler()
    local row = sth:fetch(true)
    ngx.say("<li>" .. row .. "</li>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for sth:fetch -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_LuaDBI_StatementRows_CommandInjection(t *testing.T) {
	code := `
function handler()
    local r = stmt:rows(true)
    os.execute("process " .. r)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for stmt:rows -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_Lsqlite3_GetValue_XSS(t *testing.T) {
	code := `
function handler()
    local name = stmt:get_value(0)
    ngx.say("<span>" .. name .. "</span>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for stmt:get_value -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_Lsqlite3_GetValues_CommandInjection(t *testing.T) {
	code := `
function handler()
    local vals = stmt:get_values()
    os.execute("run " .. vals)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for stmt:get_values -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_Lsqlite3_GetNamedValues_XSS(t *testing.T) {
	code := `
function handler()
    local row = statement:get_named_values()
    ngx.say("<div>" .. row .. "</div>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for statement:get_named_values -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_Lsqlite3_GetUvalues_XSS(t *testing.T) {
	code := `
function handler()
    local row = stmt:get_uvalues()
    ngx.say(row)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for stmt:get_uvalues -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Negative test: a constant string (no source) must NOT produce a SrcDatabase
// flow, guarding against an over-broad pattern that fires on any :fetch /
// :rows / :get_value regardless of where the data came from.
func TestLua_DBReadSources_ConstantString_NoFlow(t *testing.T) {
	code := `
function handler()
    local val = "static config value"
    ngx.say("<p>" .. val .. "</p>")
    os.execute("echo " .. val)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Source.Category == taint.SrcDatabase {
			t.Errorf("unexpected SrcDatabase flow on constant string: %s -> %s (id=%s)",
				f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
