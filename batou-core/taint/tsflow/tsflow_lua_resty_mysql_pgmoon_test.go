package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — lua-resty-mysql db:query() + pgmoon pg:query() / pg:simple_query()
// SrcDatabase result-row sources (CWE-79 / CWE-78 / CWE-117 second-order
// taint).
//
// These three calls are the dominant relational-DB read paths in OpenResty
// deployments (Kong, APISIX, custom nginx-Lua services). The existing
// catalog already treats each :query() / :simple_query() call's first
// argument as a SQLi sink (lua.resty.mysql.query, lua.pgmoon.query,
// lua.pgmoon.simple_query) — that catches first-order injection. The new
// SrcDatabase entries cover the OTHER side of the same call: the return
// value is a list of rows whose fields carry data persisted by an earlier
// writer. That return-value taint chains into XSS / log / command sinks
// when applications render or pass row fields without re-escaping.
//
// Mirrors the existing lua-resty-redis read-result coverage
// (tsflow_lua_resty_redis_test.go) and the lua-resty-mysql db:read_result
// source already on main. Originally landed as PR #604 (closed during CI
// cleanup, not on content — see the closing comment on that PR).
// =========================================================================

func TestLua_RestyMySQL_Query_StoredXSS_ngx_say(t *testing.T) {
	code := `
function handler()
    local rows = db:query("SELECT name FROM users WHERE id = 1")
    ngx.say("<p>" .. rows .. "</p>")
end
`
	flows := Analyze(code, "/app/handlers/profile.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected stored-XSS flow for db:query result -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_RestyMySQL_Query_CommandInjection_os_execute(t *testing.T) {
	code := `
function handler()
    local rows = db:query("SELECT cmd FROM jobs WHERE pending = 1")
    os.execute("worker " .. rows)
end
`
	flows := Analyze(code, "/app/handlers/worker.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected stored-command-injection flow for db:query result -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_RestyMySQL_Query_CommandInjection_io_popen(t *testing.T) {
	code := `
function handler()
    local rows = db:query("SELECT path FROM uploads")
    local pipe = io.popen("ls " .. rows)
end
`
	flows := Analyze(code, "/app/handlers/list.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected stored-command-injection flow for db:query result -> io.popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Pgmoon_Query_StoredXSS_ngx_say(t *testing.T) {
	code := `
function handler()
    local rows = pg:query("SELECT username FROM accounts WHERE active = true")
    ngx.say("<span>" .. rows .. "</span>")
end
`
	flows := Analyze(code, "/app/handlers/accounts.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected stored-XSS flow for pg:query result -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Pgmoon_Query_CommandInjection_os_execute(t *testing.T) {
	code := `
function handler()
    local rows = pg:query("SELECT path FROM uploads")
    os.execute("ls " .. rows)
end
`
	flows := Analyze(code, "/app/handlers/files.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected stored-command-injection flow for pg:query result -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Pgmoon_Query_StoredXSS_ngx_print(t *testing.T) {
	code := `
function handler()
    local rows = pg:query("SELECT bio FROM profiles WHERE id = 1")
    ngx.print(rows)
end
`
	flows := Analyze(code, "/app/handlers/bio.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected stored-XSS flow for pg:query result -> ngx.print")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Pgmoon_SimpleQuery_StoredXSS_ngx_say(t *testing.T) {
	code := `
function handler()
    local rows = pg:simple_query("SELECT title FROM posts ORDER BY id DESC LIMIT 1")
    ngx.say("<h1>" .. rows .. "</h1>")
end
`
	flows := Analyze(code, "/app/handlers/post.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected stored-XSS flow for pg:simple_query result -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Pgmoon_SimpleQuery_CommandInjection_os_execute(t *testing.T) {
	code := `
function handler()
    local rows = pg:simple_query("SELECT script FROM cron")
    os.execute("bash -c " .. rows)
end
`
	flows := Analyze(code, "/app/handlers/cron.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected stored-command-injection flow for pg:simple_query result -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// ---- single-letter receiver via the matcher's prefix-abbreviation heuristic ----
// Receiver `p` matches ObjectType "pgmoon" (HasPrefix("pgmoon", "p") = true).

func TestLua_Pgmoon_Query_ShortReceiver(t *testing.T) {
	code := `
function handler()
    local rows = pgmoon:query("SELECT name FROM accounts")
    ngx.say("<li>" .. rows .. "</li>")
end
`
	flows := Analyze(code, "/app/handlers/pg.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected stored-XSS flow for pgmoon:query result -> ngx.say (canonical-name receiver)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// ---- negative control: constant query + constant output should not flow ----

func TestLua_Pgmoon_Query_NoFlow_ConstantOutput(t *testing.T) {
	code := `
function handler()
    local rows = pg:query("SELECT 1")
    ngx.say("hello world")
end
`
	flows := Analyze(code, "/app/handlers/health.lua", rules.LangLua)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("did not expect XSS flow: ngx.say emits a constant string that never references the query result")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}
