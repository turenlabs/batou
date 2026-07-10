package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — lua-resty-redis additional read sources (CWE-79, CWE-89, CWE-78,
// CWE-94 second-order). lua-resty-redis is the canonical Redis client in
// OpenResty (Kong, Apisix, etc.). Values returned by these methods come
// from data previously stored by application or external code; treating
// them as taint sources catches second-order injection bugs (XSS via
// stored leaderboard names, SQLi via queued search terms, etc.).
//
// Existing entries cover hget/hgetall/mget/lrange/smembers. This file
// exercises the new sorted-set / hash-keys / list-pop / set-pop sources.
// =========================================================================

func TestLua_RestyRedis_Hkeys_XSS(t *testing.T) {
	code := `
function handler()
    local field = red:hkeys("user:profile")
    ngx.say("<p>" .. field .. "</p>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for red:hkeys -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Hvals_XSS(t *testing.T) {
	code := `
function handler()
    local val = red:hvals("user:profile")
    ngx.say(val)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for red:hvals -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Zrange_CommandInjection(t *testing.T) {
	code := `
function handler()
    local entry = red:zrange("leaderboard", 0, 10)
    os.execute("echo " .. entry)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for red:zrange -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Zrevrange_XSS(t *testing.T) {
	code := `
function handler()
    local entry = red:zrevrange("leaderboard", 0, 10)
    ngx.say("<li>" .. entry .. "</li>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for red:zrevrange -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Zrangebyscore_XSS(t *testing.T) {
	code := `
function handler()
    local entry = red:zrangebyscore("scores", 0, 100)
    ngx.say("<span>" .. entry .. "</span>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for red:zrangebyscore -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Lpop_CommandInjection(t *testing.T) {
	code := `
function handler()
    local job = red:lpop("queue:pending")
    os.execute("process " .. job)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for red:lpop -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Rpop_CommandInjection(t *testing.T) {
	code := `
function handler()
    local job = red:rpop("queue:pending")
    os.execute("worker " .. job)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for red:rpop -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Lindex_XSS(t *testing.T) {
	code := `
function handler()
    local item = red:lindex("recent:searches", 0)
    ngx.say("<p>" .. item .. "</p>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for red:lindex -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Srandmember_XSS(t *testing.T) {
	code := `
function handler()
    local pick = red:srandmember("featured:users")
    ngx.say("<a>" .. pick .. "</a>")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for red:srandmember -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestLua_RestyRedis_Spop_CommandInjection(t *testing.T) {
	code := `
function handler()
    local target = red:spop("targets:pending")
    os.execute("ping " .. target)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for red:spop -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// Negative test: a constant string (no source) should NOT produce a flow,
// guarding against an over-broad pattern that fires on any :hkeys/:zrange
// regardless of where the data came from.
func TestLua_RestyRedis_ConstantString_NoFlow(t *testing.T) {
	code := `
function handler()
    local val = "static config value"
    ngx.say("<p>" .. val .. "</p>")
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
