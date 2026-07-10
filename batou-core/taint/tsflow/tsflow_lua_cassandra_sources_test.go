package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — lua-cassandra / lua-resty-cassandra peer:execute() and
// cluster:execute() SrcDatabase result-row sources (second-order taint).
//
// The catalog already treats the first argument of each call as a CQL
// injection sink (lua.cassandra.peer.execute / lua.cassandra.cluster.execute,
// CWE-943). These tests cover the OTHER side of the same call: the return
// value is the list of result rows of a SELECT, whose fields carry data an
// earlier writer persisted. That return-value taint chains into XSS / log /
// command sinks when applications render or pass row fields without
// re-escaping. Mirrors the existing lua-resty-mysql db:query() / pgmoon
// pg:query() read-result coverage (tsflow_lua_resty_mysql_pgmoon_test.go) and
// the Java/Kotlin/Groovy Cassandra Row source cycles.
//
// Note: the CQL string in these fixtures is a CONSTANT — there is no
// first-order injection. The only taint is the second-order kind introduced
// by the new SrcDatabase entries, so the flow proves the source fires.
// =========================================================================

func TestLua_Cassandra_PeerExecute_StoredXSS_ngx_say(t *testing.T) {
	code := `
function handler()
    local rows = peer:execute("SELECT name FROM users WHERE id = 1")
    ngx.say("<p>" .. rows .. "</p>")
end
`
	flows := Analyze(code, "/app/handlers/profile.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected stored-XSS flow for peer:execute result -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Cassandra_PeerExecute_CommandInjection_os_execute(t *testing.T) {
	code := `
function handler()
    local rows = peer:execute("SELECT cmd FROM jobs WHERE pending = 1")
    os.execute("worker " .. rows)
end
`
	flows := Analyze(code, "/app/handlers/worker.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected stored-command-injection flow for peer:execute result -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Cassandra_ClusterExecute_StoredXSS_ngx_say(t *testing.T) {
	code := `
function handler()
    local rows = cluster:execute("SELECT bio FROM profiles WHERE id = 7")
    ngx.say("<div>" .. rows .. "</div>")
end
`
	flows := Analyze(code, "/app/handlers/bio.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected stored-XSS flow for cluster:execute result -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Cassandra_ClusterExecute_CommandInjection_io_popen(t *testing.T) {
	code := `
function handler()
    local rows = cluster:execute("SELECT path FROM uploads")
    local pipe = io.popen("ls " .. rows)
end
`
	flows := Analyze(code, "/app/handlers/list.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected stored-command-injection flow for cluster:execute result -> io.popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Negative control: a constant string (no Cassandra read) concatenated into
// ngx.say must NOT produce a taint flow — proves the flow above comes from the
// new SrcDatabase source, not from ngx.say firing on any argument.
func TestLua_Cassandra_NoSource_Constant_Safe(t *testing.T) {
	code := `
function handler()
    local name = "static-content"
    ngx.say("<p>" .. name .. "</p>")
end
`
	flows := Analyze(code, "/app/handlers/static.lua", rules.LangLua)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("did not expect a taint flow for a constant string -> ngx.say")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}
