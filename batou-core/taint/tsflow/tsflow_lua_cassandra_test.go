package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — lua-cassandra / lua-resty-cassandra CQL injection (CWE-943)
// =========================================================================

func TestLua_Cassandra_PeerExecute_TaintedCQL(t *testing.T) {
	code := `
function handler()
    local user_id = ngx.req.get_uri_args()["id"]
    local cql = "SELECT * FROM users WHERE id = " .. user_id
    local rows, err = peer:execute(cql)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for ngx.req.get_uri_args -> peer:execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Cassandra_ClusterExecute_TaintedCQL(t *testing.T) {
	code := `
function handler()
    local name = ngx.req.get_post_args()["name"]
    local cql = "INSERT INTO users (name) VALUES ('" .. name .. "')"
    local rows, err = cluster:execute(cql)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for ngx.req.get_post_args -> cluster:execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Cassandra_PeerBatch_TaintedCQL(t *testing.T) {
	code := `
function handler()
    local user_input = ngx.req.get_uri_args()["q"]
    local stmt = "DELETE FROM logs WHERE user = '" .. user_input .. "'"
    local res, err = peer:batch({stmt})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for ngx.req.get_uri_args -> peer:batch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Cassandra_ClusterBatch_TaintedCQL(t *testing.T) {
	code := `
function handler()
    local tag = ngx.req.get_uri_args()["tag"]
    local s = "UPDATE posts SET tag = '" .. tag .. "' WHERE id = 1"
    local res, err = cluster:batch({s})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected CQL injection flow for ngx.req.get_uri_args -> cluster:batch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: CQL uses ? placeholders and passes the tainted value via the args table,
// which goes through driver-side parameter binding. No CQL injection flow should fire.
func TestLua_Cassandra_PeerExecute_Parameterized_Safe(t *testing.T) {
	code := `
function handler()
    local user_id = ngx.req.get_uri_args()["id"]
    local rows, err = peer:execute("SELECT * FROM users WHERE id = ?", {user_id})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "lua.cassandra.peer.execute" {
			t.Errorf("expected no CQL injection flow for parameterized peer:execute, got: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
