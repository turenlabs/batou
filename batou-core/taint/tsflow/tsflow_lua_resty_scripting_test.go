package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — lua-resty-redis Lua-script execution (CWE-94),
// lua-resty-mysql async query (CWE-89), and lua-elasticsearch additional
// search/scroll/count DSL injection (CWE-943).
//
// Companion to tsflow_lua_resty_redis_test.go (read sources) and
// tsflow_lua_elasticsearch_test.go (DSL injection on bulk/msearch/template
// methods). Existing entries cover the Redis-server-side EVAL sandbox
// (lua.redis.eval via redis.call('EVAL', ...)) and the basic resty.mysql
// query (lua.resty.mysql.query / db:query). These tests exercise the
// OpenResty / Nginx-side script-dispatch path (red:eval / red:evalsha),
// the asynchronous MySQL multi-statement path (mysql:send_query), and the
// foundational ES search/scroll/count read endpoints.
// =========================================================================

// --- lua-resty-redis: red:eval (Lua script eval on Redis server) ---

func TestLua_RestyRedis_Eval_TaintedScript(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["script"]
    local res, err = red:eval(input, 0)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !findSinkID(flows, "lua.resty.redis.eval") {
		t.Errorf("expected lua.resty.redis.eval flow for ngx.req.get_uri_args -> red:eval; got flows: %+v", flows)
	}
}

func TestLua_RestyRedis_Eval_ConcatenatedScript(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_post_args()["filter"]
    local script = "return redis.call('GET', '" .. input .. "')"
    local res, err = red:eval(script, 0)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !findSinkID(flows, "lua.resty.redis.eval") {
		t.Errorf("expected lua.resty.redis.eval flow for ngx.req.get_post_args -> red:eval (concatenated); got flows: %+v", flows)
	}
}

func TestLua_RestyRedis_Evalsha_TaintedSha(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["sha"]
    local res, err = red:evalsha(input, 0)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !findSinkID(flows, "lua.resty.redis.evalsha") {
		t.Errorf("expected lua.resty.redis.evalsha flow for ngx.req.get_uri_args -> red:evalsha; got flows: %+v", flows)
	}
}

func TestLua_RestyRedis_Eval_LiteralScript_NoFlow(t *testing.T) {
	// Negative — over-broadness regression. A constant Lua script should
	// not produce an EVAL flow even though red:eval is a known sink.
	code := `
function handler()
    local res, err = red:eval("return 1", 0)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if findSinkID(flows, "lua.resty.redis.eval") {
		t.Errorf("did NOT expect lua.resty.redis.eval flow for constant script; got flows: %+v", flows)
	}
}

// --- lua-resty-mysql: mysql:send_query (async multi-statement) ---

func TestLua_RestyMysql_SendQuery_Tainted(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["filter"]
    local sql = "SELECT * FROM users WHERE name = '" .. input .. "'"
    local bytes, err = mysql:send_query(sql)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !findSinkID(flows, "lua.resty.mysql.send_query") {
		t.Errorf("expected lua.resty.mysql.send_query flow for ngx.req.get_uri_args -> mysql:send_query; got flows: %+v", flows)
	}
}

func TestLua_RestyMysql_SendQuery_Literal_NoFlow(t *testing.T) {
	code := `
function handler()
    local bytes, err = mysql:send_query("SELECT 1")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if findSinkID(flows, "lua.resty.mysql.send_query") {
		t.Errorf("did NOT expect lua.resty.mysql.send_query flow for constant SQL; got flows: %+v", flows)
	}
}

// --- lua-elasticsearch: client:search / client:scroll / client:count ---

func TestLua_Elasticsearch_Search_TaintedBody(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["q"]
    local body = '{"query":{"match":{"name":"' .. input .. '"}}}'
    local data, err = client:search({index = "users", body = body})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !findSinkID(flows, "lua.elasticsearch.client.search") {
		t.Errorf("expected lua.elasticsearch.client.search flow for ngx.req.get_uri_args -> client:search; got flows: %+v", flows)
	}
}

func TestLua_Elasticsearch_Scroll_TaintedBody(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["scroll_id"]
    local body = '{"scroll":"1m","scroll_id":"' .. input .. '"}'
    local data, err = client:scroll({body = body})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !findSinkID(flows, "lua.elasticsearch.client.scroll") {
		t.Errorf("expected lua.elasticsearch.client.scroll flow for ngx.req.get_uri_args -> client:scroll; got flows: %+v", flows)
	}
}

func TestLua_Elasticsearch_Count_TaintedBody(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_post_args()["term"]
    local body = '{"query":{"term":{"role":"' .. input .. '"}}}'
    local data, err = client:count({index = "u", body = body})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !findSinkID(flows, "lua.elasticsearch.client.count") {
		t.Errorf("expected lua.elasticsearch.client.count flow for ngx.req.get_post_args -> client:count; got flows: %+v", flows)
	}
}

func TestLua_Elasticsearch_Search_HardcodedBody_NoFlow(t *testing.T) {
	// Negative — a fully literal body should not produce a DSL injection flow.
	code := `
function handler()
    local body = '{"query":{"match_all":{}}}'
    local data, err = client:search({index = "users", body = body})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if findSinkID(flows, "lua.elasticsearch.client.search") {
		t.Errorf("did NOT expect lua.elasticsearch.client.search flow for constant body; got flows: %+v", flows)
	}
}

// --- Smoke test: catalog registration ---

func TestLua_RestyScripting_CatalogRegistration(t *testing.T) {
	wantSinks := []string{
		"lua.resty.redis.eval",
		"lua.resty.redis.evalsha",
		"lua.resty.mysql.send_query",
		"lua.elasticsearch.client.search",
		"lua.elasticsearch.client.scroll",
		"lua.elasticsearch.client.count",
	}
	all := taint.SinksForLanguage(rules.LangLua)
	have := make(map[string]bool, len(all))
	for _, s := range all {
		have[s.ID] = true
	}
	for _, want := range wantSinks {
		if !have[want] {
			t.Errorf("expected sink %q registered for Lua, missing", want)
		}
	}
}
