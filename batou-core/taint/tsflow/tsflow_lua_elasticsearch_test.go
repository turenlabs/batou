package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — lua-elasticsearch / lua-resty-elasticsearch DSL injection (CWE-943)
// and Mustache template injection (CWE-94 propagated through query DSL).
// =========================================================================

func TestLua_Elasticsearch_Bulk_TaintedBody(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_post_args()["payload"]
    local doc = '{"index":{"_index":"x"}}\n{"name":"' .. input .. '"}\n'
    local data, err = client:bulk({body = doc})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for ngx.req.get_post_args -> client:bulk")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Elasticsearch_Msearch_TaintedBody(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["q"]
    local body = '{}\n{"query":{"query_string":{"query":"' .. input .. '"}}}\n'
    local data, err = client:msearch({body = body})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for ngx.req.get_uri_args -> client:msearch")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Elasticsearch_UpdateByQuery_TaintedScript(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_post_args()["expr"]
    local script = "ctx._source.tag = '" .. input .. "'"
    local data, err = client:updateByQuery({index = "x", body = {query = {match_all = {}}, script = {source = script}}})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected Painless eval flow for ngx.req.get_post_args -> client:updateByQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Elasticsearch_DeleteByQuery_TaintedQuery(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["term"]
    local q = '{"query":{"match":{"name":"' .. input .. '"}}}'
    local data, err = client:deleteByQuery({index = "x", body = q})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for ngx.req.get_uri_args -> client:deleteByQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Elasticsearch_Reindex_TaintedSource(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_post_args()["src_index"]
    local body = '{"source":{"index":"' .. input .. '"},"dest":{"index":"y"}}'
    local data, err = client:reIndex({body = body})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected DSL injection flow for ngx.req.get_post_args -> client:reIndex")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Elasticsearch_SearchTemplate_TaintedTemplate(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["tmpl"]
    local tmpl = '{"source":"' .. input .. '","params":{"q":"hello"}}'
    local data, err = client:searchTemplate({index = "x", body = tmpl})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Mustache template injection flow for ngx.req.get_uri_args -> client:searchTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Elasticsearch_RenderSearchTemplate_TaintedTemplate(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["src"]
    local body = '{"source":"' .. input .. '"}'
    local data, err = client:renderSearchTemplate({body = body})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected Mustache template injection flow for ngx.req.get_uri_args -> client:renderSearchTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

func TestLua_Elasticsearch_PutTemplate_TaintedBody(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_post_args()["tmpl"]
    local body = '{"script":{"lang":"mustache","source":"' .. input .. '"}}'
    local data, err = client:putTemplate({id = "stored", body = body})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected stored-template injection flow for ngx.req.get_post_args -> client:putTemplate")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s id=%s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Confidence)
		}
	}
}

// Safe: hardcoded body with no user input touching the sink at all.
// Even though the handler reads user input, it is never propagated into the
// searchTemplate call — no ES sink should fire.
func TestLua_Elasticsearch_SearchTemplate_HardcodedBody_Safe(t *testing.T) {
	code := `
function handler()
    local _ = ngx.req.get_uri_args()["q"]
    local data, err = client:searchTemplate({index = "x", body = {id = "stored_template", params = {q = "hello"}}})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.ID == "lua.elasticsearch.client.searchtemplate" {
			t.Errorf("expected no DSL injection flow for hardcoded body, got: %s -> %s id=%s",
				f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
