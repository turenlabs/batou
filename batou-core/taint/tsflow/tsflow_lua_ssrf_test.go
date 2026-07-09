package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua — SSRF sinks via HTTP client libraries (CWE-918)
// =========================================================================

func TestLua_SSRF_LuaSecHttps_Request(t *testing.T) {
	code := `
local https = require("ssl.https")
function handler()
    local url = ngx.req.get_uri_args()["target"]
    local body, code = ssl.https.request(url)
    return body
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> ssl.https.request")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSRF_LuaCurl_EasyPositional(t *testing.T) {
	// Lua-cURL `curl.easy(opts)` accepts the same options table that the
	// brace form does. A tainted options variable flows directly into the
	// first positional argument.
	code := `
local curl = require("cURL")
function handler()
    local target = ngx.req.get_uri_args()["u"]
    cURL.easy(target)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> cURL.easy(target)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSRF_LuaHttp_RequestNewFromUri(t *testing.T) {
	code := `
local http_request = require("http.request")
function handler()
    local target = ngx.req.get_uri_args()["url"]
    local headers, stream = http.request.new_from_uri(target):go()
    return stream:get_body_as_string()
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> http.request.new_from_uri")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSRF_LuaHttp_WebsocketNewFromUri(t *testing.T) {
	code := `
local websocket = require("http.websocket")
function handler()
    local target = ngx.req.get_uri_args()["ws"]
    local ws = http.websocket.new_from_uri(target)
    ws:connect()
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> http.websocket.new_from_uri")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSRF_LuaRequests_Get(t *testing.T) {
	code := `
local requests = require("requests")
function handler()
    local url = ngx.req.get_uri_args()["target"]
    local r = requests.get(url)
    return r.text
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> requests.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSRF_LuaRequests_Post(t *testing.T) {
	code := `
local requests = require("requests")
function handler()
    local endpoint = ngx.req.get_uri_args()["ep"]
    local payload = {data = "fixed"}
    local r = requests.post(endpoint, payload)
    return r.status_code
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> requests.post")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Negative tests — hardcoded / unrelated calls should NOT trigger SSRF.
// =========================================================================

func TestLua_SSRF_Safe_HardcodedLuaSecUrl(t *testing.T) {
	code := `
function handler()
    local body, code = ssl.https.request("https://api.example.com/health")
    return body
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow for hardcoded ssl.https.request URL")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSRF_Safe_RequestsUnrelatedTableGet(t *testing.T) {
	// `requests.get(key)` here is a local table lookup, not the HTTP client.
	// Because the value flows in from a hardcoded literal, no taint is present
	// and no SSRF flow should be reported even though the call name matches.
	code := `
function handler()
    local requests = {get = function(k) return "ok" end}
    local name = "fixed"
    requests.get(name)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when taint is absent")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
