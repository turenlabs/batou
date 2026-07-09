package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua — SSRF at the low-level connect boundary of OpenResty client libraries
// (CWE-918). These complement the high-level URL-fetch sinks (request_uri,
// http.request, ssl.https.request) which are tested in tsflow_lua_ssrf_test.go.
// =========================================================================

// lua-resty-http low-level API: httpc:connect(host, port) reaches an
// attacker-controlled host before the subsequent httpc:request{...}.
func TestLua_SSRF_RestyHttp_LowLevelConnect(t *testing.T) {
	code := `
local http = require("resty.http")
function handler()
    local host = ngx.req.get_uri_args()["h"]
    local httpc = http.new()
    httpc:connect(host, 6379)
    local res = httpc:request({ path = "/" })
    return res.body
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> httpc:connect(host)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// lua-resty-websocket client: wb:connect(uri) with a tainted ws:// URI drives
// the WebSocket handshake to an arbitrary host.
func TestLua_SSRF_RestyWebsocket_ClientConnect(t *testing.T) {
	code := `
local client = require("resty.websocket.client")
function handler()
    local target = ngx.req.get_uri_args()["ws"]
    local wb = client:new()
    local ok, err = wb:connect(target)
    return ok
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> wb:connect(uri)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// OpenResty UDP cosocket: sock:setpeername(host, port) with a tainted host.
func TestLua_SSRF_NgxUdpSocket_Setpeername(t *testing.T) {
	code := `
function handler()
    local host = ngx.req.get_uri_args()["target"]
    local sock = ngx.socket.udp()
    sock:setpeername(host, 53)
    sock:send("payload")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for ngx.req.get_uri_args -> sock:setpeername(host)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Negative tests — hardcoded targets must NOT produce SSRF flows.
// =========================================================================

func TestLua_SSRF_Safe_RestyHttpConnectHardcoded(t *testing.T) {
	code := `
local http = require("resty.http")
function handler()
    local httpc = http.new()
    httpc:connect("127.0.0.1", 6379)
    return httpc:request({ path = "/" })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow for hardcoded httpc:connect host")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSRF_Safe_RestyWebsocketConnectHardcoded(t *testing.T) {
	code := `
local client = require("resty.websocket.client")
function handler()
    local wb = client:new()
    wb:connect("ws://127.0.0.1:8080/feed")
    return wb
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow for hardcoded wb:connect URI")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSRF_Safe_NgxUdpSetpeernameHardcoded(t *testing.T) {
	code := `
function handler()
    local sock = ngx.socket.udp()
    sock:setpeername("10.0.0.5", 53)
    sock:send("payload")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow for hardcoded sock:setpeername host")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
