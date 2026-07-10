package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua / Kong API Gateway PDK — XSS via response body (CWE-79)
// =========================================================================

func TestLua_Kong_XSS_ResponseExit(t *testing.T) {
	code := `
function handler()
    local name = kong.request.get_query_arg("name")
    kong.response.exit(200, "<h1>Hello " .. name .. "</h1>")
end
`
	flows := Analyze(code, "/app/plugins/greet/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML output flow for kong.request.get_query_arg -> kong.response.exit")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_XSS_SetRawBody(t *testing.T) {
	code := `
function handler()
    local raw = kong.request.get_raw_body()
    kong.response.set_raw_body(raw)
end
`
	flows := Analyze(code, "/app/plugins/echo/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML output flow for kong.request.get_raw_body -> kong.response.set_raw_body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua / Kong API Gateway PDK — Header injection / CRLF (CWE-113)
// =========================================================================

func TestLua_Kong_HeaderInjection_ResponseSetHeader(t *testing.T) {
	code := `
function handler()
    local lang = kong.request.get_header("Accept-Language")
    kong.response.set_header("X-User-Lang", lang)
end
`
	flows := Analyze(code, "/app/plugins/lang/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for kong.request.get_header -> kong.response.set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_HeaderInjection_ResponseAddHeader(t *testing.T) {
	code := `
function handler()
    local body = kong.request.get_body()
    kong.response.add_header("X-Echo", body["tag"])
end
`
	flows := Analyze(code, "/app/plugins/echo/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for kong.request.get_body -> kong.response.add_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_UpstreamHeaderInjection(t *testing.T) {
	code := `
function handler()
    local hdrs = kong.request.get_headers()
    kong.service.request.set_header("X-Forwarded-User", hdrs["x-user"])
end
`
	flows := Analyze(code, "/app/plugins/proxy/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for kong.request.get_headers -> kong.service.request.set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua / Kong API Gateway PDK — SSRF via upstream path (CWE-918)
// =========================================================================

func TestLua_Kong_SSRF_UpstreamSetPath(t *testing.T) {
	code := `
function handler()
    local target = kong.request.get_query_arg("target")
    kong.service.request.set_path(target)
end
`
	flows := Analyze(code, "/app/plugins/route/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for kong.request.get_query_arg -> kong.service.request.set_path")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua / Kong API Gateway PDK — Log injection (CWE-117)
// =========================================================================

func TestLua_Kong_LogInjection_LogErr(t *testing.T) {
	code := `
function handler()
    local user_agent = kong.request.get_header("User-Agent")
    kong.log.err("auth failed for ua=" .. user_agent)
end
`
	flows := Analyze(code, "/app/plugins/auth/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for kong.request.get_header -> kong.log.err")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua / Kong — Safe pattern (validated input should NOT produce flow)
// =========================================================================

func TestLua_Kong_Safe_Escaped(t *testing.T) {
	code := `
function handler()
    local raw = kong.request.get_query_arg("name")
    local safe = ngx.escape_uri(raw)
    kong.response.exit(200, "<a href=\"/u/" .. safe .. "\">profile</a>")
end
`
	flows := Analyze(code, "/app/plugins/profile/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO HTML output flow after ngx.escape_uri sanitization")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
