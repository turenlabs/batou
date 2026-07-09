package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua / Kong PDK — additional request sources
// (forwarded-* headers, host) and service.response upstream-data sources.
//
// These complement the kong.request.get_query_arg / get_header / get_body
// sources already covered by tsflow_lua_kong_test.go. Forwarded-* methods
// read from X-Forwarded-* headers, which are attacker-controlled when Kong
// is behind anything other than a strictly trusted proxy. service.response
// data comes from the upstream service and can be attacker-influenced.
// =========================================================================

func TestLua_Kong_Source_GetHost_HeaderInjection(t *testing.T) {
	code := `
function handler()
    local h = kong.request.get_host()
    kong.response.set_header("X-Origin-Host", h)
end
`
	flows := Analyze(code, "/app/plugins/origin/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for kong.request.get_host -> kong.response.set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_Source_ForwardedHost_SSRF(t *testing.T) {
	code := `
function handler()
    local fh = kong.request.get_forwarded_host()
    kong.service.request.set_path("/proxy/" .. fh)
end
`
	flows := Analyze(code, "/app/plugins/route/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for kong.request.get_forwarded_host -> kong.service.request.set_path")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_Source_ForwardedPath_HeaderInjection(t *testing.T) {
	code := `
function handler()
    local p = kong.request.get_forwarded_path()
    kong.response.set_header("X-Path", p)
end
`
	flows := Analyze(code, "/app/plugins/path/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for kong.request.get_forwarded_path -> kong.response.set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_Source_RawForwardedPath_LogInjection(t *testing.T) {
	code := `
function handler()
    local p = kong.request.get_raw_forwarded_path()
    kong.log.err("forwarded path=" .. p)
end
`
	flows := Analyze(code, "/app/plugins/audit/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for kong.request.get_raw_forwarded_path -> kong.log.err")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_Source_ForwardedPrefix_HeaderInjection(t *testing.T) {
	code := `
function handler()
    local pfx = kong.request.get_forwarded_prefix()
    kong.response.add_header("X-Forwarded-Prefix-Echo", pfx)
end
`
	flows := Analyze(code, "/app/plugins/prefix/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for kong.request.get_forwarded_prefix -> kong.response.add_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_Source_ForwardedScheme_LogInjection(t *testing.T) {
	code := `
function handler()
    local sch = kong.request.get_forwarded_scheme()
    kong.log.err("scheme=" .. sch)
end
`
	flows := Analyze(code, "/app/plugins/scheme/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for kong.request.get_forwarded_scheme -> kong.log.err")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua / Kong service.response — upstream response data flowing into sinks
// =========================================================================

func TestLua_Kong_Source_ServiceResponseGetHeader_HeaderInjection(t *testing.T) {
	code := `
function handler()
    local up = kong.service.response.get_header("X-Backend-User")
    kong.response.set_header("X-User", up)
end
`
	flows := Analyze(code, "/app/plugins/echohdr/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for kong.service.response.get_header -> kong.response.set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_Source_ServiceResponseGetHeaders_LogInjection(t *testing.T) {
	code := `
function handler()
    local hdrs = kong.service.response.get_headers()
    kong.log.err("upstream returned " .. hdrs["x-trace-id"])
end
`
	flows := Analyze(code, "/app/plugins/trace/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for kong.service.response.get_headers -> kong.log.err")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_Source_ServiceResponseGetRawBody_XSS(t *testing.T) {
	code := `
function handler()
    local raw = kong.service.response.get_raw_body()
    kong.response.exit(200, "<pre>" .. raw .. "</pre>")
end
`
	flows := Analyze(code, "/app/plugins/dump/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML output flow for kong.service.response.get_raw_body -> kong.response.exit")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Kong_Source_ServiceResponseGetBody_XSS(t *testing.T) {
	code := `
function handler()
    local body = kong.service.response.get_body()
    kong.response.set_raw_body(body["html"])
end
`
	flows := Analyze(code, "/app/plugins/passthrough/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML output flow for kong.service.response.get_body -> kong.response.set_raw_body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua / Kong client — forwarded client IP
// =========================================================================

func TestLua_Kong_Source_ClientGetForwardedIP_LogInjection(t *testing.T) {
	code := `
function handler()
    local ip = kong.client.get_forwarded_ip()
    kong.log.err("rate-limit hit ip=" .. ip)
end
`
	flows := Analyze(code, "/app/plugins/ratelimit/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for kong.client.get_forwarded_ip -> kong.log.err")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Negative regression — constant string should NOT produce flow.
// Catches the case where the new sources were registered too broadly
// (e.g. matching any *.get_header() call regardless of receiver).
// =========================================================================

func TestLua_Kong_Source_ConstantString_NoFlow(t *testing.T) {
	code := `
function handler()
    local hardcoded = "static-tenant"
    kong.response.set_header("X-Tenant", hardcoded)
end
`
	flows := Analyze(code, "/app/plugins/static/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Error("expected NO header injection flow for hardcoded constant; over-broad source match")
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
