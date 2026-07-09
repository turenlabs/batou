package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua — SSTI sinks for popular template engines (CWE-1336)
// etlua, lustache, liluat, cosmo
// =========================================================================

func TestLua_SSTI_Etlua_Render_Vulnerable(t *testing.T) {
	code := `
local etlua = require("etlua")
function handler()
    local tpl = ngx.req.get_uri_args()["tpl"]
    return etlua.render(tpl, { name = "x" })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> etlua.render")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_Etlua_Compile_Vulnerable(t *testing.T) {
	code := `
local etlua = require("etlua")
function handler()
    local tpl = ngx.req.get_uri_args()["tpl"]
    local fn = etlua.compile(tpl)
    return fn({})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> etlua.compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_Lustache_Render_Vulnerable(t *testing.T) {
	code := `
local lustache = require("lustache")
function handler()
    local tpl = ngx.req.get_uri_args()["tpl"]
    return lustache:render(tpl, { name = "x" })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> lustache:render")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_Liluat_Render_Vulnerable(t *testing.T) {
	code := `
local liluat = require("liluat")
function handler()
    local tpl = ngx.req.get_uri_args()["tpl"]
    return liluat.render(tpl, { name = "x" })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> liluat.render")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_Liluat_Compile_Vulnerable(t *testing.T) {
	code := `
local liluat = require("liluat")
function handler()
    local tpl = ngx.req.get_uri_args()["tpl"]
    local compiled = liluat.compile(tpl)
    return liluat.render(compiled, {})
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> liluat.compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_Cosmo_Fill_Vulnerable(t *testing.T) {
	code := `
local cosmo = require("cosmo")
function handler()
    local tpl = ngx.req.get_uri_args()["tpl"]
    return cosmo.fill(tpl, { name = "x" })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> cosmo.fill")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_Cosmo_Compile_Vulnerable(t *testing.T) {
	code := `
local cosmo = require("cosmo")
function handler()
    local tpl = ngx.req.get_uri_args()["tpl"]
    local f = cosmo.compile(tpl)
    return f({ name = "x" })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> cosmo.compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: tainted data passed only via the data context, not as the template
// string itself. The template is a constant literal, so SSTI is impossible.
func TestLua_SSTI_Etlua_Safe_TaintInDataOnly(t *testing.T) {
	code := `
local etlua = require("etlua")
function handler()
    local name = ngx.req.get_uri_args()["name"]
    return etlua.render("<h1><%= name %></h1>", { name = name })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate &&
			(f.Sink.ID == "lua.etlua.render" || f.Sink.ID == "lua.etlua.compile") {
			t.Errorf("expected NO SSTI flow when template is constant: %s -> %s", f.Source.Category, f.Sink.ID)
		}
	}
}
