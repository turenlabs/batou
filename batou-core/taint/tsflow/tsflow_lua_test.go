package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua — Trust boundary sinks (CWE-501)
// =========================================================================

func TestLua_TrustBoundary_NgxSharedSet_UriArgs(t *testing.T) {
	code := `
function handler()
    local user_input = ngx.req.get_uri_args()["name"]
    ngx.shared.sessions:set("current_user", user_input)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for ngx.req.get_uri_args -> ngx.shared.DICT:set")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_TrustBoundary_NgxSharedSet(t *testing.T) {
	code := `
function handler()
    local val = ngx.req.get_post_args()["token"]
    ngx.shared.cache:set("session_token", val)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for ngx.req.get_post_args -> ngx.shared.DICT:set")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_TrustBoundary_NgxSharedSafeSet(t *testing.T) {
	code := `
function handler()
    local data = ngx.req.get_body_data()
    ngx.shared.mydict:safe_set("user_data", data)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for ngx.req.get_body_data -> ngx.shared.DICT:safe_set")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua — Deserialization sinks (CWE-502)
// =========================================================================

func TestLua_Deserialize_CmsgpackUnpack(t *testing.T) {
	code := `
function handler()
    local raw = ngx.req.get_body_data()
    local data = cmsgpack.unpack(raw)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for ngx.req.get_body_data -> cmsgpack.unpack")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Deserialize_SerpentLoad(t *testing.T) {
	// serpent.load() internally uses loadstring, so the generic `load` eval sink
	// also matches. Either SnkDeserialize or SnkEval is a valid detection.
	code := `
function handler()
    local input = io.read()
    local ok, data = serpent.load(input)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkDeserialize) && !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected deserialization or eval flow for io.read -> serpent.load")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Deserialize_MarshalDecode(t *testing.T) {
	code := `
function handler()
    local raw = ngx.req.get_body_data()
    local obj = marshal.decode(raw)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization flow for ngx.req.get_body_data -> marshal.decode")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua — Log injection via print (CWE-117)
// =========================================================================

func TestLua_LogInjection_Print(t *testing.T) {
	code := `
function handler()
    local name = ngx.req.get_uri_args()["name"]
    print("User logged in: " .. name)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for ngx.req.get_uri_args -> print")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua — Safe patterns (should NOT produce flows)
// =========================================================================

func TestLua_TrustBoundary_Safe_Validated(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["count"]
    local count = tonumber(input)
    ngx.shared.stats:set("request_count", count)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow after tonumber validation")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua — Trust boundary sanitizers (new: type check, anchored match)
// =========================================================================

func TestLua_TrustBoundary_Safe_TypeCheck(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["role"]
    if type(input) == "string" then
        ngx.shared.sessions:set("user_role", input)
    end
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow after type() check guard")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_TrustBoundary_Safe_AnchoredMatch(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["token"]
    if string.match(input, "^%x+$") then
        ngx.shared.cache:set("session_token", input)
    end
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow after anchored string.match validation")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua — Template injection sanitizers (CWE-1336)
// =========================================================================

func TestLua_Template_Vulnerable(t *testing.T) {
	code := `
function handler()
    local name = ngx.req.get_uri_args()["name"]
    template.render(name)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for ngx.req.get_uri_args -> template.render")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Template_Safe_HtmlEntities(t *testing.T) {
	code := `
function handler()
    local name = ngx.req.get_uri_args()["name"]
    local safe = string.gsub(name, "<", "&lt;")
    template.render("hello.html", { user = safe })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate {
			t.Error("expected NO template flow after HTML entity escaping via string.gsub")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Template_Safe_CjsonEncode(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["data"]
    local safe = cjson.encode(input)
    template.render("display.html", { payload = safe })
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTemplate {
			t.Error("expected NO template flow after cjson.encode sanitization")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua — Log injection sanitizers (CWE-117)
// =========================================================================

func TestLua_Log_Safe_CjsonEncode(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["action"]
    local safe = cjson.encode(input)
    ngx.log(ngx.INFO, "user action: " .. safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow after cjson.encode sanitization")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Log_Safe_ControlCharStrip(t *testing.T) {
	code := `
function handler()
    local input = ngx.req.get_uri_args()["msg"]
    local clean = string.gsub(input, "%c", "")
    ngx.log(ngx.WARN, "message: " .. clean)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow after control char stripping via gsub")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua — Header injection sanitizers (CWE-113)
// =========================================================================

func TestLua_Header_Vulnerable(t *testing.T) {
	code := `
function handler()
    local val = ngx.req.get_uri_args()["name"]
    ngx.req.set_header("X-User", val)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for ngx.req.get_uri_args -> ngx.req.set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Header_Safe_NgxReSub(t *testing.T) {
	code := `
function handler()
    local val = ngx.req.get_uri_args()["name"]
    local clean = ngx.re.sub(val, "[\r\n]", "", "jo")
    ngx.req.set_header("X-User", clean)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Error("expected NO header injection flow after ngx.re.sub CRLF stripping")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Header_Safe_Base64Encode(t *testing.T) {
	code := `
function handler()
    local data = ngx.req.get_uri_args()["token"]
    local encoded = ngx.encode_base64(data)
    ngx.req.set_header("X-Token", encoded)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Error("expected NO header injection flow after base64 encoding")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_Header_Safe_ControlCharStrip(t *testing.T) {
	// Uses ngx.re.sub (matched by tsflow via MethodName "ngx.re.sub").
	// Note: string.gsub sanitizers use parenthesized MethodNames which
	// are only matched by the regex fallback engine, not by tsflow.
	code := `
function handler()
    local val = ngx.req.get_uri_args()["value"]
    local safe = ngx.re.sub(val, "[\\x00-\\x1f]", "", "jo")
    ngx.req.set_header("X-Custom", safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Error("expected NO header injection flow after ngx.re.sub control char stripping")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua — Template Injection / SSTI sinks (CWE-1336)
// =========================================================================

func TestLua_SSTI_EtluaRender(t *testing.T) {
	code := `
function handler()
    local tpl = ngx.req.get_uri_args()["template"]
    local html = etlua.render(tpl, {name = "world"})
    ngx.say(html)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> etlua.render")
	}
}
// Lua — JWT signature bypass (CWE-345) via lua-resty-jwt
// =========================================================================

func TestLua_JWT_Vulnerable_LoadJWT(t *testing.T) {
	// jwt:load_jwt parses the JWT but does NOT verify the signature.
	// The decoded payload is attacker-controlled.
	code := `
function handler()
    local token = ngx.req.get_uri_args()["token"]
    local jwt_obj = jwt:load_jwt(token)
    ngx.say(jwt_obj.payload.user)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for ngx.req.get_uri_args -> jwt:load_jwt (signature bypass)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_EtluaCompile(t *testing.T) {
	code := `
function handler()
    local tpl = ngx.req.get_post_args()["tpl"]
    local fn = etlua.compile(tpl)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_post_args -> etlua.compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_LustacheRender(t *testing.T) {
	code := `
function handler()
    local tpl = ngx.req.get_uri_args()["tpl"]
    local html = lustache:render(tpl, {user = "alice"})
    ngx.say(html)
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

func TestLua_SSTI_CosmoFill(t *testing.T) {
	code := `
function handler()
    local tpl = ngx.req.get_body_data()
    local html = cosmo.fill(tpl, {title = "page"})
    ngx.say(html)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_body_data -> cosmo.fill")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_SSTI_PenlightTemplateSubstitute(t *testing.T) {
	code := `
function handler()
    local tpl = ngx.req.get_uri_args()["tmpl"]
    local out = template.substitute(tpl, {name = "bob"})
    ngx.say(out)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected SSTI flow for ngx.req.get_uri_args -> template.substitute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_JWT_Safe_Verify(t *testing.T) {
	// jwt:verify is a sanitizer for trust-boundary sinks: the signed payload
	// is integrity-checked against the secret before being used. Storing the
	// verified payload into ngx.shared (a trust boundary) should NOT flow.
	code := `
function handler()
    local token = ngx.req.get_uri_args()["token"]
    local jwt_obj = jwt:verify("secret", token)
    if jwt_obj.verified then
        ngx.shared.sessions:set("current_user", jwt_obj.payload.user)
    end
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust-boundary flow after jwt:verify signature check")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
