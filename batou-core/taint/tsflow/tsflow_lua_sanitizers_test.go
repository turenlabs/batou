package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Lua — sanitizer additions covering URL escape, password verify,
// hex/base64url encoding, and HTML entity escape gaps.
//
// Per-feature file (not appended to tsflow_test.go) — the long-running
// taint-research loop churns *_sinks/_sources changes across every
// language and tsflow_test.go is the most contested test file.
//
// Each test pairs a tainted user-input source with the new sanitizer and
// asserts the relevant sink-category flow is NOT produced at high
// confidence. Negative counterparts confirm the same source/sink pair
// WOULD flow without the sanitizer in place — guarding against the silent-
// pass failure mode where a sanitizer test "passes" only because the
// chosen sink never fires.
// =========================================================================

// --- LuaSocket socket.url.escape (SnkRedirect / SnkURLFetch / SnkHTMLOutput) ---

func TestLua_LuaSocketUrlEscape_SanitizesRedirect(t *testing.T) {
	code := `
local url = require("socket.url")
function handler()
    local args = ngx.req.get_uri_args()
    local target = args["next"]
    local safe = url.escape(target)
    ngx.redirect("/go?u=" .. safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.7 {
			t.Errorf("expected socket.url.escape to sanitize redirect flow, got conf %.2f", f.Confidence)
		}
	}
}

func TestLua_LuaSocketUrlEscape_NegativeControl(t *testing.T) {
	// Without the sanitizer, the same source -> sink pair must flow,
	// otherwise the positive test above is silently passing for the
	// wrong reason.
	code := `
function handler()
    local args = ngx.req.get_uri_args()
    local target = args["next"]
    ngx.redirect("/go?u=" .. target)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow without sanitizer (control); none of the configured sinks fired")
	}
}

// --- lua-bcrypt bcrypt.verify (SnkCrypto) ---
// Routes tainted password into a weak-crypto SnkCrypto sink (ngx.md5)
// after passing through the sanitizer. The negative-control variant
// asserts the flow WOULD fire without the sanitizer — guarding against
// the silent-pass failure where the sanitizer test "passes" only because
// no SnkCrypto sink ever sees the data.

func TestLua_BcryptVerify_NegativeControl(t *testing.T) {
	code := `
function handler()
    local args = ngx.req.get_post_args()
    local password = args["password"]
    return ngx.md5(password)
end
`
	flows := Analyze(code, "/app/auth.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow without sanitizer (control); ngx.md5 sink did not fire on tainted password")
	}
}

func TestLua_BcryptVerify_SanitizesCrypto(t *testing.T) {
	code := `
local bcrypt = require("bcrypt")
function handler()
    local args = ngx.req.get_post_args()
    local password = args["password"]
    local ok = bcrypt.verify(password, stored_hash)
    return ngx.md5(tostring(ok))
end
`
	flows := Analyze(code, "/app/auth.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Confidence > 0.7 {
			t.Errorf("expected bcrypt.verify to sanitize crypto flow, got conf %.2f (sink id=%s)", f.Confidence, f.Sink.ID)
		}
	}
}

// --- lua-resty-string to_hex (SnkHTMLOutput / SnkSQLQuery) ---

func TestLua_RestyStringToHex_NegativeControl(t *testing.T) {
	code := `
function handler()
    local args = ngx.req.get_uri_args()
    local input = args["data"]
    ngx.say("<p>raw=" .. input .. "</p>")
end
`
	flows := Analyze(code, "/app/render.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow without sanitizer (control); ngx.say sink did not fire on tainted query arg")
	}
}

func TestLua_RestyStringToHex_SanitizesHTMLOutput(t *testing.T) {
	code := `
local str = require("resty.string")
function handler()
    local args = ngx.req.get_uri_args()
    local input = args["data"]
    local hex = str.to_hex(input)
    ngx.say("<p>fingerprint=" .. hex .. "</p>")
end
`
	flows := Analyze(code, "/app/render.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.7 {
			t.Errorf("expected str.to_hex output to be safe in HTML context, got conf %.2f", f.Confidence)
		}
	}
}

// --- htmlentities.encode (SnkHTMLOutput) ---

func TestLua_HtmlentitiesEncode_SanitizesHTMLOutput(t *testing.T) {
	code := `
local htmlentities = require("htmlentities")
function handler()
    local args = ngx.req.get_uri_args()
    local name = args["name"]
    local safe = htmlentities.encode(name)
    ngx.say("<p>hello " .. safe .. "</p>")
end
`
	flows := Analyze(code, "/app/render.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.7 {
			t.Errorf("expected htmlentities.encode to sanitize XSS flow, got conf %.2f", f.Confidence)
		}
	}
}

func TestLua_HtmlentitiesEncode_NegativeControl(t *testing.T) {
	code := `
function handler()
    local args = ngx.req.get_uri_args()
    local name = args["name"]
    ngx.say("<p>hello " .. name .. "</p>")
end
`
	flows := Analyze(code, "/app/render.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow without sanitizer (control); none of the configured sinks fired")
	}
}

// --- Kong encode_base64url (SnkHeader / SnkHTMLOutput) ---

func TestLua_KongEncodeBase64Url_SanitizesHeader(t *testing.T) {
	code := `
local utils = require("kong.tools.utils")
function handler()
    local args = ngx.req.get_uri_args()
    local token = args["token"]
    local b64 = utils.encode_base64url(token)
    ngx.req.set_header("X-Trace", b64)
end
`
	flows := Analyze(code, "/app/proxy.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader && f.Confidence > 0.7 {
			t.Errorf("expected utils.encode_base64url to sanitize header injection flow, got conf %.2f", f.Confidence)
		}
	}
}

func TestLua_KongEncodeBase64Url_NegativeControl(t *testing.T) {
	code := `
function handler()
    local args = ngx.req.get_uri_args()
    local token = args["token"]
    ngx.req.set_header("X-Trace", token)
end
`
	flows := Analyze(code, "/app/proxy.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow without sanitizer (control); none of the configured sinks fired")
	}
}

// --- OpenResty ngx.quote_sql_str (SnkSQLQuery) ---
// Positive control: tainted ngx.var.arg flows into a lua-resty-mysql db:query
// (the same SQLi sink exercised by the passing resty-mysql tests). Proves the
// harness detects the flow before the sanitizer is applied.
func TestLuaSanitizer_NgxQuoteSqlStr_PositiveControl(t *testing.T) {
	code := `
function handler()
    local name = ngx.req.get_uri_args()["name"]
    local db = mysql:new()
    db:query("SELECT * FROM users WHERE name = '" .. name .. "'")
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("positive control: expected SQL injection flow without sanitizer; none of the configured sinks fired")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Sanitized: routing the tainted value through ngx.quote_sql_str clears the
// taint, so the same db:query must NOT produce a SQL flow.
func TestLuaSanitizer_NgxQuoteSqlStr_Sanitized(t *testing.T) {
	code := `
function handler()
    local name = ngx.req.get_uri_args()["name"]
    local db = mysql:new()
    local safe = ngx.quote_sql_str(name)
    db:query("SELECT * FROM users WHERE name = " .. safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SQL flow after ngx.quote_sql_str sanitizer, got conf %.2f (sink id=%s)", f.Confidence, f.Sink.ID)
		}
	}
}
