package lua

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- LUA-001: Command Injection ---

func TestLUA001_OsExecuteConcat(t *testing.T) {
	content := `local user_input = ngx.req.get_uri_args()["cmd"]
os.execute("ls " .. user_input)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-001")
}

func TestLUA001_IoPopenConcat(t *testing.T) {
	content := `local host = ngx.var.arg_host
local handle = io.popen("ping -c 3 " .. host)
local result = handle:read("*a")
handle:close()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-001")
}

func TestLUA001_OsExecuteVariable(t *testing.T) {
	content := `local cmd = build_command(user_input)
os.execute(cmd)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-001")
}

func TestLUA001_Safe_StaticCommand(t *testing.T) {
	content := `os.execute("ls -la /tmp")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-001")
}

func TestLUA001_Safe_StaticPopen(t *testing.T) {
	content := `local handle = io.popen("date +%Y-%m-%d")
local result = handle:read("*a")
handle:close()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-001")
}

// --- LUA-002: Code Injection ---

func TestLUA002_LoadstringVariable(t *testing.T) {
	content := `local code = ngx.req.get_body_data()
local fn = loadstring(code)
fn()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-002")
}

func TestLUA002_LoadVariable(t *testing.T) {
	content := `local chunk = get_user_code()
local fn = load(chunk)
fn()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-002")
}

func TestLUA002_DofileVariable(t *testing.T) {
	content := `local filepath = ngx.var.arg_module
dofile(filepath)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-002")
}

func TestLUA002_LoadfileVariable(t *testing.T) {
	content := `local filepath = user_input
local fn = loadfile(filepath)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-002")
}

func TestLUA002_Safe_StaticLoadstring(t *testing.T) {
	content := `local fn = loadstring("return 1 + 2")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-002")
}

func TestLUA002_Safe_StaticDofile(t *testing.T) {
	content := `dofile("/usr/local/lib/lua/config.lua")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-002")
}

// --- LUA-003: SQL Injection ---

func TestLUA003_SQLConcat(t *testing.T) {
	content := `local name = ngx.req.get_uri_args()["name"]
local sql = "SELECT * FROM users WHERE name = '" .. name .. "'"
local res, err = db:query(sql)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-003")
}

func TestLUA003_SQLFormat(t *testing.T) {
	content := `local id = ngx.var.arg_id
local sql = string.format("SELECT * FROM users WHERE id = '%s'", id)
db:query(sql)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-003")
}

func TestLUA003_Safe_QuotedSQL(t *testing.T) {
	content := `local name = ngx.req.get_uri_args()["name"]
local quoted = ngx.quote_sql_str(name)
local sql = "SELECT * FROM users WHERE name = " .. quoted
db:query(sql)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-003")
}

func TestLUA003_Safe_NoSQL(t *testing.T) {
	content := `local name = "hello"
ngx.say(name)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-003")
}

// --- LUA-004: Path Traversal ---

func TestLUA004_IoOpenVariable(t *testing.T) {
	content := `local filename = ngx.var.arg_file
local f = io.open(filename, "r")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-004")
}

func TestLUA004_IoOpenConcat(t *testing.T) {
	content := `local filename = ngx.var.arg_file
local f = io.open("/data/" .. filename, "r")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-004")
}

func TestLUA004_Safe_StaticPath(t *testing.T) {
	content := `local f = io.open("/etc/config.lua", "r")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-004")
}

func TestLUA004_Safe_WithSanitization(t *testing.T) {
	content := `local filename = ngx.var.arg_file
filename = string.gsub(filename, "%.%.", "")
local f = io.open("/data/" .. filename, "r")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-004")
}

// --- LUA-005: XSS via ngx.say/ngx.print ---

func TestLUA005_NgxSayConcat(t *testing.T) {
	content := `local name = ngx.req.get_uri_args()["name"]
ngx.say("<h1>Hello, " .. name .. "</h1>")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-005")
}

func TestLUA005_NgxPrintVariable(t *testing.T) {
	content := `local data = ngx.req.get_body_data()
ngx.print(data)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-005")
}

func TestLUA005_Safe_Escaped(t *testing.T) {
	content := `local name = ngx.req.get_uri_args()["name"]
local escaped = ngx.escape_uri(name)
ngx.say("<h1>Hello, " .. escaped .. "</h1>")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-005")
}

func TestLUA005_Safe_NoUserInput(t *testing.T) {
	content := `ngx.say("Hello, world!")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-005")
}

// --- LUA-006: Insecure Deserialization ---

func TestLUA006_LoadstringNetwork(t *testing.T) {
	content := `local data = socket:receive("*a")
local fn = loadstring(data)
fn()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-006")
}

func TestLUA006_SerpentLoad(t *testing.T) {
	content := `local serpent = require("serpent")
local data = get_remote_data()
local ok, result = serpent.load(data)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-006")
}

func TestLUA006_Safe_CjsonDecode(t *testing.T) {
	content := `local cjson = require("cjson")
local data = ngx.req.get_body_data()
local obj = cjson.decode(data)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-006")
}

// --- LUA-007: Open Redirect ---

func TestLUA007_RedirectVariable(t *testing.T) {
	content := `local url = ngx.req.get_uri_args()["redirect_url"]
ngx.redirect(url)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-007")
}

func TestLUA007_RedirectConcat(t *testing.T) {
	content := `local path = ngx.var.arg_next
ngx.redirect("https://example.com" .. path)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-007")
}

func TestLUA007_Safe_StaticRedirect(t *testing.T) {
	content := `ngx.redirect("/login")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-007")
}

func TestLUA007_Safe_NoUserInput(t *testing.T) {
	content := `local target = "/dashboard"
ngx.redirect(target)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-007")
}

// --- LUA-008: Debug Library in Production ---

func TestLUA008_DebugSetmetatable(t *testing.T) {
	content := `debug.setmetatable(string, {__index = custom_string})
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-008")
}

func TestLUA008_DebugSethook(t *testing.T) {
	content := `debug.sethook(function() end, "c")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-008")
}

func TestLUA008_DebugGetinfo(t *testing.T) {
	content := `local info = debug.getinfo(2, "Sl")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-008")
}

func TestLUA008_DebugSetupvalue(t *testing.T) {
	content := `debug.setupvalue(target_fn, 1, malicious_value)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-008")
}

func TestLUA008_Safe_NoDebug(t *testing.T) {
	content := `local function process()
    local x = 42
    return x + 1
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-008")
}

func TestLUA008_Safe_Comment(t *testing.T) {
	content := `-- debug.getinfo is not used here
local x = 42
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-008")
}

// --- Fixture Tests ---

func TestFixture_Vulnerable(t *testing.T) {
	if !testutil.FixtureExists("lua/vulnerable/openresty_handler.lua") {
		t.Skip("Lua vulnerable fixture not available")
	}
	content := testutil.LoadFixture(t, "lua/vulnerable/openresty_handler.lua")
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.AssertMinFindings(t, result, 1)
}

func TestFixture_Safe(t *testing.T) {
	if !testutil.FixtureExists("lua/safe/openresty_handler.lua") {
		t.Skip("Lua safe fixture not available")
	}
	content := testutil.LoadFixture(t, "lua/safe/openresty_handler.lua")
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-001")
	testutil.MustNotFindRule(t, result, "BATOU-LUA-002")
	testutil.MustNotFindRule(t, result, "BATOU-LUA-003")
}
