package lua

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- LUA-015: OpenResty Args in SQL ---

func TestLUA015_Vulnerable(t *testing.T) {
	content := `local args = ngx.req.get_uri_args()
local name = args["name"]
local sql = "SELECT * FROM users WHERE name = '" .. name .. "'"
local res, err = db:query(sql)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-015")
}

func TestLUA015_PostArgs(t *testing.T) {
	content := `local args = ngx.req.get_post_args()
local id = args["id"]
local res = db:execute("DELETE FROM orders WHERE id = " .. id)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-015")
}

func TestLUA015_Safe_NoArgs(t *testing.T) {
	content := `local name = "admin"
local sql = "SELECT * FROM users WHERE name = '" .. name .. "'"
local res, err = db:query(sql)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-015")
}

func TestLUA015_Safe_NoSQL(t *testing.T) {
	content := `local args = ngx.req.get_uri_args()
local name = args["name"]
ngx.say("Hello, " .. name)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-015")
}

// --- LUA-016: Redis Injection ---

func TestLUA016_Vulnerable(t *testing.T) {
	content := `local key = ngx.var.arg_key
red:get(ngx.var.arg_key)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-016")
}

func TestLUA016_RedisCallArgs(t *testing.T) {
	content := `local val = args["cmd"]
redis:call("EVAL", args["script"], 0)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-016")
}

func TestLUA016_Safe_StaticKey(t *testing.T) {
	content := `red:get("static_key")
red:set("counter", 1)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-016")
}

func TestLUA016_Safe_SeparateLines(t *testing.T) {
	content := `local key = ngx.var.arg_key
local validated = validate(key)
red:get(validated)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-016")
}

// --- LUA-017: SSRF via ngx.location.capture ---

func TestLUA017_Vulnerable(t *testing.T) {
	content := `local target = ngx.var.arg_url
local res = ngx.location.capture("/proxy" .. target)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-017")
}

func TestLUA017_NearbyUserInput(t *testing.T) {
	content := `local args = ngx.req.get_uri_args()
local path = args["path"]
local url = "/internal/" .. path
local res = ngx.location.capture(url)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-017")
}

func TestLUA017_Safe_StaticPath(t *testing.T) {
	content := `local res = ngx.location.capture("/internal/health")
ngx.say(res.body)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-017")
}

// --- LUA-018: Redis Lua Sandbox Escape ---

func TestLUA018_Vulnerable(t *testing.T) {
	content := `redis.call("SET", "key", "value")
local fn = loadstring(user_script)
fn()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-018")
}

func TestLUA018_LoadFunction(t *testing.T) {
	content := `redis.call("GET", KEYS[1])
local chunk = load(ARGV[1])
chunk()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-018")
}

func TestLUA018_Safe_NoLoadstring(t *testing.T) {
	content := `redis.call("SET", KEYS[1], ARGV[1])
redis.call("GET", KEYS[1])
return redis.call("INCR", KEYS[2])
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-018")
}

func TestLUA018_Safe_NoRedisCall(t *testing.T) {
	content := `local fn = loadstring("return 1 + 2")
local result = fn()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-018")
}

// --- LUA-019: JWT Validation Bypass ---

func TestLUA019_Vulnerable(t *testing.T) {
	content := `local jwt = require("resty.jwt")
local jwt_token = ngx.var.arg_token
local jwt_obj = jwt:verify("secret", jwt_token)
if jwt_obj.verified then
    ngx.say("authenticated")
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-019")
}

func TestLUA019_VerifyJwtObj(t *testing.T) {
	content := `local jwt = require("resty.jwt")
local token = ngx.req.get_headers()["Authorization"]
local jwt_obj = jwt:verify_jwt_obj("secret", token)
if jwt_obj.valid then
    ngx.say("ok")
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-019")
}

func TestLUA019_Safe_AlgCheck(t *testing.T) {
	content := `local jwt = require("resty.jwt")
local token = ngx.var.arg_token
local jwt_obj = jwt:verify("secret", token)
if jwt_obj.header.alg ~= "HS256" then
    ngx.exit(ngx.HTTP_FORBIDDEN)
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-019")
}

func TestLUA019_Safe_AllowedAlg(t *testing.T) {
	content := `local jwt = require("resty.jwt")
local allowed_alg = { HS256 = true, HS384 = true }
local jwt_obj = jwt:verify("secret", token)
if not allowed_alg[jwt_obj.header.alg] then
    return ngx.exit(403)
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-019")
}

// --- LUA-020: LuaJIT FFI Unsafe Pointer ---

func TestLUA020_Vulnerable(t *testing.T) {
	content := `local ffi = require("ffi")
local ptr = ffi.cast("uint8_t*", buf)
ptr[0] = 0xFF
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-020")
}

func TestLUA020_VoidPointer(t *testing.T) {
	content := `local ffi = require("ffi")
local raw = ffi.cast("void*", address)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-020")
}

func TestLUA020_Safe_NoPointer(t *testing.T) {
	content := `local ffi = require("ffi")
local val = ffi.cast("int32_t", number)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-020")
}

func TestLUA020_Safe_FfiNew(t *testing.T) {
	content := `local ffi = require("ffi")
local buf = ffi.new("uint8_t[256]")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-020")
}

// --- LUA-021: LuaSocket Without TLS ---

func TestLUA021_Vulnerable(t *testing.T) {
	content := `local socket = require("socket")
local conn = socket.connect("api.example.com", 80)
conn:send("GET /data HTTP/1.1\r\n\r\n")
local response = conn:receive("*a")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-021")
}

func TestLUA021_SocketTcp(t *testing.T) {
	content := `local socket = require("socket")
local tcp = socket.tcp()
tcp:connect("db.internal", 5432)
tcp:send(query)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-021")
}

func TestLUA021_Safe_WithSSL(t *testing.T) {
	content := `local socket = require("socket")
local ssl = require("ssl")
local conn = socket.connect("api.example.com", 443)
conn = ssl.wrap(conn, {mode = "client", protocol = "tlsv1_2"})
conn:dohandshake()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-021")
}

func TestLUA021_Safe_NoSocket(t *testing.T) {
	content := `local http = require("resty.http")
local httpc = http.new()
local res = httpc:request_uri("https://api.example.com/data")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-021")
}

// --- LUA-022: string.dump Code Leak ---

func TestLUA022_Vulnerable(t *testing.T) {
	content := `local function secret_logic(x)
    return x * 42 + secret_key
end
local bytecode = string.dump(secret_logic)
ngx.say(bytecode)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-022")
}

func TestLUA022_NgxPrint(t *testing.T) {
	content := `local dumped = string.dump(handler_fn)
ngx.print(dumped)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-022")
}

func TestLUA022_Safe_NoResponse(t *testing.T) {
	content := `local bytecode = string.dump(my_function)
local f = io.open("/tmp/cache.bin", "wb")
f:write(bytecode)
f:close()
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-022")
}

func TestLUA022_Safe_NoDump(t *testing.T) {
	content := `local data = compute_result()
ngx.say(data)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-022")
}

// --- LUA-023: Missing HTTPS Redirect ---

func TestLUA023_Vulnerable(t *testing.T) {
	content := `if not authenticated then
    ngx.redirect("http://example.com/login")
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-023")
}

func TestLUA023_HttpRedirect(t *testing.T) {
	content := `ngx.redirect("http://internal.corp.com/callback")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-023")
}

func TestLUA023_Safe_HTTPS(t *testing.T) {
	content := `if not authenticated then
    ngx.redirect("https://example.com/login")
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-023")
}

func TestLUA023_Safe_RelativePath(t *testing.T) {
	content := `ngx.redirect("/login")
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-023")
}

// --- LUA-024: Insecure math.random ---

func TestLUA024_Vulnerable(t *testing.T) {
	content := `local function generate_auth_token(user_id)
    local token = ""
    for i = 1, 32 do
        token = token .. string.char(math.random(65, 90))
    end
    return token
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-024")
}

func TestLUA024_SessionId(t *testing.T) {
	content := `local function create_session(user)
    local session_id = math.random(100000, 999999)
    sessions[session_id] = user
    return session_id
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-024")
}

func TestLUA024_CsrfToken(t *testing.T) {
	content := `local function get_csrf_token()
    local nonce = tostring(math.random(1, 2^31))
    return nonce
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustFindRule(t, result, "BATOU-LUA-024")
}

func TestLUA024_Safe_NoSecurityContext(t *testing.T) {
	content := `local function shuffle(tbl)
    for i = #tbl, 2, -1 do
        local j = math.random(1, i)
        tbl[i], tbl[j] = tbl[j], tbl[i]
    end
    return tbl
end
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-024")
}

func TestLUA024_Safe_GameRandom(t *testing.T) {
	content := `local function roll_dice()
    return math.random(1, 6)
end
local result = roll_dice()
print("You rolled: " .. result)
`
	result := testutil.ScanContent(t, "/app/handler.lua", content)
	testutil.MustNotFindRule(t, result, "BATOU-LUA-024")
}
