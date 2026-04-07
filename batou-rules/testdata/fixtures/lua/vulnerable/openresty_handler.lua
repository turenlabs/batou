-- Vulnerable OpenResty handler demonstrating common Lua security issues
-- This file should trigger multiple GTSS rules

local _M = {}

-- LUA-001: Command injection via os.execute with user input
function _M.ping_handler()
    local args = ngx.req.get_uri_args()
    local host = args["host"]
    os.execute("ping -c 3 " .. host)
end

-- LUA-001: Command injection via io.popen with user input
function _M.lookup_handler()
    local args = ngx.req.get_uri_args()
    local domain = args["domain"]
    local handle = io.popen("nslookup " .. domain)
    local result = handle:read("*a")
    handle:close()
    ngx.say(result)
end

-- LUA-002: Code injection via loadstring with user data
function _M.eval_handler()
    ngx.req.read_body()
    local code = ngx.req.get_body_data()
    local fn = loadstring(code)
    if fn then fn() end
end

-- LUA-002: Code injection via dofile with user-controlled path
function _M.plugin_handler()
    local args = ngx.req.get_uri_args()
    local plugin = args["plugin"]
    dofile(plugin)
end

-- LUA-003: SQL injection via string concatenation
function _M.user_lookup()
    local args = ngx.req.get_uri_args()
    local name = args["name"]
    local sql = "SELECT * FROM users WHERE name = '" .. name .. "'"
    local db = require("resty.mysql"):new()
    db:query(sql)
end

-- LUA-003: SQL injection via string.format
function _M.user_search()
    local args = ngx.req.get_uri_args()
    local term = args["q"]
    local sql = string.format("SELECT * FROM products WHERE name LIKE '%%%s%%'", term)
    db:query(sql)
end

-- LUA-004: Path traversal via io.open with user path
function _M.file_read()
    local args = ngx.req.get_uri_args()
    local filename = args["file"]
    local f = io.open(filename, "r")
    if f then
        local content = f:read("*a")
        f:close()
        ngx.say(content)
    end
end

-- LUA-005: XSS via ngx.say with unescaped user input
function _M.greeting()
    local args = ngx.req.get_uri_args()
    local name = args["name"]
    ngx.say("<html><body><h1>Hello, " .. name .. "!</h1></body></html>")
end

-- LUA-007: Open redirect via ngx.redirect with user URL
function _M.redirect_handler()
    local args = ngx.req.get_uri_args()
    local url = args["next"]
    ngx.redirect(url)
end

-- LUA-008: Debug library usage
function _M.debug_handler()
    local info = debug.getinfo(2, "Sl")
    debug.setmetatable(string, {__index = function() return "pwned" end})
end

return _M
