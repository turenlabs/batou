-- Safe OpenResty handler demonstrating secure Lua patterns
-- This file should NOT trigger GTSS rules for injection/XSS/traversal

local _M = {}
local cjson = require("cjson")

-- SAFE: Parameterized query with quote_sql_str
function _M.user_lookup()
    local args = ngx.req.get_uri_args()
    local name = args["name"]
    if not name or name == "" then
        ngx.status = 400
        ngx.say(cjson.encode({error = "name required"}))
        return
    end
    local quoted = ngx.quote_sql_str(name)
    local sql = "SELECT * FROM users WHERE name = " .. quoted
    -- query with escaped input
end

-- SAFE: Numeric validation prevents injection
function _M.user_by_id()
    local args = ngx.req.get_uri_args()
    local id = tonumber(args["id"])
    if not id then
        ngx.status = 400
        ngx.say(cjson.encode({error = "invalid id"}))
        return
    end
    local sql = "SELECT * FROM users WHERE id = " .. id
end

-- SAFE: HTML escaping prevents XSS
function _M.greeting()
    local args = ngx.req.get_uri_args()
    local name = args["name"] or "World"
    local escaped = ngx.escape_uri(name)
    ngx.header["Content-Type"] = "text/html"
    ngx.say("<html><body><h1>Hello, " .. escaped .. "!</h1></body></html>")
end

-- SAFE: JSON response (no XSS risk)
function _M.api_response()
    local args = ngx.req.get_uri_args()
    local name = args["name"]
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({greeting = "Hello, " .. (name or "World")}))
end

-- SAFE: Static redirect (no open redirect)
function _M.redirect_to_login()
    ngx.redirect("/login")
end

-- SAFE: Path validation prevents traversal
function _M.read_file()
    local args = ngx.req.get_uri_args()
    local filename = args["file"]
    if not filename then
        ngx.status = 400
        return
    end
    -- Sanitize: remove directory traversal
    filename = string.gsub(filename, "%.%.", "")
    filename = string.gsub(filename, "/", "")
    local f = io.open("/data/public/" .. filename, "r")
    if f then
        local content = f:read("*a")
        f:close()
        ngx.say(content)
    else
        ngx.status = 404
    end
end

-- SAFE: Static command execution (no injection)
function _M.get_uptime()
    local handle = io.popen("uptime")
    local result = handle:read("*a")
    handle:close()
    ngx.say(result)
end

-- SAFE: Using cjson.decode instead of loadstring for deserialization
function _M.parse_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local ok, data = pcall(cjson.decode, body)
    if not ok then
        ngx.status = 400
        ngx.say(cjson.encode({error = "invalid JSON"}))
        return
    end
    -- Process data safely
end

return _M
