-- Source: CWE-89 - SQL Injection via string concatenation in Lua
-- Expected: BATOU-LUA
-- OWASP: A03:2021 - Injection (SQL Injection)

local mysql = require("luasql.mysql")

local function find_user(username)
    local env = mysql.mysql()
    local conn = env:connect("app", "root", "", "localhost")
    local query = "SELECT * FROM users WHERE name = '" .. username .. "'"
    local cursor = conn:execute(query)
    return cursor
end

local input = arg[1]
find_user(input)
