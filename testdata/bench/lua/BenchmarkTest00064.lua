-- LuaSQL SQL injection: safe (tonumber sanitization)
local luasql = require "luasql.postgres"
local env = luasql.postgres()
local conn = env:connect("mydb", "user", "pass", "127.0.0.1", 5432)
local user_input = ngx.req.get_uri_args()["id"]
local safe_id = tonumber(user_input)
local cur = conn:execute("DELETE FROM sessions WHERE user_id = " .. safe_id)
conn:close()
