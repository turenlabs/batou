-- Vulnerable Redis Lua script demonstrating injection issues
-- This file should trigger GTSS rules

-- LUA-003: SQL-like injection via string concatenation with KEYS/ARGV
local key = KEYS[1]
local user_input = ARGV[1]

-- Unsafe: building command strings with user input
local query = "SELECT * FROM cache WHERE key = '" .. user_input .. "'"

-- LUA-002: loadstring with external data (code injection)
local code = ARGV[2]
local fn = loadstring(code)
if fn then fn() end

return redis.call("GET", key)
