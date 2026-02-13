-- Safe Redis Lua script demonstrating proper KEYS/ARGV usage
-- This file should NOT trigger GTSS rules

-- SAFE: Using KEYS and ARGV through redis.call parameters (not string concat)
local key = KEYS[1]
local value = ARGV[1]
local ttl = tonumber(ARGV[2])

-- SAFE: Direct parameterized redis calls
redis.call("SET", key, value)

if ttl and ttl > 0 then
    redis.call("EXPIRE", key, ttl)
end

-- SAFE: Numeric validation
local count = tonumber(ARGV[3]) or 0
if count > 0 then
    redis.call("INCRBY", key .. ":counter", count)
end

return redis.call("GET", key)
