-- Source: CWE-78 - OS Command Injection via os.execute in Lua
-- Expected: BATOU-LUA
-- OWASP: A03:2021 - Injection (Command Injection)

local input = arg[1]
local cmd = "ping -c 1 " .. input
os.execute(cmd)
