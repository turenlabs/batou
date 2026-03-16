-- Source: CWE-22 - Path Traversal via io.open in Lua
-- Expected: BATOU-LUA
-- OWASP: A01:2021 - Broken Access Control (Path Traversal)

local input = arg[1]
local path = "/var/uploads/" .. input
local file = io.open(path, "r")
if file then
    local content = file:read("*a")
    print(content)
    file:close()
end
