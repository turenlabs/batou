-- Vulnerable Lua deserialization patterns
-- This file should trigger LUA-006

local socket = require("socket")

-- LUA-006: loadstring used to deserialize network data
function receive_and_execute()
    local tcp = socket.tcp()
    tcp:connect("remote.server", 9000)
    local data = tcp:receive("*a")
    local fn = loadstring(data)
    if fn then fn() end
    tcp:close()
end

-- LUA-006: serpent.load from untrusted source
local serpent = require("serpent")

function load_remote_config()
    local data = get_remote_data()
    local ok, result = serpent.load(data)
    return result
end
