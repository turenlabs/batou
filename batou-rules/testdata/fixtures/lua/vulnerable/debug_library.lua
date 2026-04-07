-- Vulnerable Lua: Debug library usage in production

local _M = {}

-- LUA-008: debug.getinfo usage
function _M.get_caller_info()
    local info = debug.getinfo(2, "Sln")
    return info.source .. ":" .. info.currentline
end

-- LUA-008: debug.setmetatable (sandbox escape)
function _M.modify_string_meta()
    debug.setmetatable("", {
        __index = function(self, key)
            return "intercepted"
        end
    })
end

-- LUA-008: debug.sethook
function _M.install_hook()
    debug.sethook(function(event, line)
        print("Event:", event, "Line:", line)
    end, "cl")
end

-- LUA-008: debug.setupvalue (modify enclosing scope)
function _M.modify_upvalue(fn)
    debug.setupvalue(fn, 1, "malicious_value")
end

-- LUA-008: debug.getlocal (read local variables)
function _M.inspect_locals()
    local secret = "should_not_be_visible"
    local name, value = debug.getlocal(1, 1)
    return name, value
end

return _M
