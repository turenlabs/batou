-- Vulnerable Lua: Path traversal and file access

local _M = {}

-- LUA-004: Path traversal via io.open with user variable
function _M.read_file(filename)
    local f = io.open(filename, "r")
    if f then
        local content = f:read("*a")
        f:close()
        return content
    end
    return nil
end

-- LUA-004: Path traversal via io.open with concatenation
function _M.read_upload(upload_dir, name)
    local f = io.open(upload_dir .. "/" .. name, "r")
    if f then
        local data = f:read("*a")
        f:close()
        return data
    end
    return nil
end

-- LUA-002: Code injection via load() with variable
function _M.run_plugin(plugin_code)
    local fn = load(plugin_code)
    if fn then
        return fn()
    end
end

-- LUA-002: Code injection via loadfile with variable
function _M.load_module(module_path)
    local fn = loadfile(module_path)
    if fn then
        return fn()
    end
end

return _M
