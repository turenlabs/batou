-- Vulnerable Lua: File read with tainted path (path traversal)

local lfs = require("lfs")

local _M = {}

-- File read with user-controlled path
function _M.serve_file(path)
    local f = io.open(path, "r")
    local content = f:read("*a")
    f:close()
    return content
end

-- File info disclosure with user-controlled path
function _M.check_file(path)
    local attrs = lfs.attributes(path)
    return attrs
end

-- OpenResty: read file from user-supplied path
function _M.handle_request()
    local args = ngx.req.get_uri_args()
    local filepath = args["file"]
    local f = io.open(filepath, "r")
    local data = f:read("*a")
    ngx.say(data)
end

return _M
