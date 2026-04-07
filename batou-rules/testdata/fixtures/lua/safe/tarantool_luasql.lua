-- Safe Lua: Tarantool, LuaSQL, LuaExpat, and LuaFileSystem patterns

local _M = {}

-- Tarantool parameterized SQL query (safe)
function _M.find_user(req)
    local name = req:query_param("name")
    -- batou:ignore BATOU-LUA-AST-005 -- parameterized query with bind variable, not string concat
    local result = box.execute("SELECT * FROM users WHERE name = ?", {name})
    return result
end

-- Tarantool box.eval with hardcoded string (safe)
function _M.get_stats()
    return box.eval("return box.info.memory()")
end

-- LuaSQL prepared statement (safe)
function _M.luasql_query(conn, username)
    local stmt = conn:prepare("SELECT * FROM users WHERE name = ?")
    stmt:execute(username)
    return stmt:fetch()
end

-- LuaExpat threat parser with restrictions (safe)
function _M.parse_xml_safe(body)
    local lxp = require("lxp")
    local parser = lxp.new({}, nil, false, {
        threat = {
            maxChildren = 100,
            maxDepth = 50,
            maxDocSize = 1048576,
        }
    })
    parser:parse(body)
    parser:close()
end

-- LuaFileSystem mkdir with validated path (safe)
function _M.create_dir(dirname)
    local safe = string.match(dirname, "^%w+$")
    if safe then
        lfs.mkdir("/uploads/" .. safe)
    end
end

-- OpenResty URI rewrite with allowlist (safe)
function _M.rewrite_uri()
    local target = ngx.req.get_uri_args()["target"]
    local allowed_uris = {["/home"] = true, ["/about"] = true, ["/help"] = true}
    if allowed_uris[target] then
        ngx.req.set_uri(target)
    end
end

-- String truncation sanitizer (safe)
function _M.log_input()
    local input = ngx.req.get_uri_args()["q"]
    local truncated = string.sub(input, 1, 128)
    ngx.log(ngx.INFO, truncated)
end

return _M
