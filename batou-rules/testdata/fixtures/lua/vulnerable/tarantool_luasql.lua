-- Vulnerable Lua: Tarantool, LuaSQL, LuaExpat, and LuaFileSystem patterns

local _M = {}

-- Tarantool SQL injection via box.execute with string concat
function _M.find_user(req)
    local name = req:query_param("name")
    local result = box.execute("SELECT * FROM users WHERE name = '" .. name .. "'")
    return result
end

-- Tarantool code injection via box.eval
function _M.run_code(req)
    local code = req:json().code
    return box.eval(code)
end

-- Tarantool HTTP body source flowing to space insert
function _M.create_record(req)
    local body = req:json()
    local data = body.payload
    box.execute("INSERT INTO records VALUES ('" .. data .. "')")
end

-- LuaSQL SQL injection via conn:execute
function _M.luasql_query(conn, username)
    local input = ngx.req.get_uri_args()["user"]
    local sql = "SELECT * FROM users WHERE name = '" .. input .. "'"
    local cur = conn:execute(sql)
    return cur
end

-- LuaExpat XML parsing with untrusted input (XXE risk)
function _M.parse_xml(req)
    local body = ngx.req.get_body_data()
    local lxp = require("lxp")
    local parser = lxp.new({})
    parser:parse(body)
    parser:close()
end

-- LuaExpat lom.parse with untrusted input
function _M.parse_xml_lom(req)
    local lom = require("lxp.lom")
    local body = ngx.req.get_body_data()
    local doc = lom.parse(body)
    return doc
end

-- LuaFileSystem mkdir with tainted path
function _M.create_dir(req)
    local dirname = ngx.req.get_uri_args()["dir"]
    lfs.mkdir("/uploads/" .. dirname)
end

-- LuaFileSystem rmdir with tainted path
function _M.remove_dir(req)
    local dirname = ngx.req.get_uri_args()["dir"]
    lfs.rmdir("/data/" .. dirname)
end

-- LuaFileSystem chdir with tainted path
function _M.change_dir(req)
    local path = ngx.req.get_uri_args()["path"]
    lfs.chdir(path)
end

-- OpenResty URI rewrite with tainted input
function _M.rewrite_uri()
    local target = ngx.req.get_uri_args()["target"]
    ngx.req.set_uri(target)
end

-- Tarantool fiber channel source to eval sink
function _M.process_channel()
    local fiber = require("fiber")
    local ch = fiber.channel(1)
    local data = ch:get()
    box.eval(data)
end

return _M
