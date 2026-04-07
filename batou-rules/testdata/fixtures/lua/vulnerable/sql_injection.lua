-- Vulnerable Lua: SQL injection patterns

local _M = {}

-- LUA-003: SQL injection via string concatenation
function _M.find_user(db, username)
    local sql = "SELECT * FROM users WHERE username = '" .. username .. "'"
    return db:query(sql)
end

-- LUA-003: SQL injection via string.format
function _M.search_products(db, term)
    local sql = string.format("SELECT * FROM products WHERE name LIKE '%%%s%%'", term)
    return db:query(sql)
end

-- LUA-003: SQL injection in DELETE
function _M.delete_record(db, id)
    local sql = "DELETE FROM records WHERE id = " .. id
    return db:query(sql)
end

return _M
