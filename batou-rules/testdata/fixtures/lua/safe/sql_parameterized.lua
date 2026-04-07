-- Safe Lua: Parameterized SQL queries

local _M = {}

-- SAFE: Using quote_sql_str for escaping
function _M.find_user(db, username)
    local escaped = ngx.quote_sql_str(username)
    local sql = "SELECT * FROM users WHERE username = " .. escaped
    return db:query(sql)
end

-- SAFE: Static SQL query
function _M.get_all_users(db)
    return db:query("SELECT id, name, email FROM users ORDER BY id")
end

-- SAFE: Using ndk.set_var for SQL escaping
function _M.search(db, term)
    local safe_term = ndk.set_var.set_quote_sql_str(term)
    local sql = "SELECT * FROM products WHERE name LIKE " .. safe_term
    return db:query(sql)
end

return _M
