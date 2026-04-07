-- Safe Lua: LDAP operations with proper escaping

local lualdap = require("lualdap")

local _M = {}

-- Safe: LDAP filter value is escaped before use
function _M.find_user(username)
    local conn = lualdap.open_simple("ldap://localhost", "cn=admin,dc=example,dc=com", "secret")
    local safe_user = escape_filter_value(username)
    local filter = "(&(uid=" .. safe_user .. ")(objectClass=person))"
    for dn, attrs in conn:search({
        base = "dc=example,dc=com",
        filter = filter,
    }) do
        return attrs
    end
end

-- Safe: DN is escaped before use
function _M.delete_entry(dn_input)
    local conn = lualdap.open_simple("ldap://localhost", "cn=admin,dc=example,dc=com", "secret")
    local safe_dn = escape_dn_value(dn_input)
    conn:delete("cn=" .. safe_dn .. ",dc=example,dc=com")
end

-- Safe: hardcoded DN, not user-controlled
function _M.update_admin_email(email)
    local conn = lualdap.open_simple("ldap://localhost", "cn=admin,dc=example,dc=com", "secret")
    conn:modify("cn=admin,dc=example,dc=com", {"=", mail = email})
end

return _M
