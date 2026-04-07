-- Vulnerable Lua: LDAP injection via LuaLDAP

local lualdap = require("lualdap")

local _M = {}

-- LDAP search with tainted filter
function _M.find_user(username)
    local conn = lualdap.open_simple("ldap://localhost", "cn=admin,dc=example,dc=com", "secret")
    local filter = "(&(uid=" .. username .. ")(objectClass=person))"
    for dn, attrs in conn:search({
        base = "dc=example,dc=com",
        filter = filter,
    }) do
        return attrs
    end
end

-- LDAP delete with tainted DN
function _M.delete_entry(dn)
    local conn = lualdap.open_simple("ldap://localhost", "cn=admin,dc=example,dc=com", "secret")
    conn:delete(dn)
end

-- LDAP modify with tainted DN
function _M.update_entry(dn, email)
    local conn = lualdap.open_simple("ldap://localhost", "cn=admin,dc=example,dc=com", "secret")
    conn:modify(dn, {"=", mail = email})
end

-- LDAP compare with tainted DN
function _M.check_password(dn, password)
    local conn = lualdap.open_simple("ldap://localhost", "cn=admin,dc=example,dc=com", "secret")
    return conn:compare(dn, "userPassword", password)
end

-- LDAP rename with tainted DN
function _M.rename_entry(old_dn, new_rdn)
    local conn = lualdap.open_simple("ldap://localhost", "cn=admin,dc=example,dc=com", "secret")
    conn:rename(old_dn, new_rdn)
end

return _M
