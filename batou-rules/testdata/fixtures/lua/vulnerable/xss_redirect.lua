-- Vulnerable Lua: XSS and open redirect via OpenResty

local _M = {}

-- LUA-005: XSS via ngx.say with concatenated user input
function _M.greet()
    local args = ngx.req.get_uri_args()
    local name = args["name"]
    ngx.say("<html><body><h1>Welcome, " .. name .. "!</h1></body></html>")
end

-- LUA-005: XSS via ngx.print with variable
function _M.echo()
    local args = ngx.req.get_uri_args()
    local msg = args["msg"]
    ngx.print(msg)
end

-- LUA-007: Open redirect via ngx.redirect with user URL
function _M.login_redirect()
    local args = ngx.req.get_uri_args()
    local next_url = args["next"]
    ngx.redirect(next_url)
end

-- LUA-007: Open redirect with concatenation
function _M.goto_page()
    local args = ngx.req.get_uri_args()
    local page = args["page"]
    ngx.redirect("/app/" .. page)
end

return _M
