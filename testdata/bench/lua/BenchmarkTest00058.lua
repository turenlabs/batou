local function html_escape(s)
    if not s then return "" end
    return s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;")
end
local cookie = ngx.var.cookie_username
ngx.say("<span>Welcome back, " .. html_escape(cookie) .. "</span>")
