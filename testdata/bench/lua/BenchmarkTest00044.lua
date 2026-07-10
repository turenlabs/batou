local function html_escape(s)
    return s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;"):gsub("'", "&#39;")
end
local args = ngx.req.get_uri_args()
local message = args.msg
ngx.print("<div>" .. html_escape(message) .. "</div>")
