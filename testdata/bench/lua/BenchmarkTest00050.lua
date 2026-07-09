local function html_escape(s)
    return s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
end
ngx.req.read_body()
local args = ngx.req.get_post_args()
local comment = args.comment
ngx.print("<p>" .. html_escape(comment) .. "</p>")
