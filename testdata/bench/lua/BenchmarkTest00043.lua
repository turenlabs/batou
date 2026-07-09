local args = ngx.req.get_uri_args()
local message = args.msg
ngx.print("<div>" .. message .. "</div>")
