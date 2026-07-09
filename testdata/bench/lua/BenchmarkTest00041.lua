local args = ngx.req.get_uri_args()
local name = args.name
ngx.say("<h1>Hello " .. name .. "</h1>")
