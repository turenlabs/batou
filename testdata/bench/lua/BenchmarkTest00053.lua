local args = ngx.req.get_uri_args()
local title = args.title
local desc = args.desc
ngx.print("<h1>" .. title .. "</h1><p>" .. desc .. "</p>")
