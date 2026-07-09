local args = ngx.req.get_uri_args()
local domain = args.domain
local handle = io.popen("nslookup " .. domain)
local result = handle:read("*a")
handle:close()
ngx.say(result)
