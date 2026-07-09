local args = ngx.req.get_uri_args()
local url = args.url
local handle = io.popen("curl -s " .. url)
local body = handle:read("*a")
handle:close()
ngx.say(body)
