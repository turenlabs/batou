local args = ngx.req.get_uri_args()
local dir = args.dir
local handle = io.popen("ls -la " .. dir)
local result = handle:read("*a")
handle:close()
ngx.say(result)
