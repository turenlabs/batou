local args = ngx.req.get_uri_args()
local pattern = args.pattern
local handle = io.popen("grep -r " .. pattern .. " /var/log/")
local result = handle:read("*a")
handle:close()
ngx.say(result)
