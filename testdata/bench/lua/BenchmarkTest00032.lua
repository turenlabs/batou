local shell = require "resty.shell"
local args = ngx.req.get_uri_args()
local dir = args.dir
if not dir:match("^[%w/%-_]+$") then
    ngx.exit(400)
end
local ok, stdout = shell.run("ls", {"-la", dir})
ngx.say(stdout)
