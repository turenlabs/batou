local args = ngx.req.get_uri_args()
local filename = args.file
if not filename:match("^[%w%.%-_]+$") then
    ngx.exit(400)
end
local f = io.open("/var/data/" .. filename, "r")
local content = f:read("*a")
f:close()
ngx.say(content)
