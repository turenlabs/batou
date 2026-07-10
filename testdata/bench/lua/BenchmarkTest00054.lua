local cjson = require "cjson"
local args = ngx.req.get_uri_args()
local title = args.title
local desc = args.desc
ngx.header.content_type = "application/json"
ngx.say(cjson.encode({title = title, description = desc}))
