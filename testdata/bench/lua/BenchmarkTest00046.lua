local cjson = require "cjson"
local args = ngx.req.get_uri_args()
local search = args.q
ngx.header.content_type = "application/json"
ngx.say(cjson.encode({query = search}))
