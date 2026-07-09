local mysql = require "resty.mysql"
local args = ngx.req.get_uri_args()
local name = args.name
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="app"})
local res = db:query("SELECT * FROM users WHERE name = '" .. name .. "'")
ngx.say(res)
