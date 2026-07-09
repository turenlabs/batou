local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local name = args.name
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
local res = pg:query("SELECT * FROM users WHERE name = $1", name)
ngx.say(res)
