local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local user_id = args.uid
local pg = pgmoon.new({host="127.0.0.1", database="social"})
pg:connect()
local res = pg:query("SELECT p.* FROM posts p JOIN users u ON p.user_id = u.id WHERE u.id = $1", user_id)
ngx.say(res)
