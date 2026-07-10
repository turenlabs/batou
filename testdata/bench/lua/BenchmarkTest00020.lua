local pgmoon = require "pgmoon"
local args = ngx.req.get_post_args()
local user = args.username
local pass = args.password
local pg = pgmoon.new({host="127.0.0.1", database="auth"})
pg:connect()
local res = pg:query("SELECT * FROM accounts WHERE username = $1 AND password = $2", user, pass)
ngx.say(res)
