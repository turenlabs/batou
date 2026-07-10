local mysql = require "resty.mysql"
local args = ngx.req.get_post_args()
local user = args.username
local pass = args.password
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="auth"})
local res = db:query("SELECT * FROM accounts WHERE username = '" .. user .. "' AND password = '" .. pass .. "'")
ngx.say(res)
