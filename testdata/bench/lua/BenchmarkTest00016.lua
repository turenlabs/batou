local mysql = require "resty.mysql"
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="admin"})
local res = db:query("SELECT COUNT(*) FROM users")
ngx.say(res)
