local mysql = require "resty.mysql"
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="blog"})
local res = db:query("SELECT * FROM posts WHERE title LIKE '%news%'")
ngx.say(res)
