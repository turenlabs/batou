local mysql = require "resty.mysql"
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="shop"})
db:query("DELETE FROM items WHERE id = 42")
ngx.say("deleted")
