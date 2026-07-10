local mysql = require "resty.mysql"
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="store"})
db:query("UPDATE orders SET status = 'shipped' WHERE id = 100")
ngx.say("updated")
