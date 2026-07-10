local mysql = require "resty.mysql"
local args = ngx.req.get_post_args()
local status = args.status
local oid = args.order_id
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="store"})
db:query("UPDATE orders SET status = '" .. status .. "' WHERE id = " .. oid)
ngx.say("updated")
