local mysql = require "resty.mysql"
local args = ngx.req.get_uri_args()
local item_id = args.item_id
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="shop"})
db:query("DELETE FROM items WHERE id = " .. item_id)
ngx.say("deleted")
