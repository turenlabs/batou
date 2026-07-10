local mysql = require "resty.mysql"
local args = ngx.req.get_uri_args()
local table_name = args.table
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="admin"})
local q = string.format("SELECT COUNT(*) FROM %s", table_name)
local res = db:query(q)
ngx.say(res)
