local mysql = require "resty.mysql"
local args = ngx.req.get_uri_args()
local search = args.q
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="blog"})
local res = db:query("SELECT * FROM posts WHERE title LIKE '%" .. search .. "%'")
ngx.say(res)
