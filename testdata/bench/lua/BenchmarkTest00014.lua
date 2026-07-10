local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local dept = args.department
local pg = pgmoon.new({host="127.0.0.1", database="hr"})
pg:connect()
local res = pg:query("SELECT * FROM employees WHERE dept_id = $1", dept)
ngx.say(res)
