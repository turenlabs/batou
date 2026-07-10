-- pgmoon SQL injection: safe (escape_literal sanitization)
local pgmoon = require("pgmoon")
local pg = pgmoon.new({host="127.0.0.1", port="5432", database="mydb"})
pg:connect()
local user_input = ngx.req.get_uri_args()["search"]
local safe_input = pg:escape_literal(user_input)
local res = pg:query("SELECT * FROM products WHERE name = " .. safe_input)
ngx.say(res)
