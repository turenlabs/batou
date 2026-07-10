-- pgmoon SQL injection: vulnerable (simple_query with concat)
local pgmoon = require("pgmoon")
local pg = pgmoon.new({host="127.0.0.1", port="5432", database="mydb"})
pg:connect()
local user_input = ngx.req.get_uri_args()["search"]
local res = pg:simple_query("SELECT * FROM products WHERE name LIKE '%" .. user_input .. "%'")
ngx.say(res)
