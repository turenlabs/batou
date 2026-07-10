-- pgmoon SQL injection: safe (parameterized query)
local pgmoon = require("pgmoon")
local pg = pgmoon.new({host="127.0.0.1", port="5432", database="mydb"})
pg:connect()
local user_input = ngx.req.get_uri_args()["username"]
local res = pg:query("SELECT * FROM users WHERE name = $1", user_input)
ngx.say(res)
