local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local id = args.id
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
local query = string.format("SELECT * FROM orders WHERE id = %s", id)
local res = pg:query(query)
ngx.say(res)
