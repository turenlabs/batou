local pgmoon = require "pgmoon"
local args = ngx.req.get_post_args()
local username = args.username
local email = args.email
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
local q = string.format("INSERT INTO users (name, email) VALUES ('%s', '%s')", username, email)
pg:query(q)
ngx.say("created")
