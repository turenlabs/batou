local pgmoon = require "pgmoon"
local args = ngx.req.get_post_args()
local username = args.username
local email = args.email
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
pg:query("INSERT INTO users (name, email) VALUES ($1, $2)", username, email)
ngx.say("created")
