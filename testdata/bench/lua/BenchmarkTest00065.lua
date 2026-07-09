-- Tarantool SQL injection: vulnerable (string concat)
local user_input = ngx.req.get_uri_args()["name"]
local result = box.execute("SELECT * FROM users WHERE name = '" .. user_input .. "'")
ngx.say(result)
