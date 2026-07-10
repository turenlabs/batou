-- Tarantool SQL injection: safe (hardcoded query)
local result = box.execute("SELECT * FROM users WHERE active = 1")
ngx.say(result)
