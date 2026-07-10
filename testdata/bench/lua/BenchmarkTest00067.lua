-- SSRF via cosocket TCP connect: vulnerable
local user_host = ngx.req.get_uri_args()["host"]
local tcp = ngx.socket.tcp()
tcp:connect(user_host, 6379)
tcp:send("PING\r\n")
local data = tcp:receive()
ngx.say(data)
