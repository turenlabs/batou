ngx.req.read_body()
local body = ngx.req.get_body_data()
ngx.say("<pre>" .. body .. "</pre>")
