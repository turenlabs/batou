local template = require "resty.template"
ngx.req.read_body()
local body = ngx.req.get_body_data()
ngx.say("<pre>" .. template.escape(body) .. "</pre>")
