local args = ngx.req.get_uri_args()
local value = args.value
ngx.say("<input type='text' value='" .. value .. "'>")
