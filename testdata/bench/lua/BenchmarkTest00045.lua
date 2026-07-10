local args = ngx.req.get_uri_args()
local search = args.q
ngx.say(search)
