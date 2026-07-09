local args = ngx.req.get_uri_args()
local host = args.host
os.execute("ping -c 4 " .. host)
ngx.say("done")
