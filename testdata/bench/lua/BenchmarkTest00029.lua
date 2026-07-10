local args = ngx.req.get_uri_args()
local target = args.target
os.execute("traceroute " .. target)
ngx.say("trace complete")
