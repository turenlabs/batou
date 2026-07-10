local args = ngx.req.get_uri_args()
local filename = args.file
os.execute("cat " .. filename)
ngx.say("done")
