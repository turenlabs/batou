local args = ngx.req.get_post_args()
local input_file = args.input
os.execute("convert " .. input_file .. " output.png")
ngx.say("converted")
