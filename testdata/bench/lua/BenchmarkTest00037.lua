local args = ngx.req.get_post_args()
local archive_name = args.name
os.execute("tar czf /tmp/" .. archive_name .. ".tar.gz /var/data/")
ngx.say("archived")
