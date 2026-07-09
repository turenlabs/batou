local args = ngx.req.get_post_args()
os.execute("myapp status")
ngx.say("done")
