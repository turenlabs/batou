local args = ngx.req.get_uri_args()
os.execute("ping -c 4 localhost")
ngx.say("done")
