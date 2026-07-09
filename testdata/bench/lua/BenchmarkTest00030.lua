local args = ngx.req.get_uri_args()
os.execute("traceroute 8.8.8.8")
ngx.say("trace complete")
