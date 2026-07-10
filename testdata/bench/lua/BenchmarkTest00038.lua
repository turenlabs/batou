local args = ngx.req.get_post_args()
os.execute("tar czf /tmp/backup.tar.gz /var/data/")
ngx.say("archived")
