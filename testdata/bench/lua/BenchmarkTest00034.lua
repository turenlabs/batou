local args = ngx.req.get_post_args()
os.execute("convert /uploads/photo.jpg /output/photo.png")
ngx.say("converted")
