ngx.req.read_body()
local args = ngx.req.get_post_args()
local comment = args.comment
ngx.print("<p>" .. comment .. "</p>")
