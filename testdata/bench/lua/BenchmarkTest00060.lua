local args = ngx.req.get_uri_args()
local error_msg = args.error
ngx.print("<div class='error'>" .. ngx.escape_uri(error_msg) .. "</div>")
