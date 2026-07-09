local cookie = ngx.var.cookie_username
ngx.say("<span>Welcome back, " .. cookie .. "</span>")
