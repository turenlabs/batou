local user_agent = ngx.var.http_user_agent
ngx.say("<p>Your browser: " .. user_agent .. "</p>")
