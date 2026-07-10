local user_agent = ngx.var.http_user_agent
ngx.log(ngx.INFO, "UA: " .. user_agent)
ngx.say("<p>Your browser info has been logged.</p>")
