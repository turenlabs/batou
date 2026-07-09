local args = ngx.req.get_uri_args()
local domain = args.domain
local resolver = require "resty.dns.resolver"
local r = resolver:new({nameservers = {"8.8.8.8"}})
local answers = r:query(domain)
ngx.say(answers)
