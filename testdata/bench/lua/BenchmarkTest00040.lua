local http = require "resty.http"
local args = ngx.req.get_uri_args()
local url = args.url
local httpc = http.new()
local res = httpc:request_uri(url, {method = "GET"})
ngx.say(res.body)
