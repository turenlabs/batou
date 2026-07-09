-- LuaExpat XXE: vulnerable (parsing untrusted XML)
local lxp = require "lxp"
local body = ngx.req.get_body_data()
local callbacks = {
    StartElement = function(parser, name, attrs)
        ngx.say("element: " .. name)
    end,
}
local parser = lxp.new(callbacks)
parser:parse(body)
parser:close()
