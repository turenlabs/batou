-- LuaExpat XXE: safe (hardcoded XML)
local lxp = require "lxp"
local callbacks = {
    StartElement = function(parser, name, attrs)
        ngx.say("element: " .. name)
    end,
}
local parser = lxp.new(callbacks)
parser:parse("<config><version>1.0</version></config>")
parser:close()
