-- Vulnerable Lua: Lor framework XSS, XPath injection, MongoDB NoSQL injection

local lor = require("lor.index")
local xpath = require("xpath")
local lom = require("lxp.lom")

local app = lor()

-- XSS via Lor res:html with tainted query param
app:get("/greet", function(req, res, next)
    local name = req.query.name
    res:html("<h1>Hello, " .. name .. "</h1>")
end)

-- XSS via Lor res:send with tainted body
app:post("/echo", function(req, res, next)
    local msg = req.body.message
    res:send(msg)
end)

-- Open redirect via Lor res:redirect with tainted param
app:get("/login", function(req, res, next)
    local next_url = req.params.next
    res:redirect(next_url)
end)

-- SSTI via Lor res:render with tainted data
app:get("/profile", function(req, res, next)
    local template_name = req.query.template
    res:render(template_name, { user = "test" })
end)

-- Header injection via Lor res:set_header
app:get("/proxy", function(req, res, next)
    local origin = req.headers.origin
    res:set_header("Access-Control-Allow-Origin", origin)
end)

-- XPath injection via xpath.selectNodes
app:get("/search", function(req, res, next)
    local query = req.query.xpath
    local xml_tree = lom.parse(xml_data)
    local nodes = xpath.selectNodes(xml_tree, query)
    res:json(nodes)
end)

-- XPath injection via selector:xpath OOP style
app:get("/find", function(req, res, next)
    local expr = req.query.expr
    local items = selector:xpath(expr)
    res:json(items)
end)

-- MongoDB NoSQL injection via col:find
app:get("/users", function(req, res, next)
    local filter = req.query.filter
    local results = col:find(filter)
    res:json(results)
end)

-- MongoDB NoSQL injection via col:find_one
app:get("/user", function(req, res, next)
    local username = req.body.username
    local user = col:find_one({name = username})
    res:json(user)
end)

-- MongoDB NoSQL injection via col:delete
app:post("/delete", function(req, res, next)
    local id = req.body.id
    col:delete({_id = id})
    res:send("deleted")
end)

app:run()
