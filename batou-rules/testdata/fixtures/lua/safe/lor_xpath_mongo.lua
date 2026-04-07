-- Safe Lua: Lor framework with proper sanitization, safe XPath, safe MongoDB

local lor = require("lor.index")
local xpath = require("xpath")
local lom = require("lxp.lom")

local app = lor()

-- Safe: HTML escaped output
app:get("/greet", function(req, res, next)
    local name = req.query.name
    local escaped = ngx.escape_uri(name)
    res:html("<h1>Hello, " .. escaped .. "</h1>")
end)

-- Safe: JSON response (not raw HTML)
app:post("/echo", function(req, res, next)
    local msg = req.body.message
    res:json({ message = msg })
end)

-- Safe: Redirect with allowlist validation
app:get("/login", function(req, res, next)
    local next_url = req.params.next
    local allowed_urls = { ["/dashboard"] = true, ["/profile"] = true }
    if allowed_urls[next_url] then
        res:redirect(next_url)
    else
        res:redirect("/dashboard")
    end
end)

-- Safe: Static template name, not user-controlled
app:get("/profile", function(req, res, next)
    res:render("profile.html", { user = "test" })
end)

-- Safe: Header with validated value
app:get("/proxy", function(req, res, next)
    local origin = req.headers.origin
    local allowed_origins = { ["https://example.com"] = true }
    if allowed_origins[origin] then
        res:set_header("Access-Control-Allow-Origin", origin)
    end
end)

-- Safe: Static XPath expression, not user-controlled
app:get("/search", function(req, res, next)
    local xml_tree = lom.parse(xml_data)
    local nodes = xpath.selectNodes(xml_tree, "//item[@type='public']")
    res:json(nodes)
end)

-- Safe: MongoDB query with validated/sanitized input
app:get("/users", function(req, res, next)
    local page = tonumber(req.query.page)
    local results = col:find({active = true})
    res:json(results)
end)

-- Safe: MongoDB with parameterized lookup by known field
app:get("/user", function(req, res, next)
    local id = tonumber(req.body.id)
    if id then
        local user = col:find_one({_id = id})
        res:json(user)
    end
end)

app:run()
