package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

func (c *LuaCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- OpenResty / ngx_lua request input ---
		{
			ID:          "lua.ngx.req.get_uri_args",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `ngx\.req\.get_uri_args\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.req.get_uri_args",
			Description: "OpenResty URI query arguments",
			Assigns:     "return",
		},
		{
			ID:          "lua.ngx.req.get_post_args",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `ngx\.req\.get_post_args\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.req.get_post_args",
			Description: "OpenResty POST body arguments",
			Assigns:     "return",
		},
		{
			ID:          "lua.ngx.req.get_body_data",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `ngx\.req\.get_body_data\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.req.get_body_data",
			Description: "OpenResty raw request body",
			Assigns:     "return",
		},
		{
			ID:          "lua.ngx.req.get_headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `ngx\.req\.get_headers\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.req.get_headers",
			Description: "OpenResty request headers",
			Assigns:     "return",
		},
		{
			ID:          "lua.ngx.var",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `ngx\.var\.\w+`,
			ObjectType:  "ngx",
			MethodName:  "ngx.var",
			Description: "OpenResty nginx variable (may contain user input)",
			Assigns:     "return",
		},
		{
			ID:          "lua.ngx.req.raw_header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `ngx\.req\.raw_header\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.req.raw_header",
			Description: "OpenResty raw request header string",
			Assigns:     "return",
		},

		// --- LOVE2D filesystem input ---
		{
			ID:          "lua.love.filesystem.read",
			Category:    taint.SrcFileRead,
			Language:    rules.LangLua,
			Pattern:     `love\.filesystem\.read\s*\(`,
			ObjectType:  "love",
			MethodName:  "love.filesystem.read",
			Description: "LOVE2D file read (may read user-supplied files)",
			Assigns:     "return",
		},
		{
			ID:          "lua.love.filesystem.lines",
			Category:    taint.SrcFileRead,
			Language:    rules.LangLua,
			Pattern:     `love\.filesystem\.lines\s*\(`,
			ObjectType:  "love",
			MethodName:  "love.filesystem.lines",
			Description: "LOVE2D file lines iterator",
			Assigns:     "return",
		},

		// --- Standard library input ---
		{
			ID:          "lua.io.read",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `io\.read\s*\(`,
			ObjectType:  "",
			MethodName:  "io.read",
			Description: "Standard input read",
			Assigns:     "return",
		},
		{
			ID:          "lua.io.lines",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `io\.lines\s*\(`,
			ObjectType:  "",
			MethodName:  "io.lines",
			Description: "Standard input line iterator",
			Assigns:     "return",
		},
		{
			ID:          "lua.os.getenv",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangLua,
			Pattern:     `os\.getenv\s*\(`,
			ObjectType:  "",
			MethodName:  "os.getenv",
			Description: "Environment variable value",
			Assigns:     "return",
		},
		{
			ID:          "lua.arg",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangLua,
			Pattern:     `\barg\s*\[`,
			ObjectType:  "",
			MethodName:  "arg[]",
			Description: "Command-line argument table",
			Assigns:     "return",
		},

		// --- Redis Lua scripting ---
		{
			ID:          "lua.redis.keys",
			Category:    taint.SrcExternal,
			Language:    rules.LangLua,
			Pattern:     `KEYS\s*\[`,
			ObjectType:  "redis",
			MethodName:  "KEYS[]",
			Description: "Redis Lua script KEYS table (external input)",
			Assigns:     "return",
		},
		{
			ID:          "lua.redis.argv",
			Category:    taint.SrcExternal,
			Language:    rules.LangLua,
			Pattern:     `ARGV\s*\[`,
			ObjectType:  "redis",
			MethodName:  "ARGV[]",
			Description: "Redis Lua script ARGV table (external input)",
			Assigns:     "return",
		},

		// --- Network / socket input ---
		{
			ID:          "lua.socket.receive",
			Category:    taint.SrcNetwork,
			Language:    rules.LangLua,
			Pattern:     `:receive\s*\(`,
			ObjectType:  "socket",
			MethodName:  "socket:receive",
			Description: "LuaSocket network receive",
			Assigns:     "return",
		},
		{
			ID:          "lua.ngx.socket.tcp.receive",
			Category:    taint.SrcNetwork,
			Language:    rules.LangLua,
			Pattern:     `tcp:receive\s*\(|sock:receive\s*\(`,
			ObjectType:  "ngx.socket",
			MethodName:  "cosocket:receive",
			Description: "OpenResty cosocket TCP receive",
			Assigns:     "return",
		},

		// --- Lapis framework ---
		{
			ID:          "lua.lapis.params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `self\.params\.\w+|self\.params\[`,
			ObjectType:  "lapis",
			MethodName:  "self.params",
			Description: "Lapis web framework request parameters",
			Assigns:     "return",
		},
		{
			ID:          "lua.lapis.req",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `self\.req\.parsed_url|self\.req\.headers`,
			ObjectType:  "lapis",
			MethodName:  "self.req",
			Description: "Lapis web framework request data",
			Assigns:     "return",
		},

		// --- OpenResty cookies ---
		{
			ID:          "lua.ngx.req.cookies",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `ngx\.var\.cookie_\w+|resty\.cookie`,
			ObjectType:  "ngx",
			MethodName:  "ngx.var.cookie_*",
			Description: "OpenResty cookie value",
			Assigns:     "return",
		},

		// --- JSON deserialization ---
		{
			ID:          "lua.cjson.decode",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangLua,
			Pattern:     `cjson\.decode\s*\(|cjson\.new\s*\(\s*\)\s*\.decode\s*\(|dkjson\.decode\s*\(`,
			ObjectType:  "cjson",
			MethodName:  "cjson.decode",
			Description: "JSON deserialized data from untrusted source",
			Assigns:     "return",
		},

		// --- OpenResty request method ---
		{
			ID:          "lua.ngx.req.method",
			Category:    taint.SrcUserInput,
			Language:    rules.LangLua,
			Pattern:     `ngx\.req\.get_method\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.req.get_method",
			Description: "OpenResty request method string",
			Assigns:     "return",
		},

		// --- File input ---
		{
			ID:          "lua.file.read",
			Category:    taint.SrcFileRead,
			Language:    rules.LangLua,
			Pattern:     `file:read\s*\(|:read\s*\(\s*"\*a"|:read\s*\(\s*"\*l"`,
			ObjectType:  "",
			MethodName:  "file:read",
			Description: "File handle read operation",
			Assigns:     "return",
		},

		// --- Additional Lua sources ---
		{
			ID:          "lua.socket.receive",
			Category:    taint.SrcNetwork,
			Language:    rules.LangLua,
			Pattern:     `socket\.tcp\(\).*:receive\(|:receive\s*\(`,
			ObjectType:  "socket",
			MethodName:  "receive",
			Description: "LuaSocket TCP receive data",
			Assigns:     "return",
		},
		{
			ID:          "lua.json.decode",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangLua,
			Pattern:     `cjson\.decode\s*\(|json\.decode\s*\(|dkjson\.decode\s*\(`,
			ObjectType:  "cjson",
			MethodName:  "decode",
			Description: "JSON decoded data from potentially untrusted source",
			Assigns:     "return",
		},
		{
			ID:          "lua.redis.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangLua,
			Pattern:     `redis\.call\s*\(\s*['"]GET|redis\.call\s*\(\s*['"]get`,
			ObjectType:  "redis",
			MethodName:  "call(GET)",
			Description: "Redis GET command result",
			Assigns:     "return",
		},
	}
}
