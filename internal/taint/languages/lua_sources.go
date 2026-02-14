package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
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
	}
}
