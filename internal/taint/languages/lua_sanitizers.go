package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

func (c *LuaCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- URL / HTML escaping ---
		{
			ID:          "lua.ngx.escape_uri",
			Language:    rules.LangLua,
			Pattern:     `ngx\.escape_uri\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.escape_uri",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "OpenResty URI escaping",
		},
		{
			ID:          "lua.ngx.encode_args",
			Language:    rules.LangLua,
			Pattern:     `ngx\.encode_args\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.encode_args",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "OpenResty argument encoding",
		},
		{
			ID:          "lua.ngx.encode_base64",
			Language:    rules.LangLua,
			Pattern:     `ngx\.encode_base64\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.encode_base64",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "OpenResty base64 encoding",
		},

		// --- Parameterized queries ---
		{
			ID:          "lua.ndk.set_var.set_quote_sql_str",
			Language:    rules.LangLua,
			Pattern:     `ndk\.set_var\.set_quote_sql_str\s*\(|ngx\.quote_sql_str\s*\(`,
			ObjectType:  "ndk",
			MethodName:  "set_quote_sql_str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQL string quoting via ngx_devel_kit",
		},
		{
			ID:          "lua.resty.mysql.quote",
			Language:    rules.LangLua,
			Pattern:     `:quote_sql_str\s*\(`,
			ObjectType:  "resty.mysql",
			MethodName:  "quote_sql_str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MySQL string quoting via lua-resty-mysql",
		},

		// --- Numeric conversion ---
		{
			ID:          "lua.tonumber",
			Language:    rules.LangLua,
			Pattern:     `tonumber\s*\(`,
			ObjectType:  "",
			MethodName:  "tonumber",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Numeric conversion restricts to numeric values",
		},

		// --- String validation patterns ---
		{
			ID:          "lua.string.match.validate",
			Language:    rules.LangLua,
			Pattern:     `string\.match\s*\(.*%^[%%a%%d%%w]`,
			ObjectType:  "",
			MethodName:  "string.match (validation)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "String pattern matching used for input validation",
		},
		{
			ID:          "lua.string.find.validate",
			Language:    rules.LangLua,
			Pattern:     `string\.find\s*\(.*%^[%%a%%d%%w]`,
			ObjectType:  "",
			MethodName:  "string.find (validation)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "String pattern search used for input validation",
		},

		// --- Path sanitization ---
		{
			ID:          "lua.string.gsub.dotdot",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\(.*%.%.%`,
			ObjectType:  "",
			MethodName:  "string.gsub (path sanitization)",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "String substitution removing directory traversal patterns",
		},

		// --- HTML escaping libraries ---
		{
			ID:          "lua.resty.template.escape",
			Language:    rules.LangLua,
			Pattern:     `template\.escape\s*\(|html_escape\s*\(`,
			ObjectType:  "resty.template",
			MethodName:  "template.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "HTML escaping via lua-resty-template or custom function",
		},
	}
}
