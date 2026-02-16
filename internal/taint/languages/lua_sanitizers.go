package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
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

		// --- cjson safe decode ---
		{
			ID:          "lua.cjson.safe",
			Language:    rules.LangLua,
			Pattern:     `cjson\.safe\.decode\s*\(|pcall\s*\(\s*cjson\.decode`,
			ObjectType:  "cjson",
			MethodName:  "cjson.safe.decode",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Safe JSON decoding with error handling",
		},

		// --- Lapis HTML escaping ---
		{
			ID:          "lua.lapis.escape",
			Language:    rules.LangLua,
			Pattern:     `escape\s*\(|lapis\.html\.escape`,
			ObjectType:  "lapis",
			MethodName:  "lapis.html.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Lapis HTML escaping",
		},

		// --- OpenResty SHA256 ---
		{
			ID:          "lua.ngx.sha256",
			Language:    rules.LangLua,
			Pattern:     `ngx\.sha1_bin\s*\(|resty\.sha256|resty\.sha512`,
			ObjectType:  "ngx/resty",
			MethodName:  "resty.sha256",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenResty secure hashing",
		},

		// --- String format validation ---
		{
			ID:          "lua.string.format",
			Language:    rules.LangLua,
			Pattern:     `string\.format\s*\(\s*"%%d"`,
			ObjectType:  "",
			MethodName:  "string.format(%d)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Format string restricting to numeric value",
		},

		// --- Allowlist check ---
		{
			ID:          "lua.table.contains",
			Language:    rules.LangLua,
			Pattern:     `allowed_\w+\[|whitelist\[|allowlist\[`,
			ObjectType:  "",
			MethodName:  "table lookup validation",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkCommand},
			Description: "Table-based allowlist validation",
		},

		// --- Numeric conversion ---
		{
			ID:          "lua.tonumber.sanitizer",
			Language:    rules.LangLua,
			Pattern:     `tonumber\s*\(`,
			ObjectType:  "",
			MethodName:  "tonumber",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Numeric conversion (restricts to numeric values)",
		},

		// --- Pattern escaping ---
		{
			ID:          "lua.string.pattern.escape",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\(.*%%`,
			ObjectType:  "",
			MethodName:  "string.gsub (escape)",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Lua pattern metacharacter escaping via gsub",
		},
	}
}
