package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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

		// --- pgmoon SQL escaping ---
		{
			ID:          "lua.pgmoon.escape_literal",
			Language:    rules.LangLua,
			Pattern:     `pg:escape_literal\s*\(|:escape_literal\s*\(`,
			ObjectType:  "pgmoon",
			MethodName:  "pg:escape_literal",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "pgmoon SQL literal escaping (quotes and escapes values)",
		},
		{
			ID:          "lua.pgmoon.escape_identifier",
			Language:    rules.LangLua,
			Pattern:     `pg:escape_identifier\s*\(|:escape_identifier\s*\(`,
			ObjectType:  "pgmoon",
			MethodName:  "pg:escape_identifier",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "pgmoon SQL identifier escaping (double-quotes identifiers)",
		},
		{
			ID:          "lua.pgmoon.parameterized",
			Language:    rules.LangLua,
			Pattern:     `pg:query\s*\([^,]+,\s*\w`,
			ObjectType:  "pgmoon",
			MethodName:  "pg:query (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "pgmoon parameterized query with $N placeholders (safe)",
		},

		// --- Shell metachar escaping ---
		{
			ID:          "lua.string.gsub.shell_escape",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\([^,]+,\s*['"][\[\\]?[^'"]*shell|string\.gsub\s*\([^,]+,\s*['"][^a-zA-Z0-9]`,
			ObjectType:  "",
			MethodName:  "string.gsub (shell escape)",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Shell metacharacter escaping via string.gsub",
		},

		// --- URL host validation for SSRF ---
		{
			ID:          "lua.url.parse.host_check",
			Language:    rules.LangLua,
			Pattern:     `url\.parse\s*\(.*\.host|socket\.dns\.toip\s*\(`,
			ObjectType:  "",
			MethodName:  "url.parse (host check)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "URL parsing with host extraction for SSRF validation",
		},

		// --- tostring type coercion ---
		{
			ID:          "lua.tostring.sanitizer",
			Language:    rules.LangLua,
			Pattern:     `tostring\s*\(`,
			ObjectType:  "",
			MethodName:  "tostring",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "String coercion (may limit injection in numeric contexts)",
		},

		// --- Tarantool parameterized SQL ---
		{
			ID:          "lua.tarantool.box.execute.params",
			Language:    rules.LangLua,
			Pattern:     `box\.execute\s*\(\s*['"][^'"]*\?\s*[^'"]*['"]\s*,\s*\{`,
			ObjectType:  "box",
			MethodName:  "box.execute with params",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Tarantool parameterized SQL query (bind variables via ? placeholders)",
		},

		// --- LuaSQL prepared statements ---
		{
			ID:          "lua.luasql.prepare",
			Language:    rules.LangLua,
			Pattern:     `conn:prepare\s*\(|:prepare\s*\(`,
			ObjectType:  "luasql",
			MethodName:  "conn:prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "LuaSQL prepared statement (parameterized query)",
		},

		// --- LuaExpat threat parser (XXE prevention) ---
		{
			ID:          "lua.lxp.threat",
			Language:    rules.LangLua,
			Pattern:     `threat\s*=\s*\{|lxp%.new\s*\(.*threat`,
			ObjectType:  "lxp",
			MethodName:  "lxp.new with threat protection",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkXPath},
			Description: "LuaExpat threat parser with entity/DTD restrictions (XXE prevention)",
		},

		// --- String length truncation ---
		{
			ID:          "lua.string.sub.limit",
			Language:    rules.LangLua,
			Pattern:     `string\.sub\s*\(\s*\w+\s*,\s*1\s*,`,
			ObjectType:  "",
			MethodName:  "string.sub (length limit)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "String truncation via string.sub to limit input length",
		},

		// --- Cryptographically secure random ---
		{
			ID:          "lua.resty.random.bytes",
			Language:    rules.LangLua,
			Pattern:     `resty\.random\.bytes\s*\(`,
			ObjectType:  "resty.random",
			MethodName:  "resty.random.bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "CSPRNG via lua-resty-random (OpenSSL RAND_bytes)",
		},
		{
			ID:          "lua.openssl.rand.bytes",
			Language:    rules.LangLua,
			Pattern:     `rand\.bytes\s*\(|openssl\.rand\.bytes\s*\(`,
			ObjectType:  "openssl.rand",
			MethodName:  "rand.bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "CSPRNG via lua-openssl RAND_bytes",
		},

		// --- Strong hash algorithms ---
		{
			ID:          "lua.resty.sha256.new",
			Language:    rules.LangLua,
			Pattern:     `(?:resty\.)?sha256:new\s*\(`,
			ObjectType:  "resty.sha256",
			MethodName:  "sha256:new",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-256 hash via lua-resty-string (strong replacement for MD5/SHA-1)",
		},
		{
			ID:          "lua.resty.sha512.new",
			Language:    rules.LangLua,
			Pattern:     `(?:resty\.)?sha512:new\s*\(`,
			ObjectType:  "resty.sha512",
			MethodName:  "sha512:new",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-512 hash via lua-resty-string (strong replacement for MD5/SHA-1)",
		},
		{
			ID:          "lua.resty.hmac.new",
			Language:    rules.LangLua,
			Pattern:     `(?:resty\.)?hmac:new\s*\(`,
			ObjectType:  "resty.hmac",
			MethodName:  "hmac:new",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HMAC via lua-resty-hmac (keyed hash for integrity/authentication)",
		},

		// --- XPath input sanitization ---
		{
			ID:          "lua.xpath.escape",
			Language:    rules.LangLua,
			Pattern:     `xpath_escape\s*\(|escape_xpath\s*\(|string\.gsub\s*\([^,]+,\s*['"]['\[\]@=]`,
			ObjectType:  "",
			MethodName:  "xpath_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XPath special character escaping (quotes, brackets, operators)",
		},

		// --- MongoDB input sanitization ---
		{
			ID:          "lua.mongol.sanitize",
			Language:    rules.LangLua,
			Pattern:     `mongo_sanitize\s*\(|sanitize_query\s*\(|string\.gsub\s*\([^,]+,\s*['"]%$`,
			ObjectType:  "mongol",
			MethodName:  "mongo_sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MongoDB query sanitization (strips $ operators to prevent NoSQL injection)",
		},

		// --- LDAP escaping ---
		{
			ID:          "lua.ldap.escape_filter",
			Language:    rules.LangLua,
			Pattern:     `ldap_escape_filter\s*\(|escape_filter_value\s*\(|ldap\.filter\.escape\s*\(`,
			ObjectType:  "ldap",
			MethodName:  "escape_filter",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP filter value escaping (RFC 4515 special characters)",
		},
		{
			ID:          "lua.ldap.escape_dn",
			Language:    rules.LangLua,
			Pattern:     `ldap_escape_dn\s*\(|escape_dn_value\s*\(|ldap\.dn\.escape\s*\(`,
			ObjectType:  "ldap",
			MethodName:  "escape_dn",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP distinguished name escaping (RFC 4514 special characters)",
		},
	}
}
