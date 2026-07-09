package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkHeader},
			Description: "OpenResty base64 encoding (eliminates CRLF and control characters)",
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
		{
			ID:          "lua.ngx.quote_sql_str",
			Language:    rules.LangLua,
			Pattern:     `ngx\.quote_sql_str\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.quote_sql_str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "OpenResty lua-nginx-module SQL string quoting (MySQL rules)",
		},

		// Sailor db.escape(q) delegates to the active connection's :escape()
		// ("Should be used before concatenating strings on a query") and is the
		// framework-sanctioned way to neutralize a value before it is spliced
		// into a db.query/db.query_one string.
		{
			ID:          "lua.sailor.db.escape",
			Language:    rules.LangLua,
			Pattern:     `\bdb\.escape\s*\(`,
			ObjectType:  "db",
			MethodName:  "db.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Sailor db.escape() quotes a value via the DB connection before SQL concatenation",
		},

		// --- Numeric conversion ---
		{
			ID:          "lua.tonumber",
			Language:    rules.LangLua,
			Pattern:     `tonumber\s*\(`,
			ObjectType:  "",
			MethodName:  "tonumber",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkTrustBoundary},
			Description: "Numeric conversion restricts to numeric values",
		},

		// --- Path sanitization ---
		{
			ID:          "lua.string.gsub.dotdot",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\(.*%.%.`,
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
			Pattern:     `\bescape\s*\(|lapis\.html\.escape`,
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
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
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

		// --- Penlight shell argument quoting ---
		{
			ID:          "lua.pl.utils.quote_arg",
			Language:    rules.LangLua,
			Pattern:     `pl\.utils\.quote_arg\s*\(|utils\.quote_arg\s*\(`,
			ObjectType:  "pl.utils",
			MethodName:  "pl.utils.quote_arg",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Penlight quote_arg escapes shell arguments with single-quote wrapping (equivalent to shlex.quote)",
		},

		// --- Custom shell escape functions ---
		{
			ID:          "lua.shell.escape",
			Language:    rules.LangLua,
			Pattern:     `shell_escape\s*\(|shell_quote\s*\(|shellescape\s*\(`,
			ObjectType:  "",
			MethodName:  "shell_escape/shell_quote",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Custom shell escape/quote function (common pattern in Lua projects)",
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
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
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

		// --- JSON encoding (prevents XSS, template injection, log injection) ---
		{
			ID:          "lua.cjson.encode",
			Language:    rules.LangLua,
			Pattern:     `cjson\.encode\s*\(`,
			ObjectType:  "cjson",
			MethodName:  "cjson.encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate, taint.SnkLog},
			Description: "cjson JSON encoding (escapes <>&, template delimiters, and \\n/\\r control chars)",
		},

		// --- CRLF stripping (prevents header/log injection) ---
		{
			ID:          "lua.string.gsub.crlf",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\([^,]+,\s*['"]\\n|string\.gsub\s*\([^,]+,\s*['"]\\r`,
			ObjectType:  "",
			MethodName:  "string.gsub (CRLF strip)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Newline/carriage-return stripping via string.gsub (prevents log and header injection)",
		},

		// --- OpenResty regex replacement (general sanitizer) ---
		{
			ID:          "lua.ngx.re.gsub",
			Language:    rules.LangLua,
			Pattern:     `ngx\.re\.gsub\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.re.gsub",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog, taint.SnkHTMLOutput},
			Description: "OpenResty PCRE regex replacement (sanitizes tainted data via pattern substitution)",
		},

		// --- Trust boundary validation ---
		{
			ID:          "lua.ngx.re.match.validate",
			Language:    rules.LangLua,
			Pattern:     `ngx\.re\.match\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.re.match",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "OpenResty PCRE regex match used for input validation before trust boundary storage",
		},

		// --- Eval sandboxing (CWE-94 prevention) ---
		{
			ID:          "lua.load.sandbox_env",
			Language:    rules.LangLua,
			Pattern:     `load\s*\([^,]+,\s*[^,]+,\s*['"]t['"],\s*\{`,
			ObjectType:  "",
			MethodName:  "load",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Lua 5.2+ load() with text-only mode and restricted environment table (sandboxed eval)",
		},
		{
			ID:          "lua.pcall.eval",
			Language:    rules.LangLua,
			Pattern:     `pcall\s*\(\s*(?:loadstring|load)\s*\(`,
			ObjectType:  "",
			MethodName:  "pcall",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Protected call wrapping loadstring/load catches errors from malformed code input",
		},
		{
			ID:          "lua.redis.evalsha",
			Language:    rules.LangLua,
			Pattern:     `redis\.call\s*\(\s*['"]EVALSHA`,
			ObjectType:  "redis",
			MethodName:  "redis.call",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Redis EVALSHA executes pre-registered script by hash (not user-provided code)",
		},

		// --- Deserialization safety ---
		{
			ID:          "lua.pcall.deser",
			Language:    rules.LangLua,
			Pattern:     `pcall\s*\(\s*(?:cmsgpack\.unpack|serpent\.load|marshal\.decode)`,
			ObjectType:  "",
			MethodName:  "pcall (safe deserialization)",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Protected call wrapping deserialization catches errors from malformed input",
		},
		{
			ID:          "lua.hmac.verify",
			Language:    rules.LangLua,
			Pattern:     `ngx\.hmac_sha1\s*\(|(?:resty\.)?hmac:(?:update|final)\s*\(`,
			ObjectType:  "resty.hmac",
			MethodName:  "ngx.hmac_sha1/hmac.update/hmac.final",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "HMAC integrity verification before deserialization prevents forged payloads",
		},
		{
			ID:          "lua.assert.type",
			Language:    rules.LangLua,
			Pattern:     `assert\s*\(\s*type\s*\(\s*\w+\s*\)\s*==\s*['"]`,
			ObjectType:  "",
			MethodName:  "assert",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Runtime type assertion after deserialization prevents unexpected object types",
		},

		// --- Log sanitization ---
		{
			ID:          "lua.string.gsub.newline.log",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\([^,]+,\s*['"][\r\n]`,
			ObjectType:  "",
			MethodName:  "string.gsub (newline strip)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Newline stripping via string.gsub prevents log injection/forging",
		},

		// --- Path traversal sanitizers (CWE-22 prevention) ---
		{
			ID:          "lua.posix.realpath",
			Language:    rules.LangLua,
			Pattern:     `posix\.realpath\s*\(`,
			ObjectType:  "posix",
			MethodName:  "posix.realpath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "luaposix realpath resolves symlinks and .. components to canonical absolute path",
		},
		{
			ID:          "lua.pl.path.normpath",
			Language:    rules.LangLua,
			Pattern:     `pl\.path\.normpath\s*\(`,
			ObjectType:  "pl.path",
			MethodName:  "pl.path.normpath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Penlight path normalization resolves A//B, A/./B and A/foo/../B patterns",
		},
		{
			ID:          "lua.pl.path.abspath",
			Language:    rules.LangLua,
			Pattern:     `pl\.path\.abspath\s*\(`,
			ObjectType:  "pl.path",
			MethodName:  "pl.path.abspath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Penlight absolute path resolution (calls normpath internally)",
		},
		{
			ID:          "lua.pl.path.basename",
			Language:    rules.LangLua,
			Pattern:     `pl\.path\.basename\s*\(`,
			ObjectType:  "pl.path",
			MethodName:  "pl.path.basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Penlight basename strips directory components preventing traversal",
		},
		{
			ID:          "lua.string.find.dotdot.guard",
			Language:    rules.LangLua,
			Pattern:     `string\.find\s*\([^,]+,\s*['"]%.%.`,
			ObjectType:  "",
			MethodName:  "string.find (.. guard)",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Directory traversal detection via string.find checking for .. patterns",
		},
		{
			ID:          "lua.string.gsub.pathsep",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\([^,]+,\s*['"][/\\]`,
			ObjectType:  "",
			MethodName:  "string.gsub (path separator strip)",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Path separator stripping via string.gsub prevents directory traversal",
		},

		// --- Eval sandbox / safe loading (CWE-94 prevention) ---
		{
			ID:          "lua.setfenv.sandbox",
			Language:    rules.LangLua,
			Pattern:     `setfenv\s*\(`,
			ObjectType:  "",
			MethodName:  "setfenv",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Lua 5.1/LuaJIT setfenv restricts loaded code to a sandboxed environment table",
		},
		{
			ID:          "lua.sandbox.run",
			Language:    rules.LangLua,
			Pattern:     `sandbox\.run\s*\(|sandbox\.protect\s*\(`,
			ObjectType:  "sandbox",
			MethodName:  "sandbox.run/protect",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "sandbox.lua library (kikito/sandbox.lua, Kong sandbox) safe code execution",
		},
		{
			ID:          "lua.load.text_mode_env",
			Language:    rules.LangLua,
			Pattern:     `\bload\s*\([^,]+,[^,]+,\s*["']t["']\s*,`,
			ObjectType:  "",
			MethodName:  "load (text mode + env)",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Lua 5.2+ load() with text-only mode and restricted environment table (4th arg)",
		},

		// --- Safe JSON parsers for deserialization (CWE-502 prevention) ---
		{
			ID:          "lua.dkjson.decode",
			Language:    rules.LangLua,
			Pattern:     `dkjson\.decode\s*\(`,
			ObjectType:  "dkjson",
			MethodName:  "dkjson.decode",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "dkjson pure-Lua JSON decoder (safe by design — no code execution)",
		},
		{
			ID:          "lua.rapidjson.decode",
			Language:    rules.LangLua,
			Pattern:     `rapidjson\.decode\s*\(`,
			ObjectType:  "rapidjson",
			MethodName:  "rapidjson.decode",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "lua-rapidjson JSON decoder (C binding, safe by design — no code execution)",
		},

		// --- LDAP injection prevention (CWE-90) ---
		{
			ID:          "lua.string.gsub.ldap_escape",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\([^,]+,\s*['"][^'"]*[*()\\]`,
			ObjectType:  "",
			MethodName:  "string.gsub (LDAP escape)",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP special character escaping via string.gsub (RFC 4515: *, (, ), \\, NUL)",
		},

		// --- SSRF / URL validation (CWE-918 prevention) ---
		{
			ID:          "lua.string.find.scheme_validate",
			Language:    rules.LangLua,
			Pattern:     `string\.find\s*\([^,]+,\s*['"]%^https?://|string\.match\s*\([^,]+,\s*['"]%^https?://`,
			ObjectType:  "",
			MethodName:  "string.find/match (scheme check)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL scheme validation ensuring only http/https via Lua pattern anchor",
		},
		{
			ID:          "lua.resty.http.set_keepalive",
			Language:    rules.LangLua,
			Pattern:     `httpc:connect\s*\(\s*\{[^}]*scheme\s*=\s*["']https?["']`,
			ObjectType:  "resty.http",
			MethodName:  "httpc:connect (fixed scheme)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "OpenResty resty.http connection with hardcoded https scheme prevents SSRF protocol abuse",
		},

		// --- Trust boundary validation (CWE-501 prevention) ---
		{
			ID:          "lua.type.check.guard",
			Language:    rules.LangLua,
			Pattern:     `type\s*\(\s*\w+\s*\)\s*==\s*['"]`,
			ObjectType:  "",
			MethodName:  "type (guard)",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Runtime type checking validates data type before trust boundary storage (e.g., type(x) == \"string\")",
		},
		{
			ID:          "lua.string.match.fullstring",
			Language:    rules.LangLua,
			Pattern:     `string\.match\s*\([^,]+,\s*['"]\^`,
			ObjectType:  "",
			MethodName:  "string.match (anchored)",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkRedirect},
			Description: "Anchored Lua pattern matching validates entire string against whitelist pattern (e.g., string.match(x, \"^%w+$\"))",
		},

		// --- Template injection prevention (CWE-1336) ---
		{
			ID:          "lua.string.gsub.html_entities",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\([^,]+,\s*['"][<>&]`,
			ObjectType:  "",
			MethodName:  "string.gsub (HTML entities)",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Manual HTML entity escaping via string.gsub (replaces < > & with safe entities)",
		},

		// --- Log/header injection prevention (CWE-117, CWE-113) ---
		{
			ID:          "lua.string.gsub.control_chars",
			Language:    rules.LangLua,
			Pattern:     `string\.gsub\s*\([^,]+,\s*['"]%c`,
			ObjectType:  "",
			MethodName:  "string.gsub (control strip)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Stripping all control characters via Lua's %c class (includes \\n, \\r, \\t) prevents log and header injection",
		},
		{
			ID:          "lua.ngx.re.sub",
			Language:    rules.LangLua,
			Pattern:     `ngx\.re\.sub\s*\(`,
			ObjectType:  "ngx",
			MethodName:  "ngx.re.sub",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog, taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OpenResty PCRE single-replacement sanitization (strips or replaces dangerous characters)",
		},

		// --- JWT verification (CWE-345 / CWE-501) ---
		// lua-resty-jwt: jwt:verify and jwt:verify_jwt_obj validate the signature
		// against the secret/key, so claims can be trusted across trust boundaries.
		// jwt:sign produces a server-signed token whose payload is integrity-protected.
		{
			ID:          "lua.resty.jwt.verify",
			Language:    rules.LangLua,
			Pattern:     `jwt:verify\s*\(`,
			ObjectType:  "resty.jwt",
			MethodName:  "jwt:verify",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkDeserialize},
			Description: "lua-resty-jwt jwt:verify(secret, token) validates the JWT signature before exposing claims (the standard OpenResty/Kong JWT library)",
		},
		{
			ID:          "lua.resty.jwt.verify_jwt_obj",
			Language:    rules.LangLua,
			Pattern:     `jwt:verify_jwt_obj\s*\(`,
			ObjectType:  "resty.jwt",
			MethodName:  "jwt:verify_jwt_obj",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkDeserialize},
			Description: "lua-resty-jwt jwt:verify_jwt_obj(secret, jwt_obj) validates signature on a pre-loaded JWT object",
		},
		{
			ID:          "lua.resty.jwt.sign",
			Language:    rules.LangLua,
			Pattern:     `jwt:sign\s*\(`,
			ObjectType:  "resty.jwt",
			MethodName:  "jwt:sign",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "lua-resty-jwt jwt:sign produces a server-signed token; payload is integrity-protected for downstream verification",
		},

		// --- LuaSocket URL escaping (CWE-79 / CWE-601 / CWE-918) ---
		// LuaSocket's `socket.url.escape(s)` percent-encodes a string per
		// RFC 3986 — every byte outside the unreserved set becomes %HH.
		// Idiomatic call after `local url = require "socket.url"` is
		// `url.escape(value)`. Receiver "url" matches ObjectType "socket.url"
		// via the matcher's lastPart heuristic ("url" == lastPart).
		{
			ID:          "lua.luasocket.url.escape",
			Language:    rules.LangLua,
			Pattern:     `(?:socket\.)?url\.escape\s*\(`,
			ObjectType:  "socket.url",
			MethodName:  "url.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog},
			Description: "LuaSocket socket.url.escape percent-encodes URL components (CWE-79/601/918 prevention)",
		},

		// --- bcrypt password verification (CWE-916 / CWE-208) ---
		// `bcrypt.verify(plain, hash)` (mikejsavage/lua-bcrypt and similar)
		// is the canonical Lua bcrypt comparator: salt-aware, slow, and
		// timing-safe. Sanitizes tainted plaintext flowing into a verify
		// call against a stored hash.
		{
			ID:          "lua.bcrypt.verify",
			Language:    rules.LangLua,
			Pattern:     `bcrypt\.verify\s*\(`,
			ObjectType:  "bcrypt",
			MethodName:  "bcrypt.verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "lua-bcrypt password verification — salt-aware, work-factor-tunable, constant-time comparison",
		},

		// --- lua-resty-string hex encoding (CWE-79 / CWE-89 / CWE-117) ---
		// `to_hex(bin)` from openresty/lua-resty-string converts arbitrary
		// binary into [0-9a-f]+ — that output cannot contain HTML, SQL, or
		// log-injection metacharacters. Idiomatic call after
		// `local str = require "resty.string"` is `str.to_hex(bytes)`.
		// Receiver "str" matches ObjectType "resty.string" via the
		// prefix-abbreviation heuristic (lastPart "string" starts with "str").
		{
			ID:          "lua.resty.string.to_hex",
			Language:    rules.LangLua,
			Pattern:     `(?:resty\.)?string\.to_hex\s*\(`,
			ObjectType:  "resty.string",
			MethodName:  "string.to_hex",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery, taint.SnkHeader, taint.SnkLog, taint.SnkFileWrite},
			Description: "lua-resty-string to_hex(bin) — output is [0-9a-f]+ only, eliminates injection metacharacters",
		},

		// --- htmlentities HTML entity encoding (CWE-79) ---
		// htmlentities-lua exposes `htmlentities.encode(s)` which converts
		// `&<>"'` (and other named entities) to their HTML-entity form.
		// Distinct from existing string.gsub-based html_entities sanitizer:
		// covers the named-library form used in production code.
		{
			ID:          "lua.htmlentities.encode",
			Language:    rules.LangLua,
			Pattern:     `htmlentities\.encode\s*\(`,
			ObjectType:  "htmlentities",
			MethodName:  "htmlentities.encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "htmlentities-lua HTML entity encoding (XSS prevention via named-entity escape)",
		},

		// --- Kong base64url encoding (CWE-79 / CWE-117 / CWE-113) ---
		// Kong gateway exposes `encode_base64url(s)` (kong.tools.utils in
		// Kong 2.x, kong.tools.string in Kong 3.x). Output is [A-Za-z0-9_-]
		// only — no `/`, `+`, `=`, CRLF, or HTML metacharacters. Used widely
		// in Kong plugins for cookie/header values derived from user input.
		// Idiomatic call: `local utils = require "kong.tools.utils";
		// utils.encode_base64url(input)`.
		{
			ID:          "lua.kong.tools.utils.encode_base64url",
			Language:    rules.LangLua,
			Pattern:     `(?:kong\.tools\.utils\.|kong\.tools\.string\.|utils\.)encode_base64url\s*\(`,
			ObjectType:  "kong.tools.utils",
			MethodName:  "utils.encode_base64url",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkHeader, taint.SnkLog},
			Description: "Kong encode_base64url — URL-safe base64 (no +/=, no CRLF, no HTML metacharacters)",
		},

		// --- NoSQL: lua-mongo / luamongo BSON helpers ---
		// `mongo.ObjectID(hex)` validates a 24-char hex string and returns a
		// typed ObjectID userdata; `mongo.BSON(table)` (lua-mongo) and
		// `mongo.bson_encode(table)` (luamongo) marshal a Lua table into a
		// typed BSON document where values are bound as typed entries
		// rather than concatenated into a query string.
		{
			ID:          "lua.mongo.objectid",
			Language:    rules.LangLua,
			Pattern:     `mongo\.ObjectID\s*\(`,
			ObjectType:  "mongo",
			MethodName:  "mongo.ObjectID",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "lua-mongo mongo.ObjectID validates a 24-char hex string and returns a typed ObjectID (rejects malformed input)",
		},
		{
			ID:          "lua.mongo.bson",
			Language:    rules.LangLua,
			Pattern:     `mongo\.BSON\s*\(`,
			ObjectType:  "mongo",
			MethodName:  "mongo.BSON",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "lua-mongo mongo.BSON marshals a Lua table to a typed BSON document (values bound as typed entries, not concatenated)",
		},
		{
			ID:          "lua.mongo.bson_encode",
			Language:    rules.LangLua,
			Pattern:     `mongo\.bson_encode\s*\(`,
			ObjectType:  "mongo",
			MethodName:  "mongo.bson_encode",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "luamongo mongo.bson_encode marshals a Lua table to a typed BSON document (values bound as typed entries, not concatenated)",
		},

		// --- SSRF / URL validation sanitizers ---
		// OpenResty / Kong / nginx-lua workloads dominate Lua HTTP usage.
		// These idioms are the typical SSRF guards in those stacks.
		{
			ID:          "lua.socket.url_parse",
			Language:    rules.LangLua,
			Pattern:     `socket\.url\.parse\s*\(`,
			ObjectType:  "socket.url",
			MethodName:  "socket.url.parse",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "LuaSocket socket.url.parse — typed-URL parser; allowlist checks normally run on the returned host/scheme fields (prevents allowlist bypass via encoded characters)",
		},
		{
			ID:          "lua.resty.url.is_private",
			Language:    rules.LangLua,
			Pattern:     `resty\.url\.is_private\s*\(|is_private_ip\s*\(`,
			ObjectType:  "resty.url",
			MethodName:  "is_private",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "OpenResty resty.url.is_private / is_private_ip helper — denies RFC-1918 / loopback / link-local addresses (SSRF allowlist guard)",
		},
		{
			ID:          "lua.openresty.ngx_re_match_host",
			Language:    rules.LangLua,
			Pattern:     `ngx\.re\.match\s*\([^,]+,\s*['"][^'"]*\\\\.(?:com|net|org|io|local)`,
			ObjectType:  "ngx.re",
			MethodName:  "ngx.re.match (host allowlist)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "OpenResty ngx.re.match used as a domain-suffix allowlist regex (idiomatic SSRF guard before proxy_pass / capture)",
		},
		{
			ID:          "lua.openresty.balancer_set_peer",
			Language:    rules.LangLua,
			Pattern:     `balancer\.set_current_peer\s*\(`,
			ObjectType:  "ngx.balancer",
			MethodName:  "balancer.set_current_peer",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "OpenResty ngx.balancer.set_current_peer — peer is selected from an allowlist of upstream addresses (the request never reaches an attacker-supplied URL)",
		},
		{
			ID:          "lua.url_validate.lpeg",
			Language:    rules.LangLua,
			Pattern:     `lpeg\.match\s*\(|re\.compile\s*\(\s*['"]\s*\\\\[ah]`,
			ObjectType:  "lpeg",
			MethodName:  "lpeg.match (URL grammar)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "lpeg URL-grammar match — accepts only inputs that conform to a typed URL grammar (prevents allowlist bypass via embedded credentials / IDN homographs)",
		},

		// --- Crypto sanitizers — strong password-hash / KDF for Lua/OpenResty ---
		{
			ID:          "lua.bcrypt.digest",
			Language:    rules.LangLua,
			Pattern:     `\bbcrypt\.digest\s*\(|\bbcrypt\.salt\s*\(`,
			ObjectType:  "bcrypt",
			MethodName:  "bcrypt.digest/salt",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "lua-bcrypt module bcrypt.digest / bcrypt.salt — bcrypt password hash (defends CWE-916)",
		},
		{
			ID:          "lua.resty.bcrypt",
			Language:    rules.LangLua,
			Pattern:     `resty\.bcrypt\.digest\s*\(|resty\.bcrypt\.hash\s*\(`,
			ObjectType:  "resty.bcrypt",
			MethodName:  "resty.bcrypt.digest/hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenResty lua-resty-bcrypt digest / hash — bcrypt password hash for OpenResty (CWE-916)",
		},
		{
			ID:          "lua.argon2.hash",
			Language:    rules.LangLua,
			Pattern:     `argon2\.hash_encoded\s*\(|argon2\.encrypt\s*\(`,
			ObjectType:  "argon2",
			MethodName:  "argon2.hash_encoded/encrypt",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "lua-argon2 / lua-argon2-ffi hash_encoded / encrypt — Argon2 password hash (CWE-916)",
		},
		{
			ID:          "lua.openresty.random_bytes",
			Language:    rules.LangLua,
			Pattern:     `resty\.random\.bytes\s*\(|resty\.string\.to_hex\s*\(.*resty\.random`,
			ObjectType:  "resty.random",
			MethodName:  "resty.random.bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenResty lua-resty-random bytes() — CSPRNG-backed random bytes (defends CWE-338 weak-PRNG)",
		},
		{
			ID:          "lua.openssl_rand_bytes",
			Language:    rules.LangLua,
			Pattern:     `\bopenssl\.random\s*\(|openssl\.rand\.pseudo_bytes\s*\(`,
			ObjectType:  "openssl",
			MethodName:  "openssl.random/rand.pseudo_bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "lua-openssl random / pseudo_bytes — OS-backed CSPRNG (CWE-338 defence)",
		},

		// --- ReDoS prevention — regex metacharacter escaping (CWE-1333) ---
		// The SnkRegexDoS sink (lua.ngx.re.match.redos) fires when a tainted
		// pattern reaches ngx.re.match/gmatch. Escaping every PCRE/Lua-pattern
		// metacharacter in the user string so it matches literally removes the
		// attacker's ability to inject the nested quantifiers that cause
		// catastrophic backtracking. Common helper names across OpenResty/Lua
		// projects (the analogue of RE2::QuoteMeta / Python re.escape).
		{
			ID:          "lua.regex.escape_meta",
			Language:    rules.LangLua,
			Pattern:     `regex_escape\s*\(|escape_regex\s*\(|escape_pattern\s*\(|quote_meta\s*\(`,
			ObjectType:  "",
			MethodName:  "regex_escape/escape_regex/escape_pattern/quote_meta",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Regex metacharacter escaping helper — escapes user input so it matches literally inside a pattern, removing the injected quantifiers that cause catastrophic backtracking (ReDoS, CWE-1333)",
		},

		// --- CSV / formula injection prevention (CWE-1236) ---
		// The SnkCSV sink (lua.csv.write) fires when a tainted cell beginning with
		// =, +, -, @ is written and later interpreted as a spreadsheet formula.
		// The two idiomatic mitigations: (1) a named escape helper that prefixes
		// at-risk cells with a single quote, and (2) the inline `"'" .. value`
		// prefix concatenation. Both are scoped strictly to SnkCSV so they never
		// neutralize unrelated sinks.
		{
			ID:          "lua.csv.formula_escape",
			Language:    rules.LangLua,
			Pattern:     `csv_escape\s*\(|escape_csv\s*\(|escape_formula\s*\(|sanitize_csv\s*\(|csv_sanitize\s*\(`,
			ObjectType:  "",
			MethodName:  "csv_escape/escape_csv/escape_formula/sanitize_csv/csv_sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "CSV/formula-injection escape helper — neutralizes leading =, +, -, @ cells (typically by prefixing a single quote) before they are written to a spreadsheet-bound CSV (CWE-1236)",
		},
		{
			ID:          "lua.csv.leading_quote",
			Language:    rules.LangLua,
			Pattern:     `['"]'['"]\s*\.\.\s*\w`,
			ObjectType:  "",
			MethodName:  "leading single-quote prefix",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Inline CSV-formula-injection mitigation prefixing a literal single quote to a cell value (\"'\" .. value) so a spreadsheet treats the cell as text, not a formula (CWE-1236)",
		},

		// --- Unrestricted file upload prevention (CWE-434) ---
		// The SnkUpload sinks (lua.openresty.get_body_file, lua.openresty.upload_parse,
		// lua.lapis.params_file, lua.kong.request_get_body) expose client-supplied
		// filenames, content types, and body content. Validating the extension /
		// MIME type against an allowlist, or routing the value through a named
		// upload validator, neutralizes the unrestricted-upload risk.
		{
			ID:          "lua.upload.validate",
			Language:    rules.LangLua,
			Pattern:     `validate_extension\s*\(|check_extension\s*\(|validate_filename\s*\(|validate_upload\s*\(|validate_mime\s*\(|validate_content_type\s*\(`,
			ObjectType:  "",
			MethodName:  "validate_extension/validate_filename/validate_mime/validate_content_type",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Named upload validator — checks the client-supplied filename / extension / content type against an allowlist before the upload is stored (CWE-434 prevention)",
		},
		{
			ID:          "lua.upload.allowlist",
			Language:    rules.LangLua,
			Pattern:     `allowed_ext\w*\s*\[|allowed_type\w*\s*\[|allowed_mime\w*\s*\[`,
			ObjectType:  "",
			MethodName:  "allowed_extensions/allowed_types/allowed_mimes table lookup",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Table-based extension/MIME allowlist lookup (allowed_extensions[ext], allowed_mimes[ct]) gating an upload — only permitted file types proceed (CWE-434 prevention)",
		},
		// --- web_sanitize (leafo) — whitelist HTML/CSS sanitizer ---
		// web_sanitize is a production-grade Lua library (LuaRocks: web_sanitize)
		// for sanitizing untrusted HTML. Unlike the entity-escapers above
		// (htmlentities.encode, lapis.html.escape) it parses the HTML and
		// strips dangerous elements/attributes via a whitelist, returning safe
		// markup. Each function returns a sanitized value (return-value model),
		// so a tainted -> web_sanitize.fn -> HTML-output flow is neutralised.
		{
			ID:          "lua.web_sanitize.sanitize_html",
			Language:    rules.LangLua,
			Pattern:     `web_sanitize\.sanitize_html\s*\(`,
			ObjectType:  "web_sanitize",
			MethodName:  "web_sanitize.sanitize_html",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "web_sanitize.sanitize_html(html) — whitelist HTML sanitizer that strips dangerous tags/attributes (e.g. <script>, onload=) and returns safe markup, preventing stored/reflected XSS (CWE-79)",
		},
		{
			ID:          "lua.web_sanitize.extract_text",
			Language:    rules.LangLua,
			Pattern:     `web_sanitize\.extract_text\s*\(`,
			ObjectType:  "web_sanitize",
			MethodName:  "web_sanitize.extract_text",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "web_sanitize.extract_text(html) — strips all markup and returns plain text, removing any executable HTML before output (CWE-79 prevention)",
		},
		{
			ID:          "lua.web_sanitize.sanitize_style",
			Language:    rules.LangLua,
			Pattern:     `web_sanitize\.sanitize_(?:style|css)\s*\(`,
			ObjectType:  "web_sanitize",
			MethodName:  "web_sanitize.sanitize_style/web_sanitize.sanitize_css",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "web_sanitize.sanitize_style(css)/sanitize_css(css) — whitelist CSS sanitizer that removes dangerous declarations (e.g. behavior:url(...), expression()) before they reach a style attribute, preventing CSS-based XSS (CWE-79)",
		},
	}
}
