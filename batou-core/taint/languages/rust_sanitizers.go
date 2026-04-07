package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

func (c *RustCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- SQL parameterization ---
		{
			ID:          "rust.sqlx.query_macro",
			Language:    rules.LangRust,
			Pattern:     `sqlx::query!\s*\(`,
			ObjectType:  "sqlx",
			MethodName:  "sqlx::query!",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLx compile-time checked query macro (prevents SQL injection)",
		},
		{
			ID:          "rust.sqlx.query_as_macro",
			Language:    rules.LangRust,
			Pattern:     `sqlx::query_as!\s*\(`,
			ObjectType:  "sqlx",
			MethodName:  "sqlx::query_as!",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLx compile-time checked typed query macro",
		},
		{
			ID:          "rust.sqlx.bind",
			Language:    rules.LangRust,
			Pattern:     `\.bind\s*\(`,
			ObjectType:  "sqlx",
			MethodName:  ".bind()",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLx parameter binding (prevents SQL injection)",
		},
		{
			ID:          "rust.diesel.parameterized",
			Language:    rules.LangRust,
			Pattern:     `\.filter\s*\(`,
			ObjectType:  "diesel",
			MethodName:  ".filter()",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Diesel parameterized query filter (prevents SQL injection)",
		},
		{
			ID:          "rust.rusqlite.params",
			Language:    rules.LangRust,
			Pattern:     `params!\s*\[`,
			ObjectType:  "rusqlite",
			MethodName:  "params![]",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Rusqlite parameterized query (prevents SQL injection)",
		},

		// --- HTML sanitization ---
		{
			ID:          "rust.ammonia.clean",
			Language:    rules.LangRust,
			Pattern:     `ammonia::clean\s*\(`,
			ObjectType:  "ammonia",
			MethodName:  "ammonia::clean",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Ammonia HTML sanitizer (prevents XSS)",
		},
		{
			ID:          "rust.html_escape",
			Language:    rules.LangRust,
			Pattern:     `html_escape::encode_\w+\s*\(`,
			ObjectType:  "html_escape",
			MethodName:  "html_escape::encode_text/html_escape::encode_safe/html_escape::encode_double_quoted_attribute/html_escape::encode_single_quoted_attribute/html_escape::encode_unquoted_attribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "HTML escape encoding (prevents XSS)",
		},

		// --- Input validation ---
		{
			ID:          "rust.validator.validate",
			Language:    rules.LangRust,
			Pattern:     `\.validate\s*\(`,
			ObjectType:  "validator",
			MethodName:  ".validate()",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "Validator crate struct validation",
		},

		// --- URL validation ---
		{
			ID:          "rust.url.parse",
			Language:    rules.LangRust,
			Pattern:     `Url::parse\s*\(`,
			ObjectType:  "url::Url",
			MethodName:  "Url::parse",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL parsing and validation",
		},

		// --- Path validation ---
		{
			ID:          "rust.path.canonicalize",
			Language:    rules.LangRust,
			Pattern:     `\.canonicalize\s*\(`,
			ObjectType:  "",
			MethodName:  "canonicalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path canonicalization (resolves symlinks and .., prevents traversal)",
		},
		{
			ID:          "rust.path.file_name",
			Language:    rules.LangRust,
			Pattern:     `\.file_name\s*\(`,
			ObjectType:  "",
			MethodName:  "file_name",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract file name component (strips directory traversal)",
		},
		{
			ID:          "rust.path.starts_with",
			Language:    rules.LangRust,
			Pattern:     `\.starts_with\s*\(`,
			ObjectType:  "",
			MethodName:  "starts_with",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path prefix check (containment verification)",
		},

		// --- Numeric conversion ---
		{
			ID:          "rust.str.parse_int",
			Language:    rules.LangRust,
			Pattern:     `\.parse\s*::\s*<\s*(?:i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)\s*>`,
			ObjectType:  "str",
			MethodName:  "str::parse::<integer>",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch},
			Description: "String to integer parsing (restricts to numeric values)",
		},
		{
			ID:          "rust.str.parse_generic",
			Language:    rules.LangRust,
			Pattern:     `\.parse\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkEval},
			Description: "Generic parse (type-inferred numeric parsing neutralizes injection sinks)",
		},

		// --- Crypto sanitizers ---
		{
			ID:          "rust.argon2.hash",
			Language:    rules.LangRust,
			Pattern:     `Argon2::default\s*\(\s*\)\s*\.\s*hash_password\s*\(`,
			ObjectType:  "argon2",
			MethodName:  "Argon2::hash_password",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2 password hashing",
		},
		{
			ID:          "rust.bcrypt.hash",
			Language:    rules.LangRust,
			Pattern:     `bcrypt::hash\s*\(`,
			ObjectType:  "bcrypt",
			MethodName:  "bcrypt::hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Bcrypt password hashing",
		},

		// --- Tera auto-escaping ---
		{
			ID:          "rust.tera.autoescape",
			Language:    rules.LangRust,
			Pattern:     `Tera::new\s*\(|tera\.autoescape_on`,
			ObjectType:  "tera",
			MethodName:  "Tera::new (auto-escaping)",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Tera template engine with auto-escaping enabled by default",
		},

		// --- Regex validation ---
		{
			ID:          "rust.regex.is_match",
			Language:    rules.LangRust,
			Pattern:     `Regex::new\s*\(.*\)\s*.*\.is_match\s*\(`,
			ObjectType:  "regex",
			MethodName:  "Regex::is_match",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Regex-based input validation",
		},

		// --- tokio-postgres parameterized ---
		{
			ID:          "rust.tokio.postgres.params",
			Language:    rules.LangRust,
			Pattern:     `client\.query\s*\([^,]+,\s*&\[`,
			ObjectType:  "tokio_postgres",
			MethodName:  "query with params",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "tokio-postgres parameterized query",
		},

		// --- sea-orm DSL ---
		{
			ID:          "rust.seaorm.dsl",
			Language:    rules.LangRust,
			Pattern:     `Entity::find\(\)\.filter\s*\(|\.col\s*\(.*\.eq\s*\(`,
			ObjectType:  "sea_orm",
			MethodName:  "Entity::find().filter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SeaORM query builder DSL (parameterized)",
		},

		// --- String escaping ---
		{
			ID:          "rust.encode_uri_component",
			Language:    rules.LangRust,
			Pattern:     `urlencoding::encode\s*\(|percent_encoding::utf8_percent_encode\s*\(`,
			ObjectType:  "urlencoding",
			MethodName:  "urlencoding::encode",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHTMLOutput},
			Description: "URL encoding for safe URL construction",
		},

		// --- Path canonicalization ---
		{
			ID:          "rust.fs.canonicalize",
			Language:    rules.LangRust,
			Pattern:     `\.canonicalize\s*\(|fs::canonicalize\s*\(`,
			ObjectType:  "std::fs",
			MethodName:  "canonicalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path canonicalization with symlink resolution",
		},

		// --- Regex escaping ---
		{
			ID:          "rust.regex.escape",
			Language:    rules.LangRust,
			Pattern:     `regex::escape\s*\(`,
			ObjectType:  "regex",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Regex metacharacter escaping (prevents ReDoS)",
		},

		// --- Numeric conversion ---
		{
			ID:          "rust.parse.numeric",
			Language:    rules.LangRust,
			Pattern:     `\.parse::<f64>\s*\(|\.parse::<f32>\s*\(|\.parse::<i64>\s*\(|\.parse::<u64>\s*\(`,
			ObjectType:  "",
			MethodName:  "parse::<numeric>",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Numeric type parsing (restricts to numeric values)",
		},

		// --- Command injection sanitizers ---
		{
			ID:          "rust.shell_escape.escape",
			Language:    rules.LangRust,
			Pattern:     `shell_escape::escape\s*\(`,
			ObjectType:  "shell_escape",
			MethodName:  "shell_escape::escape",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Shell argument quoting via shell-escape crate (safe for shell invocation)",
		},
		{
			ID:          "rust.shlex.try_quote",
			Language:    rules.LangRust,
			Pattern:     `shlex::try_quote\s*\(|shlex::try_join\s*\(`,
			ObjectType:  "shlex",
			MethodName:  "shlex::try_quote/try_join",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Shell quoting via shlex >=1.3.0 (rejects NUL bytes, prevents command injection)",
		},
		{
			ID:          "rust.shell_words.join",
			Language:    rules.LangRust,
			Pattern:     `shell_words::join\s*\(`,
			ObjectType:  "shell_words",
			MethodName:  "shell_words::join",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "POSIX shell word joining via shell_words crate (safe argument escaping)",
		},

		// --- Log injection sanitizers ---
		{
			ID:          "rust.log.sanitize_newlines",
			Language:    rules.LangRust,
			Pattern:     `\.replace\s*\(\s*['"]\\.n['"]|\.replace\s*\(\s*['"]\\.r['"]|\.replace\s*\(\s*&?\[.*\\n.*\\r`,
			ObjectType:  "",
			MethodName:  "str::replace (newline stripping)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Newline/CR stripping before logging (prevents log injection/forging)",
		},
		{
			ID:          "rust.log.filter_control",
			Language:    rules.LangRust,
			Pattern:     `is_control\s*\(`,
			ObjectType:  "",
			MethodName:  "char::is_control filter",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Control character filtering before logging (prevents log injection)",
		},
		{
			ID:          "rust.tracing.structured_field",
			Language:    rules.LangRust,
			Pattern:     `(?:info|warn|error|debug|trace)!\s*\(\s*\w+\s*=\s*[%?]`,
			ObjectType:  "tracing",
			MethodName:  "tracing structured field (= %var / = ?var)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Tracing structured field syntax serializes value separately (prevents log forging)",
		},

		// --- Open redirect sanitizers ---
		{
			ID:          "rust.url.host_check",
			Language:    rules.LangRust,
			Pattern:     `\.host_str\s*\(\s*\)|\.host\s*\(\s*\)`,
			ObjectType:  "url::Url",
			MethodName:  "Url::host_str/host",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "URL host extraction for allowlist validation (prevents open redirect)",
		},
		{
			ID:          "rust.url.origin",
			Language:    rules.LangRust,
			Pattern:     `\.origin\s*\(\s*\)`,
			ObjectType:  "url::Url",
			MethodName:  "Url::origin",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "URL origin extraction for same-origin validation",
		},

		// --- Deserialization sanitizers ---
		{
			ID:          "rust.serde.typed_deser",
			Language:    rules.LangRust,
			Pattern:     `serde_json::from_str\s*::\s*<|serde_json::from_slice\s*::\s*<|serde_json::from_reader\s*::\s*<`,
			ObjectType:  "serde_json",
			MethodName:  "serde_json::from_*::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Typed JSON deserialization to concrete struct (rejects unexpected structure)",
		},
		{
			ID:          "rust.serde_valid.validate",
			Language:    rules.LangRust,
			Pattern:     `\.validate\s*\(\s*\)`,
			ObjectType:  "serde_valid",
			MethodName:  "serde_valid::Validate",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Field-level validation post-deserialization (size/range constraints)",
		},
		{
			ID:          "rust.bincode.with_limit",
			Language:    rules.LangRust,
			Pattern:     `\.with_limit\s*\(`,
			ObjectType:  "bincode",
			MethodName:  "bincode::Options::with_limit",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Bincode deserialization with byte limit (prevents DoS from huge payloads)",
		},
		{
			ID:          "rust.serde.typed_toml",
			Language:    rules.LangRust,
			Pattern:     `toml::from_str\s*::\s*<`,
			ObjectType:  "toml",
			MethodName:  "toml::from_str::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Typed TOML deserialization to concrete struct",
		},

		// --- Header injection sanitizers ---
		{
			ID:          "rust.http.header_value_from_str",
			Language:    rules.LangRust,
			Pattern:     `HeaderValue::from_str\s*\(`,
			ObjectType:  "http::header::HeaderValue",
			MethodName:  "HeaderValue::from_str",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "http::HeaderValue::from_str rejects non-visible-ASCII including CRLF (prevents header injection)",
		},
		{
			ID:          "rust.http.header_value_from_bytes",
			Language:    rules.LangRust,
			Pattern:     `HeaderValue::from_bytes\s*\(`,
			ObjectType:  "http::header::HeaderValue",
			MethodName:  "HeaderValue::from_bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "http::HeaderValue::from_bytes rejects control bytes including CRLF",
		},
		{
			ID:          "rust.header.strip_crlf",
			Language:    rules.LangRust,
			Pattern:     `\.replace\s*\(\s*['"]\\.r\\.n['"]|\.replace\s*\(\s*['"]\\r\\n['"]`,
			ObjectType:  "",
			MethodName:  "str::replace (CRLF stripping)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "CRLF stripping before setting HTTP headers (prevents header injection)",
		},

		// --- LDAP injection sanitizers ---
		{
			ID:          "rust.ldap3.ldap_escape",
			Language:    rules.LangRust,
			Pattern:     `ldap3::ldap_escape\s*\(|ldap_escape\s*\(`,
			ObjectType:  "",
			MethodName:  "ldap_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "ldap3::ldap_escape escapes special characters in LDAP filter values (prevents filter injection)",
		},
		{
			ID:          "rust.ldap3.dn_escape",
			Language:    rules.LangRust,
			Pattern:     `ldap3::dn_escape\s*\(|dn_escape\s*\(`,
			ObjectType:  "",
			MethodName:  "dn_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "ldap3::dn_escape escapes special characters in DN attribute values per RFC 4514",
		},
	}
}
