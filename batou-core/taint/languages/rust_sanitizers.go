package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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
			ID:          "rust.ammonia.clean_text",
			Language:    rules.LangRust,
			Pattern:     `ammonia::clean_text\s*\(`,
			ObjectType:  "ammonia",
			MethodName:  "ammonia::clean_text",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "ammonia::clean_text HTML-escapes a plain-text string (&, <, >, \", ', /) so it is safe to insert into HTML text or attribute context (prevents XSS, CWE-79)",
		},
		{
			// Companion to the existing rust.html_escape entry, which only lists
			// the body/attribute encoders (encode_text / encode_safe /
			// encode_*_quoted_attribute). The html-escape crate also ships
			// context-specific encoders for <script> (JS text) and <style> (CSS
			// text); these were not in the tsflow MethodName list, so a tainted
			// value passed through them was still reported as XSS.
			ID:          "rust.html_escape.encode_script_style",
			Language:    rules.LangRust,
			Pattern:     `html_escape::encode_(?:script|style)\s*\(`,
			ObjectType:  "html_escape",
			MethodName:  "html_escape::encode_script/html_escape::encode_style",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "html_escape::encode_script / encode_style escape a string for safe embedding inside <script> (JS text) or <style> (CSS text) context (prevents XSS, CWE-79)",
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
		// --- Salvo framework: safe (non-HTML) response writers ---
		// Wrapping user data in Salvo's Text::Plain or Text::Json sets a
		// text/plain or application/json content type, so the body is NOT
		// interpreted as HTML by the browser — neutralizing reflected XSS
		// for that payload. Scoped to the `Text` path so it does not affect
		// unrelated Rust code.
		{
			ID:          "rust.salvo.text_plain",
			Language:    rules.LangRust,
			Pattern:     `Text::Plain\s*\(|Text::Json\s*\(`,
			ObjectType:  "Text",
			MethodName:  "Text::Plain/Text::Json",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Salvo Text::Plain/Text::Json response (non-HTML content type prevents XSS)",
		},

		// --- Input validation ---
		{
			ID:          "rust.validator.validate",
			Language:    rules.LangRust,
			Pattern:     `\.validate\s*\(`,
			ObjectType:  "validator",
			MethodName:  ".validate()",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkTrustBoundary},
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
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path canonicalization (resolves symlinks and .., prevents traversal)",
		},
		{
			ID:          "rust.path.file_name",
			Language:    rules.LangRust,
			Pattern:     `\.file_name\s*\(`,
			ObjectType:  "",
			MethodName:  "file_name",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Extract file name component (strips directory traversal)",
		},
		{
			ID:          "rust.path.starts_with",
			Language:    rules.LangRust,
			Pattern:     `\.starts_with\s*\(`,
			ObjectType:  "",
			MethodName:  "starts_with",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
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
			Pattern:     `Entity::find\(\)\.filter\s*\(|\.col\s*\([^;]*\.eq\s*\(`,
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
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
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
			Pattern:     `\.replace\s*\(\s*['"]\\n['"]|\.replace\s*\(\s*['"]\\r['"]|\.replace\s*\(\s*&?\[.*\\n.*\\r`,
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
			Pattern:     `\.replace\s*\(\s*['"]\\r\\n['"]|\.replace\s*\(\s*['"]\\r\\n['"]`,
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

		// --- Cryptographic PRNG (neutralizes weak random) ---
		{
			ID:          "rust.rand.osrng",
			Language:    rules.LangRust,
			Pattern:     `OsRng\b`,
			ObjectType:  "rand::rngs",
			MethodName:  "OsRng",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OS-backed cryptographic RNG (prevents weak random)",
		},
		{
			ID:          "rust.rand.thread_rng",
			Language:    rules.LangRust,
			Pattern:     `thread_rng\s*\(`,
			ObjectType:  "rand",
			MethodName:  "thread_rng",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure thread-local RNG (prevents weak random)",
		},
		{
			ID:          "rust.getrandom",
			Language:    rules.LangRust,
			Pattern:     `getrandom::getrandom\s*\(|getrandom\s*\(\s*&mut`,
			ObjectType:  "getrandom",
			MethodName:  "getrandom",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OS-level random bytes via getrandom crate (cryptographically secure)",
		},

		// --- Command sanitizer ---
		{
			ID:          "rust.shell_escape",
			Language:    rules.LangRust,
			Pattern:     `shell_escape::escape\s*\(|shell_escape::unix::escape\s*\(|shell_escape::windows::escape\s*\(`,
			ObjectType:  "shell_escape",
			MethodName:  "shell_escape::escape",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "shell-escape crate escapes shell metacharacters (prevents command injection)",
		},

		// --- Trust boundary sanitizers ---
		{
			ID:          "rust.serde.typed_deser_trust",
			Language:    rules.LangRust,
			Pattern:     `serde_json::from_str\s*::\s*<|serde_json::from_slice\s*::\s*<`,
			ObjectType:  "serde_json",
			MethodName:  "serde_json::from_*::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Typed JSON deserialization constrains data shape before session storage",
		},
		{
			ID:          "rust.str.parse_int_trust",
			Language:    rules.LangRust,
			Pattern:     `\.parse\s*::\s*<\s*(?:i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)\s*>`,
			ObjectType:  "str",
			MethodName:  "str::parse::<integer>",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Integer parsing restricts value to numeric type before session storage",
		},

		// --- MongoDB NoSQL injection sanitizers ---
		{
			ID:          "rust.bson.to_bson",
			Language:    rules.LangRust,
			Pattern:     `bson::to_bson\s*\(`,
			ObjectType:  "bson",
			MethodName:  "bson::to_bson",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "bson::to_bson converts typed Rust struct to BSON (constrains document shape, prevents operator injection)",
		},
		{
			ID:          "rust.bson.to_document",
			Language:    rules.LangRust,
			Pattern:     `bson::to_document\s*\(`,
			ObjectType:  "bson",
			MethodName:  "bson::to_document",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "bson::to_document converts typed struct to Document (prevents NoSQL operator injection)",
		},

		// --- mysql_async SQL injection sanitizers ---
		{
			ID:          "rust.mysql.prep",
			Language:    rules.LangRust,
			Pattern:     `\.prep\s*\(`,
			ObjectType:  "mysql_async::Conn",
			MethodName:  "Conn::prep",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "mysql_async prepared statement creation (parameterized query prevents SQL injection)",
		},
		{
			ID:          "rust.mysql.exec_drop",
			Language:    rules.LangRust,
			Pattern:     `\.exec_drop\s*\(`,
			ObjectType:  "mysql_async::Conn",
			MethodName:  "Conn::exec_drop",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "mysql_async parameterized execution (uses prepared statement with bound params)",
		},
		{
			ID:          "rust.mysql.exec_first",
			Language:    rules.LangRust,
			Pattern:     `\.exec_first\s*\(`,
			ObjectType:  "mysql_async::Conn",
			MethodName:  "Conn::exec_first",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "mysql_async parameterized query returning first result (uses prepared statement)",
		},

		// --- Path traversal sanitizers (FileRead) ---
		{
			ID:          "rust.dunce.canonicalize",
			Language:    rules.LangRust,
			Pattern:     `dunce::canonicalize\s*\(`,
			ObjectType:  "dunce",
			MethodName:  "dunce::canonicalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Windows-compatible path canonicalization via dunce crate (resolves symlinks and ..)",
		},

		// --- Typed deserialization sanitizers ---
		{
			ID:          "rust.serde_yaml.typed_deser",
			Language:    rules.LangRust,
			Pattern:     `serde_yaml::from_str\s*::\s*<|serde_yaml::from_reader\s*::\s*<|serde_yaml::from_slice\s*::\s*<`,
			ObjectType:  "serde_yaml",
			MethodName:  "serde_yaml::from_*::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Typed YAML deserialization to concrete struct (rejects unexpected structure)",
		},
		{
			ID:          "rust.rmp_serde.typed_deser",
			Language:    rules.LangRust,
			Pattern:     `rmp_serde::from_slice\s*::\s*<|rmp_serde::from_read\s*::\s*<|rmp_serde::decode::from_slice\s*::\s*<|rmp_serde::decode::from_read\s*::\s*<`,
			ObjectType:  "rmp_serde",
			MethodName:  "rmp_serde::from_*::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Typed MessagePack deserialization to concrete struct (rejects unexpected structure)",
		},
		{
			ID:          "rust.ciborium.typed_deser",
			Language:    rules.LangRust,
			Pattern:     `ciborium::from_reader\s*::\s*<|ciborium::de::from_reader\s*::\s*<`,
			ObjectType:  "ciborium",
			MethodName:  "ciborium::from_reader::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Typed CBOR deserialization to concrete struct via ciborium (rejects unexpected structure)",
		},
		{
			ID:          "rust.ron.typed_deser",
			Language:    rules.LangRust,
			Pattern:     `ron::from_str\s*::\s*<|ron::de::from_str\s*::\s*<`,
			ObjectType:  "ron",
			MethodName:  "ron::from_str::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Typed RON deserialization to concrete struct (rejects unexpected structure)",
		},
		{
			ID:          "rust.serde_cbor.typed_deser",
			Language:    rules.LangRust,
			Pattern:     `serde_cbor::from_slice\s*::\s*<|serde_cbor::from_reader\s*::\s*<`,
			ObjectType:  "serde_cbor",
			MethodName:  "serde_cbor::from_*::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Typed CBOR deserialization to concrete struct via serde_cbor (rejects unexpected structure)",
		},
		{
			ID:          "rust.postcard.typed_deser",
			Language:    rules.LangRust,
			Pattern:     `postcard::from_bytes\s*::\s*<|postcard::from_bytes_cobs\s*::\s*<`,
			ObjectType:  "postcard",
			MethodName:  "postcard::from_bytes::<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Typed embedded-format deserialization via postcard (rejects unexpected structure)",
		},

		// --- SSRF sanitizers ---
		{
			ID:          "rust.url.scheme",
			Language:    rules.LangRust,
			Pattern:     `\.scheme\s*\(\s*\)`,
			ObjectType:  "url::Url",
			MethodName:  "Url::scheme",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL scheme extraction for protocol allowlist validation (prevents SSRF via file://, gopher://, etc.)",
		},
		{
			ID:          "rust.url.domain",
			Language:    rules.LangRust,
			Pattern:     `\.domain\s*\(\s*\)`,
			ObjectType:  "url::Url",
			MethodName:  "Url::domain",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "URL domain extraction for host allowlist validation (prevents SSRF)",
		},

		// --- Template engine auto-escape sanitizers ---
		{
			ID:          "rust.handlebars.html_escape",
			Language:    rules.LangRust,
			Pattern:     `handlebars::html_escape\s*\(`,
			ObjectType:  "handlebars",
			MethodName:  "handlebars::html_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Handlebars explicit HTML escaping function (prevents XSS in template output)",
		},
		{
			ID:          "rust.minijinja.environment_new",
			Language:    rules.LangRust,
			Pattern:     `minijinja::Environment::new\s*\(\s*\)`,
			ObjectType:  "minijinja",
			MethodName:  "minijinja::Environment::new",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Minijinja template environment with auto-escaping enabled by default",
		},
		{
			ID:          "rust.maud.html_macro",
			Language:    rules.LangRust,
			Pattern:     `maud::html!\s*\{`,
			ObjectType:  "maud",
			MethodName:  "maud::html!",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Maud compile-time HTML generation macro (auto-escapes all interpolated values)",
		},

		// --- File path sanitization ---
		{
			ID:          "rust.sanitize_filename.sanitize",
			Language:    rules.LangRust,
			Pattern:     `sanitize_filename::sanitize\s*\(`,
			ObjectType:  "sanitize_filename",
			MethodName:  "sanitize_filename::sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "sanitize-filename crate strips directory separators and traversal characters from filenames",
		},

		// --- Constant-time crypto comparison ---
		{
			ID:          "rust.subtle.ct_eq",
			Language:    rules.LangRust,
			Pattern:     `\.ct_eq\s*\(`,
			ObjectType:  "subtle",
			MethodName:  "ConstantTimeEq::ct_eq",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "subtle crate constant-time equality comparison (prevents timing side-channel attacks)",
		},
		{
			ID:          "rust.ring.constant_time_verify",
			Language:    rules.LangRust,
			Pattern:     `ring::constant_time::verify_slices_are_equal\s*\(`,
			ObjectType:  "ring",
			MethodName:  "ring::constant_time::verify_slices_are_equal",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "ring constant-time byte slice comparison (prevents timing attacks on HMAC/hash verification)",
		},

		// --- SSRF IP address validation ---
		{
			ID:          "rust.ipaddr.ssrf_check",
			Language:    rules.LangRust,
			Pattern:     `\.is_loopback\s*\(\s*\)|\.is_private\s*\(\s*\)|\.is_link_local\s*\(\s*\)`,
			ObjectType:  "std::net::IpAddr",
			MethodName:  "IpAddr::is_loopback/is_private/is_link_local",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address internal network check prevents SSRF by detecting loopback, private, and link-local addresses",
		},

		// --- XPath injection sanitizers ---
		{
			ID:          "rust.sxd_xpath.context_set_variable",
			Language:    rules.LangRust,
			Pattern:     `\.set_variable\s*\(\s*"[^"]+"\s*,`,
			ObjectType:  "sxd_xpath::Context",
			MethodName:  "Context::set_variable",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "sxd_xpath Context variable binding separates XPath expression from user data (prevents injection)",
		},
		{
			ID:          "rust.quick_xml.escape",
			Language:    rules.LangRust,
			Pattern:     `quick_xml::escape::escape\s*\(`,
			ObjectType:  "quick_xml::escape",
			MethodName:  "quick_xml::escape::escape",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkHTMLOutput},
			Description: "quick-xml XML entity escaping encodes &, <, >, \", ' to prevent XPath and XSS injection",
		},
		{
			ID:          "rust.xmlrs.escape_str_attribute",
			Language:    rules.LangRust,
			Pattern:     `xml::escape::escape_str_attribute\s*\(|xml::escape::escape_str_pcdata\s*\(`,
			ObjectType:  "xml::escape",
			MethodName:  "xml::escape::escape_str_attribute/xml::escape::escape_str_pcdata",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkHTMLOutput},
			Description: "xml-rs XML character escaping for attribute values and PCDATA (prevents XPath and XSS injection)",
		},

		// --- Code injection (eval) sanitizers ---
		{
			ID:          "rust.rhai.set_max_operations",
			Language:    rules.LangRust,
			Pattern:     `\.set_max_operations\s*\(`,
			ObjectType:  "rhai::Engine",
			MethodName:  "Engine::set_max_operations",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Rhai engine operation limit prevents infinite loops and resource exhaustion from untrusted scripts",
		},
		{
			ID:          "rust.rhai.disable_symbol",
			Language:    rules.LangRust,
			Pattern:     `\.disable_symbol\s*\(`,
			ObjectType:  "rhai::Engine",
			MethodName:  "Engine::disable_symbol",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Rhai keyword/operator disabling restricts engine to safe subset (e.g., disable eval, loops)",
		},
		{
			ID:          "rust.rhai.engine_new_raw",
			Language:    rules.LangRust,
			Pattern:     `Engine::new_raw\s*\(`,
			ObjectType:  "rhai::Engine",
			MethodName:  "Engine::new_raw",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Rhai raw engine creation with zero built-in functions (whitelist-only approach for untrusted input)",
		},
		{
			ID:          "rust.rhai.set_max_string_size",
			Language:    rules.LangRust,
			Pattern:     `\.set_max_string_size\s*\(`,
			ObjectType:  "rhai::Engine",
			MethodName:  "Engine::set_max_string_size",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Rhai string size limit prevents memory exhaustion from untrusted scripts",
		},
		{
			ID:          "rust.mlua.sandbox",
			Language:    rules.LangRust,
			Pattern:     `\.sandbox\s*\(\s*true\s*\)|Lua::new_with\s*\(`,
			ObjectType:  "mlua::Lua",
			MethodName:  "Lua::sandbox/Lua::new_with",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "mlua Lua sandbox mode or restricted stdlib creation prevents untrusted code from accessing OS/IO",
		},

		// --- JWT signature verification (CWE-345) ---
		// jsonwebtoken::decode() requires a DecodingKey + Validation and
		// enforces the HMAC/RSA/ECDSA signature check. Any data flowing out
		// of decode() has crossed the JWT trust boundary correctly.
		{
			ID:          "rust.jsonwebtoken.decode",
			Language:    rules.LangRust,
			Pattern:     `jsonwebtoken::decode\s*(?:::<|\()`,
			ObjectType:  "jsonwebtoken",
			MethodName:  "decode",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "jsonwebtoken::decode() verifies the JWT signature before returning claims (safe alternative to dangerous::insecure_decode)",
		},
		// --- Email Header Injection Sanitizer: lettre Address::new (CWE-93) ---
		{
			ID:          "rust.lettre.address.new",
			Language:    rules.LangRust,
			Pattern:     `Address::new\s*\(`,
			ObjectType:  "",
			MethodName:  "Address::new",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "lettre Address::new validates RFC 5321 address format and rejects CRLF / invalid characters in local-part and domain",
		},
		{
			ID:          "rust.zip.file.enclosed_name",
			Language:    rules.LangRust,
			Pattern:     `\.enclosed_name\s*\(`,
			ObjectType:  "",
			MethodName:  "enclosed_name",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "zip crate ZipFile::enclosed_name rejects path-traversal components — safe PathBuf or None (CWE-22)",
		},

		// --- RustCrypto password_hash trait (CWE-916, CWE-326) ---
		// Generic PasswordHasher::hash_password covers Argon2, Scrypt, Pbkdf2,
		// sha-crypt, balloon-hash, and any other RustCrypto password hasher
		// that implements the password-hash trait. The method name is unique
		// enough across the Rust ecosystem that empty ObjectType is safe —
		// only password hashers expose `.hash_password()`.
		{
			ID:          "rust.password_hash.hash_password",
			Language:    rules.LangRust,
			Pattern:     `\.hash_password\s*\(`,
			ObjectType:  "",
			MethodName:  "hash_password",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "RustCrypto PasswordHasher::hash_password trait method (Argon2, Scrypt, Pbkdf2, etc. — adaptive password hashing with salt)",
		},

		// --- IDN normalization for SSRF / open-redirect host checks (CWE-918, CWE-601) ---
		// idna::domain_to_ascii performs Unicode IDNA processing per UTS #46,
		// converting Unicode hostnames to their ASCII (Punycode) form so
		// host-allowlist checks compare apples to apples and aren't bypassed
		// by Unicode look-alikes.
		{
			ID:          "rust.idna.domain_to_ascii",
			Language:    rules.LangRust,
			Pattern:     `idna::domain_to_ascii\s*\(`,
			ObjectType:  "idna",
			MethodName:  "idna::domain_to_ascii",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "idna::domain_to_ascii converts IDN hostnames to ASCII Punycode form (UTS #46) for safe host-allowlist comparison",
		},
		{
			ID:          "rust.idna.domain_to_ascii_strict",
			Language:    rules.LangRust,
			Pattern:     `idna::domain_to_ascii_strict\s*\(`,
			ObjectType:  "idna",
			MethodName:  "idna::domain_to_ascii_strict",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "idna::domain_to_ascii_strict applies STD3 ASCII rules and rejects invalid hostnames (stricter SSRF host validation)",
		},

		// --- percent-encoding crate explicit URL encoding (CWE-79, CWE-918) ---
		// The existing rust.encode_uri_component entry only matches calls
		// where the receiver is "urlencoding". percent-encoding is a separate
		// crate with its own namespace; its calls (`percent_encoding::utf8_percent_encode`,
		// `percent_encoding::percent_encode`) need their own catalog entries
		// to fire in the tsflow engine.
		{
			ID:          "rust.percent_encoding.utf8_percent_encode",
			Language:    rules.LangRust,
			Pattern:     `percent_encoding::utf8_percent_encode\s*\(`,
			ObjectType:  "percent_encoding",
			MethodName:  "percent_encoding::utf8_percent_encode",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHTMLOutput},
			Description: "percent-encoding crate utf8_percent_encode percent-encodes a string against a character set (safe URL component construction)",
		},
		{
			ID:          "rust.percent_encoding.percent_encode",
			Language:    rules.LangRust,
			Pattern:     `percent_encoding::percent_encode\s*\(`,
			ObjectType:  "percent_encoding",
			MethodName:  "percent_encoding::percent_encode",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHTMLOutput},
			Description: "percent-encoding crate percent_encode percent-encodes a byte slice against a character set (safe URL component construction)",
		},

		// --- htmlescape crate (CWE-79) ---
		// htmlescape is a separate, widely-used crate with its own namespace
		// (distinct from html_escape, which the existing rust.html_escape
		// entry covers). encode_minimal escapes &<>"' for HTML body context;
		// encode_attribute additionally escapes characters unsafe inside
		// attribute values.
		{
			ID:          "rust.htmlescape.encode_minimal",
			Language:    rules.LangRust,
			Pattern:     `htmlescape::encode_minimal\s*\(`,
			ObjectType:  "htmlescape",
			MethodName:  "htmlescape::encode_minimal",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "htmlescape crate encode_minimal escapes &<>\"' for safe HTML body content (prevents XSS)",
		},
		{
			ID:          "rust.htmlescape.encode_attribute",
			Language:    rules.LangRust,
			Pattern:     `htmlescape::encode_attribute\s*\(`,
			ObjectType:  "htmlescape",
			MethodName:  "htmlescape::encode_attribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "htmlescape crate encode_attribute escapes characters unsafe inside HTML attribute values (stricter XSS prevention)",
		},

		// v_htmlescape — SIMD-optimized HTML escaping (Actix-web ecosystem,
		// 600k+ downloads/month, used by 400+ crates). Distinct from the
		// html_escape and htmlescape crates already covered above.
		{
			ID:          "rust.v_htmlescape.escape",
			Language:    rules.LangRust,
			Pattern:     `v_htmlescape::escape\s*\(`,
			ObjectType:  "v_htmlescape",
			MethodName:  "v_htmlescape::escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "v_htmlescape crate escape (SIMD HTML escape; canonical Actix-web HTML escaping)",
		},

		// askama_escape — HTML/XML escaper extracted from the Askama template
		// engine. Useful when callers want template-style escaping without
		// pulling in the full template engine.
		{
			ID:          "rust.askama_escape.escape",
			Language:    rules.LangRust,
			Pattern:     `askama_escape::escape\s*\(`,
			ObjectType:  "askama_escape",
			MethodName:  "askama_escape::escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "askama_escape crate escape (returns MarkupDisplay that escapes &<>\"' for HTML/XML output)",
		},

		// --- URL encoding (urlencoding crate, distinct from percent-encoding) ---
		// The urlencoding crate is a separate widely-used crate with a
		// simpler API than percent-encoding (which requires defining an
		// AsciiSet). Both are commonly used.
		{
			ID:          "rust.urlencoding.encode",
			Language:    rules.LangRust,
			Pattern:     `urlencoding::encode\s*\(`,
			ObjectType:  "urlencoding",
			MethodName:  "urlencoding::encode",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHTMLOutput},
			Description: "urlencoding crate encode percent-encodes a string for safe URL component construction",
		},
		{
			ID:          "rust.urlencoding.encode_binary",
			Language:    rules.LangRust,
			Pattern:     `urlencoding::encode_binary\s*\(`,
			ObjectType:  "urlencoding",
			MethodName:  "urlencoding::encode_binary",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHTMLOutput},
			Description: "urlencoding crate encode_binary percent-encodes a byte slice for safe URL component construction",
		},

		// --- Typed parsing as input validation ---
		// Uuid::parse_str returns Result<Uuid> — a successful parse guarantees
		// the input is a well-formed UUID, removing SQL/URL injection risk
		// when the parsed UUID is later re-formatted into queries or URLs.
		{
			ID:          "rust.uuid.parse_str",
			Language:    rules.LangRust,
			Pattern:     `Uuid::parse_str\s*\(`,
			ObjectType:  "Uuid",
			MethodName:  "Uuid::parse_str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "uuid crate Uuid::parse_str validates input as a well-formed UUID (rejects injection payloads)",
		},

		// --- Path canonicalization (additional crates) ---
		// path-clean: lexical path normalization (Plan 9 cleanname / Go path.Clean port).
		// Resolves "." and ".." segments without touching the filesystem;
		// pair with prefix-check for full traversal prevention.
		{
			ID:          "rust.path_clean.clean",
			Language:    rules.LangRust,
			Pattern:     `path_clean::clean\s*\(`,
			ObjectType:  "path_clean",
			MethodName:  "path_clean::clean",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "path-clean crate clean lexically normalizes a path (collapses . and .. segments) — Plan 9 / Go path.Clean port",
		},
		// tokio::fs::canonicalize — async equivalent of std::fs::canonicalize.
		// Resolves symlinks and "..", returning a real path; common in async
		// Rust web servers when validating user-supplied file paths.
		{
			ID:          "rust.tokio_fs.canonicalize",
			Language:    rules.LangRust,
			Pattern:     `tokio::fs::canonicalize\s*\(`,
			ObjectType:  "tokio::fs",
			MethodName:  "tokio::fs::canonicalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "tokio::fs::canonicalize async path canonicalization (resolves symlinks and .., prevents traversal)",
		},

		// --- Temporal parsing (chrono / time / humantime) ---
		// Parsing user input into a strongly-typed Date/Time/Duration value
		// neutralizes free-form-string injection: the result is a typed struct
		// whose Display impl is well-defined (ISO-8601 / RFC formats), so it
		// cannot carry shell metachars, SQL syntax, path separators, CRLFs,
		// HTML, or scheme-injection payloads. Same model as
		// kotlin.time.*.parse (PR #600).
		{
			ID:          "rust.chrono.datetime.parse_from_rfc3339",
			Language:    rules.LangRust,
			Pattern:     `DateTime::parse_from_rfc3339\s*\(`,
			ObjectType:  "chrono::DateTime",
			MethodName:  "parse_from_rfc3339",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "chrono::DateTime::parse_from_rfc3339 strict RFC-3339 parser (returns DateTime<FixedOffset>, no injection)",
		},
		{
			ID:          "rust.chrono.datetime.parse_from_rfc2822",
			Language:    rules.LangRust,
			Pattern:     `DateTime::parse_from_rfc2822\s*\(`,
			ObjectType:  "chrono::DateTime",
			MethodName:  "parse_from_rfc2822",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "chrono::DateTime::parse_from_rfc2822 strict RFC-2822 parser (returns DateTime<FixedOffset>, no injection)",
		},
		{
			ID:          "rust.chrono.datetime.parse_from_str",
			Language:    rules.LangRust,
			Pattern:     `DateTime::parse_from_str\s*\(`,
			ObjectType:  "chrono::DateTime",
			MethodName:  "parse_from_str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "chrono::DateTime::parse_from_str format-string parser (returns DateTime<FixedOffset>, no injection)",
		},
		{
			ID:          "rust.chrono.naivedate.parse_from_str",
			Language:    rules.LangRust,
			Pattern:     `NaiveDate::parse_from_str\s*\(`,
			ObjectType:  "chrono::NaiveDate",
			MethodName:  "parse_from_str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "chrono::NaiveDate::parse_from_str (returns NaiveDate, no injection)",
		},
		{
			ID:          "rust.chrono.naivedatetime.parse_from_str",
			Language:    rules.LangRust,
			Pattern:     `NaiveDateTime::parse_from_str\s*\(`,
			ObjectType:  "chrono::NaiveDateTime",
			MethodName:  "parse_from_str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "chrono::NaiveDateTime::parse_from_str (returns NaiveDateTime, no injection)",
		},
		{
			ID:          "rust.chrono.naivetime.parse_from_str",
			Language:    rules.LangRust,
			Pattern:     `NaiveTime::parse_from_str\s*\(`,
			ObjectType:  "chrono::NaiveTime",
			MethodName:  "parse_from_str",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "chrono::NaiveTime::parse_from_str (returns NaiveTime, no injection)",
		},
		{
			ID:          "rust.time.offsetdatetime.parse",
			Language:    rules.LangRust,
			Pattern:     `OffsetDateTime::parse\s*\(`,
			ObjectType:  "time::OffsetDateTime",
			MethodName:  "OffsetDateTime::parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "time crate OffsetDateTime::parse (returns OffsetDateTime, no injection)",
		},
		{
			ID:          "rust.time.primitivedatetime.parse",
			Language:    rules.LangRust,
			Pattern:     `PrimitiveDateTime::parse\s*\(`,
			ObjectType:  "time::PrimitiveDateTime",
			MethodName:  "PrimitiveDateTime::parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "time crate PrimitiveDateTime::parse (returns PrimitiveDateTime, no injection)",
		},
		{
			ID:          "rust.humantime.parse_duration",
			Language:    rules.LangRust,
			Pattern:     `humantime::parse_duration\s*\(`,
			ObjectType:  "humantime",
			MethodName:  "humantime::parse_duration",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "humantime::parse_duration human-readable duration parser (returns std::time::Duration, no injection)",
		},
		{
			ID:          "rust.humantime.parse_rfc3339",
			Language:    rules.LangRust,
			Pattern:     `humantime::parse_rfc3339\s*\(`,
			ObjectType:  "humantime",
			MethodName:  "humantime::parse_rfc3339",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "humantime::parse_rfc3339 strict RFC-3339 parser (returns SystemTime, no injection)",
		},

		// --- NoSQL parameterization (BSON document construction with typed values) ---
		{
			ID:          "rust.bson.doc_macro",
			Language:    rules.LangRust,
			Pattern:     `\bdoc!\s*\{`,
			ObjectType:  "bson",
			MethodName:  "doc!",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson::doc! macro constructs typed BSON documents (values are bound as data, not concatenated into the query)",
		},
		{
			ID:          "rust.bson.to_bson",
			Language:    rules.LangRust,
			Pattern:     `bson::to_bson\s*\(`,
			ObjectType:  "bson",
			MethodName:  "bson::to_bson",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson::to_bson serialises a Rust value to a typed BSON value (no string concatenation)",
		},
		{
			ID:          "rust.bson.oid_parse",
			Language:    rules.LangRust,
			Pattern:     `ObjectId::parse_str\s*\(`,
			ObjectType:  "bson::oid::ObjectId",
			MethodName:  "ObjectId::parse_str",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson::oid::ObjectId::parse_str strictly parses a 24-char hex string (validates input as a typed ObjectId)",
		},
		{
			ID:          "rust.mongodb.bson_oid_new",
			Language:    rules.LangRust,
			Pattern:     `bson::oid::ObjectId::new\s*\(`,
			ObjectType:  "bson::oid::ObjectId",
			MethodName:  "ObjectId::new",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson::oid::ObjectId::new generates a fresh ObjectId (no caller-supplied bytes flow through)",
		},
		{
			ID:          "rust.bson.regex_typed",
			Language:    rules.LangRust,
			Pattern:     `bson::Regex\s*\{|Bson::Regex\s*\(`,
			ObjectType:  "bson::Regex",
			MethodName:  "Regex",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson::Regex { pattern, options } — typed BSON regex; pattern bound as a typed regex value (cannot smuggle a $where document)",
		},
		{
			ID:          "rust.regex.escape_nosql",
			Language:    rules.LangRust,
			Pattern:     `regex::escape\s*\(`,
			ObjectType:  "regex",
			MethodName:  "regex::escape",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "regex::escape — escapes regex metacharacters before embedding user input in a $regex MongoDB filter or a SQL LIKE pattern (prevents broadened-match injection)",
		},
		{
			ID:          "rust.bson.document_from_reader",
			Language:    rules.LangRust,
			Pattern:     `bson::Document::from_reader\s*\(|bson::from_reader\s*\(`,
			ObjectType:  "bson::Document",
			MethodName:  "Document::from_reader",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson::Document::from_reader / bson::from_reader — strict typed BSON parser (errors on malformed input, blocking free-form operator injection)",
		},
		{
			ID:          "rust.mongo.collection_typed",
			Language:    rules.LangRust,
			Pattern:     `\.collection::<[^>]+>\s*\(`,
			ObjectType:  "mongodb::Collection",
			MethodName:  "Collection<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "mongodb::Collection<T> typed-collection accessor — find/update_one/etc. accept a typed T (serde-derived), so attacker-supplied keys cannot reach the BSON filter outside of the typed schema",
		},

		// --- Header injection (CWE-93 CRLF) — strip + typed http::HeaderMap ---
		{
			ID:          "rust.http.header_value_from_str",
			Language:    rules.LangRust,
			Pattern:     `HeaderValue::from_str\s*\(|HeaderValue::from_bytes\s*\(`,
			ObjectType:  "http::HeaderValue",
			MethodName:  "HeaderValue::from_str/from_bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "http::HeaderValue::from_str / from_bytes — typed HeaderValue parser; rejects CR/LF and non-printable characters per HTTP spec (returns Result so invalid headers are caught at compile-time)",
		},
		{
			ID:          "rust.http.header_name_from_str",
			Language:    rules.LangRust,
			Pattern:     `HeaderName::from_str\s*\(|HeaderName::from_bytes\s*\(`,
			ObjectType:  "http::HeaderName",
			MethodName:  "HeaderName::from_str/from_bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "http::HeaderName::from_str / from_bytes — typed HeaderName parser; restricts to RFC-compliant tokens (rejects spaces, colons, control characters)",
		},
		{
			ID:          "rust.string.replace_crlf",
			Language:    rules.LangRust,
			Pattern:     `\.replace\s*\(\s*'\\\\r'\s*,|\.replace\s*\(\s*'\\\\n'\s*,|\.replace\s*\(\s*"[\\\\r\\\\n]+"\s*,`,
			ObjectType:  "str",
			MethodName:  "str::replace(CRLF)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Manual CR/LF stripping (.replace('\\r', '') / .replace('\\n', '')) — defends header / log injection (CWE-93)",
		},

		// --- Crypto sanitizers — strong password-hash / KDF crates ---
		{
			ID:          "rust.argon2.hash",
			Language:    rules.LangRust,
			Pattern:     `Argon2::default\s*\(\s*\)|Argon2::new\s*\(|argon2::hash_encoded\s*\(`,
			ObjectType:  "argon2",
			MethodName:  "Argon2",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "argon2 crate — RFC-9106 Argon2 password hash; sound replacement for ad-hoc hash-based password storage (defends CWE-916)",
		},
		{
			ID:          "rust.bcrypt.hash",
			Language:    rules.LangRust,
			Pattern:     `\bbcrypt::hash\s*\(`,
			ObjectType:  "bcrypt",
			MethodName:  "bcrypt::hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "bcrypt crate hash — bcrypt password hash (defends CWE-916)",
		},
		{
			ID:          "rust.scrypt.params",
			Language:    rules.LangRust,
			Pattern:     `scrypt::Params::new\s*\(|scrypt::scrypt\s*\(`,
			ObjectType:  "scrypt",
			MethodName:  "scrypt",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "scrypt crate Params / hash — scrypt KDF (defends CWE-916)",
		},
		{
			ID:          "rust.pbkdf2.derive",
			Language:    rules.LangRust,
			Pattern:     `pbkdf2::pbkdf2(?:_hmac)?\s*::<|pbkdf2_hmac\s*\(`,
			ObjectType:  "pbkdf2",
			MethodName:  "pbkdf2",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "pbkdf2 crate (HMAC variant) — PBKDF2 KDF; sound for password hashing / key derivation",
		},
		{
			ID:          "rust.ring.rand_systemrandom",
			Language:    rules.LangRust,
			Pattern:     `ring::rand::SystemRandom::new\s*\(\s*\)|SystemRandom::new\s*\(\s*\)`,
			ObjectType:  "ring::rand::SystemRandom",
			MethodName:  "SystemRandom::new",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "ring::rand::SystemRandom — OS-backed CSPRNG (CWE-338 weak-PRNG defence)",
		},

		// --- SeaQuery parameterized build (CWE-89) ---
		// The whole point of sea-query is to produce a (sql, values) pair where
		// user data is carried in the values slice and the SQL string contains
		// only `?`/`$N` placeholders. `.build(QueryBuilder)` (and the
		// driver-specific `.build_sqlx(...)`) emit that parameterised pair, so a
		// query assembled through the typed builder DSL and finalised with
		// .build* is safe even if individual values are tainted.
		{
			ID:          "rust.seaquery.build",
			Language:    rules.LangRust,
			Pattern:     `\.build\s*\(\s*(?:PostgresQueryBuilder|MysqlQueryBuilder|SqliteQueryBuilder)`,
			ObjectType:  "sea_query",
			MethodName:  "QueryStatementBuilder::build",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "sea-query .build(PostgresQueryBuilder/MysqlQueryBuilder/SqliteQueryBuilder) emits a (sql, values) pair with placeholders — values are bound, not concatenated (prevents SQL injection)",
		},
		{
			ID:          "rust.seaquery.build_sqlx",
			Language:    rules.LangRust,
			Pattern:     `\.build_sqlx\s*\(`,
			ObjectType:  "sea_query",
			MethodName:  "build_sqlx",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "sea-query .build_sqlx(QueryBuilder) emits a parameterised SQL string + sqlx Values bundle for binding (prevents SQL injection)",
		},

		// --- ReDoS / regex resource-exhaustion limits (CWE-1333) ---
		// Rust's regex crate is linear-time, so the DoS surface is the compiled
		// program size. RegexBuilder::size_limit / dfa_size_limit cap that
		// memory, neutralising a hostile (large) pattern.
		{
			ID:          "rust.regex.size_limit",
			Language:    rules.LangRust,
			Pattern:     `\.size_limit\s*\(`,
			ObjectType:  "regex::RegexBuilder",
			MethodName:  "RegexBuilder::size_limit",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "regex::RegexBuilder::size_limit caps the compiled program size, bounding memory use for a user-controlled pattern (prevents regex resource exhaustion)",
		},
		{
			ID:          "rust.regex.dfa_size_limit",
			Language:    rules.LangRust,
			Pattern:     `\.dfa_size_limit\s*\(`,
			ObjectType:  "regex::RegexBuilder",
			MethodName:  "RegexBuilder::dfa_size_limit",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "regex::RegexBuilder::dfa_size_limit caps the lazy-DFA cache size, bounding memory use for a user-controlled pattern (prevents regex resource exhaustion)",
		},
		{
			ID:          "rust.regex.escape_redos",
			Language:    rules.LangRust,
			Pattern:     `regex::escape\s*\(`,
			ObjectType:  "regex",
			MethodName:  "regex::escape",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "regex::escape turns user input into a literal-matching pattern (no metacharacters), so a tainted string can no longer control regex structure (prevents ReDoS)",
		},

		// --- CSV / spreadsheet-formula injection guard (CWE-1236) ---
		// There is no canonical CSV-escaper crate; the standard mitigation is a
		// leading-character guard that detects cells beginning with a formula
		// trigger (= + - @ tab CR) before writing. Scoped to those leading
		// chars so it doesn't collide with path/prefix starts_with checks.
		{
			ID:          "rust.csv.formula_guard",
			Language:    rules.LangRust,
			Pattern:     `\.starts_with\s*\(\s*['"][=+\-@\t\r]`,
			ObjectType:  "str",
			MethodName:  "str::starts_with (formula-char guard)",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Leading formula-character guard (starts_with('='/'+'/'-'/'@'/tab/CR)) before writing a CSV cell — the standard defence against spreadsheet formula injection (CWE-1236)",
		},

		// --- File-upload sanitizers (CWE-434) ---
		// sanitize-filename strips path separators/traversal from the
		// attacker-supplied filename, and content-based MIME sniffing (infer)
		// validates the file's *true* type instead of trusting the client
		// extension/Content-Type — both are the canonical upload defences.
		{
			ID:          "rust.upload.sanitize_filename",
			Language:    rules.LangRust,
			Pattern:     `sanitize_filename::sanitize\s*\(`,
			ObjectType:  "sanitize_filename",
			MethodName:  "sanitize_filename::sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "sanitize-filename crate strips directory separators and traversal sequences from a client-supplied upload filename (prevents path traversal in unrestricted upload, CWE-434)",
		},
		{
			ID:          "rust.upload.infer_get",
			Language:    rules.LangRust,
			Pattern:     `infer::get\s*\(`,
			ObjectType:  "infer",
			MethodName:  "infer::get",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "infer::get sniffs the true file type from magic bytes — validating uploaded content against an allowlist (rather than trusting the client extension) defends unrestricted file upload (CWE-434)",
		},
		{
			ID:          "rust.upload.infer_get_from_path",
			Language:    rules.LangRust,
			Pattern:     `infer::get_from_path\s*\(`,
			ObjectType:  "infer",
			MethodName:  "infer::get_from_path",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "infer::get_from_path sniffs the true file type from a saved file's magic bytes — allowlisting on the detected type defends unrestricted file upload (CWE-434)",
		},

		// --- Binary-to-text encoding (hex / base64) — output encoding for injection-context safety ---
		// Mirrors the C (c.openssl.buf2hexstr, c.encoding.glib_base64_encode) and
		// Zig (zig.fmt.fmtSliceHexLower, zig.base64.encode) precedents: encoding
		// arbitrary bytes to hex or base64 yields an alphabet with no HTML/log/header
		// metacharacters, so the result is safe to embed in those output contexts.
		{
			ID:          "rust.hex.encode",
			Language:    rules.LangRust,
			Pattern:     `hex::encode\s*\(`,
			ObjectType:  "hex",
			MethodName:  "hex::encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader},
			Description: "hex crate hex::encode converts arbitrary bytes to a lowercase [0-9a-f] string — output has no HTML/log/header injection characters (CWE-79, CWE-117, CWE-93)",
		},
		{
			ID:          "rust.hex.encode_upper",
			Language:    rules.LangRust,
			Pattern:     `hex::encode_upper\s*\(`,
			ObjectType:  "hex",
			MethodName:  "hex::encode_upper",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader},
			Description: "hex crate hex::encode_upper converts arbitrary bytes to an uppercase [0-9A-F] string — output has no HTML/log/header injection characters (CWE-79, CWE-117, CWE-93)",
		},
		{
			ID:          "rust.base64.encode",
			Language:    rules.LangRust,
			Pattern:     `base64::encode\s*\(`,
			ObjectType:  "base64",
			MethodName:  "base64::encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader},
			Description: "base64 crate base64::encode produces an [A-Za-z0-9+/=] string with no angle-bracket / quote / CRLF characters — safe in HTML body, log, and header output contexts (CWE-79, CWE-117, CWE-93)",
		},

		// --- Allocation-size bounding (CWE-770) ---
		// Clamping a tainted length to a fixed upper bound before using it as an
		// allocation capacity makes the allocation safe. std::cmp::min(n, MAX),
		// n.min(MAX), n.clamp(lo, hi), and the saturating/checked size arithmetic
		// all cap the value, so a Vec::with_capacity / reserve fed the result is
		// no longer attacker-controlled. Neutralizes SnkMemory only.
		{
			ID:          "rust.alloc.size_bound",
			Language:    rules.LangRust,
			Pattern:     `(?:std::)?cmp::min\s*\(|\.min\s*\(|\.clamp\s*\(|\.saturating_\w+\s*\(|\.checked_\w+\s*\(`,
			ObjectType:  "std::cmp",
			MethodName:  "cmp::min/min/clamp/saturating_add/saturating_mul/checked_add/checked_mul",
			Neutralizes: []taint.SinkCategory{taint.SnkMemory},
			Description: "Clamping a tainted size with std::cmp::min / .min() / .clamp() / saturating or checked arithmetic caps the allocation at a fixed upper bound — the capacity is no longer attacker-controlled (CWE-770)",
		},
	}
}
