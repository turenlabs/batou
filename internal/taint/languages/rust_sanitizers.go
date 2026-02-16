package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
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
			MethodName:  "html_escape::encode_*",
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
			ObjectType:  "url",
			MethodName:  "Url::parse",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL parsing and validation",
		},

		// --- Path validation ---
		{
			ID:          "rust.path.canonicalize",
			Language:    rules.LangRust,
			Pattern:     `\.canonicalize\s*\(`,
			ObjectType:  "std::path::Path",
			MethodName:  "Path::canonicalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path canonicalization (resolves symlinks and .., prevents traversal)",
		},
		{
			ID:          "rust.path.file_name",
			Language:    rules.LangRust,
			Pattern:     `\.file_name\s*\(`,
			ObjectType:  "std::path::Path",
			MethodName:  "Path::file_name",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract file name component (strips directory traversal)",
		},
		{
			ID:          "rust.path.starts_with",
			Language:    rules.LangRust,
			Pattern:     `\.starts_with\s*\(`,
			ObjectType:  "std::path::Path",
			MethodName:  "Path::starts_with",
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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "String to integer parsing (restricts to numeric values)",
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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Numeric type parsing (restricts to numeric values)",
		},
	}
}
