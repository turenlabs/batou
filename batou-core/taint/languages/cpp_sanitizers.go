package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (cppCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// ── Input validation / type coercion ──────────────────────────
		{ID: "cpp.stoi", Language: rules.LangCPP, Pattern: `std::sto[ilfdu]\s*\(`, ObjectType: "std", MethodName: "stoi/stol/stof/stod", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkMemory}, Description: "String to numeric conversion (type coercion/validation)"},

		// ── SQL parameterization ──────────────────────────────────────
		{ID: "cpp.sqlite3.bind", Language: rules.LangCPP, Pattern: `sqlite3_bind_(?:text|int|double|blob|int64)\s*\(`, ObjectType: "sqlite3", MethodName: "sqlite3_bind_*", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "SQLite parameterized query binding"},
		{ID: "cpp.mysql.stmt.bind", Language: rules.LangCPP, Pattern: `mysql_stmt_bind_param\s*\(`, ObjectType: "mysql", MethodName: "mysql_stmt_bind_param", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQL prepared statement parameter binding"},
		{ID: "cpp.sqlite3.mprintf", Language: rules.LangCPP, Pattern: `sqlite3_mprintf\s*\(`, ObjectType: "sqlite3", MethodName: "sqlite3_mprintf", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "SQLite mprintf with %q SQL escaping"},

		// ── HTML encoding / escaping ──────────────────────────────────
		{ID: "cpp.html.escape", Language: rules.LangCPP, Pattern: `(?:html_escape|htmlEncode|escapeHtml|escape_html)\s*\(`, ObjectType: "", MethodName: "html_escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML entity escaping function"},
		{ID: "cpp.crow.mustache", Language: rules.LangCPP, Pattern: `crow::mustache::`, ObjectType: "crow::mustache", MethodName: "mustache", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Crow Mustache template engine (auto-escapes by default)"},

		// ── Path sanitization ─────────────────────────────────────────
		{ID: "cpp.basename", Language: rules.LangCPP, Pattern: `\bbasename\s*\(`, ObjectType: "", MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "Strip directory component from path (prevents traversal)"},

		// ── Crypto sanitizers ─────────────────────────────────────────
		{ID: "cpp.openssl.rand.bytes", Language: rules.LangCPP, Pattern: `RAND_bytes\s*\(`, ObjectType: "OpenSSL", MethodName: "RAND_bytes", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "OpenSSL cryptographically secure random bytes"},
		{ID: "cpp.random.device", Language: rules.LangCPP, Pattern: `std::random_device`, ObjectType: "std", MethodName: "random_device", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "std::random_device hardware-based non-deterministic random"},
		{ID: "cpp.openssl.aes.gcm", Language: rules.LangCPP, Pattern: `EVP_aes_(?:128|256)_gcm\s*\(`, ObjectType: "OpenSSL", MethodName: "EVP_aes_*_gcm", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "OpenSSL AES-GCM authenticated encryption"},
		{ID: "cpp.openssl.sha256", Language: rules.LangCPP, Pattern: `SHA256\s*\(|EVP_sha256\s*\(`, ObjectType: "OpenSSL", MethodName: "SHA256", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "SHA-256 secure hash algorithm"},
		{ID: "cpp.openssl.sha384_512", Language: rules.LangCPP, Pattern: `EVP_sha384\s*\(|EVP_sha512\s*\(`, ObjectType: "OpenSSL", MethodName: "EVP_sha384/EVP_sha512", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "SHA-384/SHA-512 secure hash algorithms"},
		{ID: "cpp.openssl.chacha20poly1305", Language: rules.LangCPP, Pattern: `EVP_chacha20_poly1305\s*\(`, ObjectType: "OpenSSL", MethodName: "EVP_chacha20_poly1305", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "ChaCha20-Poly1305 authenticated encryption (fast, safe alternative to AES-GCM)"},
		{ID: "cpp.openssl.pbkdf2", Language: rules.LangCPP, Pattern: `PKCS5_PBKDF2_HMAC\s*\(`, ObjectType: "OpenSSL", MethodName: "PKCS5_PBKDF2_HMAC", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "PBKDF2 key derivation function (stretches passwords securely)"},
		{ID: "cpp.openssl.tls_method", Language: rules.LangCPP, Pattern: `\bTLS_method\s*\(|\bTLS_(?:client|server)_method\s*\(`, ObjectType: "OpenSSL", MethodName: "TLS_method", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Modern OpenSSL TLS method (negotiates highest available protocol version)"},
		{ID: "cpp.libsodium.secretbox", Language: rules.LangCPP, Pattern: `crypto_secretbox_easy\s*\(|crypto_secretbox_open_easy\s*\(`, ObjectType: "libsodium", MethodName: "crypto_secretbox_easy", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "libsodium authenticated symmetric encryption (XSalsa20-Poly1305)"},
		{ID: "cpp.libsodium.aead", Language: rules.LangCPP, Pattern: `crypto_aead_\w+_encrypt\s*\(|crypto_aead_\w+_decrypt\s*\(`, ObjectType: "libsodium", MethodName: "crypto_aead_*_encrypt/decrypt", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "libsodium AEAD encryption (AES-256-GCM or XChaCha20-Poly1305)"},
		{ID: "cpp.libsodium.randombytes", Language: rules.LangCPP, Pattern: `randombytes_buf\s*\(`, ObjectType: "libsodium", MethodName: "randombytes_buf", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "libsodium cryptographically secure random bytes"},
		{ID: "cpp.botan.rng", Language: rules.LangCPP, Pattern: `Botan::AutoSeeded_RNG\b|Botan::system_rng\s*\(`, ObjectType: "Botan", MethodName: "AutoSeeded_RNG/system_rng", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Botan cryptographically secure RNG"},
		{ID: "cpp.botan.aead", Language: rules.LangCPP, Pattern: `Botan::AEAD_Mode::create\s*\(`, ObjectType: "Botan", MethodName: "AEAD_Mode::create", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Botan AEAD mode creation (authenticated encryption)"},

		// ── Modern password hashing (memory-hard KDFs) ────────────────
		// libsodium password hashing: Argon2id by default, recommended for credential storage (CWE-916).
		{ID: "cpp.libsodium.crypto_pwhash", Language: rules.LangCPP, Pattern: `\bcrypto_pwhash\s*\(`, ObjectType: "", MethodName: "crypto_pwhash", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "libsodium Argon2 password-derived key (memory-hard KDF; safe replacement for raw hashes)"},
		{ID: "cpp.libsodium.crypto_pwhash_str", Language: rules.LangCPP, Pattern: `\bcrypto_pwhash_str\s*\(`, ObjectType: "", MethodName: "crypto_pwhash_str", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "libsodium Argon2id encoded password hash for storage (CWE-916 mitigation)"},
		{ID: "cpp.libsodium.crypto_pwhash_str_verify", Language: rules.LangCPP, Pattern: `\bcrypto_pwhash_str_verify\s*\(`, ObjectType: "", MethodName: "crypto_pwhash_str_verify", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "libsodium constant-time password verification against an encoded Argon2 hash"},
		{ID: "cpp.libsodium.sodium_memcmp", Language: rules.LangCPP, Pattern: `\bsodium_memcmp\s*\(`, ObjectType: "", MethodName: "sodium_memcmp", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "libsodium constant-time memory comparison (timing-safe credential check; replace memcmp on secrets)"},
		// Argon2 reference library (P-H-C). Widely vendored; the canonical Argon2 implementation.
		{ID: "cpp.argon2.argon2id_hash_encoded", Language: rules.LangCPP, Pattern: `\bargon2id_hash_encoded\s*\(`, ObjectType: "", MethodName: "argon2id_hash_encoded", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "P-H-C Argon2id encoded password hash (recommended variant for credential storage)"},
		{ID: "cpp.argon2.argon2id_hash_raw", Language: rules.LangCPP, Pattern: `\bargon2id_hash_raw\s*\(`, ObjectType: "", MethodName: "argon2id_hash_raw", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "P-H-C Argon2id raw key derivation (memory-hard KDF for symmetric key material)"},
		{ID: "cpp.argon2.argon2_verify", Language: rules.LangCPP, Pattern: `\bargon2_verify\s*\(`, ObjectType: "", MethodName: "argon2_verify", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "P-H-C Argon2 encoded-hash verification (constant-time; safe credential check)"},
		// Botan password hashing.
		{ID: "cpp.botan.argon2", Language: rules.LangCPP, Pattern: `Botan::Argon2\s*[(<]`, ObjectType: "Botan", MethodName: "Argon2", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Botan Argon2 password hashing class (memory-hard KDF for credential storage)"},
		{ID: "cpp.botan.bcrypt", Language: rules.LangCPP, Pattern: `Botan::generate_bcrypt\s*\(|Botan::check_bcrypt\s*\(`, ObjectType: "Botan", MethodName: "generate_bcrypt/check_bcrypt", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Botan bcrypt password hash generation/verification"},
		// OpenSSL constant-time comparison (CRYPTO_memcmp is the timing-safe replacement for memcmp on secrets).
		{ID: "cpp.openssl.crypto_memcmp", Language: rules.LangCPP, Pattern: `\bCRYPTO_memcmp\s*\(`, ObjectType: "", MethodName: "CRYPTO_memcmp", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "OpenSSL constant-time memory comparison (timing-safe credential check)"},

		// ── URL encoding ──────────────────────────────────────────────
		{ID: "cpp.curl.escape", Language: rules.LangCPP, Pattern: `curl_easy_escape\s*\(`, ObjectType: "", MethodName: "curl_easy_escape", Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkRedirect, taint.SnkURLFetch}, Description: "libcurl URL encoding (neutralizes CRLF in headers and URLs)"},

		// ── XML safe parsing ──────────────────────────────────────────
		{ID: "cpp.libxml2.disable_entities", Language: rules.LangCPP, Pattern: `xmlSubstituteEntitiesDefault\s*\(\s*0\s*\)`, ObjectType: "libxml2", MethodName: "xmlSubstituteEntitiesDefault(0)", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "Disable XML entity substitution (XXE prevention)"},
		{ID: "cpp.libxml2.nonet", Language: rules.LangCPP, Pattern: `XML_PARSE_NONET`, ObjectType: "libxml2", MethodName: "XML_PARSE_NONET", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "libxml2 NONET flag prevents network access during XML parsing"},

		// NOTE: realpath(3), std::filesystem::canonical/weakly_canonical,
		// std::filesystem::proximate/relative, path::lexically_normal(),
		// boost::filesystem::canonical, and QDir::cleanPath() are
		// intentionally NOT registered as standalone CWE-22 sanitizers
		// (mirrors the filepath.Clean note in go_sanitizers.go and the
		// os.path.normpath/realpath note in python_sanitizers.go).
		// Canonicalization alone does not reject escapes:
		// lexically_normal()/cleanPath() leave "../../etc/passwd" untouched,
		// canonical()/realpath() resolve it to "/etc/passwd" — a real path
		// OUTSIDE the safe base — and relative()/proximate() can return a
		// result that still begins with "..". A complete defence is
		// canonicalize + containment (e.g. canonical(p).string().rfind(base,
		// 0) == 0); the canonicalize step by itself must not kill the taint
		// flow.

		// ── LDAP escaping ────────────────────────────────────────────
		{ID: "cpp.ldap.escape.filter", Language: rules.LangCPP, Pattern: `ldap_simple_escape\s*\(|ldap_filter_escape\s*\(`, ObjectType: "", MethodName: "ldap_simple_escape/ldap_filter_escape", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "LDAP filter escaping prevents LDAP injection"},
		{ID: "cpp.ldap.bv2escaped.filter.value", Language: rules.LangCPP, Pattern: `\bldap_bv2escaped_filter_value(?:_s)?\s*\(`, ObjectType: "", MethodName: "ldap_bv2escaped_filter_value/ldap_bv2escaped_filter_value_s", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "OpenLDAP RFC 4515 filter value escaping (neutralizes LDAP metacharacters)"},

		// ── URL encoding (Boost) ─────────────────────────────────────
		{ID: "cpp.boost.urls.encode", Language: rules.LangCPP, Pattern: `boost::urls::encode\s*\(`, ObjectType: "boost::urls", MethodName: "encode", Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkRedirect, taint.SnkURLFetch}, Description: "Boost.URL percent-encoding (neutralizes CRLF in headers and URLs)"},

		// ── Template auto-escaping ───────────────────────────────────
		{ID: "cpp.inja.autoescape", Language: rules.LangCPP, Pattern: `inja::Environment.*\.set_html_autoescape\s*\(\s*true`, ObjectType: "inja::Environment", MethodName: "set_html_autoescape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "Inja HTML auto-escaping enabled (prevents XSS/template injection)"},

		// --- Regex escaping ---
		{
			ID:          "cpp.regex.escape",
			Language:    rules.LangCPP,
			Pattern:     `boost::regex_replace\s*\(.*boost::regex_constants::format_literal`,
			ObjectType:  "boost",
			MethodName:  "regex_replace (literal)",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Boost regex literal format replacement (safe from ReDoS in replacement)",
		},

		// --- RE2 safe regex (linear-time guarantee, immune to ReDoS) ---
		{
			ID:          "cpp.re2.construct",
			Language:    rules.LangCPP,
			Pattern:     `re2::RE2\s+\w+\s*\(|re2::RE2\s*\(`,
			ObjectType:  "re2",
			MethodName:  "RE2",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Google RE2 regex construction (guaranteed linear-time matching, immune to ReDoS catastrophic backtracking)",
		},
		{
			ID:          "cpp.re2.match",
			Language:    rules.LangCPP,
			Pattern:     `RE2::(?:Full|Partial)Match\s*\(`,
			ObjectType:  "RE2",
			MethodName:  "FullMatch/PartialMatch",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "RE2 safe regex matching functions (linear-time guarantee)",
		},

		// NOTE: std::filesystem::weakly_canonical and proximate/relative
		// deliberately absent — canonicalize-only, see the path
		// canonicalization note near the top of this list.

		// --- Sanitized output ---
		{
			ID:          "cpp.poco.htmlencode",
			Language:    rules.LangCPP,
			Pattern:     `Poco::Net::HTMLForm|Poco::XML::toXMLString`,
			ObjectType:  "Poco",
			MethodName:  "HTMLForm/toXMLString",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "POCO HTML form encoding / XML string escaping",
		},

		// --- Numeric conversion ---
		{
			ID:          "cpp.stod",
			Language:    rules.LangCPP,
			Pattern:     `std::stod\s*\(|std::stof\s*\(|std::stold\s*\(`,
			ObjectType:  "",
			MethodName:  "stod/stof/stold",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkMemory},
			Description: "Floating-point string conversion (restricts to numeric values)",
		},

		// ── ODBC parameterized queries ────────────────────────────────
		{
			ID:          "cpp.odbc.sqlbindparameter",
			Language:    rules.LangCPP,
			Pattern:     `SQLBindParameter\s*\(`,
			ObjectType:  "ODBC",
			MethodName:  "SQLBindParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ODBC parameterized query binding (prevents SQL injection)",
		},

		// ── SOCI parameterized queries ────────────────────────────────
		{
			ID:          "cpp.soci.use",
			Language:    rules.LangCPP,
			Pattern:     `soci::use\s*\(`,
			ObjectType:  "soci",
			MethodName:  "use",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SOCI parameter binding via soci::use() (prevents SQL injection)",
		},

		// ── nanodbc parameterized queries ─────────────────────────────
		{
			ID:          "cpp.nanodbc.statement.bind",
			Language:    rules.LangCPP,
			Pattern:     `nanodbc::statement.*\.bind\s*\(`,
			ObjectType:  "nanodbc::statement",
			MethodName:  "bind",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "nanodbc prepared statement parameter binding (prevents SQL injection)",
		},

		// ── Qt SQL parameterized queries ──────────────────────────────
		{
			ID:          "cpp.qt.qsqlquery.bindvalue",
			Language:    rules.LangCPP,
			Pattern:     `QSqlQuery.*\.(?:bindValue|addBindValue)\s*\(`,
			ObjectType:  "QSqlQuery",
			MethodName:  "bindValue/addBindValue",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Qt SQL parameterized query binding (prevents SQL injection)",
		},

		// ── POCO Data parameterized queries ───────────────────────────
		{
			ID:          "cpp.poco.data.bind",
			Language:    rules.LangCPP,
			Pattern:     `Poco::Data::Keywords::use\s*\(|Poco::Data::Keywords::bind\s*\(`,
			ObjectType:  "Poco::Data",
			MethodName:  "use/bind",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "POCO Data parameterized query binding (prevents SQL injection)",
		},

		// ── libpqxx SQL-escape helpers ────────────────────────────────
		// libpqxx (pqxx::) exposes string-escaping helpers that render
		// user data safe for inclusion in a SQL statement. `esc` escapes a
		// string for use as a SQL string literal; `quote` escapes AND wraps
		// the value in quotes (the two primary, most-used escapers, available
		// on both pqxx::connection and pqxx::transaction_base). `esc_like`
		// escapes LIKE-pattern meta-characters; `quote_name` wraps an
		// identifier in double-quotes and escapes internal quotes. Empty
		// ObjectType follows the sibling entries' convention — idiomatic
		// libpqxx receiver names (`txn`, `tx`, `w`, `conn`) do not prefix-
		// match the type name (`work`/`transaction_base`), so the method
		// name carries the match. Neutralizes only SnkSQLQuery, which bounds
		// any over-match to the SQL-injection category.
		{
			ID:          "cpp.libpqxx.esc",
			Language:    rules.LangCPP,
			Pattern:     `\.esc\s*\(`,
			ObjectType:  "",
			MethodName:  "esc",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "libpqxx esc() escapes a user-supplied string for safe use as a SQL string literal (prevents SQL injection)",
		},
		{
			ID:          "cpp.libpqxx.quote",
			Language:    rules.LangCPP,
			Pattern:     `\.quote\s*\(`,
			ObjectType:  "",
			MethodName:  "quote",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "libpqxx quote() escapes and quotes a user-supplied value for safe inclusion in SQL (prevents SQL injection)",
		},
		{
			ID:          "cpp.libpqxx.esc_like",
			Language:    rules.LangCPP,
			Pattern:     `\.esc_like\s*\(`,
			ObjectType:  "",
			MethodName:  "esc_like",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "libpqxx esc_like() escapes SQL LIKE meta-characters in a user-supplied string",
		},
		{
			ID:          "cpp.libpqxx.quote_name",
			Language:    rules.LangCPP,
			Pattern:     `\.quote_name\s*\(`,
			ObjectType:  "",
			MethodName:  "quote_name",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "libpqxx quote_name() safely quotes a SQL identifier (prevents SQL injection)",
		},

		// ── URL validation (SSRF prevention) ──────────────────────────
		{
			ID:          "cpp.poco.uri.parse",
			Language:    rules.LangCPP,
			Pattern:     `Poco::URI\s*\w+\s*\(`,
			ObjectType:  "Poco::URI",
			MethodName:  "URI",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "POCO URI parsing with validation (helps prevent SSRF when combined with allowlist)",
		},

		// ── Deserialization safety ────────────────────────────────────
		{
			ID:          "cpp.flatbuffers.verifier",
			Language:    rules.LangCPP,
			Pattern:     `flatbuffers::Verifier`,
			ObjectType:  "flatbuffers",
			MethodName:  "Verifier",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "FlatBuffers Verifier validates buffer integrity before access",
		},
		{
			ID:          "cpp.protobuf.parsepartial.check",
			Language:    rules.LangCPP,
			Pattern:     `\.IsInitialized\s*\(\s*\)`,
			ObjectType:  "google::protobuf::Message",
			MethodName:  "IsInitialized",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Protobuf message validation check after deserialization",
		},

		// ── XSS sanitizers (framework-specific) ──────────────────────
		{
			ID:          "cpp.drogon.htmltranslate",
			Language:    rules.LangCPP,
			Pattern:     `HttpViewData::htmlTranslate\s*\(`,
			ObjectType:  "",
			MethodName:  "htmlTranslate",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Drogon HTML entity escaping (prevents XSS)",
		},

		// ── Log injection sanitizers (CWE-117) ───────────────────────
		{
			ID:          "cpp.spdlog.structured",
			Language:    rules.LangCPP,
			Pattern:     `spdlog::(?:info|warn|error|debug|trace|critical)\s*\(\s*"[^"]*\{\}`,
			ObjectType:  "spdlog",
			MethodName:  "structured logging",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "spdlog structured logging with format placeholders (data not in format string position)",
		},
		{
			ID:          "cpp.std.quoted",
			Language:    rules.LangCPP,
			Pattern:     `std::quoted\s*\(`,
			ObjectType:  "std",
			MethodName:  "quoted",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "std::quoted escapes special characters for safe string output",
		},

		// ── Trust boundary sanitizers (CWE-501) ──────────────────────
		{
			ID:          "cpp.allowlist.count",
			Language:    rules.LangCPP,
			Pattern:     `\b(?:allowed|valid|whitelist|safe)\w*\.(?:count|find|contains)\s*\(`,
			ObjectType:  "",
			MethodName:  "allowlist.count/find/contains",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Allowlist validation before session/context storage (prevents trust boundary violation)",
		},
		{
			ID:         "cpp.session.validate",
			Language:   rules.LangCPP,
			Pattern:    `\bvalidate\w*\s*\(|\bsanitize\w*\s*\(`,
			ObjectType: "",
			MethodName: "validate/sanitize",
			// Name-based match (any validate*/sanitize* call), so it must NOT
			// neutralize SQL/command injection — a function named validateLen()
			// or sanitizeRole() carries no guarantee it escapes shell/SQL
			// metacharacters, and claiming so silently drops CWE-78/CWE-89.
			// Limited to the trust-boundary heuristic (CWE-501: "was the value
			// run through a named validation gate before being stored"), which
			// is the conventional, low-impact use this entry exists for.
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Named validation/sanitization gate before a trust-boundary crossing (CWE-501); name-based, so does NOT neutralize SQL/command injection",
		},

		// ── YAML safe loading (CWE-502) ──────────────────────────────
		{
			ID:          "cpp.yamlcpp.safe.nodeAs",
			Language:    rules.LangCPP,
			Pattern:     `\.as<(?:int|double|float|bool|std::string)>\s*\(`,
			ObjectType:  "YAML::Node",
			MethodName:  "as<T>()",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "yaml-cpp typed extraction (constrains to primitive types, prevents object injection)",
		},

		// ── Protobuf input size limiting (CWE-502) ───────────────────
		{
			ID:          "cpp.protobuf.setbyteslimit",
			Language:    rules.LangCPP,
			Pattern:     `SetTotalBytesLimit\s*\(`,
			ObjectType:  "google::protobuf::io::CodedInputStream",
			MethodName:  "SetTotalBytesLimit",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Protobuf CodedInputStream size limit (prevents DoS via oversized messages)",
		},

		// ── CRLF stripping (CWE-117/CWE-113) ────────────────────────
		{
			ID:          "cpp.algorithm.remove.crlf",
			Language:    rules.LangCPP,
			Pattern:     `std::(?:remove|replace)\s*\([^)]*'\\[nr]'`,
			ObjectType:  "std",
			MethodName:  "remove/replace(newline)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "std::remove/replace of newline characters (prevents log forging and header injection)",
		},
		{
			ID:          "cpp.boost.erase.crlf",
			Language:    rules.LangCPP,
			Pattern:     `boost::(?:replace_all|erase_all)\s*\([^)]*"\\[nr]"`,
			ObjectType:  "boost",
			MethodName:  "replace_all/erase_all(newline)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Boost newline removal via replace_all/erase_all (prevents log forging and header injection)",
		},

		// ── SSRF host validation (CWE-918) ───────────────────────────
		{
			ID:          "cpp.boost.asio.ip.address.validate",
			Language:    rules.LangCPP,
			Pattern:     `boost::asio::ip::address::from_string\s*\(|boost::asio::ip::make_address\s*\(`,
			ObjectType:  "boost::asio::ip",
			MethodName:  "from_string/make_address",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Boost.Asio IP address parsing for host validation (SSRF prevention — validates address format before connection)",
		},
		{
			ID:          "cpp.boost.urls.parse_uri",
			Language:    rules.LangCPP,
			Pattern:     `boost::urls::parse_uri\s*\(`,
			ObjectType:  "boost::urls",
			MethodName:  "parse_uri",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Boost.URL strict URI parsing validates scheme, host, and structure (returns error on invalid input — SSRF/redirect prevention)",
		},
		{
			ID:          "cpp.boost.urls.parse_origin_form",
			Language:    rules.LangCPP,
			Pattern:     `boost::urls::parse_origin_form\s*\(`,
			ObjectType:  "boost::urls",
			MethodName:  "parse_origin_form",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Boost.URL origin-form parsing restricts input to path-only URLs per RFC 7230 (prevents external host SSRF)",
		},
		{
			ID:          "cpp.curl.url.set",
			Language:    rules.LangCPP,
			Pattern:     `curl_url_set\s*\(`,
			ObjectType:  "CURLU",
			MethodName:  "curl_url_set",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "libcurl URL API parses and validates URL components — returns error code on invalid URLs (SSRF prevention)",
		},
		{
			ID:          "cpp.curl.url.get",
			Language:    rules.LangCPP,
			Pattern:     `curl_url_get\s*\(`,
			ObjectType:  "CURLU",
			MethodName:  "curl_url_get",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "libcurl URL API extracts validated host/scheme/path components for allowlist checking (SSRF prevention)",
		},
		{
			ID:          "cpp.curl.setopt.protocols",
			Language:    rules.LangCPP,
			Pattern:     `curl_easy_setopt\s*\([^,]+,\s*CURLOPT_(?:REDIR_)?PROTOCOLS(?:_STR)?`,
			ObjectType:  "CURL",
			MethodName:  "curl_easy_setopt(CURLOPT_PROTOCOLS)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "libcurl protocol restriction limits allowed URL schemes (prevents file://, gopher://, dict:// SSRF vectors)",
		},
		{
			ID:          "cpp.qt.qurl.fromuserinput",
			Language:    rules.LangCPP,
			Pattern:     `QUrl::fromUserInput\s*\(`,
			ObjectType:  "QUrl",
			MethodName:  "fromUserInput",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Qt QUrl::fromUserInput normalizes user-supplied URL into structured QUrl for subsequent scheme/host validation",
		},
		// Qt QString::toHtmlEscaped() is the canonical Qt XSS escaper: it
		// converts &, <, >, and " to their HTML entity forms, making the
		// returned string safe to embed in HTML body/attribute context.
		// Receiver-method with no args (ObjectType "" + the Qt-unique method
		// name toHtmlEscaped), so it matches any `str.toHtmlEscaped()`.
		{
			ID:          "cpp.qt.qstring.tohtmlescaped",
			Language:    rules.LangCPP,
			Pattern:     `\.toHtmlEscaped\s*\(`,
			ObjectType:  "",
			MethodName:  "toHtmlEscaped",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Qt QString::toHtmlEscaped() escapes &<>\" to HTML entities (prevents XSS in HTML output)",
		},
		// NOTE: Qt QDir::cleanPath() deliberately absent — lexical
		// normalization only (QDir::cleanPath("../../etc/passwd") is
		// unchanged), see the path canonicalization note near the top of
		// this list.
		// Qt QUrl::toPercentEncoding() percent-encodes a string for safe use
		// in a URL/header context, neutralizing CRLF and URL metacharacters.
		// Parity with boost::urls::encode (cpp.boost.urls.encode).
		{
			ID:          "cpp.qt.qurl.topercentencoding",
			Language:    rules.LangCPP,
			Pattern:     `QUrl::toPercentEncoding\s*\(`,
			ObjectType:  "QUrl",
			MethodName:  "toPercentEncoding",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Qt QUrl::toPercentEncoding() percent-encodes user input (neutralizes CRLF in headers and URL metacharacters)",
		},
		{
			ID:          "cpp.inet_pton.validate",
			Language:    rules.LangCPP,
			Pattern:     `inet_pton\s*\(\s*AF_INET`,
			ObjectType:  "",
			MethodName:  "inet_pton",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "inet_pton parses IP address to binary form for private range validation (blocks SSRF to internal networks)",
		},

		// ── Redis parameterized commands (CWE-943) ───────────────────
		{
			ID:          "cpp.hiredis.command.format",
			Language:    rules.LangCPP,
			Pattern:     `\bredisCommand\s*\([^,]+,\s*"[^"]*%[sb]`,
			ObjectType:  "",
			MethodName:  "redisCommand",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "hiredis parameterized command with format specifiers (%s/%b) — values are escaped, preventing Redis injection",
		},

		// ── Path traversal sanitizers (CWE-22) ───────────────────────
		{
			ID:          "cpp.filesystem.path.filename",
			Language:    rules.LangCPP,
			Pattern:     `\.filename\s*\(\s*\)`,
			ObjectType:  "std::filesystem::path",
			MethodName:  "filename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "std::filesystem::path::filename() extracts just the filename component, stripping directory traversal",
		},
		// NOTE: path::lexically_normal() and boost::filesystem::canonical()
		// deliberately absent — canonicalize-only, see the path
		// canonicalization note near the top of this list.

		// ── Eval / ReDoS sanitizers (CWE-94, CWE-1333) ──────────────
		{
			ID:          "cpp.pcre2.match_limit",
			Language:    rules.LangCPP,
			Pattern:     `pcre2_set_match_limit\s*\(`,
			ObjectType:  "pcre2",
			MethodName:  "pcre2_set_match_limit",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "PCRE2 match limit prevents catastrophic backtracking (ReDoS mitigation)",
		},
		{
			ID:          "cpp.hyperscan.compile",
			Language:    rules.LangCPP,
			Pattern:     `hs_compile(?:_multi|_ext_multi)?\s*\(`,
			ObjectType:  "hs",
			MethodName:  "hs_compile",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Intel Hyperscan automata-based regex compilation (avoids backtracking, ReDoS-resistant)",
		},
		{
			ID:          "cpp.lua.checktype",
			Language:    rules.LangCPP,
			Pattern:     `luaL_check(?:integer|number|string|lstring)\s*\(`,
			ObjectType:  "lua",
			MethodName:  "luaL_check*",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Lua C API type-checking enforces expected argument types (prevents arbitrary code in type position)",
		},
		{
			ID:          "cpp.duktape.require_type",
			Language:    rules.LangCPP,
			Pattern:     `duk_require_(?:int|number|string|boolean)\s*\(`,
			ObjectType:  "duktape",
			MethodName:  "duk_require_*",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Duktape JS engine type-checking enforces expected argument types (prevents code injection)",
		},

		// ── Deserialization sanitizers (CWE-502) ─────────────────────
		{
			ID:          "cpp.capnproto.readeroptions",
			Language:    rules.LangCPP,
			Pattern:     `capnp::ReaderOptions`,
			ObjectType:  "capnp",
			MethodName:  "ReaderOptions",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Cap'n Proto ReaderOptions sets traversal and nesting limits (prevents amplification attacks)",
		},
		{
			ID:          "cpp.nlohmann.json.accept",
			Language:    rules.LangCPP,
			Pattern:     `(?:nlohmann::)?json::accept\s*\(`,
			ObjectType:  "nlohmann::json",
			MethodName:  "accept",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "nlohmann::json::accept() validates JSON syntax without allocating (safe pre-parse gate)",
		},
		{
			ID:          "cpp.thrift.protocol.sizelimit",
			Language:    rules.LangCPP,
			Pattern:     `->set(?:String|Container)SizeLimit\s*\(`,
			ObjectType:  "apache::thrift::protocol",
			MethodName:  "setStringSizeLimit/setContainerSizeLimit",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Apache Thrift protocol size limits prevent DoS via oversized payloads during deserialization",
		},

		// ── Abseil string escape sanitizers (CWE-93 CRLF, CWE-117 log injection, CWE-601 redirect) ──
		// All Abseil escape functions have a return-value form `std::string out = absl::Foo(input);`
		// which is the canonical usage shown in Abseil docs and what tsflow's sanitizer model handles.
		{
			ID:          "cpp.absl.cescape",
			Language:    rules.LangCPP,
			Pattern:     `absl::CEscape\s*\(`,
			ObjectType:  "absl",
			MethodName:  "CEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Abseil CEscape escapes control characters and CRLF (neutralizes log/header injection)",
		},
		{
			ID:          "cpp.absl.utf8safecescape",
			Language:    rules.LangCPP,
			Pattern:     `absl::Utf8SafeCEscape\s*\(`,
			ObjectType:  "absl",
			MethodName:  "Utf8SafeCEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Abseil Utf8SafeCEscape escapes control characters while preserving UTF-8 multi-byte sequences",
		},
		{
			ID:          "cpp.absl.chexescape",
			Language:    rules.LangCPP,
			Pattern:     `absl::CHexEscape\s*\(`,
			ObjectType:  "absl",
			MethodName:  "CHexEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Abseil CHexEscape escapes non-printable bytes as hex (neutralizes log/header injection)",
		},
		{
			ID:          "cpp.absl.base64escape",
			Language:    rules.LangCPP,
			Pattern:     `absl::Base64Escape\s*\(`,
			ObjectType:  "absl",
			MethodName:  "Base64Escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch},
			Description: "Abseil Base64Escape produces URL-/header-safe encoding (alphanumeric + '+/=' only)",
		},
		{
			ID:          "cpp.absl.websafebase64escape",
			Language:    rules.LangCPP,
			Pattern:     `absl::WebSafeBase64Escape\s*\(`,
			ObjectType:  "absl",
			MethodName:  "WebSafeBase64Escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Abseil WebSafeBase64Escape produces URL-safe base64 encoding (uses '-_' instead of '+/')",
		},
		{
			ID:          "cpp.absl.byteshexstring",
			Language:    rules.LangCPP,
			Pattern:     `absl::BytesToHexString\s*\(`,
			ObjectType:  "absl",
			MethodName:  "BytesToHexString",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Abseil BytesToHexString converts bytes to hexadecimal text (neutralizes control chars in logs/headers)",
		},

		// ── cpp-httplib URL/path encoding (CWE-79, CWE-113, CWE-601, CWE-22) ──
		// cpp-httplib (yhirose/cpp-httplib) exposes free-function encoders in the
		// top-level httplib:: namespace that return percent-encoded std::string —
		// canonical return-value sanitizer form `auto safe = httplib::encode_uri(input);`.
		{
			ID:          "cpp.cpphttplib.encode_uri",
			Language:    rules.LangCPP,
			Pattern:     `httplib::encode_uri\s*\(`,
			ObjectType:  "httplib",
			MethodName:  "encode_uri",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "cpp-httplib JavaScript-style encodeURI: percent-encodes reserved characters except URL syntax (neutralizes CRLF in headers/URLs and external host injection in redirects)",
		},
		{
			ID:          "cpp.cpphttplib.encode_uri_component",
			Language:    rules.LangCPP,
			Pattern:     `httplib::encode_uri_component\s*\(`,
			ObjectType:  "httplib",
			MethodName:  "encode_uri_component",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "cpp-httplib encodeURIComponent: strict percent-encoding of all reserved characters including / : ? & = (safe for header, URL fetch, and redirect targets)",
		},
		{
			ID:          "cpp.cpphttplib.encode_query_component",
			Language:    rules.LangCPP,
			Pattern:     `httplib::encode_query_component\s*\(`,
			ObjectType:  "httplib",
			MethodName:  "encode_query_component",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "cpp-httplib RFC 3986 query-component encoder: percent-encodes & = and other delimiters (prevents query parameter and CRLF injection)",
		},
		{
			ID:          "cpp.cpphttplib.encode_path_component",
			Language:    rules.LangCPP,
			Pattern:     `httplib::encode_path_component\s*\(`,
			ObjectType:  "httplib",
			MethodName:  "encode_path_component",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "cpp-httplib RFC 3986 path-component encoder: percent-encodes / and other path-segment delimiters (prevents traversal characters from passing as separators)",
		},
		{
			ID:          "cpp.cpphttplib.sanitize_filename",
			Language:    rules.LangCPP,
			Pattern:     `httplib::sanitize_filename\s*\(`,
			ObjectType:  "httplib",
			MethodName:  "sanitize_filename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "cpp-httplib sanitize_filename returns a path-safe filename with traversal sequences and separators stripped (CWE-22 mitigation)",
		},

		// ── Drogon URL encoding (CWE-79, CWE-113, CWE-601) ────────────
		// Drogon utilities expose return-value URL encoders in drogon::utils namespace.
		{
			ID:          "cpp.drogon.utils.urlencode",
			Language:    rules.LangCPP,
			Pattern:     `drogon::utils::urlEncode\s*\(`,
			ObjectType:  "drogon::utils",
			MethodName:  "urlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Drogon urlEncode percent-encodes reserved characters (neutralizes CRLF in headers and external host injection in redirects/URL fetches)",
		},
		{
			ID:          "cpp.drogon.utils.urlencodecomponent",
			Language:    rules.LangCPP,
			Pattern:     `drogon::utils::urlEncodeComponent\s*\(`,
			ObjectType:  "drogon::utils",
			MethodName:  "urlEncodeComponent",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Drogon urlEncodeComponent strict percent-encoding for individual URL components — encodes path/query/fragment delimiters (CWE-113/CWE-601 mitigation)",
		},

		// ── Crow URL-safe base64 (CWE-113, CWE-601) ───────────────────
		// crow::utility::base64encode_urlsafe returns a base64 string with URL-safe
		// alphabet (- and _ instead of + and /) — safe to embed in URLs/headers.
		{
			ID:          "cpp.crow.utility.base64encode_urlsafe",
			Language:    rules.LangCPP,
			Pattern:     `crow::utility::base64encode_urlsafe\s*\(`,
			ObjectType:  "crow::utility",
			MethodName:  "base64encode_urlsafe",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Crow URL-safe base64 encoding (alphabet: A-Z a-z 0-9 - _) — safe for embedding in URLs and HTTP header values without further escaping",
		},

		// --- CSV (CWE-1236) — formula-prefix escape helpers ---
		{
			ID:          "cpp.csv.escape_formula",
			Language:    rules.LangCPP,
			Pattern:     `\b(?:escapeCsvFormula|sanitizeCsvCell|csvSafeCell|csvEscape|EscapeCsvFormula|SanitizeCsvCell)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeCsvFormula",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Custom escapeCsvFormula / sanitizeCsvCell helper — prefixes a single quote when a field starts with =, +, -, @, TAB (defends CSV-formula injection)",
		},
		{
			ID:          "cpp.rapidcsv.quote_all",
			Language:    rules.LangCPP,
			Pattern:     `SeparatorParams\s*\([^)]*true\s*,\s*true\s*\)`,
			ObjectType:  "rapidcsv::SeparatorParams",
			MethodName:  "SeparatorParams(_,_,quoted=true)",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "rapidcsv SeparatorParams with hasQuotes=true — always quotes every field at write time (combined with formula-prefix escape this defends CSV-formula injection)",
		},

		// ── ReDoS-safe regex (CWE-1333) ──────────────────────────────
		// The SnkRegexDoS sink (cpp.regex.dynamic.pattern) fires when a
		// backtracking std::regex/boost::regex is built from a tainted
		// pattern. RE2 guarantees linear-time matching (no catastrophic
		// backtracking), and RE2::QuoteMeta escapes a user string so it
		// matches literally inside a regex. These neutralize SnkRegexDoS.
		// (The corresponding SnkEval neutralizers already exist separately
		// for the cpp.regex.construct sink.)
		{
			ID:          "cpp.re2.construct.redos",
			Language:    rules.LangCPP,
			Pattern:     `re2::RE2\s+\w+\s*\(|re2::RE2\s*\(`,
			ObjectType:  "re2",
			MethodName:  "RE2",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Google RE2 construction guarantees linear-time matching — immune to catastrophic backtracking (ReDoS) even with attacker-controlled patterns",
		},
		{
			ID:          "cpp.re2.match.redos",
			Language:    rules.LangCPP,
			Pattern:     `RE2::(?:Full|Partial)Match\s*\(`,
			ObjectType:  "RE2",
			MethodName:  "FullMatch/PartialMatch",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "RE2 FullMatch/PartialMatch run in guaranteed linear time (ReDoS-safe)",
		},
		{
			ID:          "cpp.re2.quotemeta",
			Language:    rules.LangCPP,
			Pattern:     `\bRE2::QuoteMeta\s*\(`,
			ObjectType:  "RE2",
			MethodName:  "QuoteMeta",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "RE2::QuoteMeta escapes all regex metacharacters in a user string so it is treated as a literal — neutralizes ReDoS via injected pattern operators",
		},

		// ── NoSQL injection prevention — typed BSON builders (CWE-943) ─
		// The mongocxx / hiredis NoSQL sinks (SnkNoSQL) inject when a user
		// string is interpreted as a query operator ($where, $ne, $gt).
		// Building the filter with typed BSON appenders treats the value
		// strictly as data, never as an operator, neutralizing injection.
		{
			ID:          "cpp.libbson.append_utf8",
			Language:    rules.LangCPP,
			Pattern:     `\bbson_append_utf8\s*\(`,
			ObjectType:  "",
			MethodName:  "bson_append_utf8",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "libbson bson_append_utf8 binds a user string as a typed BSON value (data, not a query operator) — prevents MongoDB operator injection",
		},
		{
			ID:          "cpp.bsoncxx.builder",
			Language:    rules.LangCPP,
			Pattern:     `bsoncxx::builder::(?:basic|stream)`,
			ObjectType:  "bsoncxx::builder",
			MethodName:  "builder::basic/stream",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bsoncxx typed document builder constructs a filter where user values are bound as data (kvp), not as operators — prevents NoSQL injection",
		},

		// ── Wt / Witty output & URL encoding (CWE-79, CWE-113, CWE-601) ─
		// Wt::Utils exposes return-value encoders: htmlEncode escapes HTML
		// metacharacters (XSS), urlEncode percent-encodes for safe inclusion
		// in URLs/headers (CRLF, external host injection).
		{
			ID:          "cpp.wt.utils.htmlencode",
			Language:    rules.LangCPP,
			Pattern:     `Wt::Utils::htmlEncode\s*\(`,
			ObjectType:  "Wt::Utils",
			MethodName:  "htmlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Wt Utils::htmlEncode escapes HTML metacharacters (&, <, >, \") — neutralizes XSS in rendered output",
		},
		{
			ID:          "cpp.wt.utils.urlencode",
			Language:    rules.LangCPP,
			Pattern:     `Wt::Utils::urlEncode\s*\(`,
			ObjectType:  "Wt::Utils",
			MethodName:  "urlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Wt Utils::urlEncode percent-encodes reserved characters (neutralizes CRLF in headers and external host injection in redirects/URL fetches)",
		},
		// CppCMS escaping helpers.
		{ID: "cpp.cppcms.util.escape", Language: rules.LangCPP, Pattern: `(?:cppcms::util|filters)::escape\s*\(`, ObjectType: "cppcms::util", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "CppCMS util::escape / filters::escape converts < > & \" ' to HTML entities (XSS defense)"},
		{ID: "cpp.cppcms.util.urlencode", Language: rules.LangCPP, Pattern: `cppcms::util::urlencode\s*\(`, ObjectType: "cppcms::util", MethodName: "urlencode", Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkURLFetch, taint.SnkRedirect}, Description: "CppCMS util::urlencode percent-encodes reserved characters (neutralizes CRLF in headers and host injection in redirects/URL fetches)"},
	}
}
