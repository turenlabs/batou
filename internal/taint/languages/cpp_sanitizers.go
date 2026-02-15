package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (cppCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// ── Smart pointers (memory safety) ────────────────────────────
		{ID: "cpp.make_unique", Language: rules.LangCPP, Pattern: `std::make_unique\s*<`, ObjectType: "std", MethodName: "make_unique", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::make_unique safe allocation (RAII ownership)"},
		{ID: "cpp.make_shared", Language: rules.LangCPP, Pattern: `std::make_shared\s*<`, ObjectType: "std", MethodName: "make_shared", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::make_shared safe allocation (shared RAII ownership)"},
		{ID: "cpp.unique_ptr.ctor", Language: rules.LangCPP, Pattern: `std::unique_ptr\s*<`, ObjectType: "std", MethodName: "unique_ptr", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::unique_ptr wraps raw pointer with RAII ownership"},
		{ID: "cpp.shared_ptr.ctor", Language: rules.LangCPP, Pattern: `std::shared_ptr\s*<`, ObjectType: "std", MethodName: "shared_ptr", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::shared_ptr wraps raw pointer with shared RAII ownership"},

		// ── Bounds-checked access ─────────────────────────────────────
		{ID: "cpp.container.at", Language: rules.LangCPP, Pattern: `\.at\s*\(`, ObjectType: "container", MethodName: "at", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Bounds-checked container access via .at() (throws on OOB)"},
		{ID: "cpp.container.empty.check", Language: rules.LangCPP, Pattern: `\.empty\s*\(\s*\)`, ObjectType: "container", MethodName: "empty", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Container emptiness check before access"},
		{ID: "cpp.container.size.check", Language: rules.LangCPP, Pattern: `\.size\s*\(\s*\)`, ObjectType: "container", MethodName: "size", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Container size check before access"},

		// ── Safe string operations ────────────────────────────────────
		{ID: "cpp.string.substr", Language: rules.LangCPP, Pattern: `\.substr\s*\(`, ObjectType: "std::string", MethodName: "substr", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::string::substr safe substring extraction"},
		{ID: "cpp.string.find", Language: rules.LangCPP, Pattern: `\.find\s*\(`, ObjectType: "std::string", MethodName: "find", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::string::find validates content before use"},
		{ID: "cpp.strncpy", Language: rules.LangCPP, Pattern: `\bstrncpy\s*\(`, ObjectType: "", MethodName: "strncpy", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Bounded string copy (safer than strcpy)"},
		{ID: "cpp.strncat", Language: rules.LangCPP, Pattern: `\bstrncat\s*\(`, ObjectType: "", MethodName: "strncat", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Bounded string concatenation (safer than strcat)"},
		{ID: "cpp.snprintf.sanitizer", Language: rules.LangCPP, Pattern: `\bsnprintf\s*\(`, ObjectType: "", MethodName: "snprintf", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Bounded snprintf (safer than sprintf)"},
		{ID: "cpp.strlcpy", Language: rules.LangCPP, Pattern: `\bstrlcpy\s*\(`, ObjectType: "", MethodName: "strlcpy", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "BSD safe string copy with guaranteed null termination"},
		{ID: "cpp.strlcat", Language: rules.LangCPP, Pattern: `\bstrlcat\s*\(`, ObjectType: "", MethodName: "strlcat", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "BSD safe string concatenation with guaranteed null termination"},
		{ID: "cpp.memcpy_s", Language: rules.LangCPP, Pattern: `\bmemcpy_s\s*\(`, ObjectType: "", MethodName: "memcpy_s", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "C11 Annex K bounds-checked memcpy"},

		// ── Modern C++ safe types ─────────────────────────────────────
		{ID: "cpp.std.string", Language: rules.LangCPP, Pattern: `std::string\s+\w+`, ObjectType: "std", MethodName: "string", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::string manages memory automatically (vs raw char*)"},
		{ID: "cpp.std.array", Language: rules.LangCPP, Pattern: `std::array\s*<`, ObjectType: "std", MethodName: "array", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::array fixed-size container with bounds info (vs C arrays)"},
		{ID: "cpp.std.vector", Language: rules.LangCPP, Pattern: `std::vector\s*<`, ObjectType: "std", MethodName: "vector", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::vector dynamic container with bounds tracking"},
		{ID: "cpp.std.span", Language: rules.LangCPP, Pattern: `std::span\s*<`, ObjectType: "std", MethodName: "span", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::span (C++20) non-owning view with size (bounds safety)"},
		{ID: "cpp.std.string_view", Language: rules.LangCPP, Pattern: `std::string_view`, ObjectType: "std", MethodName: "string_view", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::string_view non-owning string view (no allocation issues)"},
		{ID: "cpp.gsl.span", Language: rules.LangCPP, Pattern: `gsl::span\s*<`, ObjectType: "gsl", MethodName: "span", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "GSL span for bounds-safe array views"},
		{ID: "cpp.gsl.not_null", Language: rules.LangCPP, Pattern: `gsl::not_null\s*<`, ObjectType: "gsl", MethodName: "not_null", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "GSL not_null wrapper prevents null pointer dereference"},

		// ── Input validation / type coercion ──────────────────────────
		{ID: "cpp.stoi", Language: rules.LangCPP, Pattern: `std::sto[ilfdu]\s*\(`, ObjectType: "std", MethodName: "stoi/stol/stof/stod", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "String to numeric conversion (type coercion/validation)"},

		// ── SQL parameterization ──────────────────────────────────────
		{ID: "cpp.sqlite3.bind", Language: rules.LangCPP, Pattern: `sqlite3_bind_(?:text|int|double|blob|int64)\s*\(`, ObjectType: "sqlite3", MethodName: "sqlite3_bind_*", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "SQLite parameterized query binding"},
		{ID: "cpp.mysql.stmt.bind", Language: rules.LangCPP, Pattern: `mysql_stmt_bind_param\s*\(`, ObjectType: "mysql", MethodName: "mysql_stmt_bind_param", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQL prepared statement parameter binding"},
		{ID: "cpp.sqlite3.mprintf", Language: rules.LangCPP, Pattern: `sqlite3_mprintf\s*\(`, ObjectType: "sqlite3", MethodName: "sqlite3_mprintf", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "SQLite mprintf with %q SQL escaping"},

		// ── HTML encoding / escaping ──────────────────────────────────
		{ID: "cpp.html.escape", Language: rules.LangCPP, Pattern: `(?:html_escape|htmlEncode|escapeHtml|escape_html)\s*\(`, ObjectType: "", MethodName: "html_escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML entity escaping function"},
		{ID: "cpp.crow.mustache", Language: rules.LangCPP, Pattern: `crow::mustache::`, ObjectType: "crow::mustache", MethodName: "mustache", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Crow Mustache template engine (auto-escapes by default)"},

		// ── Path sanitization ─────────────────────────────────────────
		{ID: "cpp.basename", Language: rules.LangCPP, Pattern: `\bbasename\s*\(`, ObjectType: "", MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Strip directory component from path (prevents traversal)"},

		// ── Crypto sanitizers ─────────────────────────────────────────
		{ID: "cpp.openssl.rand.bytes", Language: rules.LangCPP, Pattern: `RAND_bytes\s*\(`, ObjectType: "OpenSSL", MethodName: "RAND_bytes", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "OpenSSL cryptographically secure random bytes"},
		{ID: "cpp.random.device", Language: rules.LangCPP, Pattern: `std::random_device`, ObjectType: "std", MethodName: "random_device", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "std::random_device hardware-based non-deterministic random"},
		{ID: "cpp.openssl.aes.gcm", Language: rules.LangCPP, Pattern: `EVP_aes_(?:128|256)_gcm\s*\(`, ObjectType: "OpenSSL", MethodName: "EVP_aes_*_gcm", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "OpenSSL AES-GCM authenticated encryption"},
		{ID: "cpp.openssl.sha256", Language: rules.LangCPP, Pattern: `SHA256\s*\(|EVP_sha256\s*\(`, ObjectType: "OpenSSL", MethodName: "SHA256", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "SHA-256 secure hash algorithm"},

		// ── URL encoding ──────────────────────────────────────────────
		{ID: "cpp.curl.escape", Language: rules.LangCPP, Pattern: `curl_easy_escape\s*\(`, ObjectType: "CURL", MethodName: "curl_easy_escape", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch}, Description: "libcurl URL encoding"},

		// ── XML safe parsing ──────────────────────────────────────────
		{ID: "cpp.libxml2.disable_entities", Language: rules.LangCPP, Pattern: `xmlSubstituteEntitiesDefault\s*\(\s*0\s*\)`, ObjectType: "libxml2", MethodName: "xmlSubstituteEntitiesDefault(0)", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "Disable XML entity substitution (XXE prevention)"},
		{ID: "cpp.libxml2.nonet", Language: rules.LangCPP, Pattern: `XML_PARSE_NONET`, ObjectType: "libxml2", MethodName: "XML_PARSE_NONET", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "libxml2 NONET flag prevents network access during XML parsing"},

		// ── RAII pattern sanitizer ─────────────────────────────────────
		{ID: "cpp.lock_guard", Language: rules.LangCPP, Pattern: `std::lock_guard\s*<|std::scoped_lock\s*<|std::unique_lock\s*<`, ObjectType: "std", MethodName: "lock_guard/scoped_lock", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "RAII lock guard prevents data races"},

		// ── Path canonicalization ─────────────────────────────────────
		{ID: "cpp.realpath", Language: rules.LangCPP, Pattern: `\brealpath\s*\(`, ObjectType: "", MethodName: "realpath", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "POSIX realpath resolves symlinks and normalizes path (prevents traversal)"},
		{ID: "cpp.std.filesystem.canonical", Language: rules.LangCPP, Pattern: `std::filesystem::canonical\s*\(|std::filesystem::weakly_canonical\s*\(`, ObjectType: "std::filesystem", MethodName: "canonical/weakly_canonical", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "C++17 filesystem canonical path resolution (prevents traversal)"},

		// ── LDAP escaping ────────────────────────────────────────────
		{ID: "cpp.ldap.escape.filter", Language: rules.LangCPP, Pattern: `ldap_simple_escape\s*\(|ldap_filter_escape\s*\(`, ObjectType: "", MethodName: "ldap_simple_escape/ldap_filter_escape", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "LDAP filter escaping prevents LDAP injection"},

		// ── URL encoding (Boost) ─────────────────────────────────────
		{ID: "cpp.boost.urls.encode", Language: rules.LangCPP, Pattern: `boost::urls::encode\s*\(`, ObjectType: "boost::urls", MethodName: "encode", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch}, Description: "Boost.URL percent-encoding for safe URL construction"},

		// ── Numeric clamping ─────────────────────────────────────────
		{ID: "cpp.std.clamp", Language: rules.LangCPP, Pattern: `std::clamp\s*\(`, ObjectType: "std", MethodName: "clamp", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "std::clamp constrains value to safe range (prevents overflow/injection)"},

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

		// --- std::filesystem path sanitization ---
		{
			ID:          "cpp.filesystem.weakly_canonical",
			Language:    rules.LangCPP,
			Pattern:     `std::filesystem::weakly_canonical\s*\(`,
			ObjectType:  "std::filesystem",
			MethodName:  "weakly_canonical",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Filesystem weakly_canonical path resolution (resolves symlinks)",
		},
		{
			ID:          "cpp.filesystem.proximate",
			Language:    rules.LangCPP,
			Pattern:     `std::filesystem::proximate\s*\(|std::filesystem::relative\s*\(`,
			ObjectType:  "std::filesystem",
			MethodName:  "proximate/relative",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Filesystem proximate/relative path computation (safe relative path)",
		},

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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Floating-point string conversion (restricts to numeric values)",
		},
	}
}
