package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *CCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- Input validation / numeric conversion ---
		{
			ID:         "c.validate.strtol",
			Language:   rules.LangC,
			Pattern:    `\bstrtol\s*\(`,
			ObjectType: "",
			MethodName: "strtol",
			// A parsed integer is sound for SQL/command (no injectable chars) and
			// for a memory-copy length/size argument (a checked numeric bound),
			// but NOT for file-write: a tainted integer reaching a file sink is an
			// attacker-controlled index/offset/length, which strtol does not
			// constrain — so SnkFileWrite is dropped.
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkMemory},
			Description: "String to long conversion with error checking (restricts to numeric)",
		},
		{
			ID:         "c.validate.strtoul",
			Language:   rules.LangC,
			Pattern:    `\bstrtoul\s*\(`,
			ObjectType: "",
			MethodName: "strtoul",
			// Same as strtol: numeric result is sound for SQL/command and for a
			// memory-copy size argument, but not for file-write value control, so
			// SnkFileWrite is dropped.
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkMemory},
			Description: "String to unsigned long conversion with error checking",
		},
		{
			ID:          "c.validate.strtod",
			Language:    rules.LangC,
			Pattern:     `\bstrtod\s*\(`,
			ObjectType:  "",
			MethodName:  "strtod",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkMemory},
			Description: "String to double conversion with error checking",
		},
		{
			ID:          "c.validate.atoi",
			Language:    rules.LangC,
			Pattern:     `\batoi\s*\(`,
			ObjectType:  "",
			MethodName:  "atoi",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkMemory},
			Description: "String to integer conversion (restricts to numeric values)",
		},

		// --- Memory clearing ---
		{
			ID:          "c.mem.memset",
			Language:    rules.LangC,
			Pattern:     `\bmemset\s*\(`,
			ObjectType:  "",
			MethodName:  "memset",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Memory clearing for sensitive data erasure",
		},
		{
			ID:          "c.mem.explicit_bzero",
			Language:    rules.LangC,
			Pattern:     `\bexplicit_bzero\s*\(`,
			ObjectType:  "",
			MethodName:  "explicit_bzero",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Guaranteed memory clearing that cannot be optimized away",
		},
		{
			ID:          "c.mem.memset_s",
			Language:    rules.LangC,
			Pattern:     `\bmemset_s\s*\(`,
			ObjectType:  "",
			MethodName:  "memset_s",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "C11 secure memory clearing that cannot be optimized away",
		},

		// --- SQL parameterization ---
		{
			ID:          "c.sql.sqlite3_prepare",
			Language:    rules.LangC,
			Pattern:     `\bsqlite3_prepare\w*\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite prepared statement (parameterized query)",
		},
		{
			ID:          "c.sql.sqlite3_bind",
			Language:    rules.LangC,
			Pattern:     `\bsqlite3_bind_\w+\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_bind_*",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite parameter binding (prevents SQL injection)",
		},
		{
			ID:          "c.sql.mysql_real_escape_string",
			Language:    rules.LangC,
			Pattern:     `\bmysql_real_escape_string\s*\(`,
			ObjectType:  "",
			MethodName:  "mysql_real_escape_string",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MySQL string escaping (prevents SQL injection)",
		},
		{
			ID:          "c.sql.mysql_stmt_prepare",
			Language:    rules.LangC,
			Pattern:     `\bmysql_stmt_prepare\s*\(`,
			ObjectType:  "",
			MethodName:  "mysql_stmt_prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MySQL prepared statement (parameterized query)",
		},
		{
			ID:          "c.sql.pqexecparams",
			Language:    rules.LangC,
			Pattern:     `\bPQexecParams\s*\(`,
			ObjectType:  "",
			MethodName:  "PQexecParams",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL parameterized query (prevents SQL injection)",
		},
		{
			ID:          "c.sql.pqprepare",
			Language:    rules.LangC,
			Pattern:     `\bPQprepare\s*\(`,
			ObjectType:  "",
			MethodName:  "PQprepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL prepared statement (prevents SQL injection)",
		},
		{
			ID:          "c.sql.sqlite3_mprintf",
			Language:    rules.LangC,
			Pattern:     `\bsqlite3_mprintf\s*\(\s*"%q"`,
			ObjectType:  "",
			MethodName:  "sqlite3_mprintf(%q)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite string escaping via %q format (prevents SQL injection)",
		},

		// --- Path validation ---
		{
			ID:          "c.path.basename",
			Language:    rules.LangC,
			Pattern:     `\bbasename\s*\(`,
			ObjectType:  "",
			MethodName:  "basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Extract base filename (strips directory traversal)",
		},
		// NOTE: realpath(3) is intentionally NOT a standalone CWE-22 sanitizer
		// (mirrors the filepath.Clean note in go_sanitizers.go and the
		// os.path.normpath/realpath note in python_sanitizers.go).
		// realpath("../../etc/passwd") resolves to "/etc/passwd" — a real
		// path OUTSIDE the safe base. A complete defence is canonicalize +
		// containment (e.g. strncmp(resolved, base, strlen(base)) == 0); the
		// canonicalize step by itself must not kill the taint flow. The same
		// reasoning removes canonicalize_file_name(3), xmlCanonicPath, and
		// g_canonicalize_filename below.
		{
			ID:          "c.path.mkstemp",
			Language:    rules.LangC,
			Pattern:     `\bmkstemp[s]?\s*\(`,
			ObjectType:  "",
			MethodName:  "mkstemp/mkstemps",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "POSIX safe temporary file creation with unique name (avoids user-controlled paths)",
		},
		{
			ID:          "c.path.mkdtemp",
			Language:    rules.LangC,
			Pattern:     `\bmkdtemp\s*\(`,
			ObjectType:  "",
			MethodName:  "mkdtemp",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "POSIX safe temporary directory creation with unique name (avoids user-controlled paths)",
		},

		// --- Secure cryptography ---
		{
			ID:          "c.crypto.rand_bytes",
			Language:    rules.LangC,
			Pattern:     `RAND_bytes\s*\(`,
			ObjectType:  "",
			MethodName:  "RAND_bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random number generation",
		},
		{
			ID:          "c.crypto.sha256",
			Language:    rules.LangC,
			Pattern:     `\bSHA256\s*\(|\bEVP_sha256\s*\(`,
			ObjectType:  "",
			MethodName:  "SHA256",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-256 strong hash function (safe replacement for MD5/SHA1)",
		},

		// --- XML security ---
		{
			ID:          "c.xml.disable_entities",
			Language:    rules.LangC,
			Pattern:     `xmlSubstituteEntitiesDefault\s*\(\s*0\s*\)`,
			ObjectType:  "",
			MethodName:  "xmlSubstituteEntitiesDefault(0)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Disable XML entity substitution (prevents XXE)",
		},
		{
			ID:          "c.xml.parse_nonet",
			Language:    rules.LangC,
			Pattern:     `XML_PARSE_NONET`,
			ObjectType:  "",
			MethodName:  "XML_PARSE_NONET",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Disable network access during XML parsing (prevents XXE)",
		},
		// libxslt — xsltSetSecurityPrefs configures an xsltSecurityPrefsPtr
		// that forbids file read/write, network I/O, and EXSLT command
		// execution before xsltApplyStylesheet runs. Presence of this call
		// indicates the application has tightened the XSLT trust boundary.
		{
			ID:          "c.libxslt.security_prefs",
			Language:    rules.LangC,
			Pattern:     `xsltSetSecurityPrefs\s*\(`,
			ObjectType:  "",
			MethodName:  "xsltSetSecurityPrefs",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "libxslt security prefs forbid stylesheet file/network/process access",
		},

		// --- LDAP escaping ---
		{
			ID:          "c.ldap.escape",
			Language:    rules.LangC,
			Pattern:     `ldap_simple_escape\s*\(|ldap_filter_escape\s*\(`,
			ObjectType:  "",
			MethodName:  "ldap_filter_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP filter escaping (prevents LDAP injection)",
		},
		{
			ID:          "c.ldap.str2dn",
			Language:    rules.LangC,
			Pattern:     `\bldap_str2dn\s*\(`,
			ObjectType:  "",
			MethodName:  "ldap_str2dn",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "OpenLDAP DN structural validation and parsing (rejects malformed distinguished names)",
		},

		// --- URL escaping ---
		{
			ID:          "c.url.curl_escape",
			Language:    rules.LangC,
			Pattern:     `curl_easy_escape\s*\(`,
			ObjectType:  "",
			MethodName:  "curl_easy_escape",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL encoding via libcurl (prevents SSRF and open redirect)",
		},

		// --- Additional bounds checking ---
		{
			ID:          "c.validate.isdigit",
			Language:    rules.LangC,
			Pattern:     `\bisdigit\s*\(|\bisalpha\s*\(|\bisalnum\s*\(`,
			ObjectType:  "",
			MethodName:  "isdigit/isalpha/isalnum",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Character classification functions (restrict to safe character sets)",
		},

		// NOTE: canonicalize_file_name(3) deliberately absent —
		// canonicalize-only (GNU equivalent of realpath(3)), see the realpath
		// note above.

		// --- Secure hashing ---
		{
			ID:          "c.crypto.sha512",
			Language:    rules.LangC,
			Pattern:     `\bSHA512\s*\(|\bSHA384\s*\(|\bEVP_sha512\s*\(`,
			ObjectType:  "",
			MethodName:  "SHA512/SHA384",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Strong SHA-512/384 hash function usage",
		},

		// --- ODBC parameterized query binding ---
		{
			ID:          "c.sql.odbc.bindparam",
			Language:    rules.LangC,
			Pattern:     `\bSQLBindParameter\s*\(`,
			ObjectType:  "",
			MethodName:  "SQLBindParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ODBC parameterized query binding (prevents SQL injection)",
		},

		// --- PCRE2 regex validation ---
		{
			ID:          "c.validate.pcre2_match",
			Language:    rules.LangC,
			Pattern:     `\bpcre2_match\s*\(`,
			ObjectType:  "",
			MethodName:  "pcre2_match",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "PCRE2 regex matching for input validation (allowlist enforcement)",
		},

		// --- POSIX regex validation ---
		{
			ID:          "c.validate.regexec",
			Language:    rules.LangC,
			Pattern:     `\bregexec\s*\(`,
			ObjectType:  "",
			MethodName:  "regexec",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "POSIX regex matching for input validation (allowlist enforcement)",
		},

		// --- Secure DNS resolution ---
		{
			ID:          "c.validate.inet_pton",
			Language:    rules.LangC,
			Pattern:     `\binet_pton\s*\(`,
			ObjectType:  "",
			MethodName:  "inet_pton",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address parsing and validation (restricts to valid IP format)",
		},

		// --- Encoding (GLib) ---
		{
			ID:          "c.encoding.glib_base64_encode",
			Language:    rules.LangC,
			Pattern:     `\bg_base64_encode\s*\(`,
			ObjectType:  "",
			MethodName:  "g_base64_encode",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileRead, taint.SnkFileWrite, taint.SnkHeader, taint.SnkLog},
			Description: "GLib base64 encoding produces alphanumeric+/= output safe for injection contexts",
		},

		// --- HTML/XML escaping (libxml2, GLib) ---
		{
			ID:          "c.xml.encode_special_chars",
			Language:    rules.LangC,
			Pattern:     `\bxmlEncodeSpecialChars\s*\(`,
			ObjectType:  "",
			MethodName:  "xmlEncodeSpecialChars",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkXPath},
			Description: "libxml2 XML/HTML entity encoding (escapes <, >, &, etc.)",
		},
		{
			ID:          "c.glib.markup_escape",
			Language:    rules.LangC,
			Pattern:     `\bg_markup_escape_text\s*\(`,
			ObjectType:  "",
			MethodName:  "g_markup_escape_text",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkXPath},
			Description: "GLib markup escaping (escapes <, >, &, \", ' for safe XML/HTML output)",
		},

		// --- Command injection escaping (GLib) ---
		{
			ID:          "c.glib.shell_quote",
			Language:    rules.LangC,
			Pattern:     `\bg_shell_quote\s*\(`,
			ObjectType:  "",
			MethodName:  "g_shell_quote",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "GLib shell argument quoting (prevents shell injection via /bin/sh)",
		},

		// --- URL/SSRF escaping (GLib) ---
		{
			ID:          "c.glib.uri_escape",
			Language:    rules.LangC,
			Pattern:     `\bg_uri_escape_string\s*\(`,
			ObjectType:  "",
			MethodName:  "g_uri_escape_string",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "GLib URI percent-encoding (prevents SSRF and open redirect)",
		},

		// --- URL/HTML escaping (libevent / evhttp) ---
		// libevent's evhttp helpers return a freshly allocated escaped string
		// with the tainted input as the first argument, so they fit the
		// walker's args[0] return-value sanitizer model. evhttp request URIs
		// are already modeled as a source (c.net.evhttp_uri); these close the
		// output-encoding side of the same library.
		{
			ID:          "c.evhttp.encode_uri",
			Language:    rules.LangC,
			Pattern:     `\bevhttp_encode_uri\s*\(`,
			ObjectType:  "",
			MethodName:  "evhttp_encode_uri",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "libevent URI percent-encoding (prevents SSRF and open redirect)",
		},
		{
			ID:          "c.evhttp.uriencode",
			Language:    rules.LangC,
			Pattern:     `\bevhttp_uriencode\s*\(`,
			ObjectType:  "",
			MethodName:  "evhttp_uriencode",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "libevent length-aware URI percent-encoding (prevents SSRF and open redirect)",
		},
		{
			ID:          "c.evhttp.htmlescape",
			Language:    rules.LangC,
			Pattern:     `\bevhttp_htmlescape\s*\(`,
			ObjectType:  "",
			MethodName:  "evhttp_htmlescape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "libevent HTML entity escaping of <, >, \", ', & (prevents XSS)",
		},

		// --- PostgreSQL escaping (libpq) ---
		{
			ID:          "c.sql.pqescapeliteral",
			Language:    rules.LangC,
			Pattern:     `\bPQescapeLiteral\s*\(`,
			ObjectType:  "",
			MethodName:  "PQescapeLiteral",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL SQL literal escaping with quoting (prevents SQL injection)",
		},
		{
			ID:          "c.sql.pqescapeidentifier",
			Language:    rules.LangC,
			Pattern:     `\bPQescapeIdentifier\s*\(`,
			ObjectType:  "",
			MethodName:  "PQescapeIdentifier",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL SQL identifier escaping (prevents SQL injection in table/column names)",
		},
		{
			ID:          "c.sql.pqescapestringconn",
			Language:    rules.LangC,
			Pattern:     `\bPQescapeStringConn\s*\(`,
			ObjectType:  "",
			MethodName:  "PQescapeStringConn",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL connection-aware string escaping (prevents SQL injection)",
		},

		// --- MySQL parameter binding ---
		{
			ID:          "c.sql.mysql_stmt_bind",
			Language:    rules.LangC,
			Pattern:     `\bmysql_stmt_bind_param\s*\(`,
			ObjectType:  "",
			MethodName:  "mysql_stmt_bind_param",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MySQL prepared statement parameter binding (prevents SQL injection)",
		},

		// --- OpenSSL cryptographic primitives ---
		{
			ID:          "c.crypto.hmac",
			Language:    rules.LangC,
			Pattern:     `\bHMAC\s*\(`,
			ObjectType:  "",
			MethodName:  "HMAC",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenSSL HMAC message authentication code (secure integrity verification)",
		},
		{
			ID:          "c.crypto.evp_aes_gcm",
			Language:    rules.LangC,
			Pattern:     `\bEVP_aes_\d+_gcm\s*\(`,
			ObjectType:  "",
			MethodName:  "EVP_aes_*_gcm",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenSSL AES-GCM authenticated encryption (safe replacement for insecure ciphers)",
		},
		{
			ID:          "c.crypto.evp_sha3",
			Language:    rules.LangC,
			Pattern:     `\bEVP_sha3_\d+\s*\(`,
			ObjectType:  "",
			MethodName:  "EVP_sha3_*",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenSSL SHA-3 hash family (safe replacement for MD5/SHA1)",
		},
		{
			ID:          "c.crypto.evp_chacha20_poly1305",
			Language:    rules.LangC,
			Pattern:     `\bEVP_chacha20_poly1305\s*\(`,
			ObjectType:  "",
			MethodName:  "EVP_chacha20_poly1305",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "ChaCha20-Poly1305 AEAD cipher (modern, safe replacement for RC4/DES/Blowfish)",
		},
		{
			ID:          "c.crypto.getrandom",
			Language:    rules.LangC,
			Pattern:     `\bgetrandom\s*\(`,
			ObjectType:  "",
			MethodName:  "getrandom",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Linux cryptographically secure random number generation (safe replacement for rand/random/drand48)",
		},
		{
			ID:          "c.crypto.getentropy",
			Language:    rules.LangC,
			Pattern:     `\bgetentropy\s*\(`,
			ObjectType:  "",
			MethodName:  "getentropy",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "POSIX cryptographically secure entropy source (safe replacement for rand/random/drand48)",
		},
		{
			ID:          "c.crypto.pbkdf2",
			Language:    rules.LangC,
			Pattern:     `\bPKCS5_PBKDF2_HMAC\s*\(`,
			ObjectType:  "",
			MethodName:  "PKCS5_PBKDF2_HMAC",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 key derivation with configurable iterations (safe replacement for EVP_BytesToKey)",
		},
		{
			ID:          "c.crypto.evp_aes_cbc",
			Language:    rules.LangC,
			Pattern:     `\bEVP_aes_(?:128|192|256)_cbc\s*\(`,
			ObjectType:  "",
			MethodName:  "EVP_aes_*_cbc",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "AES-CBC encryption (acceptable block cipher, prefer AES-GCM for authenticated encryption)",
		},

		// --- libcurl SSRF protocol restriction ---
		{
			ID:          "c.curl.protocols",
			Language:    rules.LangC,
			Pattern:     `\bCURLOPT_PROTOCOLS\b`,
			ObjectType:  "",
			MethodName:  "CURLOPT_PROTOCOLS",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "libcurl protocol restriction (limits allowed URL schemes to prevent SSRF)",
		},
		{
			// curl 7.85+ string form: curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR,
			// "https"). The integer-bitmask CURLOPT_PROTOCOLS option above does
			// NOT cover this enum (the `\b` after PROTOCOLS does not match the
			// `_STR` suffix — `S` and `_` are both word characters). Restricting
			// the scheme set kills file://, gopher://, dict:// and other
			// SSRF-amplifying schemes just like the bitmask form, so it is the
			// same mitigation and must neutralize the same SnkURLFetch flows.
			// Anchored on the literal enum constant — the same no-new-match-surface
			// technique as the existing CURLOPT_PROTOCOLS sanitizer; it only
			// suppresses real mitigation sites.
			ID:          "c.curl.protocols_str",
			Language:    rules.LangC,
			Pattern:     `\bCURLOPT_PROTOCOLS_STR\b`,
			ObjectType:  "",
			MethodName:  "CURLOPT_PROTOCOLS_STR",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "libcurl protocol restriction (string form, curl 7.85+) — limits allowed URL schemes to prevent SSRF",
		},
		{
			// CURLOPT_REDIR_PROTOCOLS / CURLOPT_REDIR_PROTOCOLS_STR restrict which
			// schemes libcurl will FOLLOW on an HTTP redirect. Without it, an
			// allowed https:// initial fetch can be redirected to file:// or
			// gopher:// (the classic SSRF-via-redirect bypass), so setting it is a
			// genuine SSRF mitigation for the redirect leg. One pattern matches
			// both the bitmask and string enum names (the `_STR` suffix is
			// optional in the alternation). Literal-enum anchored — no new match
			// surface, suppression only.
			ID:          "c.curl.redir_protocols",
			Language:    rules.LangC,
			Pattern:     `\bCURLOPT_REDIR_PROTOCOLS(?:_STR)?\b`,
			ObjectType:  "",
			MethodName:  "CURLOPT_REDIR_PROTOCOLS",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "libcurl redirect-protocol restriction — limits schemes followed across redirects (prevents SSRF-via-redirect to file://, gopher://, etc.)",
		},

		// --- Log injection sanitizers (CWE-117) ---
		{
			ID:          "c.log.sd_journal",
			Language:    rules.LangC,
			Pattern:     `\bsd_journal_(?:send|print|printv)\s*\(`,
			ObjectType:  "",
			MethodName:  "sd_journal_send",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "systemd structured journal logging with key=value pairs (immune to log injection)",
		},
		{
			ID:          "c.log.glib_structured",
			Language:    rules.LangC,
			Pattern:     `\bg_log_structured\s*\(`,
			ObjectType:  "",
			MethodName:  "g_log_structured",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "GLib structured logging API with typed fields (prevents log forging)",
		},
		{
			ID:          "c.log.crlf_strpbrk",
			Language:    rules.LangC,
			Pattern:     `strpbrk\s*\([^)]+,\s*"[^"]*\\[rn]`,
			ObjectType:  "",
			MethodName:  "strpbrk (CRLF check)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "CRLF character detection via strpbrk before logging or header output",
		},

		// --- Header injection sanitizers (CWE-113) ---
		{
			ID:          "c.header.json_encode",
			Language:    rules.LangC,
			Pattern:     `\bjson_object_new_string\s*\(|\bjson_pack\s*\(`,
			ObjectType:  "",
			MethodName:  "json_object_new_string / json_pack",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "JSON string encoding via json-c or jansson (escapes control characters)",
		},

		// --- Trust boundary sanitizers (CWE-501) ---
		{
			ID:          "c.trust.clearenv",
			Language:    rules.LangC,
			Pattern:     `\bclearenv\s*\(`,
			ObjectType:  "",
			MethodName:  "clearenv",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Clear entire environment before selectively setting known-good variables",
		},
		{
			ID:          "c.trust.secure_getenv",
			Language:    rules.LangC,
			Pattern:     `\bsecure_getenv\s*\(`,
			ObjectType:  "",
			MethodName:  "secure_getenv",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "GNU secure_getenv returns NULL under elevated privileges (suid/sgid safety)",
		},

		// --- Deserialization sanitizers (CWE-502) ---
		{
			ID:          "c.deser.xml_schema_validate",
			Language:    rules.LangC,
			Pattern:     `\bxmlSchemaValidateDoc\s*\(`,
			ObjectType:  "",
			MethodName:  "xmlSchemaValidateDoc",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "libxml2 XML Schema (XSD) validation ensures parsed document conforms to expected structure",
		},
		{
			ID:          "c.deser.xml_relaxng_validate",
			Language:    rules.LangC,
			Pattern:     `\bxmlRelaxNGValidateDoc\s*\(`,
			ObjectType:  "",
			MethodName:  "xmlRelaxNGValidateDoc",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "libxml2 RelaxNG validation ensures parsed document conforms to expected schema",
		},
		{
			ID:          "c.deser.xml_validate_dtd",
			Language:    rules.LangC,
			Pattern:     `\bxmlValidateDtd\s*\(`,
			ObjectType:  "",
			MethodName:  "xmlValidateDtd",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "libxml2 DTD validation ensures parsed document conforms to expected structure",
		},
		{
			ID:          "c.deser.jansson_unpack_ex",
			Language:    rules.LangC,
			Pattern:     `\bjson_unpack_ex\s*\(`,
			ObjectType:  "",
			MethodName:  "json_unpack_ex",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Jansson strict format unpacking validates JSON structure against expected format string",
		},

		// --- Eval / dynamic loading sanitizers (CWE-829, CWE-1333) ---
		{
			ID:          "c.eval.pcre2_jit",
			Language:    rules.LangC,
			Pattern:     `\bpcre2_jit_compile\s*\(`,
			ObjectType:  "",
			MethodName:  "pcre2_jit_compile",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "PCRE2 JIT compilation enables built-in backtrack limits (mitigates ReDoS)",
		},
		{
			ID:          "c.eval.pcre2_match_limit",
			Language:    rules.LangC,
			Pattern:     `\bpcre2_set_match_limit\s*\(`,
			ObjectType:  "",
			MethodName:  "pcre2_set_match_limit",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "PCRE2 explicit match limit prevents catastrophic backtracking (ReDoS mitigation)",
		},
		{
			ID:          "c.glib.regex_escape",
			Language:    rules.LangC,
			Pattern:     `\bg_regex_escape_string\s*\(`,
			ObjectType:  "",
			MethodName:  "g_regex_escape_string",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "GLib g_regex_escape_string escapes all regex metacharacters so a tainted pattern becomes a literal substring in g_regex_new/GRegex (prevents ReDoS catastrophic backtracking and regex-pattern injection, CWE-1333)",
		},

		// --- Deserialization sanitizers: XXE prevention (CWE-611) ---
		{
			ID:          "c.deser.expat_entity_decl_handler",
			Language:    rules.LangC,
			Pattern:     `\bXML_SetEntityDeclHandler\s*\(`,
			ObjectType:  "",
			MethodName:  "XML_SetEntityDeclHandler",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkXPath},
			Description: "Expat entity declaration handler enables rejection of DTD entity declarations (XXE prevention)",
		},
		{
			ID:          "c.deser.expat_external_entity_handler",
			Language:    rules.LangC,
			Pattern:     `\bXML_SetExternalEntityRefHandler\s*\(`,
			ObjectType:  "",
			MethodName:  "XML_SetExternalEntityRefHandler",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkXPath},
			Description: "Expat external entity ref handler enables blocking of external entity resolution (XXE prevention)",
		},

		// --- Deserialization sanitizers: bounded JSON parsing ---
		{
			ID:          "c.deser.cjson_parsewithlen",
			Language:    rules.LangC,
			Pattern:     `\bcJSON_ParseWithLength\s*\(`,
			ObjectType:  "",
			MethodName:  "cJSON_ParseWithLength",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "cJSON bounded-length parse prevents unbounded input consumption",
		},
		{
			ID:          "c.deser.json_tokener_set_flags",
			Language:    rules.LangC,
			Pattern:     `\bjson_tokener_set_flags\s*\(`,
			ObjectType:  "",
			MethodName:  "json_tokener_set_flags",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "json-c tokener flags enable strict parsing mode (rejects non-standard JSON)",
		},

		// --- LDAP sanitizer (CWE-90) ---
		{
			ID:          "c.ldap.bv2escaped",
			Language:    rules.LangC,
			Pattern:     `\bldap_bv2escaped_filter_value\s*\(`,
			ObjectType:  "",
			MethodName:  "ldap_bv2escaped_filter_value",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "OpenLDAP filter value escaping per RFC 4515 (prevents LDAP injection)",
		},

		// --- URL encoding sanitizer (CWE-918) ---
		{
			ID:          "c.url.mg_url_encode",
			Language:    rules.LangC,
			Pattern:     `\bmg_url_encode\s*\(`,
			ObjectType:  "",
			MethodName:  "mg_url_encode",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Mongoose URL encoding sanitizes user input for safe URL construction",
		},

		// --- hiredis parameterized format sanitizers (CWE-943) ---
		// hiredis treats the format string specially: %s sends a NUL-terminated
		// C string as a bulk string, %b sends a binary-safe buffer. Values
		// passed as varargs under a literal format string are NOT interpreted
		// as Redis commands, so the format becomes the trust boundary.
		{
			ID:          "c.hiredis.redisCommand.format",
			Language:    rules.LangC,
			Pattern:     `\bredisCommand\s*\([^,]+,\s*"[^"]*%[sb]`,
			ObjectType:  "",
			MethodName:  "redisCommand",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "hiredis redisCommand with literal format string and %s/%b specifiers (values sent as binary-safe bulk strings, preventing Redis injection)",
		},
		{
			ID:          "c.hiredis.redisAppendCommand.format",
			Language:    rules.LangC,
			Pattern:     `\bredisAppendCommand\s*\([^,]+,\s*"[^"]*%[sb]`,
			ObjectType:  "",
			MethodName:  "redisAppendCommand",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "hiredis redisAppendCommand with literal format string and %s/%b specifiers (values sent as binary-safe bulk strings, preventing Redis injection)",
		},

		// --- libcouchbase parameterized-binding sanitizers (CWE-943) ---
		// Couchbase N1QL/Analytics support named ($name) and positional ($1) parameters.
		// Values bound via these APIs are JSON-encoded and never concatenated into the
		// statement text, so user input passed through them cannot break the query.
		{
			ID:          "c.couchbase.lcb_cmdquery_named_param",
			Language:    rules.LangC,
			Pattern:     `\blcb_cmdquery_named_param\s*\(`,
			ObjectType:  "",
			MethodName:  "lcb_cmdquery_named_param",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "libcouchbase v3 N1QL named parameter binding (values are JSON-encoded, preventing N1QL injection)",
		},
		{
			ID:          "c.couchbase.lcb_cmdquery_positional_param",
			Language:    rules.LangC,
			Pattern:     `\blcb_cmdquery_positional_param\s*\(`,
			ObjectType:  "",
			MethodName:  "lcb_cmdquery_positional_param",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "libcouchbase v3 N1QL positional parameter binding (values are JSON-encoded, preventing N1QL injection)",
		},
		{
			ID:          "c.couchbase.lcb_cmdanalytics_named_param",
			Language:    rules.LangC,
			Pattern:     `\blcb_cmdanalytics_named_param\s*\(`,
			ObjectType:  "",
			MethodName:  "lcb_cmdanalytics_named_param",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "libcouchbase v3 Analytics named parameter binding (values are JSON-encoded, preventing SQL++ injection)",
		},
		{
			ID:          "c.couchbase.lcb_cmdanalytics_positional_param",
			Language:    rules.LangC,
			Pattern:     `\blcb_cmdanalytics_positional_param\s*\(`,
			ObjectType:  "",
			MethodName:  "lcb_cmdanalytics_positional_param",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "libcouchbase v3 Analytics positional parameter binding (values are JSON-encoded, preventing SQL++ injection)",
		},

		// --- NoSQL injection neutralizers (CWE-943) ---
		// The MongoDB (libmongoc/libbson) and Redis (hiredis) sinks in
		// c_sinks.go are SnkNoSQL but previously had no neutralizing entry.
		// Building the query/command with typed BSON appenders or binary-safe
		// argv/format placeholders means user input is inserted as a value, not
		// reinterpreted as a query operator ($where/$gt/...) or a Redis verb.
		{
			ID:          "c.nosql.bson_append_utf8",
			Language:    rules.LangC,
			Pattern:     `\bbson_append_utf8\s*\(`,
			ObjectType:  "",
			MethodName:  "bson_append_utf8",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "libbson typed UTF-8 value append — tainted input becomes a BSON string value, not a MongoDB query operator (prevents NoSQL operator injection)",
		},
		{
			ID:          "c.nosql.bcon_utf8",
			Language:    rules.LangC,
			Pattern:     `\bBCON_UTF8\b`,
			ObjectType:  "",
			MethodName:  "BCON_UTF8",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "libbson BCON_UTF8 builder macro — wraps user input as a typed string value in a BCON document (prevents MongoDB operator injection)",
		},
		{
			ID:          "c.nosql.hiredis_argv",
			Language:    rules.LangC,
			Pattern:     `\bredisCommandArgv\s*\(`,
			ObjectType:  "",
			MethodName:  "redisCommandArgv",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "hiredis argv form — each argument is sent as a separate binary-safe bulk string, so user input cannot be reinterpreted as a Redis command (prevents Redis injection)",
		},
		{
			ID:          "c.nosql.hiredis_format",
			Language:    rules.LangC,
			Pattern:     `\bredisCommand\s*\([^,]+,\s*"[^"]*%[sb]`,
			ObjectType:  "",
			MethodName:  "redisCommand(%s/%b)",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "hiredis redisCommand with a literal format string and %s/%b specifiers — values are sent as binary-safe bulk strings, preventing Redis command injection",
		},

		// --- Modern password hashing (memory-hard KDFs) — CWE-916 mitigation ---
		// libsodium password hashing (Argon2id by default; recommended for credential storage).
		{
			ID:          "c.libsodium.crypto_pwhash",
			Language:    rules.LangC,
			Pattern:     `\bcrypto_pwhash\s*\(`,
			ObjectType:  "",
			MethodName:  "crypto_pwhash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium Argon2 password-derived key (memory-hard KDF; safe replacement for raw hashes)",
		},
		{
			ID:          "c.libsodium.crypto_pwhash_str",
			Language:    rules.LangC,
			Pattern:     `\bcrypto_pwhash_str\s*\(`,
			ObjectType:  "",
			MethodName:  "crypto_pwhash_str",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium Argon2id encoded password hash for storage (CWE-916 mitigation)",
		},
		{
			ID:          "c.libsodium.crypto_pwhash_str_verify",
			Language:    rules.LangC,
			Pattern:     `\bcrypto_pwhash_str_verify\s*\(`,
			ObjectType:  "",
			MethodName:  "crypto_pwhash_str_verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium constant-time password verification against an encoded Argon2 hash",
		},
		// Argon2 reference library (P-H-C); the canonical Argon2 implementation, widely vendored.
		{
			ID:          "c.argon2.argon2id_hash_encoded",
			Language:    rules.LangC,
			Pattern:     `\bargon2id_hash_encoded\s*\(`,
			ObjectType:  "",
			MethodName:  "argon2id_hash_encoded",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "P-H-C Argon2id encoded password hash (recommended variant for credential storage)",
		},
		{
			ID:          "c.argon2.argon2id_hash_raw",
			Language:    rules.LangC,
			Pattern:     `\bargon2id_hash_raw\s*\(`,
			ObjectType:  "",
			MethodName:  "argon2id_hash_raw",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "P-H-C Argon2id raw key derivation (memory-hard KDF for symmetric key material)",
		},
		{
			ID:          "c.argon2.argon2_verify",
			Language:    rules.LangC,
			Pattern:     `\bargon2_verify\s*\(`,
			ObjectType:  "",
			MethodName:  "argon2_verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "P-H-C Argon2 encoded-hash verification (constant-time; safe credential check)",
		},
		// libxcrypt (POSIX crypt(3) replacement): bcrypt/yescrypt/scrypt password hashing.
		{
			ID:          "c.libxcrypt.crypt_r",
			Language:    rules.LangC,
			Pattern:     `\bcrypt_r\s*\(`,
			ObjectType:  "",
			MethodName:  "crypt_r",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "POSIX crypt_r (libxcrypt) — bcrypt/yescrypt/scrypt password hashing for credential storage",
		},

		// --- Constant-time comparison (CWE-208 timing-attack mitigation) ---
		// Use these instead of memcmp() when comparing secrets, MACs, tokens, password hashes.
		{
			ID:          "c.libsodium.sodium_memcmp",
			Language:    rules.LangC,
			Pattern:     `\bsodium_memcmp\s*\(`,
			ObjectType:  "",
			MethodName:  "sodium_memcmp",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "libsodium constant-time memory comparison (timing-safe credential check; replace memcmp on secrets)",
		},
		{
			ID:          "c.openssl.crypto_memcmp",
			Language:    rules.LangC,
			Pattern:     `\bCRYPTO_memcmp\s*\(`,
			ObjectType:  "",
			MethodName:  "CRYPTO_memcmp",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenSSL constant-time memory comparison (timing-safe credential check)",
		},
		{
			ID:          "c.bsd.timingsafe_bcmp",
			Language:    rules.LangC,
			Pattern:     `\btimingsafe_bcmp\s*\(`,
			ObjectType:  "",
			MethodName:  "timingsafe_bcmp",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenBSD/macOS timingsafe_bcmp — constant-time bcmp for secret comparison",
		},
		{
			ID:          "c.bsd.timingsafe_memcmp",
			Language:    rules.LangC,
			Pattern:     `\btimingsafe_memcmp\s*\(`,
			ObjectType:  "",
			MethodName:  "timingsafe_memcmp",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "OpenBSD/macOS timingsafe_memcmp — constant-time memcmp for secret comparison",
		},

		// --- Return-value escape/encode sanitizers (args[0] = tainted input) ---
		// These take the tainted input as the FIRST argument and return the
		// pool-/heap-allocated escaped string. The tsflow walker only checks
		// args[0] for taint when applying Neutralizes, so functions whose
		// canonical signature places the tainted input later (e.g. APR's
		// `apr_pescape_*(pool, str)`) cannot be expressed as sanitizers here.
		{
			ID:          "c.glib.strescape",
			Language:    rules.LangC,
			Pattern:     `\bg_strescape\s*\(`,
			ObjectType:  "",
			MethodName:  "g_strescape",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "GLib g_strescape — escapes \\b \\f \\n \\r \\t \\v \\ \" and 0x01-0x1F, 0x7F-0xFF as octal; safe for log/printable contexts (defeats log-injection CRLF and terminal escape sequences)",
		},
		{
			ID:          "c.openssl.buf2hexstr",
			Language:    rules.LangC,
			Pattern:     `\bOPENSSL_buf2hexstr\s*\(`,
			ObjectType:  "",
			MethodName:  "OPENSSL_buf2hexstr",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "OpenSSL OPENSSL_buf2hexstr — converts arbitrary bytes to colon-separated hex; output is [0-9A-F:] only, safe for log lines and HTTP headers",
		},
		{
			ID:          "c.libxml2.uri_escape",
			Language:    rules.LangC,
			Pattern:     `\bxmlURIEscape\s*\(`,
			ObjectType:  "",
			MethodName:  "xmlURIEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHeader},
			Description: "libxml2 xmlURIEscape — RFC 3986 URI percent-escape; output is safe for use in URLs, Location: redirects, and HTTP header values",
		},
		{
			ID:          "c.libxml2.uri_escape_str",
			Language:    rules.LangC,
			Pattern:     `\bxmlURIEscapeStr\s*\(`,
			ObjectType:  "",
			MethodName:  "xmlURIEscapeStr",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHeader},
			Description: "libxml2 xmlURIEscapeStr — RFC 3986 URI percent-escape with caller-supplied retain list; safe for URL/redirect/header contexts",
		},
		// --- Basename helpers (path-traversal neutralizers) ---
		// g_path_get_basename / apr_filepath_name_get strip directory
		// prefixes (return-value sanitizer model — the result cannot name a
		// directory outside the base).
		//
		// NOTE: xmlCanonicPath and g_canonicalize_filename deliberately
		// absent — canonicalize-only. xmlCanonicPath percent-escapes non-URI
		// chars but "../" survives untouched, and g_canonicalize_filename
		// resolves ".." AGAINST the base dir, happily returning a path
		// outside it ("/etc/passwd"). See the realpath note above.
		{
			ID:          "c.glib.path_get_basename",
			Language:    rules.LangC,
			Pattern:     `\bg_path_get_basename\s*\(`,
			ObjectType:  "",
			MethodName:  "g_path_get_basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "GLib g_path_get_basename — extracts the last path component, stripping directory traversal prefixes; safe for file-path sinks",
		},
		{
			ID:          "c.apr.filepath_name_get",
			Language:    rules.LangC,
			Pattern:     `\bapr_filepath_name_get\s*\(`,
			ObjectType:  "",
			MethodName:  "apr_filepath_name_get",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Apache Portable Runtime apr_filepath_name_get — returns the final path component (basename); strips directory-traversal prefixes for file-path sinks",
		},
		// --- libsoup URI encoding (URL/SSRF/redirect/header neutralizer) ---
		{
			ID:          "c.soup.uri_encode",
			Language:    rules.LangC,
			Pattern:     `\bsoup_uri_encode\s*\(`,
			ObjectType:  "",
			MethodName:  "soup_uri_encode",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHeader},
			Description: "libsoup soup_uri_encode — RFC 3986 percent-encodes a URI part with an optional extra-escape set; safe for URL/redirect/header contexts",
		},

		// --- CSV (CWE-1236) — formula-prefix escape helpers ---
		{
			ID:          "c.csv.escape_formula",
			Language:    rules.LangC,
			Pattern:     `\b(?:escape_csv_formula|sanitize_csv_cell|csv_safe_cell|csv_escape)\s*\(`,
			ObjectType:  "",
			MethodName:  "escape_csv_formula",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Custom escape_csv_formula / sanitize_csv_cell helper — prefixes a single quote when a field starts with =, +, -, @, TAB (defends CSV-formula injection)",
		},
		{
			ID:          "c.libcsv.write_quoted",
			Language:    rules.LangC,
			Pattern:     `csv_set_quoted\s*\(|csv_set_opts\s*\([^,]+,\s*CSV_QUOTED\s*\)`,
			ObjectType:  "libcsv",
			MethodName:  "csv_set_quoted/CSV_QUOTED",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "libcsv csv_set_quoted / CSV_QUOTED option — always quote every field (sufficient combined with formula-prefix escape to defend CSV-formula injection)",
		},

		// --- Ulfius HTTP framework (babelouest/ulfius) JSON response ---
		// `ulfius_set_json_body_response(response, status, j_body)` serializes a
		// jansson `json_t` and emits an application/json response. Jansson's
		// json_string()/json_dumps() escape control and structural characters,
		// so a request value carried as a JSON string value cannot break out of
		// the JSON document — this is the framework-idiomatic safe alternative
		// to emitting raw HTML, neutralizing reflected-XSS for the response.
		{
			ID:          "c.ulfius.set_json_body_response",
			Language:    rules.LangC,
			Pattern:     `\bulfius_set_json_body_response\s*\(`,
			ObjectType:  "",
			MethodName:  "ulfius_set_json_body_response",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Ulfius JSON body response — jansson serialization escapes structural characters, preventing reflected XSS when returning request data as JSON",
		},
	}
}
