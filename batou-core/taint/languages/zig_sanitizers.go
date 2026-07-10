package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *ZigCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- Path normalization ---
		{
			ID:          "zig.fs.path.normalize",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.normalize\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.normalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path normalization (resolves .. and . components)",
		},
		{
			ID:          "zig.fs.path.resolve",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.resolve\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.resolve",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path resolution against base directory",
		},

		// --- Path canonicalization ---
		{
			ID:          "zig.fs.Dir.realpathAlloc",
			Language:    rules.LangZig,
			Pattern:     `\.realpathAlloc\s*\(`,
			ObjectType:  "std.fs.Dir",
			MethodName:  "Dir.realpathAlloc",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path canonicalization (resolves symlinks, prevents traversal)",
		},
		{
			ID:          "zig.fs.realpathAlloc",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.realpathAlloc\s*\(`,
			ObjectType:  "std.fs",
			MethodName:  "std.fs.realpathAlloc",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Absolute path canonicalization with symlink resolution",
		},

		// --- Numeric conversion ---
		{
			ID:          "zig.fmt.parseInt",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.parseInt\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.parseInt",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "String to integer parsing (restricts to numeric values)",
		},
		{
			ID:          "zig.fmt.parseFloat",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.parseFloat\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.parseFloat",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "String to float parsing (restricts to numeric values)",
		},
		{
			ID:          "zig.fmt.parseUnsigned",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.parseUnsigned\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.parseUnsigned",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "String to unsigned integer parsing",
		},
		{
			ID:          "zig.fmt.parseIntSizeSuffix",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.parseIntSizeSuffix\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.parseIntSizeSuffix",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Parse SI/binary size-suffixed string (e.g. \"2KiB\") to a usize — result is numeric, not attacker-controlled text",
		},
		{
			ID:          "zig.fmt.charToDigit",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.charToDigit\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.charToDigit",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Convert a single character to its numeric digit value for a given base (rejects non-digit input) — coerces to an integer",
		},

		// --- Enum / allowlist mapping ---
		{
			ID:          "zig.meta.stringToEnum",
			Language:    rules.LangZig,
			Pattern:     `std\.meta\.stringToEnum\s*\(`,
			ObjectType:  "std.meta",
			MethodName:  "std.meta.stringToEnum",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkRedirect},
			Description: "Map an untrusted string to a known enum variant or null — canonical Zig allowlist; the result is constrained to a fixed, developer-defined set of values",
		},

		// --- Path component extraction ---
		{
			ID:          "zig.fs.path.basename",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.basename\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Extract file name component (strips directory traversal)",
		},

		// --- URL encoding ---
		{
			ID:          "zig.Uri.escapeString",
			Language:    rules.LangZig,
			Pattern:     `std\.Uri\.escapeString\s*\(`,
			ObjectType:  "std.Uri",
			MethodName:  "std.Uri.escapeString",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHTMLOutput},
			Description: "URI string escaping for safe URL construction",
		},

		// --- URL validation ---
		{
			ID:          "zig.Uri.parse",
			Language:    rules.LangZig,
			Pattern:     `std\.Uri\.parse\s*\(`,
			ObjectType:  "std.Uri",
			MethodName:  "std.Uri.parse",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI parsing and validation (structural validation of URL)",
		},

		// --- IP address validation (SSRF prevention) ---
		{
			ID:          "zig.net.Address.parseIp",
			Language:    rules.LangZig,
			Pattern:     `std\.net\.Address\.parseIp\s*\(`,
			ObjectType:  "std.net.Address",
			MethodName:  "Address.parseIp",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address parsing — validates IP format for SSRF allowlist/blocklist (CWE-918)",
		},
		{
			ID:          "zig.net.Ip4Address.parse",
			Language:    rules.LangZig,
			Pattern:     `std\.net\.Ip4Address\.parse\s*\(`,
			ObjectType:  "std.net.Ip4Address",
			MethodName:  "Ip4Address.parse",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IPv4 address parsing — validates IPv4 for SSRF prevention (CWE-918)",
		},

		// --- Case-insensitive comparison (scheme/host validation) ---
		{
			ID:          "zig.ascii.eqlIgnoreCase",
			Language:    rules.LangZig,
			Pattern:     `std\.ascii\.eqlIgnoreCase\s*\(`,
			ObjectType:  "std.ascii",
			MethodName:  "std.ascii.eqlIgnoreCase",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Case-insensitive comparison — validates URL scheme/host (CWE-918, CWE-601)",
		},

		// --- Substring search (blocklist/allowlist pattern check) ---
		{
			ID:         "zig.mem.indexOf",
			Language:   rules.LangZig,
			Pattern:    `std\.mem\.indexOf\s*\(`,
			ObjectType: "std.mem",
			MethodName: "std.mem.indexOf",
			// indexOf returns a position (?usize); it transforms nothing. Keep
			// only the weak-but-conventional SSRF blocklist heuristic (SnkURLFetch);
			// it does NOT neutralize command injection — a "contains" check never
			// removes shell metacharacters, so SnkCommand is dropped.
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Substring search — weak blocklist check for URLs (CWE-918); does NOT sanitize command injection",
		},

		// --- Parameterized queries ---
		{
			ID:          "zig.sqlite.prepareWithBind",
			Language:    rules.LangZig,
			Pattern:     `\.bind\s*\(`,
			ObjectType:  "sqlite.Statement",
			MethodName:  "Statement.bind",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite parameterized query binding (prevents SQL injection)",
		},

		// --- Allowlist check ---
		{
			ID:          "zig.mem.eql",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.eql\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.eql",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkCommand, taint.SnkURLFetch},
			Description: "Memory equality comparison (allowlist validation)",
		},
		{
			ID:          "zig.mem.startsWith",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.startsWith\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.startsWith",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Prefix check for URL/path allowlist validation",
		},
		{
			ID:          "zig.mem.endsWith",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.endsWith\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.endsWith",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Suffix check for file extension validation",
		},

		// --- Numeric bounds clamping ---
		{
			ID:          "zig.math.clamp",
			Language:    rules.LangZig,
			Pattern:     `std\.math\.clamp\s*\(`,
			ObjectType:  "std.math",
			MethodName:  "std.math.clamp",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Numeric value clamping to safe bounds",
		},

		// --- HTML escaping (std.html, Zig 0.13+) ---
		{
			ID:          "zig.html.escape",
			Language:    rules.LangZig,
			Pattern:     `std\.html\.escape\s*\(`,
			ObjectType:  "std.html",
			MethodName:  "std.html.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "HTML body context escaping (encodes <, >, &, etc.)",
		},
		{
			ID:          "zig.html.escapeAttribute",
			Language:    rules.LangZig,
			Pattern:     `std\.html\.escapeAttribute\s*\(`,
			ObjectType:  "std.html",
			MethodName:  "std.html.escapeAttribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "HTML attribute context escaping (encodes quotes and special chars)",
		},
		{
			ID:          "zig.html.escapeJavaScript",
			Language:    rules.LangZig,
			Pattern:     `std\.html\.escapeJavaScript\s*\(`,
			ObjectType:  "std.html",
			MethodName:  "std.html.escapeJavaScript",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "JavaScript string escaping for safe inline script embedding",
		},

		// --- Secure CSPRNG (neutralizes weak crypto findings) ---
		{
			ID:          "zig.crypto.random.bytes",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.random\.bytes\s*\(`,
			ObjectType:  "std.crypto.random",
			MethodName:  "random.bytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random byte generation",
		},
		{
			ID:          "zig.crypto.random.int",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.random\.int\s*\(`,
			ObjectType:  "std.crypto.random",
			MethodName:  "random.int",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random integer generation",
		},

		// --- Secure hashing (neutralizes weak hash findings) ---
		{
			ID:          "zig.crypto.hash.sha256",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.hash\.sha2\.Sha256`,
			ObjectType:  "std.crypto.hash.sha2",
			MethodName:  "Sha256",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-256 secure hash algorithm",
		},
		{
			ID:          "zig.crypto.hash.blake2",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.hash\.Blake2`,
			ObjectType:  "std.crypto.hash",
			MethodName:  "Blake2",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BLAKE2 secure hash algorithm",
		},

		// --- Log sanitization ---
		{
			ID:          "zig.mem.replaceScalar",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.replaceScalar\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.replaceScalar",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Byte replacement (can strip newlines/control chars for log/header injection)",
		},
		{
			ID:          "zig.ascii.isAlphanumeric",
			Language:    rules.LangZig,
			Pattern:     `std\.ascii\.isAlphanumeric\s*\(`,
			ObjectType:  "std.ascii",
			MethodName:  "std.ascii.isAlphanumeric",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Alphanumeric character validation (allowlist check)",
		},

		// --- JSON schema validation (safe deserialization) ---
		{
			ID:          "zig.json.parseFromValue",
			Language:    rules.LangZig,
			Pattern:     `std\.json\.parseFromValue\s*\(`,
			ObjectType:  "std.json",
			MethodName:  "std.json.parseFromValue",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Type-safe JSON parsing into known struct (comptime schema validation)",
		},

		// --- Comptime format strings (safe against format injection) ---
		{
			ID:          "zig.fmt.comptimeFmt",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.comptimePrint\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.comptimePrint",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkTemplate},
			Description: "Compile-time format string (cannot be tainted at runtime)",
		},

		// --- Character replacement (strip dangerous characters) ---
		{
			ID:          "zig.mem.replace",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.replace\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.replace",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Byte sequence replacement (can strip newlines/control chars for log/header injection)",
		},

		// --- POSIX path canonicalization ---
		{
			ID:          "zig.posix.realpath",
			Language:    rules.LangZig,
			Pattern:     `std\.posix\.realpath\s*\(`,
			ObjectType:  "std.posix",
			MethodName:  "std.posix.realpath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "POSIX realpath resolves symlinks and normalizes path (prevents traversal)",
		},

		// --- pg.zig parameterized queries (safe against SQLi) ---
		{
			ID:          "zig.pg.conn.prepare",
			Language:    rules.LangZig,
			Pattern:     `conn\.prepare\s*\(`,
			ObjectType:  "pg.Conn",
			MethodName:  "Conn.prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "pg.zig prepared statement (parameterized query prevents SQL injection)",
		},
		{
			ID:          "zig.pg.conn.prepareOpts",
			Language:    rules.LangZig,
			Pattern:     `conn\.prepareOpts\s*\(`,
			ObjectType:  "pg.Conn",
			MethodName:  "Conn.prepareOpts",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "pg.zig prepared statement with options (parameterized query)",
		},

		// --- myzql (speed2exe/myzql) parameterized queries (safe against SQLi) ---
		// myzql's binary protocol uses Conn.prepare(...) with `?` placeholders,
		// then Conn.execute / Conn.executeRows binds the user values as typed
		// parameters out-of-band — they are never spliced into SQL text, so the
		// query string stays trusted. This is the recommended alternative to the
		// text-protocol Conn.queryRows sink. Scoped to the myzql Conn receiver
		// (conventionally `c` / `conn`).
		{
			ID:          "zig.myzql.conn.prepare",
			Language:    rules.LangZig,
			Pattern:     `\.prepare\s*\(`,
			ObjectType:  "myzql.Conn",
			MethodName:  "Conn.prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "myzql Conn.prepare builds a prepared statement with `?` placeholders; user values are bound out-of-band at execute time (parameterized query prevents SQL injection)",
		},
		{
			ID:          "zig.myzql.conn.executeRows",
			Language:    rules.LangZig,
			Pattern:     `\.executeRows\s*\(`,
			ObjectType:  "myzql.Conn",
			MethodName:  "Conn.executeRows",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "myzql Conn.executeRows runs a prepared statement, binding user values as typed parameters (never spliced into SQL text) — parameterized query prevents SQL injection",
		},
		{
			ID:          "zig.myzql.conn.execute",
			Language:    rules.LangZig,
			Pattern:     `\.execute\s*\(`,
			ObjectType:  "myzql.Conn",
			MethodName:  "Conn.execute",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "myzql Conn.execute runs a prepared statement (ok/err), binding user values as typed parameters (never spliced into SQL text) — parameterized query prevents SQL injection",
		},

		// --- Digit-only validation ---
		{
			ID:          "zig.ascii.isDigit",
			Language:    rules.LangZig,
			Pattern:     `std\.ascii\.isDigit\s*\(`,
			ObjectType:  "std.ascii",
			MethodName:  "std.ascii.isDigit",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Digit-only character validation (strict numeric allowlist check)",
		},

		// --- UTF-8 validation (prevents encoding attacks) ---
		{
			ID:          "zig.unicode.utf8ValidateSlice",
			Language:    rules.LangZig,
			Pattern:     `std\.unicode\.utf8ValidateSlice\s*\(`,
			ObjectType:  "std.unicode",
			MethodName:  "std.unicode.utf8ValidateSlice",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader},
			Description: "UTF-8 validation prevents encoding-based injection attacks",
		},

		// --- Base64 encoding (safe output encoding) ---
		{
			ID:          "zig.base64.encode",
			Language:    rules.LangZig,
			Pattern:     `std\.base64\.\w+\.Encoder\.encode\s*\(`,
			ObjectType:  "std.base64",
			MethodName:  "Encoder.encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog},
			Description: "Base64 encoding produces safe A-Za-z0-9+/= output (no HTML/log injection chars)",
		},

		// --- JSON serialization (safe output encoding) ---
		{
			ID:          "zig.json.stringify",
			Language:    rules.LangZig,
			Pattern:     `std\.json\.stringify\s*\(`,
			ObjectType:  "std.json",
			MethodName:  "std.json.stringify",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog},
			Description: "JSON serialization escapes special characters for safe output embedding",
		},
		{
			ID:          "zig.json.stringifyAlloc",
			Language:    rules.LangZig,
			Pattern:     `std\.json\.stringifyAlloc\s*\(`,
			ObjectType:  "std.json",
			MethodName:  "std.json.stringifyAlloc",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog},
			Description: "JSON serialization with allocation escapes special characters for safe output",
		},

		// --- AEAD authenticated encryption (neutralizes weak crypto) ---
		{
			ID:          "zig.crypto.aead.aes_gcm",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.aead\.aes_gcm\.`,
			ObjectType:  "std.crypto.aead",
			MethodName:  "aes_gcm",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "AES-GCM authenticated encryption (NIST-approved AEAD cipher)",
		},
		{
			ID:          "zig.crypto.aead.chacha_poly",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.aead\.chacha_poly\.`,
			ObjectType:  "std.crypto.aead",
			MethodName:  "chacha_poly",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "ChaCha20-Poly1305 authenticated encryption (RFC 8439)",
		},

		// --- Password hashing (neutralizes weak password storage) ---
		{
			ID:          "zig.crypto.pwhash.argon2",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.pwhash\.argon2\.`,
			ObjectType:  "std.crypto.pwhash",
			MethodName:  "argon2",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2 password hashing (OWASP-recommended KDF)",
		},
		{
			ID:          "zig.crypto.pwhash.bcrypt",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.pwhash\.bcrypt\.`,
			ObjectType:  "std.crypto.pwhash",
			MethodName:  "bcrypt",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "bcrypt password hashing (adaptive cost function)",
		},

		// --- Additional secure hash algorithms ---
		{
			ID:          "zig.crypto.hash.sha384",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.hash\.sha2\.Sha384`,
			ObjectType:  "std.crypto.hash.sha2",
			MethodName:  "Sha384",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-384 secure hash algorithm",
		},
		{
			ID:          "zig.crypto.hash.sha512",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.hash\.sha2\.Sha512`,
			ObjectType:  "std.crypto.hash.sha2",
			MethodName:  "Sha512",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-512 secure hash algorithm",
		},

		// --- SHA-3 / Keccak family (NIST FIPS 202) ---
		{
			ID:          "zig.crypto.hash.sha3_256",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.hash\.sha3\.Sha3_256`,
			ObjectType:  "std.crypto.hash.sha3",
			MethodName:  "Sha3_256",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA3-256 secure hash algorithm (FIPS 202)",
		},
		{
			ID:          "zig.crypto.hash.sha3_384",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.hash\.sha3\.Sha3_384`,
			ObjectType:  "std.crypto.hash.sha3",
			MethodName:  "Sha3_384",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA3-384 secure hash algorithm (FIPS 202)",
		},
		{
			ID:          "zig.crypto.hash.sha3_512",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.hash\.sha3\.Sha3_512`,
			ObjectType:  "std.crypto.hash.sha3",
			MethodName:  "Sha3_512",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA3-512 secure hash algorithm (FIPS 202)",
		},

		// --- HMAC with SHA-2 family (modern MAC) ---
		{
			ID:          "zig.crypto.auth.hmac.HmacSha256",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.auth\.hmac\.sha2\.HmacSha256\b`,
			ObjectType:  "std.crypto.auth.hmac.sha2",
			MethodName:  "HmacSha256",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HMAC-SHA256 message authentication (modern alternative to HmacMd5/HmacSha1)",
		},
		{
			ID:          "zig.crypto.auth.hmac.HmacSha512",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.auth\.hmac\.sha2\.HmacSha512\b`,
			ObjectType:  "std.crypto.auth.hmac.sha2",
			MethodName:  "HmacSha512",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HMAC-SHA512 message authentication (modern alternative to HmacMd5/HmacSha1)",
		},

		// --- HKDF key derivation (RFC 5869) ---
		{
			ID:          "zig.crypto.kdf.hkdf.HkdfSha256",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.kdf\.hkdf\.HkdfSha256`,
			ObjectType:  "std.crypto.kdf.hkdf",
			MethodName:  "HkdfSha256",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HKDF-SHA256 key derivation function (RFC 5869)",
		},
		{
			ID:          "zig.crypto.kdf.hkdf.HkdfSha512",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.kdf\.hkdf\.HkdfSha512`,
			ObjectType:  "std.crypto.kdf.hkdf",
			MethodName:  "HkdfSha512",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HKDF-SHA512 key derivation function (RFC 5869)",
		},

		// --- Additional password hashing KDFs ---
		{
			ID:          "zig.crypto.pwhash.scrypt",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.pwhash\.scrypt\.`,
			ObjectType:  "std.crypto.pwhash",
			MethodName:  "scrypt",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "scrypt password hashing (RFC 7914 memory-hard KDF)",
		},
		{
			ID:          "zig.crypto.pwhash.pbkdf2",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.pwhash\.pbkdf2\s*\(`,
			ObjectType:  "std.crypto.pwhash",
			MethodName:  "std.crypto.pwhash.pbkdf2",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 password-based key derivation (RFC 8018)",
		},

		// --- Constant-time comparison (CWE-208 timing-attack mitigation) ---
		{
			ID:          "zig.crypto.utils.timingSafeEql",
			Language:    rules.LangZig,
			Pattern:     `std\.crypto\.utils\.timingSafeEql\s*\(`,
			ObjectType:  "std.crypto.utils",
			MethodName:  "std.crypto.utils.timingSafeEql",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Constant-time equality comparison for MACs/signatures (prevents timing side-channels, CWE-208)",
		},

		// --- Path validation (absolute-path check) ---
		{
			ID:          "zig.fs.path.isAbsolute",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.isAbsolute\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.isAbsolute",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Absolute-path check used in path-validation guards (path traversal mitigation)",
		},

		// --- Schema-typed JSON deserialization (parsed into known struct T) ---
		{
			ID:          "zig.json.parseFromSlice",
			Language:    rules.LangZig,
			Pattern:     `std\.json\.parseFromSlice\s*\(`,
			ObjectType:  "std.json",
			MethodName:  "std.json.parseFromSlice",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Type-safe JSON parsing into known struct (comptime schema validation)",
		},

		// --- Hex encoding (safe output, no HTML/log injection chars) ---
		{
			ID:          "zig.fmt.fmtSliceHexLower",
			Language:    rules.LangZig,
			Pattern:     `std\.fmt\.fmtSliceHexLower\s*\(`,
			ObjectType:  "std.fmt",
			MethodName:  "std.fmt.fmtSliceHexLower",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog},
			Description: "Lowercase hex byte formatting produces safe 0-9a-f output (no HTML/log injection chars)",
		},

		// --- UTF-8 codepoint validation (prevents encoding attacks) ---
		{
			ID:          "zig.unicode.utf8ValidCodepoint",
			Language:    rules.LangZig,
			Pattern:     `std\.unicode\.utf8ValidCodepoint\s*\(`,
			ObjectType:  "std.unicode",
			MethodName:  "std.unicode.utf8ValidCodepoint",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader},
			Description: "Per-codepoint UTF-8 validation (prevents encoding-based injection)",
		},

		// --- CSV (CWE-1236) — formula-prefix escape helpers ---
		{
			ID:          "zig.csv.escape_formula",
			Language:    rules.LangZig,
			Pattern:     `\b(?:escapeCsvFormula|sanitizeCsvCell|csvSafeCell|csvEscape)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeCsvFormula",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Custom escapeCsvFormula / sanitizeCsvCell helper — prefixes a single quote when a field starts with =, +, -, @, TAB (defends CSV-formula injection)",
		},
		{
			ID:          "zig.csv.quote_all",
			Language:    rules.LangZig,
			Pattern:     `\.quote_all\s*=\s*true|always_quote\s*=\s*true`,
			ObjectType:  "csv.Writer",
			MethodName:  "csv.Writer(.{.quote_all=true})",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Zig csv.Writer .quote_all=true option — quotes every field at write time (combined with formula-prefix escape this defends CSV-formula injection)",
		},

		// --- LDAP filter/DN escaping (CWE-90) ---
		// The Zig LDAP sinks (zig.ldap.*) inject when user input lands in an
		// ldap_search filter or a DN. There is no stdlib LDAP escaper, so the
		// safe form is a custom RFC 4515 (filter) / RFC 4514 (DN) escaper that
		// neutralizes (, ), *, \, NUL and DN special chars before use.
		{
			ID:          "zig.ldap.escape_filter",
			Language:    rules.LangZig,
			Pattern:     `\b(?:escapeLdapFilter|ldapEscape|escapeLdapDn|escapeDN|escapeLdapValue)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeLdapFilter",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Custom RFC 4515/4514 LDAP escaper (escapeLdapFilter / ldapEscape / escapeDN) — escapes (, ), *, \\, NUL and DN metacharacters so user input is treated as a literal value (prevents LDAP injection, CWE-90)",
		},

		// --- NoSQL injection prevention (CWE-943) ---
		// The Zig NoSQL sinks (zig.mongoc.*, zig.redis.*) inject when a user
		// string is interpreted as a query operator. Binding values through the
		// typed libbson appenders treats them strictly as data, not operators.
		{
			ID:          "zig.libbson.append_utf8",
			Language:    rules.LangZig,
			Pattern:     `\bbson_append_utf8\s*\(`,
			ObjectType:  "libbson",
			MethodName:  "bson_append_utf8",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "libbson bson_append_utf8 binds a user string as a typed BSON value (data, not a query operator) — prevents MongoDB operator injection (CWE-943)",
		},
		{
			ID:          "zig.redis.command_argv",
			Language:    rules.LangZig,
			Pattern:     `\.redisCommandArgv\s*\(`,
			ObjectType:  "hiredis",
			MethodName:  "redisCommandArgv",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "hiredis redisCommandArgv passes each command argument as a separate argv element — user data is never parsed as command syntax (prevents Redis command injection, CWE-943)",
		},

		// --- XPath injection prevention (CWE-643) ---
		// The Zig XPath sinks (zig.libxml2.*) inject when user input is
		// concatenated into an XPath expression. Binding the value as an XPath
		// variable (xmlXPathRegisterVariable) or escaping it keeps it as data.
		{
			ID:          "zig.libxml2.xpath_register_variable",
			Language:    rules.LangZig,
			Pattern:     `\bxmlXPathRegisterVariable\s*\(`,
			ObjectType:  "libxml2",
			MethodName:  "xmlXPathRegisterVariable",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "libxml2 xmlXPathRegisterVariable binds a user value to an XPath variable ($var) so it is evaluated as data, not as expression syntax (prevents XPath injection, CWE-643)",
		},
		{
			ID:          "zig.xpath.escape",
			Language:    rules.LangZig,
			Pattern:     `\b(?:escapeXPath|xpathQuote|escapeXpathLiteral)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeXPath",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Custom XPath literal escaper (escapeXPath / xpathQuote) — wraps/escapes quotes and metacharacters so user input becomes an XPath string literal (prevents XPath injection, CWE-643)",
		},

		// --- Upload validation (CWE-434) ---
		// The Zig upload sinks (zig.zap.parameters_files, zig.httpz.formData_file,
		// zig.http_multipart.fields) carry client-supplied files. Validating the
		// extension / MIME type against an allowlist before persisting neutralizes
		// unrestricted file upload.
		{
			ID:          "zig.upload.validate_extension",
			Language:    rules.LangZig,
			Pattern:     `\b(?:validateFileExtension|isAllowedExtension|isAllowedMimeType|validateUpload|allowedContentType)\s*\(`,
			ObjectType:  "",
			MethodName:  "isAllowedExtension",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Custom upload validator (isAllowedExtension / isAllowedMimeType / validateUpload) checks the filename extension or MIME type against an allowlist before persisting — prevents unrestricted file upload (CWE-434)",
		},

		// --- RegexDoS prevention (CWE-1333) ---
		// The Zig RegexDoS sinks (zig.regex.compile, zig.mvzr.compile) fire when a
		// backtracking regex is compiled from a tainted pattern. Escaping the user
		// string so it matches literally removes all attacker-controlled operators.
		{
			ID:          "zig.regex.escape",
			Language:    rules.LangZig,
			Pattern:     `\b(?:escapeRegex|regexEscape|quoteMeta|escapeRegexMeta)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeRegex",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Custom regex-metacharacter escaper (escapeRegex / quoteMeta) escapes all regex operators so the user string matches literally — neutralizes catastrophic-backtracking ReDoS from an injected pattern (CWE-1333)",
		},
	}
}
