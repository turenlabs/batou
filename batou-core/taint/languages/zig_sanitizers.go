package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path normalization (resolves .. and . components)",
		},
		{
			ID:          "zig.fs.path.resolve",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.resolve\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.resolve",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path resolution against base directory",
		},

		// --- Path canonicalization ---
		{
			ID:          "zig.fs.Dir.realpathAlloc",
			Language:    rules.LangZig,
			Pattern:     `\.realpathAlloc\s*\(`,
			ObjectType:  "std.fs.Dir",
			MethodName:  "Dir.realpathAlloc",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path canonicalization (resolves symlinks, prevents traversal)",
		},
		{
			ID:          "zig.fs.realpathAlloc",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.realpathAlloc\s*\(`,
			ObjectType:  "std.fs",
			MethodName:  "std.fs.realpathAlloc",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Absolute path canonicalization with symlink resolution",
		},

		// --- String sanitization ---
		{
			ID:          "zig.mem.trim",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.trim\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.trim",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Memory trim operation (strips specified bytes)",
		},
		{
			ID:          "zig.mem.splitSequence",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.splitSequence\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.splitSequence",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Split by sequence for structured parsing",
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

		// --- Path component extraction ---
		{
			ID:          "zig.fs.path.basename",
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.path\.basename\s*\(`,
			ObjectType:  "std.fs.path",
			MethodName:  "std.fs.path.basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
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
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkFileWrite},
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
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkCommand, taint.SnkSQLQuery},
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

		// --- Structured parsing (restricts input to parsed tokens) ---
		{
			ID:          "zig.mem.tokenizeAny",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.tokenizeAny\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.tokenizeAny",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery},
			Description: "Tokenize by any of multiple delimiter bytes (structured parsing)",
		},
		{
			ID:          "zig.mem.tokenizeScalar",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.tokenizeScalar\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.tokenizeScalar",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery},
			Description: "Tokenize by single delimiter byte (structured parsing)",
		},
		{
			ID:          "zig.mem.splitAny",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.splitAny\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.splitAny",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery},
			Description: "Split by any of multiple delimiter bytes (structured parsing)",
		},
		{
			ID:          "zig.mem.splitScalar",
			Language:    rules.LangZig,
			Pattern:     `std\.mem\.splitScalar\s*\(`,
			ObjectType:  "std.mem",
			MethodName:  "std.mem.splitScalar",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery},
			Description: "Split by single delimiter byte (structured parsing)",
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

		// --- Strict allowlist validation ---
		{
			ID:          "zig.ascii.isAlphabetic",
			Language:    rules.LangZig,
			Pattern:     `std\.ascii\.isAlphabetic\s*\(`,
			ObjectType:  "std.ascii",
			MethodName:  "std.ascii.isAlphabetic",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkFileWrite},
			Description: "Alphabetic character validation (strict allowlist check)",
		},
		{
			ID:          "zig.ascii.isHex",
			Language:    rules.LangZig,
			Pattern:     `std\.ascii\.isHex\s*\(`,
			ObjectType:  "std.ascii",
			MethodName:  "std.ascii.isHex",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery},
			Description: "Hexadecimal character validation (strict allowlist check)",
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
	}
}
