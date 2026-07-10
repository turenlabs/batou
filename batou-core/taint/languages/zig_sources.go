package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *ZigCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- HTTP server input ---
		{
			ID:          "zig.http.server.request",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `std\.http\.Server`,
			ObjectType:  "std.http.Server",
			MethodName:  "std.http.Server",
			Description: "Zig HTTP server request object",
			Assigns:     "return",
		},
		{
			ID:          "zig.http.server.request_target",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `\.request\.target`,
			ObjectType:  "std.http.Server.Request",
			MethodName:  "request.target",
			Description: "HTTP request target (URL path/query)",
			Assigns:     "return",
		},
		{
			ID:          "zig.http.server.request_headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `\.request\.headers`,
			ObjectType:  "std.http.Server.Request",
			MethodName:  "request.headers",
			Description: "HTTP request headers",
			Assigns:     "return",
		},
		{
			ID:          "zig.http.server.read_body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `\.reader\(\)`,
			ObjectType:  "std.http.Server.Response",
			MethodName:  "reader()",
			Description: "HTTP request body reader",
			Assigns:     "return",
		},

		// --- I/O reader input ---
		{
			ID:          "zig.io.reader.read",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.read\s*\(`,
			ObjectType:  "std.io.Reader",
			MethodName:  "Reader.read",
			Description: "I/O reader read operation",
			Assigns:     "return",
		},
		{
			ID:          "zig.io.reader.readAllAlloc",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.readAllAlloc\s*\(`,
			ObjectType:  "std.io.Reader",
			MethodName:  "Reader.readAllAlloc",
			Description: "Read entire stream into allocated buffer",
			Assigns:     "return",
		},
		{
			ID:          "zig.io.reader.readUntilDelimiter",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.readUntilDelimiter\s*\(`,
			ObjectType:  "std.io.Reader",
			MethodName:  "Reader.readUntilDelimiter",
			Description: "Read from stream until delimiter",
			Assigns:     "return",
		},

		// --- CLI arguments ---
		{
			ID:          "zig.os.argv",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangZig,
			Pattern:     `std\.os\.argv`,
			ObjectType:  "",
			MethodName:  "std.os.argv",
			Description: "Program command-line arguments",
			Assigns:     "return",
		},
		{
			ID:          "zig.process.argsAlloc",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangZig,
			Pattern:     `std\.process\.argsAlloc\s*\(`,
			ObjectType:  "std.process",
			MethodName:  "std.process.argsAlloc",
			Description: "Allocated command-line argument iterator",
			Assigns:     "return",
		},
		{
			ID:          "zig.process.ArgIterator",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangZig,
			Pattern:     `std\.process\.ArgIterator`,
			ObjectType:  "std.process",
			MethodName:  "std.process.ArgIterator",
			Description: "Command-line argument iterator type",
			Assigns:     "return",
		},
		{
			ID:          "zig.process.ArgIterator.next",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangZig,
			Pattern:     `\.next\s*\(`,
			ObjectType:  "std.process.ArgIterator",
			MethodName:  "ArgIterator.next",
			Description: "Next command-line argument from iterator",
			Assigns:     "return",
		},

		// --- Environment variables ---
		{
			ID:          "zig.os.environ",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangZig,
			Pattern:     `std\.os\.environ`,
			ObjectType:  "",
			MethodName:  "std.os.environ",
			Description: "Process environment variables",
			Assigns:     "return",
		},
		{
			ID:          "zig.process.getEnvMap",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangZig,
			Pattern:     `std\.process\.getEnvMap\s*\(`,
			ObjectType:  "std.process",
			MethodName:  "std.process.getEnvMap",
			Description: "Get environment variables as map",
			Assigns:     "return",
		},

		// --- Network input ---
		{
			ID:          "zig.net.stream.read",
			Category:    taint.SrcNetwork,
			Language:    rules.LangZig,
			Pattern:     `\.read\s*\(`,
			ObjectType:  "std.net.Stream",
			MethodName:  "Stream.read",
			Description: "Network stream socket read",
			Assigns:     "return",
		},
		{
			ID:          "zig.net.StreamServer.accept",
			Category:    taint.SrcNetwork,
			Language:    rules.LangZig,
			Pattern:     `\.accept\s*\(`,
			ObjectType:  "std.net.StreamServer",
			MethodName:  "StreamServer.accept",
			Description: "Accept incoming network connection",
			Assigns:     "return",
		},

		// --- Deserialization ---
		{
			ID:          "zig.json.parseFromSlice",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangZig,
			Pattern:     `std\.json\.parseFromSlice\s*\(`,
			ObjectType:  "std.json",
			MethodName:  "std.json.parseFromSlice",
			Description: "JSON deserialization from byte slice",
			Assigns:     "return",
		},
		{
			ID:          "zig.json.parseFromSliceLeaky",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangZig,
			Pattern:     `std\.json\.parseFromSliceLeaky\s*\(`,
			ObjectType:  "std.json",
			MethodName:  "std.json.parseFromSliceLeaky",
			Description: "JSON deserialization (leaky allocator variant)",
			Assigns:     "return",
		},
		{
			ID:          "zig.json.parseFromTokenSource",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangZig,
			Pattern:     `std\.json\.parseFromTokenSource\s*\(`,
			ObjectType:  "std.json",
			MethodName:  "std.json.parseFromTokenSource",
			Description: "JSON deserialization from token source",
			Assigns:     "return",
		},

		// --- File system ---
		{
			ID:          "zig.fs.Dir.openFile",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.openFile\s*\(`,
			ObjectType:  "std.fs.Dir",
			MethodName:  "Dir.openFile",
			Description: "Open file from directory handle",
			Assigns:     "return",
		},
		{
			ID:          "zig.fs.cwd",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.cwd\s*\(`,
			ObjectType:  "std.fs",
			MethodName:  "std.fs.cwd",
			Description: "Current working directory handle",
			Assigns:     "return",
		},
		{
			ID:          "zig.fs.openFileAbsolute",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `std\.fs\.openFileAbsolute\s*\(`,
			ObjectType:  "std.fs",
			MethodName:  "std.fs.openFileAbsolute",
			Description: "Open file by absolute path",
			Assigns:     "return",
		},

		// --- zap web framework (facil.io wrapper) ---
		{
			ID:          "zig.zap.request.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `\br\.path`,
			ObjectType:  "zap.Request",
			MethodName:  "Request.path",
			Description: "zap HTTP request URL path",
			Assigns:     "return",
		},
		{
			ID:          "zig.zap.request.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `\br\.query`,
			ObjectType:  "zap.Request",
			MethodName:  "Request.query",
			Description: "zap HTTP request query string",
			Assigns:     "return",
		},
		{
			ID:          "zig.zap.request.getParamSlice",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `\.getParamSlice\s*\(`,
			ObjectType:  "zap.Request",
			MethodName:  "Request.getParamSlice",
			Description: "zap parsed query parameter by key",
			Assigns:     "return",
		},
		{
			ID:          "zig.zap.request.getCookieStr",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `\.getCookieStr\s*\(`,
			ObjectType:  "zap.Request",
			MethodName:  "Request.getCookieStr",
			Description: "zap HTTP cookie value",
			Assigns:     "return",
		},

		// --- httpz / http.zig (used by jetzig) ---
		{
			ID:          "zig.httpz.request.param",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `req\.param\s*\(`,
			ObjectType:  "httpz.Request",
			MethodName:  "Request.param",
			Description: "httpz route parameter",
			Assigns:     "return",
		},
		{
			ID:          "zig.httpz.request.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `req\.query\s*\(`,
			ObjectType:  "httpz.Request",
			MethodName:  "Request.query",
			Description: "httpz query string parameters",
			Assigns:     "return",
		},
		{
			ID:          "zig.httpz.request.header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `req\.header\s*\(`,
			ObjectType:  "httpz.Request",
			MethodName:  "Request.header",
			Description: "httpz HTTP request header value",
			Assigns:     "return",
		},
		{
			ID:          "zig.httpz.request.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `req\.body\s*\(`,
			ObjectType:  "httpz.Request",
			MethodName:  "Request.body",
			Description: "httpz HTTP request body",
			Assigns:     "return",
		},
		{
			ID:          "zig.httpz.request.json",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangZig,
			Pattern:     `req\.json\s*\(`,
			ObjectType:  "httpz.Request",
			MethodName:  "Request.json",
			Description: "httpz parsed JSON request body",
			Assigns:     "return",
		},

		// --- Jetzig web framework ---
		{
			ID:          "zig.jetzig.request.params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `request\.params\s*\(`,
			ObjectType:  "jetzig.Request",
			MethodName:  "Request.params",
			Description: "Jetzig request parameters (body or query string)",
			Assigns:     "return",
		},
		{
			ID:          "zig.jetzig.request.queryParams",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `request\.queryParams\s*\(`,
			ObjectType:  "jetzig.Request",
			MethodName:  "Request.queryParams",
			Description: "Jetzig query string parameters",
			Assigns:     "return",
		},
		{
			ID:          "zig.jetzig.request.expectParams",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `request\.expectParams\s*\(`,
			ObjectType:  "jetzig.Request",
			MethodName:  "Request.expectParams",
			Description: "Jetzig typed request parameters",
			Assigns:     "return",
		},

		// --- C interop sources ---
		{
			ID:          "zig.c.getenv",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangZig,
			Pattern:     `std\.c\.getenv\s*\(`,
			ObjectType:  "std.c",
			MethodName:  "std.c.getenv",
			Description: "Environment variable via C interop (returns tainted data)",
			Assigns:     "return",
		},
		{
			ID:          "zig.c.fread",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `std\.c\.fread\s*\(`,
			ObjectType:  "std.c",
			MethodName:  "std.c.fread",
			Description: "Read from file stream via C interop",
			Assigns:     "return",
		},

		// --- POSIX network input ---
		{
			ID:          "zig.posix.recv",
			Category:    taint.SrcNetwork,
			Language:    rules.LangZig,
			Pattern:     `std\.posix\.recv\s*\(`,
			ObjectType:  "std.posix",
			MethodName:  "std.posix.recv",
			Description: "POSIX socket receive (user-controlled network input)",
			Assigns:     "return",
		},
		{
			ID:          "zig.posix.recvfrom",
			Category:    taint.SrcNetwork,
			Language:    rules.LangZig,
			Pattern:     `std\.posix\.recvfrom\s*\(`,
			ObjectType:  "std.posix",
			MethodName:  "std.posix.recvfrom",
			Description: "POSIX socket recvfrom (network input with sender address)",
			Assigns:     "return",
		},
		{
			ID:          "zig.posix.read",
			Category:    taint.SrcNetwork,
			Language:    rules.LangZig,
			Pattern:     `std\.posix\.read\s*\(`,
			ObjectType:  "std.posix",
			MethodName:  "std.posix.read",
			Description: "POSIX read from file descriptor (network socket or file input)",
			Assigns:     "return",
		},

		// --- C interop file input ---
		{
			ID:          "zig.c.fgets",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `std\.c\.fgets\s*\(`,
			ObjectType:  "std.c",
			MethodName:  "std.c.fgets",
			Description: "C fgets reads line from FILE stream (user-controlled input)",
			Assigns:     "return",
		},

		// --- pg.zig query results as data source ---
		{
			ID:          "zig.pg.result.next",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `\bresult\.next\s*\(`,
			ObjectType:  "pg.Result",
			MethodName:  "Result.next",
			Description: "pg.zig query result row iteration",
			Assigns:     "return",
		},
		{
			ID:          "zig.pg.row.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `\brow\.get\s*\(`,
			ObjectType:  "pg.QueryRow",
			MethodName:  "QueryRow.get",
			Description: "pg.zig typed column value from query result",
			Assigns:     "return",
		},

		// --- zig-sqlite (vrischmann/zig-sqlite) read-result sources ---
		// Pair with the existing zig.sqlite.exec/prepare/execDynamic sinks to
		// catch second-order taint where attacker-controlled data stored in
		// SQLite is read back and flowed to a dangerous sink (path traversal,
		// XSS, command injection, etc.).
		{
			ID:          "zig.sqlite.Db.one",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `\bdb\.one\s*\(`,
			ObjectType:  "sqlite.Db",
			MethodName:  "Db.one",
			Description: "zig-sqlite Db.one(Type, query, ...) row read",
			Assigns:     "return",
		},
		{
			ID:          "zig.sqlite.Stmt.one",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `\bstmt\.one\s*\(`,
			ObjectType:  "sqlite.Stmt",
			MethodName:  "Stmt.one",
			Description: "zig-sqlite Stmt.one(Type, ...) optional row read",
			Assigns:     "return",
		},
		{
			ID:          "zig.sqlite.Stmt.oneAlloc",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `stmt\.oneAlloc\s*\(`,
			ObjectType:  "sqlite.Stmt",
			MethodName:  "Stmt.oneAlloc",
			Description: "zig-sqlite Stmt.oneAlloc(Type, allocator, ...) row read with allocator",
			Assigns:     "return",
		},
		{
			ID:          "zig.sqlite.Stmt.all",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `stmt\.all\s*\(`,
			ObjectType:  "sqlite.Stmt",
			MethodName:  "Stmt.all",
			Description: "zig-sqlite Stmt.all(Type, allocator, ...) all-rows read",
			Assigns:     "return",
		},
		{
			ID:          "zig.sqlite.Stmt.iterator",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `stmt\.iterator\s*\(`,
			ObjectType:  "sqlite.Stmt",
			MethodName:  "Stmt.iterator",
			Description: "zig-sqlite Stmt.iterator(Type, ...) row iterator",
			Assigns:     "return",
		},
		{
			ID:          "zig.sqlite.Iterator.next",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `\b(?:iter|iterator)\.next\s*\(`,
			ObjectType:  "sqlite.Iterator",
			MethodName:  "Iterator.next",
			Description: "zig-sqlite Iterator.next() row read (no allocator)",
			Assigns:     "return",
		},
		{
			ID:          "zig.sqlite.Iterator.nextAlloc",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `(?:iter|iterator)\.nextAlloc\s*\(`,
			ObjectType:  "sqlite.Iterator",
			MethodName:  "Iterator.nextAlloc",
			Description: "zig-sqlite Iterator.nextAlloc(allocator, ...) row read with allocator",
			Assigns:     "return",
		},

		// --- POSIX socket read sources ---
		{
			ID:          "zig.posix.recv",
			Category:    taint.SrcNetwork,
			Language:    rules.LangZig,
			Pattern:     `std\.posix\.recv\s*\(`,
			ObjectType:  "std.posix",
			MethodName:  "std.posix.recv",
			Description: "POSIX socket receive — returns untrusted network data",
			Assigns:     "return",
		},
		{
			ID:          "zig.posix.recvfrom",
			Category:    taint.SrcNetwork,
			Language:    rules.LangZig,
			Pattern:     `std\.posix\.recvfrom\s*\(`,
			ObjectType:  "std.posix",
			MethodName:  "std.posix.recvfrom",
			Description: "POSIX socket receive with source address — returns untrusted network data",
			Assigns:     "return",
		},

		// --- POSIX file descriptor read ---
		{
			ID:          "zig.posix.read",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `std\.posix\.read\s*\(`,
			ObjectType:  "std.posix",
			MethodName:  "std.posix.read",
			Description: "POSIX read from file descriptor — returns untrusted data from file or socket",
		},
		// --- Standard I/O stdin ---
		{
			ID:          "zig.io.getStdIn",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `std\.io\.getStdIn\s*\(`,
			ObjectType:  "std.io",
			MethodName:  "std.io.getStdIn",
			Description: "Standard input file descriptor (user-controlled terminal input)",
			Assigns:     "return",
		},

		// --- Environment variable (single key) ---
		{
			ID:          "zig.process.getEnvVarOwned",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangZig,
			Pattern:     `std\.process\.getEnvVarOwned\s*\(`,
			ObjectType:  "std.process",
			MethodName:  "std.process.getEnvVarOwned",
			Description: "Single environment variable by name (returns owned allocation)",
			Assigns:     "return",
		},

		// --- Reader variant: readUntilDelimiterAlloc ---
		{
			ID:          "zig.io.reader.readUntilDelimiterAlloc",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.readUntilDelimiterAlloc\s*\(`,
			ObjectType:  "std.io.Reader",
			MethodName:  "Reader.readUntilDelimiterAlloc",
			Description: "Read from stream until delimiter with allocation (stdin/file/network)",
			Assigns:     "return",
		},

		// --- httpz cookie access ---
		{
			ID:          "zig.httpz.request.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `req\.cookie\s*\(`,
			ObjectType:  "httpz.Request",
			MethodName:  "Request.cookie",
			Description: "httpz HTTP cookie value by name",
			Assigns:     "return",
		},

		// --- httpz form data ---
		{
			ID:          "zig.httpz.request.formData",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `req\.formData\s*\(`,
			ObjectType:  "httpz.Request",
			MethodName:  "Request.formData",
			Description: "httpz parsed form-encoded body data",
			Assigns:     "return",
		},

		// --- zap request body ---
		{
			ID:          "zig.zap.request.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangZig,
			Pattern:     `\br\.body`,
			ObjectType:  "zap.Request",
			MethodName:  "Request.body",
			Description: "zap HTTP request body content",
			Assigns:     "return",
		},

		// --- myzql (speed2exe/myzql) MySQL driver — read-result sources ---
		// Pair with the myzql SQL sink to catch second-order taint where
		// attacker-controlled data persisted in MySQL is read back via a result
		// row and then flowed to a dangerous sink (path traversal, XSS, command
		// injection, etc.). myzql rows are decoded with ResultRow.scan /
		// BinaryResultRow.scan (struct fill) whose return value carries the
		// stored data. Scoped to the myzql result-row receiver so it does not
		// over-match generic .scan calls in unrelated zig code.
		{
			ID:          "zig.myzql.BinaryResultRow.scan",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `\.scan\s*\(`,
			ObjectType:  "myzql.BinaryResultRow",
			MethodName:  "BinaryResultRow.scan",
			Description: "myzql BinaryResultRow.scan decodes a prepared-statement result row (data read back from MySQL — second-order taint)",
			Assigns:     "return",
		},
		{
			ID:          "zig.myzql.TextResultRow.scan",
			Category:    taint.SrcDatabase,
			Language:    rules.LangZig,
			Pattern:     `\.scan\s*\(`,
			ObjectType:  "myzql.TextResultRow",
			MethodName:  "TextResultRow.scan",
			Description: "myzql TextResultRow.scan decodes a text-protocol result row (data read back from MySQL — second-order taint)",
			Assigns:     "return",
		},

		// --- std.fs.File / std.io.Reader allocating reads (file & stream content) ---
		// These return freshly-read file/stream bytes. The std library exposes
		// several allocating read helpers beyond readAllAlloc / readUntilDelimiterAlloc
		// (already cataloged); the variants below are just as common in real Zig
		// code and produce the same attacker-influenced data when the file or
		// stream is untrusted (uploaded file, request body spilled to disk,
		// pipe from a child process, socket reader, etc.). Method names are
		// std-unique, so the bare-dot pattern matches the same way the existing
		// openFile / readAllAlloc entries do.
		{
			ID:          "zig.fs.File.readToEndAlloc",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.readToEndAlloc\s*\(`,
			ObjectType:  "std.fs.File",
			MethodName:  "readToEndAlloc",
			Description: "Reads an entire file/stream into an allocated buffer (contents may be tainted)",
			Assigns:     "return",
		},
		{
			ID:          "zig.fs.File.readToEndAllocOptions",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.readToEndAllocOptions\s*\(`,
			ObjectType:  "std.fs.File",
			MethodName:  "readToEndAllocOptions",
			Description: "Reads an entire file/stream into an allocated buffer with options (contents may be tainted)",
			Assigns:     "return",
		},
		{
			ID:          "zig.io.reader.readUntilDelimiterOrEof",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.readUntilDelimiterOrEof\s*\(`,
			ObjectType:  "std.io.Reader",
			MethodName:  "readUntilDelimiterOrEof",
			Description: "Reads until a delimiter or end-of-stream into a caller buffer (tainted input)",
			Assigns:     "return",
		},
		{
			ID:          "zig.io.reader.readUntilDelimiterOrEofAlloc",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.readUntilDelimiterOrEofAlloc\s*\(`,
			ObjectType:  "std.io.Reader",
			MethodName:  "readUntilDelimiterOrEofAlloc",
			Description: "Reads until a delimiter or end-of-stream with allocation (tainted input)",
			Assigns:     "return",
		},
		{
			ID:          "zig.io.reader.readBoundedBytes",
			Category:    taint.SrcFileRead,
			Language:    rules.LangZig,
			Pattern:     `\.readBoundedBytes\s*\(`,
			ObjectType:  "std.io.Reader",
			MethodName:  "readBoundedBytes",
			Description: "Reads up to N bytes from a reader into a bounded array (tainted input)",
			Assigns:     "return",
		},

		// --- Subprocess output (second-order external input) ---
		// The argv side of these calls is already modeled as a command-injection
		// SINK (zig.process.Child.run / .init). Here we model the RETURN value:
		// RunResult.stdout / .stderr hold whatever the spawned program wrote,
		// which is untrusted external content (e.g. attacker-controlled commit
		// messages from `git log`, filenames, EXIF data from a converter) that
		// can flow on into a downstream command/SQL/path sink. Mirrors the
		// subprocess-output sources already present for JS (Deno.Command /
		// Bun.spawn), Java/Kotlin (ProcessBuilder) and Groovy.
		{
			ID:          "zig.process.child.run.output",
			Category:    taint.SrcExternal,
			Language:    rules.LangZig,
			Pattern:     `std\.process\.Child\.run\s*\(`,
			ObjectType:  "std.process.Child",
			MethodName:  "Child.run",
			Description: "std.process.Child.run RunResult.stdout/.stderr — untrusted output of a spawned subprocess",
			Assigns:     "return",
		},
		{
			ID:          "zig.process.childprocess.exec.output",
			Category:    taint.SrcExternal,
			Language:    rules.LangZig,
			Pattern:     `std\.ChildProcess\.exec\s*\(`,
			ObjectType:  "std.ChildProcess",
			MethodName:  "ChildProcess.exec",
			Description: "std.ChildProcess.exec ExecResult.stdout/.stderr (legacy Zig ≤0.11) — untrusted subprocess output",
			Assigns:     "return",
		},
	}
}
