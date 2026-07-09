package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// jsSinks defines taint sinks for JavaScript/TypeScript.
var jsSinks = []taint.SinkDef{
	// SQL injection
	{ID: "js.sql.query", Category: taint.SnkSQLQuery, Pattern: `\.query\s*\(`, ObjectType: "", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL query with potential injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.sql.execute", Category: taint.SnkSQLQuery, Pattern: `\.execute\s*\(`, ObjectType: "", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL execute with potential injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.sql.prepare", Category: taint.SnkSQLQuery, Pattern: `\.prepare\s*\(`, ObjectType: "", MethodName: "prepare", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL prepared statement with string concatenation", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.knex.raw", Category: taint.SnkSQLQuery, Pattern: `knex\.raw\s*\(`, ObjectType: "knex", MethodName: "raw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Knex raw SQL query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.sequelize.query", Category: taint.SnkSQLQuery, Pattern: `sequelize\.query\s*\(`, ObjectType: "sequelize", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Sequelize raw SQL query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	// sequelize.literal / Sequelize.literal injects a RAW, un-parameterized SQL
	// fragment straight into a generated query — it is the documented escape hatch
	// from Sequelize's parameter binding, so a tainted argument is SQL injection
	// (CWE-89). `sequelize.query` (above) is the raw-query entry; `.literal` is the
	// distinct fragment-injection vector that the generic .query catch-all does not
	// see (the literal is built first, then embedded in a where/attributes clause).
	// ObjectType "Sequelize" matches both the instance receiver (`sequelize`) and
	// the class receiver (`Sequelize`) via the last-component name match. Safe
	// form: pass user values through `replacements`/`bind` or the typed where
	// operators (Op.eq, …), never through literal().
	{ID: "js.sequelize.literal", Category: taint.SnkSQLQuery, Pattern: `(?:[Ss]equelize)\.literal\s*\(`, ObjectType: "Sequelize", MethodName: "literal", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Sequelize.literal(fragment) embeds a raw, un-parameterized SQL fragment into the generated query, bypassing parameter binding — a tainted argument is SQL injection; pass user values via the query's replacements/bind options or typed where operators instead", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	// mysql / mysql2 SqlString.format(sql, values) and mysql.format(...) build a
	// query string by interpolating `values` into `?` placeholders. The DANGER is
	// the FIRST argument (the SQL template): when the template itself is tainted
	// (`mysql.format(userControlledSql, [...])`), the placeholder-escaping of the
	// values does nothing to protect the structure, so the result is SQL injection
	// once it reaches connection.query(...). DangerousArgs=[0] targets the template
	// only — the safe, idiomatic form passes a CONSTANT template with user data in
	// the values array (arg 1), which carries no taint at arg 0 and stays clean.
	// ObjectType "SqlString" / module gate on "mysql" keeps this off unrelated
	// `.format(...)` calls (date/string formatters).
	{ID: "js.mysql.sqlstring.format", Category: taint.SnkSQLQuery, Pattern: `SqlString\.format\s*\(`, ObjectType: "SqlString", MethodName: "format", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "mysql/mysql2 SqlString.format(sql, values) interpolates values into the sql template — when the SQL TEMPLATE itself is tainted, placeholder escaping cannot protect the query structure, so the result is SQL injection; keep the template constant and pass user data only in the values array", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mysql.format", Category: taint.SnkSQLQuery, Pattern: `mysql\.format\s*\(`, ObjectType: "mysql", MethodName: "format", Module: "mysql", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "mysql/mysql2 mysql.format(sql, values) interpolates values into the sql template — when the SQL TEMPLATE is tainted, placeholder escaping cannot protect the query structure, so the result is SQL injection; keep the template constant and pass user data only in the values array", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	// Raw SQL-driver methods NOT covered by the generic .query/.execute/.prepare
	// catch-alls above. (db.exec() is already caught by js.cloudflare.d1.exec via
	// the matcher's "database" substring heuristic, so it is intentionally omitted.)
	{ID: "js.postgres.unsafe", Category: taint.SnkSQLQuery, Pattern: `sql\.unsafe\s*\(`, ObjectType: "sql", MethodName: "unsafe", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "postgres.js sql.unsafe(query) bypasses parameterized tagged-template safety and runs a raw SQL string — a tainted argument is SQL injection; use the tagged-template form sql`...${value}...` which parameterizes values", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.sqlite.run", Category: taint.SnkSQLQuery, Pattern: `(?:db|database|sqlite)\.run\s*\(`, ObjectType: "Database", MethodName: "run", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "node-sqlite3 / bun:sqlite Database.run(sql) executes a raw SQL string — a tainted query is SQL injection; pass user values via ? placeholders and a params array instead", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.sqlite.each", Category: taint.SnkSQLQuery, Pattern: `(?:db|database|sqlite)\.each\s*\(`, ObjectType: "Database", MethodName: "each", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "node-sqlite3 Database.each(sql, ...) executes a raw SQL string per-row — a tainted query is SQL injection; pass user values via ? placeholders and a params array instead", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

	// Microsoft SQL Server (mssql / tedious) — distinct shapes the generic
	// .query/.execute catch-alls miss.
	//
	//   - mssql's `.batch(rawTSQL)` runs a raw T-SQL batch with NO parameter
	//     API (params are not interpolable into .batch), so a tainted argument
	//     is unconditionally SQL injection. The receiver is a `new sql.Request()`
	//     object conventionally named `request`/`req`. Anchored to the
	//     last-component ObjectType `Request`: this strongly-matches a `request.`
	//     receiver and wins over the generic Cassandra `.batch` wildcard
	//     (ObjectType "") via the matcher's strong-vs-weak deferral, while a
	//     Cassandra `client.batch(...)` (receiver "client") keeps falling
	//     through to the wildcard NoSQL entry. `.input('n', type, val).query()`
	//     is the parameterized form and is cleared by js.mssql.input below.
	{ID: "js.mssql.request.batch", Category: taint.SnkSQLQuery, Pattern: `\.batch\s*\(`, ObjectType: "Request", MethodName: "batch", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "mssql Request.batch(tsql) executes a raw T-SQL batch — .batch has no parameter API, so a tainted argument is SQL injection; use request.input('name', type, value) bindings with a parameterized .query() instead", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	// NOTE: tedious `new Request(sql, callback)` is intentionally NOT modeled —
	// the constructor name `Request` collides with the widely-used Fetch/undici
	// `new Request(url)` and, with no receiver to bind a module gate to, a bare
	// entry would mislabel those as SQLi. mssql's `.batch` (above) is the precise,
	// non-colliding T-SQL shape.

	// Command injection
	//
	// `.exec()` is heavily overloaded in JS: RegExp.prototype.exec, Drizzle
	// query .exec(), Mongoose .exec(), Vite/Rollup plugins, etc. To avoid
	// firing on `someRegex.exec(html)` (the dominant FP shape in real-world
	// scans — Ghost build-time Vite plugins, etc.), command-exec sinks bind
	// the receiver to a known child_process / shell module:
	//   - `child_process.exec(...)` — explicit Node built-in
	//   - `cp.exec(...)` — common alias (`const cp = require('child_process')`)
	//   - `shelljs.exec(...)` — shelljs library
	//   - bare `exec(...)` — only when the call has NO receiver (`@global`),
	//     i.e. it's a top-level identifier brought in via destructuring
	//     (`const { exec } = require('child_process')`), not a method call.
	// `myRegex.exec(input)` falls through all of these (receiver "myRegex"
	// matches none of the modules, and is not empty so `@global` rejects it).
	{ID: "js.child_process.exec", Category: taint.SnkCommand, Pattern: `child_process\.exec\s*\(`, ObjectType: "child_process", MethodName: "exec", Module: "child_process", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via child_process.exec", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.child_process.execsync", Category: taint.SnkCommand, Pattern: `child_process\.execSync\s*\(`, ObjectType: "child_process", MethodName: "execSync", Module: "child_process", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Synchronous OS command execution", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.child_process.spawn", Category: taint.SnkCommand, Pattern: `child_process\.spawn\s*\(`, ObjectType: "child_process", MethodName: "spawn", Module: "child_process", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command spawn", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	// `cp` alias (`const cp = require('child_process')`).
	{ID: "js.cp.exec", Category: taint.SnkCommand, Pattern: `\bcp\.exec\s*\(`, ObjectType: "cp", MethodName: "exec", Module: "cp", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via cp.exec (child_process alias)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.cp.execsync", Category: taint.SnkCommand, Pattern: `\bcp\.execSync\s*\(`, ObjectType: "cp", MethodName: "execSync", Module: "cp", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Synchronous OS command execution via cp.execSync (child_process alias)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.cp.execfile", Category: taint.SnkCommand, Pattern: `\bcp\.execFile\s*\(`, ObjectType: "cp", MethodName: "execFile", Module: "cp", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via cp.execFile (child_process alias)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.cp.execfilesync", Category: taint.SnkCommand, Pattern: `\bcp\.execFileSync\s*\(`, ObjectType: "cp", MethodName: "execFileSync", Module: "cp", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Synchronous OS command execution via cp.execFileSync (child_process alias)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	// shelljs library (`require('shelljs').exec(...)`).
	{ID: "js.shelljs.exec", Category: taint.SnkCommand, Pattern: `\bshelljs?\.exec\s*\(`, ObjectType: "shelljs", MethodName: "exec", Module: "shelljs", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via shelljs.exec", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	// Bare top-level identifiers (e.g. `const { exec } = require('child_process')`).
	// `@global` requires the call site has no receiver, so RegExp.exec /
	// drizzle.exec / mongoose.exec etc. do NOT match.
	{ID: "js.exec.short", Category: taint.SnkCommand, Pattern: `\bexec\s*\(`, ObjectType: "@global", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via bare exec() (top-level identifier)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.execsync.short", Category: taint.SnkCommand, Pattern: `\bexecSync\s*\(`, ObjectType: "@global", MethodName: "execSync", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Synchronous OS command execution via bare execSync() (top-level identifier)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.spawn.short", Category: taint.SnkCommand, Pattern: `\bspawn\s*\(`, ObjectType: "", MethodName: "spawn", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command spawn via spawn()", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// Code evaluation
	{ID: "js.eval", Category: taint.SnkEval, Pattern: `\beval\s*\(`, ObjectType: "", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Dynamic code evaluation via eval()", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.new.function", Category: taint.SnkEval, Pattern: `new\s+Function\s*\(`, ObjectType: "", MethodName: "Function", DangerousArgs: []int{-1}, Severity: rules.Critical, Description: "Dynamic function construction", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	// setTimeout / setInterval are only dangerous (legacy implicit eval) when
	// arg 0 is a STRING — passing a function is the normal modern usage and
	// not a sink. Scoped to @global so member calls like
	// `socket.setTimeout(5000)` or `req.setTimeout(timeoutMs)` — which are
	// numeric Node.js/DOM timeout setters, not eval — don't trip the
	// catalog. Arg-shape filtering (suppress when arg 0 is an arrow/function
	// expression or non-string literal) is enforced in
	// `timerArgZeroLooksLikeString` in tsflow/walker.go to keep the
	// JS-specific receiver/shape rules in one place. Together they remove
	// the dominant FP shape: `setTimeout(() => ..., 500)`.
	{ID: "js.settimeout.string", Category: taint.SnkEval, Pattern: `setTimeout\s*\(\s*["'\x60]`, ObjectType: "@global", MethodName: "setTimeout", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "setTimeout with string argument (implicit eval)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.setinterval.string", Category: taint.SnkEval, Pattern: `setInterval\s*\(\s*["'\x60]`, ObjectType: "@global", MethodName: "setInterval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "setInterval with string argument (implicit eval)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// XSS
	{ID: "js.dom.innerhtml.write", Category: taint.SnkHTMLOutput, Pattern: `\.innerHTML\s*=`, ObjectType: "HTMLElement", MethodName: "innerHTML", DangerousArgs: []int{0}, Severity: rules.High, Description: "innerHTML assignment (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dom.document.write", Category: taint.SnkHTMLOutput, Pattern: `document\.write\s*\(`, ObjectType: "document", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "document.write (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.react.dangerouslysetinnerhtml", Category: taint.SnkHTMLOutput, Pattern: `dangerouslySetInnerHTML`, ObjectType: "", MethodName: "dangerouslySetInnerHTML", DangerousArgs: []int{0}, Severity: rules.High, Description: "React dangerouslySetInnerHTML (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.send", Category: taint.SnkHTMLOutput, Pattern: `res\.send\s*\(`, ObjectType: "Response", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.High, Description: "Express response send (potential XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.write", Category: taint.SnkHTMLOutput, Pattern: `res\.write\s*\(`, ObjectType: "Response", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "Express response write (potential XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

	// Express response sinks
	{ID: "js.express.res.render", Category: taint.SnkEval, Pattern: `res\.render\s*\(`, ObjectType: "Response", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Express template path injection via res.render", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.sendfile", Category: taint.SnkFileWrite, Pattern: `res\.sendFile\s*\(`, ObjectType: "Response", MethodName: "sendFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Path traversal via res.sendFile", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.express.res.download", Category: taint.SnkFileWrite, Pattern: `res\.download\s*\(`, ObjectType: "Response", MethodName: "download", DangerousArgs: []int{0}, Severity: rules.High, Description: "Path traversal via res.download", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// File operations
	{ID: "js.fs.writefile", Category: taint.SnkFileWrite, Pattern: `fs\.writeFile\s*\(`, ObjectType: "fs", MethodName: "writeFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "File write with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.readfile.sink", Category: taint.SnkFileWrite, Pattern: `fs\.readFile\s*\(`, ObjectType: "fs", MethodName: "readFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "File read with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.readfile.bare", Category: taint.SnkFileWrite, Pattern: `\breadFile\s*\(`, ObjectType: "", MethodName: "readFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "File read with potential path traversal (bare import)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.unlink", Category: taint.SnkFileWrite, Pattern: `fs\.unlink\s*\(`, ObjectType: "fs", MethodName: "unlink", DangerousArgs: []int{0}, Severity: rules.High, Description: "File deletion with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.createreadstream", Category: taint.SnkFileWrite, Pattern: `fs\.createReadStream\s*\(`, ObjectType: "fs", MethodName: "createReadStream", DangerousArgs: []int{0}, Severity: rules.High, Description: "File stream with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// Redirect
	{ID: "js.express.res.redirect", Category: taint.SnkRedirect, Pattern: `res\.redirect\s*\(`, ObjectType: "Response", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via res.redirect", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.dom.window.location.assign", Category: taint.SnkRedirect, Pattern: `window\.location\s*=`, ObjectType: "window", MethodName: "location", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via window.location assignment", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.dom.location.href.assign", Category: taint.SnkRedirect, Pattern: `location\.href\s*=`, ObjectType: "location", MethodName: "href", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via location.href assignment", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

	// SSRF
	{ID: "js.fetch.ssrf", Category: taint.SnkURLFetch, Pattern: `\bfetch\s*\(`, ObjectType: "@global", MethodName: "fetch", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via global fetch() (Fetch API; excludes ORM .fetch() method calls)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.axios.get.ssrf", Category: taint.SnkURLFetch, Pattern: `axios\.get\s*\(`, ObjectType: "axios", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via axios.get", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.http.get.ssrf", Category: taint.SnkURLFetch, Pattern: `http\.get\s*\(`, ObjectType: "http", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via http.get", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// undici — Node.js built-in HTTP/1.1 client (Node 18+, powers global fetch).
	// Scoped to receiver "undici" so destructured `import { request } from 'undici'`
	// callers fall through to the existing js.request.ssrf catch-all. Must precede
	// js.request.ssrf below so qualified `undici.request(...)` resolves to the
	// undici-specific entry first (matchSinkCall returns the first match in slice
	// order). CVE history: CVE-2023-23936, CVE-2023-24807, CVE-2023-45143.
	{ID: "js.undici.request", Category: taint.SnkURLFetch, Pattern: `\bundici\.request\s*\(`, ObjectType: "undici", MethodName: "request", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via undici.request() with user-controlled URL/origin", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.undici.fetch", Category: taint.SnkURLFetch, Pattern: `\bundici\.fetch\s*\(`, ObjectType: "undici", MethodName: "fetch", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via undici.fetch() with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.undici.stream", Category: taint.SnkURLFetch, Pattern: `\bundici\.stream\s*\(`, ObjectType: "undici", MethodName: "stream", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via undici.stream() with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.undici.pipeline", Category: taint.SnkURLFetch, Pattern: `\bundici\.pipeline\s*\(`, ObjectType: "undici", MethodName: "pipeline", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via undici.pipeline() with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.undici.connect", Category: taint.SnkURLFetch, Pattern: `\bundici\.connect\s*\(`, ObjectType: "undici", MethodName: "connect", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via undici.connect() HTTP CONNECT tunnel with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.undici.upgrade", Category: taint.SnkURLFetch, Pattern: `\bundici\.upgrade\s*\(`, ObjectType: "undici", MethodName: "upgrade", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via undici.upgrade() HTTP/1.1 Upgrade with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.undici.client.new", Category: taint.SnkURLFetch, Pattern: `new\s+undici\.Client\s*\(`, ObjectType: "undici", MethodName: "Client", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via new undici.Client(url) — base origin from user input", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.undici.pool.new", Category: taint.SnkURLFetch, Pattern: `new\s+undici\.Pool\s*\(`, ObjectType: "undici", MethodName: "Pool", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via new undici.Pool(url) — base origin from user input", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Reverse-proxy SSRF (node-http-proxy / http-proxy-middleware). The proxy
	// target/router is the forwarding destination — when it flows from request
	// input, an attacker controls where the server connects, i.e. SSRF. Each
	// sink is receiver/module anchored, and the dangerous slot is the options
	// OBJECT (matcher's nodeIsTainted recurses into `{target: <tainted>}` /
	// `{router: <tainted>}`); the common static-config proxy (constant target)
	// carries no taint and never fires.
	//   - httpProxy.createProxyServer({ target }) — node-http-proxy factory.
	{ID: "js.httpproxy.createproxyserver", Category: taint.SnkURLFetch, Pattern: `\.createProxyServer\s*\(`, ObjectType: "httpProxy", MethodName: "createProxyServer", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via http-proxy createProxyServer({ target }) — a request-controlled target lets an attacker make the server proxy to an arbitrary origin; pin the target to a fixed allowlisted upstream", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	//   - proxy.web(req, res, { target }) — per-request forward; opts is arg 2.
	{ID: "js.httpproxy.web", Category: taint.SnkURLFetch, Pattern: `\.web\s*\(`, ObjectType: "proxy", MethodName: "web", DangerousArgs: []int{2}, Severity: rules.High, Description: "SSRF via http-proxy proxy.web(req, res, { target }) — a request-controlled target proxies to an attacker-chosen origin; validate the target against an upstream allowlist", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	//   - createProxyMiddleware({ target | router }) — http-proxy-middleware.
	//     Bound to @global (bare top-level call from a destructured import); the
	//     name is distinctive to this one package, so no module gate is needed
	//     (and a bare call has no receiver for RequireModule to bind anyway).
	{ID: "js.httpproxymiddleware.create", Category: taint.SnkURLFetch, Pattern: `\bcreateProxyMiddleware\s*\(`, ObjectType: "@global", MethodName: "createProxyMiddleware", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via http-proxy-middleware createProxyMiddleware({ target | router }) — a request-controlled target/router forwards to an attacker-chosen origin; resolve the upstream from a fixed allowlist, not from request data", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	{ID: "js.request.ssrf", Category: taint.SnkURLFetch, Pattern: `\brequest\s*\(`, ObjectType: "", MethodName: "request", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via request()", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Deserialization
	{ID: "js.json.parse", Category: taint.SnkDeserialize, Pattern: `JSON\.parse\s*\(`, ObjectType: "JSON", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.Low, Description: "JSON.parse (low risk deserialization)", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.node.serialize", Category: taint.SnkDeserialize, Pattern: `(?:unserialize|deserialize)\s*\(`, ObjectType: "", MethodName: "unserialize/deserialize", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Unsafe deserialization via node-serialize", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures", Advisory: "CVE-2017-5941 (node-serialize) — unserialize() of untrusted input executes embedded IIFE functions (RCE)", AdvisoryID: "CVE-2017-5941"},
	{ID: "js.yaml.load", Category: taint.SnkDeserialize, Pattern: `yaml\.load\s*\(`, ObjectType: "yaml", MethodName: "load", DangerousArgs: []int{0}, Severity: rules.High, Description: "Unsafe YAML deserialization via js-yaml.load", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.yaml.loadall", Category: taint.SnkDeserialize, Pattern: `yaml\.loadAll\s*\(`, ObjectType: "yaml", MethodName: "loadAll", DangerousArgs: []int{0}, Severity: rules.High, Description: "Unsafe YAML deserialization via js-yaml.loadAll — iterates multiple documents from untrusted input", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.v8.deserialize", Category: taint.SnkDeserialize, Pattern: `v8\.deserialize\s*\(`, ObjectType: "v8", MethodName: "deserialize", DangerousArgs: []int{0}, Severity: rules.High, Description: "Node.js v8.deserialize() of untrusted binary data — prototype pollution and type confusion risks", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.cryo.parse", Category: taint.SnkDeserialize, Pattern: `cryo\.parse\s*\(`, ObjectType: "cryo", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "cryo.parse() deserializes functions and objects — untrusted input leads to RCE", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.msgpack.decode.sink", Category: taint.SnkDeserialize, Pattern: `msgpack\.decode\s*\(`, ObjectType: "msgpack", MethodName: "decode", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "MessagePack decode of untrusted binary — type confusion and prototype pollution risk (CVE-2021-23410)", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.msgpack.unpack.sink", Category: taint.SnkDeserialize, Pattern: `msgpack\.unpack\s*\(`, ObjectType: "msgpack", MethodName: "unpack", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "msgpack-lite unpack of untrusted binary — arbitrary object construction from wire data", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.bson.deserialize.sink", Category: taint.SnkDeserialize, Pattern: `BSON\.deserialize\s*\(`, ObjectType: "BSON", MethodName: "deserialize", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "BSON deserialization of untrusted binary — arbitrary object construction from wire format", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "js.cbor.decode.sink", Category: taint.SnkDeserialize, Pattern: `cbor\.decode\s*\(`, ObjectType: "cbor", MethodName: "decode", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "CBOR decode of untrusted binary — arbitrary nested structures from external data", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// XML External Entity (XXE) — unsafe XML parsing (CWE-611)
	{ID: "js.libxmljs.parsexml", Category: taint.SnkDeserialize, Pattern: `libxmljs\.parseXml\s*\(`, ObjectType: "libxmljs", MethodName: "parseXml", DangerousArgs: []int{0}, Severity: rules.High, Description: "libxmljs.parseXml() on untrusted input — DTD processing enables XXE / billion laughs unless nonet:true and dtdload:false are set (CVE-2022-40895)", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.libxmljs.parsexmlstring", Category: taint.SnkDeserialize, Pattern: `libxmljs\.parseXmlString\s*\(`, ObjectType: "libxmljs", MethodName: "parseXmlString", DangerousArgs: []int{0}, Severity: rules.High, Description: "libxmljs.parseXmlString() (deprecated) on untrusted input — same XXE risk as parseXml", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.libxmljs2.parsexml", Category: taint.SnkDeserialize, Pattern: `libxmljs2\.parseXml\s*\(`, ObjectType: "libxmljs2", MethodName: "parseXml", DangerousArgs: []int{0}, Severity: rules.High, Description: "libxmljs2.parseXml() (fork) on untrusted input — inherits libxml2 XXE / entity-expansion risks", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.xml2js.parsestring", Category: taint.SnkDeserialize, Pattern: `xml2js\.parseString\s*\(`, ObjectType: "xml2js", MethodName: "parseString", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "xml2js.parseString() on untrusted input — entity expansion enabled by default (billion-laughs DoS, CWE-776)", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.xml2js.parsestringpromise", Category: taint.SnkDeserialize, Pattern: `xml2js\.parseStringPromise\s*\(`, ObjectType: "xml2js", MethodName: "parseStringPromise", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "xml2js.parseStringPromise() on untrusted input — same entity-expansion risk as parseString", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.plist.parse", Category: taint.SnkDeserialize, Pattern: `plist\.parse\s*\(`, ObjectType: "plist", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "plist.parse() on untrusted XML plist — underlying XML parsing is XXE-exposed", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	// node-expat — a streaming SAX parser over libexpat with NO built-in entity-
	// expansion limits. `parser.parse(xml)` / `parser.write(xml)` on untrusted XML
	// is exposed to the billion-laughs / quadratic-blowup entity-expansion DoS
	// (CWE-611/CWE-776): a tiny document with nested entity definitions expands to
	// gigabytes and exhausts memory. Anchored to ObjectType "node-expat" plus the
	// conventional parser receiver name (`parser`) so it does not collide with
	// other `.parse(...)`/`.write(...)` calls (JSON.parse, stream.write). Safe
	// form: cap input size and reject DOCTYPE/entity declarations before parsing,
	// or use a parser with entity limits.
	{ID: "js.nodeexpat.parse", Category: taint.SnkDeserialize, Pattern: `(?:parser|expat)\.parse\s*\(`, ObjectType: "node-expat", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "node-expat parser.parse() on untrusted XML — libexpat has no entity-expansion limit, so a crafted document triggers the billion-laughs / entity-expansion DoS (CWE-776); cap input size and reject DOCTYPE/entity declarations before parsing", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	// XML parsing (CWE-611 XXE / prototype pollution / billion laughs)
	{ID: "js.libxmljs.parsexml", Category: taint.SnkDeserialize, Pattern: `libxmljs\.parseXml(?:String)?\s*\(`, ObjectType: "libxmljs", MethodName: "parseXml/parseXmlString", DangerousArgs: []int{0}, Severity: rules.High, Description: "libxmljs parseXml/parseXmlString of untrusted XML — XXE via {noent: true} resolves external entities and file:// URLs (CVE-2021-21341, CVE-2022-29017)", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.libxmljs2.parsexml", Category: taint.SnkDeserialize, Pattern: `libxmljs2\.parseXml(?:String)?\s*\(`, ObjectType: "libxmljs2", MethodName: "parseXml/parseXmlString", DangerousArgs: []int{0}, Severity: rules.High, Description: "libxmljs2 parseXml/parseXmlString of untrusted XML — XXE via {noent: true} resolves external entities and file:// URLs", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.xml2js.parsestring", Category: taint.SnkDeserialize, Pattern: `xml2js\.parseString(?:Promise|Sync)?\s*\(`, ObjectType: "xml2js", MethodName: "parseString/parseStringPromise/parseStringSync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "xml2js parseString of untrusted XML — prototype pollution via crafted __proto__ attributes (CVE-2023-0842)", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},

	// Template injection
	{ID: "js.ejs.render", Category: taint.SnkTemplate, Pattern: `ejs\.render\s*\(`, ObjectType: "ejs", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "EJS template injection", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.pug.render", Category: taint.SnkTemplate, Pattern: `pug\.render\s*\(`, ObjectType: "pug", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Pug template injection", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	// --- Handlebars SSTI (CVE-2019-19919; CWE-1336 / CWE-94 family) ---
	// Compiling a request-controlled template body permits attacker JS to
	// execute at render time. Use precompiled templates from trusted code at
	// startup; the request must only choose between them by name.
	{ID: "BATOU-JSTS-SSTI-001", Category: taint.SnkTemplate, Pattern: `Handlebars\.compile\s*\(`, ObjectType: "Handlebars", MethodName: "compile", Module: "Handlebars", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.High, Description: "Handlebars.compile(source) with a request-controlled template body — attacker can break out of the sandbox via __proto__/constructor lookups (CVE-2019-19919)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "BATOU-JSTS-SSTI-001b", Category: taint.SnkTemplate, Pattern: `handlebars\.compile\s*\(`, ObjectType: "handlebars", MethodName: "compile", Module: "handlebars", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.High, Description: "handlebars.compile() lowercase-alias receiver — same SSTI risk as Handlebars.compile (CVE-2019-19919)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "BATOU-JSTS-SSTI-002", Category: taint.SnkTemplate, Pattern: `Handlebars\.precompile\s*\(`, ObjectType: "Handlebars", MethodName: "precompile", Module: "Handlebars", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.High, Description: "Handlebars.precompile(source) on a request-controlled template body — same lookup-traversal risk as compile()", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "BATOU-JSTS-SSTI-002b", Category: taint.SnkTemplate, Pattern: `handlebars\.precompile\s*\(`, ObjectType: "handlebars", MethodName: "precompile", Module: "handlebars", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.High, Description: "handlebars.precompile() lowercase-alias receiver", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

	// --- lodash _.template — code injection (CVE-2021-23337; CWE-94) ---
	// _.template(source) compiles the source via new Function(...) at runtime.
	// User-controlled template body is direct RCE — flagged as Critical and
	// categorised under SnkEval so it's treated as code-injection (CWE-94),
	// not just template-injection.
	{ID: "BATOU-JSTS-CODE-010", Category: taint.SnkEval, Pattern: `_\.template\s*\(`, ObjectType: "_", MethodName: "template", Module: "_", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Lodash _.template() compiles the template via new Function(...) — user-controlled template body is direct RCE (CVE-2021-23337)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection", Advisory: "CVE-2021-23337 (lodash) — _.template() compiles the template body via new Function(); attacker-controlled input is remote code execution; upgrade to lodash >= 4.17.21", AdvisoryID: "CVE-2021-23337"},
	{ID: "BATOU-JSTS-CODE-010b", Category: taint.SnkEval, Pattern: `lodash\.template\s*\(`, ObjectType: "lodash", MethodName: "template", Module: "lodash", RequireModule: true, DangerousArgs: []int{0}, Severity: rules.Critical, Description: "lodash.template() namespaced form — same new-Function() RCE risk as _.template (CVE-2021-23337)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection", Advisory: "CVE-2021-23337 (lodash) — lodash.template() compiles via new Function(); attacker-controlled input is remote code execution; upgrade to lodash >= 4.17.21", AdvisoryID: "CVE-2021-23337"},
	{ID: "js.nunjucks.renderstring", Category: taint.SnkTemplate, Pattern: `nunjucks\.renderString\s*\(`, ObjectType: "nunjucks", MethodName: "renderString", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Nunjucks renderString() with user-controlled template — SSTI leading to RCE via constructor chain", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dot.template", Category: taint.SnkTemplate, Pattern: `doT\.template\s*\(`, ObjectType: "doT", MethodName: "template", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "doT.template() compiles via new Function() — user-controlled template leads to RCE (CVE-2021-25075)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mustache.render", Category: taint.SnkTemplate, Pattern: `Mustache\.render\s*\(`, ObjectType: "Mustache", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Mustache.render() with user-controlled template — logic-less but enables data exfiltration via {{secret}} tags", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.ejs.renderfile", Category: taint.SnkTemplate, Pattern: `ejs\.renderFile\s*\(`, ObjectType: "ejs", MethodName: "renderFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "EJS renderFile() with user-controlled path — path traversal + template injection", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.eta.render", Category: taint.SnkTemplate, Pattern: `eta\.render(?:String)?\s*\(`, ObjectType: "eta", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.High, Description: "Eta template render with user-controlled template — SSTI (EJS-compatible engine)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.liquidjs.parseandrender", Category: taint.SnkTemplate, Pattern: `\.parseAndRender\s*\(`, ObjectType: "", MethodName: "parseAndRender", DangerousArgs: []int{0}, Severity: rules.High, Description: "LiquidJS parseAndRender() with user-controlled template — SSTI in Shopify Liquid port", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.squirrelly.render", Category: taint.SnkTemplate, Pattern: `(?:Sqrl|sqrl)\.render\s*\(`, ObjectType: "Sqrl", MethodName: "render", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Squirrelly Sqrl.render() with user-controlled template — the template body is compiled to a JS function, so a tainted template is SSTI leading to RCE (CVE-2021-32819, GHSL-2021-023)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.squirrelly.compile", Category: taint.SnkTemplate, Pattern: `(?:Sqrl|sqrl)\.compile\s*\(`, ObjectType: "Sqrl", MethodName: "compile", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Squirrelly Sqrl.compile() with user-controlled template — compiles the template body into a callable JS function (new Function), so a tainted template is SSTI leading to RCE (CVE-2021-32819)", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

	// Header injection
	{ID: "js.express.res.setheader", Category: taint.SnkHeader, Pattern: `res\.setHeader\s*\(`, ObjectType: "Response", MethodName: "setHeader", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via res.setHeader", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.header", Category: taint.SnkHeader, Pattern: `res\.header\s*\(`, ObjectType: "Response", MethodName: "header", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via res.header", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.node.response.writehead", Category: taint.SnkHeader, Pattern: `\.writeHead\s*\(`, ObjectType: "Response", MethodName: "writeHead", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via Node.js response.writeHead(status, headers)", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.set", Category: taint.SnkHeader, Pattern: `res\.set\s*\(`, ObjectType: "Response", MethodName: "set", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via Express res.set(name, value)", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.express.res.append", Category: taint.SnkHeader, Pattern: `res\.append\s*\(`, ObjectType: "Response", MethodName: "append", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via Express res.append(name, value)", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.fastify.reply.header", Category: taint.SnkHeader, Pattern: `reply\.header\s*\(`, ObjectType: "FastifyReply", MethodName: "header", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via Fastify reply.header(name, value)", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.fastify.reply.headers", Category: taint.SnkHeader, Pattern: `reply\.headers\s*\(`, ObjectType: "FastifyReply", MethodName: "headers", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP header injection via Fastify reply.headers(object)", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.koa.ctx.set", Category: taint.SnkHeader, Pattern: `ctx\.set\s*\(`, ObjectType: "KoaContext", MethodName: "set", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via Koa ctx.set(name, value)", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.koa.ctx.append", Category: taint.SnkHeader, Pattern: `ctx\.append\s*\(`, ObjectType: "KoaContext", MethodName: "append", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP header injection via Koa ctx.append(name, value)", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

	// Prisma raw SQL
	{ID: "js.prisma.queryraw", Category: taint.SnkSQLQuery, Pattern: `\$queryRaw\s*\(`, ObjectType: "PrismaClient", MethodName: "$queryRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Prisma raw SQL query (bypasses parameterization)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.prisma.executeraw", Category: taint.SnkSQLQuery, Pattern: `\$executeRaw\s*\(`, ObjectType: "PrismaClient", MethodName: "$executeRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Prisma raw SQL execute (bypasses parameterization)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.prisma.queryrawunsafe", Category: taint.SnkSQLQuery, Pattern: `\$queryRawUnsafe\s*\(`, ObjectType: "PrismaClient", MethodName: "$queryRawUnsafe", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Prisma unsafe raw query with string interpolation", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.prisma.executerawunsafe", Category: taint.SnkSQLQuery, Pattern: `\$executeRawUnsafe\s*\(`, ObjectType: "PrismaClient", MethodName: "$executeRawUnsafe", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Prisma unsafe raw execute with string interpolation", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

	// MongoDB / Firestore / CouchDB NoSQL injection (CWE-943) — categorised
	// as SnkNoSQL so taint-based negative confirmation works for this CWE.
	// $where is server-side JavaScript evaluation; the concat/template
	// variants catch string-construction of $where bodies.
	{ID: "js.mongoose.where", Category: taint.SnkNoSQL, Pattern: `\.\$where\s*\(`, ObjectType: "MongooseQuery", MethodName: "$where", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB $where operator (JS code execution)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.where.concat", Category: taint.SnkNoSQL, Pattern: `\$where\s*:\s*['"][^'"]*['"]\s*\+`, ObjectType: "MongooseQuery", MethodName: "$where (concat)", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB $where with string concatenation (NoSQL code injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.where.template", Category: taint.SnkNoSQL, Pattern: `\$where\s*:\s*` + "`[^`]*\\$\\{", ObjectType: "MongooseQuery", MethodName: "$where (template)", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB $where with template literal interpolation (NoSQL code injection)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	// Firestore: tainted document path / collection name → IDOR or
	// cross-tenant access. Tightened to known Firestore client identifiers
	// to avoid collision with `db.doc` etc. in non-Firestore code.
	{ID: "js.firestore.doc.tainted", Category: taint.SnkNoSQL, Pattern: `(?:firestore|firestoreDb|getFirestore\(\))\.doc\s*\(`, ObjectType: "Firestore", MethodName: "doc", DangerousArgs: []int{0}, Severity: rules.High, Description: "Firestore .doc(path) with tainted document path — IDOR / wrong-document access", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.firestore.collection.tainted", Category: taint.SnkNoSQL, Pattern: `(?:firestore|firestoreDb|getFirestore\(\))\.collection\s*\(`, ObjectType: "Firestore", MethodName: "collection", DangerousArgs: []int{0}, Severity: rules.High, Description: "Firestore .collection(name) with tainted collection name — cross-tenant access risk", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	// CouchDB / Cloudant: temporary view with user-controlled `map` function
	// allows server-side JS execution.
	{ID: "js.couchdb.view.fn", Category: taint.SnkNoSQL, Pattern: `\.view\s*\(\s*\{[^}]*map\s*:`, ObjectType: "Database", MethodName: "view (map fn)", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "CouchDB temporary view with tainted map function (server-side JS execution)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},

	// CSV / spreadsheet formula injection (CWE-1236) — untrusted data
	// serialized into a CSV/spreadsheet cell where a value beginning with
	// =, +, -, @, tab or CR is interpreted as a formula by Excel /
	// LibreOffice / Google Sheets when the file is opened (DDE / command
	// execution on the viewer's machine). The dangerous arg is the
	// row/record data being serialized. Only distinctive library calls are
	// listed: `Papa.unparse` (receiver-checked) and `fast-csv`
	// `writeToString` (distinctive method name). Bare `stringify(...)` /
	// `parse(...)` are deliberately excluded — too generic to bind without
	// import resolution. (A `json2csv` `Parser.parse` sink was dropped:
	// in tsflow the receiver matcher treats any name that is a prefix of
	// `parser` as a match, so a generic XML/HTML/date `parser.parse(...)`
	// mis-fires as CWE-1236, and there is no clean way to bind it to the
	// json2csv module — CSV injection is a serialize concern, not a parse
	// one.)
	{ID: "js.papaparse.unparse", Category: taint.SnkCSV, Pattern: `(?:Papa|papaparse)\.unparse\s*\(`, ObjectType: "Papa", MethodName: "unparse", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "PapaParse Papa.unparse() with user-controlled rows — cell values beginning with =, +, -, @ become formulas when the CSV is opened in a spreadsheet (CSV/formula injection)", CWEID: "CWE-1236", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.fastcsv.writetostring", Category: taint.SnkCSV, Pattern: `\.writeToString\s*\(`, ObjectType: "", MethodName: "writeToString", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "fast-csv writeToString() with user-controlled rows — cell values beginning with =, +, -, @ become formulas when the CSV is opened in a spreadsheet (CSV/formula injection)", CWEID: "CWE-1236", OWASPCategory: "A03:2021-Injection"},

	// Unrestricted file upload (CWE-434) — an uploaded file moved/persisted
	// without validating its extension / MIME type / content lets an
	// attacker drop a webshell. The sink is the persist/move call; either
	// the uploaded-file handle (receiver) or the destination path being
	// tainted produces a flow. `express-fileupload`: req.files.<name>.mv(path)
	// — `mv` is a distinctive method name. `multer({...})` is the config site
	// (bare global call, no receiver). Bare `upload.single/.array/.fields(...)`
	// are deliberately excluded: `single/array/fields` are too generic to bind
	// without import resolution, and the conventional middleware var name
	// (`upload`) is not a prefix of "Multer".
	{ID: "js.expressfileupload.mv", Category: taint.SnkUpload, Pattern: `\.mv\s*\(`, ObjectType: "", MethodName: "mv", DangerousArgs: []int{0}, Severity: rules.High, Description: "express-fileupload UploadedFile.mv() moving a req.files[...] upload to a destination path without extension/MIME validation (unrestricted file upload)", CWEID: "CWE-434", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.multer.constructor", Category: taint.SnkUpload, Pattern: `\bmulter\s*\(`, ObjectType: "@global", MethodName: "multer", DangerousArgs: []int{0}, Severity: rules.High, Description: "multer({...}) configured without a fileFilter / limits — accepts arbitrary uploaded file types and sizes (unrestricted file upload)", CWEID: "CWE-434", OWASPCategory: "A04:2021-Insecure Design"},
	// History: a previous bare `\.find\s*\(` sink matched every `.find(` call
	// in JS/TS (Array.prototype.find, Vue Test Utils, Knex/Sequelize/Prisma
	// ORM finders) and produced massive FPs (Strapi alone: 23 FPs). It was
	// removed; the Mongo CRUD finders below RESTORE coverage for the dominant
	// Express+Mongo NoSQL-injection shape — `collection.find({$where: tainted})`
	// / `find(taintedReqObject)` — but are gated by RequiresArgShape:
	// ArgShapeContainer (see argshape.go `jsArgIsNoSQLContainerShape`). That gate
	// fires ONLY when the filter is an object literal carrying a top-level
	// `$`-operator key, or a whole tainted object/variable; the pervasive SAFE
	// parameterized equality form `find({_id: req.params.id})` and the
	// Array.prototype.find callback `arr.find(x => …)` both drop out, so the
	// historical FP class does not return. The Patterns are the bare method name
	// so weakSinkPatternOK re-validates the wildcard-ObjectType match.
	{ID: "js.mongodb.find", Category: taint.SnkNoSQL, Pattern: `\.find\s*\(`, ObjectType: "", MethodName: "find", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.High, Description: "MongoDB Collection.find() with a user-controlled query filter carrying `$`-operators (`{$where: …}` server-side JS execution, or a whole attacker-controlled filter object enabling operator injection like `{$ne: null}`) — NoSQL injection; coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongodb.findone", Category: taint.SnkNoSQL, Pattern: `\.findOne\s*\(`, ObjectType: "", MethodName: "findOne", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.Critical, Description: "MongoDB Collection.findOne() with a user-controlled query filter carrying `$`-operators or a whole attacker-controlled filter object — NoSQL injection (auth-bypass via `{$ne: null}` / `$where` server-side JS execution); coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongodb.findoneandupdate", Category: taint.SnkNoSQL, Pattern: `\.findOneAndUpdate\s*\(`, ObjectType: "", MethodName: "findOneAndUpdate", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.Critical, Description: "MongoDB Collection.findOneAndUpdate() with a user-controlled query filter carrying `$`-operators or a whole attacker-controlled filter object — NoSQL injection; coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongodb.findoneandreplace", Category: taint.SnkNoSQL, Pattern: `\.findOneAndReplace\s*\(`, ObjectType: "", MethodName: "findOneAndReplace", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.Critical, Description: "MongoDB Collection.findOneAndReplace() with a user-controlled query filter carrying `$`-operators or a whole attacker-controlled filter object — NoSQL injection; coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongodb.findoneanddelete", Category: taint.SnkNoSQL, Pattern: `\.findOneAndDelete\s*\(`, ObjectType: "", MethodName: "findOneAndDelete", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.Critical, Description: "MongoDB Collection.findOneAndDelete() with a user-controlled query filter carrying `$`-operators or a whole attacker-controlled filter object — NoSQL injection; coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongodb.updateone", Category: taint.SnkNoSQL, Pattern: `\.updateOne\s*\(`, ObjectType: "", MethodName: "updateOne", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.Critical, Description: "MongoDB Collection.updateOne() with a user-controlled query filter (arg 0) carrying `$`-operators or a whole attacker-controlled filter object — NoSQL injection; coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongodb.updatemany", Category: taint.SnkNoSQL, Pattern: `\.updateMany\s*\(`, ObjectType: "", MethodName: "updateMany", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.Critical, Description: "MongoDB Collection.updateMany() with a user-controlled query filter (arg 0) carrying `$`-operators or a whole attacker-controlled filter object — NoSQL injection; coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongodb.deleteone", Category: taint.SnkNoSQL, Pattern: `\.deleteOne\s*\(`, ObjectType: "", MethodName: "deleteOne", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.Critical, Description: "MongoDB Collection.deleteOne() with a user-controlled query filter carrying `$`-operators or a whole attacker-controlled filter object — NoSQL injection; coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongodb.deletemany", Category: taint.SnkNoSQL, Pattern: `\.deleteMany\s*\(`, ObjectType: "", MethodName: "deleteMany", DangerousArgs: []int{0}, RequiresArgShape: taint.ArgShapeContainer, Severity: rules.Critical, Description: "MongoDB Collection.deleteMany() with a user-controlled query filter carrying `$`-operators or a whole attacker-controlled filter object — NoSQL injection; coerce user values to strings or use a typed/validated filter", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.aggregate.tainted", Category: taint.SnkNoSQL, Pattern: `\.aggregate\s*\(`, ObjectType: "", MethodName: "aggregate", DangerousArgs: []int{0}, Severity: rules.High, Description: "MongoDB aggregate pipeline with tainted data", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},

	// MongoDB operator-injection — server-side JavaScript operators (CWE-943).
	// These are MongoDB-specific operator keys whose `body`/function value is
	// evaluated server-side; a tainted body is direct code execution, the same
	// class as $where but reaching via the aggregation/expression operators
	// rather than the legacy $where field. Anchored to the literal operator
	// key so they do not fire on ORM `findOne({where:...})` shapes.
	{ID: "js.mongoose.operator.function", Category: taint.SnkNoSQL, Pattern: `\$function\s*:`, ObjectType: "MongoQuery", MethodName: "$function", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB $function operator runs a server-side JavaScript body (aggregation $expr/$function) — a tainted function string is NoSQL code injection; use native aggregation operators instead", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.operator.accumulator", Category: taint.SnkNoSQL, Pattern: `\$accumulator\s*:`, ObjectType: "MongoQuery", MethodName: "$accumulator", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB $accumulator operator runs server-side JavaScript init/accumulate/merge functions — tainted bodies are NoSQL code injection (server-side JS execution)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.mongoose.mapreduce", Category: taint.SnkNoSQL, Pattern: `\.mapReduce\s*\(`, ObjectType: "", MethodName: "mapReduce", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MongoDB mapReduce(map, reduce, ...) takes server-side JavaScript map/reduce functions — tainted function bodies are NoSQL code injection (server-side JS execution)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},

	// child_process additional sinks
	{ID: "js.child_process.execfile", Category: taint.SnkCommand, Pattern: `(?:child_process\.)?execFile\s*\(`, ObjectType: "child_process", MethodName: "execFile", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via execFile", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.child_process.fork", Category: taint.SnkCommand, Pattern: `(?:child_process\.)?fork\s*\(`, ObjectType: "child_process", MethodName: "fork", DangerousArgs: []int{0}, Severity: rules.High, Description: "Node child process fork with tainted module path", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// vm module (code eval)
	{ID: "js.vm.runincontext", Category: taint.SnkEval, Pattern: `vm\.runInContext\s*\(`, ObjectType: "vm", MethodName: "runInContext", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code execution via vm.runInContext", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.vm.runinnewcontext", Category: taint.SnkEval, Pattern: `vm\.runInNewContext\s*\(`, ObjectType: "vm", MethodName: "runInNewContext", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code execution via vm.runInNewContext", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.vm.runinthiscontext", Category: taint.SnkEval, Pattern: `vm\.runInThisContext\s*\(`, ObjectType: "vm", MethodName: "runInThisContext", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code execution via vm.runInThisContext", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.vm.script", Category: taint.SnkEval, Pattern: `new\s+vm\.Script\s*\(`, ObjectType: "vm", MethodName: "Script", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code compilation via new vm.Script", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.vm.compilefunction", Category: taint.SnkEval, Pattern: `vm\.compileFunction\s*\(`, ObjectType: "vm", MethodName: "compileFunction", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Code compilation via vm.compileFunction() — a tainted function body string is compiled and callable, equivalent to new Function() / eval", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	// NOTE: the bare global Function constructor `new Function(body)` is already
	// modeled by js.new.function (CWE-94) above — not re-added here.

	// Dynamic module loading (CWE-94). A tainted module specifier passed to a
	// dynamic import() expression or require() loads and executes arbitrary
	// module code at runtime (local file include / dependency confusion / RCE).
	// import(...) is always the dynamic call form (static import is a
	// statement, not a call), so this only fires on dynamic imports; the taint
	// engine additionally requires the specifier to be attacker-controlled, so
	// literal `require('fs')` / `import('./static')` do not flow here.
	{ID: "js.dynamic.import", Category: taint.SnkEval, Pattern: `\bimport\s*\(`, ObjectType: "@global", MethodName: "import", DangerousArgs: []int{0}, Severity: rules.High, Description: "Dynamic import() with a tainted module specifier — loads and executes arbitrary module code at runtime (dynamic code/module injection)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dynamic.require", Category: taint.SnkEval, Pattern: `\brequire\s*\(`, ObjectType: "@global", MethodName: "require", DangerousArgs: []int{0}, Severity: rules.High, Description: "require() with a tainted module specifier — loads and executes arbitrary module code at runtime (path-controlled module load / RCE)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// Crypto weak patterns
	{ID: "js.crypto.createhash.md5", Category: taint.SnkCrypto, Pattern: `createHash\s*\(\s*['"]md5['"]`, ObjectType: "crypto", MethodName: "createHash", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak hash algorithm (MD5)", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
	{ID: "js.crypto.createhash.sha1", Category: taint.SnkCrypto, Pattern: `createHash\s*\(\s*['"]sha1['"]`, ObjectType: "crypto", MethodName: "createHash", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak hash algorithm (SHA-1)", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
	{ID: "js.crypto.createcipheriv.weak", Category: taint.SnkCrypto, Pattern: `createCipheriv\s*\(\s*['"](?:des|rc4|aes-128-ecb)['"]`, ObjectType: "crypto", MethodName: "createCipheriv", DangerousArgs: []int{0}, Severity: rules.High, Description: "Weak cipher algorithm (DES/RC4/ECB mode)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},

	// Insecure random
	{ID: "js.crypto.math_random", Category: taint.SnkCrypto, Pattern: `Math\.random\s*\(`, ObjectType: "Math", MethodName: "random", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Math.random() used for security-sensitive value (use crypto.randomBytes instead)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},

	// JWT without verification
	{ID: "js.jwt.decode.noverify", Category: taint.SnkCrypto, Pattern: `jwt\.decode\s*\(|jsonwebtoken\.decode\s*\(`, ObjectType: "jsonwebtoken", MethodName: "decode", DangerousArgs: []int{0}, Severity: rules.High, Description: "JWT decoded without signature verification (use jwt.verify instead)", CWEID: "CWE-345", OWASPCategory: "A02:2021-Cryptographic Failures"},
	{ID: "js.jwt.verify.none_algo", Category: taint.SnkCrypto, Pattern: `jwt\.verify\s*\(.*algorithms\s*:\s*\[.*['"]none['"]`, ObjectType: "jsonwebtoken", MethodName: "verify (none)", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "JWT verification with 'none' algorithm allowed", CWEID: "CWE-345", OWASPCategory: "A02:2021-Cryptographic Failures"},
	// jose library (~27M weekly): decodeJwt / decodeProtectedHeader are documented as NOT
	// performing signature verification — library docs explicitly direct callers to jwtVerify.
	// ObjectType "@global" restricts these to bare-function calls (how jose exports them)
	// so we never collide with `obj.decodeJwt(...)` / `obj.decodeProtectedHeader(...)` methods.
	{ID: "js.jose.decodejwt", Category: taint.SnkCrypto, Pattern: `\bdecodeJwt\s*\(`, ObjectType: "@global", MethodName: "decodeJwt", DangerousArgs: []int{0}, Severity: rules.High, Description: "jose decodeJwt() returns the JWT claims set without verifying the JWS signature or validating claim types; use jose.jwtVerify() for authenticated decode", CWEID: "CWE-347", OWASPCategory: "A02:2021-Cryptographic Failures"},
	{ID: "js.jose.decodeprotectedheader", Category: taint.SnkCrypto, Pattern: `\bdecodeProtectedHeader\s*\(`, ObjectType: "@global", MethodName: "decodeProtectedHeader", DangerousArgs: []int{0}, Severity: rules.High, Description: "jose decodeProtectedHeader() parses a JWS/JWE protected header without any cryptographic verification; trusting header fields (e.g. alg, kid) enables algorithm-confusion and kid-injection attacks", CWEID: "CWE-347", OWASPCategory: "A02:2021-Cryptographic Failures"},
	// UnsecuredJWT is jose's explicit API for alg=none tokens — the token string carries no
	// signature, so anyone can forge claims; treating its output as authenticated is CWE-347.
	{ID: "js.jose.unsecuredjwt.decode", Category: taint.SnkCrypto, Pattern: `UnsecuredJWT\.decode\s*\(`, ObjectType: "UnsecuredJWT", MethodName: "decode", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "jose UnsecuredJWT.decode() parses an alg=none JWT — the token is unsigned by design, so any claims are attacker-controlled; never use on tokens from untrusted parties", CWEID: "CWE-347", OWASPCategory: "A02:2021-Cryptographic Failures"},

	// Redis command injection
	{ID: "js.redis.sendcommand", Category: taint.SnkCommand, Pattern: `\.sendCommand\s*\(`, ObjectType: "RedisClient", MethodName: "sendCommand", DangerousArgs: []int{0}, Severity: rules.High, Description: "Redis command execution with tainted arguments", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.redis.eval", Category: taint.SnkEval, Pattern: `\.eval\s*\(`, ObjectType: "RedisClient", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Redis Lua script evaluation with tainted script", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// DNS lookup with tainted hostname
	{ID: "js.dns.lookup", Category: taint.SnkURLFetch, Pattern: `dns\.lookup\s*\(|dns\.resolve\s*\(`, ObjectType: "dns", MethodName: "lookup/resolve", DangerousArgs: []int{0}, Severity: rules.High, Description: "DNS lookup with tainted hostname (SSRF/DNS rebinding)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	// AWS Lambda invocation — `lambda.invoke({FunctionName, Payload})` (SDK v2) or
	// `lambdaClient.send(new InvokeCommand({...}))` (SDK v3). A request-controlled
	// FunctionName lets an attacker pivot to invoke an arbitrary function in the
	// account (privilege escalation / SSRF into the AWS control plane, CWE-918);
	// a tainted Payload forwards untrusted data into the downstream function.
	// Anchored to ObjectType "Lambda" — the SDK client is conventionally bound to
	// `lambda`/`lambdaClient` (both prefix-match "lambda") — so it does not collide
	// with unrelated `.invoke(...)` (EventEmitter-style, hook .invoke()). The whole
	// options object (arg 0) is dangerous because both FunctionName and Payload are
	// sensitive fields. Safe form: a constant/allowlisted FunctionName.
	{ID: "js.aws.lambda.invoke", Category: taint.SnkURLFetch, Pattern: `\.invoke\s*\(`, ObjectType: "Lambda", MethodName: "invoke", DangerousArgs: []int{0}, Severity: rules.High, Description: "AWS Lambda lambda.invoke({FunctionName, Payload}) with a request-controlled FunctionName lets an attacker invoke an arbitrary function in the account (privilege escalation / control-plane SSRF, CWE-918); resolve FunctionName from a fixed allowlist, never from request data", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.aws.lambda.invokecommand", Category: taint.SnkURLFetch, Pattern: `new\s+InvokeCommand\s*\(`, ObjectType: "@global", MethodName: "InvokeCommand", DangerousArgs: []int{0}, Severity: rules.High, Description: "AWS SDK v3 new InvokeCommand({FunctionName, Payload}) with a request-controlled FunctionName invokes an attacker-chosen function (privilege escalation / control-plane SSRF, CWE-918); pin FunctionName to an allowlisted constant", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	// Chrome DevTools Protocol (chrome-remote-interface / puppeteer-core CDPSession).
	// `Runtime.evaluate({expression})` runs an arbitrary JS expression in the page
	// context — a tainted expression is remote code execution (CWE-94), the CDP
	// analogue of eval(). `Page.navigate({url})` drives the browser to an arbitrary
	// URL — a tainted url is SSRF / local-file (file://) access (CWE-918). Anchored
	// to the CDP domain receivers ("Runtime"/"Page"): the matcher's runtime alias
	// already binds `runtime`/`Runtime`; the Page navigate entry binds `page`/`Page`
	// via last-component match. Safe form: never pass user input to evaluate(); use
	// page.$eval with a constant function, and validate navigation URLs.
	{ID: "js.cdp.runtime.evaluate", Category: taint.SnkEval, Pattern: `(?:Runtime|client)\.evaluate\s*\(`, ObjectType: "Runtime", MethodName: "evaluate", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Chrome DevTools Protocol Runtime.evaluate({expression}) runs an arbitrary JavaScript expression in the page context — a tainted expression is remote code execution (CWE-94), the CDP equivalent of eval(); never build the expression from user input", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.cdp.page.navigate", Category: taint.SnkURLFetch, Pattern: `(?:Page|client)\.navigate\s*\(`, ObjectType: "Page", MethodName: "navigate", DangerousArgs: []int{0}, Severity: rules.High, Description: "Chrome DevTools Protocol Page.navigate({url}) drives the headless browser to a request-controlled URL — a tainted url enables SSRF and local-file (file://) access (CWE-918); validate the navigation target against an allowlist", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Docker exec
	{ID: "js.dockerode.exec", Category: taint.SnkCommand, Pattern: `container\.exec\s*\(`, ObjectType: "Dockerode.Container", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Docker container exec with tainted command", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// Kafka message construction
	{ID: "js.kafkajs.send", Category: taint.SnkCommand, Pattern: `producer\.send\s*\(`, ObjectType: "KafkaJS.Producer", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Kafka message produced with tainted data", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},

	// SMTP/email header injection
	{ID: "js.nodemailer.sendmail", Category: taint.SnkHeader, Pattern: `transporter\.sendMail\s*\(|\.sendMail\s*\(`, ObjectType: "Nodemailer", MethodName: "sendMail", DangerousArgs: []int{0}, Severity: rules.High, Description: "Email send with tainted headers/recipients (email injection)", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

	// Log injection (CWE-117)
	{ID: "js.console.log", Category: taint.SnkLog, Pattern: `console\.log\s*\(`, ObjectType: "console", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "console.log with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.console.warn", Category: taint.SnkLog, Pattern: `console\.warn\s*\(`, ObjectType: "console", MethodName: "warn", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "console.warn with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.console.error", Category: taint.SnkLog, Pattern: `console\.error\s*\(`, ObjectType: "console", MethodName: "error", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "console.error with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.console.info", Category: taint.SnkLog, Pattern: `console\.info\s*\(`, ObjectType: "console", MethodName: "info", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "console.info with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	// Externally-controlled format string (CWE-134). Node's util.format /
	// util.formatWithOptions treat arg 0 (resp. arg 1) as a printf-style format
	// string: a tainted format string lets an attacker inject %s/%d/%o/%j
	// directives that mis-format / leak subsequent arguments (and, with %o/%j,
	// trigger deep inspection of objects). Receiver-anchored to `util` so a bare
	// `format(...)` / `obj.format(...)` (date formatters, string builders) never
	// matches. nodeIsTainted only fires when the format slot is actually a
	// tainted variable — a literal format string (`util.format('done %s', x)`)
	// carries no taint and stays clean.
	{ID: "js.util.format", Category: taint.SnkLog, Pattern: `util\.format\s*\(`, ObjectType: "util", MethodName: "format", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "util.format(fmt, ...) with a tainted format string — attacker-controlled %-directives mis-format/leak the trailing arguments; pass a constant format string and put user data in the value slots, or use a structured logger", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.util.formatwithoptions", Category: taint.SnkLog, Pattern: `util\.formatWithOptions\s*\(`, ObjectType: "util", MethodName: "formatWithOptions", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "util.formatWithOptions(opts, fmt, ...) with a tainted format string (arg 1) — attacker-controlled %-directives mis-format/leak the trailing arguments; pass a constant format string and put user data in the value slots", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.winston.log", Category: taint.SnkLog, Pattern: `winston\.(?:log|info|warn|error|debug)\s*\(`, ObjectType: "winston", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Winston logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.pino.log", Category: taint.SnkLog, Pattern: `pino\.(?:info|warn|error|debug|fatal|trace)\s*\(`, ObjectType: "pino", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Pino logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.bunyan.log", Category: taint.SnkLog, Pattern: `bunyan\.(?:info|warn|error|debug|fatal|trace)\s*\(`, ObjectType: "bunyan", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Bunyan logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
	{ID: "js.logger.generic", Category: taint.SnkLog, Pattern: `logger\.(?:info|warn|error|debug|log)\s*\(`, ObjectType: "Logger", MethodName: "log", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Logger with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

	// Additional file operations
	{ID: "js.fs.writefilesync", Category: taint.SnkFileWrite, Pattern: `fs\.writeFileSync\s*\(`, ObjectType: "fs", MethodName: "writeFileSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "Synchronous file write with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.mkdir", Category: taint.SnkFileWrite, Pattern: `fs\.mkdir\s*\(|fs\.mkdirSync\s*\(`, ObjectType: "fs", MethodName: "mkdir/mkdirSync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Directory creation with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.rename", Category: taint.SnkFileWrite, Pattern: `fs\.rename\s*\(|fs\.renameSync\s*\(`, ObjectType: "fs", MethodName: "rename/renameSync", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "File rename with potentially tainted path (external control of file name)", CWEID: "CWE-73", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.symlink", Category: taint.SnkFileWrite, Pattern: `fs\.symlink\s*\(|fs\.symlinkSync\s*\(`, ObjectType: "fs", MethodName: "symlink/symlinkSync", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "Symlink creation with potentially tainted path", CWEID: "CWE-59", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.link", Category: taint.SnkFileWrite, Pattern: `fs\.link\s*\(|fs\.linkSync\s*\(`, ObjectType: "fs", MethodName: "link/linkSync", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "Hard link creation with potentially tainted path (external control of file name)", CWEID: "CWE-73", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.copyfile", Category: taint.SnkFileWrite, Pattern: `fs\.copyFile\s*\(|fs\.copyFileSync\s*\(`, ObjectType: "fs", MethodName: "copyFile/copyFileSync", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "File copy with potentially tainted path (external control of file name)", CWEID: "CWE-73", OWASPCategory: "A01:2021-Broken Access Control"},

	// File read operations (path traversal via read — SnkFileRead)
	{ID: "js.fs.readfilesync.sink", Category: taint.SnkFileRead, Pattern: `fs\.readFileSync\s*\(`, ObjectType: "fs", MethodName: "readFileSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "Synchronous file read with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.readdir", Category: taint.SnkFileRead, Pattern: `fs\.readdir\s*\(|fs\.readdirSync\s*\(`, ObjectType: "fs", MethodName: "readdir/readdirSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "Directory listing with tainted path (information disclosure)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.stat", Category: taint.SnkFileRead, Pattern: `fs\.stat\s*\(|fs\.statSync\s*\(`, ObjectType: "fs", MethodName: "stat/statSync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "File stat with tainted path (existence probing)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.lstat", Category: taint.SnkFileRead, Pattern: `fs\.lstat\s*\(|fs\.lstatSync\s*\(`, ObjectType: "fs", MethodName: "lstat/lstatSync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Symlink-aware stat with tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.access", Category: taint.SnkFileRead, Pattern: `fs\.access\s*\(|fs\.accessSync\s*\(`, ObjectType: "fs", MethodName: "access/accessSync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "File access check with tainted path (existence probing)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.open", Category: taint.SnkFileRead, Pattern: `fs\.open\s*\(|fs\.openSync\s*\(`, ObjectType: "fs", MethodName: "open/openSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "Low-level file open with tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.realpath", Category: taint.SnkFileRead, Pattern: `fs\.realpath\s*\(|fs\.realpathSync\s*\(`, ObjectType: "fs", MethodName: "realpath/realpathSync", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Real path resolution with tainted input (path disclosure)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// fs.promises API (modern async Node.js file operations)
	{ID: "js.fs.promises.readfile", Category: taint.SnkFileRead, Pattern: `fs\.promises\.readFile\s*\(|fsPromises\.readFile\s*\(`, ObjectType: "fs.promises", MethodName: "readFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Async file read with potential path traversal (fs.promises)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.promises.readdir", Category: taint.SnkFileRead, Pattern: `fs\.promises\.readdir\s*\(|fsPromises\.readdir\s*\(`, ObjectType: "fs.promises", MethodName: "readdir", DangerousArgs: []int{0}, Severity: rules.High, Description: "Async directory listing with tainted path (fs.promises)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.promises.stat", Category: taint.SnkFileRead, Pattern: `fs\.promises\.stat\s*\(|fsPromises\.stat\s*\(`, ObjectType: "fs.promises", MethodName: "stat", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Async file stat with tainted path (fs.promises)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.promises.access", Category: taint.SnkFileRead, Pattern: `fs\.promises\.access\s*\(|fsPromises\.access\s*\(`, ObjectType: "fs.promises", MethodName: "access", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Async file access check with tainted path (fs.promises)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.promises.open", Category: taint.SnkFileRead, Pattern: `fs\.promises\.open\s*\(|fsPromises\.open\s*\(`, ObjectType: "fs.promises", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "Async low-level file open with tainted path (fs.promises)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.promises.writefile", Category: taint.SnkFileWrite, Pattern: `fs\.promises\.writeFile\s*\(|fsPromises\.writeFile\s*\(`, ObjectType: "fs.promises", MethodName: "writeFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Async file write with potential path traversal (fs.promises)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.promises.rename", Category: taint.SnkFileWrite, Pattern: `fs\.promises\.rename\s*\(|fsPromises\.rename\s*\(`, ObjectType: "fs.promises", MethodName: "rename", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "Async file rename with potentially tainted path (external control of file name, fs.promises)", CWEID: "CWE-73", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.promises.copyfile", Category: taint.SnkFileWrite, Pattern: `fs\.promises\.copyFile\s*\(|fsPromises\.copyFile\s*\(`, ObjectType: "fs.promises", MethodName: "copyFile", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "Async file copy with potentially tainted path (external control of file name, fs.promises)", CWEID: "CWE-73", OWASPCategory: "A01:2021-Broken Access Control"},

	// Additional write operations
	{ID: "js.fs.appendfile", Category: taint.SnkFileWrite, Pattern: `fs\.appendFile\s*\(|fs\.appendFileSync\s*\(`, ObjectType: "fs", MethodName: "appendFile/appendFileSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "File append with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.createwritestream", Category: taint.SnkFileWrite, Pattern: `fs\.createWriteStream\s*\(`, ObjectType: "fs", MethodName: "createWriteStream", DangerousArgs: []int{0}, Severity: rules.High, Description: "Write stream with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.fs.chmod", Category: taint.SnkFileWrite, Pattern: `fs\.chmod\s*\(|fs\.chmodSync\s*\(`, ObjectType: "fs", MethodName: "chmod/chmodSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "File permission change with tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// Hono response sinks
	{ID: "js.hono.c.html", Category: taint.SnkHTMLOutput, Pattern: `c\.html\s*\(`, ObjectType: "HonoContext", MethodName: "html", DangerousArgs: []int{0}, Severity: rules.High, Description: "Hono c.html() response (XSS if tainted)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.hono.c.text", Category: taint.SnkHTMLOutput, Pattern: `c\.text\s*\(`, ObjectType: "HonoContext", MethodName: "text", DangerousArgs: []int{0}, Severity: rules.Low, Description: "Hono c.text() response with tainted data", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.hono.c.redirect", Category: taint.SnkRedirect, Pattern: `c\.redirect\s*\(`, ObjectType: "HonoContext", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via Hono c.redirect()", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

	// Fastify response sinks
	{ID: "js.fastify.reply.send", Category: taint.SnkHTMLOutput, Pattern: `reply\.send\s*\(`, ObjectType: "FastifyReply", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.High, Description: "Fastify reply.send() with tainted data (potential XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.fastify.reply.redirect", Category: taint.SnkRedirect, Pattern: `reply\.redirect\s*\(`, ObjectType: "FastifyReply", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via Fastify reply.redirect()", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

	// Koa response sinks
	{ID: "js.koa.ctx.redirect", Category: taint.SnkRedirect, Pattern: `ctx\.redirect\s*\(`, ObjectType: "KoaContext", MethodName: "redirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "Open redirect via Koa ctx.redirect()", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

	// XSS additional vectors
	{ID: "js.dom.outerhtml", Category: taint.SnkHTMLOutput, Pattern: `\.outerHTML\s*=`, ObjectType: "HTMLElement", MethodName: "outerHTML", DangerousArgs: []int{0}, Severity: rules.High, Description: "outerHTML assignment (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dom.insertadjacenthtml", Category: taint.SnkHTMLOutput, Pattern: `\.insertAdjacentHTML\s*\(`, ObjectType: "HTMLElement", MethodName: "insertAdjacentHTML", DangerousArgs: []int{1}, Severity: rules.High, Description: "insertAdjacentHTML (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dom.document.writeln", Category: taint.SnkHTMLOutput, Pattern: `document\.writeln\s*\(`, ObjectType: "document", MethodName: "writeln", DangerousArgs: []int{0}, Severity: rules.High, Description: "document.writeln (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dom.createcontextualfragment", Category: taint.SnkHTMLOutput, Pattern: `\.createContextualFragment\s*\(`, ObjectType: "Range", MethodName: "createContextualFragment", DangerousArgs: []int{0}, Severity: rules.High, Description: "Range.createContextualFragment() parses an HTML string into live DOM nodes — a tainted string is DOM-based XSS (same risk as innerHTML)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.angular.domsanitizer.bypasshtml", Category: taint.SnkHTMLOutput, Pattern: `\.bypassSecurityTrustHtml\s*\(`, ObjectType: "DomSanitizer", MethodName: "bypassSecurityTrustHtml", DangerousArgs: []int{0}, Severity: rules.High, Description: "Angular DomSanitizer.bypassSecurityTrustHtml() marks a tainted string as safe HTML, bypassing Angular's built-in sanitizer (DOM XSS); pass the value through sanitizer.sanitize(SecurityContext.HTML, ...) instead", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	// The rest of the Angular DomSanitizer.bypassSecurityTrust* family. Each
	// re-introduces taint into a specific trusted-value context, defeating
	// Angular's contextual auto-escaping for that context. bypassSecurityTrustHtml
	// (above) is XSS; the remaining four each map a tainted string into a sink
	// Angular would otherwise sanitize:
	//   - ResourceUrl → <script src>/<iframe src>/lazy-loaded module URL — a
	//     tainted resource URL is script/SSRF (CWE-94 code load), the most
	//     dangerous of the family.
	//   - Script → inline <script> body — direct code injection (CWE-94).
	//   - Url → href/[src] attribute — javascript: URL / open-redirect XSS.
	//   - Style → CSS context — expression()/url() exfiltration (CWE-79).
	// All are anchored to ObjectType "DomSanitizer" (the Angular-injected service,
	// conventionally bound to `sanitizer`/`domSanitizer`/`_sanitizer`, all of which
	// prefix-match "domsanitizer"). The safe path is sanitizer.sanitize(context,
	// value), which IS a sanitizer below — so a sanitized value never reaches here.
	{ID: "js.angular.domsanitizer.bypassresourceurl", Category: taint.SnkEval, Pattern: `\.bypassSecurityTrustResourceUrl\s*\(`, ObjectType: "DomSanitizer", MethodName: "bypassSecurityTrustResourceUrl", DangerousArgs: []int{0}, Severity: rules.High, Description: "Angular DomSanitizer.bypassSecurityTrustResourceUrl() marks a tainted string as a trusted resource URL (<script src>/<iframe src>/module URL), bypassing Angular's sanitizer — a tainted value loads attacker-controlled code/resources (XSS/SSRF); never bypass user input, resolve resource URLs from a fixed allowlist", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.angular.domsanitizer.bypassscript", Category: taint.SnkEval, Pattern: `\.bypassSecurityTrustScript\s*\(`, ObjectType: "DomSanitizer", MethodName: "bypassSecurityTrustScript", DangerousArgs: []int{0}, Severity: rules.High, Description: "Angular DomSanitizer.bypassSecurityTrustScript() marks a tainted string as trusted inline script, bypassing Angular's sanitizer — a tainted value is direct code injection (CWE-94); never pass user input to bypassSecurityTrustScript", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.angular.domsanitizer.bypassurl", Category: taint.SnkHTMLOutput, Pattern: `\.bypassSecurityTrustUrl\s*\(`, ObjectType: "DomSanitizer", MethodName: "bypassSecurityTrustUrl", DangerousArgs: []int{0}, Severity: rules.High, Description: "Angular DomSanitizer.bypassSecurityTrustUrl() marks a tainted string as a trusted URL (href/[src]), bypassing Angular's sanitizer — a tainted value enables javascript: URL XSS / open redirect; validate against an allowlist instead of bypassing", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.angular.domsanitizer.bypassstyle", Category: taint.SnkHTMLOutput, Pattern: `\.bypassSecurityTrustStyle\s*\(`, ObjectType: "DomSanitizer", MethodName: "bypassSecurityTrustStyle", DangerousArgs: []int{0}, Severity: rules.High, Description: "Angular DomSanitizer.bypassSecurityTrustStyle() marks a tainted string as trusted CSS, bypassing Angular's sanitizer — a tainted value enables CSS-context injection (url()/expression() exfiltration, CWE-79); never bypass user input", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	// jQuery HTML-manipulation sinks — the dominant DOM-XSS surface in the huge
	// installed base of jQuery apps. `$(htmlString)`, `$el.html(taint)`, and the
	// DOM-insertion family (.append/.prepend/.after/.before/.replaceWith/.wrap/
	// .wrapInner/.wrapAll) all parse their string argument as HTML and inject live
	// nodes — a tainted argument is XSS exactly like innerHTML. These are anchored
	// to ObjectType "jQuery": the matcher's jquery alias (see matcher.go) binds the
	// receiver only when it is the jQuery sigil/result — `$`, a `$(...)` call, a
	// `$`-prefixed variable (`$el`/`$content`), or a literal `jQuery(...)` — so a
	// plain `array.append(x)` / `stream.wrap(x)` (receiver "array"/"stream", no `$`)
	// never matches and the array/stream FP shape stays clean. The DangerousArgs
	// is the HTML string (arg 0). Safe form: .text(value) (auto-escaping, a
	// sanitizer below) or DOMPurify.sanitize() before insertion.
	{ID: "js.jquery.html", Category: taint.SnkHTMLOutput, Pattern: `\.html\s*\(`, ObjectType: "jQuery", MethodName: "html", DangerousArgs: []int{0}, Severity: rules.High, Description: "jQuery .html(value) parses the argument as HTML and replaces element content with live nodes — a tainted value is DOM-based XSS (CWE-79); use .text(value) for text or DOMPurify.sanitize() before injecting HTML", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.jquery.append", Category: taint.SnkHTMLOutput, Pattern: `\.(?:append|prepend|after|before|replaceWith)\s*\(`, ObjectType: "jQuery", MethodName: "append/prepend/after/before/replaceWith", DangerousArgs: []int{0}, Severity: rules.High, Description: "jQuery DOM-insertion (.append/.prepend/.after/.before/.replaceWith) parses a string argument as HTML and inserts live nodes — a tainted value is DOM-based XSS (CWE-79); insert text via .text() or sanitize the HTML with DOMPurify first", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.jquery.wrap", Category: taint.SnkHTMLOutput, Pattern: `\.(?:wrap|wrapInner|wrapAll)\s*\(`, ObjectType: "jQuery", MethodName: "wrap/wrapInner/wrapAll", DangerousArgs: []int{0}, Severity: rules.High, Description: "jQuery .wrap/.wrapInner/.wrapAll(htmlString) parses the wrapper argument as HTML and inserts live nodes — a tainted wrapper string is DOM-based XSS (CWE-79); use a constant wrapper element, never user input", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.jquery.constructor", Category: taint.SnkHTMLOutput, Pattern: `\$\s*\(`, ObjectType: "@global", MethodName: "$", DangerousArgs: []int{0}, Severity: rules.High, Description: "jQuery $(htmlString) parses a string beginning with '<' as HTML and builds live DOM nodes — passing a tainted value to the jQuery function is DOM-based XSS (CWE-79); pass only constant selectors/markup, and sanitize any HTML with DOMPurify", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.angular.sce.trustashtml", Category: taint.SnkHTMLOutput, Pattern: `\.trustAsHtml\s*\(`, ObjectType: "", MethodName: "trustAsHtml", DangerousArgs: []int{0}, Severity: rules.High, Description: "AngularJS $sce.trustAsHtml() marks a tainted string as trusted HTML, bypassing $sce contextual escaping (DOM XSS); never pass user input — sanitize with $sanitize or ngSanitize instead. ObjectType relaxed to \"\" because trustAsHtml is a distinctive method name", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

	// ReDoS
	{ID: "js.regexp.constructor", Category: taint.SnkEval, Pattern: `new\s+RegExp\s*\(`, ObjectType: "", MethodName: "RegExp", DangerousArgs: []int{0}, Severity: rules.High, Description: "RegExp construction with potentially tainted pattern (ReDoS)", CWEID: "CWE-1333", OWASPCategory: "A03:2021-Injection"},
	// Dedicated SnkRegexDoS view of the RegExp constructor (CWE-1333 /
	// CWE-400). Mirrors the Python re.* / C# Regex.* / C / C++ ReDoS sinks:
	// compiling an attacker-controlled *pattern* (arg 0) into the backtracking
	// V8 RegExp engine permits a catastrophically-backtracking expression to
	// exhaust the event loop (Denial of Service), distinct from code injection.
	// Only the dynamic-pattern form fires — a regex *literal* (`/[a-z]+/`)
	// carries no taint, and `new\s+RegExp` requires whitespace before `RegExp`
	// so it does not substring-match inside identifiers (`renewRegExp`) nor
	// collide with the `RegExp.escape(...)` sanitizer. The string being scanned
	// (`str.match(re)`) is the haystack and is never the dangerous argument, so
	// keeping DangerousArgs=[0] (the pattern) reflects the real threat. The safe
	// fix is escape-string-regexp / RegExp.escape on user input, or the
	// linear-time `re2` engine.
	{ID: "js.regexp.constructor.redos", Category: taint.SnkRegexDoS, Pattern: `new\s+RegExp\s*\(`, ObjectType: "", MethodName: "RegExp", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "new RegExp(pattern) with a potentially tainted pattern at arg 0 — catastrophic backtracking in the V8 regex engine exhausts the event loop (ReDoS). The haystack passed to str.match/replace is never the dangerous argument; escape user input with escape-string-regexp / RegExp.escape, or use the linear-time re2 engine", CWEID: "CWE-1333", OWASPCategory: "A03:2021-Injection"},

	// Additional SSRF vectors
	{ID: "js.axios.post.ssrf", Category: taint.SnkURLFetch, Pattern: `axios\.post\s*\(|axios\.put\s*\(|axios\.delete\s*\(|axios\.patch\s*\(`, ObjectType: "axios", MethodName: "post/put/delete/patch", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via axios HTTP methods", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.got.ssrf", Category: taint.SnkURLFetch, Pattern: `\bgot\s*\(|got\.get\s*\(|got\.post\s*\(`, ObjectType: "got", MethodName: "got", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via got HTTP client", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.node-fetch.ssrf", Category: taint.SnkURLFetch, Pattern: `node-fetch`, ObjectType: "node-fetch", MethodName: "fetch", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via node-fetch", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// --- Additional HTTP-client SSRF sinks (CWE-918) ---
	// Followup to the axios/got/undici/http SSRF entries above. These cover
	// HTTP-client call shapes that the existing entries miss:
	//   - the bare-callable form `axios(url|config)` (the existing js.axios.*
	//     entries only match `axios.get`/`axios.post`/etc.)
	//   - `axios.head(url)` (HEAD is a classic SSRF probe and isn't in the
	//     existing js.axios.post.ssrf method list)
	//   - `https.get(url)` (the existing js.http.get.ssrf is scoped to the
	//     `http` module receiver, which the abbreviation heuristic does NOT
	//     stretch to cover `https`)
	//   - got's `get`/`post`/`put`/`delete`/`patch`/`head`/`stream`/`paginate`
	//     methods — the existing js.got.ssrf only registers method name "got"
	//     so qualified `got.get(...)` calls are unmatched in tsflow
	//     (CVE-2022-33987: got followed redirects to UNIX-socket origins)
	//   - superagent (`superagent.get(url)`, `superagent('GET', url)`)
	//   - needle (`needle.get(url)`)
	//   - ky (`ky.get(url)` — runs server-side via Node 18+ fetch)
	//   - phin (`phin(url|{url})` — minimal HTTP client)
	// All are SSRF gadgets when the request URL/origin is built from user
	// input; the safe fix is to allowlist the destination host. ObjectType is
	// pinned to the library's canonical receiver name so unrelated `.get`/
	// `.post`/`.head`/`.stream` methods on other objects do not false-fire.
	{ID: "js.axios.client.ssrf", Category: taint.SnkURLFetch, Pattern: `\baxios\s*\(`, ObjectType: "axios", MethodName: "axios", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via axios(url) / axios(config) callable form with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.axios.head.ssrf", Category: taint.SnkURLFetch, Pattern: `axios\.head\s*\(`, ObjectType: "axios", MethodName: "head", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via axios.head() with user-controlled URL (HEAD requests are a common SSRF probe)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.https.get.ssrf", Category: taint.SnkURLFetch, Pattern: `https\.get\s*\(`, ObjectType: "https", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via Node.js https.get() with user-controlled URL/options", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.got.method.ssrf", Category: taint.SnkURLFetch, Pattern: `got\.(?:get|post|put|delete|patch|head)\s*\(`, ObjectType: "got", MethodName: "get/post/put/delete/patch/head", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via got HTTP-method shortcut (got.get/post/put/delete/patch/head) with user-controlled URL (CVE-2022-33987)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.got.stream.ssrf", Category: taint.SnkURLFetch, Pattern: `got\.stream\s*\(`, ObjectType: "got", MethodName: "stream", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via got.stream() with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.got.paginate.ssrf", Category: taint.SnkURLFetch, Pattern: `got\.paginate\s*\(`, ObjectType: "got", MethodName: "paginate", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via got.paginate() with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.superagent.method.ssrf", Category: taint.SnkURLFetch, Pattern: `superagent\.(?:get|post|put|patch|head|del|delete)\s*\(`, ObjectType: "superagent", MethodName: "get/post/put/patch/head/del/delete", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via superagent HTTP-method shortcut (superagent.get/post/put/patch/head/del/delete) with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.superagent.client.ssrf", Category: taint.SnkURLFetch, Pattern: `superagent\s*\(\s*["'\x60]`, ObjectType: "superagent", MethodName: "superagent", DangerousArgs: []int{1}, Severity: rules.High, Description: "SSRF via superagent(method, url) callable form with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.needle.method.ssrf", Category: taint.SnkURLFetch, Pattern: `needle\.(?:get|post|put|patch|delete|head)\s*\(`, ObjectType: "needle", MethodName: "get/post/put/patch/delete/head", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via needle HTTP-method shortcut (needle.get/post/put/patch/delete/head) with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.ky.method.ssrf", Category: taint.SnkURLFetch, Pattern: `\bky\.(?:get|post|put|patch|delete|head)\s*\(`, ObjectType: "ky", MethodName: "get/post/put/patch/delete/head", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via ky HTTP-method shortcut (ky.get/post/put/patch/delete/head) with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.phin.ssrf", Category: taint.SnkURLFetch, Pattern: `\bphin\s*\(`, ObjectType: "phin", MethodName: "phin", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via phin(url) / phin({url}) with user-controlled URL", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Headless-browser automation (Puppeteer + Playwright). Both libraries expose
	// a `page` object (from browser.newPage() / context.newPage()) whose methods
	// are pinned here via ObjectType "Page" (the matcher matches the conventional
	// receiver names `page` / `p`). Screenshot/PDF/scraper services that feed a
	// user-supplied URL into page.goto() are a classic SSRF vector — the headless
	// browser will happily reach internal hosts, cloud metadata endpoints, and
	// file:// URLs. page.evaluate/evaluateHandle run a string in the page's JS
	// context (arbitrary code execution when the argument is a tainted string;
	// the recommended pattern passes user data as a *serialized* later argument,
	// which is arg 1+ and so does not fire here). page.setContent injects raw
	// HTML/markup into the page (script execution / XSS in the browser context).
	{ID: "js.puppeteer.goto", Category: taint.SnkURLFetch, Pattern: `\bpage\.goto\s*\(`, ObjectType: "Page", MethodName: "goto", DangerousArgs: []int{0}, Severity: rules.High, Description: "SSRF via page.goto() in Puppeteer/Playwright with a user-controlled URL — a headless browser navigating to an attacker-supplied URL reaches internal services, cloud metadata (169.254.169.254), and file:// resources. Validate/allowlist the destination host", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.puppeteer.evaluate", Category: taint.SnkEval, Pattern: `\bpage\.evaluate\s*\(`, ObjectType: "Page", MethodName: "evaluate", DangerousArgs: []int{0}, Severity: rules.High, Description: "Code injection via page.evaluate() in Puppeteer/Playwright — a tainted string passed as the page function is compiled and executed in the browser's JS context. Pass a function literal and supply user data as a serialized later argument instead", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.puppeteer.evaluatehandle", Category: taint.SnkEval, Pattern: `\bpage\.evaluateHandle\s*\(`, ObjectType: "Page", MethodName: "evaluateHandle", DangerousArgs: []int{0}, Severity: rules.High, Description: "Code injection via page.evaluateHandle() in Puppeteer/Playwright — a tainted string is executed as JS in the browser context (same risk as page.evaluate)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.puppeteer.setcontent", Category: taint.SnkHTMLOutput, Pattern: `\bpage\.setContent\s*\(`, ObjectType: "Page", MethodName: "setContent", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTML/script injection via page.setContent() in Puppeteer/Playwright — tainted markup is loaded as the page body and any embedded <script> runs in the headless browser context", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

	// Deprecated crypto
	{ID: "js.crypto.createcipher", Category: taint.SnkCrypto, Pattern: `crypto\.createCipher\s*\(`, ObjectType: "crypto", MethodName: "createCipher", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deprecated crypto.createCipher without IV (use createCipheriv)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},

	// LDAP Injection (CWE-90)
	{ID: "js.ldapjs.search", Category: taint.SnkLDAP, Pattern: `client\.search\s*\(`, ObjectType: "ldapjs.Client", MethodName: "search", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP search with potentially tainted filter via ldapjs", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.ldapjs.bind", Category: taint.SnkLDAP, Pattern: `client\.bind\s*\(`, ObjectType: "ldapjs.Client", MethodName: "bind", DangerousArgs: []int{0}, Severity: rules.High, Description: "LDAP bind with potentially tainted DN via ldapjs", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.ldapjs.modify", Category: taint.SnkLDAP, Pattern: `client\.modify\s*\(`, ObjectType: "ldapjs.Client", MethodName: "modify", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "LDAP modify with potentially tainted DN/changes via ldapjs", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.ldapjs.add", Category: taint.SnkLDAP, Pattern: `client\.add\s*\(`, ObjectType: "ldapjs.Client", MethodName: "add", DangerousArgs: []int{0}, Severity: rules.High, Description: "LDAP add entry with potentially tainted DN via ldapjs (also covers ldapts)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.ldapjs.del", Category: taint.SnkLDAP, Pattern: `client\.del\s*\(`, ObjectType: "ldapjs.Client", MethodName: "del", DangerousArgs: []int{0}, Severity: rules.High, Description: "LDAP delete entry with potentially tainted DN via ldapjs (also covers ldapts)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.ldapjs.modifydn", Category: taint.SnkLDAP, Pattern: `client\.modifyDN\s*\(`, ObjectType: "ldapjs.Client", MethodName: "modifyDN", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "LDAP modifyDN with potentially tainted old/new DN via ldapjs (also covers ldapts)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.ldapjs.compare", Category: taint.SnkLDAP, Pattern: `client\.compare\s*\(`, ObjectType: "ldapjs.Client", MethodName: "compare", DangerousArgs: []int{0, 2}, Severity: rules.High, Description: "LDAP compare with potentially tainted DN/value via ldapjs (also covers ldapts)", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.ldapjs.exop", Category: taint.SnkLDAP, Pattern: `client\.exop\s*\(`, ObjectType: "ldapjs.Client", MethodName: "exop", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "LDAP extended operation with potentially tainted request name/value via ldapjs", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.activedirectory.authenticate", Category: taint.SnkLDAP, Pattern: `ad\.authenticate\s*\(`, ObjectType: "ad", MethodName: "authenticate", DangerousArgs: []int{0}, Severity: rules.High, Description: "ActiveDirectory authenticate with potentially tainted username (DN) — activedirectory/activedirectory2", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.activedirectory.finduser", Category: taint.SnkLDAP, Pattern: `ad\.findUser\s*\(`, ObjectType: "ad", MethodName: "findUser", DangerousArgs: []int{0}, Severity: rules.High, Description: "ActiveDirectory findUser with potentially tainted filter — activedirectory/activedirectory2", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.activedirectory.findgroup", Category: taint.SnkLDAP, Pattern: `ad\.findGroup\s*\(`, ObjectType: "ad", MethodName: "findGroup", DangerousArgs: []int{0}, Severity: rules.High, Description: "ActiveDirectory findGroup with potentially tainted filter — activedirectory/activedirectory2", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

	// XPath Injection (CWE-643)
	{ID: "js.xpath.select", Category: taint.SnkXPath, Pattern: `xpath\.select\s*\(`, ObjectType: "xpath", MethodName: "select", DangerousArgs: []int{0}, Severity: rules.High, Description: "XPath query with potentially tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.xpath.evaluate", Category: taint.SnkXPath, Pattern: `xpath\.evaluate\s*\(`, ObjectType: "xpath", MethodName: "evaluate", DangerousArgs: []int{0}, Severity: rules.High, Description: "XPath evaluation with potentially tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.xpath.select1", Category: taint.SnkXPath, Pattern: `xpath\.select1\s*\(`, ObjectType: "xpath", MethodName: "select1", DangerousArgs: []int{0}, Severity: rules.High, Description: "XPath select1 with potentially tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.dom.document.evaluate", Category: taint.SnkXPath, Pattern: `document\.evaluate\s*\(`, ObjectType: "document", MethodName: "evaluate", DangerousArgs: []int{0}, Severity: rules.High, Description: "DOM-native document.evaluate() with potentially tainted XPath expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.fontoxpath.evaluatexpath", Category: taint.SnkXPath, Pattern: `evaluateXPath\s*\(`, ObjectType: "", MethodName: "evaluateXPath", DangerousArgs: []int{0}, Severity: rules.High, Description: "fontoxpath evaluateXPath() with potentially tainted XPath 3.1 expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.fontoxpath.evaluatexpathtonodes", Category: taint.SnkXPath, Pattern: `evaluateXPathToNodes\s*\(`, ObjectType: "", MethodName: "evaluateXPathToNodes", DangerousArgs: []int{0}, Severity: rules.High, Description: "fontoxpath evaluateXPathToNodes() with potentially tainted XPath expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.fontoxpath.evaluatexpathtostring", Category: taint.SnkXPath, Pattern: `evaluateXPathToString\s*\(`, ObjectType: "", MethodName: "evaluateXPathToString", DangerousArgs: []int{0}, Severity: rules.High, Description: "fontoxpath evaluateXPathToString() with potentially tainted XPath expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.fontoxpath.evaluatexpathtofirstnode", Category: taint.SnkXPath, Pattern: `evaluateXPathToFirstNode\s*\(`, ObjectType: "", MethodName: "evaluateXPathToFirstNode", DangerousArgs: []int{0}, Severity: rules.High, Description: "fontoxpath evaluateXPathToFirstNode() with potentially tainted XPath expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},

	// TypeORM SQL injection sinks
	{ID: "js.typeorm.query", Category: taint.SnkSQLQuery, Pattern: `\.query\s*\(`, ObjectType: "typeorm", MethodName: "query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "TypeORM manager.query() raw SQL (SQL injection)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.typeorm.createquerybuilder.where", Category: taint.SnkSQLQuery, Pattern: `\.where\s*\([^{]`, ObjectType: "typeorm.QueryBuilder", MethodName: "where", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "TypeORM createQueryBuilder().where() with raw string (SQL injection)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.typeorm.rawquery", Category: taint.SnkSQLQuery, Pattern: `\.createQueryRunner\s*\(\s*\)\.query\s*\(`, ObjectType: "typeorm", MethodName: "createQueryRunner.query", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "TypeORM createQueryRunner().query() raw SQL (SQL injection)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

	// Drizzle ORM SQL injection sinks
	{ID: "js.drizzle.sqlraw", Category: taint.SnkSQLQuery, Pattern: `sql\.raw\s*\(`, ObjectType: "drizzle", MethodName: "sql.raw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Drizzle sql.raw() unparameterized SQL (SQL injection)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.drizzle.execute", Category: taint.SnkSQLQuery, Pattern: `\.execute\s*\(`, ObjectType: "drizzle", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Drizzle db.execute() with raw SQL string (SQL injection)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

	// postgres.js (porsager/postgres) sql.unsafe() is already modeled above as
	// js.postgres.unsafe — no second entry needed here.

	// node:sqlite (Node 22+ DatabaseSync) and better-sqlite3 raw SQL exec (CWE-89).
	// DatabaseSync.exec(sql) executes one or more raw SQL statements with no
	// parameterization (stacked statements are allowed) — a tainted or
	// interpolated statement is SQL injection. ObjectType "DatabaseSync" also
	// matches the conventional `db`/`database`/`sqlite` receivers via the
	// database-name heuristic in matchesCatalogEntry, so better-sqlite3's
	// `db.exec(...)` (same raw-exec semantics) is covered as well. The method
	// name `exec` here is the SQLite statement executor, distinct from the
	// child_process/shelljs command `.exec(` entries (which are scoped to those
	// modules / @global). Use db.prepare(sql).run(params) with bound parameters.
	{ID: "js.node_sqlite.exec", Category: taint.SnkSQLQuery, Pattern: `\.exec\s*\(`, ObjectType: "DatabaseSync", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "node:sqlite DatabaseSync.exec() / better-sqlite3 db.exec() executes raw, unparameterized SQL (stacked statements allowed) — tainted input is SQL injection. Use db.prepare(sql).run(params) with bound parameters instead", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

	// Trust boundary violation (CWE-501) — tainted data stored in session/storage
	{ID: "js.express.session.set", Category: taint.SnkTrustBoundary, Pattern: `req\.session\.\w+\s*=[^=]`, ObjectType: "express.Session", MethodName: "session", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Trust boundary violation: tainted data stored in Express session", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.express.session.bracket", Category: taint.SnkTrustBoundary, Pattern: `req\.session\[.*\]\s*=[^=]`, ObjectType: "express.Session", MethodName: "session", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Trust boundary violation: tainted data stored in Express session via bracket notation", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.koa.session.set", Category: taint.SnkTrustBoundary, Pattern: `ctx\.session\.\w+\s*=[^=]`, ObjectType: "koa.Session", MethodName: "session", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Trust boundary violation: tainted data stored in Koa session", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.fastify.session.set", Category: taint.SnkTrustBoundary, Pattern: `request\.session\.set\s*\(`, ObjectType: "fastify.Session", MethodName: "set", DangerousArgs: []int{1}, Severity: rules.High, Description: "Trust boundary violation: tainted data stored in Fastify session", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.localstorage.setitem", Category: taint.SnkTrustBoundary, Pattern: `localStorage\.setItem\s*\(`, ObjectType: "localStorage", MethodName: "setItem", DangerousArgs: []int{1}, Severity: rules.High, Description: "Trust boundary violation: tainted data stored in localStorage", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.sessionstorage.setitem", Category: taint.SnkTrustBoundary, Pattern: `sessionStorage\.setItem\s*\(`, ObjectType: "sessionStorage", MethodName: "setItem", DangerousArgs: []int{1}, Severity: rules.High, Description: "Trust boundary violation: tainted data stored in sessionStorage", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.express.res.cookie", Category: taint.SnkTrustBoundary, Pattern: `res\.cookie\s*\(`, ObjectType: "express.Response", MethodName: "cookie", DangerousArgs: []int{1}, Severity: rules.High, Description: "Trust boundary violation: tainted data stored in cookie via Express res.cookie()", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.document.cookie.set", Category: taint.SnkTrustBoundary, Pattern: `document\.cookie\s*=`, ObjectType: "document", MethodName: "cookie", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Trust boundary violation: tainted data stored in document.cookie", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},

	// H3/Nitro sinks
	{ID: "js.h3.sendredirect", Category: taint.SnkRedirect, Pattern: `sendRedirect\s*\(`, ObjectType: "", MethodName: "sendRedirect", DangerousArgs: []int{1}, Severity: rules.High, Description: "H3/Nitro open redirect via sendRedirect(event, url)", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.h3.setresponseheader", Category: taint.SnkHeader, Pattern: `setResponseHeader\s*\(`, ObjectType: "", MethodName: "setResponseHeader", DangerousArgs: []int{2}, Severity: rules.Medium, Description: "H3/Nitro response header injection via setResponseHeader(event, name, value)", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

	// Bun runtime — command injection (CWE-78)
	{ID: "js.bun.spawn", Category: taint.SnkCommand, Pattern: `Bun\.spawn\s*\(`, ObjectType: "Bun", MethodName: "spawn", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Bun.spawn() OS command execution with user-controlled arguments", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.bun.spawnsync", Category: taint.SnkCommand, Pattern: `Bun\.spawnSync\s*\(`, ObjectType: "Bun", MethodName: "spawnSync", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Bun.spawnSync() synchronous OS command execution", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// Bun runtime — file operations (CWE-22)
	{ID: "js.bun.file", Category: taint.SnkFileRead, Pattern: `Bun\.file\s*\(`, ObjectType: "Bun", MethodName: "file", DangerousArgs: []int{0}, Severity: rules.High, Description: "Bun.file() path traversal via user-controlled file path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.bun.write", Category: taint.SnkFileWrite, Pattern: `Bun\.write\s*\(`, ObjectType: "Bun", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "Bun.write() arbitrary file write with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// Deno runtime — command injection (CWE-78)
	{ID: "js.deno.command", Category: taint.SnkCommand, Pattern: `new\s+Deno\.Command\s*\(`, ObjectType: "Deno", MethodName: "Command", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Deno.Command constructor for OS command execution", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.deno.run", Category: taint.SnkCommand, Pattern: `Deno\.run\s*\(`, ObjectType: "Deno", MethodName: "run", DangerousArgs: []int{-1}, Severity: rules.Critical, Description: "Deno.run() OS command execution (deprecated, use Deno.Command)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// Deno runtime — file read (CWE-22)
	{ID: "js.deno.readtextfile", Category: taint.SnkFileRead, Pattern: `Deno\.readTextFile\s*\(`, ObjectType: "Deno", MethodName: "readTextFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deno.readTextFile() path traversal via user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.deno.readfile", Category: taint.SnkFileRead, Pattern: `Deno\.readFile\s*\(`, ObjectType: "Deno", MethodName: "readFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deno.readFile() path traversal via user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.deno.open", Category: taint.SnkFileRead, Pattern: `Deno\.open\s*\(`, ObjectType: "Deno", MethodName: "open", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deno.open() file open with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// Deno runtime — file write (CWE-22)
	{ID: "js.deno.writetextfile", Category: taint.SnkFileWrite, Pattern: `Deno\.writeTextFile\s*\(`, ObjectType: "Deno", MethodName: "writeTextFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deno.writeTextFile() arbitrary file write with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.deno.writefile", Category: taint.SnkFileWrite, Pattern: `Deno\.writeFile\s*\(`, ObjectType: "Deno", MethodName: "writeFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deno.writeFile() arbitrary file write with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.deno.remove", Category: taint.SnkFileWrite, Pattern: `Deno\.remove\s*\(`, ObjectType: "Deno", MethodName: "remove", DangerousArgs: []int{0}, Severity: rules.High, Description: "Deno.remove() file/directory deletion with user-controlled path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// Deno runtime — code execution (CWE-94)
	{ID: "js.deno.dlopen", Category: taint.SnkEval, Pattern: `Deno\.dlopen\s*\(`, ObjectType: "Deno", MethodName: "dlopen", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Deno.dlopen() dynamic library loading with user-controlled path", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// Deno runtime — SSRF (CWE-918)
	{ID: "js.deno.connect", Category: taint.SnkURLFetch, Pattern: `Deno\.connect\s*\(`, ObjectType: "Deno", MethodName: "connect", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Deno.connect() TCP connection with user-controlled hostname (SSRF)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// --- Electron desktop app sinks ---
	// Electron apps run with full OS access. User-controlled data reaching these APIs
	// can lead to RCE, SSRF, file access, and privilege escalation.

	// Electron — command execution via protocol handler (CWE-78)
	{ID: "js.electron.shell.openexternal", Category: taint.SnkCommand, Pattern: `shell\.openExternal\s*\(`, ObjectType: "electron.shell", MethodName: "openExternal", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Electron shell.openExternal() opens URL in default app — attacker-controlled URL with custom protocol handler leads to RCE (CVE-2018-1000006, CVE-2020-25019)", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

	// Electron — URL loading in BrowserWindow (CWE-918)
	{ID: "js.electron.loadurl", Category: taint.SnkURLFetch, Pattern: `\.loadURL\s*\(`, ObjectType: "", MethodName: "loadURL", DangerousArgs: []int{0}, Severity: rules.High, Description: "Electron BrowserWindow/WebView loadURL() with user-controlled URL — SSRF to internal network, javascript: URL for XSS, or phishing via arbitrary page load", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Electron — local file loading (CWE-22)
	{ID: "js.electron.loadfile", Category: taint.SnkFileRead, Pattern: `\.loadFile\s*\(`, ObjectType: "", MethodName: "loadFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Electron BrowserWindow.loadFile() with user-controlled path — path traversal to read arbitrary local files", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// Electron — code injection in renderer (CWE-94)
	{ID: "js.electron.executejavascript", Category: taint.SnkEval, Pattern: `\.executeJavaScript\s*\(`, ObjectType: "", MethodName: "executeJavaScript", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Electron webContents.executeJavaScript() with user-controlled code — arbitrary JS execution in renderer context (RCE if nodeIntegration enabled)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// Electron — CSS injection (CWE-79)
	{ID: "js.electron.insertcss", Category: taint.SnkHTMLOutput, Pattern: `\.insertCSS\s*\(`, ObjectType: "", MethodName: "insertCSS", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Electron webContents.insertCSS() with user-controlled CSS — UI spoofing, data exfiltration via CSS selectors", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

	// Electron — custom protocol file access (CWE-22)
	{ID: "js.electron.protocol.registerfileprotocol", Category: taint.SnkFileRead, Pattern: `protocol\.register(?:File|Buffer|String|Stream|Http)Protocol\s*\(`, ObjectType: "electron.protocol", MethodName: "registerFileProtocol", DangerousArgs: []int{-1}, Severity: rules.High, Description: "Electron custom protocol handler registration — if callback serves files based on request URL, enables path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// Electron — proxy hijacking (CWE-918)
	{ID: "js.electron.session.setproxy", Category: taint.SnkURLFetch, Pattern: `session\.setProxy\s*\(`, ObjectType: "electron.session", MethodName: "setProxy", DangerousArgs: []int{0}, Severity: rules.High, Description: "Electron session.setProxy() with user-controlled config — redirects all network traffic through attacker proxy (MITM)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

	// Electron — IPC trust boundary violation (CWE-501)
	{ID: "js.electron.webcontents.send", Category: taint.SnkTrustBoundary, Pattern: `\.webContents\.send\s*\(`, ObjectType: "electron.webContents", MethodName: "send", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "Electron webContents.send() passes tainted data from main process to renderer — trust boundary violation if renderer assumes data is safe", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},

	// Electron — clipboard HTML injection (CWE-79)
	{ID: "js.electron.clipboard.writehtml", Category: taint.SnkHTMLOutput, Pattern: `clipboard\.writeHTML\s*\(`, ObjectType: "electron.clipboard", MethodName: "writeHTML", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Electron clipboard.writeHTML() with user-controlled content — HTML injection when pasted into rich text editors", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

	// Electron — save dialog path control (CWE-22)
	{ID: "js.electron.dialog.showsavedialog", Category: taint.SnkFileWrite, Pattern: `dialog\.showSaveDialog(?:Sync)?\s*\(`, ObjectType: "electron.dialog", MethodName: "showSaveDialog", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Electron dialog.showSaveDialog() with user-controlled defaultPath — influences save location for social engineering attacks", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// =================================================================
	// Prototype pollution — CWE-1321 (SnkPrototype)
	// =================================================================
	// Each library family needs two entries (one per common receiver alias)
	// because the tsflow walker's Module gate matches a single module name
	// per sink. lodash callers may use either the `_` shorthand or the
	// `lodash` namespace; Hoek may appear as `Hoek`, `hoek`, or `@hapi/hoek`
	// (the destructured-import form `const { merge } = require('lodash')`
	// is a known limitation — restoring it requires per-file import-alias
	// resolution which the regex/tsflow path does not have).

	// --- lodash _.defaultsDeep / lodash.defaultsDeep (CVE-2019-10744) ---
	{ID: "BATOU-JSTS-PROTO-001", Category: taint.SnkPrototype, Pattern: `_\.defaultsDeep\s*\(`, ObjectType: "_", MethodName: "defaultsDeep", Module: "_", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "Lodash _.defaultsDeep() assigns defaults into a nested object — attacker-controlled source keys pollute Object.prototype (CVE-2019-10744)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "BATOU-JSTS-PROTO-001b", Category: taint.SnkPrototype, Pattern: `lodash\.defaultsDeep\s*\(`, ObjectType: "lodash", MethodName: "defaultsDeep", Module: "lodash", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "lodash.defaultsDeep() namespaced form — same prototype-pollution risk as _.defaultsDeep (CVE-2019-10744)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- lodash _.merge / lodash.merge (CVE-2018-16487, CVE-2019-10744 family) ---
	{ID: "BATOU-JSTS-PROTO-002", Category: taint.SnkPrototype, Pattern: `_\.merge\s*\(`, ObjectType: "_", MethodName: "merge", Module: "_", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "Lodash _.merge() recursively merges user-controlled source into target — attacker keys like __proto__/constructor/prototype cause prototype pollution (CVE-2018-16487, CVE-2019-10744)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "BATOU-JSTS-PROTO-002b", Category: taint.SnkPrototype, Pattern: `lodash\.merge\s*\(`, ObjectType: "lodash", MethodName: "merge", Module: "lodash", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "lodash.merge() namespaced form — same prototype-pollution risk as _.merge", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- lodash _.mergeWith / lodash.mergeWith (CVE-2018-16487) ---
	{ID: "BATOU-JSTS-PROTO-003", Category: taint.SnkPrototype, Pattern: `_\.mergeWith\s*\(`, ObjectType: "_", MethodName: "mergeWith", Module: "_", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "Lodash _.mergeWith() recursively merges user-controlled source with a customizer — still vulnerable to __proto__/constructor pollution (CVE-2018-16487)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "BATOU-JSTS-PROTO-003b", Category: taint.SnkPrototype, Pattern: `lodash\.mergeWith\s*\(`, ObjectType: "lodash", MethodName: "mergeWith", Module: "lodash", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "lodash.mergeWith() namespaced form — same prototype-pollution risk", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- lodash _.set / lodash.set (CVE-2020-8203) ---
	// _.set(obj, path, value): the path string can contain __proto__ segments.
	// All args are flagged (path AND value) since either being attacker-derived
	// constitutes the vulnerability shape.
	{ID: "BATOU-JSTS-PROTO-004", Category: taint.SnkPrototype, Pattern: `_\.set\s*\(`, ObjectType: "_", MethodName: "set", Module: "_", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "Lodash _.set(obj, path, value) with user-controlled path traverses __proto__ segments to pollute Object.prototype (CVE-2020-8203)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "BATOU-JSTS-PROTO-004b", Category: taint.SnkPrototype, Pattern: `lodash\.set\s*\(`, ObjectType: "lodash", MethodName: "set", Module: "lodash", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "lodash.set() namespaced form — same __proto__-traversal risk as _.set (CVE-2020-8203)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- lodash _.setWith / lodash.setWith (CVE-2020-8203 family) ---
	{ID: "BATOU-JSTS-PROTO-005", Category: taint.SnkPrototype, Pattern: `_\.setWith\s*\(`, ObjectType: "_", MethodName: "setWith", Module: "_", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "Lodash _.setWith(obj, path, value, customizer) with user-controlled path pollutes Object.prototype via __proto__ traversal (CVE-2020-8203)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "BATOU-JSTS-PROTO-005b", Category: taint.SnkPrototype, Pattern: `lodash\.setWith\s*\(`, ObjectType: "lodash", MethodName: "setWith", Module: "lodash", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "lodash.setWith() namespaced form — same __proto__-traversal risk", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- lodash _.zipObjectDeep / lodash.zipObjectDeep (CVE-2020-8203) ---
	{ID: "BATOU-JSTS-PROTO-006", Category: taint.SnkPrototype, Pattern: `_\.zipObjectDeep\s*\(`, ObjectType: "_", MethodName: "zipObjectDeep", Module: "_", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "Lodash _.zipObjectDeep(paths, values) with user-controlled paths pollutes Object.prototype when a path begins with __proto__ (CVE-2020-8203)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "BATOU-JSTS-PROTO-006b", Category: taint.SnkPrototype, Pattern: `lodash\.zipObjectDeep\s*\(`, ObjectType: "lodash", MethodName: "zipObjectDeep", Module: "lodash", RequireModule: true, DangerousArgs: []int{-1}, Severity: rules.High, Description: "lodash.zipObjectDeep() namespaced form — same __proto__-traversal risk", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- hapi/Hoek Hoek.merge (CVE-2018-3728) ---
	// Receiver may be `Hoek` (legacy), `hoek` (lowercase alias), or `@hapi/hoek`.
	// The Module field matches the first dotted segment, so we register the
	// distinct receiver shapes separately.
	{ID: "BATOU-JSTS-PROTO-007", Category: taint.SnkPrototype, Pattern: `Hoek\.merge\s*\(`, ObjectType: "Hoek", MethodName: "merge", Module: "Hoek", RequireModule: true, DangerousArgs: []int{1}, Severity: rules.High, Description: "hapi Hoek.merge(target, source) recursively copies user-controlled source keys — vulnerable to __proto__/constructor pollution (CVE-2018-3728)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "BATOU-JSTS-PROTO-007b", Category: taint.SnkPrototype, Pattern: `hoek\.merge\s*\(`, ObjectType: "hoek", MethodName: "merge", Module: "hoek", RequireModule: true, DangerousArgs: []int{1}, Severity: rules.High, Description: "hapi hoek.merge() lowercase-alias receiver — same prototype-pollution risk (CVE-2018-3728)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- hapi/Hoek Hoek.applyToDefaults (CVE-2018-3728) ---
	{ID: "BATOU-JSTS-PROTO-008", Category: taint.SnkPrototype, Pattern: `Hoek\.applyToDefaults\s*\(`, ObjectType: "Hoek", MethodName: "applyToDefaults", Module: "Hoek", RequireModule: true, DangerousArgs: []int{1}, Severity: rules.High, Description: "hapi Hoek.applyToDefaults(defaults, options) deep-copies user-controlled options — attacker keys pollute Object.prototype (CVE-2018-3728)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
	{ID: "BATOU-JSTS-PROTO-008b", Category: taint.SnkPrototype, Pattern: `hoek\.applyToDefaults\s*\(`, ObjectType: "hoek", MethodName: "applyToDefaults", Module: "hoek", RequireModule: true, DangerousArgs: []int{1}, Severity: rules.High, Description: "hapi hoek.applyToDefaults() lowercase-alias receiver — same prototype-pollution risk", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- Object.assign(target, src) (generic prototype-pollution gadget) ---
	// Plain ECMAScript Object.assign is safe for non-attacker objects, but when
	// the source object originates from JSON.parse / req.body and contains the
	// __proto__ key, Object.assign(target, src) is still a vector. The
	// receiver is the global `Object` namespace — RequireModule is intentionally
	// false here because Object is built-in, not imported.
	{ID: "BATOU-JSTS-PROTO-009", Category: taint.SnkPrototype, Pattern: `Object\.assign\s*\(`, ObjectType: "Object", MethodName: "assign", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "Object.assign(target, src) with user-controlled src — when src contains the literal key '__proto__' Node still walks the property descriptor and can pollute the target's prototype chain (defence-in-depth filter; sanitize keys before assignment)", CWEID: "CWE-1321", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

	// --- Archive extraction sinks (Zip Slip / Tar Slip — CWE-22) ---
	// These library calls extract archives directly to the filesystem. When the
	// archive is attacker-controlled (uploaded, downloaded from an untrusted
	// source), entries containing "../" or absolute paths escape the target
	// directory. References: CVE-2018-1002204 (adm-zip), CVE-2021-32803 /
	// CVE-2021-37701 (node-tar), Snyk zip-slip advisories for decompress and
	// extract-zip. Mitigation: validate each resolved entry path starts with
	// the intended target before writing.
	{ID: "js.admzip.extractallto", Category: taint.SnkFileWrite, Pattern: `\.extractAllTo\s*\(`, ObjectType: "", MethodName: "extractAllTo", DangerousArgs: []int{0}, Severity: rules.High, Description: "adm-zip AdmZip.extractAllTo() does not validate entry paths — malicious archives write outside target (Zip Slip, CVE-2018-1002204)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.admzip.extractentryto", Category: taint.SnkFileWrite, Pattern: `\.extractEntryTo\s*\(`, ObjectType: "", MethodName: "extractEntryTo", DangerousArgs: []int{1}, Severity: rules.High, Description: "adm-zip AdmZip.extractEntryTo() writes a single archive entry to target — entry path is attacker-controlled (Zip Slip)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.tar.x", Category: taint.SnkFileWrite, Pattern: `\btar\.x\s*\(`, ObjectType: "tar", MethodName: "x", DangerousArgs: []int{0}, Severity: rules.High, Description: "node-tar tar.x() extracts a tarball — symlink/path tricks bypass protections on older versions (CVE-2021-32803, CVE-2021-37701)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.tar.extract", Category: taint.SnkFileWrite, Pattern: `\btar\.extract\s*\(`, ObjectType: "tar", MethodName: "extract", DangerousArgs: []int{0}, Severity: rules.High, Description: "node-tar tar.extract() extracts a tarball into cwd — entries with absolute paths or symlinks escape target", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// --- Task queue producer trust-boundary sinks (CWE-501) ---
	// Producer-side trust boundary: when a web handler pushes user-controlled
	// values into a background job queue, the payload is serialized (JSON/MessagePack)
	// to Redis/RabbitMQ/AMQP and later deserialized + acted on by a worker in a
	// privileged context. Tainted arg → cross-boundary re-execution. Mirror of
	// the existing Python py.rq.enqueue / py.celery.apply_async and Ruby
	// Sidekiq/Resque/ActiveJob trust-boundary sinks.
	{ID: "js.bullmq.queue.addbulk", Category: taint.SnkTrustBoundary, Pattern: `\.addBulk\s*\(`, ObjectType: "", MethodName: "addBulk", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "BullMQ/Bull queue.addBulk([{name, data}]) enqueues jobs with tainted payloads — data serialized to Redis, re-executed later in worker context (trust boundary)", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.beequeue.createjob", Category: taint.SnkTrustBoundary, Pattern: `\.createJob\s*\(`, ObjectType: "", MethodName: "createJob", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "bee-queue queue.createJob(data) creates a job with tainted payload — data serialized to Redis, re-executed later in worker context (trust boundary)", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.resque.enqueue", Category: taint.SnkTrustBoundary, Pattern: `\.enqueue\s*\(`, ObjectType: "", MethodName: "enqueue", DangerousArgs: []int{2}, Severity: rules.Medium, Description: "node-resque queue.enqueue(queueName, jobName, args) with tainted args — args serialized to Redis, re-executed later in worker context (trust boundary)", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.resque.enqueuein", Category: taint.SnkTrustBoundary, Pattern: `\.enqueueIn\s*\(`, ObjectType: "", MethodName: "enqueueIn", DangerousArgs: []int{3}, Severity: rules.Medium, Description: "node-resque queue.enqueueIn(ms, queueName, jobName, args) delayed job with tainted args — crosses trust boundary via Redis", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.resque.enqueueat", Category: taint.SnkTrustBoundary, Pattern: `\.enqueueAt\s*\(`, ObjectType: "", MethodName: "enqueueAt", DangerousArgs: []int{3}, Severity: rules.Medium, Description: "node-resque queue.enqueueAt(timestamp, queueName, jobName, args) scheduled job with tainted args — crosses trust boundary via Redis", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.amqplib.sendtoqueue", Category: taint.SnkTrustBoundary, Pattern: `\.sendToQueue\s*\(`, ObjectType: "", MethodName: "sendToQueue", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "amqplib channel.sendToQueue(queue, content) with tainted Buffer — payload published to RabbitMQ, re-executed later in consumer context (trust boundary)", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},

	// --- Neo4j Cypher-injection sinks (CWE-943) ---
	// neo4j-driver (the official Node.js driver) executes Cypher via
	// Session.run / Transaction.run / Driver.executeQuery. When the Cypher
	// string is built from user input via concatenation or template literals,
	// attackers can alter MATCH/CREATE/DELETE semantics. The canonical fix is
	// to pass user values through a parameters map with $name placeholders:
	//   session.run('MATCH (u:User {name: $name}) RETURN u', { name: userInput })
	// See https://neo4j.com/developer/kb/protecting-against-cypher-injection/
	// Mirrors the existing java.neo4j.session.run / java.neo4j.tx.run sinks.
	{ID: "js.neo4j.session.run", Category: taint.SnkNoSQL, Pattern: `(?:session|sess|neo4jSession)\.run\s*\(`, ObjectType: "Session", MethodName: "run", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Neo4j Session.run() with tainted Cypher string (Cypher injection); pass user values via a parameters object with $name placeholders instead", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.neo4j.tx.run", Category: taint.SnkNoSQL, Pattern: `(?:tx|trx|neo4jTx)\.run\s*\(`, ObjectType: "Tx", MethodName: "run", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Neo4j Transaction.run() (inside session.executeRead/executeWrite callback or session.beginTransaction block) with tainted Cypher string (Cypher injection); pass user values via a parameters object with $name placeholders instead", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.neo4j.driver.executequery", Category: taint.SnkNoSQL, Pattern: `(?:driver|neo4jDriver)\.executeQuery\s*\(`, ObjectType: "Driver", MethodName: "executeQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Neo4j Driver.executeQuery() (v5.5+ unified API) with tainted Cypher string (Cypher injection); pass user values via a parameters object with $name placeholders instead", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},

	// --- Elasticsearch v8 / OpenSearch query-DSL + Painless script injection ---
	// @elastic/elasticsearch and @opensearch-project/opensearch expose
	// camelCase methods on the Client where the request body is an object
	// containing query DSL JSON. A tainted body permits arbitrary
	// query-structure injection (CWE-943) and — for endpoints that accept
	// Painless scripts (updateByQuery, reindex, putScript, scriptsPainlessExecute)
	// — arbitrary code execution on the cluster (CWE-94).
	//
	// Mirrors py.elasticsearch.* / go.elasticsearch.* / php.elasticsearch.*
	// sinks. The OpenSearch JS client is a fork of the Elasticsearch one and
	// shares identical method names, so a single sink set covers both —
	// patterns intentionally do not constrain receiver to "esClient" vs
	// "osClient" to avoid double-firing on `client.foo(...)`.
	//
	// Refs:
	//   https://www.elastic.co/guide/en/elasticsearch/client/javascript-api/current/api-reference.html
	//   https://opensearch.org/docs/latest/clients/javascript/index/
	//   https://www.elastic.co/guide/en/elasticsearch/painless/current/painless-execute-api.html
	{ID: "js.elasticsearch.bulk", Category: taint.SnkNoSQL, Pattern: `\.bulk\s*\(`, ObjectType: "", MethodName: "bulk", DangerousArgs: []int{0}, Severity: rules.High, Description: "Elasticsearch/OpenSearch JS client .bulk() with tainted body — DSL injection across mixed index/update/delete actions on the cluster (CWE-943)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.elasticsearch.msearch", Category: taint.SnkNoSQL, Pattern: `\.msearch\s*\(`, ObjectType: "", MethodName: "msearch", DangerousArgs: []int{0}, Severity: rules.High, Description: "Elasticsearch/OpenSearch JS client .msearch() multi-search with tainted NDJSON body — per-shard DSL injection / cross-index data exfiltration (CWE-943)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.elasticsearch.deletebyquery", Category: taint.SnkNoSQL, Pattern: `\.deleteByQuery\s*\(`, ObjectType: "", MethodName: "deleteByQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Elasticsearch/OpenSearch JS client .deleteByQuery() with tainted query body — DSL injection on a destructive bulk operation (mass document deletion outside intended scope) (CWE-943)", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.elasticsearch.updatebyquery", Category: taint.SnkEval, Pattern: `\.updateByQuery\s*\(`, ObjectType: "", MethodName: "updateByQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Elasticsearch/OpenSearch JS client .updateByQuery() with tainted body — Painless 'script' field allows arbitrary code execution on the cluster; query field allows DSL injection (CWE-94/CWE-943)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.elasticsearch.reindex", Category: taint.SnkEval, Pattern: `\.reindex\s*\(`, ObjectType: "", MethodName: "reindex", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Elasticsearch/OpenSearch JS client .reindex() body accepts a 'script' field (Painless) — tainted source = arbitrary code execution on the cluster plus DSL injection over source/dest selectors (CWE-94)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.elasticsearch.putscript", Category: taint.SnkEval, Pattern: `\.putScript\s*\(`, ObjectType: "", MethodName: "putScript", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Elasticsearch/OpenSearch JS client .putScript() stores a tainted Painless script — every later invocation executes the attacker-supplied code on the cluster (persistent RCE) (CWE-94)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.elasticsearch.scriptspainlessexecute", Category: taint.SnkEval, Pattern: `\.scriptsPainlessExecute\s*\(`, ObjectType: "", MethodName: "scriptsPainlessExecute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Elasticsearch/OpenSearch JS client .scriptsPainlessExecute() with tainted script body — direct Painless code execution on the cluster (CWE-94)", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

	// Apache Cassandra / ScyllaDB / DataStax Enterprise — DataStax cassandra-driver
	// Node.js (and @scylladb/scylla-driver, dse-driver forks) — CQL injection (CWE-943).
	//
	// The driver exposes a Client constructed as
	//   const cassandra = require('cassandra-driver');
	//   const client = new cassandra.Client({ contactPoints, localDataCenter });
	// Methods that take a CQL string as their first argument:
	//   - client.execute(cql, params, opts) — already covered by the generic
	//     js.sql.execute (empty-ObjectType, MethodName "execute").
	//   - client.executeAsync(cql, ...) — older promise-style API kept for
	//     backwards compatibility; not covered elsewhere.
	//   - client.eachRow(cql, params, [opts], rowCb, [endCb]) — streaming
	//     row-by-row API; uniquely Cassandra.
	//   - client.batch(queries, [opts]) — first arg is an array of CQL
	//     strings or {query, params} objects; tainted CQL inside any entry
	//     is injectable.
	//   - new cassandra.types.SimpleStatement(cql) — explicit Statement
	//     constructor; values must travel via the params arg, not the CQL.
	// Safe code uses parameterized queries:
	//   client.execute(cql, [val], { prepare: true }).
	//
	// @scylladb/scylla-driver and dse-driver are API-compatible forks; the
	// same method names cover all three drivers.
	//
	// Refs:
	//   https://docs.datastax.com/en/developer/nodejs-driver/latest/api/
	//   https://github.com/datastax/nodejs-driver
	//   https://github.com/scylladb/nodejs-driver
	{ID: "js.cassandra.client.eachrow", Category: taint.SnkNoSQL, Pattern: `\.eachRow\s*\(`, ObjectType: "", MethodName: "eachRow", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "DataStax cassandra-driver / ScyllaDB Client.eachRow(cql, params, ...) with tainted CQL string enables CQL injection; pass user values via the params array, not by string interpolation", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.cassandra.client.executeasync", Category: taint.SnkNoSQL, Pattern: `\.executeAsync\s*\(`, ObjectType: "", MethodName: "executeAsync", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "DataStax cassandra-driver Client.executeAsync(cql, params) with tainted CQL string enables CQL injection; pass user values via the params array, not by string interpolation", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.cassandra.client.batch", Category: taint.SnkNoSQL, Pattern: `\.batch\s*\(`, ObjectType: "", MethodName: "batch", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "DataStax cassandra-driver Client.batch(queries, opts) with tainted CQL inside the queries array (string or {query, params}) enables CQL injection; build entries from prepared statements or literal CQL with ? placeholders", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.cassandra.simplestatement", Category: taint.SnkNoSQL, Pattern: `\bSimpleStatement\s*\(`, ObjectType: "", MethodName: "SimpleStatement", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "DataStax cassandra-driver new cassandra.types.SimpleStatement(cql) seeded from a tainted CQL string is injectable; use a literal CQL with ? placeholders and pass values via the params arg", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},

	// ── Cloud Data Warehouse SQL/PartiQL injection (CWE-89 / CWE-943) ──────
	// JavaScript / TypeScript clients for managed analytics warehouses. All of
	// these libraries provide a parameter-binding API (positional ? or named
	// @name / :name placeholders) — direct concatenation of user input into
	// the SQL string is SQL injection. Safe equivalents are documented inline.
	//
	// Refs:
	//   BigQuery Node.js client:   https://github.com/googleapis/nodejs-bigquery
	//   BigQuery parameterized SQL: https://cloud.google.com/bigquery/docs/parameterized-queries
	//   AWS SDK v3 Athena:         https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-athena/
	//   AWS SDK v3 Redshift Data:  https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-redshift-data/
	//   AWS SDK v3 RDS Data:       https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-rds-data/
	//   AWS SDK v3 DynamoDB PartiQL: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.html
	//   Athena prepared statements: https://docs.aws.amazon.com/athena/latest/ug/querying-with-prepared-statements.html
	{ID: "js.bigquery.client.createqueryjob", Category: taint.SnkSQLQuery, Pattern: `\.createQueryJob\s*\(`, ObjectType: "", MethodName: "createQueryJob", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "@google-cloud/bigquery BigQuery.createQueryJob(sqlOrOptions) submits raw SQL to BigQuery — tainted concatenated SQL is SQL injection. Pass user values via the `params` field (named @name or positional ?) of an options object alongside a constant `query` string instead.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.aws.athena.startqueryexecutioncommand", Category: taint.SnkSQLQuery, Pattern: `new\s+StartQueryExecutionCommand\s*\(`, ObjectType: "", MethodName: "StartQueryExecutionCommand", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "@aws-sdk/client-athena new StartQueryExecutionCommand({QueryString, ExecutionParameters}) — tainted QueryString built by string concatenation is SQL injection on Athena. Use ? placeholders inside QueryString and pass user values via the ExecutionParameters[] array.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.aws.executestatementcommand", Category: taint.SnkSQLQuery, Pattern: `new\s+ExecuteStatementCommand\s*\(`, ObjectType: "", MethodName: "ExecuteStatementCommand", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AWS SDK v3 ExecuteStatementCommand (covers @aws-sdk/client-redshift-data, @aws-sdk/client-rds-data, and @aws-sdk/client-dynamodb PartiQL) — tainted Sql/sql/Statement string in the input object is SQL/PartiQL injection. Use the Parameters[]/parameters[] array with named (:name) or positional (?) placeholders to bind user values safely.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.aws.batchexecutestatementcommand", Category: taint.SnkSQLQuery, Pattern: `new\s+BatchExecuteStatementCommand\s*\(`, ObjectType: "", MethodName: "BatchExecuteStatementCommand", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AWS SDK v3 BatchExecuteStatementCommand (covers @aws-sdk/client-redshift-data Sqls[] and @aws-sdk/client-dynamodb PartiQL Statements[]) — tainted entries in the array are SQL/PartiQL injection. Build each statement from a constant template with placeholders + bound parameters.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

	// ── Elasticsearch / OpenSearch search template (CWE-943) ────────────────
	// Followup to the elasticsearch sink set above (see PR #457 / cycle #616):
	// .searchTemplate({body: {source, params}}) renders the Mustache `source`
	// template into a query DSL on the cluster — when source is attacker-
	// controlled, the entire DSL is attacker-controlled (cross-index search
	// injection / data exfiltration). The safe form references a stored
	// template by `id` and binds user values via the `params` object only.
	//   https://www.elastic.co/guide/en/elasticsearch/reference/current/search-template.html
	{ID: "js.elasticsearch.searchtemplate", Category: taint.SnkNoSQL, Pattern: `\.searchTemplate\s*\(`, ObjectType: "", MethodName: "searchTemplate", DangerousArgs: []int{0}, Severity: rules.High, Description: "Elasticsearch/OpenSearch JS client .searchTemplate() with tainted body — Mustache `source` template renders directly into the query DSL, allowing DSL injection / cross-index data exfiltration when `source` is attacker-controlled. Reference a stored template by `id` and bind user input via the `params` object only.", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},

	// =================================================================
	// Mined from public MIT-licensed security-model data.
	// JS Models-as-Data extension data — Apollo, AWS SDK, axios, cors,
	// SAP HANA clients, file-system util packages, etc.
	// =================================================================
	{ID: "js.apollo.gql", Category: taint.SnkSQLQuery, Pattern: `\bgql\s*` + "`" + `|\bgql\s*\(`, ObjectType: "@apollo/server", MethodName: "gql", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Apollo Server gql template — tainted GraphQL query string permits query injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.apollo.cors_origin", Category: taint.SnkHeader, Pattern: `\bApolloServer\s*\(`, ObjectType: "@apollo/server", MethodName: "ApolloServer/cors.origin", DangerousArgs: []int{0}, Severity: rules.High, Description: "Apollo Server cors.origin option — a tainted value enables cross-origin attacks", CWEID: "CWE-942", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.aws.athena.start_query_execution", Category: taint.SnkSQLQuery, Pattern: `\.(?:startQueryExecution|createNamedQuery|updateNamedQuery)\s*\(`, ObjectType: "aws-sdk", MethodName: "Athena.startQueryExecution/createNamedQuery/updateNamedQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AWS Athena QueryString — Presto SQL injection through tainted query", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.aws.s3.select_object_content", Category: taint.SnkSQLQuery, Pattern: `\.selectObjectContent\s*\(`, ObjectType: "aws-sdk", MethodName: "S3.selectObjectContent", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AWS S3.selectObjectContent Expression — S3 Select SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.aws.rds.execute_statement", Category: taint.SnkSQLQuery, Pattern: `\.(?:executeStatement|batchExecuteStatement)\s*\(`, ObjectType: "aws-sdk", MethodName: "RDSDataService.executeStatement/batchExecuteStatement", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AWS RDS Data API sql parameter — SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.aws.dynamodb.execute_statement", Category: taint.SnkNoSQL, Pattern: `\.(?:executeStatement|batchExecuteStatement)\s*\(`, ObjectType: "aws-sdk", MethodName: "DynamoDB.executeStatement/batchExecuteStatement", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AWS DynamoDB PartiQL Statement — NoSQL injection", CWEID: "CWE-943", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.axios.interceptor_request_url", Category: taint.SnkURLFetch, Pattern: `axios\.interceptors\.request\.use\s*\(`, ObjectType: "axios", MethodName: "interceptors.request.use", DangerousArgs: []int{0}, Severity: rules.High, Description: "axios request interceptor — a tainted config.url permits SSRF on intercepted requests", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
	{ID: "js.cors.origin", Category: taint.SnkHeader, Pattern: `\bcors\s*\(`, ObjectType: "cors", MethodName: "cors", DangerousArgs: []int{0}, Severity: rules.High, Description: "cors middleware origin option — a reflected or wildcarded origin enables cross-origin attacks", CWEID: "CWE-942", OWASPCategory: "A05:2021-Security Misconfiguration"},
	{ID: "js.hana.exec", Category: taint.SnkSQLQuery, Pattern: `\.(?:exec|prepare)\s*\(`, ObjectType: "@sap/hana-client", MethodName: "createConnection.exec/prepare", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SAP HANA client exec/prepare — SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.hdb.exec", Category: taint.SnkSQLQuery, Pattern: `\.(?:exec|prepare|execute)\s*\(`, ObjectType: "hdb", MethodName: "Client.exec/prepare/execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "hdb Client SAP HANA query — SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.hdbext.load_procedure", Category: taint.SnkSQLQuery, Pattern: `\.loadProcedure\s*\(`, ObjectType: "@sap/hdbext", MethodName: "loadProcedure", DangerousArgs: []int{2}, Severity: rules.Critical, Description: "SAP HANA loadProcedure schema/proc name — SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.hana.stream.create_proc_statement", Category: taint.SnkSQLQuery, Pattern: `\.createProcStatement\s*\(`, ObjectType: "@sap/hana-client/extension/Stream", MethodName: "createProcStatement", DangerousArgs: []int{1}, Severity: rules.Critical, Description: "SAP HANA Stream createProcStatement — SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.make_dir.make_directory", Category: taint.SnkFileWrite, Pattern: `\bmake[Dd]irectory(?:Sync)?\s*\(`, ObjectType: "make-dir", MethodName: "makeDirectory/makeDirectorySync", DangerousArgs: []int{0}, Severity: rules.High, Description: "make-dir makeDirectory — tainted path is path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.mkdirp.native", Category: taint.SnkFileWrite, Pattern: `\bmkdirp\.(?:nativeSync|native|manual|manualSync|mkdirpNative|mkdirpManual|mkdirpManualSync|mkdirpNativeSync|mkdirpSync|sync)\s*\(`, ObjectType: "mkdirp", MethodName: "nativeSync/native/manual/manualSync/mkdirpNative/mkdirpManual/mkdirpManualSync/mkdirpNativeSync/mkdirpSync/sync", DangerousArgs: []int{0}, Severity: rules.High, Description: "mkdirp variants — tainted directory path is path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.open.open_app", Category: taint.SnkCommand, Pattern: `\bopen\.openApp\s*\(`, ObjectType: "open", MethodName: "openApp", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "open.openApp — launches an application; tainted arg is command injection", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.rimraf.async", Category: taint.SnkFileWrite, Pattern: `\brimraf\.(?:sync|native|manual|windows|moveRemove|posix)\s*\(`, ObjectType: "rimraf", MethodName: "sync/native/manual/windows/moveRemove/posix", DangerousArgs: []int{0}, Severity: rules.High, Description: "rimraf removal — tainted path lets attacker remove arbitrary files", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
	{ID: "js.rimraf.sync", Category: taint.SnkFileWrite, Pattern: `\brimraf\.(?:rimrafSync|nativeSync|manualSync|windowsSync|moveRemoveSync|posixSync)\s*\(`, ObjectType: "rimraf", MethodName: "rimrafSync/nativeSync/manualSync/windowsSync/moveRemoveSync/posixSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "rimraf sync removal variants — tainted path lets attacker remove arbitrary files", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

	// =================================================================
	// Cloudflare Workers bindings — D1 SQL injection + Queue trust-boundary.
	//
	// Bindings are exposed as `env.<BINDING_NAME>` (and via Hono `c.env.<BINDING_NAME>`)
	// with TypeScript types `D1Database`, `Queue`, `KVNamespace`, `R2Bucket`.
	// Catalog uses the type name as ObjectType; tsflow matcher's database/
	// qualified-receiver heuristics map the conventional binding names
	// `env.DB` (D1Database — via `.db` suffix), `env.QUEUE` (Queue — via
	// last-component equality on the qualified receiver), and the bare
	// type-name aliases (DB/Queue) to these entries.
	//
	// Refs:
	//   https://developers.cloudflare.com/d1/worker-api/d1-database/#exec
	//   https://developers.cloudflare.com/queues/configuration/javascript-apis/
	// =================================================================
	{ID: "js.cloudflare.d1.exec", Category: taint.SnkSQLQuery, Pattern: `\.exec\s*\(`, ObjectType: "D1Database", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Cloudflare D1Database.exec(sql) runs one or more raw SQL statements with no parameter binding — tainted SQL string is SQL injection (use db.prepare(sql).bind(...) for parameterized queries)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.cloudflare.queue.send", Category: taint.SnkTrustBoundary, Pattern: `\.send\s*\(`, ObjectType: "Queue", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Cloudflare Workers Queue.send(message) with tainted payload — the message is serialized and re-executed in the consumer worker context (trust boundary, same pattern as amqplib.sendToQueue / bullmq.queue.add)", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	{ID: "js.cloudflare.queue.sendbatch", Category: taint.SnkTrustBoundary, Pattern: `\.sendBatch\s*\(`, ObjectType: "Queue", MethodName: "sendBatch", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Cloudflare Workers Queue.sendBatch([{body}]) with tainted message bodies — batched messages are serialized and re-executed in the consumer worker context (trust boundary)", CWEID: "CWE-501", OWASPCategory: "A04:2021-Insecure Design"},
	// --- AdonisJS (Lucid ORM / Edge templating) ---
	// AdonisJS v6 is a popular full-stack TypeScript MVC framework for Node.js.
	// Its Lucid ORM raw query API runs attacker-supplied SQL when the statement
	// string (arg 0) is built by string concatenation / template interpolation
	// instead of being passed through the bindings array (arg 1). The method
	// names below are intrinsically SQL-distinctive: rawQuery is unique to Lucid
	// (Knex/TypeORM use .raw), and the *Raw query-builder clause helpers
	// (whereRaw/orderByRaw/havingRaw/...) carry their own Raw suffix — the caller
	// has explicitly opted OUT of parameterisation for arg 0 — so matching on the
	// bare method (wildcard ObjectType) is safe and avoids the chained-receiver
	// problem (User.query().whereRaw(...) has no stable receiver name). The JS/TS
	// engine already suppresses the safe bind-array form whereRaw('id = ?', [id])
	// via isSafeJSSQLBuilderCall, so only the concat/interpolation shape reaches a
	// finding. db.raw IS receiver-scoped (ObjectType "Database" matches db) since
	// the bare name `raw` collides with unrelated APIs.
	{ID: "js.adonis.db.rawquery", Language: rules.LangJavaScript, Category: taint.SnkSQLQuery, Pattern: `\.rawQuery\s*\(`, ObjectType: "", MethodName: "rawQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AdonisJS Lucid db.rawQuery(sql) — running a concatenated/interpolated SQL string (instead of the bindings array) is SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.adonis.db.raw", Language: rules.LangJavaScript, Category: taint.SnkSQLQuery, Pattern: `\b(?:db|Database|trx)\.raw\s*\(`, ObjectType: "Database", MethodName: "raw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AdonisJS Lucid db.raw(sql) raw fragment — a concatenated SQL string injected into a builder query is SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.adonis.lucid.whereraw", Language: rules.LangJavaScript, Category: taint.SnkSQLQuery, Pattern: `\.(?:where|orWhere|andWhere)Raw\s*\(`, ObjectType: "", MethodName: "whereRaw/orWhereRaw/andWhereRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AdonisJS Lucid whereRaw(sql) — an attacker-controlled raw WHERE clause string (arg 0, not the bindings array) is SQL injection; the safe whereRaw('id = ?', [id]) bind form is suppressed by the engine's isSafeJSSQLBuilderCall", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.adonis.lucid.havingraw", Language: rules.LangJavaScript, Category: taint.SnkSQLQuery, Pattern: `\.(?:having|orHaving)Raw\s*\(`, ObjectType: "", MethodName: "havingRaw/orHavingRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AdonisJS Lucid havingRaw(sql) — attacker-controlled raw HAVING clause string (arg 0, not bindings) is SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	{ID: "js.adonis.lucid.orderbyraw", Language: rules.LangJavaScript, Category: taint.SnkSQLQuery, Pattern: `\.(?:orderBy|groupBy)Raw\s*\(`, ObjectType: "", MethodName: "orderByRaw/groupByRaw", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "AdonisJS Lucid orderByRaw/groupByRaw(sql) — attacker-controlled ORDER BY / GROUP BY clause string is SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	// Edge view raw-string rendering compiles the supplied template body, so a
	// request-controlled string is server-side template injection (SSTI).
	// renderRaw is Edge-distinctive, so a wildcard ObjectType is safe.
	{ID: "js.adonis.edge.renderraw", Language: rules.LangJavaScript, Category: taint.SnkTemplate, Pattern: `\.renderRaw(?:Sync)?\s*\(`, ObjectType: "", MethodName: "renderRaw/renderRawSync", DangerousArgs: []int{0}, Severity: rules.High, Description: "AdonisJS Edge view.renderRaw(templateString) — compiling an attacker-controlled template body is server-side template injection", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
}
