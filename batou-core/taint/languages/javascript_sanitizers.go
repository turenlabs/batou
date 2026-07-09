package languages

import (
	"github.com/turenlabs/batou-core/taint"

	"github.com/turenlabs/batou-rules/rules"
)

// jsSanitizers defines sanitizer patterns for JavaScript/TypeScript.
var jsSanitizers = []taint.SanitizerDef{
	{ID: "js.encodeuricomponent", Pattern: `encodeURIComponent\s*\(`, MethodName: "encodeURIComponent", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect}, Description: "URI component encoding"},
	{ID: "js.encodeuri", Pattern: `encodeURI\s*\(`, MethodName: "encodeURI", Neutralizes: []taint.SinkCategory{taint.SnkRedirect}, Description: "URI encoding"},
	{ID: "js.dompurify.sanitize", Pattern: `DOMPurify\.sanitize\s*\(`, ObjectType: "DOMPurify", MethodName: "sanitize", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "DOMPurify HTML sanitization"},
	{ID: "js.sanitize.html", Pattern: `sanitizeHtml\s*\(`, MethodName: "sanitizeHtml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "sanitize-html library"},
	{ID: "js.validator.escape", Pattern: `validator\.escape\s*\(`, ObjectType: "validator", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "validator.js escape"},
	{ID: "js.parseint", Pattern: `parseInt\s*\(`, MethodName: "parseInt", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer parsing (type coercion)"},
	{ID: "js.path.basename", Pattern: `path\.basename\s*\(`, ObjectType: "path", MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "Path basename extraction"},
	{ID: "js.knex.parameterized", Pattern: `knex\([^)]*\)\s*\.where\s*\(`, ObjectType: "knex", MethodName: "where", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Knex parameterized queries"},
	{ID: "js.escapehtml", Pattern: `\bescapeHtml\s*\(`, MethodName: "escapeHtml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML escape function"},

	// SQL parameterization sanitizers
	{ID: "js.prisma.tagged.template", Pattern: `Prisma\.sql\s*\x60`, ObjectType: "Prisma", MethodName: "sql", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Prisma tagged template literal (parameterized)"},
	{ID: "js.sequelize.bind", Pattern: `\.query\s*\([^,]+,\s*\{\s*(?:replacements|bind)`, ObjectType: "sequelize", MethodName: "query", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Sequelize parameterized query with bind/replacements"},
	// mssql request.input('name', type, value) declares a typed bound parameter;
	// the value is bound (never string-interpolated), so a subsequent
	// parameterized .query()/.execute() with @name placeholders is safe. Clears
	// the SQL category for the value flowing through the binding.
	{ID: "js.mssql.input", Pattern: `\.input\s*\(`, ObjectType: "Request", MethodName: "input", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "mssql Request.input(name, type, value) binds a typed parameter (parameterized, not interpolated)"},

	// MongoDB sanitizers
	{ID: "js.mongo.sanitize", Pattern: `mongo-sanitize|express-mongo-sanitize|sanitize\s*\(`, MethodName: "sanitize", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkNoSQL}, Description: "MongoDB query sanitization — mongo-sanitize / express-mongo-sanitize strip `$`-prefixed operator keys from the filter, defeating NoSQL operator/`$where` injection (SnkNoSQL); also retained for the legacy SnkSQLQuery pairing"},

	// Validation library sanitizers
	{ID: "js.zod.parse", Pattern: `\w+Schema\.parse\s*\(`, ObjectType: "ZodSchema", MethodName: "parse", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkTrustBoundary}, Description: "Zod schema validation and parsing"},
	{ID: "js.joi.validate", Pattern: `Joi\.(?:validate|attempt)\s*\(`, ObjectType: "Joi", MethodName: "validate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkTrustBoundary}, Description: "Joi schema validation"},
	{ID: "js.class-validator", Pattern: `@Is(?:String|Int|Email|Number|UUID)\s*\(`, ObjectType: "class-validator", MethodName: "IsString", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "class-validator decorator validation (Nest.js)"},
	{ID: "js.nestjs.validationpipe", Pattern: `ValidationPipe`, ObjectType: "NestJS", MethodName: "ValidationPipe", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Nest.js ValidationPipe (class-validator integration)"},

	// XSS sanitizers
	{ID: "js.xss.filter", Pattern: `xss\s*\(`, MethodName: "xss", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "xss library filter"},
	{ID: "js.isomorphic-dompurify", Pattern: `\bsanitize\s*\(`, ObjectType: "DOMPurify", MethodName: "sanitize", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "isomorphic-dompurify sanitize"},

	// Crypto / Auth Sanitizers
	{ID: "js.crypto.bcrypt.hash", Pattern: `bcrypt\.hash\s*\(|bcrypt\.hashSync\s*\(`, ObjectType: "bcrypt", MethodName: "bcrypt.hash", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "bcrypt password hashing (safe password storage)"},
	{ID: "js.crypto.bcrypt.compare", Pattern: `bcrypt\.compare\s*\(|bcrypt\.compareSync\s*\(`, ObjectType: "bcrypt", MethodName: "bcrypt.compare", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "bcrypt password verification (constant-time comparison)"},
	{ID: "js.crypto.timingsafeequal", Pattern: `crypto\.timingSafeEqual\s*\(`, ObjectType: "crypto", MethodName: "timingSafeEqual", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Constant-time buffer comparison (prevents timing attacks)"},
	{ID: "js.crypto.randombytes", Pattern: `crypto\.randomBytes\s*\(|crypto\.randomUUID\s*\(`, ObjectType: "crypto", MethodName: "randomBytes/randomUUID", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Cryptographically secure random bytes/UUID generation"},
	{ID: "js.csrf.middleware", Pattern: `csurf\s*\(|csrf\s*\(|csrfProtection`, ObjectType: "csurf", MethodName: "csurf", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "CSRF protection middleware (Express csurf)"},

	// Input validation sanitizers (CWE-20)
	{ID: "js.express-validator", Pattern: `(?:check|body|param|query|header)\s*\(\s*['"]`, ObjectType: "express-validator", MethodName: "check/body/param/query", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite, taint.SnkFileRead}, Description: "express-validator input validation"},
	{ID: "js.yup.validate", Pattern: `\.validate\s*\(|yup\.\w+\(\)`, ObjectType: "yup", MethodName: "validate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Yup schema validation"},
	{ID: "js.zod.safeparse", Pattern: `\.safeParse\s*\(`, ObjectType: "ZodSchema", MethodName: "safeParse", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Zod safe schema validation and parsing"},
	{ID: "js.ajv.validate", Pattern: `ajv\.validate\s*\(|\.compile\s*\([^)]*\)\s*\(`, ObjectType: "Ajv", MethodName: "validate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Ajv JSON schema validation"},

	// Infrastructure / Network Sanitizers
	{ID: "js.validator.isurl", Pattern: `validator\.isURL\s*\(`, ObjectType: "validator", MethodName: "isURL", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL validation via validator.js isURL (SSRF prevention)"},
	{ID: "js.validator.isip", Pattern: `validator\.isIP\s*\(`, ObjectType: "validator", MethodName: "isIP", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "IP address validation via validator.js isIP (SSRF prevention)"},
	// NOTE: `new URL(x).hostname` is intentionally NOT a standalone sanitizer.
	// Extracting the hostname performs no validation — the attacker still
	// controls the hostname, so fetching/redirecting with it is still
	// SSRF/open-redirect. Only extraction PLUS an allowlist comparison
	// neutralizes those sinks; the extraction step by itself must not kill
	// the taint flow.

	// NOTE: path.normalize() and path.resolve() are intentionally NOT
	// registered as standalone CWE-22 sanitizers (mirrors the filepath.Clean
	// note in go_sanitizers.go and the os.path.normpath/realpath note in
	// python_sanitizers.go). normalize("../../etc/passwd") is still
	// "../../etc/passwd", and resolve() returns an absolute path that can lie
	// OUTSIDE the safe base. A complete defence is canonicalize + containment
	// (e.g. path.resolve(base, x).startsWith(base + path.sep)) — the
	// canonicalize step by itself must not kill the taint flow.

	// Numeric coercion
	{ID: "js.number", Pattern: `\bNumber\s*\(`, MethodName: "Number", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Number type coercion (restricts to numeric values)"},
	{ID: "js.parsefloat", Pattern: `parseFloat\s*\(`, MethodName: "parseFloat", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Float parsing (type coercion to numeric)"},

	// HTML entity encoding
	{ID: "js.he.encode", Pattern: `he\.encode\s*\(|he\.escape\s*\(`, ObjectType: "he", MethodName: "encode/escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML entity encoding via he library"},

	// Safe YAML
	{ID: "js.yaml.safeload", Pattern: `yaml\.safeLoad\s*\(|YAML\.parse\s*\(`, ObjectType: "yaml", MethodName: "safeLoad/parse", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Safe YAML loading (disables dangerous types)"},

	// Type coercion sanitizers (convert to safe primitive types)
	{ID: "js.string.coerce", Pattern: `\bString\s*\(`, MethodName: "String", Neutralizes: []taint.SinkCategory{taint.SnkNoSQL}, Description: "String type coercion — defeats NoSQL operator injection (an object like {$ne: null} coerces to the literal string \"[object Object]\"). Does NOT neutralize SQL or command injection: String() of an already-string payload is the identity, so the injection survives."},

	// JSON serialization (prevents XSS — output is JSON-encoded)
	{ID: "js.json.stringify", Pattern: `JSON\.stringify\s*\(`, ObjectType: "JSON", MethodName: "stringify", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkDeserialize}, Description: "JSON serialization (HTML-safe output)"},

	// Express res.json (sets Content-Type: application/json, prevents XSS)
	{ID: "js.express.res.json", Pattern: `res\.json\s*\(`, ObjectType: "Response", MethodName: "json", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Express JSON response (prevents XSS via Content-Type)"},

	// TypeORM sanitizers
	{ID: "js.typeorm.parameterized", Pattern: `\.query\s*\([^,]+,\s*\[`, ObjectType: "typeorm", MethodName: "query", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "TypeORM query() with parameters array (parameterized)"},
	{ID: "js.typeorm.repository", Pattern: `\.(find|findOne|findOneBy|findBy)\s*\(\s*\{`, ObjectType: "typeorm.Repository", MethodName: "find/findOne/findOneBy/findBy", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "TypeORM Repository find methods (uses parameterized queries)"},
	{ID: "js.typeorm.where.object", Pattern: `\.where\s*\(\s*\{`, ObjectType: "typeorm.QueryBuilder", MethodName: "where", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "TypeORM where() with object syntax (parameterized)"},

	// Drizzle ORM sanitizers
	{ID: "js.drizzle.sqltag", Pattern: "sql`", ObjectType: "drizzle", MethodName: "sql", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Drizzle sql tagged template literal (parameterized)"},
	{ID: "js.drizzle.querybuilder", Pattern: `db\.(select|insert|update|delete)\s*\(`, ObjectType: "drizzle", MethodName: "select/insert/update/delete", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Drizzle query builder (parameterized)"},

	// Bookshelf.js ORM sanitizers — knex-backed, auto-parameterized. The taint engine
	// otherwise mis-fires js.mongoose.* sinks on Bookshelf's findOne/find/update/fetch
	// and js.fetch.ssrf on .related(...).fetch(options). We neutralize the common
	// Bookshelf-distinctive call shapes:
	// .related('x').fetch() — the .related() method is Bookshelf-specific
	// Member.forge(...) — Bookshelf model factory
	// .fetchAll(options) — Bookshelf collection fetch
	// .related() is Bookshelf-distinctive; no other common JS API uses this name,
	// so method-name matching is safe here.
	{ID: "js.bookshelf.related", Pattern: `\.related\s*\(`, ObjectType: "", MethodName: "related", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkURLFetch}, Description: "Bookshelf .related() relation accessor (knex-parameterized)"},
	{ID: "js.bookshelf.forge", Pattern: `\.forge\s*\(`, ObjectType: "", MethodName: "forge", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Bookshelf .forge() model factory (no SQL issued)"},
	{ID: "js.bookshelf.fetchall", Pattern: `\.fetchAll\s*\(`, ObjectType: "", MethodName: "fetchAll", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkURLFetch}, Description: "Bookshelf .fetchAll() (knex-parameterized, not HTTP)"},
	{ID: "js.bookshelf.fetchpage", Pattern: `\.fetchPage\s*\(`, ObjectType: "", MethodName: "fetchPage", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkURLFetch}, Description: "Bookshelf .fetchPage() pagination (knex-parameterized)"},

	// Date constructor (type coercion to safe date object)
	{ID: "js.date.constructor", Pattern: `new\s+Date\s*\(`, MethodName: "Date", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Date constructor (type coercion to safe date)"},

	// Regex test as sanitizer for validated input
	{ID: "js.regex.replace.sanitize", Pattern: `\.replace\s*\(\s*/[^/]+/[gi]*\s*,\s*['"]`, MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkFileWrite, taint.SnkFileRead}, Description: "Regex replace stripping dangerous characters"},

	// --- SnkEval sanitizers (code injection prevention) ---
	{ID: "js.vm.createcontext", Pattern: `vm\.createContext\s*\(`, ObjectType: "vm", MethodName: "createContext", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "V8 sandbox context creation (isolates eval scope)"},
	{ID: "js.vm2.vm", Pattern: `new\s+VM\s*\(\s*\{`, ObjectType: "vm2", MethodName: "VM", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "vm2 sandbox VM (secure eval isolation)"},
	{ID: "js.safeeval", Pattern: `safeEval\s*\(`, MethodName: "safeEval", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "safe-eval library (restricted eval context)"},
	{ID: "js.boolean.coerce", Pattern: `\bBoolean\s*\(`, MethodName: "Boolean", Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery, taint.SnkCommand}, Description: "Boolean type coercion (restricts to true/false)"},
	{ID: "js.isolated-vm.isolate", Pattern: `new\s+ivm\.Isolate\s*\(`, ObjectType: "isolated-vm", MethodName: "Isolate", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "isolated-vm V8 isolate sandbox (process-level eval isolation)"},
	{ID: "js.mathjs.evaluate", Pattern: `math(?:js)?\.evaluate\s*\(`, ObjectType: "mathjs", MethodName: "evaluate", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "mathjs safe expression evaluator (math-only, no arbitrary code execution)"},
	{ID: "js.escape-string-regexp", Pattern: `escapeStringRegexp\s*\(|escapeRegExp\s*\(`, MethodName: "escapeStringRegexp", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "escape-string-regexp metacharacter escaping (prevents ReDoS via dynamic regex)"},

	// --- SnkHeader sanitizers (HTTP header injection prevention) ---
	{ID: "js.replace.newlines", Pattern: `\.replace\s*\(\s*/\\[rn]/`, MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog}, Description: "Newline stripping via regex replace (prevents header/log injection)"},
	{ID: "js.helmet", Pattern: `helmet\s*\(`, ObjectType: "helmet", MethodName: "helmet", Neutralizes: []taint.SinkCategory{taint.SnkHeader}, Description: "Helmet middleware (sets security headers, prevents header manipulation)"},
	{ID: "js.validator.striplow", Pattern: `validator\.stripLow\s*\(`, ObjectType: "validator", MethodName: "stripLow", Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog}, Description: "validator.js stripLow (removes control characters including CR/LF)"},

	// --- SnkLDAP sanitizers (LDAP injection prevention) ---
	{ID: "js.ldap.escape.filter", Pattern: `ldapEscape\.filter\s*\(|ldapEscape\.dn\s*\(`, ObjectType: "ldapEscape", MethodName: "filter/dn", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "ldap-escape library filter/DN escaping"},
	{ID: "js.ldapjs.parsedN", Pattern: `ldap\.parseDN\s*\(`, ObjectType: "ldap", MethodName: "parseDN", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "ldapjs DN parsing (validates and normalizes DN components)"},

	// --- SnkTrustBoundary sanitizers (session/storage integrity) ---
	{ID: "js.jwt.sign", Pattern: `jwt\.sign\s*\(`, ObjectType: "jsonwebtoken", MethodName: "sign", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary}, Description: "JWT signing provides cryptographic integrity for data crossing trust boundaries"},
	{ID: "js.jwt.verify", Pattern: `jwt\.verify\s*\(`, ObjectType: "jsonwebtoken", MethodName: "verify", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary}, Description: "JWT verification validates signature and claims before trusting data"},
	{ID: "js.jose.jwtverify", Pattern: `jwtVerify\s*\(`, ObjectType: "jose", MethodName: "jwtVerify", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary}, Description: "jose jwtVerify validates JWT signature, claims, and expiry (modern JWT standard)"},

	// --- SnkLog sanitizers (log injection prevention) ---
	{ID: "js.string.replace.crlf", Pattern: `\.replace\s*\(\s*/\\n/|\.replace\s*\(\s*/\\r/`, MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader}, Description: "Newline character replacement (prevents log/header injection)"},
	{ID: "js.pino.child", Pattern: `logger\.child\s*\(\s*\{`, ObjectType: "pino", MethodName: "child", Neutralizes: []taint.SinkCategory{taint.SnkLog}, Description: "Pino structured child logger (key-value prevents injection)"},
	{ID: "js.winston.structured", Pattern: `logger\.\w+\s*\(\s*\{`, ObjectType: "winston", MethodName: "structured", Neutralizes: []taint.SinkCategory{taint.SnkLog}, Description: "Winston structured logging with object metadata"},
	{ID: "js.strip-ansi", Pattern: `stripAnsi\s*\(`, ObjectType: "strip-ansi", MethodName: "stripAnsi", Neutralizes: []taint.SinkCategory{taint.SnkLog}, Description: "strip-ansi removes ANSI escape codes (prevents log ANSI injection/formatting attacks)"},

	// --- SnkTemplate sanitizers (SSTI prevention) ---
	{ID: "js.handlebars.escapeexpression", Pattern: `Handlebars\.Utils\.escapeExpression\s*\(|Handlebars\.escapeExpression\s*\(`, ObjectType: "Handlebars", MethodName: "escapeExpression", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "Handlebars HTML escaping (default in {{}} expressions)"},
	{ID: "js.nunjucks.autoescape", Pattern: `nunjucks\.configure\s*\([^)]*autoescape\s*:\s*true`, ObjectType: "nunjucks", MethodName: "configure", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "Nunjucks template engine with autoescaping enabled"},
	{ID: "js.ejs.escape", Pattern: `ejs\.render\s*\([^)]*\{[^}]*escape\s*:`, ObjectType: "ejs", MethodName: "render", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "EJS render with custom escape function"},
	{ID: "js.mustache.escape", Pattern: `Mustache\.escape\s*\(`, ObjectType: "Mustache", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "Mustache HTML escaping function"},

	// --- SnkXPath sanitizers (XPath injection prevention) ---
	{ID: "js.xpath.escape.quotes", Pattern: `\.replace\s*\(\s*/['"]/g\s*,`, MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "Quote character replacement (basic XPath injection prevention)"},
	{ID: "js.xpath.parseint.safe", Pattern: `parseInt\s*\([^,]+,\s*10\s*\)`, MethodName: "parseInt", Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkLDAP}, Description: "Integer parsing with radix 10 (type coercion prevents injection)"},

	// --- SnkDeserialize sanitizers (safe deserialization alternatives) ---
	{ID: "js.superjson.parse", Pattern: `superjson\.(?:parse|deserialize)\s*\(`, ObjectType: "superjson", MethodName: "parse/deserialize", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "superjson safe typed deserialization (preserves Date, BigInt, RegExp without code execution)"},
	{ID: "js.devalue.parse", Pattern: `devalue\.(?:parse|unflatten)\s*\(`, ObjectType: "devalue", MethodName: "parse/unflatten", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "devalue safe deserialization (SvelteKit — no prototype pollution or code execution)"},
	{ID: "js.flatted.parse", Pattern: `flatted\.parse\s*\(`, ObjectType: "flatted", MethodName: "parse", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "flatted safe circular JSON deserialization (handles cycles without eval)"},
	{ID: "js.class-transformer.plaintoinstance", Pattern: `plainTo(?:Instance|Class)\s*\(`, ObjectType: "class-transformer", MethodName: "plainToInstance/plainToClass", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "class-transformer typed deserialization with class-validator integration (NestJS)"},
	// --- SnkCommand sanitizers (shell injection prevention) ---
	{ID: "js.shellquote.quote", Pattern: `shellQuote\.quote\s*\(|shell_quote\.quote\s*\(`, ObjectType: "", MethodName: "quote", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "shell-quote library escapes shell metacharacters (25M+ weekly downloads)"},
	{ID: "js.execa", Pattern: `\bexeca\s*\(|execa\.command\s*\(|execaCommand\s*\(|execaSync\s*\(`, ObjectType: "execa", MethodName: "execa", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "execa library — no shell spawned by default, args passed as array (105M+ weekly downloads)"},
	{ID: "js.cross.spawn", Pattern: `crossSpawn\s*\(|crossSpawn\.sync\s*\(|cross_spawn\s*\(`, ObjectType: "cross-spawn", MethodName: "spawn", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "cross-spawn — cross-platform spawn without shell interpolation (100M+ weekly downloads)"},

	// --- SnkDeserialize sanitizers (safe deserialization) ---
	{ID: "js.superjson.parse", Pattern: `superjson\.parse\s*\(|superjson\.deserialize\s*\(`, ObjectType: "superjson", MethodName: "parse/deserialize", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "superjson safe deserialization — handles Date, Map, Set, BigInt without code execution"},
	{ID: "js.devalue.parse", Pattern: `devalue\.parse\s*\(|devalue\.unflatten\s*\(`, ObjectType: "devalue", MethodName: "parse/unflatten", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "devalue safe deserialization — SvelteKit official serializer, XSS-safe output"},
	{ID: "js.protobufjs.decode", Pattern: `\.decode\s*\(\s*(?:Uint8Array|Buffer|bytes|buf|data|payload)\b`, ObjectType: "protobufjs", MethodName: "decode", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Protocol Buffers schema-enforced deserialization — only defined fields accepted"},
	{ID: "js.class.transformer", Pattern: `plainToInstance\s*\(|plainToClass\s*\(`, ObjectType: "class-transformer", MethodName: "plainToInstance/plainToClass", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary}, Description: "class-transformer type-safe deserialization — decorator-based property mapping (NestJS standard)"},

	// --- SnkURLFetch sanitizers (SSRF prevention) ---
	{ID: "js.ssrf.filter", Pattern: `ssrfFilter\s*\(`, ObjectType: "", MethodName: "ssrfFilter", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "ssrf-req-filter blocks requests to private IPs, localhost, and cloud metadata endpoints"},

	// --- SnkFileRead additional sanitizers (path traversal prevention) ---
	// NOTE: fs.realpathSync()/fs.realpath() deliberately absent —
	// realpath("../../etc/passwd") resolves to "/etc/passwd": a real path
	// OUTSIDE the safe base. Canonicalize-only, see the path.normalize note
	// above.
	{ID: "js.express.static", Pattern: `express\.static\s*\(`, ObjectType: "express", MethodName: "static", Neutralizes: []taint.SinkCategory{taint.SnkFileRead}, Description: "Express static file middleware (serves files safely with path traversal protection)"},
	{ID: "js.serve.static", Pattern: `serveStatic\s*\(`, ObjectType: "serve-static", MethodName: "serveStatic", Neutralizes: []taint.SinkCategory{taint.SnkFileRead}, Description: "serve-static middleware (underlying express.static, prevents path traversal)"},
	{ID: "js.sendfile.root", Pattern: `\.sendFile\s*\([^)]+,\s*\{[^}]*root\s*:`, ObjectType: "Response", MethodName: "sendFile", Neutralizes: []taint.SinkCategory{taint.SnkFileRead}, Description: "Express sendFile with root option (confines file serving to root directory)"},

	// --- Bun runtime sanitizers ---
	{ID: "js.bun.escapehtml", Pattern: `Bun\.escapeHTML\s*\(`, ObjectType: "Bun", MethodName: "escapeHTML", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "Bun built-in HTML entity escaping (prevents XSS)"},
	{ID: "js.bun.password.hash", Pattern: `Bun\.password\.hash\s*\(`, ObjectType: "Bun.password", MethodName: "hash", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Bun built-in bcrypt/argon2 password hashing (safe password storage)"},
	// --- SnkTrustBoundary sanitizers (trust boundary validation) ---
	{ID: "js.jwt.verify", Pattern: `jwt\.verify\s*\(`, ObjectType: "jsonwebtoken", MethodName: "verify", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkDeserialize}, Description: "JWT signature verification validates token integrity before trusting claims (jsonwebtoken ~200M weekly)"},
	{ID: "js.jose.jwtverify", Pattern: `jwtVerify\s*\(`, ObjectType: "jose", MethodName: "jwtVerify", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkDeserialize}, Description: "jose library JWT verification with claims validation (~27M weekly)"},
	{ID: "js.cookie.signedcookies", Pattern: `req\.signedCookies`, ObjectType: "cookie-parser", MethodName: "signedCookies", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary}, Description: "Express signed cookies — HMAC-verified, tampered values become false (~5M weekly)"},
	{ID: "js.iron-session.get", Pattern: `getIronSession\s*\(`, ObjectType: "iron-session", MethodName: "getIronSession", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkDeserialize}, Description: "iron-session encrypted+signed session — data decrypted and integrity-verified by server"},
	{ID: "js.passport.deserializeuser", Pattern: `passport\.deserializeUser\s*\(`, ObjectType: "passport", MethodName: "deserializeUser", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary}, Description: "Passport.js deserializeUser reconstructs user from trusted store (database lookup by session ID)"},

	// --- SnkDeserialize additional sanitizers (safe deserialization) ---
	{ID: "js.class-transformer.plaintoinstance", Pattern: `plainToInstance\s*\(|plainToClass\s*\(`, ObjectType: "class-transformer", MethodName: "plainToInstance", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary}, Description: "class-transformer type-safe object transformation with @Exclude/@Expose decorators (~6M weekly)"},
	{ID: "js.superjson.parse", Pattern: `superjson\.parse\s*\(|superjson\.deserialize\s*\(`, ObjectType: "superjson", MethodName: "parse/deserialize", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "superjson safe serialization — no code execution, type-preserving (~3M weekly, used by tRPC)"},
	{ID: "js.devalue.parse", Pattern: `devalue\.parse\s*\(|devalue\.unflatten\s*\(`, ObjectType: "devalue", MethodName: "parse/unflatten", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "devalue safe deserialization — no code execution, handles cycles (~5M weekly, used by SvelteKit)"},

	// --- SnkEval additional sanitizers (safe expression evaluation) ---
	{ID: "js.mathjs.evaluate", Pattern: `math\.evaluate\s*\(|mathjs\.evaluate\s*\(`, ObjectType: "mathjs", MethodName: "evaluate", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "mathjs restricted expression evaluator — no require(), no fs, sandboxed scope (~6M weekly)"},
	{ID: "js.ses.compartment", Pattern: `new\s+Compartment\s*\(`, ObjectType: "ses", MethodName: "Compartment", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "SES Hardened JavaScript Compartment — TC39 frozen intrinsics, zero ambient authority (MetaMask/Agoric)"},

	// --- SnkTemplate additional sanitizers (safe template rendering) ---
	{ID: "js.liquidjs.parseandrender", Pattern: `\.parseAndRender\s*\(`, ObjectType: "liquidjs", MethodName: "parseAndRender", Neutralizes: []taint.SinkCategory{taint.SnkTemplate}, Description: "LiquidJS safe template rendering — no code execution, auto-escapes by default (~1M weekly)"},

	// --- Electron sanitizers ---
	{ID: "js.electron.safestorage.encrypt", Pattern: `safeStorage\.encryptString\s*\(`, ObjectType: "electron.safeStorage", MethodName: "encryptString", Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkTrustBoundary}, Description: "Electron safeStorage encrypts data using OS keychain (DPAPI/Keychain/libsecret)"},
	{ID: "js.electron.contextbridge", Pattern: `contextBridge\.exposeInMainWorld\s*\(`, ObjectType: "electron.contextBridge", MethodName: "exposeInMainWorld", Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkTrustBoundary}, Description: "Electron contextBridge safely exposes limited APIs to renderer — prevents direct Node.js access from web content"},

	// --- Yahoo xss-filters (OWASP XSS Prevention Cheat Sheet recommended) ---
	// API: yfilters.inHTMLData(s), inUnQuotedAttr(s), inDoubleQuotedAttr(s), inSingleQuotedAttr(s), uriInHTMLData(s), etc.
	// Each function uses unique camelCase names that don't collide with other libraries.
	{ID: "js.xss-filters.inhtmldata", Pattern: `\binHTMLData\s*\(`, ObjectType: "", MethodName: "inHTMLData", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "yahoo/xss-filters HTML data context encoder (OWASP XSS cheat sheet recommended for HTML body content)"},
	{ID: "js.xss-filters.inunquotedattr", Pattern: `\binUnQuotedAttr\s*\(`, ObjectType: "", MethodName: "inUnQuotedAttr", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "yahoo/xss-filters unquoted-attribute context encoder"},
	{ID: "js.xss-filters.indoublequotedattr", Pattern: `\binDoubleQuotedAttr\s*\(`, ObjectType: "", MethodName: "inDoubleQuotedAttr", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "yahoo/xss-filters double-quoted-attribute context encoder"},
	{ID: "js.xss-filters.insinglequotedattr", Pattern: `\binSingleQuotedAttr\s*\(`, ObjectType: "", MethodName: "inSingleQuotedAttr", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "yahoo/xss-filters single-quoted-attribute context encoder"},
	{ID: "js.xss-filters.uriinhtmldata", Pattern: `\buriInHTMLData\s*\(`, ObjectType: "", MethodName: "uriInHTMLData", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect}, Description: "yahoo/xss-filters URL-aware HTML data context encoder (encodes javascript: and data: URIs)"},

	// --- Modern password hashing (Argon2 — OWASP Password Storage Cheat Sheet preferred) ---
	{ID: "js.argon2.hash", Pattern: `argon2\.hash\s*\(`, ObjectType: "argon2", MethodName: "hash", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "node-argon2 / @node-rs/argon2 password hashing (memory-hard, OWASP Password Storage Cheat Sheet preferred over bcrypt)"},
	{ID: "js.argon2.verify", Pattern: `argon2\.verify\s*\(`, ObjectType: "argon2", MethodName: "verify", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "node-argon2 password verification (constant-time)"},

	// --- Node built-in KDFs (scrypt, PBKDF2) — alternatives to bcrypt for password hashing/key derivation ---
	{ID: "js.crypto.scrypt", Pattern: `crypto\.scrypt(?:Sync)?\s*\(`, ObjectType: "crypto", MethodName: "scrypt/scryptSync", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Node crypto.scrypt memory-hard KDF (RFC 7914, OWASP-recommended for password hashing)"},
	{ID: "js.crypto.pbkdf2", Pattern: `crypto\.pbkdf2(?:Sync)?\s*\(`, ObjectType: "crypto", MethodName: "pbkdf2/pbkdf2Sync", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Node crypto.pbkdf2 key derivation (NIST SP 800-132, acceptable for password hashing with high iteration count)"},

	// --- Bare-function sanitizers (unique enough package names that bare calls are safe to match) ---
	{ID: "js.striptags", Pattern: `\bstriptags\s*\(`, ObjectType: "", MethodName: "striptags", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "striptags package — removes HTML tags from string (~5M weekly downloads)"},
	{ID: "js.slugify", Pattern: `\bslugify\s*\(`, ObjectType: "", MethodName: "slugify", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead, taint.SnkRedirect}, Description: "slugify package — converts string to URL/filename-safe ASCII slug (~4M weekly downloads)"},
	{ID: "js.filenamify", Pattern: `\bfilenamify\s*\(`, ObjectType: "", MethodName: "filenamify", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "filenamify package — converts string to safe filename, strips path separators and reserved chars"},
	{ID: "js.filetype.fromtokenizer", Pattern: `fileTypeFromBuffer\s*\(|fileTypeFromBlob\s*\(|fileTypeFromStream\s*\(`, ObjectType: "", MethodName: "fileTypeFromBuffer/fileTypeFromBlob/fileTypeFromStream", Neutralizes: []taint.SinkCategory{taint.SnkUpload}, Description: "file-type package — detects the true file type from an uploaded buffer/blob/stream's magic bytes (defends unrestricted file upload when paired with an allowlist)"},

	// --- MySQL / MySQL2 / sqlstring driver-level escape (raw SQL escape used when parameterized queries aren't an option) ---
	{ID: "js.mysql.escape", Pattern: `\bmysql\.escape\s*\(`, ObjectType: "mysql", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "mysql package top-level escape() — value escape for MySQL SQL strings (~18M weekly downloads combined with mysql2)"},
	{ID: "js.mysql.escapeid", Pattern: `\bmysql\.escapeId\s*\(`, ObjectType: "mysql", MethodName: "escapeId", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "mysql package top-level escapeId() — escapes SQL identifier (table/column name) with backticks"},
	{ID: "js.mysql2.escape", Pattern: `\bmysql2\.escape\s*\(`, ObjectType: "mysql2", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "mysql2 package top-level escape() — MySQL value escape (mysql2 ~12M weekly downloads)"},
	{ID: "js.mysql2.escapeid", Pattern: `\bmysql2\.escapeId\s*\(`, ObjectType: "mysql2", MethodName: "escapeId", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "mysql2 package top-level escapeId() — MySQL identifier escape"},
	{ID: "js.mysql.connection.escape", Pattern: `connection\.escape\s*\(`, ObjectType: "Connection", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQL/mysql2 Connection.escape() — instance-level value escape"},
	{ID: "js.mysql.connection.escapeid", Pattern: `connection\.escapeId\s*\(`, ObjectType: "Connection", MethodName: "escapeId", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQL/mysql2 Connection.escapeId() — instance-level identifier escape"},
	{ID: "js.mysql.pool.escape", Pattern: `pool\.escape\s*\(`, ObjectType: "Pool", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQL/mysql2 Pool.escape() — pool-level value escape"},
	{ID: "js.mysql.pool.escapeid", Pattern: `pool\.escapeId\s*\(`, ObjectType: "Pool", MethodName: "escapeId", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MySQL/mysql2 Pool.escapeId() — pool-level identifier escape"},
	{ID: "js.sqlstring.escape", Pattern: `SqlString\.escape\s*\(`, ObjectType: "SqlString", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "sqlstring package SqlString.escape() — MySQL-compatible value escape used standalone or via mysql/mysql2"},
	{ID: "js.sqlstring.escapeid", Pattern: `SqlString\.escapeId\s*\(`, ObjectType: "SqlString", MethodName: "escapeId", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "sqlstring package SqlString.escapeId() — MySQL-compatible identifier escape"},

	// --- node-postgres (pg) instance-level escape methods (added in pg v8.0) ---
	{ID: "js.pg.client.escapeliteral", Pattern: `\.escapeLiteral\s*\(`, ObjectType: "", MethodName: "escapeLiteral", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "node-postgres Client.escapeLiteral() — PostgreSQL string-literal escape (pg-specific method name; safe to match unscoped)"},
	{ID: "js.pg.client.escapeidentifier", Pattern: `\.escapeIdentifier\s*\(`, ObjectType: "", MethodName: "escapeIdentifier", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "node-postgres Client.escapeIdentifier() — PostgreSQL identifier escape (pg-specific method name; safe to match unscoped)"},

	// --- pg-format (node-pg-format): PostgreSQL dynamic-SQL escaping helpers (~2M weekly downloads) ---
	// format.literal()/format.ident() escape values/identifiers exactly like PostgreSQL's
	// quote_literal()/quote_ident(), for the dynamic-SQL cases where parameter placeholders
	// can't be used (e.g. interpolating a table/column name). Scoped to ObjectType "format"
	// (the canonical `const format = require('pg-format')` receiver) so we do NOT match
	// Sequelize.literal(), which does the OPPOSITE — it injects RAW unescaped SQL.
	// format.string() / the bare format() are deliberately excluded: %s does not escape its
	// input, and format()'s tainted value sits at arg index >=1 (tsflow only inspects arg[0]).
	{ID: "js.pgformat.literal", Pattern: `\bformat\.literal\s*\(`, ObjectType: "format", MethodName: "literal", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "pg-format format.literal() — escapes a value as a PostgreSQL SQL literal (quote_literal equivalent) for safe dynamic SQL"},
	{ID: "js.pgformat.ident", Pattern: `\bformat\.ident\s*\(`, ObjectType: "format", MethodName: "ident", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "pg-format format.ident() — escapes an identifier (table/column name) as a PostgreSQL SQL identifier (quote_ident equivalent)"},

	// --- validator.js sanitizer-module type-coercion functions ---
	// These return a number / boolean / Date (or NaN / null), not a string, so the
	// result can no longer carry string-injection payloads. Scoped like the existing
	// JS type-coercion sanitizers (js.number, js.parseint, js.boolean.coerce).
	{ID: "js.validator.toint", Pattern: `validator\.toInt\s*\(`, ObjectType: "validator", MethodName: "toInt", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "validator.js toInt() — type coercion to integer (NaN if invalid)"},
	{ID: "js.validator.tofloat", Pattern: `validator\.toFloat\s*\(`, ObjectType: "validator", MethodName: "toFloat", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "validator.js toFloat() — type coercion to float (NaN if invalid)"},
	{ID: "js.validator.toboolean", Pattern: `validator\.toBoolean\s*\(`, ObjectType: "validator", MethodName: "toBoolean", Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery, taint.SnkCommand}, Description: "validator.js toBoolean() — type coercion to boolean"},
	{ID: "js.validator.todate", Pattern: `validator\.toDate\s*\(`, ObjectType: "validator", MethodName: "toDate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "validator.js toDate() — type coercion to Date object (null if invalid)"},
	{ID: "js.validator.isemail", Pattern: `validator\.isEmail\s*\(`, ObjectType: "validator", MethodName: "isEmail", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkHeader}, Description: "validator.js isEmail() — strict RFC-5322 email validator (rejects injection metacharacters)"},
	{ID: "js.validator.normalizeemail", Pattern: `validator\.normalizeEmail\s*\(`, ObjectType: "validator", MethodName: "normalizeEmail", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkHeader}, Description: "validator.js normalizeEmail() — canonicalises an email (lowercased, well-formed) for safe downstream use"},

	// --- additional HTML / URL escaping libraries ---
	{ID: "js.lodash.escape", Pattern: `\b_\.escape\s*\(|\blodash\.escape\s*\(`, ObjectType: "_", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "lodash / underscore _.escape() — converts &<>\"' to HTML entities (XSS escaping)"},
	{ID: "js.entities.encodehtml", Pattern: `entities\.encodeHTML\s*\(|entities\.encodeXML\s*\(|entities\.escapeUTF8\s*\(`, ObjectType: "entities", MethodName: "encodeHTML/encodeXML/escapeUTF8", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "entities package encodeHTML/encodeXML/escapeUTF8 — HTML/XML entity encoding (~30M weekly downloads; dep of cheerio/htmlparser2)"},
	{ID: "js.braintree.sanitizeurl", Pattern: `\bsanitizeUrl\s*\(`, ObjectType: "", MethodName: "sanitizeUrl", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect}, Description: "@braintree/sanitize-url sanitizeUrl() — replaces javascript:/data:/vbscript: URLs with about:blank (prevents URL-based XSS in href/src)"},
	{ID: "js.xss.filterxss", Pattern: `\bfilterXSS\s*\(`, ObjectType: "", MethodName: "filterXSS", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "js-xss library filterXSS() — HTML sanitization / XSS filtering (named export of the xss package)"},

	// --- NoSQL sanitizers (CWE-943) ---
	{ID: "js.mongo_sanitize", Pattern: `\bmongoSanitize\s*\(`, ObjectType: "mongo-sanitize", MethodName: "mongoSanitize", Neutralizes: []taint.SinkCategory{taint.SnkNoSQL}, Description: "mongo-sanitize strips MongoDB $-prefixed operator keys from an object before it is used as a query — neutralizes operator-injection NoSQLi"},
	{ID: "js.express_mongo_sanitize", Pattern: `express-mongo-sanitize|expressMongoSanitize`, ObjectType: "express-mongo-sanitize", MethodName: "expressMongoSanitize", Neutralizes: []taint.SinkCategory{taint.SnkNoSQL}, Description: "express-mongo-sanitize middleware strips $-prefixed and .-containing keys from req.body / req.query / req.params before they reach Mongo queries"},
	{ID: "js.mongoose.escape_regex", Pattern: `\.escapeRegExp\s*\(|\bescapeRegex\s*\(`, ObjectType: "", MethodName: "escapeRegExp", Neutralizes: []taint.SinkCategory{taint.SnkNoSQL}, Description: "escape-string-regexp / lodash.escapeRegExp / mongoose.escapeRegex — escapes regex metacharacters before embedding user input in a $regex query"},

	// --- SSRF / URL validation sanitizers ---
	{ID: "js.is_url.npm", Pattern: `\bisURL\s*\(|\bisUrl\s*\(`, ObjectType: "", MethodName: "isURL/isUrl", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "is-url / is-url-superb / is-url-http URL validation predicate — common SSRF allowlist guard"},
	{ID: "js.url.tostring_after_validate", Pattern: `new\s+URL\s*\([^)]+\)\.toString\s*\(\s*\)`, ObjectType: "URL", MethodName: "URL.toString", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "WHATWG URL.toString() after construction — typed-URL roundtrip drops a smuggled host or scheme"},
	{ID: "js.url.protocol_check", Pattern: `\.protocol\s*===?\s*['"]https?:['"]|\bhttps?:['"]\s*===?\s*\w+\.protocol\b`, ObjectType: "URL", MethodName: "protocol", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL.protocol allowlist check (rejects file: / gopher: / javascript: schemes for SSRF prevention)"},
	{ID: "js.psl.isvalid", Pattern: `psl\.isValid\s*\(|psl\.parse\s*\(`, ObjectType: "psl", MethodName: "psl.isValid/psl.parse", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "psl (Public Suffix List) — validates a hostname against the Mozilla PSL, used to bound domain allowlists"},
	{ID: "js.ipaddr.isvalid", Pattern: `ipaddr\.isValid\s*\(|ipaddr\.parse\s*\(`, ObjectType: "ipaddr.js", MethodName: "ipaddr.isValid/parse", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "ipaddr.js — strict IPv4/IPv6 literal validator (used to bound allowlists / detect private ranges in SSRF guards)"},
	{ID: "js.private_ip.is_ip", Pattern: `\bisPrivateIP\s*\(|\bisPrivateIp\s*\(|private_ip\s*\(`, ObjectType: "private-ip", MethodName: "isPrivateIP", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "private-ip / is-private-ip / is-ip — denies RFC-1918, link-local, and loopback ranges (SSRF allowlist guard)"},
	{ID: "js.allowlist.hostname", Pattern: `ALLOWED_HOSTS\.(?:has|includes)\s*\(|hostAllowlist\.(?:has|includes)\s*\(`, ObjectType: "", MethodName: "ALLOWED_HOSTS.has", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "Explicit Set/Array hostname allowlist (idiomatic SSRF guard — paired with URL.hostname extraction)"},
	{ID: "js.normalize_url", Pattern: `\bnormalizeUrl\s*\(|normalize-url`, ObjectType: "normalize-url", MethodName: "normalizeUrl", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "normalize-url package — canonicalises a URL (drops userinfo, sorts query keys, removes default ports); typed-URL roundtrip prevents allowlist-bypass via dotless decimals / encoded characters"},

	// --- Upload (CWE-434) — MIME / file-type detection + allowlist helpers ---
	{ID: "js.file_type.from_buffer", Pattern: `\bfileTypeFromBuffer\s*\(|\bfileTypeFromStream\s*\(|FileType\.fromBuffer\s*\(`, ObjectType: "file-type", MethodName: "fileTypeFromBuffer", Neutralizes: []taint.SinkCategory{taint.SnkUpload}, Description: "file-type package fileTypeFromBuffer / fileTypeFromStream — content-based MIME detection (defends CWE-434 when paired with an allowlist)"},
	{ID: "js.mime_types.lookup", Pattern: `\bmime\.lookup\s*\(|\bmimeTypes\.lookup\s*\(|mime\.getType\s*\(`, ObjectType: "mime / mime-types", MethodName: "mime.lookup/getType", Neutralizes: []taint.SinkCategory{taint.SnkUpload}, Description: "mime / mime-types lookup — extension→content-type for an upload allowlist check"},
	{ID: "js.path.extname", Pattern: `path\.extname\s*\(`, ObjectType: "path", MethodName: "path.extname", Neutralizes: []taint.SinkCategory{taint.SnkUpload, taint.SnkFileRead, taint.SnkFileWrite}, Description: "node:path.extname — extracts the extension for an upload-extension allowlist check"},
	{ID: "js.multer.fileFilter", Pattern: `fileFilter\s*:\s*\(`, ObjectType: "multer", MethodName: "options.fileFilter", Neutralizes: []taint.SinkCategory{taint.SnkUpload}, Description: "multer { fileFilter } option — typed callback rejecting / accepting per-upload based on MIME / extension (idiomatic Express upload guard)"},

	// --- CSV (CWE-1236) — formula-prefix sanitizers + library options ---
	{ID: "js.csv_stringify_quoted", Pattern: `csv-stringify.*quoted\s*:\s*true|stringify\s*\(\s*\{[^}]*quoted\s*:\s*true`, ObjectType: "csv-stringify", MethodName: "stringify({quoted:true})", Neutralizes: []taint.SinkCategory{taint.SnkCSV}, Description: "csv-stringify { quoted: true } option — quotes every field, defeating CSV-formula evaluation at write time"},
	{ID: "js.escape_csv_formula", Pattern: `(?:^|\b)(?:escapeCsvFormula|sanitizeCsvCell|safeCsvField|csvSafe)\s*\(`, ObjectType: "", MethodName: "escapeCsvFormula", Neutralizes: []taint.SinkCategory{taint.SnkCSV}, Description: "Custom escapeCsvFormula / sanitizeCsvCell helper — prefixes a single quote when a field starts with =, +, -, @, TAB (defends CSV-formula injection)"},

	// --- Header injection (CWE-93 CRLF) — strip / typed-header helpers ---
	{ID: "js.header.strip_crlf", Pattern: `\.replace\s*\(\s*/[\\r\\n]+/g?\s*,|\.replace\s*\(\s*/[\\x0[ad]]/g?\s*,`, ObjectType: "String", MethodName: "replace(CRLF)", Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog}, Description: "Manual CR/LF stripping (.replace(/[\\r\\n]+/g, '')) — defends header / log injection (CWE-93)"},
	{ID: "js.headers_class_typed", Pattern: `\bnew\s+Headers\s*\(|Headers\.append\s*\(|Headers\.set\s*\(`, ObjectType: "Headers", MethodName: "Headers", Neutralizes: []taint.SinkCategory{taint.SnkHeader}, Description: "Fetch API Headers class — typed multi-map header container; .append() / .set() reject CR/LF and validate token RFC compliance"},
	{ID: "js.express.set_status_header_typed", Pattern: `\.set\s*\(\s*['"][A-Za-z\-]+['"]\s*,|res\.header\s*\(\s*['"][A-Za-z\-]+['"]\s*,`, ObjectType: "express.Response", MethodName: "set/header", Neutralizes: []taint.SinkCategory{taint.SnkHeader}, Description: "Express Response.set / .header with a string-literal header name — restricts the header name to a known token (CRLF in the value still requires sanitisation but a literal name blocks attacker-controlled header names)"},

	// --- Prototype pollution sanitizers (CWE-1321) ---
	// `__proto__` magic-key comparison: if the code explicitly tests for the
	// magic key it almost always means the developer is stripping it before
	// the merge/set call.
	{ID: "js.proto.safe-key-check", Pattern: `['"]__proto__['"]`, ObjectType: "", MethodName: "__proto__-string-check", Neutralizes: []taint.SinkCategory{taint.SnkPrototype}, Description: "Explicit string compare against '__proto__' (the developer is filtering the magic key before merge/set)"},
	// Object.prototype.hasOwnProperty.call(obj, key) is the canonical
	// defensive-read shape — only own enumerable keys are accepted.
	{ID: "js.proto.hasownproperty", Pattern: `Object\.prototype\.hasOwnProperty\.call\s*\(|hasOwnProperty\.call\s*\(|\.hasOwnProperty\s*\(`, ObjectType: "Object", MethodName: "hasOwnProperty.call", Neutralizes: []taint.SinkCategory{taint.SnkPrototype}, Description: "Object.prototype.hasOwnProperty.call(obj, key) defensive-read pattern (rejects inherited / __proto__ keys)"},
	// Frozen target object: Object.freeze prevents writes to the prototype chain.
	{ID: "js.proto.assign-frozen-target", Pattern: `Object\.freeze\s*\(`, ObjectType: "Object", MethodName: "freeze", Neutralizes: []taint.SinkCategory{taint.SnkPrototype}, Description: "Object.freeze(target) prevents subsequent pollution of the target's prototype chain"},
	// secure-json-parse (Fastify) — JSON.parse drop-in that strips/rejects
	// `__proto__` and `constructor.prototype` keys (default protoAction:'error').
	// The parsed object is therefore safe to feed into deep-merge / set-by-path
	// sinks. Canonical receiver is `sjson` per the package README.
	{ID: "js.secure-json-parse.parse", Pattern: `sjson\.(?:parse|safeParse)\s*\(`, ObjectType: "sjson", MethodName: "parse/safeParse", Neutralizes: []taint.SinkCategory{taint.SnkPrototype}, Description: "secure-json-parse sjson.parse/safeParse — prototype-poisoning-safe JSON.parse drop-in (strips/rejects __proto__ and constructor.prototype, ~widely used by Fastify)"},
	// scan() sanitizes an already-parsed object in place (protoAction applied to
	// existing __proto__/constructor keys) and returns it.
	{ID: "js.secure-json-parse.scan", Pattern: `sjson\.scan\s*\(`, ObjectType: "sjson", MethodName: "scan", Neutralizes: []taint.SinkCategory{taint.SnkPrototype}, Description: "secure-json-parse sjson.scan(obj) — strips __proto__/constructor.prototype keys from an already-parsed object before merge/set"},
	// @hapi/bourne — the original prototype-poisoning-safe JSON.parse replacement
	// (secure-json-parse is a fork). Canonical receiver `Bourne`; `bourne`
	// lowercase alias covers the deprecated unscoped package's older usages.
	{ID: "js.bourne.parse", Pattern: `Bourne\.(?:parse|safeParse)\s*\(|bourne\.(?:parse|safeParse)\s*\(`, ObjectType: "Bourne", MethodName: "parse/safeParse", Neutralizes: []taint.SinkCategory{taint.SnkPrototype}, Description: "@hapi/bourne Bourne.parse/safeParse — prototype-poisoning-safe JSON.parse drop-in (default protoAction rejects __proto__)"},
	{ID: "js.bourne.scan", Pattern: `Bourne\.scan\s*\(|bourne\.scan\s*\(`, ObjectType: "Bourne", MethodName: "scan", Neutralizes: []taint.SinkCategory{taint.SnkPrototype}, Description: "@hapi/bourne Bourne.scan(obj) — strips __proto__ keys from an already-parsed object before merge/set"},
	// Handlebars.SafeString marks a value as already-escaped, used by the
	// safe-fixture pattern that pre-compiles templates from trusted literals.
	{ID: "js.handlebars.safestring", Pattern: `Handlebars\.SafeString\b|new\s+Handlebars\.SafeString\s*\(|handlebars\.SafeString\b`, ObjectType: "Handlebars", MethodName: "SafeString", Neutralizes: []taint.SinkCategory{taint.SnkTemplate}, Description: "Handlebars.SafeString wrapper marks a value as already-escaped (used with pre-compiled trusted templates)"},

	// --- Eval sanitizers — JSON.parse / numeric coercion / Function ctor explicit allowlist ---
	{ID: "js.json.parse.reviver", Pattern: `JSON\.parse\s*\(`, ObjectType: "JSON", MethodName: "JSON.parse", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "JSON.parse — strict JSON parser (no function references, no expressions); safe replacement for eval() on JSON inputs"},
	{ID: "js.expr_eval.npm", Pattern: `\bnew\s+Parser\s*\(\s*\)\.parse\s*\(|expr-eval\.Parser\b`, ObjectType: "expr-eval.Parser", MethodName: "Parser.parse", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "expr-eval package Parser.parse — math-expression-only evaluator (no global access, no statements)"},
	{ID: "js.mathjs.evaluate", Pattern: `\bmath\.evaluate\s*\(|mathjs\.evaluate\s*\(`, ObjectType: "mathjs", MethodName: "math.evaluate", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "mathjs math.evaluate — symbolic / numeric expression evaluator with a restricted symbol table (no JS host access)"},

	// --- ReDoS sanitizers (CWE-1333, SnkRegexDoS category) ---
	// Neutralize the dedicated js.regexp.constructor.redos sink. Mirrors the
	// C# Regex.Escape / C++ ReDoS sanitizers.
	//
	// escape-string-regexp (the de-facto standard, ~70M weekly downloads),
	// lodash/underscore _.escapeRegExp, and Mongoose's escapeRegExp all convert
	// every regex metacharacter in user input into its literal form, so a
	// tainted fragment becomes a fixed substring and can no longer introduce the
	// nested quantifiers / alternations that drive catastrophic backtracking.
	// The TC39 static RegExp.escape (Stage 3 / shipping in modern engines) does
	// the same at the language level. These bare function names are
	// ReDoS-distinctive enough to match unscoped.
	{ID: "js.regexp.escape_string_regexp.redos", Pattern: `\bescapeStringRegexp\s*\(|\bescapeRegExp\s*\(|\bescapeRegex\s*\(`, ObjectType: "", MethodName: "escapeStringRegexp/escapeRegExp/escapeRegex", Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS}, Description: "escape-string-regexp / lodash _.escapeRegExp / mongoose escapeRegExp converts user input into a literal pattern fragment (no metacharacters), preventing attacker-crafted backtracking (ReDoS)"},
	{ID: "js.regexp.escape.static.redos", Pattern: `RegExp\.escape\s*\(`, ObjectType: "RegExp", MethodName: "RegExp.escape", Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS}, Description: "TC39 RegExp.escape() static method escapes every regex metacharacter so a tainted pattern fragment becomes a literal substring (neutralizes ReDoS)"},
	// node-re2 (Google RE2 binding) is a linear-time, backtracking-free regex
	// engine — `new RE2(pattern)` cannot exhibit catastrophic backtracking, so a
	// tainted pattern can no longer cause a DoS. `new\s+RE2` requires whitespace
	// before RE2 so it never substring-matches inside an identifier nor the
	// `new RegExp(...)` sink.
	{ID: "js.re2.engine.redos", Pattern: `\bnew\s+RE2\s*\(`, ObjectType: "re2", MethodName: "RE2", Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS}, Description: "node-re2 (new RE2(pattern)) uses Google's RE2 linear-time engine which is mathematically free of catastrophic backtracking, neutralizing ReDoS on attacker-controlled patterns"},

	// --- AdonisJS (VineJS validation — the framework's official input layer) ---
	// AdonisJS uses VineJS for request validation. request.validateUsing(validator)
	// (and a compiled validator's .validate(...)) runs a typed schema over the
	// request and returns the schema-validated, type-enforced payload — a trusted
	// input boundary — so its output is neutralised for the injection sinks a
	// controller would feed it into.
	{ID: "js.adonis.request.validateusing", Language: rules.LangJavaScript, Pattern: `\brequest\.validateUsing\s*\(`, ObjectType: "AdonisRequest", MethodName: "validateUsing", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkNoSQL, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkTemplate, taint.SnkRedirect, taint.SnkFileRead, taint.SnkFileWrite, taint.SnkTrustBoundary}, Description: "AdonisJS request.validateUsing(validator) runs a VineJS schema and returns the typed, schema-validated payload — trusted input boundary"},
	{ID: "js.adonis.vine.compile", Language: rules.LangJavaScript, Pattern: `\bvine\.compile\s*\(`, ObjectType: "vine", MethodName: "compile", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkNoSQL, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkTemplate, taint.SnkTrustBoundary}, Description: "VineJS vine.compile(schema) builds a validator whose .validate()/validateUsing() output is schema-enforced trusted data (AdonisJS official validator)"},
	// VineJS .escape() schema modifier HTML-escapes the validated value, XSS-safe.
	{ID: "js.adonis.vine.escape", Language: rules.LangJavaScript, Pattern: `\.string\s*\(\s*\)\s*\.[A-Za-z0-9().]*escape\s*\(\s*\)`, ObjectType: "vine", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "VineJS vine.string().escape() HTML-escapes the validated value (<, >, &, quotes to entities), neutralising stored/reflected XSS"},
}
