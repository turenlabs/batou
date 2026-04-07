package languages

import "github.com/turenlabs/batou-core/taint"

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
	{ID: "js.escapehtml", Pattern: `escapeHtml\s*\(`, MethodName: "escapeHtml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML escape function"},

	// SQL parameterization sanitizers
	{ID: "js.prisma.tagged.template", Pattern: `Prisma\.sql\s*\x60`, ObjectType: "Prisma", MethodName: "sql", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Prisma tagged template literal (parameterized)"},
	{ID: "js.sequelize.bind", Pattern: `\.query\s*\([^,]+,\s*\{\s*(?:replacements|bind)`, ObjectType: "sequelize", MethodName: "query", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Sequelize parameterized query with bind/replacements"},

	// MongoDB sanitizers
	{ID: "js.mongo.sanitize", Pattern: `mongo-sanitize|express-mongo-sanitize|sanitize\s*\(`, MethodName: "sanitize", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MongoDB query sanitization"},

	// Validation library sanitizers
	{ID: "js.zod.parse", Pattern: `\w+Schema\.parse\s*\(`, ObjectType: "ZodSchema", MethodName: "parse", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkTrustBoundary}, Description: "Zod schema validation and parsing"},
	{ID: "js.joi.validate", Pattern: `Joi\.(?:validate|attempt)\s*\(`, ObjectType: "Joi", MethodName: "validate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkTrustBoundary}, Description: "Joi schema validation"},
	{ID: "js.class-validator", Pattern: `@Is(?:String|Int|Email|Number|UUID)\s*\(`, ObjectType: "class-validator", MethodName: "IsString", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "class-validator decorator validation (Nest.js)"},
	{ID: "js.nestjs.validationpipe", Pattern: `ValidationPipe`, ObjectType: "NestJS", MethodName: "ValidationPipe", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Nest.js ValidationPipe (class-validator integration)"},


	// XSS sanitizers
	{ID: "js.xss.filter", Pattern: `xss\s*\(`, MethodName: "xss", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "xss library filter"},
	{ID: "js.isomorphic-dompurify", Pattern: `sanitize\s*\(`, ObjectType: "DOMPurify", MethodName: "sanitize", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "isomorphic-dompurify sanitize"},

	// Crypto / Auth Sanitizers
	{ID: "js.crypto.bcrypt.hash", Pattern: `bcrypt\.hash\s*\(|bcrypt\.hashSync\s*\(`, ObjectType: "bcrypt", MethodName: "bcrypt.hash", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "bcrypt password hashing (safe password storage)"},
	{ID: "js.crypto.bcrypt.compare", Pattern: `bcrypt\.compare\s*\(|bcrypt\.compareSync\s*\(`, ObjectType: "bcrypt", MethodName: "bcrypt.compare", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "bcrypt password verification (constant-time comparison)"},
	{ID: "js.crypto.timingsafeequal", Pattern: `crypto\.timingSafeEqual\s*\(`, ObjectType: "crypto", MethodName: "timingSafeEqual", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Constant-time buffer comparison (prevents timing attacks)"},
	{ID: "js.crypto.randombytes", Pattern: `crypto\.randomBytes\s*\(|crypto\.randomUUID\s*\(`, ObjectType: "crypto", MethodName: "randomBytes/randomUUID", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Cryptographically secure random bytes/UUID generation"},
	{ID: "js.csrf.middleware", Pattern: `csurf\s*\(|csrf\s*\(|csrfProtection`, ObjectType: "csurf", MethodName: "csurf", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "CSRF protection middleware (Express csurf)"},

	// Input validation sanitizers (CWE-20)
	{ID: "js.express-validator", Pattern: `(?:check|body|param|query|header)\s*\(\s*['"]`, ObjectType: "express-validator", MethodName: "check/body/param/query", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite}, Description: "express-validator input validation"},
	{ID: "js.yup.validate", Pattern: `\.validate\s*\(|yup\.\w+\(\)`, ObjectType: "yup", MethodName: "validate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Yup schema validation"},
	{ID: "js.zod.safeparse", Pattern: `\.safeParse\s*\(`, ObjectType: "ZodSchema", MethodName: "safeParse", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Zod safe schema validation and parsing"},
	{ID: "js.ajv.validate", Pattern: `ajv\.validate\s*\(|\.compile\s*\([^)]*\)\s*\(`, ObjectType: "Ajv", MethodName: "validate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Ajv JSON schema validation"},

	// Infrastructure / Network Sanitizers
	{ID: "js.validator.isurl", Pattern: `validator\.isURL\s*\(`, ObjectType: "validator", MethodName: "isURL", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL validation via validator.js isURL (SSRF prevention)"},
	{ID: "js.validator.isip", Pattern: `validator\.isIP\s*\(`, ObjectType: "validator", MethodName: "isIP", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "IP address validation via validator.js isIP (SSRF prevention)"},
	{ID: "js.url.parse.hostname", Pattern: `new\s+URL\s*\([^)]+\)\.hostname`, ObjectType: "URL", MethodName: "hostname", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL hostname extraction for domain allowlist validation"},

	// Path sanitizers
	{ID: "js.path.normalize", Pattern: `path\.normalize\s*\(`, ObjectType: "path", MethodName: "normalize", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Path normalization (resolves .. and . components)"},
	{ID: "js.path.resolve", Pattern: `path\.resolve\s*\(`, ObjectType: "path", MethodName: "resolve", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Path resolution to absolute path"},

	// Numeric coercion
	{ID: "js.number", Pattern: `Number\s*\(`, MethodName: "Number", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Number type coercion (restricts to numeric values)"},
	{ID: "js.parsefloat", Pattern: `parseFloat\s*\(`, MethodName: "parseFloat", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Float parsing (type coercion to numeric)"},

	// HTML entity encoding
	{ID: "js.he.encode", Pattern: `he\.encode\s*\(|he\.escape\s*\(`, ObjectType: "he", MethodName: "encode/escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML entity encoding via he library"},

	// Safe YAML
	{ID: "js.yaml.safeload", Pattern: `yaml\.safeLoad\s*\(|YAML\.parse\s*\(`, ObjectType: "yaml", MethodName: "safeLoad/parse", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Safe YAML loading (disables dangerous types)"},

	// Type coercion sanitizers (convert to safe primitive types)
	{ID: "js.string.coerce", Pattern: `\bString\s*\(`, MethodName: "String", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "String type coercion (prevents operator injection in NoSQL queries)"},

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

	// Date constructor (type coercion to safe date object)
	{ID: "js.date.constructor", Pattern: `new\s+Date\s*\(`, MethodName: "Date", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Date constructor (type coercion to safe date)"},

	// Regex test as sanitizer for validated input
	{ID: "js.regex.replace.sanitize", Pattern: `\.replace\s*\(\s*/[^/]+/[gi]*\s*,\s*['"]`, MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkFileWrite, taint.SnkCommand}, Description: "Regex replace stripping dangerous characters"},

	// --- SnkEval sanitizers (code injection prevention) ---
	{ID: "js.vm.createcontext", Pattern: `vm\.createContext\s*\(`, ObjectType: "vm", MethodName: "createContext", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "V8 sandbox context creation (isolates eval scope)"},
	{ID: "js.vm2.vm", Pattern: `new\s+VM\s*\(\s*\{`, ObjectType: "vm2", MethodName: "VM", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "vm2 sandbox VM (secure eval isolation)"},
	{ID: "js.safeeval", Pattern: `safeEval\s*\(`, MethodName: "safeEval", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "safe-eval library (restricted eval context)"},
	{ID: "js.boolean.coerce", Pattern: `\bBoolean\s*\(`, MethodName: "Boolean", Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery, taint.SnkCommand}, Description: "Boolean type coercion (restricts to true/false)"},

	// --- SnkHeader sanitizers (HTTP header injection prevention) ---
	{ID: "js.replace.newlines", Pattern: `\.replace\s*\(\s*/\\[rn]/`, MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog}, Description: "Newline stripping via regex replace (prevents header/log injection)"},
	{ID: "js.helmet", Pattern: `helmet\s*\(`, ObjectType: "helmet", MethodName: "helmet", Neutralizes: []taint.SinkCategory{taint.SnkHeader}, Description: "Helmet middleware (sets security headers, prevents header manipulation)"},
	{ID: "js.validator.striplow", Pattern: `validator\.stripLow\s*\(`, ObjectType: "validator", MethodName: "stripLow", Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog}, Description: "validator.js stripLow (removes control characters including CR/LF)"},

	// --- SnkLDAP sanitizers (LDAP injection prevention) ---
	{ID: "js.ldap.escape.filter", Pattern: `ldapEscape\.filter\s*\(|ldapEscape\.dn\s*\(`, ObjectType: "ldapEscape", MethodName: "filter/dn", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "ldap-escape library filter/DN escaping"},
	{ID: "js.ldapjs.parsedN", Pattern: `ldap\.parseDN\s*\(`, ObjectType: "ldap", MethodName: "parseDN", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "ldapjs DN parsing (validates and normalizes DN components)"},

	// --- SnkLog sanitizers (log injection prevention) ---
	{ID: "js.string.replace.crlf", Pattern: `\.replace\s*\(\s*/\\n/|\.replace\s*\(\s*/\\r/`, MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader}, Description: "Newline character replacement (prevents log/header injection)"},
	{ID: "js.pino.child", Pattern: `logger\.child\s*\(\s*\{`, ObjectType: "pino", MethodName: "child", Neutralizes: []taint.SinkCategory{taint.SnkLog}, Description: "Pino structured child logger (key-value prevents injection)"},
	{ID: "js.winston.structured", Pattern: `logger\.\w+\s*\(\s*\{`, ObjectType: "winston", MethodName: "structured", Neutralizes: []taint.SinkCategory{taint.SnkLog}, Description: "Winston structured logging with object metadata"},

	// --- SnkTemplate sanitizers (SSTI prevention) ---
	{ID: "js.handlebars.escapeexpression", Pattern: `Handlebars\.Utils\.escapeExpression\s*\(|Handlebars\.escapeExpression\s*\(`, ObjectType: "Handlebars", MethodName: "escapeExpression", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "Handlebars HTML escaping (default in {{}} expressions)"},
	{ID: "js.nunjucks.autoescape", Pattern: `nunjucks\.configure\s*\([^)]*autoescape\s*:\s*true`, ObjectType: "nunjucks", MethodName: "configure", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "Nunjucks template engine with autoescaping enabled"},
	{ID: "js.ejs.escape", Pattern: `ejs\.render\s*\([^)]*\{[^}]*escape\s*:`, ObjectType: "ejs", MethodName: "render", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "EJS render with custom escape function"},
	{ID: "js.mustache.escape", Pattern: `Mustache\.escape\s*\(`, ObjectType: "Mustache", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput}, Description: "Mustache HTML escaping function"},

	// --- SnkXPath sanitizers (XPath injection prevention) ---
	{ID: "js.xpath.escape.quotes", Pattern: `\.replace\s*\(\s*/['"]/g\s*,`, MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "Quote character replacement (basic XPath injection prevention)"},
	{ID: "js.xpath.parseint.safe", Pattern: `parseInt\s*\([^,]+,\s*10\s*\)`, MethodName: "parseInt", Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkLDAP}, Description: "Integer parsing with radix 10 (type coercion prevents injection)"},

	// --- SnkFileRead additional sanitizers (path traversal prevention) ---
	{ID: "js.realpath.sync", Pattern: `fs\.realpathSync\s*\(|fs\.realpath\s*\(`, ObjectType: "fs", MethodName: "realpathSync/realpath", Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite}, Description: "Filesystem realpath resolution (resolves symlinks and .. components)"},
}
