package languages

import "github.com/turenlabs/batou/internal/taint"

// jsSanitizers defines sanitizer patterns for JavaScript/TypeScript.
var jsSanitizers = []taint.SanitizerDef{
	{ID: "js.encodeuricomponent", Pattern: `encodeURIComponent\s*\(`, MethodName: "encodeURIComponent", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect}, Description: "URI component encoding"},
	{ID: "js.encodeuri", Pattern: `encodeURI\s*\(`, MethodName: "encodeURI", Neutralizes: []taint.SinkCategory{taint.SnkRedirect}, Description: "URI encoding"},
	{ID: "js.dompurify.sanitize", Pattern: `DOMPurify\.sanitize\s*\(`, ObjectType: "DOMPurify", MethodName: "sanitize", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "DOMPurify HTML sanitization"},
	{ID: "js.sanitize.html", Pattern: `sanitizeHtml\s*\(`, MethodName: "sanitizeHtml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "sanitize-html library"},
	{ID: "js.validator.escape", Pattern: `validator\.escape\s*\(`, ObjectType: "validator", MethodName: "escape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "validator.js escape"},
	{ID: "js.parseint", Pattern: `parseInt\s*\(`, MethodName: "parseInt", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer parsing (type coercion)"},
	{ID: "js.path.basename", Pattern: `path\.basename\s*\(`, ObjectType: "path", MethodName: "basename", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Path basename extraction"},
	{ID: "js.knex.parameterized", Pattern: `knex\([^)]*\)\s*\.where\s*\(`, ObjectType: "knex", MethodName: "where", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Knex parameterized queries"},
	{ID: "js.escapehtml", Pattern: `escapeHtml\s*\(`, MethodName: "escapeHtml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "HTML escape function"},

	// SQL parameterization sanitizers
	{ID: "js.prisma.tagged.template", Pattern: `Prisma\.sql\s*\x60`, ObjectType: "Prisma", MethodName: "sql", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Prisma tagged template literal (parameterized)"},
	{ID: "js.sequelize.bind", Pattern: `\.query\s*\([^,]+,\s*\{\s*(?:replacements|bind)`, ObjectType: "sequelize", MethodName: "query", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Sequelize parameterized query with bind/replacements"},

	// MongoDB sanitizers
	{ID: "js.mongo.sanitize", Pattern: `mongo-sanitize|express-mongo-sanitize|sanitize\s*\(`, MethodName: "sanitize", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MongoDB query sanitization"},

	// Validation library sanitizers
	{ID: "js.zod.parse", Pattern: `\w+Schema\.parse\s*\(`, ObjectType: "ZodSchema", MethodName: "parse", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Zod schema validation and parsing"},
	{ID: "js.joi.validate", Pattern: `Joi\.(?:validate|attempt)\s*\(`, ObjectType: "Joi", MethodName: "validate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Joi schema validation"},
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
}
