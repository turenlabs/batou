package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *GoCatalog) Sanitizers() []taint.SanitizerDef {
	return append([]taint.SanitizerDef{
		{
			ID:          "go.html.escapestring",
			Language:    rules.LangGo,
			Pattern:     `html\.EscapeString\(`,
			ObjectType:  "",
			MethodName:  "EscapeString",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HTML entity escaping",
		},
		{
			ID:          "go.url.queryescape",
			Language:    rules.LangGo,
			Pattern:     `url\.QueryEscape\(`,
			ObjectType:  "",
			MethodName:  "QueryEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "URL query parameter escaping",
		},
		{
			ID:          "go.url.pathescape",
			Language:    rules.LangGo,
			Pattern:     `url\.PathEscape\(`,
			ObjectType:  "",
			MethodName:  "PathEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkURLFetch},
			Description: "URL path segment escaping",
		},
		{
			ID:          "go.filepath.base",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Base\(`,
			ObjectType:  "",
			MethodName:  "Base",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Extract base filename (strips directory traversal)",
		},
		// NOTE: filepath.Clean is intentionally NOT registered as a standalone
		// sanitizer. Clean("../../etc/passwd") still returns "../../etc/passwd" —
		// Clean only collapses .. segments lexically; it does not reject escapes.
		// Use filepath.IsLocal (Go 1.20+), filepath.Localize (Go 1.23+),
		// securejoin.SecureJoin, or a Clean+HasPrefix guard pattern. The
		// Clean+HasPrefix combo is recognised by processGuardPattern in the
		// astflow walker (strings.HasPrefix is a path-category guard).
		{
			ID:          "go.strconv.atoi",
			Language:    rules.LangGo,
			Pattern:     `strconv\.Atoi\(`,
			ObjectType:  "",
			MethodName:  "Atoi",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "Integer conversion (restricts to numeric values)",
		},
		{
			ID:          "go.strconv.parseint",
			Language:    rules.LangGo,
			Pattern:     `strconv\.ParseInt\(`,
			ObjectType:  "",
			MethodName:  "ParseInt",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "Integer parsing (restricts to numeric values)",
		},
		{
			ID:          "go.prepared.stmt",
			Language:    rules.LangGo,
			Pattern:     `stmt\.Query\(|stmt\.Exec\(|stmt\.QueryRow\(`,
			ObjectType:  "*sql.Stmt",
			MethodName:  "Prepared statement execution",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Prepared statement execution (parameterized query)",
		},
		{
			ID:          "go.template.execute",
			Language:    rules.LangGo,
			Pattern:     `\.Execute\(|\.ExecuteTemplate\(`,
			ObjectType:  "*template.Template",
			MethodName:  "Execute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "html/template auto-escaping on execution",
		},
		{
			ID:          "go.validator",
			Language:    rules.LangGo,
			Pattern:     `validate\.Struct\(|validate\.Var\(`,
			ObjectType:  "*validator.Validate",
			MethodName:  "Struct",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Struct/field validation via go-playground/validator",
		},

		// --- html/template auto-escaping ---
		{
			ID:          "go.html.template.new",
			Language:    rules.LangGo,
			Pattern:     `html/template.*\.New\(|template\.Must\(`,
			ObjectType:  "",
			MethodName:  "html/template.New",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "html/template provides auto-escaping for HTML contexts",
		},

		// --- GORM parameterized queries ---
		{
			ID:          "go.gorm.parameterized",
			Language:    rules.LangGo,
			Pattern:     `\.Where\(.*\?`,
			ObjectType:  "*gorm.DB",
			MethodName:  "Where (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "GORM Where with placeholder-based parameterized query",
		},

		// --- bluemonday HTML sanitizer ---
		{
			ID:          "go.bluemonday.sanitize",
			Language:    rules.LangGo,
			Pattern:     `\.Sanitize\(|\.SanitizeBytes\(`,
			ObjectType:  "*bluemonday.Policy",
			MethodName:  "Sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "bluemonday HTML sanitization policy",
		},

		// --- SMTP header sanitization ---
		{
			ID:          "go.strings.newline.strip",
			Language:    rules.LangGo,
			Pattern:     `strings\.ReplaceAll\(.*\\n|strings\.ReplaceAll\(.*\\r`,
			ObjectType:  "",
			MethodName:  "ReplaceAll",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Stripping newlines prevents header/log injection in SMTP/HTTP/logs",
		},

		// --- regexp QuoteMeta for ReDoS ---
		{
			ID:          "go.regexp.quotemeta",
			Language:    rules.LangGo,
			Pattern:     `regexp\.QuoteMeta\(`,
			ObjectType:  "",
			MethodName:  "QuoteMeta",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Regex metacharacter escaping prevents injection in regex patterns",
		},

		// --- Crypto / Auth Sanitizers ---
		{
			ID:          "go.crypto.bcrypt.generate",
			Language:    rules.LangGo,
			Pattern:     `bcrypt\.GenerateFromPassword\(`,
			ObjectType:  "",
			MethodName:  "bcrypt.GenerateFromPassword",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "bcrypt password hashing (safe password storage)",
		},
		{
			ID:          "go.crypto.bcrypt.compare",
			Language:    rules.LangGo,
			Pattern:     `bcrypt\.CompareHashAndPassword\(`,
			ObjectType:  "",
			MethodName:  "bcrypt.CompareHashAndPassword",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "bcrypt password verification (constant-time comparison)",
		},
		{
			ID:          "go.crypto.argon2",
			Language:    rules.LangGo,
			Pattern:     `argon2\.IDKey\(|argon2\.Key\(`,
			ObjectType:  "",
			MethodName:  "argon2.IDKey/Key",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2 key derivation (safe password storage)",
		},
		{
			ID:          "go.crypto.hmac",
			Language:    rules.LangGo,
			Pattern:     `hmac\.New\(|hmac\.Equal\(`,
			ObjectType:  "",
			MethodName:  "hmac.New/hmac.Equal",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HMAC creation and constant-time verification",
		},
		{
			ID:          "go.crypto.subtle.constanttimecompare",
			Language:    rules.LangGo,
			Pattern:     `subtle\.ConstantTimeCompare\(`,
			ObjectType:  "",
			MethodName:  "subtle.ConstantTimeCompare",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Constant-time byte comparison (prevents timing attacks)",
		},

		// --- Input validation sanitizers (CWE-20) ---
		{
			ID:          "go.gin.binding",
			Language:    rules.LangGo,
			Pattern:     `\.ShouldBindJSON\(|\.ShouldBind\(|\.BindJSON\(|binding\.Bind\(`,
			ObjectType:  "*gin.Context",
			MethodName:  "ShouldBindJSON/BindJSON",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Gin framework struct binding with validation tags",
		},
		{
			ID:          "go.echo.bind",
			Language:    rules.LangGo,
			Pattern:     `\.Bind\s*\(|echo\.Bind\(`,
			ObjectType:  "echo.Context",
			MethodName:  "Bind",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Echo framework request binding with validation",
		},
		{
			ID:          "go.ozzo.validation",
			Language:    rules.LangGo,
			Pattern:     `validation\.ValidateStruct\(|validation\.Validate\(`,
			ObjectType:  "ozzo-validation",
			MethodName:  "ValidateStruct",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "ozzo-validation struct/field validation",
		},
		{
			// ozzo-routing's *routing.Context.Read decodes the request body
			// into a typed Go struct via the content-type-matched DataReader
			// (the framework analog of Echo's Bind / Gin's ShouldBind). Like
			// those, struct binding coerces fields to their declared types,
			// so the decoded value no longer carries free-form injection
			// payloads into query/command/markup/trust sinks. Scoped to
			// *routing.Context so a generic .Read on io.Reader is unaffected.
			ID:          "go.ozzo.routing.context.read",
			Language:    rules.LangGo,
			Pattern:     `\.Read\s*\(`,
			ObjectType:  "*routing.Context",
			MethodName:  "Read",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "ozzo-routing request binding into typed struct (*routing.Context.Read)",
		},

		// --- Infrastructure / Network Sanitizers ---
		{
			ID:          "go.net.ip.parse",
			Language:    rules.LangGo,
			Pattern:     `net\.ParseIP\(`,
			ObjectType:  "",
			MethodName:  "ParseIP",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address parsing and validation (SSRF prevention)",
		},
		{
			ID:          "go.net.cidr.contains",
			Language:    rules.LangGo,
			Pattern:     `\.Contains\(|net\.ParseCIDR\(`,
			ObjectType:  "*net.IPNet",
			MethodName:  "Contains/ParseCIDR",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "CIDR range check for IP allowlisting (SSRF prevention)",
		},
		{
			ID:          "go.net.url.hostname",
			Language:    rules.LangGo,
			Pattern:     `\.Hostname\(\)`,
			ObjectType:  "*url.URL",
			MethodName:  "Hostname",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL hostname extraction for domain allowlist validation",
		},

		// --- Path sanitizers ---
		{
			ID:          "go.filepath.abs",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Abs\(`,
			ObjectType:  "",
			MethodName:  "Abs",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Absolute path resolution (anchors path to prevent traversal)",
		},
		{
			ID:          "go.filepath.islocal",
			Language:    rules.LangGo,
			Pattern:     `filepath\.IsLocal\s*\(`,
			ObjectType:  "",
			MethodName:  "filepath.IsLocal",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "filepath.IsLocal — returns true only when path is lexically contained within current dir (Go 1.20+, complete CWE-22 guard)",
		},
		{
			ID:          "go.securejoin.securejoin",
			Language:    rules.LangGo,
			Pattern:     `securejoin\.SecureJoin\s*\(`,
			ObjectType:  "",
			MethodName:  "securejoin.SecureJoin",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "cyphar/filepath-securejoin SecureJoin — joins a base with a user path while resolving symlinks safely (CWE-22/CWE-59 complete guard)",
		},
		{
			ID:          "go.securejoin.securejoinvfs",
			Language:    rules.LangGo,
			Pattern:     `securejoin\.SecureJoinVFS\s*\(`,
			ObjectType:  "",
			MethodName:  "securejoin.SecureJoinVFS",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "cyphar/filepath-securejoin SecureJoinVFS — VFS-pluggable safe join variant (CWE-22/CWE-59 complete guard)",
		},

		// --- Regex validation ---
		{
			ID:          "go.regexp.matchstring",
			Language:    rules.LangGo,
			Pattern:     `regexp\.MatchString\(|\.MatchString\(`,
			ObjectType:  "",
			MethodName:  "MatchString",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkTrustBoundary},
			Description: "Regex match validation (allowlist pattern check)",
		},

		// --- String trimming ---
		{
			ID:          "go.strings.trimspace",
			Language:    rules.LangGo,
			Pattern:     `strings\.TrimSpace\(`,
			ObjectType:  "",
			MethodName:  "TrimSpace",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Whitespace trimming (prevents header injection via leading/trailing control chars)",
		},

		// --- URL parse for hostname validation ---
		{
			ID:          "go.url.parse",
			Language:    rules.LangGo,
			Pattern:     `url\.Parse\(`,
			ObjectType:  "",
			MethodName:  "Parse",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL parsing for hostname/scheme validation (SSRF prevention)",
		},

		// --- LDAP filter escaping ---
		{
			ID:          "go.ldap.escapefilter",
			Language:    rules.LangGo,
			Pattern:     `ldap\.EscapeFilter\(`,
			ObjectType:  "",
			MethodName:  "EscapeFilter",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP filter escaping (prevents LDAP injection)",
		},
		{
			ID:          "go.ldap.escapedn",
			Language:    rules.LangGo,
			Pattern:     `ldap\.EscapeDN\s*\(`,
			ObjectType:  "",
			MethodName:  "EscapeDN",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "go-ldap/ldap/v3 EscapeDN — RFC 4514 distinguished-name escaping (escapes the DN context, distinct from filter escaping; prevents LDAP DN injection)",
		},
		{
			ID:          "go.ldap.parsedn",
			Language:    rules.LangGo,
			Pattern:     `ldap\.ParseDN\s*\(`,
			ObjectType:  "",
			MethodName:  "ParseDN",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "go-ldap/ldap/v3 ParseDN — validates and parses a distinguished name (rejects malformed/injected DN syntax before it reaches an LDAP DN sink)",
		},

		// --- Numeric conversion sanitizers ---
		{
			ID:          "go.strconv.parsefloat",
			Language:    rules.LangGo,
			Pattern:     `strconv\.ParseFloat\(`,
			ObjectType:  "",
			MethodName:  "ParseFloat",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "Float parsing (restricts to numeric values)",
		},
		{
			ID:          "go.strconv.parsebool",
			Language:    rules.LangGo,
			Pattern:     `strconv\.ParseBool\(`,
			ObjectType:  "",
			MethodName:  "ParseBool",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "Boolean parsing (restricts to true/false values)",
		},
		{
			ID:          "go.strconv.parseuint",
			Language:    rules.LangGo,
			Pattern:     `strconv\.ParseUint\(`,
			ObjectType:  "",
			MethodName:  "ParseUint",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "Unsigned integer parsing (restricts to non-negative numeric values)",
		},
		{
			// spf13/cast is one of the most widely used Go coercion libraries
			// (a dependency of Viper/Cobra). Its To<Type> helpers coerce an
			// `any` value to a strongly-typed scalar, returning the zero value
			// on failure — dropping any string-injection payload, exactly like
			// the strconv.Parse* family above. Tainted value is at arg[0].
			ID:          "go.cast.toint",
			Language:    rules.LangGo,
			Pattern:     `cast\.ToInt(8|16|32|64)?E?\s*\(`,
			ObjectType:  "",
			MethodName:  "cast.ToInt/cast.ToInt8/cast.ToInt16/cast.ToInt32/cast.ToInt64/cast.ToIntE/cast.ToInt8E/cast.ToInt16E/cast.ToInt32E/cast.ToInt64E",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "spf13/cast integer coercion (restricts to numeric values)",
		},
		{
			ID:          "go.cast.touint",
			Language:    rules.LangGo,
			Pattern:     `cast\.ToUint(8|16|32|64)?E?\s*\(`,
			ObjectType:  "",
			MethodName:  "cast.ToUint/cast.ToUint8/cast.ToUint16/cast.ToUint32/cast.ToUint64/cast.ToUintE/cast.ToUint8E/cast.ToUint16E/cast.ToUint32E/cast.ToUint64E",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "spf13/cast unsigned integer coercion (restricts to non-negative numeric values)",
		},
		{
			ID:          "go.cast.tofloat",
			Language:    rules.LangGo,
			Pattern:     `cast\.ToFloat(32|64)E?\s*\(`,
			ObjectType:  "",
			MethodName:  "cast.ToFloat32/cast.ToFloat64/cast.ToFloat32E/cast.ToFloat64E",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "spf13/cast float coercion (restricts to numeric values)",
		},
		{
			ID:          "go.cast.tobool",
			Language:    rules.LangGo,
			Pattern:     `cast\.ToBoolE?\s*\(`,
			ObjectType:  "",
			MethodName:  "cast.ToBool/cast.ToBoolE",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "spf13/cast boolean coercion (restricts to true/false values)",
		},
		{
			ID:          "go.strconv.formatint",
			Language:    rules.LangGo,
			Pattern:     `strconv\.FormatInt\(`,
			ObjectType:  "",
			MethodName:  "FormatInt",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "Integer formatting (ensures numeric string output)",
		},

		// --- Secure random ---
		{
			ID:          "go.crypto.rand.read",
			Language:    rules.LangGo,
			Pattern:     `crypto/rand|rand\.Read\(|rand\.Int\(`,
			ObjectType:  "crypto/rand",
			MethodName:  "rand.Read/rand.Int",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random via crypto/rand",
		},

		// --- sqlx parameterized queries ---
		{
			ID:          "go.sqlx.named",
			Language:    rules.LangGo,
			Pattern:     `sqlx\.Named\(`,
			ObjectType:  "sqlx",
			MethodName:  "Named",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "sqlx Named parameterized binding neutralizes SQL injection",
		},
		{
			ID:          "go.sqlx.in",
			Language:    rules.LangGo,
			Pattern:     `sqlx\.In\(`,
			ObjectType:  "sqlx",
			MethodName:  "In",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "sqlx In parameter expansion neutralizes SQL injection",
		},
		{
			ID:          "go.sqlx.rebind",
			Language:    rules.LangGo,
			Pattern:     `\.Rebind\(`,
			ObjectType:  "*sqlx.DB",
			MethodName:  "Rebind",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "sqlx Rebind placeholder rebinding neutralizes SQL injection",
		},

		// --- ent predicate builder ---
		{
			ID:          "go.ent.predicate",
			Language:    rules.LangGo,
			Pattern:     `\.Where\(.*predicate\.`,
			ObjectType:  "*ent.Client",
			MethodName:  "Where (predicate)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ent predicate builder neutralizes SQL injection",
		},

		// --- bun query builders ---
		{
			ID:          "go.bun.selectquery",
			Language:    rules.LangGo,
			Pattern:     `\.NewSelect\(\)`,
			ObjectType:  "*bun.DB",
			MethodName:  "NewSelect",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "bun SelectQuery builder neutralizes SQL injection",
		},
		{
			ID:          "go.bun.insertquery",
			Language:    rules.LangGo,
			Pattern:     `\.NewInsert\(\)`,
			ObjectType:  "*bun.DB",
			MethodName:  "NewInsert",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "bun InsertQuery builder neutralizes SQL injection",
		},

		// --- goqu query builder (doug-martin/goqu) ---
		{
			ID:          "go.goqu.from",
			Language:    rules.LangGo,
			Pattern:     `goqu\.From\s*\(|goqu\.Dialect\s*\(`,
			ObjectType:  "*goqu.Database",
			MethodName:  "goqu.From/Dialect",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "doug-martin/goqu SQL builder (From/Dialect) emits ?/$N placeholders with bound args via ToSQL — neutralizes SQL injection",
		},

		// --- Command injection sanitizers ---
		{
			ID:          "go.shellescape.quote",
			Language:    rules.LangGo,
			Pattern:     `shellescape\.Quote\(`,
			ObjectType:  "",
			MethodName:  "shellescape.Quote",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Shell argument escaping via alessio/shellescape",
		},
		{
			ID:          "go.shlex.split",
			Language:    rules.LangGo,
			Pattern:     `shlex\.Split\(`,
			ObjectType:  "",
			MethodName:  "shlex.Split",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Safe shell argument splitting via google/shlex",
		},

		// --- UUID validation sanitizers ---
		{
			ID:          "go.uuid.parse",
			Language:    rules.LangGo,
			Pattern:     `uuid\.Parse\(`,
			ObjectType:  "",
			MethodName:  "uuid.Parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkHeader, taint.SnkLDAP, taint.SnkXPath, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkTrustBoundary},
			Description: "UUID format validation restricts input to hex+dashes (google/uuid)",
		},
		{
			ID:          "go.uuid.mustparse",
			Language:    rules.LangGo,
			Pattern:     `uuid\.MustParse\(`,
			ObjectType:  "",
			MethodName:  "uuid.MustParse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkHeader, taint.SnkLDAP, taint.SnkXPath, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkTrustBoundary},
			Description: "UUID format validation (panics on invalid, restricts to hex+dashes)",
		},

		// --- Hex/encoding validation sanitizers ---
		{
			ID:          "go.hex.decodestring",
			Language:    rules.LangGo,
			Pattern:     `hex\.DecodeString\(`,
			ObjectType:  "",
			MethodName:  "hex.DecodeString",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader, taint.SnkTrustBoundary},
			Description: "Hex decoding validates input is hex-only characters (encoding/hex)",
		},
		{
			ID:          "go.hex.encodetostring",
			Language:    rules.LangGo,
			Pattern:     `hex\.EncodeToString\(`,
			ObjectType:  "",
			MethodName:  "hex.EncodeToString",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader, taint.SnkTrustBoundary},
			Description: "Hex encoding produces safe alphanumeric output (encoding/hex)",
		},

		// --- JSON encoding sanitizer ---
		{
			ID:          "go.json.marshal",
			Language:    rules.LangGo,
			Pattern:     `json\.Marshal\(`,
			ObjectType:  "",
			MethodName:  "json.Marshal",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Go json.Marshal escapes <, >, & by default (safe for HTML embedding)",
		},

		// --- Deserialization sanitizers ---
		{
			ID:          "go.json.disallowunknownfields",
			Language:    rules.LangGo,
			Pattern:     `\.DisallowUnknownFields\(`,
			ObjectType:  "*json.Decoder",
			MethodName:  "DisallowUnknownFields",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Strict JSON decoding rejects unexpected fields",
		},
		{
			ID:          "go.jsonschema.validate",
			Language:    rules.LangGo,
			Pattern:     `jsonschema\.Validate\(|\.Validate\(.*jsonschema`,
			ObjectType:  "",
			MethodName:  "jsonschema.Validate",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "JSON schema validation constrains deserialized data shape",
		},

		// --- Trust boundary sanitizers ---
		{
			ID:          "go.csrf.protect",
			Language:    rules.LangGo,
			Pattern:     `csrf\.Protect\(`,
			ObjectType:  "",
			MethodName:  "csrf.Protect",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "CSRF middleware protection via gorilla/csrf",
		},
		{
			ID:          "go.csrf.token",
			Language:    rules.LangGo,
			Pattern:     `csrf\.Token\(`,
			ObjectType:  "",
			MethodName:  "csrf.Token",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "CSRF token generation for form embedding (gorilla/csrf)",
		},
		{
			ID:          "go.jwt.parse",
			Language:    rules.LangGo,
			Pattern:     `jwt\.Parse\(|jwt\.ParseWithClaims\(`,
			ObjectType:  "",
			MethodName:  "jwt.Parse",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkDeserialize},
			Description: "JWT parsing with signature validation (golang-jwt/jwt)",
		},
		{
			ID:          "go.mail.parseaddress",
			Language:    rules.LangGo,
			Pattern:     `mail\.ParseAddress\s*\(`,
			ObjectType:  "",
			MethodName:  "mail.ParseAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkHeader},
			Description: "RFC 5322 email address validation via net/mail (rejects invalid format)",
		},

		// --- Query builder sanitizers ---
		{
			ID:          "go.squirrel.select",
			Language:    rules.LangGo,
			Pattern:     `squirrel\.Select\(|sq\.Select\(`,
			ObjectType:  "squirrel",
			MethodName:  "Select",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "squirrel query builder with parameterized queries",
		},
		{
			ID:          "go.squirrel.eq",
			Language:    rules.LangGo,
			Pattern:     `squirrel\.Eq\{|sq\.Eq\{`,
			ObjectType:  "squirrel",
			MethodName:  "Eq",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "squirrel Eq condition builder (parameterized)",
		},
		{
			ID:          "go.pgx.queryrow",
			Language:    rules.LangGo,
			Pattern:     `\.QueryRow\(.*\$\d`,
			ObjectType:  "*pgx.Conn",
			MethodName:  "QueryRow (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "pgx QueryRow with $N placeholders (parameterized query)",
		},

		// --- Path containment sanitizers ---
		{
			ID:          "go.filepath.rel",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Rel\(`,
			ObjectType:  "",
			MethodName:  "filepath.Rel",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Relative path computation for containment checks (detects traversal)",
		},
		{
			ID:          "go.filepath.match",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Match\(`,
			ObjectType:  "",
			MethodName:  "filepath.Match",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Glob pattern matching for path allowlist validation",
		},

		// --- Deserialization sanitizers ---
		{
			ID:          "go.yaml.decoder.knownfields",
			Language:    rules.LangGo,
			Pattern:     `\.KnownFields\s*\(\s*true\s*\)`,
			ObjectType:  "*yaml.Decoder",
			MethodName:  "KnownFields",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "yaml.v3 KnownFields(true) rejects unknown fields (strict deserialization)",
		},
		{
			ID:          "go.gob.register",
			Language:    rules.LangGo,
			Pattern:     `gob\.Register\s*\(`,
			ObjectType:  "",
			MethodName:  "gob.Register",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Pre-registering types limits gob deserialization to known types",
		},
		{
			ID:          "go.mapstructure.decode",
			Language:    rules.LangGo,
			Pattern:     `mapstructure\.Decode\s*\(|mapstructure\.WeakDecode\s*\(`,
			ObjectType:  "",
			MethodName:  "mapstructure.Decode",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "mitchellh/mapstructure typed struct decoding with field-level validation",
		},

		// --- Structured logging sanitizers ---
		{
			ID:          "go.slog.attr",
			Language:    rules.LangGo,
			Pattern:     `slog\.(String|Int|Bool|Float64|Any|Duration|Time|Group)\s*\(`,
			ObjectType:  "slog",
			MethodName:  "slog.String/Int/Bool/Any",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "slog typed attribute constructors bind values to named keys (prevents log injection)",
		},
		{
			ID:          "go.zap.field",
			Language:    rules.LangGo,
			Pattern:     `zap\.(String|Int|Bool|Float64|Any|Error|Duration|Binary|ByteString|Time)\s*\(`,
			ObjectType:  "zap",
			MethodName:  "zap.String/Int/Bool/Any",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "zap typed field constructors bind values to named keys (prevents log injection)",
		},

		// --- XML sanitizers ---
		{
			ID:          "go.xml.marshal",
			Language:    rules.LangGo,
			Pattern:     `xml\.Marshal\s*\(|xml\.MarshalIndent\s*\(`,
			ObjectType:  "",
			MethodName:  "xml.Marshal",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkHTMLOutput},
			Description: "encoding/xml Marshal escapes special characters in XML output",
		},

		// --- Base64 encoding sanitizer ---
		{
			ID:          "go.base64.encodetostring",
			Language:    rules.LangGo,
			Pattern:     `base64\.\w*Encoding\.EncodeToString\s*\(`,
			ObjectType:  "",
			MethodName:  "EncodeToString",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkHeader, taint.SnkLog, taint.SnkEval, taint.SnkXPath, taint.SnkLDAP},
			Description: "Base64 encoding eliminates injection metacharacters (SQL, shell, HTML, LDAP)",
		},

		// --- PostgreSQL quoting sanitizers (lib/pq) ---
		{
			ID:          "go.pq.quoteidentifier",
			Language:    rules.LangGo,
			Pattern:     `pq\.QuoteIdentifier\s*\(`,
			ObjectType:  "",
			MethodName:  "pq.QuoteIdentifier",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "lib/pq double-quote escaping for SQL identifiers (table/column names)",
		},
		{
			ID:          "go.pq.quoteliteral",
			Language:    rules.LangGo,
			Pattern:     `pq\.QuoteLiteral\s*\(`,
			ObjectType:  "",
			MethodName:  "pq.QuoteLiteral",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "lib/pq single-quote escaping for SQL string literals",
		},

		// --- pgx identifier sanitizer ---
		{
			ID:          "go.pgx.identifier.sanitize",
			Language:    rules.LangGo,
			Pattern:     `pgx\.Identifier\{.*\}\.Sanitize\s*\(`,
			ObjectType:  "",
			MethodName:  "Sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "pgx Identifier.Sanitize() safely quotes SQL identifiers",
		},

		// --- URL path sanitizers ---
		{
			ID:          "go.path.clean",
			Language:    rules.LangGo,
			Pattern:     `path\.Clean\s*\(`,
			ObjectType:  "",
			MethodName:  "path.Clean",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "path.Clean normalizes URL paths (removes .., //, trailing slashes)",
		},
		{
			ID:          "go.url.joinpath",
			Language:    rules.LangGo,
			Pattern:     `url\.JoinPath\s*\(`,
			ObjectType:  "",
			MethodName:  "url.JoinPath",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "net/url.JoinPath safely constructs URL paths (Go 1.19+)",
		},
		// cleanPath is the URL-path version of path.Clean copied verbatim from
		// julienschmidt/httprouter into gin, echo, chi and many other routers.
		// It is a complete open-redirect (CWE-601) guard for a path-only
		// redirect target: it FORCES the result to begin with a single `/`
		// (`if p[0] != '/' { buf[0] = '/' }`) and COLLAPSES repeated slashes
		// (`case p[r] == '/': // empty path element`), so a protocol-relative
		// `//evil.com` becomes `/evil.com` and `../` segments are eliminated —
		// the output can never be parsed as a host or absolute URL. This is the
		// unexported-function analog of the existing go.path.clean entry; the
		// canonical FP is gin's redirectFixedPath:
		//   findCaseInsensitivePath(cleanPath(req.URL.Path), ...)
		// Scoped to SnkRedirect only (a path-clean says nothing about an SSRF
		// host allowlist, unlike path.Clean which net/http treats as URL-safe).
		{
			ID:          "go.cleanpath.httprouter",
			Language:    rules.LangGo,
			Pattern:     `\bcleanPath\s*\(`,
			ObjectType:  "",
			MethodName:  "cleanPath",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "httprouter/gin cleanPath canonicalizes a URL path to a single-slash-rooted form (collapses //, eliminates ../), preventing open-redirect to an external host (CWE-601)",
		},

		// --- Email validation sanitizer ---
		{
			ID:          "go.mail.parseaddress",
			Language:    rules.LangGo,
			Pattern:     `mail\.ParseAddress\s*\(`,
			ObjectType:  "",
			MethodName:  "mail.ParseAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "net/mail.ParseAddress validates email format, prevents header injection",
		},

		// --- Host parsing sanitizer ---
		{
			ID:          "go.net.splithostport",
			Language:    rules.LangGo,
			Pattern:     `net\.SplitHostPort\s*\(`,
			ObjectType:  "",
			MethodName:  "net.SplitHostPort",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "net.SplitHostPort extracts validated host component for SSRF/redirect checks",
		},

		// --- Modern crypto sanitizers ---
		{
			ID:          "go.crypto.sha256",
			Language:    rules.LangGo,
			Pattern:     `sha256\.Sum256\s*\(|sha256\.New\s*\(`,
			ObjectType:  "",
			MethodName:  "sha256.Sum256/New",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-256 is a strong cryptographic hash (replaces weak MD5/SHA1)",
		},
		{
			ID:          "go.crypto.sha512",
			Language:    rules.LangGo,
			Pattern:     `sha512\.Sum512\s*\(|sha512\.New\s*\(`,
			ObjectType:  "",
			MethodName:  "sha512.Sum512/New",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-512 is a strong cryptographic hash (replaces weak MD5/SHA1)",
		},
		{
			ID:          "go.crypto.aes.gcm",
			Language:    rules.LangGo,
			Pattern:     `cipher\.NewGCM\s*\(`,
			ObjectType:  "",
			MethodName:  "cipher.NewGCM",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "AES-GCM authenticated encryption (modern AEAD, replaces ECB/CBC)",
		},
		{
			ID:          "go.crypto.ed25519",
			Language:    rules.LangGo,
			Pattern:     `ed25519\.(Sign|Verify)\s*\(`,
			ObjectType:  "",
			MethodName:  "ed25519.Sign/Verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Ed25519 digital signatures (modern, safe key sizes)",
		},
		{
			ID:          "go.crypto.scrypt",
			Language:    rules.LangGo,
			Pattern:     `scrypt\.Key\s*\(`,
			ObjectType:  "",
			MethodName:  "scrypt.Key",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "scrypt key derivation for password hashing (memory-hard, safe alternative to MD5/SHA1)",
		},

		// --- text/template escaper functions ---
		{
			ID:          "go.template.htmlescapestring",
			Language:    rules.LangGo,
			Pattern:     `template\.HTMLEscapeString\s*\(`,
			ObjectType:  "",
			MethodName:  "template.HTMLEscapeString",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "text/template HTML entity escaping (escapes <, >, &, \", ')",
		},
		{
			ID:          "go.template.jsescapestring",
			Language:    rules.LangGo,
			Pattern:     `template\.JSEscapeString\s*\(`,
			ObjectType:  "",
			MethodName:  "template.JSEscapeString",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkHTMLOutput},
			Description: "text/template JavaScript string escaping (prevents XSS in inline scripts)",
		},
		{
			ID:          "go.template.urlqueryescaper",
			Language:    rules.LangGo,
			Pattern:     `template\.URLQueryEscaper\s*\(`,
			ObjectType:  "",
			MethodName:  "template.URLQueryEscaper",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHTMLOutput},
			Description: "text/template URL query escaping for safe URL construction",
		},

		// --- strconv.Itoa (numeric output guarantee) ---
		{
			ID:          "go.strconv.itoa",
			Language:    rules.LangGo,
			Pattern:     `strconv\.Itoa\s*\(`,
			ObjectType:  "",
			MethodName:  "strconv.Itoa",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkLog, taint.SnkTemplate, taint.SnkHeader, taint.SnkEval, taint.SnkLDAP, taint.SnkXPath, taint.SnkTrustBoundary},
			Description: "Integer to string conversion (output is always numeric-only, safe for all injection contexts)",
		},

		// --- filepath.EvalSymlinks (symlink resolution) ---
		{
			ID:          "go.filepath.evalsymlinks",
			Language:    rules.LangGo,
			Pattern:     `filepath\.EvalSymlinks\s*\(`,
			ObjectType:  "",
			MethodName:  "filepath.EvalSymlinks",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Resolves all symlinks to real path (prevents symlink-based path traversal)",
		},

		// --- Modern IP validation (net/netip, Go 1.18+) ---
		{
			ID:          "go.netip.parseaddr",
			Language:    rules.LangGo,
			Pattern:     `netip\.ParseAddr\s*\(`,
			ObjectType:  "",
			MethodName:  "netip.ParseAddr",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Modern IP address validation via net/netip (Go 1.18+, SSRF prevention)",
		},
		{
			ID:          "go.netip.parseprefix",
			Language:    rules.LangGo,
			Pattern:     `netip\.ParsePrefix\s*\(`,
			ObjectType:  "",
			MethodName:  "netip.ParsePrefix",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "CIDR prefix validation via net/netip (Go 1.18+, IP allowlist for SSRF prevention)",
		},

		// --- URL path joining (resolves ..) ---
		{
			ID:          "go.path.join",
			Language:    rules.LangGo,
			Pattern:     `path\.Join\s*\(`,
			ObjectType:  "",
			MethodName:  "path.Join",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "path.Join normalizes URL path components (resolves .., cleans double slashes)",
		},

		// --- database/sql named parameters ---
		{
			ID:          "go.sql.named",
			Language:    rules.LangGo,
			Pattern:     `sql\.Named\s*\(`,
			ObjectType:  "",
			MethodName:  "sql.Named",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "database/sql named parameter binding for parameterized queries",
		},

		// --- Modern AEAD crypto ---
		{
			ID:          "go.crypto.chacha20poly1305",
			Language:    rules.LangGo,
			Pattern:     `chacha20poly1305\.New\s*\(|chacha20poly1305\.NewX\s*\(`,
			ObjectType:  "",
			MethodName:  "chacha20poly1305.New/NewX",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "ChaCha20-Poly1305 AEAD encryption (modern, safe alternative to ECB/CBC)",
		},

		// --- HKDF key derivation ---
		{
			ID:          "go.crypto.hkdf",
			Language:    rules.LangGo,
			Pattern:     `hkdf\.New\s*\(`,
			ObjectType:  "",
			MethodName:  "hkdf.New",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HKDF key derivation function (safe key material extraction, RFC 5869)",
		},

		// --- olivere/elastic structured-query builders ---
		// Structured field/value constructors place the tainted value into a
		// value position of the generated query JSON, so it cannot modify the
		// query structure. These are the safe alternatives to
		// elastic.NewQueryStringQuery / NewRawStringQuery.
		{
			ID:          "go.olivere.elastic.newtermquery",
			Language:    rules.LangGo,
			Pattern:     `elastic\.NewTermQuery\s*\(`,
			ObjectType:  "",
			MethodName:  "elastic.NewTermQuery",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "olivere/elastic structured term query (field+value isolated in query DSL, no Lucene interpolation)",
		},
		{
			ID:          "go.olivere.elastic.newmatchquery",
			Language:    rules.LangGo,
			Pattern:     `elastic\.NewMatchQuery\s*\(`,
			ObjectType:  "",
			MethodName:  "elastic.NewMatchQuery",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "olivere/elastic structured match query (analyzed text search, no Lucene injection)",
		},
		{
			ID:          "go.olivere.elastic.newrangequery",
			Language:    rules.LangGo,
			Pattern:     `elastic\.NewRangeQuery\s*\(`,
			ObjectType:  "",
			MethodName:  "elastic.NewRangeQuery",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "olivere/elastic structured range query (typed bounds, no Lucene interpolation)",
		},
		{
			ID:          "go.crypto.pbkdf2.key",
			Language:    rules.LangGo,
			Pattern:     `pbkdf2\.Key\s*\(`,
			ObjectType:  "",
			MethodName:  "pbkdf2.Key",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 key derivation (golang.org/x/crypto/pbkdf2; NIST SP 800-132, OWASP-recommended for password hashing)",
		},
		{
			ID:          "go.crypto.sha3",
			Language:    rules.LangGo,
			Pattern:     `sha3\.Sum256\s*\(|sha3\.Sum512\s*\(|sha3\.Sum384\s*\(|sha3\.Sum224\s*\(|sha3\.New256\s*\(|sha3\.New512\s*\(`,
			ObjectType:  "",
			MethodName:  "sha3.Sum256/Sum512/Sum384/Sum224/New256/New512",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SHA-3 cryptographic hash (golang.org/x/crypto/sha3; FIPS 202 Keccak family, modern strong hash)",
		},
		{
			ID:          "go.crypto.blake2b",
			Language:    rules.LangGo,
			Pattern:     `blake2b\.Sum256\s*\(|blake2b\.Sum512\s*\(|blake2b\.Sum384\s*\(|blake2b\.New\s*\(|blake2b\.New256\s*\(|blake2b\.New512\s*\(`,
			ObjectType:  "",
			MethodName:  "blake2b.Sum256/Sum512/Sum384/New/New256/New512",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BLAKE2b cryptographic hash (golang.org/x/crypto/blake2b; RFC 7693, modern fast hash, replaces MD5/SHA1)",
		},
		{
			ID:          "go.crypto.blake2s",
			Language:    rules.LangGo,
			Pattern:     `blake2s\.Sum256\s*\(|blake2s\.Sum128\s*\(|blake2s\.New256\s*\(|blake2s\.New128\s*\(`,
			ObjectType:  "",
			MethodName:  "blake2s.Sum256/Sum128/New256/New128",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BLAKE2s cryptographic hash (golang.org/x/crypto/blake2s; RFC 7693, 32-bit-optimized variant)",
		},
		{
			ID:          "go.crypto.curve25519",
			Language:    rules.LangGo,
			Pattern:     `curve25519\.X25519\s*\(`,
			ObjectType:  "",
			MethodName:  "curve25519.X25519",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Curve25519 X25519 ECDH key exchange (golang.org/x/crypto/curve25519; RFC 7748)",
		},
		{
			ID:          "go.crypto.nacl.secretbox",
			Language:    rules.LangGo,
			Pattern:     `secretbox\.Seal\s*\(`,
			ObjectType:  "",
			MethodName:  "secretbox.Seal",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "NaCl secretbox authenticated symmetric encryption (golang.org/x/crypto/nacl/secretbox; XSalsa20+Poly1305 AEAD)",
		},
		{
			ID:          "go.crypto.nacl.box",
			Language:    rules.LangGo,
			Pattern:     `box\.Seal\s*\(`,
			ObjectType:  "",
			MethodName:  "box.Seal",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "NaCl box public-key authenticated encryption (golang.org/x/crypto/nacl/box; Curve25519+XSalsa20+Poly1305)",
		},
		{
			ID:          "go.filepath.localize",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Localize\s*\(`,
			ObjectType:  "",
			MethodName:  "filepath.Localize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "filepath.Localize converts a forward-slash path to a system-local path, rejecting traversal and absolute paths (Go 1.23+, CWE-22 protection)",
		},
		{
			ID:          "go.safehtml.htmlescaped",
			Language:    rules.LangGo,
			Pattern:     `safehtml\.HTMLEscaped\s*\(`,
			ObjectType:  "",
			MethodName:  "safehtml.HTMLEscaped",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Google safehtml HTML entity escaping (github.com/google/safehtml; typed-string XSS protection)",
		},
		{
			ID:          "go.safehtml.urlsanitized",
			Language:    rules.LangGo,
			Pattern:     `safehtml\.URLSanitized\s*\(`,
			ObjectType:  "",
			MethodName:  "safehtml.URLSanitized",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "safehtml.URLSanitized(url) — scheme-allowlist URL sanitizer (github.com/google/safehtml); permits only http/https/ftp/mailto/relative/media-data URLs and replaces dangerous schemes (javascript:, vbscript:, data:text/html, file:) with InnocuousURL, preventing XSS when the URL is placed in an href/src attribute (CWE-79)",
		},
		{
			ID:          "go.safehtml.urlsetsanitized",
			Language:    rules.LangGo,
			Pattern:     `safehtml\.URLSetSanitized\s*\(`,
			ObjectType:  "",
			MethodName:  "safehtml.URLSetSanitized",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "safehtml.URLSetSanitized(srcset) — vets each URL substring of an HTML srcset value via the same scheme allowlist as URLSanitized (github.com/google/safehtml), neutralizing dangerous-scheme XSS in <img/source srcset> attributes (CWE-79)",
		},
		// IDN / hostname normalization: convert internationalized domain names to
		// ASCII Punycode form, which neutralizes Unicode homograph attacks against
		// host allowlists (CWE-1007) and strips control bytes that would otherwise
		// reach SSRF, redirect, log, and header sinks.
		{
			ID:          "go.idna.toascii",
			Language:    rules.LangGo,
			Pattern:     `idna\.ToASCII\s*\(`,
			ObjectType:  "",
			MethodName:  "idna.ToASCII",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkLog, taint.SnkHeader},
			Description: "idna.ToASCII converts IDN hostnames to ASCII Punycode form (golang.org/x/net/idna), neutralizing homograph attacks before host allowlist checks",
		},
		// Strict URL parsing: net/url.ParseRequestURI rejects relative references
		// and requires an absolute URI, which is stronger than url.Parse for SSRF
		// and open-redirect prevention.
		{
			ID:          "go.url.parserequesturi",
			Language:    rules.LangGo,
			Pattern:     `url\.ParseRequestURI\s*\(`,
			ObjectType:  "",
			MethodName:  "url.ParseRequestURI",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "url.ParseRequestURI strictly validates an absolute URI (rejects relative references), enabling subsequent hostname/scheme allowlist checks (SSRF prevention)",
		},
		// Validated host:port parsing via net/netip; rejects malformed addresses
		// that would otherwise reach SSRF sinks.
		{
			ID:          "go.netip.parseaddrport",
			Language:    rules.LangGo,
			Pattern:     `netip\.ParseAddrPort\s*\(`,
			ObjectType:  "",
			MethodName:  "netip.ParseAddrPort",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "netip.ParseAddrPort validates ip:port format (Go 1.18+), enabling host/port allowlist checks for SSRF prevention",
		},
		// Email address-list validation per RFC 5322; strips CRLF that would
		// otherwise reach header- or log-injection sinks.
		{
			ID:          "go.mail.parseaddresslist",
			Language:    rules.LangGo,
			Pattern:     `mail\.ParseAddressList\s*\(`,
			ObjectType:  "",
			MethodName:  "mail.ParseAddressList",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "net/mail.ParseAddressList validates a comma-separated address list (rejects malformed/CRLF-bearing entries) for header- and log-injection prevention",
		},
		// strconv.Quote/QuoteToASCII produce a Go-syntax double-quoted string with
		// every non-printable rune escaped, which neutralizes log-injection and
		// header-injection (CRLF, control bytes, BiDi overrides). Output is wrapped
		// in quotes so it is appropriate for log/header contexts, not raw content.
		{
			ID:          "go.strconv.quote",
			Language:    rules.LangGo,
			Pattern:     `strconv\.Quote\s*\(`,
			ObjectType:  "",
			MethodName:  "strconv.Quote",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "strconv.Quote escapes control bytes, CRLF, and non-printable runes (Go-quoted form) for log- and header-injection prevention",
		},
		{
			ID:          "go.strconv.quotetoascii",
			Language:    rules.LangGo,
			Pattern:     `strconv\.QuoteToASCII\s*\(`,
			ObjectType:  "",
			MethodName:  "strconv.QuoteToASCII",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "strconv.QuoteToASCII escapes all non-ASCII runes plus control bytes (defense-in-depth against BiDi/homograph log-injection)",
		},

		// --- bluemonday HTML sanitizer (additional return-value variants) ---
		{
			ID:          "go.bluemonday.sanitizebytes",
			Language:    rules.LangGo,
			Pattern:     `\.SanitizeBytes\s*\(`,
			ObjectType:  "*bluemonday.Policy",
			MethodName:  "SanitizeBytes",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "bluemonday SanitizeBytes (HTML sanitization for []byte input)",
		},
		{
			ID:          "go.bluemonday.sanitizereader",
			Language:    rules.LangGo,
			Pattern:     `\.SanitizeReader\s*\(`,
			ObjectType:  "*bluemonday.Policy",
			MethodName:  "SanitizeReader",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "bluemonday SanitizeReader (HTML sanitization producing *bytes.Buffer)",
		},

		// --- govalidator (asaskevich/govalidator) return-value sanitizers ---
		{
			ID:          "go.govalidator.safefilename",
			Language:    rules.LangGo,
			Pattern:     `govalidator\.SafeFileName\s*\(`,
			ObjectType:  "",
			MethodName:  "govalidator.SafeFileName",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "govalidator.SafeFileName strips path-traversal and unsafe filename characters",
		},
		{
			ID:          "go.govalidator.normalizeemail",
			Language:    rules.LangGo,
			Pattern:     `govalidator\.NormalizeEmail\s*\(`,
			ObjectType:  "",
			MethodName:  "govalidator.NormalizeEmail",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "govalidator.NormalizeEmail validates RFC 5322 form and lowercases (rejects CRLF/control chars)",
		},
		{
			ID:          "go.govalidator.whitelist",
			Language:    rules.LangGo,
			Pattern:     `govalidator\.WhiteList\s*\(`,
			ObjectType:  "",
			MethodName:  "govalidator.WhiteList",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader},
			Description: "govalidator.WhiteList retains only whitelisted character classes from the input",
		},
		{
			ID:          "go.govalidator.blacklist",
			Language:    rules.LangGo,
			Pattern:     `govalidator\.BlackList\s*\(`,
			ObjectType:  "",
			MethodName:  "govalidator.BlackList",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader},
			Description: "govalidator.BlackList strips blacklisted character classes from the input",
		},
		{
			ID:          "go.govalidator.striplow",
			Language:    rules.LangGo,
			Pattern:     `govalidator\.StripLow\s*\(`,
			ObjectType:  "",
			MethodName:  "govalidator.StripLow",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader, taint.SnkCommand},
			Description: "govalidator.StripLow removes ASCII control characters (CRLF/log-injection mitigation)",
		},

		// --- NoSQL sanitizers (CWE-943) ---
		{
			ID:          "go.bson.objectid.from_hex",
			Language:    rules.LangGo,
			Pattern:     `primitive\.ObjectIDFromHex\s*\(`,
			ObjectType:  "go.mongodb.org/mongo-driver/bson/primitive",
			MethodName:  "ObjectIDFromHex",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "primitive.ObjectIDFromHex(s) — validates and parses a 24-hex-char string into an ObjectID; rejects operator-injection payloads (CWE-943)",
		},
		{
			ID:          "go.bson.m_d",
			Language:    rules.LangGo,
			Pattern:     `\bbson\.M\s*\{|\bbson\.D\s*\{`,
			ObjectType:  "go.mongodb.org/mongo-driver/bson",
			MethodName:  "M/D",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson.M / bson.D composite literal — type-safe BSON document construction; values bind as BSON, not string-concatenated",
		},
		{
			ID:          "go.bson.a_e",
			Language:    rules.LangGo,
			Pattern:     `\bbson\.A\s*\{|\bbson\.E\s*\{`,
			ObjectType:  "go.mongodb.org/mongo-driver/bson",
			MethodName:  "A/E",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson.A (array) / bson.E (key/value pair) composite literals — typed BSON array / element constructors; entries bound as BSON values rather than concatenated into a query string",
		},
		{
			ID:          "go.bson.marshal",
			Language:    rules.LangGo,
			Pattern:     `\bbson\.Marshal(?:Extended)?\s*\(|\bbson\.MarshalValue\s*\(`,
			ObjectType:  "go.mongodb.org/mongo-driver/bson",
			MethodName:  "bson.Marshal/MarshalValue/MarshalExtended",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "bson.Marshal / MarshalValue / MarshalExtended — serialises a Go value into typed BSON bytes (each field becomes a typed BSON element, so an operator key cannot be smuggled through a struct field)",
		},
		{
			ID:          "go.mongo.options_typed",
			Language:    rules.LangGo,
			Pattern:     `options\.(?:Find|Update|Aggregate|Delete|Insert|Count|Distinct)\s*\(\s*\)\.Set\w+\s*\(`,
			ObjectType:  "go.mongodb.org/mongo-driver/mongo/options",
			MethodName:  "options.*().Set*",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB driver options.Find/Update/Aggregate/.../Set* builder — type-safe option assembly (no string-concatenated $-prefixed operators)",
		},
		{
			ID:          "go.mongo.filter_eq",
			Language:    rules.LangGo,
			Pattern:     `\bbson\.M\{[^}]*"_id"\s*:`,
			ObjectType:  "bson.M",
			MethodName:  "bson.M (typed _id filter)",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "Filter literal of the form bson.M{\"_id\": value} — binds a single typed equality predicate (operator-keys would require attacker-controlled keys, which a literal does not allow)",
		},
		{
			ID:          "go.mongo.collation_typed",
			Language:    rules.LangGo,
			Pattern:     `&options\.Collation\s*\{`,
			ObjectType:  "go.mongodb.org/mongo-driver/mongo/options",
			MethodName:  "options.Collation",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "Typed options.Collation literal — locale/strength/caseLevel bound as typed struct fields rather than appended to a query string",
		},
		{
			ID:          "go.regexp.quote_meta",
			Language:    rules.LangGo,
			Pattern:     `regexp\.QuoteMeta\s*\(`,
			ObjectType:  "regexp",
			MethodName:  "regexp.QuoteMeta",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "regexp.QuoteMeta — escapes regex metacharacters before embedding user input in a MongoDB $regex filter or a SQL LIKE pattern (prevents broadened-match injection)",
		},

		// --- Upload (CWE-434) — content-type detection + extension allowlist ---
		{
			ID:          "go.http.detect_content_type",
			Language:    rules.LangGo,
			Pattern:     `http\.DetectContentType\s*\(`,
			ObjectType:  "net/http",
			MethodName:  "http.DetectContentType",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "net/http.DetectContentType — sniffs MIME from the first 512 bytes (defends CWE-434 upload when paired with an allowlist)",
		},
		{
			ID:          "go.mimetype.detect",
			Language:    rules.LangGo,
			Pattern:     `mimetype\.Detect(?:Reader|File)?\s*\(`,
			ObjectType:  "github.com/gabriel-vasile/mimetype",
			MethodName:  "mimetype.Detect",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "gabriel-vasile/mimetype Detect / DetectReader / DetectFile — content-based MIME detection for an upload allowlist",
		},
		{
			ID:          "go.filepath.ext",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Ext\s*\(`,
			ObjectType:  "path/filepath",
			MethodName:  "filepath.Ext",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload, taint.SnkFileRead, taint.SnkFileWrite},
			Description: "path/filepath.Ext — extracts a path's extension for an upload-extension allowlist check",
		},
		{
			ID:          "go.mime.parse_media_type",
			Language:    rules.LangGo,
			Pattern:     `mime\.ParseMediaType\s*\(`,
			ObjectType:  "mime",
			MethodName:  "mime.ParseMediaType",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "mime.ParseMediaType — typed Content-Type parser for an upload allowlist",
		},

		// --- CSV (CWE-1236) — formula-prefix escape helpers ---
		{
			ID:          "go.csv.escape_formula",
			Language:    rules.LangGo,
			Pattern:     `\b(?:escapeCsvFormula|sanitizeCsvCell|csvSafeCell|csvEscape)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeCsvFormula",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Custom escapeCsvFormula / sanitizeCsvCell helper — prefixes a single quote when a field starts with =, +, -, @, TAB (defends CSV-formula injection)",
		},
		{
			ID:          "go.csv.always_quote",
			Language:    rules.LangGo,
			Pattern:     `csv\.NewWriter\s*\([^)]*\)(?:\.[A-Z]\w*)?|w\.Comma\s*=\s*[';,]\s*$|UseCRLF\b`,
			ObjectType:  "encoding/csv",
			MethodName:  "csv.Writer (typed)",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "encoding/csv.Writer — fields containing the comma/quote/CR/LF are auto-quoted; sufficient combined with formula-prefix escape to defend CSV-formula injection",
		},

		// --- Header injection (CWE-93 CRLF) — typed Set / strip / canonical helpers ---
		{
			ID:          "go.http.header_set_typed",
			Language:    rules.LangGo,
			Pattern:     `\.Header\(\)\.Set\s*\(|\.Header\(\)\.Add\s*\(|w\.Header\(\)\.Set\s*\(`,
			ObjectType:  "net/http.Header",
			MethodName:  "Header.Set/Add",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "net/http.Header.Set / .Add — rejects header values containing invalid bytes (per RFC 7230 stdlib enforces a no-CR/LF rule on outgoing headers)",
		},
		{
			ID:          "go.strings.replace_crlf",
			Language:    rules.LangGo,
			Pattern:     `strings\.NewReplacer\s*\([^)]*"\\r"[^)]*"\\n"|strings\.ReplaceAll\s*\([^,]+,\s*"[\\\\r\\\\n]"`,
			ObjectType:  "strings",
			MethodName:  "strings.Replace(CRLF)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Manual CR/LF stripping (strings.NewReplacer / strings.ReplaceAll) — defends header / log injection (CWE-93 / CWE-117)",
		},
		{
			ID:          "go.textproto.canonical_mime_header",
			Language:    rules.LangGo,
			Pattern:     `textproto\.CanonicalMIMEHeaderKey\s*\(`,
			ObjectType:  "net/textproto",
			MethodName:  "CanonicalMIMEHeaderKey",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "net/textproto.CanonicalMIMEHeaderKey — normalises a header NAME to canonical form (rejects invalid tokens); restricts attacker-supplied header names to RFC-compliant tokens",
		},

		// --- Eval sanitizers — JSON / govaluate / CEL / typed-coercion ---
		{
			ID:          "go.json.unmarshal_typed",
			Language:    rules.LangGo,
			Pattern:     `json\.Unmarshal\s*\(\s*[^,]+,\s*&\w+\s*\)|json\.NewDecoder\s*\([^)]+\)\.Decode\s*\(`,
			ObjectType:  "encoding/json",
			MethodName:  "json.Unmarshal/Decode",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "encoding/json.Unmarshal / json.Decoder.Decode into a typed Go struct — strict JSON parser (no script execution); safe alternative to ad-hoc text-eval for JSON inputs",
		},
		{
			ID:          "go.govaluate.expression",
			Language:    rules.LangGo,
			Pattern:     `govaluate\.NewEvaluableExpression\s*\(|govaluate\.NewEvaluableExpressionWithFunctions\s*\(`,
			ObjectType:  "github.com/Knetic/govaluate",
			MethodName:  "govaluate.NewEvaluableExpression",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "govaluate NewEvaluableExpression — expression-grammar-restricted evaluator (no host access, only declared functions / variables) — safe replacement for plaintext-eval patterns",
		},
		{
			ID:          "go.cel.compile_program",
			Language:    rules.LangGo,
			Pattern:     `cel\.NewEnv\s*\(|env\.Compile\s*\(|env\.Program\s*\(`,
			ObjectType:  "github.com/google/cel-go/cel",
			MethodName:  "cel.NewEnv/Compile/Program",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Google CEL (Common Expression Language) — typed, sandboxed expression evaluator (no host language access); safe replacement for ad-hoc eval patterns",
		},

		// --- SSRF allowlist primitives (net.IP / netip.Addr predicates) ---
		// These are the Go-stdlib equivalents of the Java InetAddress.isLoopback /
		// isSiteLocal / isLinkLocal denylist checks that the Java sanitizer set
		// already exposes (PR #808). Gitea's repo-migration / webhook / OpenID
		// SSRF CVEs were fixed by exactly this pattern: parse the supplied
		// host, resolve it, then reject loopback / private / link-local /
		// unspecified / multicast addresses before issuing the outbound
		// request. Treat any one of these checks as a sanitizer because the
		// canonical idiom chains them via || in an isPrivate-style helper.
		{
			ID:          "go.net.ip.isloopback",
			Language:    rules.LangGo,
			Pattern:     `\.IsLoopback\s*\(\s*\)`,
			ObjectType:  "net.IP",
			MethodName:  "IsLoopback",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "net.IP.IsLoopback — SSRF guard reject for 127.0.0.0/8 / ::1 (canonical denylist pair with IsPrivate / IsLinkLocalUnicast / IsUnspecified)",
		},
		{
			ID:          "go.net.ip.isprivate",
			Language:    rules.LangGo,
			Pattern:     `\.IsPrivate\s*\(\s*\)`,
			ObjectType:  "net.IP",
			MethodName:  "IsPrivate",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "net.IP.IsPrivate (Go 1.17+) — RFC-1918 IPv4 / IPv6 ULA denylist (SSRF allowlist guard)",
		},
		{
			ID:          "go.net.ip.islinklocal",
			Language:    rules.LangGo,
			Pattern:     `\.IsLinkLocalUnicast\s*\(\s*\)|\.IsLinkLocalMulticast\s*\(\s*\)`,
			ObjectType:  "net.IP",
			MethodName:  "IsLinkLocalUnicast/IsLinkLocalMulticast",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "net.IP.IsLinkLocalUnicast / IsLinkLocalMulticast — denies 169.254.0.0/16 (AWS / cloud-metadata) and fe80::/10 (SSRF guard)",
		},
		{
			ID:          "go.net.ip.isunspecified",
			Language:    rules.LangGo,
			Pattern:     `\.IsUnspecified\s*\(\s*\)`,
			ObjectType:  "net.IP",
			MethodName:  "IsUnspecified",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "net.IP.IsUnspecified — denies 0.0.0.0 / :: wildcards (some servers route to localhost; SSRF guard)",
		},
		{
			ID:          "go.net.ip.ismulticast",
			Language:    rules.LangGo,
			Pattern:     `\.IsMulticast\s*\(\s*\)|\.IsInterfaceLocalMulticast\s*\(\s*\)`,
			ObjectType:  "net.IP",
			MethodName:  "IsMulticast",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "net.IP.IsMulticast / IsInterfaceLocalMulticast — denies 224.0.0.0/4 (alongside IsLoopback / IsPrivate forms a complete denylist)",
		},
		// net/netip variants (Go 1.18+, preferred over net.IP for new code).
		{
			ID:          "go.netip.isglobalunicast",
			Language:    rules.LangGo,
			Pattern:     `\.IsGlobalUnicast\s*\(\s*\)|netip\.Addr.*\.IsValid\s*\(\s*\)`,
			ObjectType:  "netip.Addr",
			MethodName:  "IsGlobalUnicast",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "netip.Addr.IsGlobalUnicast — accepts only routable public addresses (rejects loopback / link-local / multicast / unspecified in one call)",
		},

		// --- Open-redirect guards ---
		{
			ID:          "go.url.isabs",
			Language:    rules.LangGo,
			Pattern:     `\.IsAbs\s*\(\s*\)`,
			ObjectType:  "url.URL",
			MethodName:  "IsAbs",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "url.URL.IsAbs — distinguishes absolute from relative URLs so a redirect target can be required to be relative (defends open redirect)",
		},
		{
			ID:          "go.url.scheme_https_check",
			Language:    rules.LangGo,
			Pattern:     `\.Scheme\s*==\s*"https?"|"https?"\s*==\s*[^.]+\.Scheme`,
			ObjectType:  "url.URL",
			MethodName:  "URL.Scheme (allowlist)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "url.URL.Scheme equality check against http / https — rejects file:// / gopher:// / javascript: (SSRF + open-redirect guard)",
		},

		// --- go-pg safe-identifier quoting (ECL: coverage-breadth) ---
		// pg.Ident / types.Ident quotes a dynamic table/column identifier so it
		// can be interpolated safely into a go-pg query. (NOTE: pg.Safe is the
		// OPPOSITE — a raw-SQL escape hatch with no escaping — so it is NOT
		// listed here.) Pairs with the go.gopg.* sinks above.
		{
			ID:          "go.gopg.ident",
			Language:    rules.LangGo,
			Pattern:     `\bpg\.Ident\s*\(|\btypes\.Ident\s*\(`,
			ObjectType:  "",
			MethodName:  "Ident",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "go-pg pg.Ident/types.Ident quotes a dynamic SQL identifier (table/column name) — safe interpolation into a go-pg query",
		},

		// --- mongo typed-filter / ObjectID parse (ECL: coverage-breadth) ---
		// Parsing user input through primitive.ObjectIDFromHex yields a typed
		// 12-byte ObjectID that cannot carry NoSQL operators ($where/$gt/...),
		// neutralizing operator-injection into a mongo filter or command.
		{
			ID:          "go.mongo.objectid_from_hex",
			Language:    rules.LangGo,
			Pattern:     `primitive\.ObjectIDFromHex\s*\(`,
			ObjectType:  "",
			MethodName:  "ObjectIDFromHex",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "mongo primitive.ObjectIDFromHex parses input into a typed 12-byte ObjectID that cannot carry NoSQL operators (NoSQL-injection guard)",
		},
	}, giteaGoSanitizers()...)
}
