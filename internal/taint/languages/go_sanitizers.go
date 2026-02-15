package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (c *GoCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
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
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkFileWrite},
			Description: "URL path segment escaping",
		},
		{
			ID:          "go.filepath.base",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Base\(`,
			ObjectType:  "",
			MethodName:  "Base",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract base filename (strips directory traversal)",
		},
		{
			ID:          "go.filepath.clean",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Clean\(`,
			ObjectType:  "",
			MethodName:  "Clean",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Filepath cleaning (resolves .., ., double slashes)",
		},
		{
			ID:          "go.strconv.atoi",
			Language:    rules.LangGo,
			Pattern:     `strconv\.Atoi\(`,
			ObjectType:  "",
			MethodName:  "Atoi",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Integer conversion (restricts to numeric values)",
		},
		{
			ID:          "go.strconv.parseint",
			Language:    rules.LangGo,
			Pattern:     `strconv\.ParseInt\(`,
			ObjectType:  "",
			MethodName:  "ParseInt",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
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
			MethodName:  "ReplaceAll (newline strip)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Stripping newlines prevents header injection in SMTP/HTTP",
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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "Gin framework struct binding with validation tags",
		},
		{
			ID:          "go.echo.bind",
			Language:    rules.LangGo,
			Pattern:     `\.Bind\s*\(|echo\.Bind\(`,
			ObjectType:  "echo.Context",
			MethodName:  "Bind",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Echo framework request binding with validation",
		},
		{
			ID:          "go.ozzo.validation",
			Language:    rules.LangGo,
			Pattern:     `validation\.ValidateStruct\(|validation\.Validate\(`,
			ObjectType:  "ozzo-validation",
			MethodName:  "ValidateStruct",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "ozzo-validation struct/field validation",
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
			ID:          "go.filepath.clean",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Clean\(`,
			ObjectType:  "",
			MethodName:  "Clean",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Filepath cleaning (resolves . and .. components)",
		},
		{
			ID:          "go.filepath.abs",
			Language:    rules.LangGo,
			Pattern:     `filepath\.Abs\(`,
			ObjectType:  "",
			MethodName:  "Abs",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Absolute path resolution (anchors path to prevent traversal)",
		},

		// --- Regex validation ---
		{
			ID:          "go.regexp.matchstring",
			Language:    rules.LangGo,
			Pattern:     `regexp\.MatchString\(|\.MatchString\(`,
			ObjectType:  "",
			MethodName:  "MatchString",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
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
	}
}
