package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *CSharpCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- Parameterized queries ---
		{
			ID:          "csharp.sql.sqlparameter",
			Language:    rules.LangCSharp,
			Pattern:     `SqlParameter|\.Parameters\.Add|\.Parameters\.AddWithValue`,
			ObjectType:  "SqlCommand",
			MethodName:  "SqlParameter/Parameters.Add",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Parameterized SQL query via SqlParameter",
		},
		{
			ID:          "csharp.ef.fromsqlinterpolated",
			Language:    rules.LangCSharp,
			Pattern:     `\.FromSqlInterpolated\(|\.ExecuteSqlInterpolated\(`,
			ObjectType:  "DbSet/DatabaseFacade",
			MethodName:  "FromSqlInterpolated/ExecuteSqlInterpolated",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Entity Framework interpolated SQL with automatic parameterization",
		},
		{
			ID:          "csharp.npgsql.parameter",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+NpgsqlParameter\s*\(`,
			ObjectType:  "NpgsqlParameter",
			MethodName:  "NpgsqlParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Npgsql parameterized query via NpgsqlParameter",
		},
		{
			ID:          "csharp.mysql.parameter",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+MySqlParameter\s*\(`,
			ObjectType:  "MySqlParameter",
			MethodName:  "MySqlParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MySQL parameterized query via MySqlParameter",
		},
		{
			ID:          "csharp.sqlite.parameter",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+SqliteParameter\s*\(`,
			ObjectType:  "SqliteParameter",
			MethodName:  "SqliteParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite parameterized query via SqliteParameter",
		},
		{
			ID:          "csharp.oracle.parameter",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+OracleParameter\s*\(`,
			ObjectType:  "OracleParameter",
			MethodName:  "OracleParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Oracle parameterized query via OracleParameter",
		},
		{
			ID:          "csharp.mongo.builders.filter",
			Language:    rules.LangCSharp,
			Pattern:     `Builders\s*<\w+>\s*\.Filter\.|FilterDefinitionBuilder`,
			ObjectType:  "FilterDefinitionBuilder",
			MethodName:  "Builders.Filter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MongoDB type-safe filter builder (prevents NoSQL injection)",
		},
		{
			ID:          "csharp.cosmos.querydefinition.withparameter",
			Language:    rules.LangCSharp,
			Pattern:     `\.WithParameter\s*\(`,
			ObjectType:  "QueryDefinition",
			MethodName:  "WithParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Azure Cosmos DB QueryDefinition.WithParameter binds values as parameters (prevents NoSQL injection)",
		},

		// --- HTML encoding / XSS prevention ---
		{
			ID:          "csharp.htmlencoder.encode",
			Language:    rules.LangCSharp,
			Pattern:     `HtmlEncoder\.Default\.Encode\(|HtmlEncoder\.Encode\(`,
			ObjectType:  "System.Text.Encodings.Web.HtmlEncoder",
			MethodName:  "HtmlEncoder.Encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HTML encoding to prevent XSS",
		},
		{
			ID:          "csharp.webutility.htmlencode",
			Language:    rules.LangCSharp,
			Pattern:     `WebUtility\.HtmlEncode\(|HttpUtility\.HtmlEncode\(`,
			ObjectType:  "WebUtility/HttpUtility",
			MethodName:  "HtmlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HTML entity encoding to prevent XSS",
		},
		{
			// Companion entry for HttpUtility.HtmlEncode — the combined
			// "WebUtility/HttpUtility" ObjectType above only matches the
			// first prefix under receiver-name heuristics.
			ID:          "csharp.httputility.htmlencode",
			Language:    rules.LangCSharp,
			Pattern:     `HttpUtility\.HtmlEncode\(`,
			ObjectType:  "HttpUtility",
			MethodName:  "HtmlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "System.Web.HttpUtility.HtmlEncode HTML entity encoding to prevent XSS",
		},
		{
			ID:          "csharp.antixss.encoder",
			Language:    rules.LangCSharp,
			Pattern:     `AntiXssEncoder\.HtmlEncode\(|Encoder\.HtmlEncode\(|Microsoft\.Security\.Application`,
			ObjectType:  "AntiXssEncoder",
			MethodName:  "AntiXssEncoder.HtmlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "AntiXSS library encoding",
		},

		// --- URL encoding ---
		{
			ID:          "csharp.urlencoder.encode",
			Language:    rules.LangCSharp,
			Pattern:     `UrlEncoder\.Default\.Encode\(|UrlEncoder\.Encode\(`,
			ObjectType:  "System.Text.Encodings.Web.UrlEncoder",
			MethodName:  "UrlEncoder.Encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "URL encoding to prevent injection in URLs",
		},
		{
			ID:          "csharp.webutility.urlencode",
			Language:    rules.LangCSharp,
			Pattern:     `WebUtility\.UrlEncode\(|HttpUtility\.UrlEncode\(|Uri\.EscapeDataString\(`,
			ObjectType:  "WebUtility/HttpUtility",
			MethodName:  "UrlEncode/EscapeDataString",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader},
			Description: "URL encoding for safe URL construction (also prevents header CRLF injection)",
		},

		// --- Path validation ---
		{
			ID:          "csharp.path.getfilename",
			Language:    rules.LangCSharp,
			Pattern:     `Path\.GetFileName\(`,
			ObjectType:  "System.IO.Path",
			MethodName:  "Path.GetFileName",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Extract filename only (strips directory traversal)",
		},

		// --- Integer parsing ---
		{
			ID:          "csharp.int.parse",
			Language:    rules.LangCSharp,
			Pattern:     `int\.Parse\(|int\.TryParse\(|Int32\.Parse\(|Int32\.TryParse\(|Convert\.ToInt32\(`,
			ObjectType:  "System.Int32",
			MethodName:  "int.Parse/TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Integer parsing restricts to numeric values",
		},

		// --- XML safe settings ---
		{
			ID:          "csharp.xml.xmlreadersettings",
			Language:    rules.LangCSharp,
			Pattern:     `DtdProcessing\s*=\s*DtdProcessing\.Prohibit|XmlReaderSettings.*DtdProcessing\.Prohibit`,
			ObjectType:  "XmlReaderSettings",
			MethodName:  "DtdProcessing.Prohibit",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XML reader with DTD processing disabled (XXE prevention)",
		},

		// --- ASP.NET anti-forgery ---
		{
			ID:          "csharp.antiforgery",
			Language:    rules.LangCSharp,
			Pattern:     `\[ValidateAntiForgeryToken\]|\[AutoValidateAntiforgeryToken\]`,
			ObjectType:  "ASP.NET MVC",
			MethodName:  "ValidateAntiForgeryToken",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "ASP.NET anti-forgery token validation (CSRF prevention)",
		},

		// --- URL validation for redirect ---
		{
			ID:          "csharp.url.islocalurl",
			Language:    rules.LangCSharp,
			Pattern:     `Url\.IsLocalUrl\(`,
			ObjectType:  "IUrlHelper",
			MethodName:  "Url.IsLocalUrl",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "URL validation ensuring local-only redirects (open redirect prevention)",
		},
		{
			ID:          "csharp.controller.localredirect",
			Language:    rules.LangCSharp,
			Pattern:     `LocalRedirect\s*\(|LocalRedirectPermanent\s*\(`,
			ObjectType:  "Controller",
			MethodName:  "LocalRedirect/LocalRedirectPermanent",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "ASP.NET LocalRedirect restricts to local URLs (prevents open redirect)",
		},
		{
			ID:          "csharp.results.localredirect",
			Language:    rules.LangCSharp,
			Pattern:     `Results\.LocalRedirect\s*\(`,
			ObjectType:  "Results",
			MethodName:  "Results.LocalRedirect",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "ASP.NET Core Minimal API Results.LocalRedirect rejects external URLs (prevents open redirect)",
		},
		{
			ID:          "csharp.typedresults.localredirect",
			Language:    rules.LangCSharp,
			Pattern:     `TypedResults\.LocalRedirect\s*\(`,
			ObjectType:  "TypedResults",
			MethodName:  "TypedResults.LocalRedirect",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "ASP.NET Core Minimal API TypedResults.LocalRedirect rejects external URLs (prevents open redirect)",
		},

		// --- Trust boundary validation ---
		{
			ID:          "csharp.modelstate.isvalid",
			Language:    rules.LangCSharp,
			Pattern:     `ModelState\.IsValid|TryValidateModel\(`,
			ObjectType:  "ModelStateDictionary",
			MethodName:  "ModelState.IsValid/TryValidateModel",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Model validation before storing in session/TempData (trust boundary protection)",
		},

		// --- Cryptographic sanitizers ---
		{
			ID:          "csharp.crypto.rfc2898",
			Language:    rules.LangCSharp,
			Pattern:     `Rfc2898DeriveBytes|new\s+Rfc2898DeriveBytes\(`,
			ObjectType:  "System.Security.Cryptography",
			MethodName:  "Rfc2898DeriveBytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 key derivation for secure password storage",
		},
		{
			ID:          "csharp.crypto.passwordhasher",
			Language:    rules.LangCSharp,
			Pattern:     `PasswordHasher.*\.HashPassword\(|PasswordHasher.*\.VerifyHashedPassword\(`,
			ObjectType:  "IPasswordHasher",
			MethodName:  "PasswordHasher.HashPassword",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "ASP.NET Identity password hasher (secure hashing)",
		},
		// --- JSON safe deserialization ---
		{
			ID:          "csharp.json.typenamehandling.none",
			Language:    rules.LangCSharp,
			Pattern:     `TypeNameHandling\s*=\s*TypeNameHandling\.None`,
			ObjectType:  "JsonSerializerSettings",
			MethodName:  "TypeNameHandling.None",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "JSON deserialization with type name handling disabled (safe)",
		},

		// --- XPath safe usage ---
		{
			ID:          "csharp.xpath.compiled",
			Language:    rules.LangCSharp,
			Pattern:     `XPathExpression\.Compile\s*\(|XPathNavigator\.Compile\s*\(`,
			ObjectType:  "XPathExpression",
			MethodName:  "XPathExpression.Compile",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Pre-compiled XPath expression",
		},
		{
			ID:          "csharp.xmlconvert.encodelocalname",
			Language:    rules.LangCSharp,
			Pattern:     `XmlConvert\.EncodeLocalName\s*\(|XmlConvert\.EncodeName\s*\(`,
			ObjectType:  "System.Xml.XmlConvert",
			MethodName:  "XmlConvert.EncodeLocalName/EncodeName",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XmlConvert name encoding neutralizes XPath injection by escaping special characters",
		},

		// --- Regex timeout ---
		{
			ID:          "csharp.regex.timeout",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+Regex\s*\([^)]+,\s*RegexOptions\.[^)]*,\s*TimeSpan`,
			ObjectType:  "Regex",
			MethodName:  "Regex with timeout",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Regex with timeout prevents ReDoS",
		},

		// --- Path validation ---
		{
			ID:          "csharp.path.getfullpath",
			Language:    rules.LangCSharp,
			Pattern:     `Path\.GetFullPath\s*\(`,
			ObjectType:  "System.IO.Path",
			MethodName:  "Path.GetFullPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Full path resolution for traversal detection",
		},

		// --- Content Security Policy ---
		{
			ID:          "csharp.csp.header",
			Language:    rules.LangCSharp,
			Pattern:     `Content-Security-Policy|ContentSecurityPolicyHeaderValue`,
			ObjectType:  "CSP",
			MethodName:  "Content-Security-Policy",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkHeader},
			Description: "Content Security Policy header for XSS mitigation",
		},

		// --- LDAP filter encoding ---
		{
			ID:          "csharp.ldap.encode",
			Language:    rules.LangCSharp,
			Pattern:     `LdapFilterEncoder\.FilterEncode\s*\(|Encoder\.LdapFilterEncode\s*\(`,
			ObjectType:  "LdapFilterEncoder",
			MethodName:  "LdapFilterEncoder.FilterEncode/Encoder.LdapFilterEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP filter encoding to prevent injection",
		},

		// --- LDAP distinguished name escaping ---
		{
			ID:          "csharp.ldap.escapedistinguishedname",
			Language:    rules.LangCSharp,
			Pattern:     `LdapFilterEncoder\.EscapeDistinguishedName\s*\(|Encoder\.LdapDistinguishedNameEncode\s*\(`,
			ObjectType:  "LdapFilterEncoder",
			MethodName:  "EscapeDistinguishedName/LdapDistinguishedNameEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP distinguished name encoding to prevent LDAP path injection",
		},

		// --- AntiXSS Encoder receiver (System.Web.Security.AntiXss) ---
		// AntiXSS exposes LdapFilterEncode / LdapDistinguishedNameEncode as static
		// methods on the Encoder class. Existing entries above scope ObjectType to
		// "LdapFilterEncoder", which does not match the "Encoder" receiver in the
		// tsflow matcher, so add a parallel entry for the Encoder receiver.
		{
			ID:          "csharp.ldap.encode.antixss",
			Language:    rules.LangCSharp,
			Pattern:     `Encoder\.LdapFilterEncode\s*\(|Encoder\.LdapDistinguishedNameEncode\s*\(`,
			ObjectType:  "Encoder",
			MethodName:  "Encoder.LdapFilterEncode/Encoder.LdapDistinguishedNameEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "AntiXSS Encoder LDAP filter/DN encoding (System.Web.Security.AntiXss)",
		},

		// --- Template sandboxing ---
		{
			ID:          "csharp.fluid.options",
			Language:    rules.LangCSharp,
			Pattern:     `TemplateOptions.*MemberAccessStrategy\s*=\s*new\s+Deny|FluidParser.*MemberAccessStrategy`,
			ObjectType:  "Fluid.TemplateOptions",
			MethodName:  "TemplateOptions.MemberAccessStrategy",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate},
			Description: "Fluid template engine with restricted member access strategy",
		},

		// --- BCrypt hashing ---
		{
			ID:          "csharp.bcrypt.hash",
			Language:    rules.LangCSharp,
			Pattern:     `BCrypt\.Net\.BCrypt\.HashPassword\s*\(|BCrypt\.HashPassword\s*\(`,
			ObjectType:  "BCrypt.Net",
			MethodName:  "BCrypt.HashPassword",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BCrypt password hashing",
		},

		// --- Regex escaping ---
		{
			ID:          "csharp.regex.escape",
			Language:    rules.LangCSharp,
			Pattern:     `Regex\.Escape\s*\(`,
			ObjectType:  "Regex",
			MethodName:  "Escape",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Regex metacharacter escaping (prevents ReDoS and injection)",
		},

		// --- Path normalization ---
		{
			ID:          "csharp.path.getfullpath.normalized",
			Language:    rules.LangCSharp,
			Pattern:     `Path\.GetFullPath\s*\([^;]*Path\.Combine`,
			ObjectType:  "Path",
			MethodName:  "GetFullPath+Combine",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Full path resolution combined with path combination",
		},

		// --- Numeric conversion ---
		{
			ID:          "csharp.double.parse",
			Language:    rules.LangCSharp,
			Pattern:     `double\.Parse\s*\(|float\.Parse\s*\(|decimal\.Parse\s*\(`,
			ObjectType:  "double/float/decimal",
			MethodName:  "Parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Floating-point parsing (restricts to numeric values)",
		},

		// --- Entity Framework Core parameterized queries ---
		{
			ID:          "csharp.efcore.linq",
			Language:    rules.LangCSharp,
			Pattern:     `\.(Where|Select|OrderBy|GroupBy|Join)\(`,
			ObjectType:  "IQueryable",
			MethodName:  "Where/Select/OrderBy/GroupBy/Join",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "LINQ queries are automatically parameterized by EF Core",
		},

		// --- Dapper parameterized queries ---
		{
			ID:          "csharp.dapper.parameterized",
			Language:    rules.LangCSharp,
			Pattern:     `\.(Query|Execute)\([^,]+,\s*new\s*\{`,
			ObjectType:  "IDbConnection (Dapper)",
			MethodName:  "Query/Execute with params",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Dapper query with anonymous object parameters (parameterized)",
		},
		{
			ID:          "csharp.dapper.dynamicparams",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+DynamicParameters\(`,
			ObjectType:  "DynamicParameters",
			MethodName:  "DynamicParameters",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Dapper DynamicParameters binding (parameterized)",
		},

		// --- Safe deserialization ---
		{
			ID:          "csharp.serializationbinder",
			Language:    rules.LangCSharp,
			Pattern:     `SerializationBinder|ISerializationBinder|\.Binder\s*=|KnownTypesBinder`,
			ObjectType:  "SerializationBinder",
			MethodName:  "SerializationBinder/ISerializationBinder",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Custom SerializationBinder restricts allowed types during deserialization",
		},
		{
			ID:          "csharp.json.contractresolver.safe",
			Language:    rules.LangCSharp,
			Pattern:     `TypeNameHandling\s*=\s*TypeNameHandling\.None|SerializationBinder\s*=`,
			ObjectType:  "JsonSerializerSettings",
			MethodName:  "TypeNameHandling.None + Binder",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Safe JSON deserialization settings (TypeNameHandling.None or custom binder)",
		},
		{
			ID:          "csharp.system.text.json",
			Language:    rules.LangCSharp,
			Pattern:     `System\.Text\.Json\.JsonSerializer\.Deserialize|JsonSerializer\.Deserialize<`,
			ObjectType:  "System.Text.Json",
			MethodName:  "System.Text.Json.JsonSerializer",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "System.Text.Json is safe by default (no polymorphic deserialization without explicit opt-in)",
		},

		// --- Assembly loading validation ---
		{
			ID:          "csharp.assembly.strongname",
			Language:    rules.LangCSharp,
			Pattern:     `AssemblyName.*PublicKeyToken|StrongNameSignatureVerification`,
			ObjectType:  "AssemblyName",
			MethodName:  "PublicKeyToken/StrongName",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Assembly strong name validation prevents loading untrusted assemblies",
		},

		// --- Log injection prevention (CWE-117) ---
		{
			ID:          "csharp.serilog.structured",
			Language:    rules.LangCSharp,
			Pattern:     `Log\.(Information|Warning|Error|Debug|Fatal|Verbose)\s*\(\s*"[^"]*\{`,
			ObjectType:  "Serilog.ILogger",
			MethodName:  "Log.Information/Warning/Error",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Serilog structured logging with message template placeholders",
		},
		{
			ID:          "csharp.nlog.structured",
			Language:    rules.LangCSharp,
			Pattern:     `logger\.(Info|Warn|Error|Debug|Trace|Fatal)\s*\(\s*"[^"]*\{`,
			ObjectType:  "NLog.ILogger",
			MethodName:  "logger.Info/Warn/Error",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "NLog structured logging with message template placeholders",
		},
		{
			ID:          "csharp.ilogger.structured",
			Language:    rules.LangCSharp,
			Pattern:     `_logger\.Log(Information|Warning|Error|Debug|Critical)\s*\(\s*"[^"]*\{`,
			ObjectType:  "ILogger",
			MethodName:  "_logger.LogInformation/Warning/Error",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Microsoft.Extensions.Logging structured logging with template placeholders",
		},
		{
			ID:          "csharp.string.replace.crlf",
			Language:    rules.LangCSharp,
			Pattern:     `\.Replace\s*\(\s*"\\r"\s*,|\.Replace\s*\(\s*"\\n"\s*,`,
			ObjectType:  "string",
			MethodName:  "Replace (CRLF removal)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "String CRLF removal to prevent log/header injection",
		},

		// --- SSRF prevention (CWE-918) ---
		{
			ID:          "csharp.uri.trycreate",
			Language:    rules.LangCSharp,
			Pattern:     `Uri\.TryCreate\s*\(`,
			ObjectType:  "System.Uri",
			MethodName:  "Uri.TryCreate",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI validation via TryCreate (validates URL structure)",
		},
		{
			ID:          "csharp.uri.escapedatastring",
			Language:    rules.LangCSharp,
			Pattern:     `Uri\.EscapeDataString\s*\(`,
			ObjectType:  "System.Uri",
			MethodName:  "Uri.EscapeDataString",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI component escaping to prevent URL injection",
		},
		{
			ID:          "csharp.ipaddress.tryparse",
			Language:    rules.LangCSharp,
			Pattern:     `IPAddress\.TryParse\s*\(`,
			ObjectType:  "System.Net.IPAddress",
			MethodName:  "IPAddress.TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address validation for SSRF prevention",
		},

		// --- Deserialization safety ---
		{
			ID:          "csharp.xmldoc.resolver.null",
			Language:    rules.LangCSharp,
			Pattern:     `XmlResolver\s*=\s*null`,
			ObjectType:  "XmlDocument/XmlReaderSettings",
			MethodName:  "XmlResolver = null",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XML resolver disabled to prevent XXE attacks",
		},
		{
			ID:          "csharp.xdocument.parse",
			Language:    rules.LangCSharp,
			Pattern:     `XDocument\.Parse\s*\(|XDocument\.Load\s*\(`,
			ObjectType:  "System.Xml.Linq.XDocument",
			MethodName:  "XDocument.Parse/Load",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XDocument is safe by default (ignores DTDs)",
		},
		{
			ID:          "csharp.jsondocument.parse",
			Language:    rules.LangCSharp,
			Pattern:     `JsonDocument\.Parse\s*\(`,
			ObjectType:  "System.Text.Json.JsonDocument",
			MethodName:  "JsonDocument.Parse",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "JsonDocument safe read-only JSON parsing (no deserialization)",
		},

		// --- JavaScript encoding (XSS in JS contexts) ---
		{
			ID:          "csharp.jsencoder.encode",
			Language:    rules.LangCSharp,
			Pattern:     `JavaScriptEncoder\.Default\.Encode\s*\(|JavaScriptEncoder\.Create\s*\(`,
			ObjectType:  "System.Text.Encodings.Web.JavaScriptEncoder",
			MethodName:  "JavaScriptEncoder.Encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "JavaScript encoding to prevent XSS in JS contexts",
		},

		// --- Type-safe parsing (converts to non-injectable types) ---
		{
			ID:          "csharp.guid.parse",
			Language:    rules.LangCSharp,
			Pattern:     `Guid\.Parse\s*\(|Guid\.TryParse\s*\(`,
			ObjectType:  "System.Guid",
			MethodName:  "Guid.Parse/TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkLDAP},
			Description: "GUID parsing restricts to UUID format (non-injectable)",
		},
		{
			ID:          "csharp.enum.parse",
			Language:    rules.LangCSharp,
			Pattern:     `Enum\.TryParse\s*[<(]|Enum\.Parse\s*[<(]`,
			ObjectType:  "System.Enum",
			MethodName:  "Enum.Parse/TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Enum parsing restricts to predefined values",
		},
		{
			ID:          "csharp.bool.parse",
			Language:    rules.LangCSharp,
			Pattern:     `bool\.Parse\s*\(|bool\.TryParse\s*\(|Boolean\.TryParse\s*\(`,
			ObjectType:  "System.Boolean",
			MethodName:  "bool.Parse/TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Boolean parsing restricts to true/false values",
		},
		{
			ID:          "csharp.datetime.parse",
			Language:    rules.LangCSharp,
			Pattern:     `DateTime\.TryParse\s*\(|DateTime\.Parse\s*\(|DateTimeOffset\.TryParse\s*\(`,
			ObjectType:  "System.DateTime",
			MethodName:  "DateTime.Parse/TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "DateTime parsing restricts to date format (non-injectable)",
		},
		{
			ID:          "csharp.long.parse",
			Language:    rules.LangCSharp,
			Pattern:     `long\.Parse\s*\(|long\.TryParse\s*\(|Int64\.Parse\s*\(|Int64\.TryParse\s*\(`,
			ObjectType:  "System.Int64",
			MethodName:  "long.Parse/TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Long integer parsing restricts to numeric values",
		},

		// --- SecurityElement.Escape for XML ---
		{
			ID:          "csharp.securityelement.escape",
			Language:    rules.LangCSharp,
			Pattern:     `SecurityElement\.Escape\s*\(`,
			ObjectType:  "System.Security.SecurityElement",
			MethodName:  "SecurityElement.Escape",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkXPath},
			Description: "XML special character escaping",
		},

		// --- Path traversal prevention (CWE-22) ---
		{
			ID:          "csharp.path.getfilenamewithoutextension",
			Language:    rules.LangCSharp,
			Pattern:     `Path\.GetFileNameWithoutExtension\s*\(`,
			ObjectType:  "System.IO.Path",
			MethodName:  "Path.GetFileNameWithoutExtension",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Filename stem extraction strips directory components (prevents path traversal)",
		},
		{
			ID:          "csharp.path.getfullpath.startswith",
			Language:    rules.LangCSharp,
			Pattern:     `Path\.GetFullPath\s*\(.*\.StartsWith\s*\(`,
			ObjectType:  "System.IO.Path",
			MethodName:  "Path.GetFullPath().StartsWith()",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Canonical path resolution + directory confinement check (the standard .NET path traversal prevention pattern)",
		},
		// Helper-method shape of the canonical `Path.GetFullPath(p).StartsWith(base)`
		// confinement guard. Many .NET codebases wrap that check in a
		// void-returning guard method that throws when the path escapes the
		// configured base directory, then call it on its own statement line
		// before the file sink:
		//     EnsurePathWithinBaseDir(path);   // throws if path escapes base
		//     return File.OpenRead(path);      // ← path is now confined
		// (bitwarden server's LocalOrganizationReportStorageService.cs is the
		// canonical example). The walker resolves the helper by its
		// security-meaningful name and marks the path argument confined for
		// CWE-22 in place (see processCall's in-place statement-guard block).
		// The names below all encode "ensure / validate this path stays within
		// a base/root/dir" — a strong, security-specific naming convention, not
		// a generic verb. @argpattern additionally requires a base/root/dir
		// confinement token in the call's identifier text so an unrelatedly
		// named guard does not over-suppress. CWE-22 only — confinement says
		// nothing about command/SQL/XSS metacharacters.
		{
			ID:          "csharp.path.confinement.guardhelper",
			Language:    rules.LangCSharp,
			Pattern:     `(?i)(?:Ensure|Validate|Assert|Check|Verify)[A-Za-z]*(?:Path|File)?[A-Za-z]*(?:Within|Inside|Under)[A-Za-z]*(?:Base|Root|Dir)`,
			ObjectType:  "@argpattern",
			MethodName:  "EnsurePathWithinBaseDir/EnsureWithinBaseDir/EnsureWithinBase/EnsurePathWithinBase/EnsureWithinRoot/EnsurePathWithinRoot/EnsureFileWithinBaseDir/ValidatePathWithinBase/ValidatePathWithinRoot/ValidatePathWithinBaseDir/EnsurePathInsideRoot/EnsurePathInsideBaseDir/EnsurePathUnderRoot/AssertPathWithinBase/CheckPathWithinRoot/VerifyPathWithinBaseDir",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path-confinement guard helper (throws/returns when the canonicalized path escapes the configured base/root directory) — the wrapped form of the Path.GetFullPath().StartsWith() check (prevents CWE-22 path traversal)",
		},
		{
			ID:          "csharp.aspnet.physicalfileprovider",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+PhysicalFileProvider\s*\(`,
			ObjectType:  "Microsoft.Extensions.FileProviders.PhysicalFileProvider",
			MethodName:  "PhysicalFileProvider",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead},
			Description: "ASP.NET Core PhysicalFileProvider confines file access to a root directory (prevents path traversal)",
		},

		// --- Trust boundary sanitizers (CWE-501) ---
		{
			ID:          "csharp.fluentvalidation.validate",
			Language:    rules.LangCSharp,
			Pattern:     `\.Validate\s*\(|\.ValidateAsync\s*\(|AbstractValidator\s*<`,
			ObjectType:  "FluentValidation.IValidator",
			MethodName:  "Validate/ValidateAsync",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "FluentValidation input validation before storing in session/cache",
		},
		{
			ID:          "csharp.dataannotations.validator",
			Language:    rules.LangCSharp,
			Pattern:     `Validator\.TryValidateObject\s*\(|Validator\.ValidateObject\s*\(`,
			ObjectType:  "System.ComponentModel.DataAnnotations.Validator",
			MethodName:  "TryValidateObject/ValidateObject",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Data annotations validation before trust boundary crossing",
		},

		// --- Eval / code injection sanitizers (CWE-94/95) ---
		{
			ID:          "csharp.expression.lambda",
			Language:    rules.LangCSharp,
			Pattern:     `Expression\.Lambda\s*[<(]`,
			ObjectType:  "System.Linq.Expressions.Expression",
			MethodName:  "Expression.Lambda",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Expression tree construction (safe alternative to string-based eval — user data flows into values not code structure)",
		},
		{
			ID:          "csharp.dynamicexpresso.interpreter",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+Interpreter\s*\(`,
			ObjectType:  "DynamicExpresso.Interpreter",
			MethodName:  "Interpreter",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "DynamicExpresso interpreter with reflection disabled by default (restricts to registered types)",
		},

		// --- Cryptographic sanitizers (CWE-327/330) ---
		{
			ID:          "csharp.crypto.rng",
			Language:    rules.LangCSharp,
			Pattern:     `RandomNumberGenerator\.GetBytes\s*\(|RandomNumberGenerator\.Create\s*\(|RandomNumberGenerator\.GetInt32\s*\(`,
			ObjectType:  "System.Security.Cryptography.RandomNumberGenerator",
			MethodName:  "RandomNumberGenerator.GetBytes/Create/GetInt32",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random number generation (replaces System.Random)",
		},
		{
			ID:          "csharp.crypto.hmacsha",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+HMACSHA(?:256|384|512)\s*\(|HMACSHA(?:256|384|512)\.HashData\s*\(`,
			ObjectType:  "System.Security.Cryptography.HMACSHA256/384/512",
			MethodName:  "HMACSHA256/384/512",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HMAC-SHA message authentication code for secure signing and verification",
		},
		{
			ID:          "csharp.crypto.keyderivation.pbkdf2",
			Language:    rules.LangCSharp,
			Pattern:     `KeyDerivation\.Pbkdf2\s*\(`,
			ObjectType:  "Microsoft.AspNetCore.Cryptography.KeyDerivation",
			MethodName:  "KeyDerivation.Pbkdf2",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 key derivation via ASP.NET Core (configurable PRF and iteration count)",
		},
		{
			ID:          "csharp.crypto.argon2",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+Argon2(?:id|i|d)\s*\(`,
			ObjectType:  "Konscious.Security.Cryptography.Argon2",
			MethodName:  "Argon2id/Argon2i/Argon2d",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2 memory-hard password hashing (PHC winner, GPU-resistant)",
		},
		{
			ID:          "csharp.crypto.aes",
			Language:    rules.LangCSharp,
			Pattern:     `Aes\.Create\s*\(|new\s+AesGcm\s*\(|new\s+AesCcm\s*\(`,
			ObjectType:  "System.Security.Cryptography.Aes/AesGcm/AesCcm",
			MethodName:  "Aes.Create/AesGcm/AesCcm",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "AES encryption (replaces weak DES/TripleDES/RC2 — AesGcm provides authenticated encryption)",
		},
		{
			ID:          "csharp.crypto.fixedtimeequals",
			Language:    rules.LangCSharp,
			Pattern:     `CryptographicOperations\.FixedTimeEquals\s*\(`,
			ObjectType:  "System.Security.Cryptography.CryptographicOperations",
			MethodName:  "FixedTimeEquals",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Constant-time byte comparison to prevent timing attacks on HMAC/hash verification",
		},

		// --- Log injection sanitizers (CWE-117) ---
		{
			ID:          "csharp.loggermessage.define",
			Language:    rules.LangCSharp,
			Pattern:     `LoggerMessage\.Define\s*[<(]`,
			ObjectType:  "Microsoft.Extensions.Logging.LoggerMessage",
			MethodName:  "LoggerMessage.Define",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Compile-time log message template (user data flows into typed slots, not message structure)",
		},
		{
			ID:          "csharp.loggermessage.attribute",
			Language:    rules.LangCSharp,
			Pattern:     `\[LoggerMessage\s*\(`,
			ObjectType:  "Microsoft.Extensions.Logging.LoggerMessageAttribute",
			MethodName:  "[LoggerMessage]",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Source-generated log message template (.NET 6+ — compile-time safe structured logging)",
		},
		{
			ID:          "csharp.string.replace.newline",
			Language:    rules.LangCSharp,
			Pattern:     `\.Replace\s*\(\s*Environment\.NewLine\s*,`,
			ObjectType:  "string",
			MethodName:  "Replace(Environment.NewLine)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Environment.NewLine removal to prevent log forging and header injection",
		},

		// --- Header injection sanitizers (CWE-113) ---
		{
			ID:          "csharp.contentdisposition.header",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+ContentDispositionHeaderValue\s*\(|ContentDispositionHeaderValue\.Parse\s*\(`,
			ObjectType:  "System.Net.Http.Headers.ContentDispositionHeaderValue",
			MethodName:  "ContentDispositionHeaderValue",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Type-safe Content-Disposition header construction with RFC 5987 encoding (prevents CRLF/quote injection)",
		},

		// --- SSRF sanitizers (CWE-918) ---
		{
			ID:          "csharp.uri.checkhostname",
			Language:    rules.LangCSharp,
			Pattern:     `Uri\.CheckHostName\s*\(`,
			ObjectType:  "System.Uri",
			MethodName:  "Uri.CheckHostName",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Hostname format validation (DNS/IPv4/IPv6 check for SSRF prevention)",
		},
		{
			ID:          "csharp.uri.iswellformed",
			Language:    rules.LangCSharp,
			Pattern:     `Uri\.IsWellFormedUriString\s*\(`,
			ObjectType:  "System.Uri",
			MethodName:  "Uri.IsWellFormedUriString",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "RFC 3986 URL format validation (prevents malformed URL injection)",
		},
		// --- ReDoS prevention (.NET 7+) ---
		{
			ID:          "csharp.regex.nonbacktracking",
			Language:    rules.LangCSharp,
			Pattern:     `RegexOptions\.NonBacktracking`,
			ObjectType:  "System.Text.RegularExpressions.RegexOptions",
			MethodName:  "RegexOptions.NonBacktracking",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: ".NET 7+ non-backtracking regex engine guarantees linear time (prevents ReDoS)",
		},

		// --- ReDoS sanitizers (CWE-1333, SnkRegexDoS category) ---
		// These mirror the SnkEval ReDoS mitigations above but neutralize the
		// dedicated SnkRegexDoS sink (csharp.regex.static.tainted and the
		// constructor sinks when re-categorized). Kept as distinct entries so
		// the SnkEval-targeting entries above retain their exact behaviour.
		//
		// RegexOptions.NonBacktracking selects the .NET 7+ linear-time engine
		// for which catastrophic backtracking is mathematically impossible —
		// a tainted pattern can no longer cause a DoS.
		{
			ID:          "csharp.regex.nonbacktracking.redos",
			Language:    rules.LangCSharp,
			Pattern:     `RegexOptions\.NonBacktracking`,
			ObjectType:  "System.Text.RegularExpressions.RegexOptions",
			MethodName:  "RegexOptions.NonBacktracking",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: ".NET 7+ non-backtracking regex engine guarantees linear-time matching (neutralizes ReDoS on attacker-controlled patterns)",
		},
		// A matchTimeout (TimeSpan) passed to the Regex constructor bounds the
		// time any single match can spend, aborting with RegexMatchTimeoutException
		// before a backtracking pattern can exhaust CPU.
		{
			ID:          "csharp.regex.ctor.timeout.redos",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+Regex\s*\([^)]+,\s*RegexOptions\.[^)]*,\s*TimeSpan`,
			ObjectType:  "System.Text.RegularExpressions.Regex",
			MethodName:  "new Regex(..., TimeSpan)",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Regex constructed with a matchTimeout (TimeSpan) aborts long-running matches, bounding ReDoS impact",
		},
		// Static Regex.* overloads also accept a trailing matchTimeout TimeSpan,
		// e.g. Regex.IsMatch(input, pattern, options, TimeSpan.FromSeconds(2)).
		{
			ID:          "csharp.regex.static.timeout.redos",
			Language:    rules.LangCSharp,
			Pattern:     `\bRegex\.(?:IsMatch|Match|Matches|Replace|Split)\s*\([^;]*,\s*TimeSpan`,
			ObjectType:  "System.Text.RegularExpressions.Regex",
			MethodName:  "Regex.IsMatch/Match/Matches/Replace/Split(..., TimeSpan)",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Static Regex.* call with a trailing matchTimeout (TimeSpan) bounds match time, mitigating ReDoS",
		},
		// Regex.Escape neutralizes every regex metacharacter in user input, so a
		// tainted fragment becomes a literal substring and cannot introduce the
		// nested quantifiers / alternations that drive catastrophic backtracking.
		{
			ID:          "csharp.regex.escape.redos",
			Language:    rules.LangCSharp,
			Pattern:     `Regex\.Escape\s*\(`,
			ObjectType:  "System.Text.RegularExpressions.Regex",
			MethodName:  "Regex.Escape",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Regex.Escape converts user input into a literal pattern fragment (no metacharacters), preventing attacker-crafted backtracking (ReDoS)",
		},

		// --- Reflection type allowlist ---
		{
			ID:          "csharp.type.isassignablefrom",
			Language:    rules.LangCSharp,
			Pattern:     `typeof\s*\([^)]+\)\.IsAssignableFrom\s*\(`,
			ObjectType:  "System.Type",
			MethodName:  "typeof(T).IsAssignableFrom",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Type allowlist check restricts Activator.CreateInstance to types implementing a known interface",
		},

		// --- Cryptographic PRNG (.NET 6+) ---
		{
			ID:          "csharp.crypto.randomnumbergenerator",
			Language:    rules.LangCSharp,
			Pattern:     `RandomNumberGenerator\.(GetBytes|GetInt32|Fill)\s*\(`,
			ObjectType:  "System.Security.Cryptography.RandomNumberGenerator",
			MethodName:  "RandomNumberGenerator.GetBytes/GetInt32/Fill",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random number generation (.NET 6+ static API)",
		},

		// --- HTML sanitization (Ganss.Xss) ---
		{
			ID:          "csharp.ganss.htmlsanitizer",
			Language:    rules.LangCSharp,
			Pattern:     `HtmlSanitizer\s*\(\s*\)\.Sanitize\s*\(|\.Sanitize\s*\(.*HtmlSanitizer`,
			ObjectType:  "Ganss.Xss.HtmlSanitizer",
			MethodName:  "HtmlSanitizer.Sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Ganss.Xss HtmlSanitizer removes dangerous HTML (allowlist-based)",
		},

		// --- FluentValidation ---
		{
			ID:          "csharp.fluentvalidation",
			Language:    rules.LangCSharp,
			Pattern:     `AbstractValidator\s*<|\.RuleFor\s*\(`,
			ObjectType:  "FluentValidation.AbstractValidator",
			MethodName:  "AbstractValidator/RuleFor",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "FluentValidation input validation library",
		},

		// --- Process shell execution bypass ---
		{
			ID:          "csharp.process.useshellexecute.false",
			Language:    rules.LangCSharp,
			Pattern:     `UseShellExecute\s*=\s*false`,
			ObjectType:  "System.Diagnostics.ProcessStartInfo",
			MethodName:  "UseShellExecute = false",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Process.Start without shell bypasses shell metacharacter interpretation",
		},

		// --- Data Protection API (ASP.NET Core) ---
		{
			ID:          "csharp.dataprotection.protect",
			Language:    rules.LangCSharp,
			Pattern:     `\.Protect\s*\(.*IDataProtect|IDataProtector.*\.Protect\s*\(|\.CreateProtector\s*\(`,
			ObjectType:  "Microsoft.AspNetCore.DataProtection.IDataProtector",
			MethodName:  "IDataProtector.Protect/CreateProtector",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Data Protection API encrypts and authenticates data crossing trust boundaries",
		},

		// --- Scriban template sandboxing ---
		{
			ID:          "csharp.scriban.memberfilter",
			Language:    rules.LangCSharp,
			Pattern:     `TemplateContext.*MemberFilter\s*=|MemberFilter\s*=\s*\(`,
			ObjectType:  "Scriban.TemplateContext",
			MethodName:  "TemplateContext.MemberFilter",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate},
			Description: "Scriban template engine with MemberFilter restricts accessible members (sandbox)",
		},

		// --- Safe command argument passing (CWE-78) ---
		{
			ID:          "csharp.processstartinfo.argumentlist",
			Language:    rules.LangCSharp,
			Pattern:     `\.ArgumentList\.Add\s*\(`,
			ObjectType:  "System.Diagnostics.ProcessStartInfo",
			MethodName:  "ArgumentList.Add",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "ProcessStartInfo.ArgumentList passes args without shell interpretation (.NET Core 2.1+)",
		},

		// --- Path validation (CWE-22) ---
		{
			ID:          "csharp.path.getextension",
			Language:    rules.LangCSharp,
			Pattern:     `Path\.GetExtension\s*\(`,
			ObjectType:  "System.IO.Path",
			MethodName:  "Path.GetExtension",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path.GetExtension extracts only the file extension (no directory traversal possible)",
		},
		{
			ID:          "csharp.path.ispathfullyqualified",
			Language:    rules.LangCSharp,
			Pattern:     `Path\.IsPathFullyQualified\s*\(`,
			ObjectType:  "System.IO.Path",
			MethodName:  "Path.IsPathFullyQualified",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path.IsPathFullyQualified validates absolute path format (.NET Core 2.1+)",
		},

		// --- Protocol Buffers safe deserialization (CWE-502) ---
		{
			ID:          "csharp.protobuf.parsefrom",
			Language:    rules.LangCSharp,
			Pattern:     `\.Parser\.ParseFrom\s*\(|Google\.Protobuf\.MessageParser`,
			ObjectType:  "Google.Protobuf.MessageParser",
			MethodName:  "MessageParser.ParseFrom",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Protocol Buffers schema-constrained deserialization (no arbitrary type instantiation)",
		},
		{
			ID:          "csharp.protobufnet.deserialize",
			Language:    rules.LangCSharp,
			Pattern:     `ProtoBuf\.Serializer\.Deserialize\s*[<(]`,
			ObjectType:  "ProtoBuf.Serializer",
			MethodName:  "ProtoBuf.Serializer.Deserialize",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "protobuf-net schema-constrained deserialization (type-safe, no polymorphic gadgets)",
		},

		// --- Base64 encoding (safe output) ---
		{
			ID:          "csharp.convert.tobase64string",
			Language:    rules.LangCSharp,
			Pattern:     `Convert\.ToBase64String\s*\(`,
			ObjectType:  "System.Convert",
			MethodName:  "Convert.ToBase64String",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader, taint.SnkXPath},
			Description: "Base64 encoding produces safe alphanumeric+/= output (no injection metacharacters)",
		},

		// --- Convert.ToXxx numeric / boolean / DateTime coercion ---
		// The csharp.int.parse / csharp.datetime.parse entries list
		// `Convert.ToInt32(` etc. in their regex Pattern, but tsflow ignores
		// the Pattern field and matches on ObjectType+MethodName — so the
		// whole System.Convert coercion family (receiver "Convert", method
		// "ToInt32"/"ToDouble"/...) was never recognised by the structural
		// engine. These entries close that gap. A value coerced to a numeric
		// or boolean type is restricted to digits / sign / decimal point /
		// exponent / "True"|"False" and cannot carry injection metacharacters
		// in any string context, so the coerced result is safe across SQL,
		// command, file-path, HTML, log, header, XPath, and LDAP sinks.
		{
			ID:          "csharp.convert.tointeger",
			Language:    rules.LangCSharp,
			Pattern:     `Convert\.To(Int16|Int32|Int64|UInt16|UInt32|UInt64|Byte|SByte)\s*\(`,
			ObjectType:  "System.Convert",
			MethodName:  "Convert.ToInt16/Convert.ToInt32/Convert.ToInt64/Convert.ToUInt16/Convert.ToUInt32/Convert.ToUInt64/Convert.ToByte/Convert.ToSByte",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader, taint.SnkXPath, taint.SnkLDAP},
			Description: "Convert.ToInt16/32/64/UInt*/Byte coerces input to an integer (digits/sign only, non-injectable)",
		},
		{
			ID:          "csharp.convert.tofloat",
			Language:    rules.LangCSharp,
			Pattern:     `Convert\.To(Double|Single|Decimal)\s*\(`,
			ObjectType:  "System.Convert",
			MethodName:  "Convert.ToDouble/Convert.ToSingle/Convert.ToDecimal",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader, taint.SnkXPath, taint.SnkLDAP},
			Description: "Convert.ToDouble/Single/Decimal coerces input to a floating-point number (non-injectable)",
		},
		{
			ID:          "csharp.convert.toboolean",
			Language:    rules.LangCSharp,
			Pattern:     `Convert\.ToBoolean\s*\(`,
			ObjectType:  "System.Convert",
			MethodName:  "Convert.ToBoolean",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkLog, taint.SnkHeader, taint.SnkXPath, taint.SnkLDAP},
			Description: "Convert.ToBoolean coerces input to True/False (non-injectable)",
		},
		{
			ID:          "csharp.convert.todatetime",
			Language:    rules.LangCSharp,
			Pattern:     `Convert\.ToDateTime\s*\(`,
			ObjectType:  "System.Convert",
			MethodName:  "Convert.ToDateTime",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Convert.ToDateTime coerces input to a DateTime (bounded date format, non-injectable)",
		},

		// --- XPath parameterization via XSLT (CWE-643) ---
		{
			ID:          "csharp.xpath.xsltargumentlist.addparam",
			Language:    rules.LangCSharp,
			Pattern:     `XsltArgumentList.*\.AddParam\s*\(`,
			ObjectType:  "System.Xml.Xsl.XsltArgumentList",
			MethodName:  "XsltArgumentList.AddParam",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XSLT parameter binding prevents XPath injection (values are typed, not interpolated into query)",
		},

		// --- Manual CSRF validation (CWE-352) ---
		{
			ID:          "csharp.antiforgery.validateasync",
			Language:    rules.LangCSharp,
			Pattern:     `\.ValidateRequestAsync\s*\(`,
			ObjectType:  "Microsoft.AspNetCore.Antiforgery.IAntiforgery",
			MethodName:  "IAntiforgery.ValidateRequestAsync",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Manual CSRF token validation via IAntiforgery (for non-MVC endpoints)",
		},

		// --- JWT signature verification (CWE-345 / CWE-347) ---
		// JwtSecurityTokenHandler.ValidateToken verifies the signature, issuer,
		// audience, and lifetime according to TokenValidationParameters and is
		// the recommended way to consume an incoming JWT.
		{
			ID:          "csharp.jwt.handler.validatetoken",
			Language:    rules.LangCSharp,
			Pattern:     `JwtSecurityTokenHandler.*\.ValidateToken\s*\(`,
			ObjectType:  "System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler",
			MethodName:  "ValidateToken",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkTrustBoundary},
			Description: "JwtSecurityTokenHandler.ValidateToken verifies signature/issuer/audience/lifetime against TokenValidationParameters",
		},
		// jose-jwt: Jose.JWT.Decode requires a key and (for asymmetric) an
		// algorithm; the multi-arg overloads perform full signature
		// verification before returning the payload.
		{
			ID:          "csharp.jose.jwt.decode",
			Language:    rules.LangCSharp,
			Pattern:     `Jose\.JWT\.Decode\s*\(`,
			ObjectType:  "Jose.JWT",
			MethodName:  "Decode",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkTrustBoundary},
			Description: "Jose.JWT.Decode(token, key[, algorithm]) verifies JWT signature before returning payload (jose-jwt)",
		},
		// --- Modern auth verification + URL-safe encoding sanitizers ---
		// BCrypt.Net-Next Verify: candidate password is at args[0], so the
		// matcher's args[0] taint check correctly applies the Neutralizes set.
		// Verify performs constant-time comparison internally.
		{
			ID:          "csharp.bcrypt.verify",
			Language:    rules.LangCSharp,
			Pattern:     `BCrypt\.Net\.BCrypt\.Verify\s*\(|BCrypt\.Verify\s*\(`,
			ObjectType:  "BCrypt.Net",
			MethodName:  "BCrypt.Verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BCrypt.Net password verification (constant-time comparison)",
		},
		{
			ID:          "csharp.bcrypt.enhancedverify",
			Language:    rules.LangCSharp,
			Pattern:     `BCrypt\.Net\.BCrypt\.EnhancedVerify\s*\(|BCrypt\.EnhancedVerify\s*\(`,
			ObjectType:  "BCrypt.Net",
			MethodName:  "BCrypt.EnhancedVerify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BCrypt.Net enhanced password verification (SHA-384 pre-hash + constant-time compare)",
		},
		// Microsoft DataProtection family: IDataProtector.Unprotect, MachineKey.Unprotect,
		// and ProtectedData.Unprotect all verify integrity (signature/MAC) before
		// returning the original bytes — tampered/forged input throws CryptographicException.
		// "Unprotect" is unique to DataProtection-family APIs in .NET, so empty
		// ObjectType is safe here (matcher.go warning targets common verbs like query/execute).
		{
			ID:          "csharp.dataprotection.unprotect",
			Language:    rules.LangCSharp,
			Pattern:     `\.Unprotect\s*\(|MachineKey\.Unprotect\s*\(|ProtectedData\.Unprotect\s*\(`,
			ObjectType:  "",
			MethodName:  "Unprotect",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "DataProtection Unprotect (IDataProtector/MachineKey/ProtectedData) verifies signature/MAC and rejects tampered input",
		},
		// MachineKey.Protect (legacy ASP.NET): authenticated encryption — output bytes
		// carry a MAC so the value cannot be tampered with across the trust boundary.
		{
			ID:          "csharp.machinekey.protect",
			Language:    rules.LangCSharp,
			Pattern:     `MachineKey\.Protect\s*\(`,
			ObjectType:  "MachineKey",
			MethodName:  "MachineKey.Protect",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "System.Web.Security.MachineKey.Protect: authenticated encryption for trust-boundary data",
		},
		// ProtectedData.Protect (DPAPI): user/machine-keyed authenticated encryption.
		{
			ID:          "csharp.protecteddata.protect",
			Language:    rules.LangCSharp,
			Pattern:     `ProtectedData\.Protect\s*\(`,
			ObjectType:  "ProtectedData",
			MethodName:  "ProtectedData.Protect",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "System.Security.Cryptography.ProtectedData.Protect (DPAPI): authenticated encryption",
		},
		// Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder.Encode: URL-safe
		// base64 — output is restricted to [A-Za-z0-9_-], so the encoded string
		// cannot inject CRLF (header) or path/query metacharacters (redirect, URL).
		{
			ID:          "csharp.base64urltextencoder.encode",
			Language:    rules.LangCSharp,
			Pattern:     `Base64UrlTextEncoder\.Encode\s*\(`,
			ObjectType:  "Microsoft.AspNetCore.WebUtilities.Base64UrlTextEncoder",
			MethodName:  "Base64UrlTextEncoder.Encode",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHeader, taint.SnkURLFetch},
			Description: "Base64UrlTextEncoder.Encode produces URL-safe base64 (A-Z a-z 0-9 _ -); prevents URL/header injection",
		},
		// Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode: modern
		// .NET 6+ replacement. Same URL-safe alphabet guarantees as above.
		{
			ID:          "csharp.webencoders.base64urlencode",
			Language:    rules.LangCSharp,
			Pattern:     `WebEncoders\.Base64UrlEncode\s*\(`,
			ObjectType:  "Microsoft.AspNetCore.WebUtilities.WebEncoders",
			MethodName:  "WebEncoders.Base64UrlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHeader, taint.SnkURLFetch},
			Description: "WebEncoders.Base64UrlEncode produces URL-safe base64; prevents URL/header injection",
		},

		// --- HTML / URL / JS gap-fill sanitizers (XSS, redirect, SSRF, log/header FP reduction) ---

		// HtmlAgilityPack.HtmlEntity.Entitize: replaces characters with HTML entities
		// (e.g. < -> &lt;, > -> &gt;, & -> &amp;). Static helper from the most widely
		// used HTML parsing library on .NET; output is safe to embed in HTML body /
		// header values.
		{
			ID:          "csharp.htmlagilitypack.htmlentity.entitize",
			Language:    rules.LangCSharp,
			Pattern:     `HtmlEntity\.Entitize\s*\(`,
			ObjectType:  "HtmlAgilityPack.HtmlEntity",
			MethodName:  "Entitize",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkHeader},
			Description: "HtmlAgilityPack HtmlEntity.Entitize escapes HTML metacharacters to entities (XSS-safe)",
		},

		// System.Web.HttpUtility.HtmlAttributeEncode: stricter HTML escaping suited
		// for attribute-context output (escapes &, <, ", and '). Use when user
		// input is interpolated into an HTML attribute value (e.g. <a href="...">).
		{
			ID:          "csharp.httputility.htmlattributeencode",
			Language:    rules.LangCSharp,
			Pattern:     `HttpUtility\.HtmlAttributeEncode\s*\(`,
			ObjectType:  "System.Web.HttpUtility",
			MethodName:  "HtmlAttributeEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "HttpUtility.HtmlAttributeEncode escapes HTML attribute-context metacharacters (&, <, \", ')",
		},

		// System.Web.HttpUtility.JavaScriptStringEncode: escapes characters that are
		// dangerous in a JavaScript string literal (e.g. quotes, backslash, control
		// chars). Output is safe to embed inside a `'...'` or `"..."` JS literal.
		{
			ID:          "csharp.httputility.javascriptstringencode",
			Language:    rules.LangCSharp,
			Pattern:     `HttpUtility\.JavaScriptStringEncode\s*\(`,
			ObjectType:  "System.Web.HttpUtility",
			MethodName:  "JavaScriptStringEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval, taint.SnkHeader},
			Description: "HttpUtility.JavaScriptStringEncode escapes JS string-literal metacharacters (XSS in inline scripts)",
		},

		// System.Web.HttpUtility.UrlEncode: percent-encodes a string for safe use in
		// a URL (legacy System.Web counterpart of System.Net.WebUtility.UrlEncode).
		// Output cannot contain unencoded scheme/path/query separators.
		{
			ID:          "csharp.httputility.urlencode",
			Language:    rules.LangCSharp,
			Pattern:     `HttpUtility\.UrlEncode\s*\(`,
			ObjectType:  "System.Web.HttpUtility",
			MethodName:  "UrlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader},
			Description: "HttpUtility.UrlEncode percent-encodes a string for safe inclusion in URLs (System.Web)",
		},

		// --- AntiXSS context-specific output encoders (CSS / XML) ---
		// Both the standalone AntiXSS library (Microsoft.Security.Application.Encoder)
		// and the System.Web built-in (System.Web.Security.AntiXss.AntiXssEncoder)
		// expose context-aware encoders beyond HtmlEncode. The catalog already models
		// Encoder.HtmlEncode (csharp.antixss.encoder); these fill the CSS- and
		// XML-context gap. Each returns an encoded string safe for its OUTPUT context,
		// so they are return-value sanitizers for SnkHTMLOutput (XSS) only — they do
		// NOT prevent server-side template injection, so SnkTemplate is intentionally
		// excluded. ObjectType is scoped to the encoder class name so a tainted
		// string's same-named method (`userInput.CssEncode()`) is not mis-treated as
		// a sanitizer; companion entries cover the AntiXssEncoder receiver.

		// Encoder.CssEncode / AntiXssEncoder.CssEncode: escapes a string for safe
		// embedding in a CSS context (style block or style attribute), encoding
		// characters that could break out of a CSS value into script context.
		{
			ID:          "csharp.antixss.cssencode",
			Language:    rules.LangCSharp,
			Pattern:     `Encoder\.CssEncode\s*\(|AntiXssEncoder\.CssEncode\s*\(`,
			ObjectType:  "Encoder",
			MethodName:  "CssEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "AntiXSS Encoder.CssEncode escapes input for CSS context (prevents style-context XSS)",
		},
		{
			ID:          "csharp.antixssencoder.cssencode",
			Language:    rules.LangCSharp,
			Pattern:     `AntiXssEncoder\.CssEncode\s*\(`,
			ObjectType:  "AntiXssEncoder",
			MethodName:  "CssEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "System.Web AntiXssEncoder.CssEncode escapes input for CSS context (prevents style-context XSS)",
		},

		// Encoder.XmlEncode / AntiXssEncoder.XmlEncode: encodes XML special
		// characters (&, <, >) so tainted input is safe inside XML/XHTML element
		// content.
		{
			ID:          "csharp.antixss.xmlencode",
			Language:    rules.LangCSharp,
			Pattern:     `Encoder\.XmlEncode\s*\(|AntiXssEncoder\.XmlEncode\s*\(`,
			ObjectType:  "Encoder",
			MethodName:  "XmlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "AntiXSS Encoder.XmlEncode encodes XML element-content metacharacters (prevents XML/XHTML XSS)",
		},
		{
			ID:          "csharp.antixssencoder.xmlencode",
			Language:    rules.LangCSharp,
			Pattern:     `AntiXssEncoder\.XmlEncode\s*\(`,
			ObjectType:  "AntiXssEncoder",
			MethodName:  "XmlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "System.Web AntiXssEncoder.XmlEncode encodes XML element-content metacharacters (prevents XML/XHTML XSS)",
		},

		// Encoder.XmlAttributeEncode / AntiXssEncoder.XmlAttributeEncode: encodes
		// XML special characters plus quotes so tainted input is safe inside an XML
		// attribute value.
		{
			ID:          "csharp.antixss.xmlattributeencode",
			Language:    rules.LangCSharp,
			Pattern:     `Encoder\.XmlAttributeEncode\s*\(|AntiXssEncoder\.XmlAttributeEncode\s*\(`,
			ObjectType:  "Encoder",
			MethodName:  "XmlAttributeEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "AntiXSS Encoder.XmlAttributeEncode encodes XML attribute-context metacharacters incl. quotes (prevents XML attribute XSS)",
		},
		{
			ID:          "csharp.antixssencoder.xmlattributeencode",
			Language:    rules.LangCSharp,
			Pattern:     `AntiXssEncoder\.XmlAttributeEncode\s*\(`,
			ObjectType:  "AntiXssEncoder",
			MethodName:  "XmlAttributeEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "System.Web AntiXssEncoder.XmlAttributeEncode encodes XML attribute-context metacharacters incl. quotes (prevents XML attribute XSS)",
		},

		// System.Globalization.IdnMapping.GetAscii: converts internationalized
		// domain names to their ASCII (Punycode) form. Used to canonicalize a host
		// before SSRF allowlist checks so that homograph / Unicode-confusable hosts
		// cannot bypass validation.
		{
			ID:          "csharp.idnmapping.getascii",
			Language:    rules.LangCSharp,
			Pattern:     `\.GetAscii\s*\(`,
			ObjectType:  "System.Globalization.IdnMapping",
			MethodName:  "GetAscii",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IdnMapping.GetAscii canonicalizes an IDN host to ASCII Punycode (homograph-safe before SSRF allowlist checks)",
		},

		// --- Additional temporal-parse sanitizers (return-value type coercion) ---
		// Each parser throws (Parse/ParseExact) or returns false (TryParse/TryParseExact)
		// on invalid input and yields a strongly-typed value whose toString() is bounded
		// numeric/ISO format (digits, dashes, colons, T, Z, +, dots, slashes, AM/PM)
		// with no characters dangerous to SQL, shell, log, file path, HTML, or redirect
		// contexts. ObjectTypes use canonical CLR names (System.X) per the matcher's
		// last-component receiver heuristic.
		{
			ID:          "csharp.datetime.parseexact",
			Language:    rules.LangCSharp,
			Pattern:     `DateTime\.ParseExact\s*\(|DateTime\.TryParseExact\s*\(`,
			ObjectType:  "System.DateTime",
			MethodName:  "DateTime.ParseExact/TryParseExact",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "DateTime.ParseExact/TryParseExact restricts to a fixed format (non-injectable)",
		},
		{
			ID:          "csharp.datetimeoffset.parse",
			Language:    rules.LangCSharp,
			Pattern:     `DateTimeOffset\.Parse\s*\(|DateTimeOffset\.TryParse\s*\(|DateTimeOffset\.ParseExact\s*\(|DateTimeOffset\.TryParseExact\s*\(`,
			ObjectType:  "System.DateTimeOffset",
			MethodName:  "DateTimeOffset.Parse/TryParse/ParseExact/TryParseExact",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "DateTimeOffset parsing restricts to ISO-8601 date+offset format (non-injectable)",
		},
		{
			ID:          "csharp.dateonly.parse",
			Language:    rules.LangCSharp,
			Pattern:     `DateOnly\.Parse\s*\(|DateOnly\.TryParse\s*\(|DateOnly\.ParseExact\s*\(|DateOnly\.TryParseExact\s*\(`,
			ObjectType:  "System.DateOnly",
			MethodName:  "DateOnly.Parse/TryParse/ParseExact/TryParseExact",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "DateOnly (.NET 6+) parsing restricts to date-only format (non-injectable)",
		},
		{
			ID:          "csharp.timeonly.parse",
			Language:    rules.LangCSharp,
			Pattern:     `TimeOnly\.Parse\s*\(|TimeOnly\.TryParse\s*\(|TimeOnly\.ParseExact\s*\(|TimeOnly\.TryParseExact\s*\(`,
			ObjectType:  "System.TimeOnly",
			MethodName:  "TimeOnly.Parse/TryParse/ParseExact/TryParseExact",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "TimeOnly (.NET 6+) parsing restricts to time-of-day format (non-injectable)",
		},
		{
			ID:          "csharp.timespan.parse",
			Language:    rules.LangCSharp,
			Pattern:     `TimeSpan\.Parse\s*\(|TimeSpan\.TryParse\s*\(|TimeSpan\.ParseExact\s*\(|TimeSpan\.TryParseExact\s*\(`,
			ObjectType:  "System.TimeSpan",
			MethodName:  "TimeSpan.Parse/TryParse/ParseExact/TryParseExact",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "TimeSpan parsing restricts to duration format (non-injectable)",
		},

		// --- NoSQL sanitizers (CWE-943) ---
		{
			ID:          "csharp.mongodb.builders.filter",
			Language:    rules.LangCSharp,
			Pattern:     `Builders<[^>]+>\.Filter\.|Builders\.Filter\.`,
			ObjectType:  "MongoDB.Driver.Builders",
			MethodName:  "Builders.Filter",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "MongoDB.Driver Builders<T>.Filter — type-safe BSON filter builder; values bind as BSON, not string-concatenated into a query",
		},
		{
			ID:          "csharp.bson.objectid.parse",
			Language:    rules.LangCSharp,
			Pattern:     `ObjectId\.(?:Parse|TryParse)\s*\(`,
			ObjectType:  "MongoDB.Bson.ObjectId",
			MethodName:  "Parse/TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "MongoDB.Bson.ObjectId.Parse / TryParse — validates a 24-hex-char string and parses to ObjectId; rejects operator-injection payloads",
		},
		{
			ID:          "csharp.mongodb.builders.update",
			Language:    rules.LangCSharp,
			Pattern:     `Builders<[^>]+>\.Update\.|Builders\.Update\.`,
			ObjectType:  "MongoDB.Driver.Builders",
			MethodName:  "Builders.Update",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB.Driver Builders<T>.Update — type-safe BSON update builder; field paths and values are bound as BSON entries (no string-concatenated $set/$inc operators)",
		},
		{
			ID:          "csharp.mongodb.builders.projection",
			Language:    rules.LangCSharp,
			Pattern:     `Builders<[^>]+>\.Projection\.|Builders\.Projection\.`,
			ObjectType:  "MongoDB.Driver.Builders",
			MethodName:  "Builders.Projection",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB.Driver Builders<T>.Projection — type-safe BSON projection builder; field selection is bound as a typed BSON projection (no $expr smuggling)",
		},
		{
			ID:          "csharp.mongodb.builders.sort",
			Language:    rules.LangCSharp,
			Pattern:     `Builders<[^>]+>\.Sort\.|Builders\.Sort\.`,
			ObjectType:  "MongoDB.Driver.Builders",
			MethodName:  "Builders.Sort",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB.Driver Builders<T>.Sort — type-safe BSON sort definition; field/direction bound as typed BSON entries",
		},
		{
			ID:          "csharp.bson.bsondocument_typed",
			Language:    rules.LangCSharp,
			Pattern:     `new\s+BsonDocument\s*\(`,
			ObjectType:  "BsonDocument",
			MethodName:  "BsonDocument",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB.Bson.BsonDocument constructor — values bound as typed BSON entries (each key/value pair becomes a typed BSON element rather than a query string fragment)",
		},
		{
			ID:          "csharp.mongodb.iqueryable_linq",
			Language:    rules.LangCSharp,
			Pattern:     `\.AsQueryable\s*\(\s*\)\.|\.Where\s*\(\s*\w+\s*=>`,
			ObjectType:  "IQueryable",
			MethodName:  "AsQueryable/Where(lambda)",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB.Driver LINQ provider IQueryable.Where(lambda) — expression tree compiled to a typed BSON filter (no string concatenation, no operator injection)",
		},
		{
			ID:          "csharp.regex.escape.nosql",
			Language:    rules.LangCSharp,
			Pattern:     `Regex\.Escape\s*\(`,
			ObjectType:  "Regex",
			MethodName:  "Regex.Escape",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "System.Text.RegularExpressions.Regex.Escape — escapes regex metacharacters before embedding user input in a MongoDB $regex filter (prevents broadened-match injection)",
		},

		// --- Upload (CWE-434) — content-type / extension allowlist ---
		{
			ID:          "csharp.fileextensions.getextension",
			Language:    rules.LangCSharp,
			Pattern:     `Path\.GetExtension\s*\(`,
			ObjectType:  "System.IO.Path",
			MethodName:  "Path.GetExtension",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload, taint.SnkFileRead, taint.SnkFileWrite},
			Description: "System.IO.Path.GetExtension — extracts a path's extension for an upload-extension allowlist check",
		},
		{
			ID:          "csharp.mimemapping.gettype",
			Language:    rules.LangCSharp,
			Pattern:     `MimeMapping\.GetMimeMapping\s*\(|FileExtensionContentTypeProvider`,
			ObjectType:  "Microsoft.AspNetCore.StaticFiles",
			MethodName:  "MimeMapping.GetMimeMapping",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "ASP.NET Core MimeMapping.GetMimeMapping / FileExtensionContentTypeProvider — typed MIME mapping for an upload allowlist",
		},
		{
			ID:          "csharp.mimedetective.inspect",
			Language:    rules.LangCSharp,
			Pattern:     `MimeDetective\.|FileType\.Inspect\s*\(`,
			ObjectType:  "MimeDetective",
			MethodName:  "MimeDetective.Inspect",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "MimeDetective — content-based MIME detection for an upload allowlist (defends CWE-434)",
		},

		// --- CSV (CWE-1236) — CsvHelper QuoteAllFields / formula-escape helpers ---
		{
			ID:          "csharp.csvhelper.quoteallfields",
			Language:    rules.LangCSharp,
			Pattern:     `ShouldQuote\s*=\s*\(?\s*\(?\s*args\s*\)?\s*=>\s*true|QuoteAllFields\s*=\s*true`,
			ObjectType:  "CsvHelper.Configuration.CsvConfiguration",
			MethodName:  "ShouldQuote=true",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "CsvHelper CsvConfiguration.ShouldQuote = _ => true (or legacy QuoteAllFields=true) — quotes every field, defeating CSV-formula evaluation at write time",
		},
		{
			ID:          "csharp.csv.escape_formula",
			Language:    rules.LangCSharp,
			Pattern:     `\b(?:EscapeCsvFormula|SanitizeCsvCell|SafeCsvField|CsvEscape)\s*\(`,
			ObjectType:  "",
			MethodName:  "EscapeCsvFormula",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Custom EscapeCsvFormula / SanitizeCsvCell helper — prefixes a single quote when a field starts with =, +, -, @, TAB (defends CSV-formula injection)",
		},

		// --- ServiceStack: OrmLite SQL escaping / typed query builders ---
		// OrmLite's dialect helpers escape a value for safe inline use in a SQL
		// fragment (SqlValue/SqlColumn quote+escape identifiers/literals;
		// SqlSpread builds an escaped IN() list). Passing user input through one
		// of these before concatenating it into a SQL string neutralises SQL
		// injection. ObjectType is left on the OrmLite helper type so the entry
		// stays scoped to ServiceStack's API and does not suppress unrelated
		// ".SqlValue(" methods on other receivers.
		{
			ID:          "csharp.servicestack.ormlite.sqlvalue",
			Language:    rules.LangCSharp,
			Pattern:     `\.SqlValue\s*\(|\.SqlColumn\s*\(|\.SqlSpread\s*\(`,
			ObjectType:  "ServiceStack.OrmLite.OrmLiteUtils",
			MethodName:  "SqlValue/SqlColumn/SqlSpread",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ServiceStack OrmLite SqlValue/SqlColumn/SqlSpread — quotes and escapes a value/identifier for safe inline SQL (prevents SQL injection)",
		},
		{
			ID:          "csharp.servicestack.ormlite.sqlverifyfragment",
			Language:    rules.LangCSharp,
			Pattern:     `\.SqlVerifyFragment\s*\(`,
			ObjectType:  "ServiceStack.OrmLite.OrmLiteUtils",
			MethodName:  "SqlVerifyFragment",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ServiceStack OrmLite SqlVerifyFragment — rejects a SQL fragment containing illegal/injection characters (allowlist validation)",
		},
		{
			ID:          "csharp.servicestack.createparam",
			Language:    rules.LangCSharp,
			Pattern:     `\.CreateParam\s*\(`,
			ObjectType:  "ServiceStack.OrmLite.OrmLiteReadApi",
			MethodName:  "CreateParam",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "ServiceStack OrmLite db.CreateParam(name,value) — binds an IDbDataParameter for parameterized SQL (prevents SQL injection)",
		},
	}
}
