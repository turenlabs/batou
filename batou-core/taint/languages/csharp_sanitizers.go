package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "URL encoding for safe URL construction",
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

		// --- Data annotations validation ---
		{
			ID:          "csharp.dataannotations",
			Language:    rules.LangCSharp,
			Pattern:     `ModelState\.IsValid|TryValidateModel\(`,
			ObjectType:  "ModelStateDictionary",
			MethodName:  "ModelState.IsValid",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite},
			Description: "Model validation via data annotations",
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
			MethodName:  "LdapFilterEncoder.FilterEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP filter encoding to prevent injection",
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
			Pattern:     `Path\.GetFullPath\s*\(.*Path\.Combine`,
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
	}
}
