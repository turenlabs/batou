package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
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
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract filename only (strips directory traversal)",
		},

		// --- Integer parsing ---
		{
			ID:          "csharp.int.parse",
			Language:    rules.LangCSharp,
			Pattern:     `int\.Parse\(|int\.TryParse\(|Int32\.Parse\(|Int32\.TryParse\(|Convert\.ToInt32\(`,
			ObjectType:  "System.Int32",
			MethodName:  "int.Parse/TryParse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
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
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
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
	}
}
