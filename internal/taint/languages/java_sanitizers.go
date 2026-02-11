package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

func (javaCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// HTML encoding
		{ID: "java.stringescapeutils.escapehtml4", Language: rules.LangJava, Pattern: `StringEscapeUtils\.escapeHtml4\s*\(`, ObjectType: "StringEscapeUtils", MethodName: "escapeHtml4", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Apache Commons HTML escape"},
		{ID: "java.spring.htmlutils.htmlescape", Language: rules.LangJava, Pattern: `HtmlUtils\.htmlEscape\s*\(`, ObjectType: "HtmlUtils", MethodName: "htmlEscape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Spring HTML escape"},
		{ID: "java.esapi.encodeforhtml", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForHTML\s*\(`, ObjectType: "ESAPI", MethodName: "encodeForHTML", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "ESAPI HTML encoding"},
		{ID: "java.jsoup.clean", Language: rules.LangJava, Pattern: `Jsoup\.clean\s*\(`, ObjectType: "Jsoup", MethodName: "clean", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Jsoup HTML sanitization"},

		// SQL parameterization
		{ID: "java.preparedstatement", Language: rules.LangJava, Pattern: `PreparedStatement|prepareStatement\s*\(`, ObjectType: "PreparedStatement", MethodName: "prepareStatement", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Parameterized SQL via PreparedStatement"},

		// Type coercion
		{ID: "java.integer.parseint", Language: rules.LangJava, Pattern: `Integer\.parseInt\s*\(`, ObjectType: "Integer", MethodName: "parseInt", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer parsing (type coercion)"},
		{ID: "java.long.parselong", Language: rules.LangJava, Pattern: `Long\.parseLong\s*\(`, ObjectType: "Long", MethodName: "parseLong", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Long parsing (type coercion)"},

		// Path traversal
		{ID: "java.filenameutils.getname", Language: rules.LangJava, Pattern: `FilenameUtils\.getName\s*\(`, ObjectType: "FilenameUtils", MethodName: "getName", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite}, Description: "Filename extraction via FilenameUtils"},

		// URL encoding
		{ID: "java.urlencoder.encode", Language: rules.LangJava, Pattern: `URLEncoder\.encode\s*\(`, ObjectType: "URLEncoder", MethodName: "encode", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHTMLOutput}, Description: "URL encoding"},

		// Input validation annotations
		{ID: "java.validation.valid", Language: rules.LangJava, Pattern: `@Valid`, ObjectType: "", MethodName: "@Valid", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Bean validation annotation"},
		{ID: "java.validation.pattern", Language: rules.LangJava, Pattern: `@Pattern`, ObjectType: "", MethodName: "@Pattern", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Pattern validation annotation"},

		// Hibernate parameterized queries
		{ID: "java.hibernate.setparameter", Language: rules.LangJava, Pattern: `\.setParameter\s*\(`, ObjectType: "Query", MethodName: "setParameter", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Hibernate/JPA parameterized query binding"},

		// MyBatis safe parameterization
		{ID: "java.mybatis.parameterized", Language: rules.LangJava, Pattern: `#\{[^}]+\}`, ObjectType: "MyBatis", MethodName: "#{}", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MyBatis #{} parameterized binding (safe alternative to ${})"},

		// OWASP Java Encoder
		{ID: "java.owasp.encode.forhtml", Language: rules.LangJava, Pattern: `Encode\.forHtml\s*\(`, ObjectType: "Encode", MethodName: "forHtml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "OWASP Java Encoder HTML encoding"},
		{ID: "java.owasp.encode.forjavascript", Language: rules.LangJava, Pattern: `Encode\.forJavaScript\s*\(`, ObjectType: "Encode", MethodName: "forJavaScript", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval}, Description: "OWASP Java Encoder JavaScript encoding"},

		// JNDI/LDAP sanitization
		{ID: "java.esapi.encodeforldap", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForLDAP\s*\(`, ObjectType: "ESAPI", MethodName: "encodeForLDAP", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "ESAPI LDAP encoding"},

		// Spring Security CSRF token validation
		{ID: "java.spring.csrf.token", Language: rules.LangJava, Pattern: `CsrfToken`, ObjectType: "CsrfToken", MethodName: "CsrfToken", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery}, Description: "Spring Security CSRF token validation"},

		// Jackson safe deserialization config
		{ID: "java.jackson.activatedefaulttyping.safe", Language: rules.LangJava, Pattern: `activateDefaultTyping\s*\([^)]*LaissezFaireSubTypeValidator`, ObjectType: "ObjectMapper", MethodName: "activateDefaultTyping", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Jackson activateDefaultTyping with validator (safer polymorphic deser)"},

		// Input validation sanitizers (CWE-20)
		{ID: "java.validator.validate", Language: rules.LangJava, Pattern: `validator\.validate\s*\(`, ObjectType: "Validator", MethodName: "validate", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite}, Description: "Bean Validation (JSR-380) validator.validate()"},
		{ID: "java.validation.notnull", Language: rules.LangJava, Pattern: `@NotNull|@NotBlank|@NotEmpty|@Size|@Min|@Max|@Email`, ObjectType: "", MethodName: "@NotNull/@Size/@Min/@Max", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Bean Validation constraint annotations"},
		{ID: "java.spring.validated", Language: rules.LangJava, Pattern: `@Validated`, ObjectType: "Spring", MethodName: "@Validated", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput}, Description: "Spring @Validated annotation for method-level validation"},

		// Crypto / Auth Sanitizers
		{ID: "java.crypto.bcrypt.hashpw", Language: rules.LangJava, Pattern: `BCrypt\.hashpw\s*\(|BCryptPasswordEncoder`, ObjectType: "BCrypt", MethodName: "hashpw", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "BCrypt password hashing (safe password storage)"},
		{ID: "java.crypto.bcrypt.checkpw", Language: rules.LangJava, Pattern: `BCrypt\.checkpw\s*\(|\.matches\s*\(`, ObjectType: "BCrypt", MethodName: "checkpw", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "BCrypt password verification"},
		{ID: "java.crypto.securerandom", Language: rules.LangJava, Pattern: `new\s+SecureRandom\s*\(|SecureRandom\.getInstanceStrong\s*\(`, ObjectType: "SecureRandom", MethodName: "SecureRandom", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Cryptographically secure random number generation"},
		{ID: "java.crypto.messageconstanttime", Language: rules.LangJava, Pattern: `MessageDigest\.isEqual\s*\(`, ObjectType: "MessageDigest", MethodName: "isEqual", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "Constant-time byte array comparison (prevents timing attacks)"},
		{ID: "java.crypto.mac.hmac", Language: rules.LangJava, Pattern: `Mac\.getInstance\s*\(\s*["']HmacSHA`, ObjectType: "Mac", MethodName: "Mac.getInstance(HmacSHA)", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "HMAC-SHA message authentication code"},

		// Infrastructure / Network Sanitizers
		{ID: "java.inetaddress.validate", Language: rules.LangJava, Pattern: `InetAddress\.getByName\s*\(.*\.isSiteLocalAddress\(|\.isLoopbackAddress\(|\.isLinkLocalAddress\(`, ObjectType: "InetAddress", MethodName: "isSiteLocal/isLoopback", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "IP address validation for internal network detection (SSRF prevention)"},
		{ID: "java.apache.urlvalidator", Language: rules.LangJava, Pattern: `UrlValidator.*\.isValid\s*\(|new\s+UrlValidator\s*\(`, ObjectType: "UrlValidator", MethodName: "isValid", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "Apache Commons URL validation (SSRF prevention)"},
		{ID: "java.url.gethost", Language: rules.LangJava, Pattern: `\.getHost\s*\(\s*\)`, ObjectType: "URL", MethodName: "getHost", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL hostname extraction for domain allowlist validation"},
	}
}
