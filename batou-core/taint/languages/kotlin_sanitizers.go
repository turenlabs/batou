package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

func (c *KotlinCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- SQL Parameterization ---
		{
			ID:          "kotlin.preparedstatement",
			Language:    rules.LangKotlin,
			Pattern:     `prepareStatement\s*\(|PreparedStatement`,
			ObjectType:  "PreparedStatement",
			MethodName:  "prepareStatement",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Parameterized SQL query via PreparedStatement",
		},
		{
			ID:          "kotlin.android.selectionargs",
			Language:    rules.LangKotlin,
			Pattern:     `rawQuery\s*\([^,]+,\s*arrayOf\s*\(`,
			ObjectType:  "SQLiteDatabase",
			MethodName:  "rawQuery with selectionArgs",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Android rawQuery with parameterized selection args",
		},
		{
			ID:          "kotlin.room.dao",
			Language:    rules.LangKotlin,
			Pattern:     `@(?:Query|Insert|Update|Delete)`,
			ObjectType:  "Room",
			MethodName:  "Room DAO annotation",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Room DAO parameterized queries",
		},
		{
			ID:          "kotlin.exposed.parameterized",
			Language:    rules.LangKotlin,
			Pattern:     `\.select\s*\{|\.selectAll\s*\(|\.where\s*\{`,
			ObjectType:  "Exposed",
			MethodName:  "Exposed DSL query",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Jetbrains Exposed DSL parameterized queries",
		},

		// --- HTML Encoding ---
		{
			ID:          "kotlin.html.escapehtml",
			Language:    rules.LangKotlin,
			Pattern:     `Html\.escapeHtml\s*\(|TextUtils\.htmlEncode\s*\(`,
			ObjectType:  "",
			MethodName:  "Html.escapeHtml/TextUtils.htmlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Android HTML entity escaping",
		},
		{
			ID:          "kotlin.spring.htmlutils",
			Language:    rules.LangKotlin,
			Pattern:     `HtmlUtils\.htmlEscape\s*\(`,
			ObjectType:  "HtmlUtils",
			MethodName:  "htmlEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Spring HTML entity escaping",
		},

		// --- URL Encoding ---
		{
			ID:          "kotlin.urlencoder.encode",
			Language:    rules.LangKotlin,
			Pattern:     `URLEncoder\.encode\s*\(`,
			ObjectType:  "URLEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "URL encoding",
		},

		// --- Input Validation ---
		{
			ID:          "kotlin.regex.matches",
			Language:    rules.LangKotlin,
			Pattern:     `\.matches\s*\(|Regex\s*\(.*\)\.matches`,
			ObjectType:  "Regex",
			MethodName:  "matches",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Regex validation restricts input to safe patterns",
		},
		{
			ID:          "kotlin.require",
			Language:    rules.LangKotlin,
			Pattern:     `require\s*\(|check\s*\(`,
			ObjectType:  "",
			MethodName:  "require/check",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Kotlin precondition check",
		},

		// --- Type Coercion ---
		{
			ID:          "kotlin.toint",
			Language:    rules.LangKotlin,
			Pattern:     `\.toInt\s*\(|\.toLong\s*\(|\.toIntOrNull\s*\(|\.toLongOrNull\s*\(`,
			ObjectType:  "",
			MethodName:  "toInt/toLong",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Integer conversion restricts to numeric values",
		},

		// --- Path Traversal Prevention ---
		{
			ID:          "kotlin.file.name",
			Language:    rules.LangKotlin,
			Pattern:     `\.name\b|File\(.*\)\.name`,
			ObjectType:  "File",
			MethodName:  "name",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract filename only (strips directory components)",
		},
		{
			ID:          "kotlin.path.normalize",
			Language:    rules.LangKotlin,
			Pattern:     `\.normalize\s*\(|\.canonicalPath|\.canonicalFile`,
			ObjectType:  "Path/File",
			MethodName:  "normalize/canonicalPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path normalization prevents traversal",
		},

		// --- Cryptography ---
		{
			ID:          "kotlin.bcrypt",
			Language:    rules.LangKotlin,
			Pattern:     `BCrypt\.hashpw\s*\(|BCryptPasswordEncoder`,
			ObjectType:  "",
			MethodName:  "BCrypt.hashpw",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "bcrypt password hashing",
		},

		// --- Spring Validation ---
		{
			ID:          "kotlin.spring.valid",
			Language:    rules.LangKotlin,
			Pattern:     `@Valid\b|@Validated\b`,
			ObjectType:  "Spring",
			MethodName:  "@Valid/@Validated",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Spring Bean Validation",
		},

		// --- Ktor Input Validation ---
		{
			ID:          "kotlin.ktor.receivewithvalidation",
			Language:    rules.LangKotlin,
			Pattern:     `call\.receive.*\.validate\s*\(|RequestValidationConfig`,
			ObjectType:  "Ktor",
			MethodName:  "receive with validation",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Ktor request validation plugin",
		},

		// --- Android EncryptedSharedPreferences ---
		{
			ID:          "kotlin.android.encryptedsharedprefs",
			Language:    rules.LangKotlin,
			Pattern:     `EncryptedSharedPreferences\.create\s*\(`,
			ObjectType:  "EncryptedSharedPreferences",
			MethodName:  "create",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Android EncryptedSharedPreferences for secure storage",
		},

		// --- OWASP Java encoder ---
		{
			ID:          "kotlin.owasp.encoder",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forHtml\s*\(|Encode\.forJavaScript\s*\(|Encode\.forUriComponent\s*\(`,
			ObjectType:  "OWASP Encoder",
			MethodName:  "Encode.forHtml/forJavaScript",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java encoder for context-aware output encoding",
		},

		// --- Spring SpEL restricted context ---
		{
			ID:          "kotlin.spring.spel.simpleevaluationcontext",
			Language:    rules.LangKotlin,
			Pattern:     `SimpleEvaluationContext\.forReadOnlyDataBinding\s*\(|SimpleEvaluationContext\.forPropertyAccessors\s*\(`,
			ObjectType:  "SimpleEvaluationContext",
			MethodName:  "forReadOnlyDataBinding/forPropertyAccessors",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Spring SimpleEvaluationContext restricts SpEL to safe operations",
		},

		// --- ESAPI SQL encoding ---
		{
			ID:          "kotlin.esapi.encodeforsql",
			Language:    rules.LangKotlin,
			Pattern:     `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForSQL\s*\(|Encoder.*\.encodeForSQL\s*\(`,
			ObjectType:  "ESAPI",
			MethodName:  "encodeForSQL",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "OWASP ESAPI SQL encoding prevents SQL injection",
		},

		// --- LDAP escaping ---
		{
			ID:          "kotlin.ldap.escape",
			Language:    rules.LangKotlin,
			Pattern:     `LdapEncoder\.filterEncode\s*\(|LdapNameBuilder|LdapUtils\.convertBinary`,
			ObjectType:  "LdapEncoder",
			MethodName:  "LdapEncoder.filterEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP filter encoding to prevent injection",
		},

		// --- Log sanitization ---
		{
			ID:          "kotlin.log.sanitize",
			Language:    rules.LangKotlin,
			Pattern:     `\.replace\s*\(\s*"\\n".*""|\.replace\s*\(\s*"\\r".*""`,
			ObjectType:  "",
			MethodName:  "replace(newline)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Log injection prevention via newline removal",
		},

		// --- XPath safe ---
		{
			ID:          "kotlin.xpath.parameterized",
			Language:    rules.LangKotlin,
			Pattern:     `XPathExpression\.evaluate\s*\(|XPathVariableResolver`,
			ObjectType:  "XPath",
			MethodName:  "XPathExpression.evaluate",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Pre-compiled XPath expression with variable resolver",
		},

		// --- Android WebView safe ---
		{
			ID:          "kotlin.android.webview.safebrowsing",
			Language:    rules.LangKotlin,
			Pattern:     `WebSettings.*javaScriptEnabled\s*=\s*false|setJavaScriptEnabled\s*\(\s*false\s*\)`,
			ObjectType:  "WebView",
			MethodName:  "setJavaScriptEnabled(false)",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval},
			Description: "WebView with JavaScript disabled",
		},

		// --- Regex escaping ---
		{
			ID:          "kotlin.regex.escape",
			Language:    rules.LangKotlin,
			Pattern:     `Regex\.escape\s*\(|Pattern\.quote\s*\(`,
			ObjectType:  "Regex",
			MethodName:  "escape/quote",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Regex metacharacter escaping (prevents ReDoS and injection)",
		},

		// --- Numeric conversion ---
		{
			ID:          "kotlin.todouble",
			Language:    rules.LangKotlin,
			Pattern:     `\.toDouble\s*\(|\.toFloat\s*\(|\.toLong\s*\(`,
			ObjectType:  "",
			MethodName:  "toDouble/toFloat/toLong",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Numeric type conversion (restricts to numeric values)",
		},

		// --- Android input validation ---
		{
			ID:          "kotlin.android.uri.parse",
			Language:    rules.LangKotlin,
			Pattern:     `Uri\.parse\s*\(.*\.host|android\.net\.Uri.*\.getHost`,
			ObjectType:  "android.net.Uri",
			MethodName:  "parse.host",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Android URI hostname extraction for domain validation",
		},

		// --- XXE Prevention ---
		{
			ID:          "kotlin.xml.disallow.doctype",
			Language:    rules.LangKotlin,
			Pattern:     `setFeature\s*\(\s*"http://apache\.org/xml/features/disallow-doctype-decl"\s*,\s*true`,
			ObjectType:  "DocumentBuilderFactory/SAXParserFactory",
			MethodName:  "setFeature(disallow-doctype-decl, true)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Disables DTD processing entirely, preventing XXE attacks",
		},
		{
			ID:          "kotlin.xml.disable.external.dtd",
			Language:    rules.LangKotlin,
			Pattern:     `ACCESS_EXTERNAL_DTD.*""`,
			ObjectType:  "XMLConstants",
			MethodName:  "ACCESS_EXTERNAL_DTD = empty",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Restricts external DTD access to prevent XXE",
		},
		{
			ID:          "kotlin.xml.stax.disable.dtd",
			Language:    rules.LangKotlin,
			Pattern:     `XMLInputFactory\.SUPPORT_DTD.*false|IS_SUPPORTING_EXTERNAL_ENTITIES.*false`,
			ObjectType:  "XMLInputFactory",
			MethodName:  "SUPPORT_DTD/IS_SUPPORTING_EXTERNAL_ENTITIES = false",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Disables DTD and external entities in StAX parser",
		},
		{
			ID:          "kotlin.xml.secure.processing",
			Language:    rules.LangKotlin,
			Pattern:     `FEATURE_SECURE_PROCESSING.*true|XMLConstants\.FEATURE_SECURE_PROCESSING`,
			ObjectType:  "TransformerFactory",
			MethodName:  "FEATURE_SECURE_PROCESSING = true",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Enables secure processing mode on XML factories",
		},

		// --- Command Injection Prevention ---
		{
			ID:          "kotlin.processbuilder.list",
			Language:    rules.LangKotlin,
			Pattern:     `ProcessBuilder\s*\(\s*listOf\s*\(`,
			ObjectType:  "ProcessBuilder",
			MethodName:  "ProcessBuilder(listOf(...))",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "ProcessBuilder with list args bypasses shell interpretation",
		},
		{
			ID:          "kotlin.runtime.exec.array",
			Language:    rules.LangKotlin,
			Pattern:     `Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*arrayOf\s*\(`,
			ObjectType:  "Runtime",
			MethodName:  "exec(arrayOf(...))",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Runtime.exec with array args bypasses shell interpretation",
		},
		{
			ID:          "kotlin.commons.exec.commandline",
			Language:    rules.LangKotlin,
			Pattern:     `CommandLine\s*\(\s*[^)]+\)\s*\.addArgument\s*\(`,
			ObjectType:  "CommandLine",
			MethodName:  "CommandLine.addArgument",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Apache Commons Exec CommandLine with individual arguments",
		},

		// --- Deserialization Safety ---
		{
			ID:          "kotlin.objectinputfilter",
			Language:    rules.LangKotlin,
			Pattern:     `ObjectInputFilter\.|setObjectInputFilter\s*\(`,
			ObjectType:  "ObjectInputFilter",
			MethodName:  "ObjectInputFilter",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "JVM ObjectInputFilter restricts deserializable classes (JEP 290)",
		},
		{
			ID:          "kotlin.jackson.defaulttyping.safe",
			Language:    rules.LangKotlin,
			Pattern:     `activateDefaultTyping\s*\([^)]*LaissezFaireSubTypeValidator`,
			ObjectType:  "ObjectMapper",
			MethodName:  "activateDefaultTyping with validator",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Jackson polymorphic deserialization with type validator",
		},
		{
			ID:          "kotlin.kotlinx.serialization.json",
			Language:    rules.LangKotlin,
			Pattern:     `Json\s*\{[^}]*\}\.decodeFromString\s*<`,
			ObjectType:  "kotlinx.serialization",
			MethodName:  "Json{}.decodeFromString<T>",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "kotlinx.serialization with explicit type (no polymorphic gadgets)",
		},

		// --- HTTP Header Injection Prevention ---
		{
			ID:          "kotlin.header.newline.strip",
			Language:    rules.LangKotlin,
			Pattern:     `\.replace\s*\(\s*["']\s*\\[rn].*["']\s*,\s*["']\s*["']\s*\)|\.filter\s*\{\s*it\s*!=\s*'\\[rn]`,
			ObjectType:  "",
			MethodName:  "replace/filter newlines",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Newline removal prevents HTTP header injection (CRLF)",
		},
		{
			ID:          "kotlin.spring.httpheaders",
			Language:    rules.LangKotlin,
			Pattern:     `HttpHeaders\s*\(\s*\)|ResponseEntity\.ok\s*\(\s*\)\s*\.header\s*\(`,
			ObjectType:  "HttpHeaders",
			MethodName:  "HttpHeaders/ResponseEntity.header",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Spring HttpHeaders builder validates header values",
		},
		{
			ID:          "kotlin.ktor.respondtext.contenttype",
			Language:    rules.LangKotlin,
			Pattern:     `call\.respondText\s*\([^)]*ContentType\.|call\.response\.header\s*\(\s*HttpHeaders\.`,
			ObjectType:  "ApplicationCall",
			MethodName:  "respondText with ContentType",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Ktor typed header APIs prevent raw header injection",
		},

		// --- SSRF Prevention ---
		{
			ID:          "kotlin.url.gethost",
			Language:    rules.LangKotlin,
			Pattern:     `URL\s*\([^)]+\)\s*\.host|\.toURL\s*\(\s*\)\s*\.host`,
			ObjectType:  "java.net.URL",
			MethodName:  "URL.host",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL hostname extraction for domain allowlist validation",
		},
		{
			ID:          "kotlin.inetaddress.issitelocal",
			Language:    rules.LangKotlin,
			Pattern:     `InetAddress\.getByName\s*\(.*\.isSiteLocalAddress|\.isLoopbackAddress|\.isLinkLocalAddress`,
			ObjectType:  "InetAddress",
			MethodName:  "isSiteLocalAddress/isLoopbackAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address validation for internal network detection (SSRF prevention)",
		},
		{
			ID:          "kotlin.apache.urlvalidator",
			Language:    rules.LangKotlin,
			Pattern:     `UrlValidator.*\.isValid\s*\(|RegexUrlValidator`,
			ObjectType:  "UrlValidator",
			MethodName:  "UrlValidator.isValid",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Apache Commons URL validation for SSRF prevention",
		},
		{
			ID:          "kotlin.uri.host.check",
			Language:    rules.LangKotlin,
			Pattern:     `URI\s*\([^)]+\)\s*\.host|URI\.create\s*\([^)]+\)\s*\.host`,
			ObjectType:  "java.net.URI",
			MethodName:  "URI.host",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI hostname extraction for domain validation (SSRF prevention)",
		},
		{
			ID:          "kotlin.url.host.allowlist",
			Language:    rules.LangKotlin,
			Pattern:     `URI\(.*\)\.host\s*(?:in|==)|URL\(.*\)\.host\s*(?:in|==)`,
			ObjectType:  "java.net.URI/URL",
			MethodName:  "host in allowlist/==",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "URL host validation against allowlist before fetching",
		},

		// --- Path traversal prevention ---
		{
			ID:          "kotlin.path.startswith",
			Language:    rules.LangKotlin,
			Pattern:     `\.normalize\s*\(\s*\)\s*\.startsWith\s*\(|\.toRealPath\s*\(\s*\)\s*\.startsWith\s*\(`,
			ObjectType:  "java.nio.file.Path",
			MethodName:  "normalize().startsWith(basePath)",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path normalization + base directory containment check",
		},

		// --- Additional HTML encoding ---
		{
			ID:          "kotlin.apache.stringescapeutils.escapehtml",
			Language:    rules.LangKotlin,
			Pattern:     `StringEscapeUtils\.escapeHtml4?\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeHtml4",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text HTML entity escaping",
		},
		{
			ID:          "kotlin.ktor.html.escape",
			Language:    rules.LangKotlin,
			Pattern:     `\.escapeHTML\s*\(|kotlinx\.html.*escape`,
			ObjectType:  "kotlinx.html",
			MethodName:  "escapeHTML",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Ktor/kotlinx.html HTML escaping",
		},

		// --- Additional crypto sanitizers ---
		{
			ID:          "kotlin.crypto.pbkdf2",
			Language:    rules.LangKotlin,
			Pattern:     `PBKDF2WithHmacSHA|PBEKeySpec\s*\(`,
			ObjectType:  "SecretKeyFactory",
			MethodName:  "PBKDF2",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 key derivation function",
		},
		{
			ID:          "kotlin.crypto.securerandom",
			Language:    rules.LangKotlin,
			Pattern:     `SecureRandom\s*\(|SecureRandom\.getInstance`,
			ObjectType:  "SecureRandom",
			MethodName:  "SecureRandom",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Cryptographically secure random number generator",
		},

		// --- Deserialization safety ---
		{
			ID:          "kotlin.jackson.typevalidation",
			Language:    rules.LangKotlin,
			Pattern:     `activateDefaultTyping\s*\(|@JsonTypeInfo`,
			ObjectType:  "ObjectMapper",
			MethodName:  "activateDefaultTyping/@JsonTypeInfo",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Jackson type validation for safe deserialization",
		},

		// --- Trust boundary sanitizers ---
		{
			ID:          "kotlin.session.validate",
			Language:    rules.LangKotlin,
			Pattern:     `\.toInt\s*\(\)|\.toLong\s*\(\)|\.toBoolean\s*\(|Enum\.valueOf\s*\(`,
			ObjectType:  "",
			MethodName:  "type coercion",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Type coercion before storing in session sanitizes trust boundary",
		},
	}
}
