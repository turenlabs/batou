package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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

		// --- Type Coercion ---
		{
			ID:          "kotlin.toint",
			Language:    rules.LangKotlin,
			Pattern:     `\.toInt\s*\(|\.toLong\s*\(|\.toIntOrNull\s*\(|\.toLongOrNull\s*\(`,
			ObjectType:  "",
			MethodName:  "toInt/toLong",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Integer conversion restricts to numeric values",
		},

		// --- Path Traversal Prevention ---
		{
			ID:          "kotlin.file.name",
			Language:    rules.LangKotlin,
			Pattern:     `\.name\b|File\(.*\)\.name`,
			ObjectType:  "File",
			MethodName:  "name",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Extract filename only (strips directory components)",
		},
		{
			ID:          "kotlin.path.normalize",
			Language:    rules.LangKotlin,
			Pattern:     `\.normalize\s*\(|\.canonicalPath|\.canonicalFile`,
			ObjectType:  "Path/File",
			MethodName:  "normalize/canonicalPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path normalization prevents traversal",
		},

		// NIO Path.toRealPath (resolves symlinks and normalizes)
		{
			ID:          "kotlin.path.torealpath",
			Language:    rules.LangKotlin,
			Pattern:     `\.toRealPath\s*\(`,
			ObjectType:  "java.nio.file.Path",
			MethodName:  "toRealPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path.toRealPath() resolves symlinks and normalizes (prevents path traversal via symlink)",
		},
		// NIO Path.toAbsolutePath (resolves relative paths for containment validation)
		{
			ID:          "kotlin.path.toabsolutepath",
			Language:    rules.LangKotlin,
			Pattern:     `\.toAbsolutePath\s*\(`,
			ObjectType:  "java.nio.file.Path",
			MethodName:  "toAbsolutePath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path.toAbsolutePath() resolves relative path for containment validation",
		},

		// NIO Path.fileName extraction (strips directory components)
		{
			ID:          "kotlin.path.filename",
			Language:    rules.LangKotlin,
			Pattern:     `\.fileName\b`,
			ObjectType:  "java.nio.file.Path",
			MethodName:  "fileName",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "NIO Path.fileName extracts filename component (strips directory traversal)",
		},
		// Apache Commons IO FilenameUtils.getName (basename extraction)
		{
			ID:          "kotlin.commons.filenameutils.getname",
			Language:    rules.LangKotlin,
			Pattern:     `FilenameUtils\.getName\s*\(`,
			ObjectType:  "org.apache.commons.io.FilenameUtils",
			MethodName:  "getName",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Apache Commons FilenameUtils.getName extracts filename (strips path)",
		},
		// Apache Commons IO FilenameUtils.normalize (path normalization)
		{
			ID:          "kotlin.commons.filenameutils.normalize",
			Language:    rules.LangKotlin,
			Pattern:     `FilenameUtils\.normalize\s*\(`,
			ObjectType:  "org.apache.commons.io.FilenameUtils",
			MethodName:  "normalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Apache Commons FilenameUtils.normalize resolves .. and . components",
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

		// --- Android platform output encoding ---
		{
			ID:          "kotlin.android.databaseutils.sqlescapestring",
			Language:    rules.LangKotlin,
			Pattern:     `DatabaseUtils\.sqlEscapeString\s*\(`,
			ObjectType:  "DatabaseUtils",
			MethodName:  "sqlEscapeString",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Android DatabaseUtils.sqlEscapeString quotes/escapes a string as an SQL literal (single-quote escaped and wrapped) for safe interpolation into SQLiteDatabase queries",
		},
		{
			ID:          "kotlin.android.uri.encode",
			Language:    rules.LangKotlin,
			Pattern:     `Uri\.encode\s*\(`,
			ObjectType:  "android.net.Uri",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Android Uri.encode percent-encodes a string for safe inclusion in a URI component (escapes reserved/unsafe characters)",
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
			ID:          "kotlin.javamail.internetaddress.parse",
			Language:    rules.LangKotlin,
			Pattern:     `InternetAddress\.parse\s*\(|InternetAddress\s*\(`,
			ObjectType:  "InternetAddress",
			MethodName:  "parse/InternetAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "JavaMail InternetAddress.parse/constructor validates RFC 2822 format and rejects CRLF, preventing email header injection",
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
		// Ktor io.ktor.http URL-encoding String extensions (Codecs.kt). These
		// percent-encode a value for safe inclusion in a URL component, defeating
		// injection into a path/query that reaches an open-redirect or an HTML
		// href/src attribute. Same Neutralizes set as kotlin.urlencoder.encode /
		// kotlin.android.uri.encode (HTMLOutput + Redirect). They do NOT defend
		// host-based SSRF (an attacker can encode a malicious host), so SnkURLFetch
		// is intentionally omitted. The tainted value is the call RECEIVER
		// (`tainted.encodeURLParameter()`), resolved via the walker's
		// callReceiverTainted fallback; ObjectType is empty because the receiver is
		// an arbitrary String variable and each method name is Ktor-unique.
		{
			ID:          "kotlin.ktor.url.encodeurlparameter",
			Language:    rules.LangKotlin,
			Pattern:     `\.encodeURLParameter\s*\(`,
			ObjectType:  "",
			MethodName:  "encodeURLParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Ktor String.encodeURLParameter() percent-encodes a value as a URL query-parameter key",
		},
		{
			ID:          "kotlin.ktor.url.encodeurlparametervalue",
			Language:    rules.LangKotlin,
			Pattern:     `\.encodeURLParameterValue\s*\(`,
			ObjectType:  "",
			MethodName:  "encodeURLParameterValue",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Ktor String.encodeURLParameterValue() percent-encodes a value as a URL query-parameter value",
		},
		{
			ID:          "kotlin.ktor.url.encodeurlpath",
			Language:    rules.LangKotlin,
			Pattern:     `\.encodeURLPath\s*\(`,
			ObjectType:  "",
			MethodName:  "encodeURLPath",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Ktor String.encodeURLPath() URL-encodes a value for use in a URL path",
		},
		{
			ID:          "kotlin.ktor.url.encodeurlpathpart",
			Language:    rules.LangKotlin,
			Pattern:     `\.encodeURLPathPart\s*\(`,
			ObjectType:  "",
			MethodName:  "encodeURLPathPart",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Ktor String.encodeURLPathPart() escapes a single URL path segment (encodeSlash=true)",
		},
		{
			ID:          "kotlin.ktor.url.encodeurlquerycomponent",
			Language:    rules.LangKotlin,
			Pattern:     `\.encodeURLQueryComponent\s*\(`,
			ObjectType:  "",
			MethodName:  "encodeURLQueryComponent",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Ktor String.encodeURLQueryComponent() percent-encodes a URL query component per RFC 3986",
		},
		{
			ID:          "kotlin.jsoup.clean",
			Language:    rules.LangKotlin,
			Pattern:     `Jsoup\.clean\s*\(`,
			ObjectType:  "Jsoup",
			MethodName:  "clean",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Jsoup.clean(html, Safelist) strips disallowed tags/attributes (canonical JVM HTML sanitizer)",
		},
		{
			ID:          "kotlin.owasp.htmlsanitizer.policy",
			Language:    rules.LangKotlin,
			Pattern:     `\bpolicy(?:Factory)?\.sanitize\s*\(`,
			ObjectType:  "PolicyFactory",
			MethodName:  "sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java HTML Sanitizer PolicyFactory.sanitize(html) — structural HTML sanitization",
		},
		{
			ID:          "kotlin.owasp.htmlsanitizer.sanitizers",
			Language:    rules.LangKotlin,
			Pattern:     `Sanitizers\.\w+.*\.sanitize\s*\(`,
			ObjectType:  "Sanitizers",
			MethodName:  "sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java HTML Sanitizer prebuilt Sanitizers.{FORMATTING,LINKS,...}.sanitize(html)",
		},
		{
			ID:          "kotlin.guava.htmlescapers",
			Language:    rules.LangKotlin,
			Pattern:     `HtmlEscapers\.htmlEscaper\s*\(\s*\)\s*\.escape\s*\(`,
			ObjectType:  "HtmlEscapers",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Google Guava HtmlEscapers.htmlEscaper().escape() HTML entity escaping",
		},
		{
			ID:          "kotlin.guava.urlescapers",
			Language:    rules.LangKotlin,
			Pattern:     `UrlEscapers\.url(?:PathSegment|FormParameter|Fragment)Escaper\s*\(\s*\)\s*\.escape\s*\(`,
			ObjectType:  "UrlEscapers",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader},
			Description: "Google Guava UrlEscapers.url{Path,Form,Fragment}Escaper().escape() URL component encoding",
		},
		{
			ID:          "kotlin.idn.toascii",
			Language:    rules.LangKotlin,
			Pattern:     `\bIDN\.toASCII\s*\(`,
			ObjectType:  "IDN",
			MethodName:  "toASCII",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "java.net.IDN.toASCII() IDNA host encoding (rejects malformed Unicode hostnames)",
		},
		{
			ID:          "kotlin.apache.stringescapeutils.escapejson",
			Language:    rules.LangKotlin,
			Pattern:     `StringEscapeUtils\.escapeJson\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeJson",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text JSON string escaping (defends XSS in JSON contexts)",
		},
		{
			ID:          "kotlin.apache.stringescapeutils.escapeecmascript",
			Language:    rules.LangKotlin,
			Pattern:     `StringEscapeUtils\.escapeEcmaScript\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeEcmaScript",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text JavaScript string escaping (defends XSS inside <script> blocks)",
		},
		{
			ID:          "kotlin.apache.stringescapeutils.escapexml11",
			Language:    rules.LangKotlin,
			Pattern:     `StringEscapeUtils\.escapeXml(?:10|11)\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeXml11",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text XML 1.0/1.1 character escaping",
		},
		{
			ID:          "kotlin.spring.htmlutils.numericescape",
			Language:    rules.LangKotlin,
			Pattern:     `HtmlUtils\.htmlEscape(?:Hex|Decimal)\s*\(`,
			ObjectType:  "HtmlUtils",
			MethodName:  "htmlEscapeHex/htmlEscapeDecimal",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Spring HtmlUtils numeric (hex/decimal) HTML entity escaping variants",
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

		// --- SnakeYAML safe constructor ---
		{
			ID:          "kotlin.snakeyaml.safeconstructor",
			Language:    rules.LangKotlin,
			Pattern:     `Yaml\s*\(\s*SafeConstructor\s*\(\s*\)\s*\)`,
			ObjectType:  "org.yaml.snakeyaml.Yaml",
			MethodName:  "Yaml(SafeConstructor())",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "SnakeYAML with SafeConstructor restricts to safe types (no arbitrary class instantiation)",
		},

		// --- Kryo class registration ---
		{
			ID:          "kotlin.kryo.setregistrationrequired",
			Language:    rules.LangKotlin,
			Pattern:     `kryo\.setRegistrationRequired\s*\(\s*true\s*\)|kryo\.isRegistrationRequired\s*=\s*true`,
			ObjectType:  "com.esotericsoftware.kryo.Kryo",
			MethodName:  "setRegistrationRequired",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Kryo with registration required prevents arbitrary class deserialization",
		},

		// --- Redirect URL validation ---
		{
			ID:          "kotlin.redirect.startswith",
			Language:    rules.LangKotlin,
			Pattern:     `\.startsWith\s*\(\s*"/"`,
			ObjectType:  "",
			MethodName:  "startsWith(\"/\")",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "Redirect URL validation ensuring relative path (starts with /)",
		},

		// --- Log injection sanitizers (CWE-117) ---
		{
			ID:          "kotlin.log.encode.forjava",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forJava\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forJava",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkEval, taint.SnkHeader},
			Description: "OWASP Java Encoder escapes control characters for safe log/header output",
		},
		{
			ID:          "kotlin.esapi.canonicalize",
			Language:    rules.LangKotlin,
			Pattern:     `ESAPI\.encoder\s*\(\s*\)\s*\.canonicalize\s*\(`,
			ObjectType:  "org.owasp.esapi.ESAPI",
			MethodName:  "canonicalize",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkCommand},
			Description: "ESAPI canonicalize strips dangerous characters including control chars",
		},
		{
			ID:          "kotlin.boolean.parse",
			Language:    rules.LangKotlin,
			Pattern:     `\.toBoolean\s*\(\s*\)|\.toBooleanStrictOrNull\s*\(\s*\)|Boolean\.parseBoolean\s*\(`,
			ObjectType:  "",
			MethodName:  "toBoolean/toBooleanStrictOrNull",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog},
			Description: "Boolean type coercion restricts input to true/false (prevents injection)",
		},

		// --- Trust Boundary Validation ---
		{
			ID:          "kotlin.trustboundary.enum",
			Language:    rules.LangKotlin,
			Pattern:     `enumValueOf\s*<|Enum\.valueOf\s*\(`,
			ObjectType:  "",
			MethodName:  "enumValueOf/Enum.valueOf",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Enum value restriction limits input to known safe values before trust boundary crossing",
		},
		{
			ID:          "kotlin.trustboundary.bean.validation",
			Language:    rules.LangKotlin,
			Pattern:     `@(?:NotNull|NotBlank|NotEmpty|Size|Pattern|Min|Max|Positive|Email)\b`,
			ObjectType:  "jakarta.validation",
			MethodName:  "Bean Validation annotations",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Jakarta Bean Validation annotations enforce constraints before trust boundary crossing",
		},
		{
			ID:          "kotlin.trustboundary.validator.validate",
			Language:    rules.LangKotlin,
			Pattern:     `validator\.validate\s*\(`,
			ObjectType:  "jakarta.validation.Validator",
			MethodName:  "validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Jakarta Validator.validate() programmatic validation before session storage",
		},

		// --- LDAP Injection Prevention ---
		{
			ID:          "kotlin.ldap.unboundid.filter",
			Language:    rules.LangKotlin,
			Pattern:     `Filter\.create(?:Equality|Substring|Presence)Filter\s*\(`,
			ObjectType:  "com.unboundid.ldap.sdk.Filter",
			MethodName:  "createEqualityFilter/createSubstringFilter",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "UnboundID LDAP SDK parameterized filter builder prevents LDAP injection",
		},
		{
			ID:          "kotlin.ldap.spring.query",
			Language:    rules.LangKotlin,
			Pattern:     `LdapQueryBuilder\.query\s*\(\s*\)\s*\.where\s*\(`,
			ObjectType:  "org.springframework.ldap.query.LdapQueryBuilder",
			MethodName:  "query().where()",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Spring LDAP query builder produces parameterized LDAP queries",
		},
		{
			ID:          "kotlin.ldap.ldapname",
			Language:    rules.LangKotlin,
			Pattern:     `\bLdapName\s*\(`,
			ObjectType:  "javax.naming.ldap.LdapName",
			MethodName:  "LdapName",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "javax.naming.ldap.LdapName validates LDAP DN structure during parsing (RFC 2253)",
		},
		{
			ID:          "kotlin.ldap.rdn.escapevalue",
			Language:    rules.LangKotlin,
			Pattern:     `Rdn\.escapeValue\s*\(`,
			ObjectType:  "javax.naming.ldap.Rdn",
			MethodName:  "escapeValue",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "javax.naming.ldap.Rdn.escapeValue() escapes special LDAP DN characters per RFC 2253",
		},

		// --- HTTP Header Injection Prevention (additional) ---
		{
			ID:          "kotlin.spring.responseentity",
			Language:    rules.LangKotlin,
			Pattern:     `ResponseEntity\.(?:ok|status|created|accepted|noContent|badRequest|notFound)\s*\(`,
			ObjectType:  "org.springframework.http.ResponseEntity",
			MethodName:  "ok/status/created/...",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Spring ResponseEntity builder validates header values",
		},

		// --- Cryptography (additional) ---
		{
			ID:          "kotlin.crypto.argon2",
			Language:    rules.LangKotlin,
			Pattern:     `Argon2(?:Factory|PasswordEncoder|Advanced)`,
			ObjectType:  "Argon2",
			MethodName:  "Argon2Factory/Argon2PasswordEncoder",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2 password hashing (memory-hard, recommended for password storage)",
		},
		{
			ID:          "kotlin.crypto.messagedigest.isEqual",
			Language:    rules.LangKotlin,
			Pattern:     `MessageDigest\.isEqual\s*\(`,
			ObjectType:  "java.security.MessageDigest",
			MethodName:  "isEqual",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Constant-time byte comparison prevents timing side-channel attacks",
		},
		{
			ID:          "kotlin.crypto.mac.hmac",
			Language:    rules.LangKotlin,
			Pattern:     `Mac\.getInstance\s*\(\s*["']HmacSHA`,
			ObjectType:  "javax.crypto.Mac",
			MethodName:  "getInstance(HmacSHA...)",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HMAC computation with secure hash algorithm for message authentication",
		},
		{
			ID:          "kotlin.log.jackson.writevalueasstring",
			Language:    rules.LangKotlin,
			Pattern:     `\.writeValueAsString\s*\(`,
			ObjectType:  "",
			MethodName:  "writeValueAsString",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Jackson JSON serialization escapes control characters (\\n → \\\\n) in string values",
		},

		// --- Trust boundary sanitizers (CWE-501) ---
		{
			ID:          "kotlin.trust.bindingresult",
			Language:    rules.LangKotlin,
			Pattern:     `(?:BindingResult|bindingResult)\.hasErrors\s*\(\s*\)`,
			ObjectType:  "org.springframework.validation.BindingResult",
			MethodName:  "hasErrors",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Spring BindingResult validation check before storing user data in session",
		},
		{
			ID:          "kotlin.trust.kotlinx.serialization.decode",
			Language:    rules.LangKotlin,
			Pattern:     `Json\.decodeFromString\s*<\w+>\s*\(`,
			ObjectType:  "Json",
			MethodName:  "decodeFromString",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "kotlinx.serialization type-safe decoding enforces schema validation before session storage",
		},

		// --- Additional log injection sanitizers (CWE-117) ---
		{
			ID:          "kotlin.log.boolean.toboolean",
			Language:    rules.LangKotlin,
			Pattern:     `\.toBoolean\s*\(|\.toBooleanStrictOrNull\s*\(`,
			ObjectType:  "",
			MethodName:  "toBoolean/toBooleanStrictOrNull",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkSQLQuery},
			Description: "Boolean conversion restricts input to true/false (prevents log injection and SQL injection)",
		},

		// --- Additional trust boundary sanitizers (CWE-501) ---
		{
			ID:          "kotlin.trust.spring.validator.validate",
			Language:    rules.LangKotlin,
			Pattern:     `(?:validator|Validator)\.validate\s*\(`,
			ObjectType:  "Validator",
			MethodName:  "validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Spring Validator.validate() enforces constraints before storing data in session",
		},

		// --- Eval / code injection sanitizers (CWE-94) ---
		{
			ID:          "kotlin.eval.graalvm.restricted",
			Language:    rules.LangKotlin,
			Pattern:     `\.allowAllAccess\s*\(\s*false\s*\)|HostAccess\.NONE|HostAccess\.SCOPED`,
			ObjectType:  "org.graalvm.polyglot.Context",
			MethodName:  "allowAllAccess(false)/HostAccess.NONE",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "GraalVM polyglot Context with restricted host access creates secure eval sandbox",
		},
		{
			ID:          "kotlin.eval.jexl.sandbox",
			Language:    rules.LangKotlin,
			Pattern:     `JexlSandbox\s*\(|JexlBuilder\s*\(\s*\)\.sandbox\s*\(`,
			ObjectType:  "org.apache.commons.jexl3.JexlSandbox",
			MethodName:  "JexlSandbox/JexlBuilder.sandbox",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Apache JEXL sandbox restricts expression evaluation to allowlisted classes/methods",
		},

		// --- MongoDB NoSQL injection sanitizers ---
		{
			ID:          "kotlin.mongo.filters.eq",
			Language:    rules.LangKotlin,
			Pattern:     `Filters\.eq\s*\(|Filters\.and\s*\(|Filters\.or\s*\(|Filters\.gt\s*\(|Filters\.lt\s*\(|Filters\.gte\s*\(|Filters\.lte\s*\(|Filters\.in\s*\(`,
			ObjectType:  "Filters",
			MethodName:  "eq/and/or/gt/lt/gte/lte/in",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MongoDB Filters builder methods produce parameterized BSON queries (prevents operator injection)",
		},
		{
			ID:          "kotlin.mongo.criteria.where",
			Language:    rules.LangKotlin,
			Pattern:     `Criteria\.where\s*\(`,
			ObjectType:  "Criteria",
			MethodName:  "where",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Spring Data MongoDB Criteria builder produces parameterized queries",
		},
		{
			ID:          "kotlin.mongo.objectid",
			Language:    rules.LangKotlin,
			Pattern:     `\bObjectId\s*\(`,
			ObjectType:  "ObjectId",
			MethodName:  "ObjectId",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MongoDB ObjectId constructor validates input as 24-char hex string (type coercion)",
		},

		// --- SSRF Prevention (additional — CWE-918) ---
		{
			ID:          "kotlin.uri.getscheme",
			Language:    rules.LangKotlin,
			Pattern:     `\.getScheme\s*\(\s*\)`,
			ObjectType:  "java.net.URI",
			MethodName:  "getScheme",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI scheme extraction for protocol allowlist validation (restricts to http/https)",
		},
		{
			ID:          "kotlin.url.getprotocol",
			Language:    rules.LangKotlin,
			Pattern:     `\.getProtocol\s*\(\s*\)`,
			ObjectType:  "java.net.URL",
			MethodName:  "getProtocol",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL protocol extraction for protocol validation (prevents file://, gopher://, etc.)",
		},
		{
			ID:          "kotlin.uri.getauthority",
			Language:    rules.LangKotlin,
			Pattern:     `\.getAuthority\s*\(\s*\)`,
			ObjectType:  "java.net.URI",
			MethodName:  "getAuthority",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI authority extraction for host validation (SSRF domain allowlist check)",
		},
		{
			ID:          "kotlin.guava.internetdomainname",
			Language:    rules.LangKotlin,
			Pattern:     `InternetDomainName\.from\s*\(`,
			ObjectType:  "com.google.common.net.InternetDomainName",
			MethodName:  "from",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Google Guava domain name validation and parsing (SSRF host validation)",
		},
		{
			ID:          "kotlin.okhttp.interceptor.hostcheck",
			Language:    rules.LangKotlin,
			Pattern:     `\.addInterceptor\s*\(.*\.host\s*\(\s*\)`,
			ObjectType:  "OkHttpClient",
			MethodName:  "addInterceptor(host check)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "OkHttp interceptor validating request host before sending (SSRF prevention)",
		},
		{
			ID:          "kotlin.spring.uricomponentsbuilder",
			Language:    rules.LangKotlin,
			Pattern:     `UriComponentsBuilder\.(fromUriString|fromHttpUrl|newInstance)\s*\(`,
			ObjectType:  "org.springframework.web.util.UriComponentsBuilder",
			MethodName:  "fromUriString/fromHttpUrl/newInstance",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Spring UriComponentsBuilder structured URL construction prevents open redirect/SSRF",
		},
		{
			ID:          "kotlin.owasp.encode.foruri",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forUri\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forUri",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "OWASP Java Encoder URI encoding for safe URL construction",
		},
		{
			ID:          "kotlin.owasp.encode.forhtmlcontent",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forHtmlContent\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forHtmlContent",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder HTML element content encoding (XSS-safe in HTML body context)",
		},
		{
			ID:          "kotlin.owasp.encode.forhtmlattribute",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forHtmlAttribute\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forHtmlAttribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder HTML attribute-value encoding (XSS-safe inside quoted attributes)",
		},
		{
			ID:          "kotlin.owasp.encode.forhtmlunquotedattribute",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forHtmlUnquotedAttribute\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forHtmlUnquotedAttribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder unquoted-attribute encoding (XSS-safe inside unquoted attribute values)",
		},
		{
			ID:          "kotlin.owasp.encode.forjavascriptattribute",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forJavaScriptAttribute\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forJavaScriptAttribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder JavaScript-in-HTML-attribute encoding (e.g., onclick handlers)",
		},
		{
			ID:          "kotlin.owasp.encode.forjavascriptblock",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forJavaScriptBlock\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forJavaScriptBlock",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder JavaScript-in-script-block encoding (XSS-safe inside <script> bodies)",
		},
		{
			ID:          "kotlin.owasp.encode.forcssstring",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forCssString\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forCssString",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder CSS string-literal encoding (XSS-safe inside CSS string contexts)",
		},
		{
			ID:          "kotlin.owasp.encode.forxmlcontent",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forXmlContent\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forXmlContent",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder XML element content encoding (XML/XHTML body context)",
		},
		{
			ID:          "kotlin.owasp.encode.forxmlattribute",
			Language:    rules.LangKotlin,
			Pattern:     `Encode\.forXmlAttribute\s*\(`,
			ObjectType:  "org.owasp.encoder.Encode",
			MethodName:  "forXmlAttribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder XML attribute-value encoding",
		},

		// --- Deserialization Safety (additional — CWE-502) ---
		{
			ID:          "kotlin.xstream.allowtypes",
			Language:    rules.LangKotlin,
			Pattern:     `(?:XStream|xstream)\.(?:allowTypes|setupDefaultSecurity|addPermission)\s*\(`,
			ObjectType:  "com.thoughtworks.xstream.XStream",
			MethodName:  "allowTypes/setupDefaultSecurity/addPermission",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XStream security framework type allowlisting prevents arbitrary class instantiation",
		},

		// --- SQL Injection Prevention (additional — CWE-89) ---
		{
			ID:          "kotlin.hibernate.setparameter",
			Language:    rules.LangKotlin,
			Pattern:     `\.setParameter\s*\(`,
			ObjectType:  "jakarta.persistence.Query",
			MethodName:  "setParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Hibernate/JPA parameterized query binding prevents SQL injection",
		},
		{
			ID:          "kotlin.jooq.dsl",
			Language:    rules.LangKotlin,
			Pattern:     `DSL\.(select|insertInto|update|delete)\s*\(`,
			ObjectType:  "org.jooq.impl.DSL",
			MethodName:  "select/insertInto/update/delete",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "jOOQ DSL type-safe SQL query builder (parameterized)",
		},
		{
			ID:          "kotlin.jooq.param",
			Language:    rules.LangKotlin,
			Pattern:     `DSL\.param\s*\(`,
			ObjectType:  "org.jooq.impl.DSL",
			MethodName:  "param",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "jOOQ DSL.param() parameterized value binding",
		},
		{
			ID:          "kotlin.uuid.fromstring",
			Language:    rules.LangKotlin,
			Pattern:     `UUID\.fromString\s*\(`,
			ObjectType:  "java.util.UUID",
			MethodName:  "fromString",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkSQLQuery},
			Description: "UUID.fromString() validates and restricts input to UUID format (hex+dashes only, no injection possible)",
		},

		// --- java.time temporal parsing (type-coerce sanitizers) ---
		// Each parser throws DateTimeParseException on invalid input and returns a
		// strongly-typed temporal object whose toString() is bounded ISO-8601 format
		// (digits, dashes, colons, T, Z, +, .) with no characters dangerous to SQL,
		// shell, log, file path, HTML, or redirect contexts.
		{
			ID:          "kotlin.time.localdate.parse",
			Language:    rules.LangKotlin,
			Pattern:     `LocalDate\.parse\s*\(`,
			ObjectType:  "java.time.LocalDate",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.LocalDate.parse() restricts input to ISO-8601 date format (YYYY-MM-DD only, no injection)",
		},
		{
			ID:          "kotlin.time.localdatetime.parse",
			Language:    rules.LangKotlin,
			Pattern:     `LocalDateTime\.parse\s*\(`,
			ObjectType:  "java.time.LocalDateTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.LocalDateTime.parse() restricts input to ISO-8601 datetime format (no injection)",
		},
		{
			ID:          "kotlin.time.instant.parse",
			Language:    rules.LangKotlin,
			Pattern:     `Instant\.parse\s*\(`,
			ObjectType:  "java.time.Instant",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.Instant.parse() restricts input to ISO-8601 instant format (no injection)",
		},
		{
			ID:          "kotlin.time.localtime.parse",
			Language:    rules.LangKotlin,
			Pattern:     `LocalTime\.parse\s*\(`,
			ObjectType:  "java.time.LocalTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.LocalTime.parse() restricts input to ISO-8601 time format (no injection)",
		},
		{
			ID:          "kotlin.time.zoneddatetime.parse",
			Language:    rules.LangKotlin,
			Pattern:     `ZonedDateTime\.parse\s*\(`,
			ObjectType:  "java.time.ZonedDateTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.ZonedDateTime.parse() restricts input to ISO-8601 zoned datetime format (no injection)",
		},
		{
			ID:          "kotlin.time.offsetdatetime.parse",
			Language:    rules.LangKotlin,
			Pattern:     `OffsetDateTime\.parse\s*\(`,
			ObjectType:  "java.time.OffsetDateTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.OffsetDateTime.parse() restricts input to ISO-8601 offset datetime format (no injection)",
		},
		{
			ID:          "kotlin.time.duration.parse",
			Language:    rules.LangKotlin,
			Pattern:     `Duration\.parse\s*\(`,
			ObjectType:  "java.time.Duration",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.Duration.parse() restricts input to ISO-8601 duration format (PnDTnHnMn.nS, no injection)",
		},
		{
			ID:          "kotlin.time.period.parse",
			Language:    rules.LangKotlin,
			Pattern:     `Period\.parse\s*\(`,
			ObjectType:  "java.time.Period",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.Period.parse() restricts input to ISO-8601 period format (PnYnMnD, no injection)",
		},

		// --- NoSQL sanitizers (CWE-943) ---
		{
			ID:          "kotlin.mongodb.filters",
			Language:    rules.LangKotlin,
			Pattern:     `Filters\.(eq|ne|gt|gte|lt|lte|in|nin|and|or|not|regex|exists|elemMatch)\s*\(`,
			ObjectType:  "com.mongodb.client.model.Filters",
			MethodName:  "Filters.*",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "MongoDB Java driver Filters builder API (Kotlin interop) — type-safe BSON query; values bind as BSON, not string-concatenated",
		},
		{
			ID:          "kotlin.spring.criteria.where",
			Language:    rules.LangKotlin,
			Pattern:     `Criteria\.where\s*\(`,
			ObjectType:  "org.springframework.data.mongodb.core.query.Criteria",
			MethodName:  "where",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "Spring Data MongoDB Criteria builder (Kotlin) — type-safe query construction",
		},
		{
			ID:          "kotlin.bson.objectid.constructor",
			Language:    rules.LangKotlin,
			Pattern:     `ObjectId\s*\(`,
			ObjectType:  "org.bson.types.ObjectId",
			MethodName:  "ObjectId",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "org.bson.types.ObjectId(hex) — validates and parses to a 24-hex-char ObjectId; rejects operator-injection payloads",
		},
		{
			ID:          "kotlin.mongodb.updates",
			Language:    rules.LangKotlin,
			Pattern:     `Updates\.(set|inc|push|pull|addToSet|combine|unset|currentDate)\s*\(`,
			ObjectType:  "com.mongodb.client.model.Updates",
			MethodName:  "Updates.*",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB Java driver Updates builder API (Kotlin) — typed BSON update document (no string-concatenated $set/$inc)",
		},
		{
			ID:          "kotlin.mongodb.projections",
			Language:    rules.LangKotlin,
			Pattern:     `Projections\.(include|exclude|fields|excludeId|elemMatch|slice|meta)\s*\(`,
			ObjectType:  "com.mongodb.client.model.Projections",
			MethodName:  "Projections.*",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB Java driver Projections builder API (Kotlin) — typed BSON projection (no $expr smuggling)",
		},
		{
			ID:          "kotlin.kmongo.dsl",
			Language:    rules.LangKotlin,
			Pattern:     `(?:eq|ne|gt|gte|lt|lte|inValues|all|exists|regex|` + "`" + `\$set` + "`" + `|` + "`" + `\$push` + "`" + `)\s*\(|\.json\b`,
			ObjectType:  "org.litote.kmongo",
			MethodName:  "KMongo DSL",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "KMongo type-safe DSL infix/prefix operators (eq/ne/gt/.../inValues/`$set`) — typed Bson Document construction (no string-concatenated operators)",
		},
		{
			ID:          "kotlin.mongo.bson_document_parse",
			Language:    rules.LangKotlin,
			Pattern:     `BsonDocument\.parse\s*\(`,
			ObjectType:  "org.bson.BsonDocument",
			MethodName:  "BsonDocument.parse",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "org.bson.BsonDocument.parse — typed BSON parser (raises BsonInvalidOperationException on malformed input, preventing free-form operator injection through an untyped path)",
		},

		// --- Crypto sanitizers — strong password-hash / KDF for JVM (Kotlin) ---
		{
			ID:          "kotlin.bcrypt.hashpw",
			Language:    rules.LangKotlin,
			Pattern:     `BCrypt\.hashpw\s*\(|BCrypt\.withDefaults\s*\(\s*\)\.hash\s*\(`,
			ObjectType:  "BCrypt",
			MethodName:  "BCrypt.hashpw/withDefaults().hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "jBCrypt / Spring Security BCrypt.hashpw / Argon2BCrypt withDefaults().hash — bcrypt password hash (defends CWE-916)",
		},
		{
			ID:          "kotlin.argon2.hash",
			Language:    rules.LangKotlin,
			Pattern:     `Argon2Factory\.create\s*\(|Argon2PasswordEncoder\s*\(`,
			ObjectType:  "Argon2",
			MethodName:  "Argon2Factory.create/Argon2PasswordEncoder",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "de.mkammerer.argon2 Argon2Factory.create / Spring Security Argon2PasswordEncoder — Argon2 password hashing (CWE-916)",
		},
		{
			ID:          "kotlin.scrypt.scryptutil",
			Language:    rules.LangKotlin,
			Pattern:     `SCryptUtil\.scrypt\s*\(|SCryptPasswordEncoder\s*\(`,
			ObjectType:  "SCryptUtil",
			MethodName:  "SCryptUtil.scrypt/SCryptPasswordEncoder",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Lambdaworks SCryptUtil.scrypt / Spring Security SCryptPasswordEncoder — scrypt password hashing (CWE-916)",
		},
		{
			ID:          "kotlin.pbkdf2.password_encoder",
			Language:    rules.LangKotlin,
			Pattern:     `Pbkdf2PasswordEncoder\s*\(|PBEKeySpec\s*\(\s*[^,]+,\s*[^,]+,\s*\d{4,}\s*,\s*\d{3,}\s*\)`,
			ObjectType:  "Pbkdf2PasswordEncoder/PBEKeySpec",
			MethodName:  "Pbkdf2PasswordEncoder",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security Pbkdf2PasswordEncoder / PBEKeySpec with iter≥1000 — PBKDF2 KDF for password hashing",
		},
		{
			ID:          "kotlin.securerandom",
			Language:    rules.LangKotlin,
			Pattern:     `SecureRandom\s*\(\s*\)|SecureRandom\.getInstanceStrong\s*\(`,
			ObjectType:  "java.security.SecureRandom",
			MethodName:  "SecureRandom",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "java.security.SecureRandom / .getInstanceStrong() — CSPRNG (defends CWE-338)",
		},

		// --- ReDoS sanitizers (CWE-1333, SnkRegexDoS category) ---
		// These neutralize the dedicated kotlin.regex.pattern.dynamic sink.
		// Pattern.quote() wraps the user fragment in \Q...\E so every
		// metacharacter is treated literally — no quantifiers/alternations can
		// be injected, so catastrophic backtracking is impossible.
		{
			ID:          "kotlin.regex.pattern.quote",
			Language:    rules.LangKotlin,
			Pattern:     `\bPattern\.quote\s*\(`,
			ObjectType:  "java.util.regex.Pattern",
			MethodName:  "Pattern.quote",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "java.util.regex.Pattern.quote() wraps user input in \\Q...\\E so it is matched literally (no metacharacters), preventing attacker-crafted backtracking (ReDoS)",
		},
		// Regex.escape() is the Kotlin stdlib equivalent — escapes every regex
		// metacharacter so the fragment becomes a literal substring.
		{
			ID:          "kotlin.regex.escape.redos",
			Language:    rules.LangKotlin,
			Pattern:     `\bRegex\.escape\s*\(`,
			ObjectType:  "kotlin.text.Regex",
			MethodName:  "Regex.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "kotlin.text.Regex.escape() converts user input into a literal pattern fragment (no metacharacters), preventing ReDoS on attacker-controlled patterns",
		},
		// Pattern.compile(pattern, Pattern.LITERAL) tells the engine to treat
		// the whole pattern as a literal string — metacharacters lose meaning,
		// so a tainted pattern cannot introduce backtracking.
		{
			ID:          "kotlin.regex.pattern.literal",
			Language:    rules.LangKotlin,
			Pattern:     `Pattern\.compile\s*\([^,)]+,\s*(?:[A-Za-z._|\s]*\b)?Pattern\.LITERAL`,
			ObjectType:  "java.util.regex.Pattern",
			MethodName:  "Pattern.compile(..., Pattern.LITERAL)",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Pattern.compile with the Pattern.LITERAL flag matches the pattern as a literal string (metacharacters inert), preventing ReDoS",
		},

		// --- CSV / formula-injection sanitizers (CWE-1236, SnkCSV category) ---
		// Neutralize the kotlin.opencsv.* / kotlin.kotlincsv.* sinks. Stripping
		// or quoting cells that begin with a spreadsheet formula trigger
		// (=, +, -, @) defangs the injection.
		{
			ID:          "kotlin.csv.formula.prefix.strip",
			Language:    rules.LangKotlin,
			Pattern:     `\.replace\s*\(\s*Regex\s*\(`,
			ObjectType:  "kotlin.text.Regex",
			MethodName:  "replace(Regex(...))",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Regex-based replace that strips/escapes leading formula characters (=, +, -, @) neutralizes CSV/formula injection in cell values",
		},
		{
			ID:          "kotlin.csv.apache.escapecsv",
			Language:    rules.LangKotlin,
			Pattern:     `\bStringEscapeUtils\.escapeCsv\s*\(`,
			ObjectType:  "org.apache.commons.text.StringEscapeUtils",
			MethodName:  "escapeCsv",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Apache Commons Text StringEscapeUtils.escapeCsv() quotes cells containing CSV special characters, preventing formula/delimiter injection",
		},

		// --- File-upload sanitizers (CWE-434, SnkUpload category) ---
		// Neutralize the kotlin.spring.multipartfile.transferto / Ktor upload
		// sinks. Validating the uploaded file's extension against an allowlist
		// is the canonical defense against unrestricted file upload.
		{
			ID:          "kotlin.upload.extension.allowlist",
			Language:    rules.LangKotlin,
			Pattern:     `\b(?:allowedExtensions|allowedTypes|ALLOWED_EXTENSIONS|allowedMimeTypes|extensionAllowlist|extensionWhitelist)\b[^\n]*\.contains\s*\(`,
			ObjectType:  "",
			MethodName:  "allowedExtensions.contains",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Checking the uploaded file's extension/MIME type against an allowlist (allowedExtensions.contains(ext)) before persisting prevents unrestricted file upload (CWE-434)",
		},
		{
			ID:          "kotlin.upload.filenameutils.getextension",
			Language:    rules.LangKotlin,
			Pattern:     `(?:^|[^\w.])(?:FilenameUtils|filenameUtils)\.getExtension\s*\(`,
			ObjectType:  "org.apache.commons.io.FilenameUtils",
			MethodName:  "getExtension",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Apache Commons FilenameUtils.getExtension() extracts the file extension for allowlist validation before an upload is persisted",
		},

		// --- http4k typed lenses (org.http4k.lens) ---
		// http4k strongly favours typed lenses over raw-string accessors. A
		// typed lens (`Query.int()`, `Path.int()`, `Path.uuid()`,
		// `Query.boolean()`, `Body.auto<T>()`) PARSES the input into a typed,
		// non-String value (Int/UUID/Boolean/typed object). A value that has
		// passed through an int/uuid/boolean/enum lens can no longer carry a
		// SQL/HTML/redirect/command payload, so it neutralises those sinks.
		// Matched by @argpattern on the lens-construction call text — this
		// fires when the lens build+extract is on the assignment RHS (the
		// canonical inline http4k idiom).
		{
			ID:          "kotlin.http4k.lens.typed",
			Language:    rules.LangKotlin,
			Pattern:     `\b(?:Query|Path|Header|FormField)\s*\.\s*(?:int|long|float|double|boolean|uuid|localDate|dateTime|instant|enum)\s*\(`,
			ObjectType:  "@argpattern",
			MethodName:  "Query.int/Path.uuid/etc",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkCommand},
			Description: "http4k typed lens (Query.int()/Path.uuid()/etc) parses input into a typed non-String value, neutralising injection/XSS/redirect (CWE-79/89/601)",
		},
		{
			ID:          "kotlin.http4k.lens.bodyauto",
			Language:    rules.LangKotlin,
			Pattern:     `\bBody\s*\.\s*auto\s*<`,
			ObjectType:  "@argpattern",
			MethodName:  "Body.auto",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkDeserialize},
			Description: "http4k Body.auto<T>() marshals the request body into a typed object via the configured (safe) auto-marshaller rather than exposing a raw injectable String",
		},
	}
}
