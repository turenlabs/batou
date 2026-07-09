package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (javaCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// HTML encoding
		{ID: "java.stringescapeutils.escapehtml4", Language: rules.LangJava, Pattern: `StringEscapeUtils\.escapeHtml4\s*\(`, ObjectType: "StringEscapeUtils", MethodName: "escapeHtml4", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Apache Commons HTML escape (lang3)"},
		{ID: "java.stringescapeutils.escapehtml", Language: rules.LangJava, Pattern: `StringEscapeUtils\.escapeHtml\s*\(`, ObjectType: "StringEscapeUtils", MethodName: "escapeHtml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Apache Commons HTML escape (lang2)"},
		{ID: "java.spring.htmlutils.htmlescape", Language: rules.LangJava, Pattern: `HtmlUtils\.htmlEscape\s*\(`, ObjectType: "HtmlUtils", MethodName: "htmlEscape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Spring HTML escape"},
		{ID: "java.spring.javascriptutils.javascriptescape", Language: rules.LangJava, Pattern: `JavaScriptUtils\.javaScriptEscape\s*\(`, ObjectType: "JavaScriptUtils", MethodName: "javaScriptEscape", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval}, Description: "Spring JavaScript string escaping (escapes quotes/backslashes for <script> contexts)"},
		{ID: "java.esapi.encodeforhtml", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForHTML\s*\(`, ObjectType: "ESAPI", MethodName: "encodeForHTML", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "ESAPI HTML encoding"},
		{ID: "java.jsoup.clean", Language: rules.LangJava, Pattern: `Jsoup\.clean\s*\(`, ObjectType: "Jsoup", MethodName: "clean", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "Jsoup HTML sanitization"},

		// SQL parameterization
		{ID: "java.preparedstatement", Language: rules.LangJava, Pattern: `PreparedStatement|prepareStatement\s*\(`, ObjectType: "PreparedStatement", MethodName: "prepareStatement", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Parameterized SQL via PreparedStatement"},

		// Type coercion
		{ID: "java.integer.parseint", Language: rules.LangJava, Pattern: `Integer\.parseInt\s*\(`, ObjectType: "Integer", MethodName: "parseInt", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Integer parsing (type coercion)"},
		{ID: "java.long.parselong", Language: rules.LangJava, Pattern: `Long\.parseLong\s*\(`, ObjectType: "Long", MethodName: "parseLong", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Long parsing (type coercion)"},

		// Path traversal
		{ID: "java.filenameutils.getname", Language: rules.LangJava, Pattern: `FilenameUtils\.getName\s*\(`, ObjectType: "FilenameUtils", MethodName: "getName", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "Filename extraction via FilenameUtils"},

		// Uploaded-file content/type validation (CWE-434 defenses): detect the
		// real MIME type from the uploaded bytes (not the client-supplied name
		// or Content-Type header) before persisting.
		{ID: "java.tika.detect", Language: rules.LangJava, Pattern: `\.detect\s*\(`, ObjectType: "Tika", MethodName: "detect", Neutralizes: []taint.SinkCategory{taint.SnkUpload}, Description: "Apache Tika.detect() — content-based MIME-type detection of uploaded bytes (defends unrestricted file upload when paired with an allowlist)"},
		{ID: "java.urlconnection.guesscontenttype", Language: rules.LangJava, Pattern: `URLConnection\.guessContentTypeFromStream\s*\(`, ObjectType: "URLConnection", MethodName: "guessContentTypeFromStream", Neutralizes: []taint.SinkCategory{taint.SnkUpload}, Description: "URLConnection.guessContentTypeFromStream() — sniffs the MIME type from an uploaded stream's leading bytes (defends unrestricted file upload when paired with an allowlist)"},

		// URL encoding
		{ID: "java.urlencoder.encode", Language: rules.LangJava, Pattern: `URLEncoder\.encode\s*\(`, ObjectType: "URLEncoder", MethodName: "encode", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkHTMLOutput, taint.SnkHeader}, Description: "URL encoding (encodes CR/LF preventing header injection)"},

		// Input validation annotations

		// PR-BBjava: java.util.regex.Pattern.matches(regex, input) with a
		// hardcoded regex literal validates the input shape. The
		// matching regex catalog entry only fires when the first arg is
		// a string literal; the tsflow walker recognises it as a guard
		// before flowing the value into a sink. Mirrors the Python
		// `re.match(r"^[a-z]+$", ...)` and JS `validator.matches(...)`
		// sanitizer patterns.
		{ID: "java.regex.pattern.matches", Language: rules.LangJava, Pattern: `Pattern\.matches\s*\(\s*["']`, ObjectType: "Pattern", MethodName: "matches", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch}, Description: "java.util.regex.Pattern.matches(literalRegex, input) — validation guard (only fires when the regex is a string literal)"},

		// Javalin typed validation API. ctx.queryParamAsClass(...)/pathParamAsClass(...)
		// coerce the input to a target type (e.g. Integer.class) and reject values
		// that don't parse, constraining the value so it cannot carry quotes/slashes
		// into SQL/command/path-traversal sinks. Scoped to the `ctx` Context receiver.
		{ID: "java.javalin.validator.asclass", Language: rules.LangJava, Pattern: `\.(?:queryParamAsClass|pathParamAsClass|formParamAsClass|headerAsClass)\s*\(`, ObjectType: "io.javalin.http.Context", MethodName: "queryParamAsClass/pathParamAsClass/formParamAsClass/headerAsClass", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileRead, taint.SnkFileWrite, taint.SnkRedirect}, Description: "Javalin typed validation (Context.*AsClass) coerces/validates input to a target type"},

		// Hibernate parameterized queries
		{ID: "java.hibernate.setparameter", Language: rules.LangJava, Pattern: `\.setParameter\s*\(`, ObjectType: "Query", MethodName: "setParameter", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Hibernate/JPA parameterized query binding"},

		// MyBatis safe parameterization
		{ID: "java.mybatis.parameterized", Language: rules.LangJava, Pattern: `#\{[^}]+\}`, ObjectType: "MyBatis", MethodName: "#{}", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MyBatis #{} parameterized binding (safe alternative to ${})"},
		// JDO (DataNucleus/JPOX) parameterized query path: declareParameters /
		// setParameters / named ":p" markers bind values out-of-band, so a JDO
		// newQuery/setFilter that uses them is not injectable. Neutralizes the JDO
		// SQLi sinks above.
		{ID: "java.jdo.declareparameters", Language: rules.LangJava, Pattern: `\.(?:declareParameters|setParameters|setNamedParameters)\s*\(`, ObjectType: "javax.jdo.Query", MethodName: "declareParameters/setParameters", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "JDO Query.declareParameters/setParameters — parameterized JDOQL binding (safe alternative to concatenated filters)"},

		// OWASP Java Encoder
		{ID: "java.owasp.encode.forhtml", Language: rules.LangJava, Pattern: `Encode\.forHtml\s*\(`, ObjectType: "Encode", MethodName: "forHtml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "OWASP Java Encoder HTML encoding"},
		{ID: "java.owasp.encode.forjavascript", Language: rules.LangJava, Pattern: `Encode\.forJavaScript\s*\(`, ObjectType: "Encode", MethodName: "forJavaScript", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval}, Description: "OWASP Java Encoder JavaScript encoding"},

		// JNDI/LDAP sanitization
		{ID: "java.esapi.encodeforldap", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForLDAP\s*\(`, ObjectType: "ESAPI", MethodName: "encodeForLDAP", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "ESAPI LDAP encoding"},

		// Spring Security CSRF token validation

		// Jackson safe deserialization config
		{ID: "java.jackson.activatedefaulttyping.safe", Language: rules.LangJava, Pattern: `activateDefaultTyping\s*\([^)]*LaissezFaireSubTypeValidator`, ObjectType: "ObjectMapper", MethodName: "activateDefaultTyping", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Jackson activateDefaultTyping with validator (safer polymorphic deser)"},

		// SnakeYAML safe loading
		{ID: "java.snakeyaml.safeload", Language: rules.LangJava, Pattern: `(?:Yaml|yaml)\.loadAs\s*\(|new\s+Yaml\s*\(\s*new\s+SafeConstructor`, ObjectType: "Yaml", MethodName: "loadAs/SafeConstructor", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "SnakeYAML type-safe loading via loadAs() or SafeConstructor"},

		// XStream security framework (post-1.4.7)
		{ID: "java.xstream.allowtypes", Language: rules.LangJava, Pattern: `(?:XStream|xstream)\.allowTypes\s*\(|(?:XStream|xstream)\.setupDefaultSecurity\s*\(|(?:XStream|xstream)\.addPermission\s*\(`, ObjectType: "XStream", MethodName: "allowTypes/setupDefaultSecurity", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "XStream security framework type allowlisting"},

		// Kryo class registration enforcement
		{ID: "java.kryo.setregistrationrequired", Language: rules.LangJava, Pattern: `(?:Kryo|kryo)\.setRegistrationRequired\s*\(\s*true`, ObjectType: "Kryo", MethodName: "setRegistrationRequired(true)", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Kryo registration-required mode (prevents arbitrary class instantiation)"},

		// ObjectInputFilter (Java 9+ deserialization filter)
		{ID: "java.objectinputfilter", Language: rules.LangJava, Pattern: `ObjectInputFilter\.Config\.setSerialFilter\s*\(|\.setObjectInputFilter\s*\(`, ObjectType: "ObjectInputFilter", MethodName: "setSerialFilter/setObjectInputFilter", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "Java 9+ ObjectInputFilter for deserialization allowlisting"},

		// Input validation sanitizers (CWE-20)

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

		// XPath sanitization
		{ID: "java.esapi.encodeforxpath", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForXPath\s*\(`, ObjectType: "ESAPI", MethodName: "encodeForXPath", Neutralizes: []taint.SinkCategory{taint.SnkXPath}, Description: "ESAPI XPath encoding"},

		// OWASP Encode additional methods
		{ID: "java.owasp.encode.forhtmlattribute", Language: rules.LangJava, Pattern: `Encode\.forHtmlAttribute\s*\(`, ObjectType: "Encode", MethodName: "forHtmlAttribute", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "OWASP Java Encoder HTML attribute encoding"},
		{ID: "java.owasp.encode.forcssstring", Language: rules.LangJava, Pattern: `Encode\.forCssString\s*\(`, ObjectType: "Encode", MethodName: "forCssString", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "OWASP Java Encoder CSS string encoding"},

		// LDAP sanitization
		{ID: "java.spring.ldapencoder.filterencode", Language: rules.LangJava, Pattern: `LdapEncoder\.filterEncode\s*\(|LdapUtils\.encode\s*\(`, ObjectType: "LdapEncoder", MethodName: "filterEncode", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Spring LDAP filter encoding"},

		// NOTE: File.getCanonicalPath(), File.toPath().normalize(),
		// Path.normalize(), and Path.toRealPath() are intentionally NOT
		// registered as standalone CWE-22 sanitizers (mirrors the
		// filepath.Clean note in go_sanitizers.go and the os.path.normpath/
		// realpath note in python_sanitizers.go). Canonicalization alone does
		// not reject escapes: Paths.get("../../etc/passwd").normalize() is
		// still "../../etc/passwd", and getCanonicalPath/toRealPath resolve
		// "../" to a real path OUTSIDE the safe base. A complete defence is
		// canonicalize + containment (e.g. canonical.startsWith(BASE_DIR)) —
		// the canonicalize step by itself must not kill the taint flow.

		// Regex escaping
		{ID: "java.pattern.quote", Language: rules.LangJava, Pattern: `Pattern\.quote\s*\(`, ObjectType: "Pattern", MethodName: "quote", Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery, taint.SnkRegexDoS}, Description: "Regex metacharacter escaping (prevents ReDoS and injection in patterns)"},

		// Numeric coercion
		{ID: "java.double.parsedouble", Language: rules.LangJava, Pattern: `Double\.parseDouble\s*\(|Float\.parseFloat\s*\(`, ObjectType: "Double/Float", MethodName: "parseDouble/parseFloat", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Floating-point parsing (restricts to numeric values)"},

		// ESAPI additional encoding
		{ID: "java.esapi.encodeforsql", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForSQL\s*\(`, ObjectType: "ESAPI", MethodName: "encodeForSQL", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "ESAPI SQL encoding for safe query construction"},

		// StringUtils escaping
		{ID: "java.stringescapeutils.escapeecmascript", Language: rules.LangJava, Pattern: `StringEscapeUtils\.escapeEcmaScript\s*\(|StringEscapeUtils\.escapeXml\s*\(`, ObjectType: "StringEscapeUtils", MethodName: "escapeEcmaScript/escapeXml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "Apache Commons text escaping for JavaScript/XML contexts"},

		// JOOQ parameterization
		{ID: "java.jooq.param", Language: rules.LangJava, Pattern: `\bDSL\.(param|val)\(`, ObjectType: "DSL", MethodName: "param/val", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "JOOQ DSL.param()/val() parameterized binding"},
		{ID: "java.jooq.dsl", Language: rules.LangJava, Pattern: `\bDSL\.(select|insertInto|update|delete)\(`, ObjectType: "DSL", MethodName: "select/insertInto/update/delete", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "JOOQ DSL type-safe query builder (parameterized)"},

		// --- COVERAGE ADD (cov/java): parameterization sanitizers paired with
		// the new NamedParameterJdbcTemplate / JDBI Handle SQL sinks above, so a
		// query that binds its values does NOT raise a false positive. These
		// neutralize SnkSQLQuery only; the bind methods are the framework's
		// canonical "I parameterized this" signal.
		//
		// JDBI v3 fluent bind: handle.createQuery(sql).bind("id", userId) /
		// .bindBean(obj) / .bindList(...) / .bindMap(...) — values are sent as
		// PreparedStatement parameters, not concatenated into the SQL.
		{ID: "java.jdbi.bind", Language: rules.LangJava, Pattern: `\.bind\s*\(`, ObjectType: "org.jdbi.v3.core.statement.SqlStatement", MethodName: "bind/bindBean/bindList/bindMap/bindByType", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "JDBI SqlStatement.bind()/.bindBean()/.bindList()/.bindMap() — positional/named PreparedStatement parameter binding (not concatenated)"},
		{ID: "java.jdbi.bindbean", Language: rules.LangJava, Pattern: `\.bindBean\s*\(`, ObjectType: "org.jdbi.v3.core.statement.SqlStatement", MethodName: "bindBean", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "JDBI SqlStatement.bindBean() — binds bean properties as named parameters (not concatenated)"},
		// Spring NamedParameterJdbcTemplate parameterization: when the call
		// supplies a MapSqlParameterSource / BeanPropertySqlParameterSource /
		// Map of named params, the `:name` placeholders bind safely.
		{ID: "java.spring.mapsqlparametersource", Language: rules.LangJava, Pattern: `new\s+MapSqlParameterSource\s*\(`, ObjectType: "org.springframework.jdbc.core.namedparam.MapSqlParameterSource", MethodName: "MapSqlParameterSource", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Spring MapSqlParameterSource — named parameter binding for NamedParameterJdbcTemplate (values bind to :name placeholders, not concatenated)"},
		{ID: "java.spring.beanpropertysqlparametersource", Language: rules.LangJava, Pattern: `new\s+BeanPropertySqlParameterSource\s*\(`, ObjectType: "org.springframework.jdbc.core.namedparam.BeanPropertySqlParameterSource", MethodName: "BeanPropertySqlParameterSource", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Spring BeanPropertySqlParameterSource — binds bean properties as named parameters (not concatenated)"},
		// MyBatis-Plus typed condition methods are the safe parameterized path;
		// .eq/.like/.in/.between/.ge/.le bind values rather than concatenating.
		// (apply(String)/last(String) raw-fragment sinks are added above.)
		{ID: "java.mybatisplus.wrapper.eq", Language: rules.LangJava, Pattern: `\.(eq|ne|gt|ge|lt|le|like|likeLeft|likeRight|in|notIn|between)\s*\(`, ObjectType: "com.baomidou.mybatisplus.core.conditions.AbstractWrapper", MethodName: "eq/ne/gt/ge/lt/le/like/in/notIn/between", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "MyBatis-Plus AbstractWrapper typed condition methods (.eq/.like/.in/.between) — values bind as #{} parameters, not concatenated"},

		// Apache Solr query escaping (CWE-943)
		{ID: "java.solr.clientutils.escapequerychars", Language: rules.LangJava, Pattern: `ClientUtils\.escapeQueryChars\s*\(`, ObjectType: "ClientUtils", MethodName: "escapeQueryChars", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkNoSQL}, Description: "Apache Solr ClientUtils.escapeQueryChars() escapes Lucene/Solr special characters per the official client utility (prevents q/fq DSL injection)"},

		// MongoDB safe query builders (type-safe Filters API prevents NoSQL injection)
		{ID: "java.mongodb.filters", Language: rules.LangJava, Pattern: `\bFilters\.(eq|ne|gt|gte|lt|lte|in|nin|and|or|not|regex|exists|elemMatch)\s*\(`, ObjectType: "Filters", MethodName: "Filters.*", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkNoSQL}, Description: "MongoDB Filters builder API (type-safe query construction; values bind as BSON, not concatenated)"},
		{ID: "java.spring.criteria.where", Language: rules.LangJava, Pattern: `\bCriteria\.where\s*\(`, ObjectType: "Criteria", MethodName: "where", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkNoSQL}, Description: "Spring Data MongoDB Criteria builder (type-safe query construction)"},
		{ID: "java.mongodb.bson.document", Language: rules.LangJava, Pattern: `new\s+Document\s*\(`, ObjectType: "org.bson.Document", MethodName: "Document", Neutralizes: []taint.SinkCategory{taint.SnkNoSQL}, Description: "org.bson.Document constructor — builds a BSON document with type-safe values (vs. parsing a tainted JSON/string into a query)"},
		{ID: "java.spring.querybyexample", Language: rules.LangJava, Pattern: `\bExample\.of\s*\(`, ObjectType: "org.springframework.data.domain.Example", MethodName: "Example.of", Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery}, Description: "Spring Data Query-by-Example — Example.of(probe) binds probe values type-safely (no concatenation)"},

		// Command injection sanitizers
		{ID: "java.esapi.encodeforos", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForOS\s*\(`, ObjectType: "", MethodName: "encodeForOS", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "ESAPI OS command encoding"},
		{ID: "java.commons.stringescapeutils.escapejava", Language: rules.LangJava, Pattern: `StringEscapeUtils\.escapeJava\s*\(`, ObjectType: "StringEscapeUtils", MethodName: "escapeJava", Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkEval, taint.SnkHeader, taint.SnkLog}, Description: "Apache Commons Java/Text escapeJava() escapes control characters including CR/LF (prevents command/header/log injection)"},

		// Log injection sanitizers
		{ID: "java.log.replace.crlf", Language: rules.LangJava, Pattern: `\.replace\s*\(\s*["']\\n["']\s*,|\.replace\s*\(\s*["']\\r["']\s*,|\.replaceAll\s*\(\s*["']\\[rn\\]`, ObjectType: "String", MethodName: "replace", Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader}, Description: "CRLF character stripping (prevents log/header injection)"},
		{ID: "java.esapi.canonicalize", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.canonicalize\s*\(`, ObjectType: "", MethodName: "canonicalize", Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkCommand}, Description: "ESAPI canonicalize (normalizes encoded input to prevent log/command injection)"},

		// XXE prevention sanitizers
		{ID: "java.dbf.setfeature.secureprocessing", Language: rules.LangJava, Pattern: `DocumentBuilderFactory.*\.setFeature\s*\(\s*XMLConstants\.FEATURE_SECURE_PROCESSING`, ObjectType: "DocumentBuilderFactory", MethodName: "setFeature(SECURE_PROCESSING)", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkXPath}, Description: "XML secure processing feature (mitigates XXE and entity expansion)"},
		{ID: "java.dbf.disallow.doctype", Language: rules.LangJava, Pattern: `DocumentBuilderFactory.*\.setFeature\s*\(\s*["']http://apache\.org/xml/features/disallow-doctype-decl["']`, ObjectType: "DocumentBuilderFactory", MethodName: "setFeature(disallow-doctype)", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkXPath}, Description: "Disallow DOCTYPE declarations entirely (strongest XXE prevention)"},
		{ID: "java.saxparser.disallow.externalentities", Language: rules.LangJava, Pattern: `SAXParserFactory.*\.setFeature\s*\(\s*["']http://xml\.org/sax/features/external-general-entities["']\s*,\s*false`, ObjectType: "SAXParserFactory", MethodName: "setFeature(external-entities=false)", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkXPath}, Description: "SAX parser external entity disabling (XXE prevention)"},
		{ID: "java.xmlinputfactory.disallow.externalentities", Language: rules.LangJava, Pattern: `XMLInputFactory.*\.setProperty\s*\(\s*XMLInputFactory\.IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*false`, ObjectType: "XMLInputFactory", MethodName: "setProperty(EXTERNAL_ENTITIES=false)", Neutralizes: []taint.SinkCategory{taint.SnkDeserialize}, Description: "StAX parser external entity disabling (XXE prevention)"},

		// OWASP Java Encoder additional methods
		{ID: "java.owasp.encode.foruri", Language: rules.LangJava, Pattern: `Encode\.forUri\s*\(`, ObjectType: "Encode", MethodName: "forUri", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch}, Description: "OWASP Java Encoder URI encoding"},
		{ID: "java.owasp.encode.forxml", Language: rules.LangJava, Pattern: `Encode\.forXml\s*\(`, ObjectType: "Encode", MethodName: "forXml", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "OWASP Java Encoder XML encoding"},
		{ID: "java.owasp.encode.forxmlcontent", Language: rules.LangJava, Pattern: `Encode\.forXmlContent\s*\(`, ObjectType: "Encode", MethodName: "forXmlContent", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "OWASP Java Encoder XML content encoding"},
		{ID: "java.owasp.encode.forxmlattribute", Language: rules.LangJava, Pattern: `Encode\.forXmlAttribute\s*\(`, ObjectType: "Encode", MethodName: "forXmlAttribute", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "OWASP Java Encoder XML attribute encoding"},
		{ID: "java.owasp.encode.forhtmlcontent", Language: rules.LangJava, Pattern: `Encode\.forHtmlContent\s*\(`, ObjectType: "Encode", MethodName: "forHtmlContent", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "OWASP Java Encoder HTML content encoding"},
		{ID: "java.owasp.encode.forhtmlunquotedattribute", Language: rules.LangJava, Pattern: `Encode\.forHtmlUnquotedAttribute\s*\(`, ObjectType: "Encode", MethodName: "forHtmlUnquotedAttribute", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput}, Description: "OWASP Java Encoder HTML unquoted attribute encoding"},
		{ID: "java.owasp.encode.forcssurl", Language: rules.LangJava, Pattern: `Encode\.forCssUrl\s*\(`, ObjectType: "Encode", MethodName: "forCssUrl", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "OWASP Java Encoder CSS url() context encoding"},
		{ID: "java.owasp.encode.foruricomponent", Language: rules.LangJava, Pattern: `Encode\.forUriComponent\s*\(`, ObjectType: "Encode", MethodName: "forUriComponent", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader}, Description: "OWASP Java Encoder URI component encoding"},
		{ID: "java.owasp.encode.forjavascriptblock", Language: rules.LangJava, Pattern: `Encode\.forJavaScriptBlock\s*\(`, ObjectType: "Encode", MethodName: "forJavaScriptBlock", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval}, Description: "OWASP Java Encoder JavaScript block (inside <script>) encoding"},
		{ID: "java.owasp.encode.forjavascriptattribute", Language: rules.LangJava, Pattern: `Encode\.forJavaScriptAttribute\s*\(`, ObjectType: "Encode", MethodName: "forJavaScriptAttribute", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval}, Description: "OWASP Java Encoder JavaScript attribute (event handler) encoding"},
		{ID: "java.owasp.encode.forjavascriptsource", Language: rules.LangJava, Pattern: `Encode\.forJavaScriptSource\s*\(`, ObjectType: "Encode", MethodName: "forJavaScriptSource", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval}, Description: "OWASP Java Encoder JavaScript source (string-literal context) encoding"},
		{ID: "java.owasp.encode.forxmlcomment", Language: rules.LangJava, Pattern: `Encode\.forXmlComment\s*\(`, ObjectType: "Encode", MethodName: "forXmlComment", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "OWASP Java Encoder XML comment encoding"},
		{ID: "java.owasp.encode.forcdata", Language: rules.LangJava, Pattern: `Encode\.forCDATA\s*\(`, ObjectType: "Encode", MethodName: "forCDATA", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "OWASP Java Encoder XML/HTML CDATA section encoding"},

		// Header injection sanitizers
		{ID: "java.spring.responseentity.builder", Language: rules.LangJava, Pattern: `ResponseEntity\.(ok|status|created|accepted|noContent|badRequest|notFound)\s*\(`, ObjectType: "ResponseEntity", MethodName: "ResponseEntity.builder", Neutralizes: []taint.SinkCategory{taint.SnkHeader}, Description: "Spring ResponseEntity builder (type-safe header construction)"},
		{ID: "java.spring.httpheaders", Language: rules.LangJava, Pattern: `new\s+HttpHeaders\s*\(|HttpHeaders\.writableHttpHeaders\s*\(`, ObjectType: "HttpHeaders", MethodName: "HttpHeaders()", Neutralizes: []taint.SinkCategory{taint.SnkHeader}, Description: "Spring HttpHeaders type-safe header builder (validates header names)"},

		// Template engine auto-escape
		{ID: "java.thymeleaf.text", Language: rules.LangJava, Pattern: `th:text\s*=`, ObjectType: "Thymeleaf", MethodName: "th:text", Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate}, Description: "Thymeleaf th:text auto-escapes HTML (safe alternative to th:utext)"},

		// Spring Security
		{ID: "java.spring.uricomponentsbuilder", Language: rules.LangJava, Pattern: `UriComponentsBuilder\.(fromUriString|fromHttpUrl|newInstance)\s*\(`, ObjectType: "UriComponentsBuilder", MethodName: "UriComponentsBuilder.from*", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch}, Description: "Spring UriComponentsBuilder (structured URL construction prevents open redirect/SSRF)"},

		// Spring UriUtils component percent-encoders (org.springframework.web.util.UriUtils).
		// Each percent-encodes characters illegal in the named URI component, neutralizing
		// CR/LF header injection and open-redirect breakout when building a URL from user input.
		{ID: "java.spring.uriutils.encode", Language: rules.LangJava, Pattern: `UriUtils\.encode\s*\(`, ObjectType: "UriUtils", MethodName: "encode", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader}, Description: "Spring UriUtils.encode percent-encodes a full URI string"},
		{ID: "java.spring.uriutils.encodepath", Language: rules.LangJava, Pattern: `UriUtils\.encodePath\s*\(`, ObjectType: "UriUtils", MethodName: "encodePath", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader}, Description: "Spring UriUtils.encodePath percent-encodes a URI path component"},
		{ID: "java.spring.uriutils.encodepathsegment", Language: rules.LangJava, Pattern: `UriUtils\.encodePathSegment\s*\(`, ObjectType: "UriUtils", MethodName: "encodePathSegment", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader}, Description: "Spring UriUtils.encodePathSegment percent-encodes a single URI path segment"},
		{ID: "java.spring.uriutils.encodequery", Language: rules.LangJava, Pattern: `UriUtils\.encodeQuery\s*\(`, ObjectType: "UriUtils", MethodName: "encodeQuery", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader}, Description: "Spring UriUtils.encodeQuery percent-encodes a URI query string"},
		{ID: "java.spring.uriutils.encodequeryparam", Language: rules.LangJava, Pattern: `UriUtils\.encodeQueryParam\s*\(`, ObjectType: "UriUtils", MethodName: "encodeQueryParam", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader}, Description: "Spring UriUtils.encodeQueryParam percent-encodes a single URI query parameter"},
		{ID: "java.spring.uriutils.encodefragment", Language: rules.LangJava, Pattern: `UriUtils\.encodeFragment\s*\(`, ObjectType: "UriUtils", MethodName: "encodeFragment", Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader}, Description: "Spring UriUtils.encodeFragment percent-encodes a URI fragment component"},

		// Additional type coercion
		{ID: "java.boolean.parseboolean", Language: rules.LangJava, Pattern: `Boolean\.parseBoolean\s*\(`, ObjectType: "Boolean", MethodName: "parseBoolean", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog}, Description: "Boolean parsing (type coercion, restricts to true/false)"},
		{ID: "java.short.parseshort", Language: rules.LangJava, Pattern: `Short\.parseShort\s*\(`, ObjectType: "Short", MethodName: "parseShort", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand}, Description: "Short parsing (type coercion)"},

		// SSRF prevention — URL/URI validation sanitizers (receiver-method pattern)
		{ID: "java.uri.getscheme", Language: rules.LangJava, Pattern: `\.getScheme\s*\(\s*\)`, ObjectType: "URI", MethodName: "getScheme", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URI scheme extraction for protocol allowlist validation (restricts to http/https)"},
		{ID: "java.url.getprotocol", Language: rules.LangJava, Pattern: `\.getProtocol\s*\(\s*\)`, ObjectType: "URL", MethodName: "getProtocol", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URL protocol extraction for protocol validation (prevents file://, gopher://, etc.)"},
		{ID: "java.uri.getauthority", Language: rules.LangJava, Pattern: `\.getAuthority\s*\(\s*\)`, ObjectType: "URI", MethodName: "getAuthority", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect}, Description: "URI authority extraction for host validation (SSRF domain allowlist check)"},
		{ID: "java.guava.internetdomainname", Language: rules.LangJava, Pattern: `InternetDomainName\.from\s*\(`, ObjectType: "InternetDomainName", MethodName: "from", Neutralizes: []taint.SinkCategory{taint.SnkURLFetch}, Description: "Google Guava domain name validation and parsing (SSRF host validation)"},

		// Path traversal prevention — file path sanitizers
		// NOTE: Path.toRealPath() deliberately absent — canonicalize-only, see
		// the getCanonicalPath/normalize note above.
		{ID: "java.file.getname", Language: rules.LangJava, Pattern: `\.getName\s*\(\s*\)`, ObjectType: "File", MethodName: "getName", Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead}, Description: "File.getName() extracts filename only, strips directory components (path traversal prevention)"},

		// Expression Language injection prevention
		{ID: "java.spring.spel.simpleevaluationcontext", Language: rules.LangJava, Pattern: `SimpleEvaluationContext\.(forReadOnlyDataBinding|forReadWriteDataBinding|forPropertyAccessors)\s*\(`, ObjectType: "SimpleEvaluationContext", MethodName: "forReadOnlyDataBinding/forPropertyAccessors", Neutralizes: []taint.SinkCategory{taint.SnkEval}, Description: "Spring SpEL SimpleEvaluationContext (restricts to property access, prevents RCE)"},

		// OWASP Java Encoder — control character escaping
		{ID: "java.owasp.encode.forjava", Language: rules.LangJava, Pattern: `Encode\.forJava\s*\(`, ObjectType: "Encode", MethodName: "forJava", Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkEval, taint.SnkHeader}, Description: "OWASP Java Encoder control character escaping (prevents log/header injection)"},

		// Apache Commons Exec safe argument handling
		{ID: "java.commons.exec.addargument.quoted", Language: rules.LangJava, Pattern: `\.addArgument\s*\([^,]+,\s*true\s*\)`, ObjectType: "CommandLine", MethodName: "addArgument(arg, true)", Neutralizes: []taint.SinkCategory{taint.SnkCommand}, Description: "Commons Exec addArgument with quoting enabled (prevents shell metachar injection)"},

		// Strong crypto algorithm usage (neutralizes weak-crypto findings when replacing insecure code)
		{ID: "java.crypto.cipher.aes_gcm", Language: rules.LangJava, Pattern: `Cipher\.getInstance\s*\(\s*["']AES/GCM`, ObjectType: "Cipher", MethodName: "getInstance(AES/GCM)", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "AES-GCM authenticated encryption (strong algorithm)"},
		{ID: "java.crypto.sslcontext.tls12plus", Language: rules.LangJava, Pattern: `SSLContext\.getInstance\s*\(\s*["']TLSv1\.[23]["']`, ObjectType: "SSLContext", MethodName: "getInstance(TLSv1.2+)", Neutralizes: []taint.SinkCategory{taint.SnkCrypto}, Description: "SSLContext with TLSv1.2 or TLSv1.3 (secure protocol version)"},

		// Trust boundary sanitizers — input validation before session storage
		{ID: "java.spring.bindingresult.haserrors", Language: rules.LangJava, Pattern: `(?:BindingResult|result)\.hasErrors\s*\(\s*\)`, ObjectType: "BindingResult", MethodName: "hasErrors", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary}, Description: "Spring BindingResult validation check before storing user data"},

		// --- Vert.x SQL Client parameterized query sanitizer ---
		{ID: "java.vertx.sqlclient.preparedquery", Language: rules.LangJava, Pattern: `\.preparedQuery\s*\(`, ObjectType: "SqlClient", MethodName: "preparedQuery", Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery}, Description: "Vert.x SQL Client preparedQuery() with parameterized binding (prevents SQL injection)"},
		// LDAP sanitizers — DN/filter encoding and type-safe query builders (CWE-90)
		{ID: "java.ldapname", Language: rules.LangJava, Pattern: `new\s+LdapName\s*\(`, ObjectType: "LdapName", MethodName: "LdapName", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "javax.naming.ldap.LdapName validates LDAP DN structure during parsing (RFC 2253)"},
		{ID: "java.rdn.escapevalue", Language: rules.LangJava, Pattern: `Rdn\.escapeValue\s*\(`, ObjectType: "Rdn", MethodName: "escapeValue", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "javax.naming.ldap.Rdn.escapeValue() escapes special LDAP DN characters per RFC 2253"},
		{ID: "java.esapi.encodefordn", Language: rules.LangJava, Pattern: `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForDN\s*\(`, ObjectType: "ESAPI", MethodName: "encodeForDN", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "ESAPI DN component encoding for LDAP distinguished names"},
		{ID: "java.unboundid.filter.create", Language: rules.LangJava, Pattern: `Filter\.create(?:Equality|Substring|Presence|Greater|Less|AND|OR|NOT)Filter\s*\(`, ObjectType: "Filter", MethodName: "createEqualityFilter", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "UnboundID LDAP SDK type-safe filter builders (auto-escapes values per RFC 4515)"},
		{ID: "java.spring.ldapquerybuilder", Language: rules.LangJava, Pattern: `LdapQueryBuilder\.query\s*\(`, ObjectType: "LdapQueryBuilder", MethodName: "query", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Spring LDAP type-safe query builder (auto-escapes filter values)"},
		{ID: "java.unboundid.filter.encodevalue", Language: rules.LangJava, Pattern: `Filter\.encodeValue\s*\(`, ObjectType: "Filter", MethodName: "encodeValue", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "UnboundID Filter.encodeValue() escapes LDAP filter special chars per RFC 4515"},
		{ID: "java.spring.ldapnamebuilder", Language: rules.LangJava, Pattern: `LdapNameBuilder\.newInstance\s*\(`, ObjectType: "LdapNameBuilder", MethodName: "newInstance", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Spring LDAP LdapNameBuilder type-safe DN construction with auto-escaping"},
		{ID: "java.spring.ldaputils.newldapname", Language: rules.LangJava, Pattern: `LdapUtils\.newLdapName\s*\(`, ObjectType: "LdapUtils", MethodName: "newLdapName", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Spring LDAP LdapUtils.newLdapName() validated DN creation"},
		{ID: "java.spring.ldapencoder.nameencode", Language: rules.LangJava, Pattern: `LdapEncoder\.nameEncode\s*\(`, ObjectType: "LdapEncoder", MethodName: "nameEncode", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Spring LDAP LdapEncoder.nameEncode() encodes DN component special chars"},
		{ID: "java.apache.filterencoder.encodefiltervalue", Language: rules.LangJava, Pattern: `FilterEncoder\.encodeFilterValue\s*\(`, ObjectType: "FilterEncoder", MethodName: "encodeFilterValue", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Apache Directory API FilterEncoder.encodeFilterValue() escapes filter values per RFC 4515"},
		{ID: "java.apache.filterbuilder", Language: rules.LangJava, Pattern: `FilterBuilder\.(?:equal|substring|present|greaterOrEqual|lessOrEqual|not|and|or|approximatelyEqual)\s*\(`, ObjectType: "FilterBuilder", MethodName: "equal", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "Apache Directory API FilterBuilder type-safe filter construction (auto-escapes values)"},
		{ID: "java.rdn.constructor", Language: rules.LangJava, Pattern: `new\s+Rdn\s*\(`, ObjectType: "Rdn", MethodName: "Rdn", Neutralizes: []taint.SinkCategory{taint.SnkLDAP}, Description: "javax.naming.ldap.Rdn constructor validates and escapes DN components (RFC 2253)"},

		// Header injection sanitizers — type-safe header construction (CWE-113)
		{ID: "java.spring.contentdisposition", Language: rules.LangJava, Pattern: `ContentDisposition\.(builder|formData|attachment|inline)\s*\(`, ObjectType: "ContentDisposition", MethodName: "builder", Neutralizes: []taint.SinkCategory{taint.SnkHeader}, Description: "Spring ContentDisposition type-safe builder (prevents CRLF in Content-Disposition header)"},
		{ID: "java.spring.responsecookie.from", Language: rules.LangJava, Pattern: `ResponseCookie\.from\s*\(`, ObjectType: "ResponseCookie", MethodName: "from", Neutralizes: []taint.SinkCategory{taint.SnkHeader}, Description: "Spring ResponseCookie type-safe builder (validates cookie name/value, prevents CRLF injection)"},

		// Log/header injection sanitizers — control character removal (CWE-117, CWE-113)
		{ID: "java.guava.charmatcher.control", Language: rules.LangJava, Pattern: `CharMatcher\.javaIsoControl\s*\(\s*\)\s*\.removeFrom\s*\(`, ObjectType: "CharMatcher", MethodName: "javaIsoControl().removeFrom", Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader}, Description: "Guava CharMatcher removes all ISO control characters including CR/LF (prevents log/header injection)"},
		{ID: "java.commons.lang.stringutils.normalizespace", Language: rules.LangJava, Pattern: `StringUtils\.normalizeSpace\s*\(`, ObjectType: "StringUtils", MethodName: "normalizeSpace", Neutralizes: []taint.SinkCategory{taint.SnkLog}, Description: "Apache Commons Lang normalizeSpace() replaces newlines/whitespace sequences with single space (prevents log forging)"},

		// Trust boundary sanitizers — input type coercion (CWE-501)
		{ID: "java.uuid.fromstring", Language: rules.LangJava, Pattern: `UUID\.fromString\s*\(`, ObjectType: "UUID", MethodName: "fromString", Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary, taint.SnkSQLQuery}, Description: "UUID.fromString() validates and restricts input to UUID format (hex+dashes only, no injection possible)"},
		// --- Log injection sanitizers (SnkLog for CWE-117) ---
		{
			ID:          "java.slf4j.parameterized",
			Language:    rules.LangJava,
			Pattern:     `\blogger\.\w+\s*\(\s*["'][^"']*\{\}`,
			ObjectType:  "Logger",
			MethodName:  "info/warn/error/debug (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "SLF4J/Logback parameterized logging with {} placeholders (message is a constant, values are sanitized by the framework)",
		},
		{
			ID:          "java.log4j2.parameterized",
			Language:    rules.LangJava,
			Pattern:     `LogManager\.getLogger\s*\(.*\.\w+\s*\(\s*["'][^"']*\{\}`,
			ObjectType:  "Logger",
			MethodName:  "Log4j2 parameterized",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Log4j2 parameterized logging with {} placeholders (values are type-safe, preventing log injection)",
		},

		// --- Trust boundary sanitizers (SnkTrustBoundary for CWE-501) ---
		{
			ID:          "java.spring.preauthorize",
			Language:    rules.LangJava,
			Pattern:     `@PreAuthorize\s*\(`,
			ObjectType:  "Spring Security",
			MethodName:  "@PreAuthorize",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Spring Security @PreAuthorize annotation enforces authorization before method execution",
		},
		{
			ID:          "java.spring.secured",
			Language:    rules.LangJava,
			Pattern:     `@Secured\s*\(`,
			ObjectType:  "Spring Security",
			MethodName:  "@Secured",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Spring Security @Secured annotation enforces role-based access control",
		},
		{
			ID:          "java.shiro.requirespermission",
			Language:    rules.LangJava,
			Pattern:     `@RequiresPermissions\s*\(|@RequiresRoles\s*\(|@RequiresAuthentication`,
			ObjectType:  "Shiro",
			MethodName:  "@RequiresPermissions/@RequiresRoles",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Apache Shiro permission/role annotations enforce authorization before trust boundary crossing",
		},

		// --- Eval / Code injection sanitizers (SnkEval for CWE-94) ---
		{
			ID:          "java.scriptengine.bindings.restrict",
			Language:    rules.LangJava,
			Pattern:     `SimpleBindings\s*\(\s*\)|Bindings\s+\w+\s*=\s*engine\.createBindings\s*\(`,
			ObjectType:  "ScriptEngine",
			MethodName:  "createBindings/SimpleBindings",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "ScriptEngine with explicit bindings restricts eval context to declared variables only",
		},
		{
			ID:          "java.graalvm.context.sandbox",
			Language:    rules.LangJava,
			Pattern:     `Context\.newBuilder\s*\(.*\.allowAllAccess\s*\(\s*false\s*\)`,
			ObjectType:  "Context",
			MethodName:  "Context.newBuilder.allowAllAccess(false)",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "GraalVM Context with restricted access (sandboxed script evaluation)",
		},

		// --- SSRF prevention sanitizers (SnkURLFetch for CWE-918) ---
		{
			ID:          "java.okhttp.interceptor.hostcheck",
			Language:    rules.LangJava,
			Pattern:     `\.addInterceptor\s*\(.*\.host\s*\(\s*\)`,
			ObjectType:  "OkHttpClient",
			MethodName:  "addInterceptor(host check)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "OkHttp interceptor with host validation (SSRF domain allowlist)",
		},
		{
			ID:          "java.apache.httpclient.requestconfig",
			Language:    rules.LangJava,
			Pattern:     `RequestConfig\.custom\s*\(\s*\).*\.setMaxRedirects\s*\(\s*0\s*\)`,
			ObjectType:  "RequestConfig",
			MethodName:  "setMaxRedirects(0)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Apache HttpClient RequestConfig disabling redirects (prevents SSRF redirect chains)",
		},
		{
			ID:          "java.uri.create.validate",
			Language:    rules.LangJava,
			Pattern:     `URI\.create\s*\(.*\.getHost\s*\(\s*\)`,
			ObjectType:  "URI",
			MethodName:  "URI.create + getHost",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URI.create() with subsequent host extraction for domain validation (SSRF prevention)",
		},
		{
			ID:          "java.guava.inetaddresses_forstring",
			Language:    rules.LangJava,
			Pattern:     `InetAddresses\.forString\s*\(`,
			ObjectType:  "InetAddresses",
			MethodName:  "InetAddresses.forString",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Google Guava InetAddresses.forString — strict IP literal parser (rejects hostnames so an SSRF allowlist cannot be bypassed by 'localhost' aliases)",
		},
		{
			ID:          "java.guava.inetaddresses_isInetAddress",
			Language:    rules.LangJava,
			Pattern:     `InetAddresses\.isInetAddress\s*\(`,
			ObjectType:  "InetAddresses",
			MethodName:  "InetAddresses.isInetAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Google Guava InetAddresses.isInetAddress — strict IP-literal validation (SSRF allowlist guard)",
		},
		{
			ID:          "java.guava.hostandport_fromstring",
			Language:    rules.LangJava,
			Pattern:     `HostAndPort\.fromString\s*\(`,
			ObjectType:  "HostAndPort",
			MethodName:  "HostAndPort.fromString",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Google Guava HostAndPort.fromString — typed host:port parser (allowlist check on .getHost() / .getPort() after)",
		},
		{
			ID:          "java.idn.to_ascii",
			Language:    rules.LangJava,
			Pattern:     `IDN\.toASCII\s*\(`,
			ObjectType:  "IDN",
			MethodName:  "IDN.toASCII",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "java.net.IDN.toASCII — normalises an Internationalised Domain Name to Punycode so an allowlist cannot be bypassed via Unicode lookalikes (homograph SSRF)",
		},
		{
			ID:          "java.inetaddress.isloopback",
			Language:    rules.LangJava,
			Pattern:     `\.isLoopbackAddress\s*\(\s*\)`,
			ObjectType:  "InetAddress",
			MethodName:  "isLoopbackAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "InetAddress.isLoopbackAddress — SSRF guard reject for 127.0.0.0/8 / ::1 (combined with isSiteLocal/isAnyLocal/isLinkLocal forms a complete RFC-1918 / link-local denylist)",
		},
		{
			ID:          "java.inetaddress.isanylocal",
			Language:    rules.LangJava,
			Pattern:     `\.isAnyLocalAddress\s*\(\s*\)`,
			ObjectType:  "InetAddress",
			MethodName:  "isAnyLocalAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "InetAddress.isAnyLocalAddress — SSRF guard reject for 0.0.0.0 / :: wildcards that some servers route to localhost",
		},
		{
			ID:          "java.inetaddress.ismulticast",
			Language:    rules.LangJava,
			Pattern:     `\.isMulticastAddress\s*\(\s*\)`,
			ObjectType:  "InetAddress",
			MethodName:  "isMulticastAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "InetAddress.isMulticastAddress — SSRF guard reject for 224.0.0.0/4 (used as a denylist alongside isLoopback / isSiteLocal)",
		},
		{
			ID:          "java.guava.urlescaper",
			Language:    rules.LangJava,
			Pattern:     `UrlEscapers\.url(?:Path|Form|Fragment)Escaper\s*\(\s*\)\s*\.escape\s*\(`,
			ObjectType:  "UrlEscapers",
			MethodName:  "urlPathEscaper.escape",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect, taint.SnkHTMLOutput, taint.SnkHeader},
			Description: "Guava UrlEscapers (urlPath/urlForm/urlFragment escaper).escape — percent-encodes reserved characters and CR/LF (prevents header injection / open-redirect-style path smuggling)",
		},

		// --- Crypto sanitizers (SnkCrypto for CWE-327, CWE-916) ---
		{
			ID:          "java.crypto.argon2",
			Language:    rules.LangJava,
			Pattern:     `Argon2Factory\.create\s*\(|Argon2.*\.hash\s*\(`,
			ObjectType:  "Argon2",
			MethodName:  "Argon2Factory.create/hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Argon2 password hashing (memory-hard KDF, strongest password storage)",
		},
		{
			ID:          "java.crypto.pbkdf2",
			Language:    rules.LangJava,
			Pattern:     `SecretKeyFactory\.getInstance\s*\(\s*["']PBKDF2`,
			ObjectType:  "SecretKeyFactory",
			MethodName:  "getInstance(PBKDF2)",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 key derivation function (safe password hashing with iterations)",
		},
		{
			ID:          "java.crypto.digest.strong",
			Language:    rules.LangJava,
			Pattern:     `MessageDigest\.getInstance\s*\(\s*["']SHA-(?:256|384|512|3)`,
			ObjectType:  "MessageDigest",
			MethodName:  "getInstance(SHA-256+)",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Strong message digest algorithm (SHA-256/384/512/SHA-3, replaces weak MD5/SHA-1)",
		},

		// --- Spring Security PasswordEncoder family (org.springframework.security.crypto.password) ---
		// Modern Spring Security uses the PasswordEncoder interface with concrete impls
		// (BCrypt/Argon2/Pbkdf2/SCrypt/Delegating). All implementations apply a slow,
		// salted, one-way KDF, so any password reaching encode()/matches() is no longer
		// plaintext and should not be flagged as a weak-crypto/plaintext-storage sink.
		{
			ID:          "java.spring.passwordencoder.encode",
			Language:    rules.LangJava,
			Pattern:     `passwordEncoder\.encode\s*\(`,
			ObjectType:  "PasswordEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security PasswordEncoder.encode() — KDF-based password hashing (interface)",
		},
		{
			ID:          "java.spring.passwordencoder.matches",
			Language:    rules.LangJava,
			Pattern:     `passwordEncoder\.matches\s*\(`,
			ObjectType:  "PasswordEncoder",
			MethodName:  "matches",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security PasswordEncoder.matches() — constant-time password verification (interface)",
		},
		{
			ID:          "java.spring.bcryptpasswordencoder.encode",
			Language:    rules.LangJava,
			Pattern:     `BCryptPasswordEncoder.*\.encode\s*\(`,
			ObjectType:  "BCryptPasswordEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security BCryptPasswordEncoder.encode() — bcrypt password hashing",
		},
		{
			ID:          "java.spring.bcryptpasswordencoder.matches",
			Language:    rules.LangJava,
			Pattern:     `BCryptPasswordEncoder.*\.matches\s*\(`,
			ObjectType:  "BCryptPasswordEncoder",
			MethodName:  "matches",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security BCryptPasswordEncoder.matches() — bcrypt constant-time password verify",
		},
		{
			ID:          "java.spring.argon2passwordencoder.encode",
			Language:    rules.LangJava,
			Pattern:     `Argon2PasswordEncoder.*\.encode\s*\(`,
			ObjectType:  "Argon2PasswordEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security Argon2PasswordEncoder.encode() — Argon2 memory-hard password hashing",
		},
		{
			ID:          "java.spring.argon2passwordencoder.matches",
			Language:    rules.LangJava,
			Pattern:     `Argon2PasswordEncoder.*\.matches\s*\(`,
			ObjectType:  "Argon2PasswordEncoder",
			MethodName:  "matches",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security Argon2PasswordEncoder.matches() — Argon2 constant-time password verify",
		},
		{
			ID:          "java.spring.pbkdf2passwordencoder.encode",
			Language:    rules.LangJava,
			Pattern:     `Pbkdf2PasswordEncoder.*\.encode\s*\(`,
			ObjectType:  "Pbkdf2PasswordEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security Pbkdf2PasswordEncoder.encode() — PBKDF2 password hashing",
		},
		{
			ID:          "java.spring.pbkdf2passwordencoder.matches",
			Language:    rules.LangJava,
			Pattern:     `Pbkdf2PasswordEncoder.*\.matches\s*\(`,
			ObjectType:  "Pbkdf2PasswordEncoder",
			MethodName:  "matches",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security Pbkdf2PasswordEncoder.matches() — PBKDF2 constant-time password verify",
		},
		{
			ID:          "java.spring.scryptpasswordencoder.encode",
			Language:    rules.LangJava,
			Pattern:     `SCryptPasswordEncoder.*\.encode\s*\(`,
			ObjectType:  "SCryptPasswordEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security SCryptPasswordEncoder.encode() — scrypt memory-hard password hashing",
		},
		{
			ID:          "java.spring.scryptpasswordencoder.matches",
			Language:    rules.LangJava,
			Pattern:     `SCryptPasswordEncoder.*\.matches\s*\(`,
			ObjectType:  "SCryptPasswordEncoder",
			MethodName:  "matches",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security SCryptPasswordEncoder.matches() — scrypt constant-time password verify",
		},
		{
			ID:          "java.spring.delegatingpasswordencoder.encode",
			Language:    rules.LangJava,
			Pattern:     `DelegatingPasswordEncoder.*\.encode\s*\(`,
			ObjectType:  "DelegatingPasswordEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security DelegatingPasswordEncoder.encode() — delegated password hashing (Spring 5+ default)",
		},
		{
			ID:          "java.spring.delegatingpasswordencoder.matches",
			Language:    rules.LangJava,
			Pattern:     `DelegatingPasswordEncoder.*\.matches\s*\(`,
			ObjectType:  "DelegatingPasswordEncoder",
			MethodName:  "matches",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Spring Security DelegatingPasswordEncoder.matches() — delegated constant-time password verify",
		},

		// --- BouncyCastle modern KDF generators (org.bouncycastle.crypto.generators) ---
		{
			ID:          "java.bouncycastle.argon2bytesgenerator.generatebytes",
			Language:    rules.LangJava,
			Pattern:     `Argon2BytesGenerator.*\.generateBytes\s*\(`,
			ObjectType:  "Argon2BytesGenerator",
			MethodName:  "generateBytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BouncyCastle Argon2BytesGenerator.generateBytes() — Argon2 KDF with explicit parameters",
		},
		{
			ID:          "java.bouncycastle.scrypt.generate",
			Language:    rules.LangJava,
			Pattern:     `org\.bouncycastle\.crypto\.generators\.SCrypt\.generate\s*\(|SCrypt\.generate\s*\(`,
			ObjectType:  "SCrypt",
			MethodName:  "generate",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BouncyCastle SCrypt.generate() — scrypt KDF with explicit cost/blocksize/parallelism",
		},

		// --- Google Guava escapers (com.google.common.html / .net) ---
		// Parity with kotlin.guava.htmlescapers / .urlescapers and
		// groovy.guava.htmlescapers / .urlescapers (already merged). Receiver
		// constraint: ObjectType is the class name, so the matcher requires
		// the receiver chain to contain "HtmlEscapers" / "UrlEscapers" —
		// `someOtherEscaper.escape(x)` does NOT fire.
		{
			ID:          "java.guava.htmlescapers",
			Language:    rules.LangJava,
			Pattern:     `HtmlEscapers\.htmlEscaper\s*\(\s*\)\s*\.escape\s*\(`,
			ObjectType:  "HtmlEscapers",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Google Guava HtmlEscapers.htmlEscaper().escape() — HTML entity escaping for response body / templates",
		},
		{
			ID:          "java.guava.urlescapers",
			Language:    rules.LangJava,
			Pattern:     `UrlEscapers\.url(?:PathSegment|FormParameter|Fragment)Escaper\s*\(\s*\)\s*\.escape\s*\(`,
			ObjectType:  "UrlEscapers",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader},
			Description: "Google Guava UrlEscapers.url{PathSegment,FormParameter,Fragment}Escaper().escape() — URL component encoding (CR/LF-safe)",
		},

		// --- Apache Commons Text StringEscapeUtils (org.apache.commons.text) ---
		// Methods unique to commons-text (not present in deprecated lang3
		// StringEscapeUtils): escapeJson, escapeXml11. Parity with
		// kotlin.apache.stringescapeutils.escapejson / .escapexml11 and
		// groovy.apache.stringescapeutils.escapejson / .escapexml11 (already
		// merged). Receiver constraint: ObjectType "StringEscapeUtils"
		// anchors to the class via the matcher's lastPart heuristic.
		{
			ID:          "java.commons.text.stringescapeutils.escapejson",
			Language:    rules.LangJava,
			Pattern:     `StringEscapeUtils\.escapeJson\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeJson",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text StringEscapeUtils.escapeJson() — JSON string escaping (defends XSS in JSON contexts)",
		},
		{
			ID:          "java.commons.text.stringescapeutils.escapexml11",
			Language:    rules.LangJava,
			Pattern:     `StringEscapeUtils\.escapeXml11\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeXml11",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text StringEscapeUtils.escapeXml11() — XML 1.1 escape (handles all valid XML 1.1 control chars)",
		},

		// --- Upload (CWE-434) — extension / content-type allowlist + tika ---
		{
			ID:          "java.tika.parseMediaType",
			Language:    rules.LangJava,
			Pattern:     `\bMediaType\.parse\s*\(`,
			ObjectType:  "org.apache.tika.mime.MediaType",
			MethodName:  "MediaType.parse",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Apache Tika MediaType.parse — typed MIME parsing for an allowlist check (defends CWE-434 upload when paired with a known set)",
		},
		{
			ID:          "java.guava.media_type_parse",
			Language:    rules.LangJava,
			Pattern:     `\bMediaType\.parse\s*\(|\bMediaType\.valueOf\s*\(`,
			ObjectType:  "com.google.common.net.MediaType",
			MethodName:  "MediaType.parse",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Guava MediaType.parse / valueOf — typed Content-Type parsing for an allowlist check",
		},
		{
			ID:          "java.commons.filename_utils",
			Language:    rules.LangJava,
			Pattern:     `FilenameUtils\.getExtension\s*\(`,
			ObjectType:  "org.apache.commons.io.FilenameUtils",
			MethodName:  "FilenameUtils.getExtension",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload, taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Apache Commons IO FilenameUtils.getExtension — extracts a path's extension for an allowlist check (defends file-upload trust by extension)",
		},

		// --- CSV (CWE-1236) — Apache Commons CSV writer with QuoteMode.ALL ---
		{
			ID:          "java.commons.csv.format_with_quote_all",
			Language:    rules.LangJava,
			Pattern:     `\.withQuoteMode\s*\(\s*QuoteMode\.ALL\s*\)|CSVFormat\.[A-Z_]+\.withQuoteMode\s*\(`,
			ObjectType:  "org.apache.commons.csv.CSVFormat",
			MethodName:  "withQuoteMode(ALL)",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Apache Commons CSV CSVFormat.withQuoteMode(QuoteMode.ALL) — quotes every field, defeating CSV-formula injection at write time",
		},
		{
			ID:          "java.csv.escape_formula_prefix",
			Language:    rules.LangJava,
			Pattern:     `(?:^|\b)(?:escapeCsvFormula|sanitizeCsvCell|safeCsvField)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeCsvFormula",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Custom escapeCsvFormula / sanitizeCsvCell helper — prefixes a single quote when a field starts with =, +, -, @, TAB (defends CSV-formula injection)",
		},

		// --- Header injection (CWE-93 CRLF) — strip / typed-header helpers ---
		{
			ID:          "java.header.strip_crlf_replaceall",
			Language:    rules.LangJava,
			Pattern:     `\.replaceAll\s*\(\s*"[\\\\r\\\\n]+"|\.replaceAll\s*\(\s*"\\\\r\\\\n"`,
			ObjectType:  "String",
			MethodName:  "String.replaceAll(CRLF)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Manual String.replaceAll(\"[\\r\\n]+\", \"\") — defends header / log injection (CWE-93 / CWE-117)",
		},
		{
			ID:          "java.spring.httpheaders_typed",
			Language:    rules.LangJava,
			Pattern:     `\bnew\s+HttpHeaders\s*\(\s*\)|HttpHeaders\.builder\s*\(`,
			ObjectType:  "org.springframework.http.HttpHeaders",
			MethodName:  "HttpHeaders",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Spring HttpHeaders — typed multi-map; .add() / .set() reject CR/LF and validate header-name tokens",
		},
		{
			ID:          "java.servlet.encodeURL",
			Language:    rules.LangJava,
			Pattern:     `\.encodeURL\s*\(|\.encodeRedirectURL\s*\(`,
			ObjectType:  "HttpServletResponse",
			MethodName:  "encodeURL/encodeRedirectURL",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkRedirect},
			Description: "HttpServletResponse.encodeURL / .encodeRedirectURL — container-managed URL rewriting (escapes URL-unsafe characters)",
		},

		// --- Eval sanitizers — SPEL evaluator with restricted context / JSON / math expression library ---
		{
			ID:          "java.spel.simplecontext",
			Language:    rules.LangJava,
			Pattern:     `\bnew\s+SimpleEvaluationContext\.Builder\s*\(|SimpleEvaluationContext\.forReadOnlyDataBinding\s*\(`,
			ObjectType:  "org.springframework.expression.spel.support.SimpleEvaluationContext",
			MethodName:  "SimpleEvaluationContext",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Spring SimpleEvaluationContext / forReadOnlyDataBinding — restricted SpEL evaluation context (no type reference, no static methods, no constructors) — safe replacement for StandardEvaluationContext",
		},
		{
			ID:          "java.jackson.readtree_typed",
			Language:    rules.LangJava,
			Pattern:     `objectMapper\.readTree\s*\(|new\s+ObjectMapper\s*\(\s*\)\.readTree\s*\(`,
			ObjectType:  "com.fasterxml.jackson.databind.ObjectMapper",
			MethodName:  "readTree",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Jackson ObjectMapper.readTree — strict JSON parser returns JsonNode (no script execution); safe alternative to ScriptEngine.eval on JSON inputs",
		},
		{
			ID:          "java.exp4j.expression",
			Language:    rules.LangJava,
			Pattern:     `\bnew\s+ExpressionBuilder\s*\(|exp4j`,
			ObjectType:  "net.objecthunter.exp4j.ExpressionBuilder",
			MethodName:  "ExpressionBuilder",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "exp4j ExpressionBuilder — math-expression-only evaluator (no JVM class access), safe replacement for ScriptEngine for numeric formulas",
		},
	}
}
