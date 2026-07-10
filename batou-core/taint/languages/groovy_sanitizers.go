package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *GroovyCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- Parameterized SQL ---
		{
			ID:          "groovy.sql.prepared",
			Language:    rules.LangGroovy,
			Pattern:     `PreparedStatement|\.execute\s*\([^"]*,\s*\[`,
			ObjectType:  "groovy.sql.Sql",
			MethodName:  "execute (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Groovy SQL with parameter list (parameterized query)",
		},
		{
			ID:          "groovy.sql.params.list",
			Language:    rules.LangGroovy,
			Pattern:     `\.rows\s*\([^,]+,\s*\[|\.firstRow\s*\([^,]+,\s*\[|\.executeUpdate\s*\([^,]+,\s*\[`,
			ObjectType:  "groovy.sql.Sql",
			MethodName:  "rows/firstRow/executeUpdate (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Groovy SQL query methods with parameter list",
		},

		// --- HTML escaping ---
		{
			ID:          "groovy.htmlutils.htmlescape",
			Language:    rules.LangGroovy,
			Pattern:     `HtmlUtils\.htmlEscape\s*\(`,
			ObjectType:  "HtmlUtils",
			MethodName:  "htmlEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Spring HtmlUtils HTML escaping",
		},
		{
			ID:          "groovy.stringescapeutils",
			Language:    rules.LangGroovy,
			Pattern:     `StringEscapeUtils\.escapeHtml\s*\(|StringEscapeUtils\.escapeXml\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeHtml/escapeXml",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons StringEscapeUtils HTML/XML escaping",
		},
		{
			ID:          "groovy.encodeashtml",
			Language:    rules.LangGroovy,
			Pattern:     `\.encodeAsHTML\s*\(`,
			ObjectType:  "Grails",
			MethodName:  "encodeAsHTML",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Grails encodeAsHTML codec",
		},
		{
			ID:          "groovy.encodeasurl",
			Language:    rules.LangGroovy,
			Pattern:     `\.encodeAsURL\s*\(`,
			ObjectType:  "Grails",
			MethodName:  "encodeAsURL",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Grails encodeAsURL codec",
		},

		// --- Access control annotations ---
		{
			ID:          "groovy.spring.secured",
			Language:    rules.LangGroovy,
			Pattern:     `@Secured`,
			ObjectType:  "Spring",
			MethodName:  "@Secured",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkFileWrite},
			Description: "Spring Security @Secured annotation enforces access control",
		},
		{
			ID:          "groovy.spring.preauthorize",
			Language:    rules.LangGroovy,
			Pattern:     `@PreAuthorize`,
			ObjectType:  "Spring",
			MethodName:  "@PreAuthorize",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkFileWrite},
			Description: "Spring Security @PreAuthorize annotation enforces access control",
		},

		// --- Input validation ---
		{
			ID:          "groovy.integer.parseint",
			Language:    rules.LangGroovy,
			Pattern:     `Integer\.parseInt\s*\(|\.toInteger\s*\(|as\s+Integer`,
			ObjectType:  "",
			MethodName:  "parseInt/toInteger",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkTrustBoundary},
			Description: "Integer conversion restricts to numeric values",
		},

		// --- XXE prevention ---
		{
			ID:          "groovy.xmlslurper.secure",
			Language:    rules.LangGroovy,
			Pattern:     `setFeature\s*\(\s*.*disallow-doctype-decl|XMLConstants\.FEATURE_SECURE_PROCESSING`,
			ObjectType:  "XmlSlurper",
			MethodName:  "setFeature (secure)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XML parser with XXE protection enabled",
		},

		// --- LDAP escaping ---
		{
			ID:          "groovy.ldap.escape",
			Language:    rules.LangGroovy,
			Pattern:     `LdapEncoder\.filterEncode\s*\(|LdapNameBuilder|LdapUtils\.convertBinary`,
			ObjectType:  "LdapEncoder",
			MethodName:  "LdapEncoder.filterEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP filter encoding to prevent injection",
		},

		// --- Log sanitization ---
		{
			ID:          "groovy.log.sanitize",
			Language:    rules.LangGroovy,
			Pattern:     `\.replaceAll\s*\(\s*"[\[\(]\\\\[nrt][\]\)]"`,
			ObjectType:  "",
			MethodName:  "replaceAll(newlines)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Log injection prevention via control character removal",
		},

		// --- URL validation ---
		{
			ID:          "groovy.url.validate",
			Language:    rules.LangGroovy,
			Pattern:     `new\s+URL\s*\(.*\)\.toURI\s*\(|URI\.create\s*\(`,
			ObjectType:  "URL",
			MethodName:  "URL.toURI",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL/URI parsing and validation",
		},

		// --- Path normalization ---
		{
			ID:          "groovy.file.canonicalpath",
			Language:    rules.LangGroovy,
			Pattern:     `\.getCanonicalPath\s*\(|\.getCanonicalFile\s*\(|\.normalize\s*\(`,
			ObjectType:  "File",
			MethodName:  "getCanonicalPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path canonicalization prevents directory traversal",
		},

		// --- Regex escaping ---
		{
			ID:          "groovy.pattern.quote",
			Language:    rules.LangGroovy,
			Pattern:     `Pattern\.quote\s*\(|Matcher\.quoteReplacement\s*\(`,
			ObjectType:  "Pattern",
			MethodName:  "quote/quoteReplacement",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkSQLQuery},
			Description: "Regex/replacement metacharacter escaping (prevents ReDoS)",
		},

		// --- Numeric conversion ---
		{
			ID:          "groovy.tointeger",
			Language:    rules.LangGroovy,
			Pattern:     `\.toInteger\s*\(|\.toDouble\s*\(|\.toLong\s*\(|\.toFloat\s*\(`,
			ObjectType:  "",
			MethodName:  "toInteger/toDouble/toLong/toFloat",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkTrustBoundary},
			Description: "Groovy numeric type conversion (restricts to numeric values)",
		},

		// --- URL encoding ---
		{
			ID:          "groovy.urlencoder.encode",
			Language:    rules.LangGroovy,
			Pattern:     `URLEncoder\.encode\s*\(`,
			ObjectType:  "URLEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader},
			Description: "URL encoding neutralizes injection in URLs and headers",
		},

		// --- ESAPI encoding ---
		{
			ID:          "groovy.esapi.encode",
			Language:    rules.LangGroovy,
			Pattern:     `ESAPI\.encoder\s*\(\s*\)\s*\.encode|Encoder\.encodeForHTML\s*\(|Encoder\.encodeForSQL\s*\(`,
			ObjectType:  "ESAPI",
			MethodName:  "ESAPI.encoder.encode*",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkSQLQuery, taint.SnkCommand},
			Description: "OWASP ESAPI encoding functions",
		},

		// --- GORM parameterized HQL ---
		{
			ID:          "groovy.gorm.parameterized",
			Language:    rules.LangGroovy,
			Pattern:     `\.executeQuery\s*\([^,]+,\s*\[|\.find\s*\([^,]+,\s*\[|\.findAll\s*\([^,]+,\s*\[`,
			ObjectType:  "GormDomain",
			MethodName:  "executeQuery/find/findAll (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "GORM HQL with parameter list — parameterized query prevents injection",
		},

		// --- Allowlist validation ---
		{
			ID:          "groovy.allowlist.contains",
			Language:    rules.LangGroovy,
			Pattern:     `\b(?:allowlist|whitelist|allowed|valid\w*)\s*\.\s*contains\s*\(`,
			ObjectType:  "",
			MethodName:  "allowlist.contains",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery, taint.SnkFileWrite, taint.SnkRedirect},
			Description: "Allowlist membership check validates input against known-good values",
		},

		// --- Jenkins single-quoted shell strings ---
		{
			ID:          "groovy.jenkins.singlequote.sh",
			Language:    rules.LangGroovy,
			Pattern:     `\bsh\s+'[^']*'`,
			ObjectType:  "JenkinsPipeline",
			MethodName:  "sh (single-quoted)",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Jenkins sh with single-quoted string — no GString interpolation, safe from injection",
		},

		// --- Grails codecs ---
		{
			ID:          "groovy.encodeasjavascript",
			Language:    rules.LangGroovy,
			Pattern:     `\.encodeAsJavaScript\s*\(`,
			ObjectType:  "Grails",
			MethodName:  "encodeAsJavaScript",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate, taint.SnkEval},
			Description: "Grails encodeAsJavaScript codec escapes for JS context",
		},

		// --- OWASP Encoder ---
		{
			ID:          "groovy.owasp.encoder.forhtml",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forHtml\s*\(|Encode\.forHtmlAttribute\s*\(|Encode\.forHtmlContent\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "Encode.forHtml",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder for HTML context",
		},
		{
			ID:          "groovy.owasp.encoder.forjs",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forJavaScript\s*\(|Encode\.forJavaScriptAttribute\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "Encode.forJavaScript",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval},
			Description: "OWASP Java Encoder for JavaScript context",
		},

		// --- Command injection sanitizers ---
		{
			ID:          "groovy.processbuilder.list",
			Language:    rules.LangGroovy,
			Pattern:     `new\s+ProcessBuilder\s*\(\s*\[|new\s+ProcessBuilder\s*\(\s*Arrays\.asList`,
			ObjectType:  "ProcessBuilder",
			MethodName:  "ProcessBuilder(List)",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "ProcessBuilder with list args prevents shell injection (no shell interpretation)",
		},

		// --- Deserialization sanitizers ---
		{
			ID:          "groovy.snakeyaml.safeload",
			Language:    rules.LangGroovy,
			Pattern:     `new\s+Yaml\s*\(\s*new\s+SafeConstructor|Yaml\s*\(\s*SafeConstructor`,
			ObjectType:  "Yaml",
			MethodName:  "Yaml(SafeConstructor)",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "SnakeYAML with SafeConstructor prevents arbitrary class instantiation",
		},
		{
			ID:          "groovy.xstream.allowtypes",
			Language:    rules.LangGroovy,
			Pattern:     `\.allowTypes\s*\(|\.allowTypesByWildcard\s*\(|\.addPermission\s*\(|XStream\.setupDefaultSecurity\s*\(`,
			ObjectType:  "XStream",
			MethodName:  "allowTypes/setupDefaultSecurity",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "XStream with explicit type allowlist restricts deserialization classes",
		},
		{
			ID:          "groovy.objectinputfilter",
			Language:    rules.LangGroovy,
			Pattern:     `ObjectInputFilter|setObjectInputFilter\s*\(`,
			ObjectType:  "ObjectInputFilter",
			MethodName:  "setObjectInputFilter",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "JEP 290 ObjectInputFilter restricts deserialization classes",
		},

		// --- Crypto sanitizers ---
		{
			ID:          "groovy.securerandom",
			Language:    rules.LangGroovy,
			Pattern:     `new\s+SecureRandom\s*\(|SecureRandom\.getInstance\s*\(`,
			ObjectType:  "SecureRandom",
			MethodName:  "SecureRandom",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SecureRandom provides cryptographically strong randomness",
		},

		// --- File read sanitizers ---
		{
			ID:          "groovy.file.canonicalpath.read",
			Language:    rules.LangGroovy,
			Pattern:     `\.getCanonicalPath\s*\(|\.getCanonicalFile\s*\(|\.toRealPath\s*\(`,
			ObjectType:  "File",
			MethodName:  "getCanonicalPath/toRealPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead},
			Description: "Path canonicalization prevents directory traversal on file reads",
		},

		// --- JNDI/SpEL sanitizers ---
		{
			ID:          "groovy.jndi.allowlist",
			Language:    rules.LangGroovy,
			Pattern:     `\.startsWith\s*\(\s*"java:comp"|\.startsWith\s*\(\s*"java:module"`,
			ObjectType:  "",
			MethodName:  "JNDI prefix allowlist",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "JNDI lookup restricted to safe java:comp/ or java:module/ namespace",
		},
		{
			ID:          "groovy.spel.simplecontext",
			Language:    rules.LangGroovy,
			Pattern:     `SimpleEvaluationContext|SimpleEvaluationContext\.forReadOnlyDataBinding`,
			ObjectType:  "SimpleEvaluationContext",
			MethodName:  "SimpleEvaluationContext",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "SpEL SimpleEvaluationContext restricts to read-only data binding (no method invocation)",
		},

		// --- Spring JdbcTemplate parameterized queries ---
		{
			ID:          "groovy.spring.jdbctemplate.parameterized",
			Language:    rules.LangGroovy,
			Pattern:     `(?:jdbcTemplate|JdbcTemplate)\.(?:query|update|execute)\s*\([^,]+,\s*(?:new\s+Object|new\s+MapSqlParameterSource|\[)`,
			ObjectType:  "JdbcTemplate",
			MethodName:  "query/update/execute (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Spring JdbcTemplate with parameter binding (safe from SQL injection)",
		},
		{
			ID:          "groovy.spring.namedparameterjdbctemplate",
			Language:    rules.LangGroovy,
			Pattern:     `(?:namedParameterJdbcTemplate|NamedParameterJdbcTemplate)\.(?:query|update|execute)\s*\(`,
			ObjectType:  "NamedParameterJdbcTemplate",
			MethodName:  "query/update/execute",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Spring NamedParameterJdbcTemplate uses named parameters (safe from SQL injection)",
		},

		// --- Hibernate parameterized queries ---
		{
			ID:          "groovy.hibernate.setparameter",
			Language:    rules.LangGroovy,
			Pattern:     `\.setParameter\s*\(`,
			ObjectType:  "Query",
			MethodName:  "setParameter",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Hibernate Query.setParameter() uses parameterized binding",
		},

		// --- URL validation for SSRF ---
		{
			ID:          "groovy.spring.uricomponentsbuilder",
			Language:    rules.LangGroovy,
			Pattern:     `UriComponentsBuilder\.fromUriString\s*\(.*\.build\s*\(`,
			ObjectType:  "UriComponentsBuilder",
			MethodName:  "fromUriString().build()",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Spring UriComponentsBuilder validates and normalizes URIs",
		},

		// --- Micronaut sanitizers ---
		{
			ID:          "groovy.micronaut.uribuilder",
			Language:    rules.LangGroovy,
			Pattern:     `UriBuilder\.of\s*\(`,
			ObjectType:  "UriBuilder",
			MethodName:  "of",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Micronaut UriBuilder safely constructs and validates URIs",
		},

		// --- Ratpack sanitizers ---
		{
			ID:          "groovy.ratpack.redirect.allowlist",
			Language:    rules.LangGroovy,
			Pattern:     `(?:allowedRedirects|redirectAllowlist|safeUrls)\.contains\s*\(`,
			ObjectType:  "Ratpack",
			MethodName:  "allowlist.contains",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "Ratpack redirect URL validated against allowlist",
		},

		// --- XPath sanitizers (CWE-643 prevention) ---
		{
			ID:          "groovy.esapi.encodeforxpath",
			Language:    rules.LangGroovy,
			Pattern:     `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForXPath\s*\(`,
			ObjectType:  "ESAPI",
			MethodName:  "encodeForXPath",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "ESAPI XPath encoding prevents XPath injection",
		},
		{
			ID:          "groovy.xpath.quote.replace",
			Language:    rules.LangGroovy,
			Pattern:     `\.replace\s*\(\s*['"]'['"]\s*,|\.replaceAll\s*\(\s*['"][\[\]'"\\\\]+['"]`,
			ObjectType:  "String",
			MethodName:  "replace/replaceAll",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XPath special character escaping via string replacement",
		},

		// --- XXE sanitizers (CWE-611 prevention) ---
		{
			ID:          "groovy.xml.documentbuilderfactory.disallow.dtd",
			Language:    rules.LangGroovy,
			Pattern:     `DocumentBuilderFactory.*\.setFeature\s*\(\s*.*disallow-doctype-decl`,
			ObjectType:  "DocumentBuilderFactory",
			MethodName:  "setFeature(disallow-doctype-decl)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "DocumentBuilderFactory with DTD processing disabled (XXE prevention)",
		},
		{
			ID:          "groovy.xml.saxparserfactory.disallow.dtd",
			Language:    rules.LangGroovy,
			Pattern:     `SAXParserFactory.*\.setFeature\s*\(\s*.*disallow-doctype-decl`,
			ObjectType:  "SAXParserFactory",
			MethodName:  "setFeature(disallow-doctype-decl)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "SAXParserFactory with DTD processing disabled (XXE prevention)",
		},
		{
			ID:          "groovy.xml.xmlinputfactory.disallow.dtd",
			Language:    rules.LangGroovy,
			Pattern:     `XMLInputFactory.*\.setProperty\s*\(\s*.*SupportDTD.*false|XMLInputFactory.*\.setProperty\s*\(\s*.*IsReplacingEntityReferences.*false`,
			ObjectType:  "XMLInputFactory",
			MethodName:  "setProperty(SupportDTD=false)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XMLInputFactory with DTD support disabled (XXE prevention)",
		},
		{
			ID:          "groovy.xml.transformerfactory.secure",
			Language:    rules.LangGroovy,
			Pattern:     `TransformerFactory.*\.setAttribute\s*\(\s*.*ACCESS_EXTERNAL_DTD|TransformerFactory.*\.setFeature\s*\(\s*.*FEATURE_SECURE_PROCESSING`,
			ObjectType:  "TransformerFactory",
			MethodName:  "setAttribute(ACCESS_EXTERNAL_DTD)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "TransformerFactory with external DTD access disabled (XXE prevention)",
		},
		{
			ID:          "groovy.xmlslurper.disableexternalentities",
			Language:    rules.LangGroovy,
			Pattern:     `XmlSlurper\s*\(\s*false\s*,\s*false\s*\)|XmlSlurper\s*\(\s*false\s*,\s*false\s*,\s*false\s*\)`,
			ObjectType:  "XmlSlurper",
			MethodName:  "XmlSlurper(false, false)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkDeserialize},
			Description: "Groovy XmlSlurper with namespace-awareness and external entities disabled",
		},
		{
			ID:          "groovy.xmlparser.disableexternalentities",
			Language:    rules.LangGroovy,
			Pattern:     `XmlParser\s*\(\s*false\s*,\s*false\s*\)|XmlParser\s*\(\s*false\s*,\s*false\s*,\s*false\s*\)`,
			ObjectType:  "XmlParser",
			MethodName:  "XmlParser(false, false)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath, taint.SnkDeserialize},
			Description: "Groovy XmlParser with namespace-awareness and external entities disabled",
		},

		// --- File read sanitizers (CWE-22 path traversal prevention) ---
		{
			ID:          "groovy.filenameutils.getname",
			Language:    rules.LangGroovy,
			Pattern:     `FilenameUtils\.getName\s*\(`,
			ObjectType:  "FilenameUtils",
			MethodName:  "getName",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Apache Commons FilenameUtils.getName() strips directory components, preventing traversal",
		},
		{
			ID:          "groovy.filenameutils.normalize",
			Language:    rules.LangGroovy,
			Pattern:     `FilenameUtils\.normalize\s*\(`,
			ObjectType:  "FilenameUtils",
			MethodName:  "normalize",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Apache Commons FilenameUtils.normalize() resolves .. and . components",
		},
		{
			ID:          "groovy.path.normalize.startswith",
			Language:    rules.LangGroovy,
			Pattern:     `\.normalize\s*\(\s*\)\s*\.startsWith\s*\(|\.toRealPath\s*\(\s*\)\s*\.startsWith\s*\(`,
			ObjectType:  "Path",
			MethodName:  "normalize().startsWith()",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "NIO Path normalization with directory containment check prevents traversal",
		},
		{
			ID:          "groovy.nio.path.torealpath",
			Language:    rules.LangGroovy,
			Pattern:     `\.toRealPath\s*\(`,
			ObjectType:  "Path",
			MethodName:  "toRealPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead},
			Description: "NIO Path.toRealPath() resolves symlinks and normalizes path",
		},

		// --- Crypto sanitizers (CWE-327/328 weak crypto prevention) ---
		{
			ID:          "groovy.crypto.bcrypt.hashpw",
			Language:    rules.LangGroovy,
			Pattern:     `BCrypt\.hashpw\s*\(|BCryptPasswordEncoder`,
			ObjectType:  "BCrypt",
			MethodName:  "hashpw",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "BCrypt password hashing with adaptive cost factor",
		},
		{
			ID:          "groovy.crypto.mac.hmac",
			Language:    rules.LangGroovy,
			Pattern:     `Mac\.getInstance\s*\(\s*["']HmacSHA`,
			ObjectType:  "Mac",
			MethodName:  "getInstance(HmacSHA*)",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "HMAC-SHA message authentication provides integrity verification",
		},
		{
			ID:          "groovy.crypto.pbkdf2",
			Language:    rules.LangGroovy,
			Pattern:     `PBKDF2WithHmacSHA|PBEKeySpec\s*\(`,
			ObjectType:  "SecretKeyFactory",
			MethodName:  "PBKDF2WithHmacSHA",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "PBKDF2 key derivation with HMAC-SHA for secure password-based keys",
		},
		{
			ID:          "groovy.crypto.messagedigest.strong",
			Language:    rules.LangGroovy,
			Pattern:     `MessageDigest\.getInstance\s*\(\s*["']SHA-(?:256|384|512)["']\s*\)`,
			ObjectType:  "MessageDigest",
			MethodName:  "getInstance(SHA-256/384/512)",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Strong cryptographic hash algorithm (SHA-256 or better)",
		},

		// --- Header injection sanitizers (CWE-113 response splitting prevention) ---
		{
			ID:          "groovy.header.crlf.strip",
			Language:    rules.LangGroovy,
			Pattern:     `\.replace\s*\(\s*["']\\n["']\s*,|\.replace\s*\(\s*["']\\r["']\s*,|\.replaceAll\s*\(\s*["']\[\\\\rn\]`,
			ObjectType:  "String",
			MethodName:  "replace/replaceAll(CRLF)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "CRLF character stripping prevents HTTP response splitting",
		},
		{
			ID:          "groovy.spring.responseentity.builder",
			Language:    rules.LangGroovy,
			Pattern:     `ResponseEntity\.(ok|status|created|accepted|noContent|badRequest|notFound)\s*\(`,
			ObjectType:  "ResponseEntity",
			MethodName:  "ok/status/created/...",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Spring ResponseEntity builder provides type-safe header construction",
		},
		{
			ID:          "groovy.spring.httpheaders.builder",
			Language:    rules.LangGroovy,
			Pattern:     `new\s+HttpHeaders\s*\(|HttpHeaders\.writableHttpHeaders\s*\(`,
			ObjectType:  "HttpHeaders",
			MethodName:  "HttpHeaders()",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Spring HttpHeaders validates header names and values against RFC 7230",
		},

		// --- Log injection sanitizers (CWE-117 log forging prevention) ---
		{
			ID:          "groovy.log.replace.crlf",
			Language:    rules.LangGroovy,
			Pattern:     `\.replace\s*\(\s*["']\\n["']\s*,\s*["']["']\s*\)|\.replace\s*\(\s*["']\\r["']\s*,\s*["']["']\s*\)`,
			ObjectType:  "String",
			MethodName:  "replace(newline, empty)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Explicit newline/carriage return removal prevents log injection",
		},
		{
			ID:          "groovy.owasp.encode.forjava",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forJava\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "Encode.forJava",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "OWASP Java Encoder escapes control characters for log and header safety",
		},
		{
			ID:          "groovy.log.boolean.parse",
			Language:    rules.LangGroovy,
			Pattern:     `Boolean\.parseBoolean\s*\(|\.toBoolean\s*\(`,
			ObjectType:  "",
			MethodName:  "Boolean.parseBoolean/toBoolean",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Boolean type coercion restricts log output to true/false",
		},

		// --- SSRF sanitizers (CWE-918 prevention) ---
		{
			ID:          "groovy.inetaddress.validate",
			Language:    rules.LangGroovy,
			Pattern:     `InetAddress\.getByName\s*\(.*\.isSiteLocalAddress\s*\(|\.isLoopbackAddress\s*\(|\.isLinkLocalAddress\s*\(`,
			ObjectType:  "InetAddress",
			MethodName:  "isSiteLocal/isLoopback/isLinkLocal",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "IP address validation detects internal/loopback addresses (SSRF prevention)",
		},
		// --- Trust boundary sanitizers (CWE-501 prevention) ---
		{
			ID:          "groovy.javax.validator.validate",
			Language:    rules.LangGroovy,
			Pattern:     `Validator\.validate\s*\(`,
			ObjectType:  "Validator",
			MethodName:  "validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "JSR-380 Bean Validation constrains input before trust boundary storage",
		},
		{
			ID:          "groovy.jackson.typed.readvalue",
			Language:    rules.LangGroovy,
			Pattern:     `ObjectMapper.*\.readValue\s*\([^,]+,\s*\w+\.class`,
			ObjectType:  "ObjectMapper",
			MethodName:  "readValue",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Jackson typed deserialization constrains data shape before trust boundary storage",
		},
		{
			ID:          "groovy.grails.domain.validate",
			Language:    rules.LangGroovy,
			Pattern:     `\.validate\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "validate",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Grails domain/command validate() constrains input before trust boundary storage",
		},

		// --- SSRF sanitizers (CWE-918 prevention) ---
		{
			ID:          "groovy.inetaddress.private.check",
			Language:    rules.LangGroovy,
			Pattern:     `\.isSiteLocalAddress\s*\(|\.isLoopbackAddress\s*\(|\.isAnyLocalAddress\s*\(`,
			ObjectType:  "InetAddress",
			MethodName:  "isSiteLocalAddress/isLoopbackAddress/isAnyLocalAddress",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "InetAddress private/loopback IP range check prevents SSRF to internal services",
		},
		{
			ID:          "groovy.apache.urlvalidator",
			Language:    rules.LangGroovy,
			Pattern:     `UrlValidator.*\.isValid\s*\(|new\s+UrlValidator\s*\(`,
			ObjectType:  "UrlValidator",
			MethodName:  "isValid",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Apache Commons UrlValidator validates URL structure and scheme",
		},

		// --- LDAP sanitizers (CWE-90 prevention) ---
		{
			ID:          "groovy.esapi.encodeforldap",
			Language:    rules.LangGroovy,
			Pattern:     `ESAPI\.encoder\s*\(\s*\)\s*\.encodeForLDAP\s*\(|ESAPI\.encoder\s*\(\s*\)\s*\.encodeForDN\s*\(`,
			ObjectType:  "ESAPI",
			MethodName:  "encodeForLDAP/encodeForDN",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "ESAPI LDAP filter and DN encoding prevents LDAP injection",
		},
		{
			ID:          "groovy.spring.ldapquerybuilder",
			Language:    rules.LangGroovy,
			Pattern:     `LdapQueryBuilder\.query\s*\(|LdapQuery\b`,
			ObjectType:  "LdapQueryBuilder",
			MethodName:  "query",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Spring LDAP parameterized query builder prevents LDAP injection",
		},
		{
			ID:          "groovy.ldap.nameencode",
			Language:    rules.LangGroovy,
			Pattern:     `LdapEncoder\.nameEncode\s*\(|LdapUtils\.newLdapName\s*\(`,
			ObjectType:  "LdapEncoder",
			MethodName:  "nameEncode/newLdapName",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "LDAP DN value encoding prevents DN injection attacks",
		},
		{
			ID:          "groovy.unboundid.filter.create",
			Language:    rules.LangGroovy,
			Pattern:     `Filter\.create(?:Equality|Substring)Filter\s*\(|Filter\.encodeValue\s*\(`,
			ObjectType:  "Filter",
			MethodName:  "createEqualityFilter/createSubstringFilter/encodeValue",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "UnboundID LDAP SDK safe filter construction prevents LDAP injection",
		},

		// --- MongoDB safe query builders (CWE-943 neutralizers) ---
		// MongoDB Filters and Aggregates builders produce type-safe Bson documents
		// that treat tainted values as data, not operators. Spring Data's Criteria
		// builder does the same for MongoTemplate queries.
		{
			ID:          "groovy.rdn.escapevalue",
			Language:    rules.LangGroovy,
			Pattern:     `Rdn\.escapeValue\s*\(|new\s+Rdn\s*\(`,
			ObjectType:  "Rdn",
			MethodName:  "escapeValue/Rdn",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "javax.naming.ldap.Rdn escapes/validates DN component special characters per RFC 2253",
		},
		{
			ID:          "groovy.apache.filterencoder",
			Language:    rules.LangGroovy,
			Pattern:     `FilterEncoder\.encodeFilterValue\s*\(`,
			ObjectType:  "FilterEncoder",
			MethodName:  "encodeFilterValue",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Apache Directory API FilterEncoder.encodeFilterValue() escapes filter values per RFC 4515",
		},
		{
			ID:          "groovy.apache.filterbuilder",
			Language:    rules.LangGroovy,
			Pattern:     `FilterBuilder\.(?:equal|substring|present|greaterOrEqual|lessOrEqual|not|and|or|approximatelyEqual)\s*\(`,
			ObjectType:  "FilterBuilder",
			MethodName:  "equal/substring/present/greaterOrEqual/lessOrEqual/not/and/or",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Apache Directory API FilterBuilder type-safe filter construction (auto-escapes values)",
		},

		// --- Cross-JVM SSTI HTML-escape helpers ---
		// Apache Velocity Tools EscapeTool.html() HTML-encodes its argument before
		// it reaches a template/output context — neutralizes XSS via template data.
		{
			ID:          "groovy.velocity.escapetool.html",
			Language:    rules.LangGroovy,
			Pattern:     `(?:EscapeTool|esc|escapeTool)\.html\s*\(`,
			ObjectType:  "org.apache.velocity.tools.generic.EscapeTool",
			MethodName:  "EscapeTool.html",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Velocity Tools EscapeTool.html() HTML-encodes template data (safe for template output contexts)",
		},
		// Thymeleaf th:text performs automatic HTML escaping (as opposed to th:utext
		// which renders raw HTML). Using th:text on user data is the safe alternative.
		{
			ID:          "groovy.thymeleaf.text",
			Language:    rules.LangGroovy,
			Pattern:     `th:text\s*=`,
			ObjectType:  "Thymeleaf",
			MethodName:  "th:text",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Thymeleaf th:text auto-escapes HTML (safe alternative to th:utext)",
		},

		// --- JSoup, Guava, OWASP Java HTML Sanitizer, IDN, Apache Commons Text gaps ---
		// Mirrors PR #520 (kotlin) for Groovy, since these libraries are JVM-wide
		// and used identically in Groovy (same canonical JVM HTML/URL sanitizers).
		{
			ID:          "groovy.jsoup.clean",
			Language:    rules.LangGroovy,
			Pattern:     `Jsoup\.clean\s*\(`,
			ObjectType:  "Jsoup",
			MethodName:  "clean",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Jsoup.clean(html, Safelist) strips disallowed tags/attributes (canonical JVM HTML sanitizer)",
		},
		{
			ID:          "groovy.owasp.htmlsanitizer.policy",
			Language:    rules.LangGroovy,
			Pattern:     `\bpolicy(?:Factory)?\.sanitize\s*\(`,
			ObjectType:  "PolicyFactory",
			MethodName:  "sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java HTML Sanitizer PolicyFactory.sanitize(html) — structural HTML sanitization",
		},
		{
			ID:          "groovy.owasp.htmlsanitizer.sanitizers",
			Language:    rules.LangGroovy,
			Pattern:     `Sanitizers\.\w+[^;]*\.sanitize\s*\(`,
			ObjectType:  "Sanitizers",
			MethodName:  "sanitize",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java HTML Sanitizer prebuilt Sanitizers.{FORMATTING,LINKS,...}.sanitize(html)",
		},
		{
			ID:          "groovy.guava.htmlescapers",
			Language:    rules.LangGroovy,
			Pattern:     `HtmlEscapers\.htmlEscaper\s*\(\s*\)\s*\.escape\s*\(`,
			ObjectType:  "HtmlEscapers",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Google Guava HtmlEscapers.htmlEscaper().escape() HTML entity escaping",
		},
		{
			ID:          "groovy.guava.urlescapers",
			Language:    rules.LangGroovy,
			Pattern:     `UrlEscapers\.url(?:PathSegment|FormParameter|Fragment)Escaper\s*\(\s*\)\s*\.escape\s*\(`,
			ObjectType:  "UrlEscapers",
			MethodName:  "escape",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader},
			Description: "Google Guava UrlEscapers.url{Path,Form,Fragment}Escaper().escape() URL component encoding",
		},
		{
			ID:          "groovy.idn.toascii",
			Language:    rules.LangGroovy,
			Pattern:     `\bIDN\.toASCII\s*\(`,
			ObjectType:  "IDN",
			MethodName:  "toASCII",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "java.net.IDN.toASCII() IDNA host encoding (rejects malformed Unicode hostnames)",
		},
		{
			ID:          "groovy.apache.stringescapeutils.escapejson",
			Language:    rules.LangGroovy,
			Pattern:     `StringEscapeUtils\.escapeJson\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeJson",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text JSON string escaping (defends XSS in JSON contexts)",
		},
		{
			ID:          "groovy.apache.stringescapeutils.escapeecmascript",
			Language:    rules.LangGroovy,
			Pattern:     `StringEscapeUtils\.escapeEcmaScript\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeEcmaScript",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text JavaScript string escaping (defends XSS inside <script> blocks)",
		},
		{
			ID:          "groovy.apache.stringescapeutils.escapexml11",
			Language:    rules.LangGroovy,
			Pattern:     `StringEscapeUtils\.escapeXml(?:10|11)\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeXml11",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text XML 1.0/1.1 character escaping",
		},
		{
			ID:          "groovy.spring.htmlutils.numericescape",
			Language:    rules.LangGroovy,
			Pattern:     `HtmlUtils\.htmlEscape(?:Hex|Decimal)\s*\(`,
			ObjectType:  "HtmlUtils",
			MethodName:  "htmlEscapeHex/htmlEscapeDecimal",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Spring HtmlUtils numeric (hex/decimal) HTML entity escaping variants",
		},

		// --- Apache Commons Text + OWASP Java Encoder gap-fill ---
		// The existing groovy.stringescapeutils entry only catches the legacy
		// StringEscapeUtils.escapeHtml/escapeXml (deprecated in Commons Lang 3,
		// moved to Commons Text). Modern code uses escapeHtml4/escapeHtml3 and
		// escapeJava — none of which were previously recognized as sanitizers,
		// causing FPs on otherwise-safe XSS, log, and header sinks.
		{
			ID:          "groovy.apache.stringescapeutils.escapehtml4",
			Language:    rules.LangGroovy,
			Pattern:     `StringEscapeUtils\.escapeHtml(?:3|4)\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeHtml4/escapeHtml3",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons Text StringEscapeUtils.escapeHtml4/escapeHtml3 — modern HTML 4.0/3.2 entity escaping (replaces deprecated escapeHtml in Commons Lang 3)",
		},
		{
			ID:          "groovy.apache.stringescapeutils.escapejava",
			Language:    rules.LangGroovy,
			Pattern:     `StringEscapeUtils\.escapeJava\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeJava",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Apache Commons Text StringEscapeUtils.escapeJava — escapes control characters in Java string literals (defends log injection / header CRLF injection)",
		},

		// OWASP Java Encoder context gaps. The existing groovy.owasp.encoder.forhtml
		// and forjs cover HTML and JavaScript contexts; these fill in CSS,
		// URI, and XML contexts which are equally documented in the OWASP
		// Encoder API and recommended by the OWASP XSS Prevention cheat sheet.
		{
			ID:          "groovy.owasp.encoder.forcss",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forCss(?:String|Url)\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forCssString/forCssUrl",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder Encode.forCssString/forCssUrl — escapes for CSS string and url() contexts (defends XSS in style attributes)",
		},
		{
			ID:          "groovy.owasp.encoder.foruri",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forUri(?:Component)?\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forUri/forUriComponent",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch, taint.SnkHeader},
			Description: "OWASP Java Encoder Encode.forUri/forUriComponent — percent-encodes URI segments (defends open-redirect, SSRF, and header injection via tainted URL components)",
		},
		{
			ID:          "groovy.owasp.encoder.forxml",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forXml(?:Content|Attribute|Comment)?\s*\(|Encode\.forCDATA\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forXml/forXmlContent/forXmlAttribute/forXmlComment/forCDATA",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate, taint.SnkXPath},
			Description: "OWASP Java Encoder Encode.forXml/forXmlContent/forXmlAttribute/forXmlComment/forCDATA — XML context escaping",
		},

		// --- OWASP Java Encoder: context-specific HTML/JavaScript methods ---
		// Encode.forHtml / Encode.forJavaScript are the generic encoders; the
		// OWASP Java Encoder also exposes the context-specific variants the OWASP
		// XSS Prevention Cheat Sheet recommends for precise output contexts
		// (element content vs. quoted/unquoted attribute, <script> block vs.
		// event-handler attribute vs. JS string-literal source). None were
		// modeled, so flows that applied the correct context encoder still
		// produced XSS false positives.
		{
			ID:          "groovy.owasp.encoder.forhtmlcontent",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forHtmlContent\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forHtmlContent",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder Encode.forHtmlContent — escapes &, <, >, and other control chars for HTML element-content context (XSS defense)",
		},
		{
			ID:          "groovy.owasp.encoder.forhtmlattribute",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forHtmlAttribute\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forHtmlAttribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder Encode.forHtmlAttribute — escapes for quoted HTML attribute value context (XSS defense)",
		},
		{
			ID:          "groovy.owasp.encoder.forhtmlunquotedattribute",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forHtmlUnquotedAttribute\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forHtmlUnquotedAttribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "OWASP Java Encoder Encode.forHtmlUnquotedAttribute — escapes for unquoted HTML attribute value context, including space/tab (XSS defense)",
		},
		{
			ID:          "groovy.owasp.encoder.forjavascriptblock",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forJavaScriptBlock\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forJavaScriptBlock",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval},
			Description: "OWASP Java Encoder Encode.forJavaScriptBlock — escapes for JavaScript inside an HTML <script> block (XSS defense)",
		},
		{
			ID:          "groovy.owasp.encoder.forjavascriptattribute",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forJavaScriptAttribute\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forJavaScriptAttribute",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval},
			Description: "OWASP Java Encoder Encode.forJavaScriptAttribute — escapes for JavaScript inside an HTML event-handler attribute (XSS defense)",
		},
		{
			ID:          "groovy.owasp.encoder.forjavascriptsource",
			Language:    rules.LangGroovy,
			Pattern:     `Encode\.forJavaScriptSource\s*\(`,
			ObjectType:  "Encode",
			MethodName:  "forJavaScriptSource",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkEval},
			Description: "OWASP Java Encoder Encode.forJavaScriptSource — escapes for a JavaScript string-literal source context (XSS defense)",
		},

		// --- java.time temporal parsing (type-coerce sanitizers) ---
		// Each parser throws DateTimeParseException on invalid input and returns a
		// strongly-typed temporal object whose toString() is bounded ISO-8601 format
		// (digits, dashes, colons, T, Z, +, .) with no characters dangerous to SQL,
		// shell, log, file path, HTML, or redirect contexts. Groovy inherits these
		// JVM APIs directly and they're idiomatic in Grails/Spring/Jenkins code.
		{
			ID:          "groovy.time.localdate.parse",
			Language:    rules.LangGroovy,
			Pattern:     `LocalDate\.parse\s*\(`,
			ObjectType:  "java.time.LocalDate",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.LocalDate.parse() restricts input to ISO-8601 date format (YYYY-MM-DD only, no injection)",
		},
		{
			ID:          "groovy.time.localdatetime.parse",
			Language:    rules.LangGroovy,
			Pattern:     `LocalDateTime\.parse\s*\(`,
			ObjectType:  "java.time.LocalDateTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.LocalDateTime.parse() restricts input to ISO-8601 datetime format (no injection)",
		},
		{
			ID:          "groovy.time.instant.parse",
			Language:    rules.LangGroovy,
			Pattern:     `Instant\.parse\s*\(`,
			ObjectType:  "java.time.Instant",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.Instant.parse() restricts input to ISO-8601 instant format (no injection)",
		},
		{
			ID:          "groovy.time.localtime.parse",
			Language:    rules.LangGroovy,
			Pattern:     `LocalTime\.parse\s*\(`,
			ObjectType:  "java.time.LocalTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.LocalTime.parse() restricts input to ISO-8601 time format (no injection)",
		},
		{
			ID:          "groovy.time.zoneddatetime.parse",
			Language:    rules.LangGroovy,
			Pattern:     `ZonedDateTime\.parse\s*\(`,
			ObjectType:  "java.time.ZonedDateTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.ZonedDateTime.parse() restricts input to ISO-8601 zoned datetime format (no injection)",
		},
		{
			ID:          "groovy.time.offsetdatetime.parse",
			Language:    rules.LangGroovy,
			Pattern:     `OffsetDateTime\.parse\s*\(`,
			ObjectType:  "java.time.OffsetDateTime",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.OffsetDateTime.parse() restricts input to ISO-8601 offset datetime format (no injection)",
		},
		{
			ID:          "groovy.time.duration.parse",
			Language:    rules.LangGroovy,
			Pattern:     `Duration\.parse\s*\(`,
			ObjectType:  "java.time.Duration",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.Duration.parse() restricts input to ISO-8601 duration format (PnDTnHnMn.nS, no injection)",
		},
		{
			ID:          "groovy.time.period.parse",
			Language:    rules.LangGroovy,
			Pattern:     `Period\.parse\s*\(`,
			ObjectType:  "java.time.Period",
			MethodName:  "parse",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "java.time.Period.parse() restricts input to ISO-8601 period format (PnYnMnD, no injection)",
		},

		// --- NoSQL sanitizers (CWE-943) ---
		{
			ID:          "groovy.mongodb.filters",
			Language:    rules.LangGroovy,
			Pattern:     `Filters\.(eq|ne|gt|gte|lt|lte|in|nin|and|or|not|regex|exists|elemMatch)\s*\(`,
			ObjectType:  "com.mongodb.client.model.Filters",
			MethodName:  "Filters.*",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "MongoDB Java driver Filters builder API (Groovy interop) — type-safe BSON query",
		},
		{
			ID:          "groovy.spring.criteria.where",
			Language:    rules.LangGroovy,
			Pattern:     `Criteria\.where\s*\(`,
			ObjectType:  "org.springframework.data.mongodb.core.query.Criteria",
			MethodName:  "where",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL, taint.SnkSQLQuery},
			Description: "Spring Data MongoDB Criteria builder (Groovy/Grails) — type-safe query construction",
		},
		{
			ID:          "groovy.mongodb.updates",
			Language:    rules.LangGroovy,
			Pattern:     `Updates\.(set|inc|push|pull|addToSet|combine|unset|currentDate)\s*\(`,
			ObjectType:  "com.mongodb.client.model.Updates",
			MethodName:  "Updates.*",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoDB Java driver Updates builder API (Groovy interop) — typed BSON update document",
		},
		{
			ID:          "groovy.bson.objectid",
			Language:    rules.LangGroovy,
			Pattern:     `new\s+ObjectId\s*\(|ObjectId\.isValid\s*\(`,
			ObjectType:  "org.bson.types.ObjectId",
			MethodName:  "ObjectId/isValid",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "org.bson.types.ObjectId(hex) / ObjectId.isValid — validates a 24-hex-char ObjectId (rejects operator payloads)",
		},
		{
			ID:          "groovy.gmongo.serializable",
			Language:    rules.LangGroovy,
			Pattern:     `\.toDBObject\s*\(\s*\)|new\s+BasicDBObject\s*\(`,
			ObjectType:  "com.mongodb.BasicDBObject",
			MethodName:  "BasicDBObject/toDBObject",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "BasicDBObject constructor / .toDBObject() — typed BSON document; entries bound as typed BSON values rather than concatenated",
		},

		// --- Cassandra/ScyllaDB CQL parameterization (CWE-943 neutralizers) ---
		// The groovy_sinks.go CqlSession.execute / SimpleStatement.* sinks fire on
		// raw CQL strings, but the safe form prepares a statement once and binds
		// user values as parameters — values are sent as typed protocol params,
		// never concatenated into the CQL text. This was a gap: the large
		// SnkNoSQL sink group had only MongoDB neutralizers.
		{
			ID:          "groovy.cassandra.session.prepare",
			Language:    rules.LangGroovy,
			Pattern:     `(?:cqlSession|CqlSession|session)\.prepare\s*\(`,
			ObjectType:  "com.datastax.oss.driver.api.core.CqlSession",
			MethodName:  "prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "DataStax CqlSession.prepare(cql) — prepared statement with ? placeholders; user values are bound as typed parameters, not concatenated into CQL (prevents CQL injection)",
		},
		{
			ID:          "groovy.cassandra.preparedstatement.bind",
			Language:    rules.LangGroovy,
			Pattern:     `(?:PreparedStatement|preparedStatement|prepared|boundStatement)\.bind\s*\(`,
			ObjectType:  "com.datastax.oss.driver.api.core.cql.PreparedStatement",
			MethodName:  "bind",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "DataStax PreparedStatement.bind(values...) binds user values as typed CQL parameters (safe from CQL injection)",
		},

		// --- Neo4j Cypher parameterization (CWE-943 neutralizers) ---
		// The groovy_sinks.go Neo4j Session/Tx.run / Neo4jClient.query sinks fire
		// on interpolated Cypher strings; the safe form supplies user values via a
		// parameters map ($name placeholders) so values never alter the query
		// structure.
		{
			ID:          "groovy.neo4j.parameters.map",
			Language:    rules.LangGroovy,
			Pattern:     `\.run\s*\([^,]+,\s*\[|\.runAsync\s*\([^,]+,\s*\[`,
			ObjectType:  "org.neo4j.driver.Session",
			MethodName:  "run(cypher, params)",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "Neo4j Session/Tx.run(cypher, [name: value]) passes user values via a parameters map with $name placeholders (prevents Cypher injection)",
		},
		{
			ID:          "groovy.neo4j.values.parameters",
			Language:    rules.LangGroovy,
			Pattern:     `\.withParameters\s*\(|Values\.parameters\s*\(`,
			ObjectType:  "org.neo4j.driver.Values",
			MethodName:  "withParameters/Values.parameters",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "Neo4j Query.withParameters(...) / Values.parameters(...) bind user values to $name placeholders (prevents Cypher injection)",
		},

		// --- ReDoS neutralizer (CWE-1333) ---
		// Pattern.quote(s) escapes every regex metacharacter in s, so a user-
		// supplied string compiled/matched after quoting cannot introduce
		// catastrophic-backtracking constructs. Complements the existing
		// groovy.pattern.quote entry (which neutralizes SnkEval/SnkSQLQuery) by
		// covering the dynamic-regex SnkRegexDoS sinks added alongside it.
		{
			ID:          "groovy.regex.pattern.quote.redos",
			Language:    rules.LangGroovy,
			Pattern:     `Pattern\.quote\s*\(`,
			ObjectType:  "java.util.regex.Pattern",
			MethodName:  "quote",
			Neutralizes: []taint.SinkCategory{taint.SnkRegexDoS},
			Description: "Pattern.quote() escapes all regex metacharacters so a user string compiled/matched as a pattern cannot trigger catastrophic backtracking (ReDoS)",
		},

		// --- CSV / spreadsheet formula injection (CWE-1236) ---
		// OpenCSV and Apache Commons CSV are JVM-wide libraries used identically
		// from Groovy and Java. The SnkCSV sinks (groovy.opencsv.csvwriter.*,
		// groovy.commonscsv.printrecord) previously had no matching sanitizer,
		// while Java already ships these two (java.commons.csv.* in
		// java_sanitizers.go). Mirrors that pair for Groovy.
		{
			ID:          "groovy.csv.escape_formula_prefix",
			Language:    rules.LangGroovy,
			Pattern:     `(?:^|\b)(?:escapeCsvFormula|sanitizeCsvCell|safeCsvField)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeCsvFormula",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Custom escapeCsvFormula / sanitizeCsvCell / safeCsvField helper — prefixes a single quote (or strips) when a cell begins with =, +, -, @ or TAB, the OWASP-recommended CSV-formula-injection defense (CWE-1236)",
		},
		{
			ID:          "groovy.commons.csv.format_with_quote_all",
			Language:    rules.LangGroovy,
			Pattern:     `\.withQuoteMode\s*\(\s*QuoteMode\.ALL\s*\)|CSVFormat\.[A-Z_]+\.withQuoteMode\s*\(`,
			ObjectType:  "org.apache.commons.csv.CSVFormat",
			MethodName:  "withQuoteMode(ALL)",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Apache Commons CSV CSVFormat.withQuoteMode(QuoteMode.ALL) — quotes every field, defeating CSV-formula injection at write time (CWE-1236)",
		},
	}
}
