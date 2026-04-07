package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Integer conversion restricts to numeric values",
		},
		{
			ID:          "groovy.commandobject",
			Language:    rules.LangGroovy,
			Pattern:     `@Validateable|class\s+\w+Command\b`,
			ObjectType:  "Grails",
			MethodName:  "Command object",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Grails command object with validation",
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

		// --- Regex validation ---
		{
			ID:          "groovy.regex.matches",
			Language:    rules.LangGroovy,
			Pattern:     `\.matches\s*\(|==~\s*/`,
			ObjectType:  "String",
			MethodName:  "matches/==~",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Regex validation restricts input to safe patterns",
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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
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
		{
			ID:          "groovy.encodeasbase64",
			Language:    rules.LangGroovy,
			Pattern:     `\.encodeAsBase64\s*\(|\.bytes\.encodeBase64\s*\(`,
			ObjectType:  "Grails",
			MethodName:  "encodeAsBase64",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkSQLQuery},
			Description: "Base64 encoding neutralizes injection metacharacters",
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
			ID:          "groovy.micronaut.valid",
			Language:    rules.LangGroovy,
			Pattern:     `@Valid\b|@Validated\b`,
			ObjectType:  "Micronaut",
			MethodName:  "@Valid/@Validated",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkEval},
			Description: "Micronaut bean validation constrains input to declared types and patterns",
		},
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
	}
}
