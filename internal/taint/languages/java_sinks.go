package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (javaCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// SQL injection
		{ID: "java.sql.statement.execute", Category: taint.SnkSQLQuery, Language: rules.LangJava, Pattern: `(?:Statement|stmt)\.execute\s*\(`, ObjectType: "Statement", MethodName: "execute", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL Statement.execute with potential injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.sql.statement.executequery", Category: taint.SnkSQLQuery, Language: rules.LangJava, Pattern: `(?:Statement|stmt)\.executeQuery\s*\(`, ObjectType: "Statement", MethodName: "executeQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL Statement.executeQuery with potential injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.sql.statement.executeupdate", Category: taint.SnkSQLQuery, Language: rules.LangJava, Pattern: `(?:Statement|stmt)\.executeUpdate\s*\(`, ObjectType: "Statement", MethodName: "executeUpdate", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "SQL Statement.executeUpdate with potential injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Command injection
		{ID: "java.runtime.exec", Category: taint.SnkCommand, Language: rules.LangJava, Pattern: `Runtime\.(?:getRuntime\s*\(\s*\)\s*\.)?exec\s*\(`, ObjectType: "Runtime", MethodName: "exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OS command execution via Runtime.exec", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.processbuilder", Category: taint.SnkCommand, Language: rules.LangJava, Pattern: `new\s+ProcessBuilder\s*\(`, ObjectType: "ProcessBuilder", MethodName: "ProcessBuilder", DangerousArgs: []int{-1}, Severity: rules.Critical, Description: "OS command execution via ProcessBuilder", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// XSS
		{ID: "java.servlet.writer.write", Category: taint.SnkHTMLOutput, Language: rules.LangJava, Pattern: `response\.getWriter\s*\(\s*\)\s*\.write\s*\(`, ObjectType: "PrintWriter", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "HTTP response write (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.servlet.writer.println", Category: taint.SnkHTMLOutput, Language: rules.LangJava, Pattern: `response\.getWriter\s*\(\s*\)\s*\.println\s*\(`, ObjectType: "PrintWriter", MethodName: "println", DangerousArgs: []int{0}, Severity: rules.High, Description: "HTTP response println (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.out.println.html", Category: taint.SnkHTMLOutput, Language: rules.LangJava, Pattern: `out\.print(?:ln)?\s*\(\s*["']<`, ObjectType: "PrintWriter", MethodName: "out.println (HTML)", DangerousArgs: []int{0}, Severity: rules.High, Description: "Direct HTML construction via out.println with string concatenation (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.writer.println.html", Category: taint.SnkHTMLOutput, Language: rules.LangJava, Pattern: `writer\.print(?:ln)?\s*\(\s*["']<`, ObjectType: "PrintWriter", MethodName: "writer.println (HTML)", DangerousArgs: []int{0}, Severity: rules.High, Description: "Direct HTML construction via writer.println with string concatenation (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// Redirect
		{ID: "java.servlet.forward", Category: taint.SnkRedirect, Language: rules.LangJava, Pattern: `(?:RequestDispatcher|dispatcher)\.forward\s*\(`, ObjectType: "RequestDispatcher", MethodName: "forward", DangerousArgs: []int{0}, Severity: rules.High, Description: "Request dispatch forward", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.servlet.sendredirect", Category: taint.SnkRedirect, Language: rules.LangJava, Pattern: `response\.sendRedirect\s*\(`, ObjectType: "HttpServletResponse", MethodName: "sendRedirect", DangerousArgs: []int{0}, Severity: rules.High, Description: "HTTP redirect with user-controlled URL", CWEID: "CWE-601", OWASPCategory: "A01:2021-Broken Access Control"},

		// Request dispatcher with tainted path
		{ID: "java.servlet.getrequestdispatcher", Category: taint.SnkRedirect, Language: rules.LangJava, Pattern: `\.getRequestDispatcher\s*\(`, ObjectType: "ServletRequest", MethodName: "getRequestDispatcher", DangerousArgs: []int{0}, Severity: rules.High, Description: "Request dispatcher with user-controlled path (path traversal)", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// File operations
		{ID: "java.file.new", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `new\s+File\s*\(`, ObjectType: "File", MethodName: "File", DangerousArgs: []int{0}, Severity: rules.High, Description: "File path with potential traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.fileoutputstream", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `new\s+FileOutputStream\s*\(`, ObjectType: "FileOutputStream", MethodName: "FileOutputStream", DangerousArgs: []int{0}, Severity: rules.High, Description: "FileOutputStream with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.filewriter", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `new\s+FileWriter\s*\(`, ObjectType: "FileWriter", MethodName: "FileWriter", DangerousArgs: []int{0}, Severity: rules.High, Description: "FileWriter with potential path traversal", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// SSRF
		{ID: "java.url.new", Category: taint.SnkURLFetch, Language: rules.LangJava, Pattern: `new\s+URL\s*\(`, ObjectType: "URL", MethodName: "URL", DangerousArgs: []int{0}, Severity: rules.High, Description: "URL with user-controlled address (SSRF)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "java.httpurlconnection", Category: taint.SnkURLFetch, Language: rules.LangJava, Pattern: `HttpURLConnection`, ObjectType: "HttpURLConnection", MethodName: "HttpURLConnection", DangerousArgs: []int{0}, Severity: rules.High, Description: "HTTP connection with potential SSRF", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "java.spring.resttemplate", Category: taint.SnkURLFetch, Language: rules.LangJava, Pattern: `(?:RestTemplate|restTemplate)\.getForObject\s*\(`, ObjectType: "RestTemplate", MethodName: "getForObject", DangerousArgs: []int{0}, Severity: rules.High, Description: "Spring RestTemplate SSRF", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// Deserialization
		{ID: "java.objectinputstream.readobject", Category: taint.SnkDeserialize, Language: rules.LangJava, Pattern: `ObjectInputStream.*\.readObject\s*\(`, ObjectType: "ObjectInputStream", MethodName: "readObject", DangerousArgs: []int{-1}, Severity: rules.Critical, Description: "Unsafe Java deserialization", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},
		{ID: "java.xmldecoder.readobject", Category: taint.SnkDeserialize, Language: rules.LangJava, Pattern: `XMLDecoder.*\.readObject\s*\(`, ObjectType: "XMLDecoder", MethodName: "readObject", DangerousArgs: []int{-1}, Severity: rules.Critical, Description: "Unsafe XML deserialization", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// XXE
		{ID: "java.xml.documentbuilder.parse", Category: taint.SnkXPath, Language: rules.LangJava, Pattern: `DocumentBuilder.*\.parse\s*\(`, ObjectType: "DocumentBuilder", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.High, Description: "XML parsing (potential XXE)", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},
		{ID: "java.xml.saxparser.parse", Category: taint.SnkXPath, Language: rules.LangJava, Pattern: `SAXParser.*\.parse\s*\(`, ObjectType: "SAXParser", MethodName: "parse", DangerousArgs: []int{0}, Severity: rules.High, Description: "SAX XML parsing (potential XXE)", CWEID: "CWE-611", OWASPCategory: "A05:2021-Security Misconfiguration"},

		// Code evaluation
		{ID: "java.scriptengine.eval", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `ScriptEngine.*\.eval\s*\(`, ObjectType: "ScriptEngine", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Script engine code evaluation", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},

		// LDAP
		{ID: "java.ldap.dircontext.search", Category: taint.SnkLDAP, Language: rules.LangJava, Pattern: `DirContext.*\.search\s*\(`, ObjectType: "DirContext", MethodName: "search", DangerousArgs: []int{1}, Severity: rules.High, Description: "LDAP query injection", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// Log injection (CWE-117)
		{ID: "java.logger.info", Category: taint.SnkLog, Language: rules.LangJava, Pattern: `(?:logger|Logger|LOG|log)\.info\s*\(`, ObjectType: "Logger", MethodName: "info", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Log injection via Logger.info", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "java.logger.debug", Category: taint.SnkLog, Language: rules.LangJava, Pattern: `(?:logger|Logger|LOG|log)\.debug\s*\(`, ObjectType: "Logger", MethodName: "debug", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Log injection via Logger.debug", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "java.logger.warn", Category: taint.SnkLog, Language: rules.LangJava, Pattern: `(?:logger|Logger|LOG|log)\.warn\s*\(`, ObjectType: "Logger", MethodName: "warn", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Log injection via Logger.warn", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "java.logger.error", Category: taint.SnkLog, Language: rules.LangJava, Pattern: `(?:logger|Logger|LOG|log)\.error\s*\(`, ObjectType: "Logger", MethodName: "error", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Log injection via Logger.error", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "java.logger.trace", Category: taint.SnkLog, Language: rules.LangJava, Pattern: `(?:logger|Logger|LOG|log)\.trace\s*\(`, ObjectType: "Logger", MethodName: "trace", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Log injection via Logger.trace", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "java.system.out.println", Category: taint.SnkLog, Language: rules.LangJava, Pattern: `System\.out\.println\s*\(`, ObjectType: "System.out", MethodName: "println", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "System.out.println with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},
		{ID: "java.system.err.println", Category: taint.SnkLog, Language: rules.LangJava, Pattern: `System\.err\.println\s*\(`, ObjectType: "System.err", MethodName: "println", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "System.err.println with potentially tainted data (log injection)", CWEID: "CWE-117", OWASPCategory: "A09:2021-Security Logging and Monitoring Failures"},

		// Hibernate HQL injection
		{ID: "java.hibernate.createquery", Category: taint.SnkSQLQuery, Language: rules.LangJava, Pattern: `(?:Session|session|entityManager)\.createQuery\s*\(`, ObjectType: "Session", MethodName: "createQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Hibernate createQuery with potential HQL injection via string concatenation", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.hibernate.createnativequery", Category: taint.SnkSQLQuery, Language: rules.LangJava, Pattern: `(?:Session|session|entityManager)\.createNativeQuery\s*\(`, ObjectType: "Session", MethodName: "createNativeQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Hibernate createNativeQuery with potential SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.hibernate.createsqlquery", Category: taint.SnkSQLQuery, Language: rules.LangJava, Pattern: `(?:Session|session)\.createSQLQuery\s*\(`, ObjectType: "Session", MethodName: "createSQLQuery", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Hibernate createSQLQuery with potential SQL injection", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// MyBatis ${} interpolation
		{ID: "java.mybatis.interpolation", Category: taint.SnkSQLQuery, Language: rules.LangJava, Pattern: `\$\{[^}]+\}`, ObjectType: "MyBatis", MethodName: "${}", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "MyBatis ${} string interpolation in SQL (use #{} for parameterized queries)", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		// Thymeleaf template injection
		{ID: "java.thymeleaf.utext", Category: taint.SnkHTMLOutput, Language: rules.LangJava, Pattern: `th:utext`, ObjectType: "Thymeleaf", MethodName: "th:utext", DangerousArgs: []int{0}, Severity: rules.High, Description: "Thymeleaf th:utext renders unescaped HTML (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.thymeleaf.attr.injection", Category: taint.SnkHTMLOutput, Language: rules.LangJava, Pattern: `th:attr`, ObjectType: "Thymeleaf", MethodName: "th:attr", DangerousArgs: []int{0}, Severity: rules.High, Description: "Thymeleaf th:attr with user-controlled attribute value", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// JSP scriptlet injection
		{ID: "java.jsp.scriptlet", Category: taint.SnkHTMLOutput, Language: rules.LangJava, Pattern: `<%=\s*[^%]*%>`, ObjectType: "JSP", MethodName: "<%=%>", DangerousArgs: []int{0}, Severity: rules.High, Description: "JSP expression tag outputs unescaped data (XSS)", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection"},

		// JNDI lookup (log4shell style)
		{ID: "java.jndi.initialcontext.lookup", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `(?:InitialContext|ctx|context)\.lookup\s*\(`, ObjectType: "InitialContext", MethodName: "lookup", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "JNDI lookup with user-controlled input (log4shell/RCE)", CWEID: "CWE-917", OWASPCategory: "A03:2021-Injection"},

		// Reflection-based code execution
		{ID: "java.reflection.class.forname", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `Class\.forName\s*\(`, ObjectType: "Class", MethodName: "forName", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Reflection Class.forName with user-controlled class name", CWEID: "CWE-470", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.reflection.method.invoke", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `(?:Method|method)\.invoke\s*\(`, ObjectType: "Method", MethodName: "invoke", DangerousArgs: []int{-1}, Severity: rules.Critical, Description: "Reflection Method.invoke with tainted arguments", CWEID: "CWE-470", OWASPCategory: "A03:2021-Injection"},

		// ReDoS via Pattern.compile
		{ID: "java.regex.pattern.compile", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `Pattern\.compile\s*\(`, ObjectType: "Pattern", MethodName: "compile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Pattern.compile with user-controlled regex (ReDoS)", CWEID: "CWE-1333", OWASPCategory: "A03:2021-Injection"},

		// Weak cryptography
		{ID: "java.crypto.cipher.getinstance", Category: taint.SnkCrypto, Language: rules.LangJava, Pattern: `Cipher\.getInstance\s*\(`, ObjectType: "Cipher", MethodName: "getInstance", DangerousArgs: []int{0}, Severity: rules.High, Description: "Cipher.getInstance with potentially weak algorithm (DES/ECB)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "java.crypto.messagedigest.md5", Category: taint.SnkCrypto, Language: rules.LangJava, Pattern: `MessageDigest\.getInstance\s*\(\s*["']MD5["']`, ObjectType: "MessageDigest", MethodName: "getInstance(MD5)", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak MD5 hash algorithm usage", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "java.crypto.messagedigest.sha1", Category: taint.SnkCrypto, Language: rules.LangJava, Pattern: `MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']`, ObjectType: "MessageDigest", MethodName: "getInstance(SHA1)", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Weak SHA-1 hash algorithm usage", CWEID: "CWE-328", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "java.crypto.insecure_random", Category: taint.SnkCrypto, Language: rules.LangJava, Pattern: `new\s+Random\s*\(|Math\.random\s*\(`, ObjectType: "Random", MethodName: "Random/Math.random", DangerousArgs: []int{-1}, Severity: rules.High, Description: "java.util.Random used for security (use SecureRandom instead)", CWEID: "CWE-338", OWASPCategory: "A02:2021-Cryptographic Failures"},
		{ID: "java.crypto.ecb_mode", Category: taint.SnkCrypto, Language: rules.LangJava, Pattern: `Cipher\.getInstance\s*\(\s*["'](?:DES|AES)/ECB`, ObjectType: "Cipher", MethodName: "getInstance(ECB)", DangerousArgs: []int{0}, Severity: rules.High, Description: "ECB mode cipher usage (no diffusion, use CBC/GCM)", CWEID: "CWE-327", OWASPCategory: "A02:2021-Cryptographic Failures"},

		// Jackson unsafe deserialization config
		{ID: "java.jackson.enabledefaulttyping", Category: taint.SnkDeserialize, Language: rules.LangJava, Pattern: `(?:ObjectMapper|objectMapper|mapper)\.enableDefaultTyping\s*\(`, ObjectType: "ObjectMapper", MethodName: "enableDefaultTyping", DangerousArgs: []int{-1}, Severity: rules.Critical, Description: "Jackson enableDefaultTyping enables polymorphic deserialization (RCE)", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures"},

		// Apache Commons file operations with tainted paths
		{ID: "java.commons.fileutils.writestringtofile", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `FileUtils\.writeStringToFile\s*\(`, ObjectType: "FileUtils", MethodName: "writeStringToFile", DangerousArgs: []int{0}, Severity: rules.High, Description: "Apache Commons FileUtils.writeStringToFile with tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.commons.fileutils.copyfile", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `FileUtils\.copyFile\s*\(`, ObjectType: "FileUtils", MethodName: "copyFile", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "Apache Commons FileUtils.copyFile with tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// HTTP header injection
		{ID: "java.servlet.setheader", Category: taint.SnkHeader, Language: rules.LangJava, Pattern: `response\.setHeader\s*\(`, ObjectType: "HttpServletResponse", MethodName: "setHeader", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP response header injection", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.servlet.addheader", Category: taint.SnkHeader, Language: rules.LangJava, Pattern: `response\.addHeader\s*\(`, ObjectType: "HttpServletResponse", MethodName: "addHeader", DangerousArgs: []int{1}, Severity: rules.Medium, Description: "HTTP response header injection via addHeader", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

		// Redis command injection (Jedis/Lettuce)
		{ID: "java.jedis.eval", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `(?:jedis|Jedis)\.eval\s*\(`, ObjectType: "Jedis", MethodName: "eval", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Redis Lua script evaluation with tainted script via Jedis", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.lettuce.dispatch", Category: taint.SnkCommand, Language: rules.LangJava, Pattern: `\.dispatch\s*\(`, ObjectType: "RedisCommands", MethodName: "dispatch", DangerousArgs: []int{0}, Severity: rules.High, Description: "Redis command dispatch with tainted arguments via Lettuce", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},

		// DNS lookup with tainted hostname
		{ID: "java.inetaddress.getbyname", Category: taint.SnkURLFetch, Language: rules.LangJava, Pattern: `InetAddress\.getByName\s*\(|InetAddress\.getAllByName\s*\(`, ObjectType: "InetAddress", MethodName: "getByName", DangerousArgs: []int{0}, Severity: rules.High, Description: "DNS lookup with tainted hostname (SSRF/DNS rebinding)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// SMTP email header injection (JavaMail)
		{ID: "java.javamail.transport.send", Category: taint.SnkHeader, Language: rules.LangJava, Pattern: `Transport\.send\s*\(|\.setRecipients\s*\(`, ObjectType: "javax.mail.Transport", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.High, Description: "JavaMail send with tainted headers/recipients (email injection)", CWEID: "CWE-93", OWASPCategory: "A03:2021-Injection"},

		// Docker exec (docker-java)
		{ID: "java.docker.execstart", Category: taint.SnkCommand, Language: rules.LangJava, Pattern: `\.execStartCmd\s*\(|\.execCreateCmd\s*\(`, ObjectType: "DockerClient", MethodName: "execCreateCmd", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Docker container exec with tainted command via docker-java", CWEID: "CWE-78", OWASPCategory: "A03:2021-Injection"},

		// Kafka message construction
		{ID: "java.kafka.producer.send", Category: taint.SnkCommand, Language: rules.LangJava, Pattern: `producer\.send\s*\(|KafkaProducer.*\.send\s*\(`, ObjectType: "KafkaProducer", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Kafka message produced with tainted data", CWEID: "CWE-77", OWASPCategory: "A03:2021-Injection"},

		// XPath injection
		{ID: "java.xpath.evaluate", Category: taint.SnkXPath, Language: rules.LangJava, Pattern: `(?:XPath|xpath)\.evaluate\s*\(`, ObjectType: "XPath", MethodName: "evaluate", DangerousArgs: []int{0}, Severity: rules.High, Description: "XPath evaluation with tainted expression", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.xpathexpression.evaluate", Category: taint.SnkXPath, Language: rules.LangJava, Pattern: `(?:XPathExpression|xpathExpr)\.evaluate\s*\(`, ObjectType: "XPathExpression", MethodName: "evaluate", DangerousArgs: []int{0}, Severity: rules.High, Description: "Compiled XPath evaluation with tainted input", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.xpathfactory.compile", Category: taint.SnkXPath, Language: rules.LangJava, Pattern: `XPathFactory.*\.newXPath\s*\(\s*\)\.compile\s*\(`, ObjectType: "XPathFactory", MethodName: "compile", DangerousArgs: []int{0}, Severity: rules.High, Description: "XPath compile with tainted expression string", CWEID: "CWE-643", OWASPCategory: "A03:2021-Injection"},

		// Template injection
		{ID: "java.velocity.mergetemplate", Category: taint.SnkTemplate, Language: rules.LangJava, Pattern: `(?:VelocityEngine|velocity|ve)\.mergeTemplate\s*\(|(?:Template|template)\.merge\s*\(`, ObjectType: "VelocityEngine", MethodName: "mergeTemplate", DangerousArgs: []int{0}, Severity: rules.High, Description: "Apache Velocity template merge with tainted data", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.freemarker.process", Category: taint.SnkTemplate, Language: rules.LangJava, Pattern: `(?:Template|template)\.process\s*\(`, ObjectType: "Template", MethodName: "process", DangerousArgs: []int{0}, Severity: rules.High, Description: "FreeMarker template processing with tainted data", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.pebble.evaluate", Category: taint.SnkTemplate, Language: rules.LangJava, Pattern: `(?:PebbleTemplate|template)\.evaluate\s*\(`, ObjectType: "PebbleTemplate", MethodName: "evaluate", DangerousArgs: []int{0}, Severity: rules.High, Description: "Pebble template evaluation with tainted data", CWEID: "CWE-1336", OWASPCategory: "A03:2021-Injection"},

		// LDAP injection (deeper coverage)
		{ID: "java.spring.ldaptemplate.search", Category: taint.SnkLDAP, Language: rules.LangJava, Pattern: `(?:LdapTemplate|ldapTemplate)\.search\s*\(`, ObjectType: "LdapTemplate", MethodName: "search", DangerousArgs: []int{0}, Severity: rules.High, Description: "Spring LDAP template search with tainted filter", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.jndi.initialdircontext.search", Category: taint.SnkLDAP, Language: rules.LangJava, Pattern: `(?:InitialDirContext|dirContext|ctx)\.search\s*\(`, ObjectType: "InitialDirContext", MethodName: "search", DangerousArgs: []int{1}, Severity: rules.High, Description: "JNDI LDAP search with tainted filter", CWEID: "CWE-90", OWASPCategory: "A03:2021-Injection"},

		// Expression Language injection
		{ID: "java.el.createvalueexpression", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `(?:ExpressionFactory|elFactory)\.createValueExpression\s*\(`, ObjectType: "ExpressionFactory", MethodName: "createValueExpression", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "EL expression evaluation with tainted input", CWEID: "CWE-917", OWASPCategory: "A03:2021-Injection"},
		{ID: "java.spring.spel.parseexpression", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `(?:SpelExpressionParser|expressionParser)\.parseExpression\s*\(`, ObjectType: "SpelExpressionParser", MethodName: "parseExpression", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "Spring Expression Language with tainted input", CWEID: "CWE-917", OWASPCategory: "A03:2021-Injection"},

		// HTTP Content-Type injection
		{ID: "java.servlet.setcontenttype", Category: taint.SnkHeader, Language: rules.LangJava, Pattern: `response\.setContentType\s*\(`, ObjectType: "HttpServletResponse", MethodName: "setContentType", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP Content-Type header with tainted value", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},

		// --- NIO File Operations (CWE-22) ---
		{ID: "java.nio.files.write", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `Files\.write\s*\(`, ObjectType: "Files", MethodName: "write", DangerousArgs: []int{0}, Severity: rules.High, Description: "NIO Files.write with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.nio.files.copy", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `Files\.copy\s*\(`, ObjectType: "Files", MethodName: "copy", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "NIO Files.copy with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.nio.files.move", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `Files\.move\s*\(`, ObjectType: "Files", MethodName: "move", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "NIO Files.move with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.nio.files.createsymboliclink", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `Files\.createSymbolicLink\s*\(`, ObjectType: "Files", MethodName: "createSymbolicLink", DangerousArgs: []int{0, 1}, Severity: rules.High, Description: "NIO symlink creation with potentially tainted paths (symlink attack)", CWEID: "CWE-59", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.nio.files.createdirectories", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `Files\.createDirectories\s*\(|Files\.createDirectory\s*\(`, ObjectType: "Files", MethodName: "createDirectories", DangerousArgs: []int{0}, Severity: rules.High, Description: "NIO directory creation with potentially tainted path", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},
		{ID: "java.nio.paths.get", Category: taint.SnkFileWrite, Language: rules.LangJava, Pattern: `Paths\.get\s*\(`, ObjectType: "Paths", MethodName: "get", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "Path construction with potentially tainted components", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control"},

		// --- SSRF via newer HTTP clients (CWE-918) ---
		{ID: "java.httpclient.send", Category: taint.SnkURLFetch, Language: rules.LangJava, Pattern: `HttpClient.*\.send\s*\(|httpClient\.send\s*\(`, ObjectType: "HttpClient", MethodName: "send", DangerousArgs: []int{0}, Severity: rules.High, Description: "Java 11+ HttpClient.send with potentially tainted request (SSRF)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "java.spring.webclient", Category: taint.SnkURLFetch, Language: rules.LangJava, Pattern: `WebClient.*\.uri\s*\(|webClient\.get\s*\(\s*\)\s*\.uri\s*\(`, ObjectType: "WebClient", MethodName: "uri", DangerousArgs: []int{0}, Severity: rules.High, Description: "Spring WebClient with potentially tainted URI (SSRF)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},
		{ID: "java.uri.create", Category: taint.SnkURLFetch, Language: rules.LangJava, Pattern: `URI\.create\s*\(`, ObjectType: "URI", MethodName: "create", DangerousArgs: []int{0}, Severity: rules.High, Description: "URI creation with potentially tainted string (SSRF)", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery"},

		// --- String.format injection (CWE-134) ---
		{ID: "java.string.format", Category: taint.SnkLog, Language: rules.LangJava, Pattern: `String\.format\s*\(`, ObjectType: "String", MethodName: "format", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "String.format with potentially tainted format string", CWEID: "CWE-134", OWASPCategory: "A03:2021-Injection"},

		// --- OGNL injection (CWE-917) ---
		{ID: "java.ognl.getvalue", Category: taint.SnkEval, Language: rules.LangJava, Pattern: `Ognl\.getValue\s*\(|OgnlUtil.*\.getValue\s*\(`, ObjectType: "Ognl", MethodName: "getValue", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "OGNL expression evaluation with tainted input (RCE)", CWEID: "CWE-917", OWASPCategory: "A03:2021-Injection"},

		// --- Cookie injection (CWE-113) ---
		{ID: "java.servlet.addcookie", Category: taint.SnkHeader, Language: rules.LangJava, Pattern: `response\.addCookie\s*\(`, ObjectType: "HttpServletResponse", MethodName: "addCookie", DangerousArgs: []int{0}, Severity: rules.Medium, Description: "HTTP cookie set with potentially tainted value", CWEID: "CWE-113", OWASPCategory: "A03:2021-Injection"},
	}
}
