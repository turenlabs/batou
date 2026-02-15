# Java Language Support

## Overview

GTSS provides comprehensive security scanning for Java code, covering Servlet-based web applications, Spring/Spring Boot, Hibernate/JPA, MyBatis, Thymeleaf, JSP, and common enterprise Java libraries. Analysis includes four layers: regex-based pattern rules (Layer 1), tree-sitter AST structural analysis providing comment-aware false positive filtering and structural code inspection (Layer 2), intraprocedural taint tracking with source-to-sink and sanitizer recognition (Layer 3), and interprocedural call graph analysis (Layer 4).

Java taint analysis uses the tree-sitter AST walker (`internal/taint/tsflow/`) which provides accurate tracking through assignments, variable declarations, method invocations, and field accesses by walking the parsed AST rather than relying on regex patterns.

## Detection

Java files are identified by the `.java` file extension. The `DetectLanguage` function in `internal/analyzer/analyzer.go` maps `.java` to the `LangJava` language constant. JSP files (`.jsp`) are not currently detected as a separate language type.

## Taint Analysis Coverage

Taint analysis tracks data flow from untrusted sources through the program to dangerous sinks, recognizing sanitizer functions that neutralize specific threat categories.

### Sources (31 tracked)

Sources are entry points where untrusted data enters the application.

#### Servlet Request (8)

| ID | Method | Description |
|---|---|---|
| `java.servlet.getparameter` | `request.getParameter()` | HTTP request parameter |
| `java.servlet.getheader` | `request.getHeader()` | HTTP request header |
| `java.servlet.getcookies` | `request.getCookies()` | HTTP request cookies |
| `java.servlet.getinputstream` | `request.getInputStream()` | HTTP request input stream |
| `java.servlet.getreader` | `request.getReader()` | HTTP request reader |
| `java.servlet.getpathinfo` | `request.getPathInfo()` | HTTP request path info |
| `java.servlet.getquerystring` | `request.getQueryString()` | HTTP request query string |
| `java.servlet.getrequesturi` | `request.getRequestURI()` | HTTP request URI |

#### Spring MVC Annotations (6)

| ID | Annotation | Description |
|---|---|---|
| `java.spring.requestparam` | `@RequestParam` | Request parameter binding |
| `java.spring.pathvariable` | `@PathVariable` | URL path variable |
| `java.spring.requestbody` | `@RequestBody` | Request body deserialization |
| `java.spring.requestheader` | `@RequestHeader` | Request header binding |
| `java.spring.cookievalue` | `@CookieValue` | Cookie value binding |
| `java.spring.matrixvariable` | `@MatrixVariable` | Matrix variable binding |

#### Environment / CLI (3)

| ID | Method | Description |
|---|---|---|
| `java.system.getenv` | `System.getenv()` | System environment variable |
| `java.main.args` | `args[]` | Main method arguments |
| `java.scanner.stdin` | `new Scanner(System.in)` | Scanner reading from stdin |

#### Database Results (3)

| ID | Method | Description |
|---|---|---|
| `java.resultset.getstring` | `ResultSet.getString()` | JDBC result set value |
| `java.mybatis.sqlsession.selectone` | `SqlSession.selectOne()` | MyBatis single result |
| `java.mybatis.sqlsession.selectlist` | `SqlSession.selectList()` | MyBatis list result |

#### Network / IO (3)

| ID | Method | Description |
|---|---|---|
| `java.bufferedreader.readline` | `BufferedReader.readLine()` | BufferedReader input (network/file) |
| `java.commons.ioutils.tostring` | `IOUtils.toString()` | Apache Commons IO stream read |
| `java.commons.fileutils.readfiletostring` | `FileUtils.readFileToString()` | Apache Commons file read |

#### Deserialization (1)

| ID | Method | Description |
|---|---|---|
| `java.jackson.readvalue` | `ObjectMapper.readValue()` | Jackson deserialized JSON data |

#### Framework-Specific (3)

| ID | Method | Description |
|---|---|---|
| `java.spring.securitycontext.getauthentication` | `SecurityContextHolder.getContext().getAuthentication()` | Spring Security auth context |
| `java.struts.actionform` | `ActionForm.get*()` | Struts ActionForm getter |
| `java.aws.lambda.event` | `implements RequestHandler` | AWS Lambda handler event data |

#### Cloud Service Sources (4)

| ID | Method | Description |
|---|---|---|
| `java.aws.sqs.receive` | `SqsClient.receiveMessage()` | AWS SQS message data |
| `java.aws.s3.getobject` | `S3Client.getObject()` | AWS S3 object data |
| `java.gcp.cloudfunctions.event` | `implements HttpFunction/BackgroundFunction` | GCP Cloud Functions event |
| `java.gcp.pubsub.pull` | `subscriber.pull()` | GCP Pub/Sub message data |

### Sinks (58 tracked)

Sinks are dangerous operations where tainted data can cause vulnerabilities.

#### SQL Injection (CWE-89)

| ID | Method | Severity |
|---|---|---|
| `java.sql.statement.execute` | `Statement.execute()` | Critical |
| `java.sql.statement.executequery` | `Statement.executeQuery()` | Critical |
| `java.sql.statement.executeupdate` | `Statement.executeUpdate()` | Critical |
| `java.hibernate.createquery` | `Session.createQuery()` (HQL) | Critical |
| `java.hibernate.createnativequery` | `Session.createNativeQuery()` | Critical |
| `java.hibernate.createsqlquery` | `Session.createSQLQuery()` | Critical |
| `java.mybatis.interpolation` | `${}` interpolation in SQL | Critical |

#### Command Injection (CWE-78)

| ID | Method | Severity |
|---|---|---|
| `java.runtime.exec` | `Runtime.getRuntime().exec()` | Critical |
| `java.processbuilder` | `new ProcessBuilder()` | Critical |
| `java.docker.execstart` | `DockerClient.execCreateCmd()` | Critical |
| `java.lettuce.dispatch` | `RedisCommands.dispatch()` | High |
| `java.kafka.producer.send` | `KafkaProducer.send()` | Medium |

#### XSS / HTML Output (CWE-79)

| ID | Method | Severity |
|---|---|---|
| `java.servlet.writer.write` | `response.getWriter().write()` | High |
| `java.servlet.writer.println` | `response.getWriter().println()` | High |
| `java.out.println.html` | `out.println("<...")` | High |
| `java.writer.println.html` | `writer.println("<...")` | High |
| `java.thymeleaf.utext` | `th:utext` (unescaped HTML) | High |
| `java.thymeleaf.attr.injection` | `th:attr` | High |
| `java.jsp.scriptlet` | JSP expression tags with unescaped output | High |

#### Redirect / Dispatch (CWE-601)

| ID | Method | Severity |
|---|---|---|
| `java.servlet.forward` | `RequestDispatcher.forward()` | High |
| `java.servlet.sendredirect` | `response.sendRedirect()` | High |
| `java.servlet.getrequestdispatcher` | `getRequestDispatcher()` | High |

#### File Operations (CWE-22)

| ID | Method | Severity |
|---|---|---|
| `java.file.new` | `new File()` | High |
| `java.fileoutputstream` | `new FileOutputStream()` | High |
| `java.filewriter` | `new FileWriter()` | High |
| `java.commons.fileutils.writestringtofile` | `FileUtils.writeStringToFile()` | High |
| `java.commons.fileutils.copyfile` | `FileUtils.copyFile()` | High |

#### SSRF (CWE-918)

| ID | Method | Severity |
|---|---|---|
| `java.url.new` | `new URL()` | High |
| `java.httpurlconnection` | `HttpURLConnection` | High |
| `java.spring.resttemplate` | `RestTemplate.getForObject()` | High |
| `java.inetaddress.getbyname` | `InetAddress.getByName()` | High |

#### Deserialization (CWE-502)

| ID | Method | Severity |
|---|---|---|
| `java.objectinputstream.readobject` | `ObjectInputStream.readObject()` | Critical |
| `java.xmldecoder.readobject` | `XMLDecoder.readObject()` | Critical |
| `java.jackson.enabledefaulttyping` | `ObjectMapper.enableDefaultTyping()` | Critical |

#### XML External Entity / XXE (CWE-611)

| ID | Method | Severity |
|---|---|---|
| `java.xml.documentbuilder.parse` | `DocumentBuilder.parse()` | High |
| `java.xml.saxparser.parse` | `SAXParser.parse()` | High |

#### Code Evaluation / JNDI (CWE-94, CWE-917)

| ID | Method | Severity |
|---|---|---|
| `java.scriptengine.eval` | `ScriptEngine.eval()` | Critical |
| `java.jndi.initialcontext.lookup` | `InitialContext.lookup()` | Critical |
| `java.reflection.class.forname` | `Class.forName()` | Critical |
| `java.reflection.method.invoke` | `Method.invoke()` | Critical |
| `java.regex.pattern.compile` | `Pattern.compile()` (ReDoS) | High |
| `java.jedis.eval` | `Jedis.eval()` (Redis Lua) | Critical |

#### LDAP Injection (CWE-90)

| ID | Method | Severity |
|---|---|---|
| `java.ldap.dircontext.search` | `DirContext.search()` | High |

#### Log Injection (CWE-117)

| ID | Method | Severity |
|---|---|---|
| `java.logger.info` | `Logger.info()` | Medium |
| `java.logger.debug` | `Logger.debug()` | Medium |
| `java.logger.warn` | `Logger.warn()` | Medium |
| `java.logger.error` | `Logger.error()` | Medium |
| `java.logger.trace` | `Logger.trace()` | Medium |
| `java.system.out.println` | `System.out.println()` | Medium |
| `java.system.err.println` | `System.err.println()` | Medium |

#### Cryptography (CWE-327, CWE-328, CWE-338)

| ID | Method | Severity |
|---|---|---|
| `java.crypto.cipher.getinstance` | `Cipher.getInstance()` with weak algorithm | High |
| `java.crypto.messagedigest.md5` | `MessageDigest.getInstance` with MD5 | Medium |
| `java.crypto.messagedigest.sha1` | `MessageDigest.getInstance` with SHA-1 | Medium |
| `java.crypto.insecure_random` | `new Random()` / `Math.random()` | High |
| `java.crypto.ecb_mode` | Cipher with insecure block mode (no diffusion) | High |

#### HTTP Header Injection (CWE-113)

| ID | Method | Severity |
|---|---|---|
| `java.servlet.setheader` | `response.setHeader()` | Medium |
| `java.servlet.addheader` | `response.addHeader()` | Medium |
| `java.javamail.transport.send` | `Transport.send()` / `setRecipients()` | High |

### Sanitizers (29 tracked)

Sanitizers neutralize tainted data for specific sink categories.

#### HTML Encoding

| ID | Method | Neutralizes |
|---|---|---|
| `java.stringescapeutils.escapehtml4` | `StringEscapeUtils.escapeHtml4()` | HTML output |
| `java.spring.htmlutils.htmlescape` | `HtmlUtils.htmlEscape()` | HTML output |
| `java.esapi.encodeforhtml` | `ESAPI.encoder().encodeForHTML()` | HTML output |
| `java.jsoup.clean` | `Jsoup.clean()` | HTML output |
| `java.owasp.encode.forhtml` | `Encode.forHtml()` | HTML output |
| `java.owasp.encode.forjavascript` | `Encode.forJavaScript()` | HTML output, eval |

#### SQL Parameterization

| ID | Method | Neutralizes |
|---|---|---|
| `java.preparedstatement` | `PreparedStatement` / `prepareStatement()` | SQL query |
| `java.hibernate.setparameter` | `Query.setParameter()` | SQL query |
| `java.mybatis.parameterized` | `#{} binding` | SQL query |

#### Type Coercion

| ID | Method | Neutralizes |
|---|---|---|
| `java.integer.parseint` | `Integer.parseInt()` | SQL query, command |
| `java.long.parselong` | `Long.parseLong()` | SQL query, command |

#### Path Traversal Prevention

| ID | Method | Neutralizes |
|---|---|---|
| `java.filenameutils.getname` | `FilenameUtils.getName()` | File write |

#### URL Encoding / Validation

| ID | Method | Neutralizes |
|---|---|---|
| `java.urlencoder.encode` | `URLEncoder.encode()` | Redirect, HTML output |
| `java.apache.urlvalidator` | `UrlValidator.isValid()` | URL fetch, redirect |
| `java.url.gethost` | `URL.getHost()` | URL fetch, redirect |

#### Input Validation

| ID | Method | Neutralizes |
|---|---|---|
| `java.validation.valid` | `@Valid` | SQL, command, HTML |
| `java.validation.pattern` | `@Pattern` | SQL, command, HTML |
| `java.validation.notnull` | `@NotNull/@Size/@Min/@Max/@Email` | SQL, command, HTML |
| `java.spring.validated` | `@Validated` | SQL, command, HTML |
| `java.validator.validate` | `Validator.validate()` | SQL, command, HTML, file |

#### LDAP Encoding

| ID | Method | Neutralizes |
|---|---|---|
| `java.esapi.encodeforldap` | `ESAPI.encoder().encodeForLDAP()` | LDAP |

#### CSRF Protection

| ID | Method | Neutralizes |
|---|---|---|
| `java.spring.csrf.token` | `CsrfToken` | HTML output, SQL |

#### Deserialization Safety

| ID | Method | Neutralizes |
|---|---|---|
| `java.jackson.activatedefaulttyping.safe` | `activateDefaultTyping()` with validator | Deserialize |

#### Cryptography

| ID | Method | Neutralizes |
|---|---|---|
| `java.crypto.bcrypt.hashpw` | `BCrypt.hashpw()` / `BCryptPasswordEncoder` | Crypto |
| `java.crypto.bcrypt.checkpw` | `BCrypt.checkpw()` | Crypto |
| `java.crypto.securerandom` | `new SecureRandom()` | Crypto |
| `java.crypto.messageconstanttime` | `MessageDigest.isEqual()` | Crypto |
| `java.crypto.mac.hmac` | `Mac.getInstance` with HMAC-SHA | Crypto |

#### Network Validation (SSRF Prevention)

| ID | Method | Neutralizes |
|---|---|---|
| `java.inetaddress.validate` | `InetAddress.isSiteLocalAddress()` / `isLoopbackAddress()` | URL fetch |

## Rule Coverage

Rules that explicitly include Java in their `Languages()` method, plus rules with `LangAny` that apply to all languages including Java.

### Injection (8 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-INJ-001` | SQLInjection | SQL queries built via string concatenation (`Statement.execute`, Hibernate HQL, etc.) |
| `GTSS-INJ-002` | CommandInjection | OS command construction with unsanitized input (`Runtime.exec`, `ProcessBuilder`) |
| `GTSS-INJ-004` | LDAPInjection | LDAP queries built with string concatenation |
| `GTSS-INJ-005` | TemplateInjection | Server-side template injection (Thymeleaf, Freemarker) |
| `GTSS-INJ-006` | XPathInjection | XPath queries built with string concatenation |
| `GTSS-INJ-007` | NoSQLInjection | Unsafe NoSQL/MongoDB query patterns |
| `GTSS-INJ-008` | GraphQLInjection | GraphQL queries built via string concatenation |
| `GTSS-INJ-009` | HTTPHeaderInjection | HTTP response headers set with `request.getParameter()` or `request.getHeader()` values without CRLF sanitization |

### XSS (4 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-XSS-008` | ServerSideRenderingXSS | JSP scriptlets, `th:utext`, `PrintWriter.write()` without escaping |
| `GTSS-XSS-011` | ReflectedXSS | Request parameters reflected directly in HTTP response body |
| `GTSS-XSS-014` | JavaHTMLStringConcat | `StringBuilder.append()` or string concatenation building HTML with user input from `@RequestParam`/`request.getParameter()` without OWASP Encoder |
| `GTSS-XSS-015` | JavaResponseWriterXSS | `response.getWriter().print()` with HTML concatenation, `String.format()` with HTML template and `%s`, Spring `@ResponseBody`/`@RestController` returning HTML via string concatenation |

### Cryptography (10 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-CRY-001` | WeakHashing | MessageDigest with broken hash algorithms used for security |
| `GTSS-CRY-002` | InsecureRandom | `Math.random()` or `java.util.Random` in security contexts |
| `GTSS-CRY-003` | WeakCipher | Broken or deprecated encryption algorithms and insecure cipher modes |
| `GTSS-CRY-004` | HardcodedIV | Hardcoded initialization vectors in encryption |
| `GTSS-CRY-006` | WeakKeySize | RSA keys below 2048 bits, insufficient symmetric key sizes |
| `GTSS-CRY-010` | WeakPRNG | `java.util.Random` in security-sensitive contexts |
| `GTSS-CRY-011` | PredictableSeed | Fixed or time-based seeds for Random |
| `GTSS-CRY-012` | HardcodedKey | Hardcoded AES keys and encryption secrets in source |
| `GTSS-CRY-013` | UnauthenticatedEncryption | CBC mode without HMAC/MAC authentication |
| `GTSS-CRY-014` | InsecureRSAPadding | PKCS#1 v1.5 padding (Bleichenbacher attack) |
| `GTSS-CRY-015` | WeakPasswordHash | Fast hashes used for password storage instead of bcrypt/Argon2 |

### Secrets (4 Java-specific rules + 4 with LangAny)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-SEC-001` | HardcodedPassword | Hardcoded passwords and credentials in string literals |
| `GTSS-SEC-002` | APIKeyExposure | Hardcoded API keys from known providers (LangAny) |
| `GTSS-SEC-003` | PrivateKeyInCode | PEM-encoded private keys embedded in source (LangAny) |
| `GTSS-SEC-004` | ConnectionString | Database connection strings with embedded credentials (LangAny) |
| `GTSS-SEC-005` | JWTSecret | Hardcoded JWT signing secrets |
| `GTSS-SEC-006` | EnvironmentLeak | `.env` contents and sensitive env vars logged (LangAny) |

### Authentication (3 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-AUTH-001` | HardcodedCredentialCheck | Passwords compared against string literals |
| `GTSS-AUTH-003` | CORSWildcard | Wildcard `*` in CORS origin configuration |
| `GTSS-AUTH-005` | WeakPasswordPolicy | Password validation with min length below 8 or missing complexity |
| `GTSS-AUTH-007` | PrivilegeEscalation | Privilege escalation patterns (CWE-269) |

### Generic (6 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-GEN-001` | DebugModeEnabled | Debug/verbose mode left enabled in production |
| `GTSS-GEN-002` | UnsafeDeserialization | `ObjectInputStream.readObject()`, `XMLDecoder` |
| `GTSS-GEN-003` | XXEVulnerability | XML parsing without disabled external entities |
| `GTSS-GEN-004` | OpenRedirect | `response.sendRedirect()` with user-controlled URL |
| `GTSS-GEN-005` | LogInjection | Unsanitized user input in log statements |
| `GTSS-GEN-009` | XMLParserMisconfig | XML parser configurations that explicitly enable external entities |
| `GTSS-GEN-012` | InsecureDownload | Insecure download patterns (CWE-494) |

### Logging (3 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-LOG-001` | UnsanitizedLogInput | User input passed directly to Logger/System.out |
| `GTSS-LOG-002` | CRLFLogInjection | String concatenation with user input in log calls |
| `GTSS-LOG-003` | SensitiveDataInLogs | Passwords, tokens, API keys logged |

### Validation (3 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-VAL-001` | DirectParamUsage | Request parameters used without any validation |
| `GTSS-VAL-002` | MissingTypeCoercion | User input used where a type is expected without parsing |
| `GTSS-VAL-003` | MissingLengthValidation | User input in DB operations without length validation |
| `GTSS-VAL-005` | FileUploadHardening | File upload without proper validation (CWE-434) |

### Traversal (4 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-TRV-001` | PathTraversal | File operations with unsanitized user input (LangAny) |
| `GTSS-TRV-003` | ArchiveExtraction | Zip/tar extraction without path validation (LangAny) |
| `GTSS-TRV-008` | NullByteFilePath | Null byte in file paths (LangAny) |
| `GTSS-TRV-010` | ZipSlipTraversal | `ZipEntry.getName()` used in `new File()` or `Paths.get()`/`Path.of()`/`resolve()` without `getCanonicalPath()` or `normalize()`+`startsWith()` validation |

### SSRF (2 rules with LangAny)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-SSRF-001` | URLFromUserInput | HTTP requests where URL comes from user input (LangAny) |
| `GTSS-SSRF-002` | InternalNetworkAccess | Requests to private IPs or cloud metadata endpoints (LangAny) |

### XXE (1 rule)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-XXE-001` | Java XXE Vulnerability | Java XML parsers (`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `XMLReader`, `SchemaFactory`) instantiated without disabling external entity processing. Checks for `setFeature()`/`setProperty()`/`setAttribute()` with `disallow-doctype-decl`, `external-general-entities`, `FEATURE_SECURE_PROCESSING`, or `ACCESS_EXTERNAL_DTD` nearby. |

### Deserialization (1 rule)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-DESER-001` | ExtendedDeserialization | `XStream.fromXML()` (many CVEs for RCE), `Kryo.readObject()`/`readClassAndObject()` without `setRegistrationRequired(true)`, `new XMLDecoder()` with untrusted data, and `SnakeYAML new Yaml()` without `SafeConstructor` (allows arbitrary object instantiation via `!!` tags) |

### Mass Assignment (1 rule)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-MASS-004` | MassAssignJava | Spring `@ModelAttribute` without `@InitBinder` field restrictions, and `BeanUtils.copyProperties()` that may copy unintended fields from user-controlled sources |

### CORS (2 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-CORS-001` | CORSWildcardCredentials | `@CrossOrigin(origins = "*")` or `allowedOrigins("*")` combined with `allowCredentials = true` in Spring CORS configuration |
| `GTSS-CORS-002` | CORSReflectedOrigin | Request `Origin` header reflected directly in `Access-Control-Allow-Origin` response header without validation (Java included in language list) |

### GraphQL (2 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-GQL-001` | GraphQL Introspection Enabled | GraphQL schema with introspection explicitly enabled (`.introspection(true)` in Java/Spring GraphQL), exposing the entire API schema for attacker reconnaissance |
| `GTSS-GQL-002` | GraphQL No Depth Limiting | GraphQL server created without query depth limiting or complexity analysis, allowing deeply nested queries that cause denial of service |

### Android Manifest (1 rule, from Kotlin rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-KT-005` | ExportedComponents | Android components (`<activity>`, `<service>`, `<receiver>`, `<provider>`) with `android:exported="true"` in `AndroidManifest.xml` without an `android:permission` attribute. ContentProviders and Services are flagged at High severity; Activities and BroadcastReceivers at Medium. Only scans files ending in `AndroidManifest.xml`. |

### Misconfiguration (1 rule)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-MISC-002` | ErrorDisclosure | `printStackTrace()` calls that may leak stack traces to clients, and exception details (`getMessage()`, `getStackTrace()`, `toString()`) written to HTTP response objects |
| `GTSS-MISC-003` | MissingSecurityHeaders | Missing security headers (CWE-1021, CWE-693) |

### Redirect (1 rule)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-REDIR-001` | ServerRedirectUserInput | `response.sendRedirect()` with `request.getParameter()` or user-controlled variable as the redirect destination, enabling open redirect attacks for phishing |

### Framework Rules -- Spring (10 rules)

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-FW-SPRING-001` | CSRFDisabled | Spring Security `http.csrf().disable()` or lambda DSL `csrf(csrf -> csrf.disable())` disabling CSRF protection |
| `GTSS-FW-SPRING-002` | OverlyPermissiveAccess | `antMatchers("/**").permitAll()` or `anyRequest().permitAll()` bypassing authentication on all endpoints |
| `GTSS-FW-SPRING-003` | InsecureCORS | `setAllowedOrigins("*")` with `setAllowCredentials(true)`, `@CrossOrigin` without origin restrictions or with wildcard origins |
| `GTSS-FW-SPRING-004` | ActuatorExposure | Actuator endpoints with `permitAll()`, `management.endpoints.web.exposure.include=*`, or `management.security.enabled=false` exposing sensitive operational data |
| `GTSS-FW-SPRING-005` | NativeQueryInjection | `@Query(nativeQuery=true)` with string concatenation, `EntityManager.createNativeQuery()` or `createQuery()` with string concatenation (SQL/HQL injection) |
| `GTSS-FW-SPRING-006` | MassAssignment | `@ModelAttribute` on controller parameters without `@InitBinder` defining `setAllowedFields()` or `setDisallowedFields()` |
| `GTSS-FW-SPRING-007` | InsecureCookie | `setHttpOnly(false)` allowing JavaScript cookie access, `setSecure(false)` allowing cookie transmission over HTTP |
| `GTSS-FW-SPRING-008` | FrameOptionsDisabled | `frameOptions().disable()` removing clickjacking protection, `headers().disable()` removing all security headers |
| `GTSS-FW-SPRING-009` | DispatcherForward | `getRequestDispatcher(variable).forward()` with user-controlled path, `new ModelAndView(variable)` with user-controlled view name in controllers handling user input |
| `GTSS-FW-SPRING-010` | SessionFixation | `sessionFixation().none()` disabling session fixation protection, allowing attackers to fix a session ID before authentication |

## Example Detections

### SQL Injection via String Concatenation

GTSS flags `Statement.executeQuery()` with a query built by concatenating user input from `request.getParameter()`:

```java
// DETECTED: GTSS-INJ-001 + taint flow java.servlet.getparameter -> java.sql.statement.executequery
String userId = request.getParameter("id");
Statement stmt = conn.createStatement();
String query = "SELECT * FROM users WHERE id = '" + userId + "'";
ResultSet rs = stmt.executeQuery(query);
```

### Reflected XSS in Servlet Response

GTSS detects request parameters written directly to the HTTP response without encoding:

```java
// DETECTED: GTSS-XSS-008 + taint flow java.servlet.getparameter -> java.servlet.writer.println
String name = request.getParameter("name");
PrintWriter out = response.getWriter();
out.println("<h1>Hello, " + name + "</h1>");
```

### OS Command Injection via Runtime.exec

GTSS catches command strings built with user input passed to `Runtime.exec()`:

```java
// DETECTED: GTSS-INJ-002 + taint flow java.servlet.getparameter -> java.runtime.exec
String host = request.getParameter("host");
String cmd = "ping -c 3 " + host;
Process process = Runtime.getRuntime().exec(cmd);
```

## Safe Patterns

### Parameterized SQL with PreparedStatement

GTSS recognizes `PreparedStatement` as a sanitizer that neutralizes SQL injection. This code does not trigger findings:

```java
// SAFE: PreparedStatement neutralizes SQL injection
String userId = request.getParameter("id");
PreparedStatement ps = conn.prepareStatement(
        "SELECT id, username, email FROM users WHERE id = ?");
ps.setString(1, userId);
ResultSet rs = ps.executeQuery();
```

### HTML Output with OWASP Encoder

GTSS recognizes `Encode.forHtml()` as a sanitizer for HTML output sinks:

```java
// SAFE: OWASP Encoder neutralizes XSS
String name = request.getParameter("name");
PrintWriter out = response.getWriter();
out.println("<h1>Hello, " + Encode.forHtml(name) + "</h1>");
```

### Command Execution with Allowlist Validation

GTSS recognizes allowlist validation patterns that prevent command injection:

```java
// SAFE: allowlist check prevents injection
private static final Set<String> ALLOWED = new HashSet<>(
        Arrays.asList("status", "version", "health"));

String action = request.getParameter("action");
if (!ALLOWED.contains(action)) {
    response.sendError(400, "Invalid action");
    return;
}
ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/tool", "--action", action);
```

## Limitations

- **JSP files**: The `.jsp` extension is not mapped in the language detector. JSP-specific patterns (like expression tag scriptlets) are defined as Java sinks but will only be matched when JSP content appears in `.java` files (e.g., inline template strings). Standalone `.jsp` files are not scanned.
- **Annotation-only sources**: Spring annotations like `@RequestParam` are detected as sources, but the association between the annotation and the specific method parameter it decorates is not tracked through the parameter's variable name with full precision. The taint engine matches the annotation presence rather than the specific annotated variable binding.
- **Struts/Legacy frameworks**: Struts ActionForm support is limited to `form.get*()` getter patterns. Advanced Struts 2 OGNL injection patterns are not covered.
- **Spring Expression Language (SpEL)**: SpEL injection (`#{...}` in Spring contexts) is not tracked as a dedicated sink.
- **Limited Android-specific rules**: The only Android rule covering Java is `GTSS-KT-005` (ExportedComponents in `AndroidManifest.xml`). Other Android-specific security patterns (Intent injection, WebView vulnerabilities, insecure SharedPreferences) are covered only for Kotlin. Java-specific Android patterns (exported components without manifest scanning, content provider SQL injection in Java code) are not covered.
- **Build configuration files**: Maven `pom.xml` and Gradle `build.gradle` files are not scanned for dependency vulnerabilities or insecure plugin configurations.
- **SSRF rules**: While taint analysis tracks Java-specific SSRF sinks (`new URL()`, `HttpURLConnection`, `RestTemplate`), the SSRF regex rules (GTSS-SSRF-003 DNS Rebinding, GTSS-SSRF-004 Redirect Following) do not include Java-specific patterns -- they apply via `LangAny` or are limited to other languages.
- **Session management**: The GTSS-AUTH-004 SessionFixation rule does not include Java in its language list. However, GTSS-FW-SPRING-010 detects Spring Security configurations that disable session fixation protection (`sessionFixation().none()`). Servlet-level session fixation patterns (`request.getSession()` without invalidation outside Spring Security) are not detected.
- **Race conditions**: The GTSS-GEN-006 RaceCondition rule does not include Java. Java-specific TOCTOU patterns with `synchronized` blocks are not checked.
- **Limited Kotlin/Android overlap**: The Kotlin rule `GTSS-KT-005` (ExportedComponents) includes `LangJava` and scans `AndroidManifest.xml` files for exported components without permission protection. Other Kotlin rules (KT-001 through KT-004, KT-006 through KT-008) target Kotlin-only patterns and do not apply to `.java` files. Kotlin (`.kt`) source files are not detected by the Java language detector.
