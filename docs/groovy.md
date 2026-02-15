# Groovy Language Support

## Overview

GTSS provides comprehensive security scanning for Groovy code, covering Grails web applications, Jenkins pipeline scripts (Jenkinsfile), and general Groovy applications. Analysis includes four layers: regex-based pattern rules (348 rules, including 10 Groovy-specific rules), tree-sitter AST structural analysis (comment-aware false positive filtering and structural code inspection via `internal/analyzer/`), intraprocedural taint tracking (source to sink with sanitizer recognition), and interprocedural call graph analysis.

Groovy taint analysis uses the tree-sitter AST walker (`internal/taint/tsflow/`) which provides accurate tracking through assignments, method calls, and property accesses by walking the parsed AST rather than relying on regex patterns.

Groovy runs on the JVM and shares many security concerns with Java, but introduces unique risks through GString interpolation, the `.execute()` method on strings, and Jenkins pipeline DSL patterns.

## Detection

Groovy files are identified by the following file extensions and filenames:

| Extension/Filename | Language Constant |
|---|---|
| `.groovy` | `LangGroovy` |
| `.gvy` | `LangGroovy` |
| `.gy` | `LangGroovy` |
| `.gsh` | `LangGroovy` |
| `.gsp` | `LangGroovy` |
| `Jenkinsfile` | `LangGroovy` |

The `DetectLanguage` function in `internal/analyzer/analyzer.go` maps these to the `LangGroovy` language constant.

## Rules (10)

### GTSS-GVY-001: Command Injection (Critical)

Detects command injection via Groovy's `String.execute()`, `Runtime.exec`, or `ProcessBuilder` with user-controlled input.

**Patterns detected:**
- `"command ${userInput}".execute()` - GString interpolation in `.execute()`
- `["cmd", "/c", var].execute()` - List `.execute()` with variables
- `Runtime.getRuntime().exec(cmd)` - Runtime.exec with tainted input
- `new ProcessBuilder(cmd)` - ProcessBuilder with tainted input

**CWE:** CWE-78 (OS Command Injection)

### GTSS-GVY-002: Code Injection (Critical)

Detects code injection via `GroovyShell.evaluate`, `Eval.me`, and `GroovyScriptEngine` with user-controlled input.

**Patterns detected:**
- `new GroovyShell().evaluate(userInput)`
- `shell.evaluate(script)` / `shell.parse(script)`
- `Eval.me(expr)` / `Eval.x(x, expr)` / `Eval.xy(x, y, expr)`
- `GroovyScriptEngine.run(scriptName, binding)`

**CWE:** CWE-94 (Code Injection)

### GTSS-GVY-003: SQL Injection (Critical)

Detects SQL injection via GString interpolation or string concatenation in Groovy SQL methods.

**Patterns detected:**
- `sql.execute("DELETE FROM users WHERE id = ${id}")`
- `sql.rows("SELECT * FROM users WHERE name = '${name}'")`
- `sql.firstRow("SELECT * FROM users WHERE id = ${id}")`
- `sql.executeUpdate("UPDATE ... SET name = '${name}'")`
- `sql.execute("DELETE FROM users WHERE id = " + id)`
- `sql.rows("SELECT ... WHERE name = '" + name + "'")`

**Safe alternatives:** `sql.rows("SELECT * FROM users WHERE name = ?", [name])`

**CWE:** CWE-89 (SQL Injection)

### GTSS-GVY-004: Jenkins Pipeline Injection (Critical)

Detects Jenkins pipeline script injection via GString interpolation in `sh`/`bat` steps or unsafe `load`.

**Patterns detected:**
- `sh "echo ${params.USER_INPUT}"` - GString in sh step
- `sh(script: "deploy.sh ${params.BRANCH}")` - GString in script parameter
- `bat "echo ${params.USER_INPUT}"` - GString in bat step
- `load ${env.SCRIPT_PATH}` - Variable in load step

**Safe alternative:** `sh 'echo $USER_INPUT'` (single-quoted, shell expansion only)

**CWE:** CWE-78 (OS Command Injection)

### GTSS-GVY-005: GString Injection (High)

Detects GString interpolation used in security-sensitive contexts like LDAP queries.

**Patterns detected:**
- `ldap.search("uid=${username},ou=users")` - GString in LDAP query

**CWE:** CWE-74 (Injection)

### GTSS-GVY-006: Grails Mass Assignment (High)

Detects Grails mass assignment via direct `params` binding without allowed fields or command objects.

**Patterns detected:**
- `new User(params)` - Domain object created with raw params
- `user.properties = params` - Domain properties set from params
- `bindData(user, params)` - bindData without field restrictions

**Safe alternatives:**
- Command objects with `@Validateable`
- `bindData(user, params, [include: ['name', 'email']])`

**CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

### GTSS-GVY-007: XXE via XmlSlurper/XmlParser (High)

Detects XML parsing via `XmlSlurper` or `XmlParser` without disabling external entities.

**Patterns detected:**
- `new XmlSlurper()` without `setFeature("...disallow-doctype-decl", true)`
- `new XmlParser()` without XXE protection

**CWE:** CWE-611 (XXE)

### GTSS-GVY-008: Insecure Deserialization (Critical)

Detects insecure deserialization via `ObjectInputStream`, `XStream`, or `SnakeYAML` in Groovy context.

**Patterns detected:**
- `new ObjectInputStream(input).readObject()`
- `new XStream().fromXML(xml)` / `xstream.fromXML(xml)`
- `new Yaml().load(yamlStr)` / `yaml.load(yamlStr)` (without SafeConstructor)

**Safe alternative:** `new Yaml(new SafeConstructor()).load(yamlStr)`

**CWE:** CWE-502 (Deserialization of Untrusted Data)

### GTSS-GVY-009: Jenkins Credentials Leak (High)

Detects Jenkins credentials leaked via `sh`/`echo` steps or print statements in pipeline scripts.

**Patterns detected:**
- `sh "curl -H 'Authorization: Bearer ${TOKEN}'"` - Credential in sh GString
- `echo "The secret is ${SECRET}"` - Credential in echo
- `println PASSWORD` - Credential in print statement

Only triggers in files that use `withCredentials()` or `credentials()`.

**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

### GTSS-GVY-010: Grails XSS (High)

Detects XSS via unescaped output in Grails GSP views using `${}` without `encodeAsHTML` or `raw()`.

**Patterns detected:**
- `${user.name}` in HTML context without encoding (GSP files)
- `.raw(user.bio)` - Explicit raw output bypassing encoding

**Safe alternatives:**
- `${user.name.encodeAsHTML()}`
- Set `grails.views.default.codec = 'html'` in Config.groovy

**CWE:** CWE-79 (Cross-Site Scripting)

## Taint Analysis Coverage

Taint analysis tracks data flow from untrusted sources through the program to dangerous sinks, recognizing sanitizer functions that neutralize specific threat categories.

### Sources (16 tracked)

| Category | ID | Description |
|---|---|---|
| Grails | `groovy.grails.params` | Request parameters |
| Grails | `groovy.grails.request.getparameter` | Servlet request parameter |
| Grails | `groovy.grails.request.json` | JSON request body |
| Grails | `groovy.grails.session` | Session data |
| Grails | `groovy.grails.cookies` | Cookie values |
| Jenkins | `groovy.jenkins.env` | Environment variables |
| Jenkins | `groovy.jenkins.params` | Build parameters |
| Jenkins | `groovy.jenkins.currentbuild` | Current build properties |
| Jenkins | `groovy.jenkins.input` | User input step |
| System | `groovy.system.getenv` | System.getenv() |
| CLI | `groovy.args` | Command-line arguments |
| IO | `groovy.inputstream` | Input streams |
| IO | `groovy.jsonslurper` | JsonSlurper parsing |
| Network | `groovy.url.text` | URL content as text |
| File | `groovy.file.text` | File content |
| Database | `groovy.sql.rows` | SQL query results |

### Sinks (38 tracked)

| Category | ID | Description |
|---|---|---|
| Command | `groovy.string.execute` | String.execute() |
| Command | `groovy.runtime.exec` | Runtime.exec() |
| Command | `groovy.processbuilder` | ProcessBuilder |
| Code Eval | `groovy.groovyshell.evaluate` | GroovyShell.evaluate() |
| Code Eval | `groovy.groovyshell.parse` | GroovyShell.parse() |
| Code Eval | `groovy.eval.me` | Eval.me/x/xy |
| Code Eval | `groovy.scriptengine.eval` | ScriptEngine.eval() |
| SQL | `groovy.sql.execute` | Sql.execute() |
| SQL | `groovy.sql.rows` | Sql.rows() |
| SQL | `groovy.sql.firstrow` | Sql.firstRow() |
| SQL | `groovy.sql.executeupdate` | Sql.executeUpdate() |
| File | `groovy.file.new` | new File() |
| File | `groovy.fileoutputstream` | FileOutputStream |
| Redirect | `groovy.grails.redirect` | Grails redirect |
| XXE | `groovy.xmlslurper.parse` | XmlSlurper.parse() |
| XXE | `groovy.xmlparser.parse` | XmlParser.parse() |
| Deserialize | `groovy.objectinputstream` | ObjectInputStream |
| HTML | `groovy.markupbuilder` | MarkupBuilder |

### Sanitizers (11 tracked)

| ID | Description | Neutralizes |
|---|---|---|
| `groovy.sql.prepared` | PreparedStatement / execute with params list | SQL |
| `groovy.sql.params.list` | rows/firstRow/executeUpdate with params list | SQL |
| `groovy.htmlutils.htmlescape` | HtmlUtils.htmlEscape() | HTML, Template |
| `groovy.stringescapeutils` | StringEscapeUtils.escapeHtml/escapeXml | HTML, Template |
| `groovy.encodeashtml` | .encodeAsHTML() Grails codec | HTML, Template |
| `groovy.encodeasurl` | .encodeAsURL() Grails codec | HTML, Redirect |
| `groovy.spring.secured` | @Secured annotation | Redirect, File |
| `groovy.spring.preauthorize` | @PreAuthorize annotation | Redirect, File |
| `groovy.integer.parseint` | Integer.parseInt / toInteger | SQL, Command, File |
| `groovy.commandobject` | Grails @Validateable command object | SQL, Command, HTML |
| `groovy.xmlslurper.secure` | setFeature(disallow-doctype-decl) | XPath/XXE |

## Cross-Language Rules Applicable to Groovy

Rules with `LangAny` also apply to Groovy files:

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-SEC-001 | HardcodedPassword | High | Hardcoded passwords and credentials |
| GTSS-SEC-002 | APIKeyExposure | High | Hardcoded API keys from known providers |
| GTSS-GEN-001 | DebugModeEnabled | Medium | Debug mode left enabled |
| GTSS-AUTH-007 | PrivilegeEscalation | High | Privilege escalation patterns (CWE-269) |
| GTSS-GEN-012 | InsecureDownload | High | Insecure download patterns (CWE-494) |
| GTSS-MISC-003 | MissingSecurityHeaders | Medium | Missing security headers (CWE-1021, CWE-693) |
| GTSS-VAL-005 | FileUploadHardening | High | File upload hardening (CWE-434) |

## Test Coverage

- `internal/rules/groovy/groovy_test.go` - 47 test cases covering all 10 rules
- `testdata/fixtures/groovy/vulnerable/` - Vulnerable Groovy samples (6 files)
- `testdata/fixtures/groovy/safe/` - Safe Groovy samples (4 files)
