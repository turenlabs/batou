# Go Language Support

## Overview

GTSS provides deep security scanning for Go code, covering the standard library (`net/http`, `database/sql`, `os/exec`, `crypto/*`), popular web frameworks (Gin, Echo, Fiber, Beego), routers (gorilla/mux, chi), ORMs (GORM), logging libraries (slog, zap, logrus), and cloud SDKs (AWS Lambda/SQS/S3, GCP Cloud Functions/Pub/Sub). Go is one of the most comprehensively covered languages, with Go-specific regex rules, taint source-to-sink tracking, and interprocedural call graph analysis.

## Detection

Go files are identified by the `.go` file extension. Detection is handled in `internal/analyzer/analyzer.go`:

| Extension | Language Constant |
|-----------|-------------------|
| `.go`     | `rules.LangGo`   |

Files matching `.go` are scanned through all three analysis layers:
- **Layer 1**: Regex-based rules (pattern matching on source code)
- **Layer 2**: Taint analysis (source-to-sink tracking with sanitizer recognition)
- **Layer 3**: Interprocedural call graph analysis (cross-function data flow)

Test files (paths matching `_test.go`) are excluded from scanning to reduce false positives.

## Taint Analysis Coverage

The Go taint catalog is defined in `internal/taint/languages/go_*.go` and tracks 30 sources, 48 sinks, and 28 sanitizers.

### Sources (User Input Entry Points)

#### HTTP Request Input (net/http)

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `go.http.request.formvalue` | `.FormValue(` | HTTP form parameter |
| `go.http.request.url.query` | `.URL.Query()` | URL query parameters |
| `go.http.request.body` | `r.Body` | HTTP request body |
| `go.http.request.header` | `r.Header.Get(` | HTTP request header |
| `go.http.request.cookie` | `r.Cookie(` | HTTP cookie value |
| `go.http.request.pathvalue` | `r.PathValue(` | URL path parameter (Go 1.22+) |
| `go.http.request.postform` | `r.PostFormValue(` | POST form value |
| `go.http.request.multipart` | `r.MultipartForm` | Multipart form data |

#### Framework-Specific Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `go.gin.context` | `c.Query(`, `c.Param(`, `c.PostForm(`, `c.GetHeader(` | Gin framework |
| `go.echo.context` | `c.QueryParam(`, `c.Param(`, `c.FormValue(` | Echo framework |
| `go.fiber.context` | `c.Query(`, `c.Params(`, `c.Body(` | Fiber framework |
| `go.beego.controller.input` | `.GetString(`, `.Input()` | Beego framework |
| `go.gorilla.mux.vars` | `mux.Vars(` | gorilla/mux route variables |
| `go.chi.urlparam` | `chi.URLParam(` | chi router URL parameter |

#### OS and I/O Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `go.os.args` | `os.Args` | Command-line arguments |
| `go.os.stdin` | `os.Stdin` | Standard input |
| `go.os.getenv` | `os.Getenv(` | Environment variable |
| `go.io.readall` | `io.ReadAll(` | Read all bytes from reader |
| `go.bufio.scanner` | `scanner.Text()` | Scanner text input |
| `go.net.conn` | `conn.Read(` | Network connection read |

#### Database and Deserialization

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `go.database.rows` | `rows.Scan(` | Database row scan result |
| `go.json.newdecoder` | `json.NewDecoder(` | JSON decoder from untrusted reader |

#### gRPC

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `go.grpc.metadata` | `metadata.FromIncomingContext(` | gRPC incoming request metadata |
| `go.grpc.stream.recv` | `.Recv(` | gRPC server stream receive |

#### Cloud SDKs

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `go.aws.lambda.event` | Lambda handler signature | AWS Lambda event data |
| `go.aws.sqs.receive` | `sqs.ReceiveMessage(` | AWS SQS message data |
| `go.aws.s3.getobject` | `s3.GetObject(` | AWS S3 object data |
| `go.gcp.cloudfunctions.event` | Cloud Function handler signature | GCP Cloud Functions event |
| `go.gcp.pubsub.receive` | `sub.Receive(` | GCP Pub/Sub message data |

### Sinks (Dangerous Functions)

#### SQL Injection (CWE-89)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `go.database.sql.query` | `db.Query(` | Critical | SQL query execution |
| `go.database.sql.exec` | `db.Exec(` | Critical | SQL exec execution |
| `go.database.sql.queryrow` | `db.QueryRow(` | Critical | SQL query row |
| `go.database.sql.prepare` | `db.Prepare(` | High | SQL prepare with tainted string |
| `go.gorm.raw` | `db.Raw(` | Critical | GORM raw SQL query |
| `go.gorm.exec` | `db.Exec(` | Critical | GORM exec |
| `go.gorm.where.string` | `db.Where(` | High | GORM Where with string condition |

#### Command Injection (CWE-78)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `go.os.exec.command` | `exec.Command(` | Critical | OS command execution |
| `go.os.exec.commandcontext` | `exec.CommandContext(` | Critical | OS command with context |
| `go.docker.containerexec` | `.ContainerExecCreate(` | Critical | Docker container exec |
| `go.redis.do` | `rdb.Do(` | High | Redis command execution |
| `go.redis.eval` | `.Eval(` | Critical | Redis Lua script evaluation |
| `go.kafka.produce` | `.Produce(` / `writer.WriteMessages(` | Medium | Kafka message production |

#### Path Traversal / File Operations (CWE-22)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `go.os.open` | `os.Open(` | High | File open with tainted path |
| `go.os.create` | `os.Create(` | High | File create with tainted path |
| `go.os.writefile` | `os.WriteFile(` | High | File write with tainted path |
| `go.os.remove` | `os.Remove(` | High | File removal with tainted path |
| `go.filepath.join` | `filepath.Join(` | Medium | Path construction with tainted component |
| `go.template.parsefiles` | `template.ParseFiles(` | High | Template parsed from tainted file path |

#### XSS / HTML Output (CWE-79)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `go.template.html` | `template.HTML(` | High | Unescaped HTML template output |
| `go.fmt.fprintf.response` | `fmt.Fprintf(w, ...` | Medium | Formatted write to HTTP response |
| `go.responsewriter.write` | `w.Write(` | Medium | Direct write to HTTP response |
| `go.fmt.fprint.response` | `fmt.Fprint(w, ...` | Medium | Unformatted write to HTTP response |
| `go.fmt.fprintln.response` | `fmt.Fprintln(w, ...` | Medium | Line write to HTTP response |
| `go.text.template.execute` | `tmpl.Execute(` | High | text/template execution (no auto-escaping) |

#### SSRF (CWE-918)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `go.http.get` | `http.Get(` | High | HTTP GET with tainted URL |
| `go.http.newrequest` | `http.NewRequest(` | High | HTTP request with tainted URL |
| `go.net.lookup` | `net.LookupHost(` / `net.LookupIP(` | High | DNS lookup with tainted hostname |

#### Open Redirect (CWE-601)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `go.http.redirect` | `http.Redirect(` | High | HTTP redirect with tainted URL |

#### Log Injection (CWE-117)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `go.log.printf` | `log.Printf(` | Medium | Standard library log |
| `go.log.println` | `log.Println(` | Medium | Standard library log |
| `go.slog.info/warn/error/debug` | `slog.Info(` etc. | Medium | Structured logging (slog) |
| `go.zap.info/error` | `logger.Info(` etc. | Medium | Zap logger |
| `go.logrus.info` | `logrus.Info(` etc. | Medium | Logrus logger |

#### Cryptographic Sinks

Detects weak hash algorithms, deprecated ciphers, insecure random sources, and hardcoded keys. The full list of crypto sink IDs is defined in `internal/taint/languages/go_sinks.go`. Key entries:

- **Weak hashes**: `go.crypto.md5`, `go.crypto.sha1` (CWE-328)
- **Deprecated ciphers**: Sink IDs for deprecated block and stream cipher packages (CWE-327)
- **Insecure PRNG**: `go.crypto.math_rand` (CWE-338)
- **Hardcoded keys**: `go.crypto.hardcoded_key` (CWE-321)
- **Insecure cipher mode**: `go.crypto.ecb_mode` (CWE-327)

#### Other Sinks

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `go.ldap.search` | `.Search(` | High | LDAP search with tainted filter |
| `go.net.smtp.sendmail` | `smtp.SendMail(` | High | SMTP with tainted headers |
| `go.json.decoder.decode` | `.Decode(` | Medium | JSON decode from untrusted source |

### Sanitizers

| Sanitizer ID | Pattern | Neutralizes | Description |
|-------------|---------|-------------|-------------|
| `go.html.escapestring` | `html.EscapeString(` | HTML output | HTML entity escaping |
| `go.url.queryescape` | `url.QueryEscape(` | HTML output, redirect | URL query escaping |
| `go.url.pathescape` | `url.PathEscape(` | Redirect, file write | URL path escaping |
| `go.filepath.base` | `filepath.Base(` | File write | Strips directory traversal |
| `go.strconv.atoi` | `strconv.Atoi(` | SQL, command, file | Integer conversion |
| `go.strconv.parseint` | `strconv.ParseInt(` | SQL, command | Integer parsing |
| `go.prepared.stmt` | `stmt.Query(` / `stmt.Exec(` | SQL | Prepared statement execution |
| `go.template.execute` | `.Execute(` / `.ExecuteTemplate(` | HTML output | html/template auto-escaping |
| `go.html.template.new` | `template.Must(` | HTML output, template | html/template auto-escaping |
| `go.validator` | `validate.Struct(` / `validate.Var(` | SQL, command | go-playground/validator |
| `go.gorm.parameterized` | `.Where(...?)` | SQL | GORM parameterized query |
| `go.bluemonday.sanitize` | `.Sanitize(` | HTML output, template | bluemonday HTML sanitizer |
| `go.strings.newline.strip` | `strings.ReplaceAll(...\n` | Header | Newline stripping for header injection |
| `go.regexp.quotemeta` | `regexp.QuoteMeta(` | SQL, command, HTML | Regex metacharacter escaping |
| `go.crypto.bcrypt.generate` | `bcrypt.GenerateFromPassword(` | Crypto | bcrypt password hashing |
| `go.crypto.bcrypt.compare` | `bcrypt.CompareHashAndPassword(` | Crypto | bcrypt verification |
| `go.crypto.argon2` | `argon2.IDKey(` | Crypto | Argon2 key derivation |
| `go.crypto.hmac` | `hmac.New(` / `hmac.Equal(` | Crypto | HMAC creation/verification |
| `go.crypto.subtle.constanttimecompare` | `subtle.ConstantTimeCompare(` | Crypto | Constant-time comparison |
| `go.gin.binding` | `.ShouldBindJSON(` / `.BindJSON(` | SQL, command, HTML, file | Gin struct binding |
| `go.echo.bind` | `.Bind(` | SQL, command, HTML | Echo request binding |
| `go.ozzo.validation` | `validation.ValidateStruct(` | SQL, command, HTML, file | ozzo-validation |
| `go.net.ip.parse` | `net.ParseIP(` | URL fetch | IP address validation |
| `go.net.cidr.contains` | `.Contains(` / `net.ParseCIDR(` | URL fetch | CIDR allowlist check |
| `go.net.url.hostname` | `.Hostname()` | URL fetch, redirect | URL hostname extraction |

## Rule Coverage

The following regex-based rules include Go in their `Languages()` method. Rules marked with "(any)" apply to all languages.

### Injection Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-INJ-001 | SQL Injection | Critical | `fmt.Sprintf` with SQL keywords; string concat with SQL keywords |
| GTSS-INJ-002 | Command Injection | Critical | `exec.Command("sh", "-c", ...)` shell invocation; `exec.Command` with string concat |
| GTSS-INJ-004 | LDAP Injection | High | LDAP filter concat, format string patterns |
| GTSS-INJ-005 | Template Injection (SSTI) | High | `template.Parse(variable)` with dynamic argument |
| GTSS-INJ-006 | XPath Injection | Medium | XPath query with string concat/format |
| GTSS-INJ-007 | NoSQL Injection | High | `$where` operator, query concat patterns |
| GTSS-INJ-008 | GraphQL Injection | High | `fmt.Sprintf` with GraphQL query/mutation keywords |

### XSS Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-XSS-004 | Unescaped Template Output | High | `template.HTML()` bypassing auto-escaping |
| GTSS-XSS-006 | Response Header Injection | High | `w.Header().Set(key, userInput)` |
| GTSS-XSS-008 | Server-Side Rendering XSS | High | `fmt.Fprintf(w, "<html>...%s", userInput)` |
| GTSS-XSS-009 | Missing Content-Type | Medium | HTML written to `w.Write()` without Content-Type header |
| GTSS-XSS-011 | Reflected XSS | High | `fmt.Fprintf(w, ..., r.FormValue(...))` |

### Traversal Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-TRV-001 | Path Traversal | Critical | `os.Open/ReadFile/Create(variable)` without `filepath.Clean` + `strings.HasPrefix` guard |
| GTSS-TRV-003 | Archive Extraction (Zip Slip) | High | `zip.OpenReader` / `os.Create` from zip entry without path validation |
| GTSS-TRV-004 | Symlink Following | Medium | `os.Readlink()` without subsequent path validation (Go-only rule) |

### Cryptographic Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-CRY-001 | Weak Hashing | High | `md5.New()`, `md5.Sum()`, `sha1.New()`, `sha1.Sum()` |
| GTSS-CRY-002 | Insecure Random | High | `math/rand` import + `rand.Int/Intn/Read` in security context |
| GTSS-CRY-003 | Weak Cipher | Critical | Deprecated cipher constructors and insecure modes |
| GTSS-CRY-004 | Hardcoded IV | High | `iv := []byte{...}` patterns |
| GTSS-CRY-005 | Insecure TLS | Critical | `InsecureSkipVerify: true`, TLS 1.0/1.1 min version |
| GTSS-CRY-006 | Weak Key Size | High | `rsa.GenerateKey(_, 1024)` or smaller |
| GTSS-CRY-007 | Plaintext Protocol | Medium | `http://` URLs (any language) |
| GTSS-CRY-010 | Weak PRNG | High | `math/rand` import + `rand.Int/Intn` in security context |
| GTSS-CRY-011 | Predictable Seed | High | `rand.Seed(time.Now())`, `rand.Seed(42)`, `rand.NewSource(42)` |
| GTSS-CRY-012 | Hardcoded Key | Critical | `key := []byte("literal")` |
| GTSS-CRY-013 | Unauthenticated Encryption | High | `cipher.NewCBCEncrypter()` without HMAC/GCM in file |
| GTSS-CRY-014 | Insecure RSA Padding | High | `rsa.EncryptPKCS1v15()`, `rsa.DecryptPKCS1v15()` |
| GTSS-CRY-015 | Weak Password Hash | Critical | `md5.Sum`/`sha256.Sum256` near password context |

### SSRF Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-SSRF-001 | URL from User Input | High | `http.Get(variable)`, `http.NewRequest("GET", variable, ...)` |
| GTSS-SSRF-003 | DNS Rebinding | High | Go-specific DNS resolution patterns |
| GTSS-SSRF-004 | Redirect Following | High | Go HTTP client redirect patterns |

### Secrets Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-SEC-001 | Hardcoded Password | High | `password := "literal"` or `password = "literal"` |
| GTSS-SEC-002 | API Key Exposure | High | API key patterns in Go code |
| GTSS-SEC-005 | JWT Secret | High | Hardcoded JWT signing keys |

### Auth Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-AUTH-001 | Hardcoded Credential Check | High | `password == "literal"` comparisons |
| GTSS-AUTH-002 | Missing Auth Check | Medium | `http.HandleFunc` on admin/sensitive routes without middleware |
| GTSS-AUTH-003 | CORS Wildcard | High | `Access-Control-Allow-Origin: *` with credentials |
| GTSS-AUTH-005 | Weak Password Policy | Medium | Password validation patterns |
| GTSS-AUTH-006 | Insecure Cookie | High | Cookie settings without Secure/HttpOnly flags |

### Generic Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-GEN-001 | Debug Mode | Medium | `gin.SetMode(gin.DebugMode)` |
| GTSS-GEN-003 | XXE Vulnerability | High | `xml.NewDecoder()` without secure configuration |
| GTSS-GEN-004 | Open Redirect | High | `http.Redirect(w, r, userInput, ...)` |
| GTSS-GEN-005 | Log Injection | Medium | Log calls with request data |
| GTSS-GEN-006 | Race Condition | Medium | Shared state access patterns |
| GTSS-GEN-007 | Mass Assignment | High | Struct field binding patterns |

### Logging Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-LOG-001 | Unsanitized Log Input | Medium | `log/slog.Print*(... r.URL/r.Form/...)`, `zap.Info(... r.URL/...)` |
| GTSS-LOG-002 | CRLF Log Injection | High | Log calls with unstripped newlines from user input |
| GTSS-LOG-003 | Sensitive Data in Logs | High | Logging password/token/secret variables |

### Validation Rules

| Rule ID | Name | Severity | Go-Specific Patterns |
|---------|------|----------|---------------------|
| GTSS-VAL-001 | Direct Param Usage | Medium | `r.URL.Query().Get(` / `r.FormValue(` used without validation |
| GTSS-VAL-002 | Missing Type Coercion | Medium | String params used without `strconv.Atoi` or similar |
| GTSS-VAL-003 | Missing Length Validation | Medium | User input without length bounds checking |
| GTSS-VAL-004 | Missing Allowlist Validation | Medium | Enum-like params without allowlist check |

## Example Detections

### SQL Injection via fmt.Sprintf

```go
// DETECTED: GTSS-INJ-001 (Critical) + taint flow go.http.request.formvalue -> go.database.sql.query
func HandleUserLookup(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    username := r.FormValue("username")
    query := fmt.Sprintf("SELECT id, email FROM users WHERE username = '%s'", username)
    rows, err := db.Query(query)
    // ...
}
```

GTSS flags the `fmt.Sprintf` constructing a SQL query with `%s` (regex rule) and traces the taint from `r.FormValue()` (source) through `query` into `db.Query()` (sink).

### Command Injection via Shell Interpreter

```go
// DETECTED: GTSS-INJ-002 (Critical) + taint flow go.http.request.url.query -> go.os.exec.command
func HandlePing(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    cmd := exec.Command("sh", "-c", "ping -c 3 "+host)
    output, _ := cmd.CombinedOutput()
    w.Write(output)
}
```

GTSS detects the `exec.Command("sh", "-c", ...)` shell invocation pattern and traces user input from the query string into the command argument.

### Reflected XSS via fmt.Fprintf

```go
// DETECTED: GTSS-XSS-008 (High) + GTSS-XSS-011 (High) + taint flow
func HandleProfile(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>", name)
}
```

GTSS detects HTML content written via `fmt.Fprintf` with `%s` containing user input, flagging both server-side rendering XSS and reflected XSS patterns.

## Safe Patterns

### Parameterized SQL Queries

```go
// SAFE: Parameterized query with bound parameter ($1)
func HandleUserLookup(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    username := r.FormValue("username")
    row := db.QueryRow("SELECT id, email FROM users WHERE username = $1", username)
    // ...
}
```

The parameterized query passes user input as a bound parameter rather than interpolating it into the query string. GTSS recognizes `stmt.Query()`, `stmt.Exec()`, and GORM's `Where("field = ?", value)` as sanitizers.

### Path Traversal Prevention

```go
// SAFE: filepath.Clean + strings.HasPrefix guard
func HandleFileDownload(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    cleaned := filepath.Clean(filename)
    fullPath := filepath.Join(baseDir, cleaned)
    absPath, _ := filepath.Abs(fullPath)
    if !strings.HasPrefix(absPath, baseDir) {
        http.Error(w, "access denied", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, absPath)
}
```

GTSS recognizes the combination of `filepath.Clean`/`filepath.Abs` (normalization) plus `strings.HasPrefix` (containment check) as a traversal guard and suppresses the finding.

### html/template Auto-Escaping

```go
// SAFE: html/template auto-escapes all template variables
var profileTmpl = template.Must(template.New("profile").Parse(`
    <h1>Hello, {{.Name}}!</h1>
    <p>Email: {{.Email}}</p>
`))

func HandleProfile(w http.ResponseWriter, r *http.Request) {
    data := ProfileData{
        Name:  r.FormValue("name"),
        Email: r.FormValue("email"),
    }
    profileTmpl.Execute(w, data)
}
```

GTSS recognizes `html/template` execution as a sanitizer for HTML output sinks. The `template.Must(template.New(...))` pattern is tracked as a safe HTML rendering method.

## Limitations

The following are known gaps or areas with reduced accuracy in Go coverage:

- **Code injection (GTSS-INJ-003)**: Go does not have `eval()` or dynamic code execution, so this rule category does not apply. GTSS correctly excludes Go from GTSS-INJ-003.

- **Taint analysis through interfaces**: Taint tracking across Go interface method calls has limited precision. When a tainted value is passed through an interface method and later retrieved via a type assertion, the taint may not always propagate correctly.

- **Struct field propagation**: When tainted data is assigned to a struct field and later read from a different reference to the same struct, the taint engine may lose track. The 0.8x confidence decay for unknown function propagation means deeply nested data flows lose confidence.

- **Goroutine boundaries**: Taint tracking does not follow data across goroutine boundaries (channel sends/receives). A tainted value sent on a channel and received in another goroutine will not be tracked.

- **Build tags and conditional compilation**: Files with build tags (`//go:build`) are scanned regardless of their target platform. Platform-specific code that would never execute on a given platform may still produce findings.

- **Vendored dependencies**: Code under `vendor/` directories is excluded by the `IsGeneratedFile` filter. Vulnerabilities in vendored code will not be detected.

- **reflect package**: Dynamic operations via the `reflect` package (e.g., `reflect.Value.Call`) are not tracked by the taint engine.

- **text/template vs html/template distinction**: The taint engine tracks `html/template` execution as a sanitizer, but may not always distinguish between `text/template` (unsafe) and `html/template` (safe) when both are imported with the same alias.

- **Third-party database drivers**: While `database/sql` and GORM sinks are covered, direct calls to driver-specific query methods (e.g., `pgx.Pool.Query` without going through `database/sql`) may not be tracked as SQL sinks.

- **Partial framework coverage**: While Gin, Echo, Fiber, Beego, gorilla/mux, and chi are covered, less common frameworks (e.g., Buffalo, Revel, Iris) may only be caught by generic patterns rather than framework-specific rules.
