# Python Language Support

## Overview

GTSS provides comprehensive security scanning for Python code, covering web frameworks (Flask, Django, FastAPI, aiohttp, Tornado, Starlette), cloud platforms (AWS Lambda, GCP Cloud Functions, Azure Functions), and standard library patterns. Analysis operates at three layers: regex-based rule matching (Layer 1), intraprocedural taint source-to-sink tracking (Layer 2), and interprocedural call graph analysis (Layer 3).

## Detection

Python files are identified by file extension:

| Extension | Language |
|-----------|----------|
| `.py`     | Python   |
| `.pyw`    | Python   |

Detection is handled in `internal/analyzer/analyzer.go` via the `extToLanguage` map. The extension is matched case-insensitively after extracting it with `filepath.Ext`.

## Taint Analysis Coverage

### Sources (User Input Entry Points)

GTSS tracks 33 taint sources for Python, organized by framework and category.

#### Flask

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `py.flask.request.args` | `request.args` | Query parameters |
| `py.flask.request.form` | `request.form` | Form data |
| `py.flask.request.data` | `request.data` | Raw request body |
| `py.flask.request.json` | `request.json` / `request.get_json()` | JSON request body |
| `py.flask.request.values` | `request.values` | Combined query + form parameters |
| `py.flask.request.headers` | `request.headers` | Request headers |
| `py.flask.request.cookies` | `request.cookies` | Request cookies |
| `py.flask.request.files` | `request.files` | File uploads |

#### Django

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `py.django.request.get` | `request.GET` | GET query parameters |
| `py.django.request.post` | `request.POST` | POST form data |
| `py.django.request.body` | `request.body` | Raw request body |

#### FastAPI

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `py.fastapi.param` | `Query()`, `Path()`, `Body()`, `Form()`, `Header()`, `Cookie()` | Parameter dependency injection |

#### aiohttp

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `py.aiohttp.request.query` | `request.query` | Query string parameters |
| `py.aiohttp.request.post` | `await request.post()` | POST form data |
| `py.aiohttp.request.json` | `await request.json()` | JSON request body |

#### Tornado

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `py.tornado.get_argument` | `self.get_argument()` / `self.get_arguments()` | Query/body argument |
| `py.tornado.get_body_argument` | `self.get_body_argument()` | POST body argument |

#### Starlette

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `py.starlette.request.query_params` | `request.query_params` | Query parameters |
| `py.starlette.request.form` | `await request.form()` | Form data |
| `py.starlette.request.json` | `await request.json()` | JSON request body |

#### Standard Library

| Source ID | Pattern | Category | Description |
|-----------|---------|----------|-------------|
| `py.input` | `input()` | User Input | Console input |
| `py.sys.argv` | `sys.argv` | CLI Arg | Command-line arguments |
| `py.os.environ` | `os.environ` / `os.getenv()` | Env Var | Environment variables |
| `py.socket.recv` | `.recv()` | Network | Socket receive data |
| `py.open.read` | `open().read()` | File Read | File contents |
| `py.urlopen` | `urllib.request.urlopen()` | Network | URL open and read |

#### Cloud / External

| Source ID | Pattern | Category | Description |
|-----------|---------|----------|-------------|
| `py.celery.task_args` | `@app.task` / `@shared_task` | External | Celery task arguments from message broker |
| `py.boto3.s3.get_object` | `.get_object()` | External | S3 object data |
| `py.lambda.event` | `def handler(event, context)` | External | AWS Lambda event data |
| `py.boto3.sqs.receive` | `.receive_message()` | External | AWS SQS message data |
| `py.gcp.cloudfunctions.event` | `def handler(event, context)` | External | GCP Cloud Function event |
| `py.gcp.pubsub.pull` | `.pull()` | External | GCP Pub/Sub message data |
| `py.azure.functions.event` | `def main(req: func.HttpRequest)` | External | Azure Functions HTTP trigger |

### Sinks (Dangerous Functions)

GTSS tracks 48 taint sinks for Python.

#### SQL Injection (CWE-89)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.cursor.execute` | `.execute()` | Critical | SQL query execution |
| `py.sqlalchemy.text` | `text()` | Critical | SQLAlchemy raw SQL text |
| `py.sqlalchemy.engine.execute` | `engine.execute()` / `connection.execute()` / `session.execute()` | Critical | SQLAlchemy execute |
| `py.django.orm.raw` | `.raw()` | Critical | Django ORM raw SQL |
| `py.django.orm.extra` | `.extra()` | High | Django ORM extra SQL fragments |
| `py.django.orm.rawsql` | `RawSQL()` | Critical | Django RawSQL expression |

#### Command Injection (CWE-78)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.os.system` | `os.system()` | Critical | OS command execution |
| `py.os.popen` | `os.popen()` | Critical | OS command via popen |
| `py.subprocess.call` | `subprocess.*()` | Critical | Subprocess execution |
| `py.docker.exec_run` | `.exec_run()` | Critical | Docker container exec |
| `py.redis.execute_command` | `.execute_command()` | High | Redis command execution |
| `py.kafka.send` | `producer.send()` | Medium | Kafka message production |

#### Code Injection (CWE-94)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.eval` | `eval()` | Critical | Dynamic code evaluation |
| `py.exec` | `exec()` | Critical | Dynamic code execution |
| `py.redis.eval` | `.eval()` on Redis client | Critical | Redis Lua script evaluation |

#### Path Traversal / File Operations (CWE-22)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.open` | `open()` | High | File open with tainted path |
| `py.os.path.join` | `os.path.join()` | Medium | File path construction |
| `py.flask.render_template` | `render_template()` | High | Template name path traversal |
| `py.flask.send_file` | `send_file()` | High | Arbitrary file read |

#### Template Injection (CWE-1336)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.render_template_string` | `render_template_string()` | Critical | Server-side template injection |
| `py.jinja.template` | `Template()` | High | Jinja2 template from tainted string |

#### Deserialization (CWE-502)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.pickle.loads` | `pickle.loads()` | Critical | Pickle deserialization (RCE risk) |
| `py.yaml.load` | `yaml.load()` | High | Unsafe YAML deserialization |
| `py.marshal.loads` | `marshal.loads()` / `marshal.load()` | Critical | Marshal deserialization |

#### XML External Entity (CWE-611)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.xml.etree.parse` | `ET.parse()` / `ElementTree.parse()` | High | XML parsing (XXE risk) |
| `py.xml.etree.fromstring` | `ET.fromstring()` | High | XML string parsing (XXE risk) |

#### SSRF (CWE-918)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.requests.get` | `requests.get()` | High | HTTP request with tainted URL |
| `py.urllib.urlopen` | `urllib.request.urlopen()` | High | URL open with tainted URL |
| `py.socket.getaddrinfo` | `socket.getaddrinfo()` / `socket.gethostbyname()` | High | DNS lookup with tainted hostname |

#### XSS / HTML Output (CWE-79)

| Sink ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| `py.send` | `.send()` / `make_response()` | Medium | HTTP response with tainted content |
| `py.django.httpresponse` | `HttpResponse()` | High | Django response with tainted content |
| `py.jinja2.markup` | `Markup()` | High | Bypasses auto-escaping |
| `py.jinja2.markup.format` | `Markup.format()` | High | Interpolates into safe HTML |
| `py.django.mark_safe` | `mark_safe()` | High | Marks tainted string as safe HTML |

#### Cryptography

Seven crypto-related sinks are tracked. These detect weak hashing (`py.hashlib.md5`, `py.hashlib.sha1`), non-cryptographic randomness (`py.random.weak`), deprecated ciphers and insecure modes (3 sink IDs under `py.crypto.*` -- see `internal/taint/languages/python_sinks.go` for the full list), and JWT decoding without verification (`py.jwt.decode.noverify`). Severities range from Medium (weak hashing) to Critical (unverified JWT).

#### Other

| Sink ID | Pattern | Severity | CWE | Description |
|---------|---------|----------|-----|-------------|
| `py.redirect` | `redirect()` | High | CWE-601 | Open redirect |
| `py.response.set_cookie` | `.set_cookie()` | Medium | CWE-113 | Header injection via cookie |
| `py.ldap.search` | `.search_s()` | High | CWE-90 | LDAP injection |
| `py.smtplib.sendmail` | `.sendmail()` | High | CWE-93 | SMTP header injection |
| `py.logging.*` | `logging.info/warning/error/debug/critical()` | Medium | CWE-117 | Log injection (10 sink variants) |

### Sanitizers (Functions That Neutralize Taint)

GTSS recognizes 25 sanitizer patterns for Python.

#### HTML/XSS Sanitizers

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `py.html.escape` | `html.escape()` / `markupsafe.escape()` | HTML output |
| `py.bleach.clean` | `bleach.clean()` | HTML output |
| `py.quote_plus` | `urllib.parse.quote_plus()` | Redirect, HTML output |
| `py.django.escapers` | `force_escape` / `escapejs` / `urlencode` | HTML output |
| `py.django.conditional_escape` | `conditional_escape()` | HTML output |
| `py.jinja2.autoescape` | `autoescape=True` | HTML output, templates |

#### SQL Sanitizers

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `py.parameterized` | Parameterized query placeholders (`%s` with tuple) | SQL query |
| `py.sqlalchemy.bindparams` | `.params()` / `bindparam()` | SQL query |
| `py.int` | `int()` | SQL query, command |

#### Command Sanitizers

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `py.shlex.quote` | `shlex.quote()` | Command |

#### File Path Sanitizers

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `py.os.path.basename` | `os.path.basename()` | File write/path traversal |

#### Deserialization Sanitizers

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `py.yaml.safeloader` | `yaml.safe_load()` / `yaml.load(...Loader=yaml.SafeLoader)` | Deserialization |
| `py.defusedxml` | `defusedxml.*.parse()` / `defusedxml.*.fromstring()` | Deserialization (XXE) |

#### Cryptography / Auth Sanitizers

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `py.secrets` | `secrets.token_hex()` / `secrets.token_urlsafe()` / `secrets.token_bytes()` | Crypto |
| `py.crypto.bcrypt.hashpw` | `bcrypt.hashpw()` / `bcrypt.gensalt()` | Crypto |
| `py.crypto.bcrypt.checkpw` | `bcrypt.checkpw()` | Crypto |
| `py.crypto.argon2` | `argon2.PasswordHasher()` | Crypto |
| `py.crypto.hmac.compare_digest` | `hmac.compare_digest()` | Crypto |
| `py.django.csrf_protect` | `@csrf_protect` / `CsrfViewMiddleware` | Crypto |

#### Input Validation Sanitizers

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `py.validators` | `validate()` / `is_valid()` / `clean()` | SQL, command, file, HTML, redirect |
| `py.pydantic.parse` | `.parse_obj()` / `.model_validate()` / `BaseModel` | SQL, command, HTML, file |
| `py.marshmallow.load` | `Schema().load()` | SQL, command, HTML |
| `py.wtforms.validate` | `form.validate()` / `form.validate_on_submit()` | SQL, command, HTML |
| `py.cerberus.validate` | `Validator().validate()` | SQL, command, HTML |
| `py.ipaddress.validate` | `ipaddress.ip_address()` / `ipaddress.ip_network()` | URL fetch (SSRF) |
| `py.validators.url` | `validators.url()` / `URLValidator()` | URL fetch, redirect |

## Rule Coverage

GTSS applies 47 regex-based rules to Python files across 11 categories.

### Injection (`internal/rules/injection/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-INJ-001 | SQLInjection | Critical | f-string, %-format, `.format()`, and concatenation in SQL queries |
| GTSS-INJ-002 | CommandInjection | Critical | `os.system()`, `os.popen()`, `subprocess.*()` with string args or `shell=True` |
| GTSS-INJ-003 | CodeInjection | Critical | `eval()`, `exec()`, `compile()` with dynamic input |
| GTSS-INJ-004 | LDAPInjection | High | LDAP filter construction with string interpolation |
| GTSS-INJ-005 | TemplateInjection | Critical | `render_template_string()` with user-controlled templates |
| GTSS-INJ-006 | XPathInjection | High | XPath query construction with unsanitized input |
| GTSS-INJ-007 | NoSQLInjection | High | MongoDB query construction with user input |
| GTSS-INJ-008 | GraphQLInjection | High | GraphQL query built with f-string, `.format()`, or `%` formatting |

### XSS (`internal/rules/xss/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-XSS-004 | UnescapedTemplateOutput | High | Jinja2 `\|safe` filter, `{% autoescape false %}` blocks |
| GTSS-XSS-008 | ServerSideRenderingXSS | High | `HttpResponse()` / `make_response()` with f-strings containing request data |
| GTSS-XSS-011 | ReflectedXSS | High | Direct reflection of request parameters in response body |
| GTSS-XSS-013 | PythonFStringHTML | High | Python f-strings building HTML with embedded variables (Python-only rule) |

### Traversal (`internal/rules/traversal/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-TRV-001 | PathTraversal | Critical | `open()`, `os.path.join()` with user-controlled path components |
| GTSS-TRV-002 | FileInclusion | Critical | Dynamic `import`, `importlib`, `__import__()` with user input |
| GTSS-TRV-003 | ArchiveExtraction | High | `zipfile`/`tarfile` extraction without path validation |
| GTSS-TRV-005 | TemplatePathInjection | High | `render_template()` with user-controlled template name |
| GTSS-TRV-008 | NullByteFilePath | Medium | File paths without null byte sanitization |

### Cryptography (`internal/rules/crypto/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-CRY-001 | WeakHashing | High | `hashlib.md5()`, `hashlib.sha1()` |
| GTSS-CRY-002 | InsecureRandom | High | `random.random()`, `random.randint()`, `random.choice()` for security |
| GTSS-CRY-003 | WeakCipher | Critical | Weak/deprecated symmetric ciphers and insecure block modes |
| GTSS-CRY-004 | HardcodedIV | High | Static initialization vectors in cipher setup |
| GTSS-CRY-005 | InsecureTLS | Critical | `verify=False` in requests, disabled SSL verification |
| GTSS-CRY-006 | WeakKeySize | High | RSA keys below 2048 bits, AES keys below 128 bits |
| GTSS-CRY-007 | PlaintextProtocol | Medium | Unencrypted protocol URLs in code (any language) |
| GTSS-CRY-009 | PythonRandomSecurity | Critical | `random.seed()` with predictable values, `random` module for tokens/passwords (Python-only rule) |
| GTSS-CRY-011 | PredictableSeed | High | `random.seed(time.time())` or fixed seed values |
| GTSS-CRY-012 | HardcodedKey | Critical | Encryption keys assigned as string/byte literals |
| GTSS-CRY-013 | UnauthenticatedEncryption | High | CBC mode without HMAC or authentication |
| GTSS-CRY-014 | InsecureRSAPadding | High | PKCS1v15 padding instead of OAEP |
| GTSS-CRY-015 | WeakPasswordHash | Critical | MD5/SHA for password hashing instead of bcrypt/argon2 |

### Secrets (`internal/rules/secrets/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-SEC-001 | HardcodedPassword | Critical | `password = "..."`, `secret = "..."` assignments |
| GTSS-SEC-002 | APIKeyExposure | Critical | AWS, GCP, Stripe, GitHub, Slack API keys (any language) |
| GTSS-SEC-003 | PrivateKeyInCode | Critical | PEM-encoded private keys (any language) |
| GTSS-SEC-004 | ConnectionString | High | Database URIs with embedded credentials (any language) |
| GTSS-SEC-005 | JWTSecret | Critical | Hardcoded JWT signing secrets |
| GTSS-SEC-006 | EnvironmentLeak | Medium | Dumping all env vars to output (any language) |

### SSRF (`internal/rules/ssrf/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-SSRF-001 | URLFromUserInput | High | `requests.get(user_url)`, `urlopen(user_url)` (any language) |
| GTSS-SSRF-002 | InternalNetworkAccess | High | Requests to localhost, cloud metadata endpoints, and private IP ranges (any language) |
| GTSS-SSRF-003 | DNSRebinding | Medium | Separate DNS resolve + HTTP request pattern |
| GTSS-SSRF-004 | RedirectFollowing | Medium | `allow_redirects=True` with user-controlled URL |

### Auth (`internal/rules/auth/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-AUTH-001 | HardcodedCredentialCheck | Critical | `if password == "..."` comparison patterns |
| GTSS-AUTH-002 | MissingAuthCheck | Medium | Route handlers without `@login_required` or auth decorators |
| GTSS-AUTH-003 | CORSWildcard | High | Overly permissive CORS origin configuration |
| GTSS-AUTH-004 | SessionFixation | High | Session ID set from request parameter |
| GTSS-AUTH-005 | WeakPasswordPolicy | Medium | Short minimum password lengths in validation |
| GTSS-AUTH-006 | InsecureCookie | High | Cookies without `secure`, `httponly`, or `samesite` flags |

### Generic (`internal/rules/generic/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-GEN-001 | DebugModeEnabled | High | `app.debug = True`, `DEBUG = True` in settings |
| GTSS-GEN-002 | UnsafeDeserialization | Critical | `pickle.loads()`, `pickle.load()`, `shelve.open()` |
| GTSS-GEN-003 | XXEVulnerability | High | `xml.etree` / `lxml` parsing without disabling entities |
| GTSS-GEN-004 | OpenRedirect | High | `redirect(request.args.get("url"))` |
| GTSS-GEN-005 | LogInjection | Medium | User input in log calls without sanitization |
| GTSS-GEN-006 | RaceCondition | Medium | TOCTOU patterns (check-then-use without locking) |
| GTSS-GEN-007 | MassAssignment | High | `**request.form` or `**request.json` spread into ORM |
| GTSS-GEN-008 | CodeAsStringEval | High | Multi-line eval/exec with string-built code |
| GTSS-GEN-009 | XMLParserMisconfig | High | XML parser with external entities or DTD enabled |

### Logging (`internal/rules/logging/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-LOG-001 | UnsanitizedLogInput | Medium | Request data logged via f-string or `.format()` |
| GTSS-LOG-002 | CRLFLogInjection | Medium | Log messages with potential newline injection |
| GTSS-LOG-003 | SensitiveDataInLogs | Medium | Passwords, tokens, or keys in log statements |

### Validation (`internal/rules/validation/`)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-VAL-001 | DirectParamUsage | Medium | `request.args["id"]` used directly without validation |
| GTSS-VAL-002 | MissingTypeCoercion | Medium | Request params used without `int()` / type conversion |
| GTSS-VAL-003 | MissingLengthValidation | Medium | String input accepted without length bounds |
| GTSS-VAL-004 | MissingAllowlistValidation | Medium | Enum-like values without allowlist check |

## Example Detections

### SQL Injection via f-string (GTSS-INJ-001)

The following Flask route is vulnerable because user input is interpolated directly into a SQL query string:

```python
# VULNERABLE: f-string SQL query with user input
# Detected by GTSS-INJ-001 (Layer 1) and taint flow
#   request.args -> cursor.execute (Layer 2)
@app.route("/users")
def get_user():
    user_id = request.args['id']
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### Command Injection via os.system (GTSS-INJ-002)

User input concatenated into a shell command string:

```python
# VULNERABLE: String concatenation in shell command
# Detected by GTSS-INJ-002 and taint sink py.os.system
@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 3 " + host)
```

### Unsafe Deserialization via pickle (GTSS-GEN-002)

Pickle deserialization of user-controlled data allows arbitrary code execution:

```python
# VULNERABLE: Pickle loads on user-controlled cookie data
# Detected by GTSS-GEN-002 and taint sink py.pickle.loads
@app.route("/restore-session", methods=["POST"])
def restore_session():
    cookie_data = request.cookies.get("session_data")
    decoded = base64.b64decode(cookie_data)
    session_obj = pickle.loads(decoded)
```

## Safe Patterns

### Parameterized SQL Queries

Using placeholder parameters prevents SQL injection regardless of input content:

```python
# SAFE: Parameterized query with ? placeholder and tuple argument
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

The `py.parameterized` sanitizer recognizes this pattern and neutralizes the SQL injection taint.

### Subprocess with List Arguments

Passing arguments as a list avoids shell interpretation:

```python
# SAFE: List arguments (no shell) + allowlist validation
ALLOWED_HOSTS = {"example.com", "test.internal"}

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if host not in ALLOWED_HOSTS:
        return "Invalid host", 400
    result = subprocess.run(
        ["ping", "-c", "3", host],
        capture_output=True, text=True, timeout=10,
    )
```

### Path Traversal Prevention

Using `os.path.realpath()` with a directory prefix check constrains file access:

```python
# SAFE: realpath + startswith constrains to allowed directory
UPLOAD_DIR = os.path.realpath("/var/uploads")

@app.route("/download")
def download():
    filename = request.args.get("file", "")
    requested_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not requested_path.startswith(UPLOAD_DIR):
        abort(403)
    return send_file(requested_path)
```

The `py.os.path.basename` sanitizer also neutralizes path traversal when used to strip directory components.

## Limitations

- **No AST parsing.** Python analysis is regex-based, not AST-based. Patterns like renamed imports (`import os as operating_system; operating_system.system(cmd)`) or deeply aliased references may be missed.

- **Dynamic dispatch.** Taint tracking does not resolve dynamic attribute access (`getattr(obj, method_name)()`) or metaclass-driven dispatch.

- **Decorator-based sanitizers.** Custom decorators that validate input (e.g., `@validate_input`) are not recognized unless they match a known sanitizer pattern like `validate()` or `is_valid()`.

- **Django template auto-escaping.** GTSS does not parse Django template files (`.html`) to verify that auto-escaping is enabled. It only detects unsafe patterns in Python view code like `mark_safe()` or `HttpResponse()` with interpolated data.

- **Type annotation awareness.** Pydantic `BaseModel` fields with constrained types (e.g., `conint`, `constr`) are recognized as sanitizers, but custom Pydantic validators using `@validator` or `@field_validator` are not individually tracked.

- **Async patterns.** While aiohttp/Starlette `await` patterns are tracked as sources, taint propagation through `asyncio.gather()`, `asyncio.create_task()`, or complex async iterator chains may lose taint tracking.

- **Third-party ORM safety.** SQLAlchemy's query builder methods (`.filter()`, `.filter_by()`) that use parameterized queries are safe but not explicitly marked as sanitizers. Only `bindparam()` and `.params()` are recognized.

- **No `requirements.txt` / `pyproject.toml` analysis.** GTSS does not check for known-vulnerable package versions.

- **Limited Jupyter notebook coverage.** While GTSS intercepts `NotebookEdit` tool calls, Python-specific cell patterns (like `!` shell commands in notebooks) are not specially handled beyond standard Python scanning.
