# PHP Language Support in GTSS

## Overview

GTSS provides comprehensive security scanning for PHP code, covering native PHP functions, and framework-specific patterns for Laravel, Symfony/Twig, CodeIgniter, and WordPress. PHP analysis includes all three scanning layers: regex-based rule matching (Layer 1), taint source-to-sink tracking (Layer 2), and interprocedural call graph analysis (Layer 3).

## Detection

PHP files are identified by the `.php` file extension. The detection is case-insensitive and handled by `internal/analyzer/analyzer.go`:

| Extension | Language Constant |
|-----------|-------------------|
| `.php`    | `LangPHP`         |

No additional heuristics (shebang lines, `<?php` tags, etc.) are used -- detection is purely extension-based.

## Taint Analysis Coverage

The PHP taint catalog is defined across four files in `internal/taint/languages/`:

- `php_catalog.go` -- catalog registration
- `php_sources.go` -- 35 source definitions
- `php_sinks.go` -- 60 sink definitions
- `php_sanitizers.go` -- 33 sanitizer definitions

### Sources (User Input Entry Points)

#### Superglobals

| ID | Pattern | Description |
|----|---------|-------------|
| `php.superglobal.get` | `$_GET[` | GET parameters |
| `php.superglobal.post` | `$_POST[` | POST parameters |
| `php.superglobal.request` | `$_REQUEST[` | Combined GET/POST/COOKIE |
| `php.superglobal.files` | `$_FILES[` | File uploads |
| `php.superglobal.cookie` | `$_COOKIE[` | Cookie values |
| `php.superglobal.server.http` | `$_SERVER['HTTP_*']` | HTTP request headers |
| `php.superglobal.server.request_uri` | `$_SERVER['REQUEST_URI']` | Request URI |
| `php.superglobal.server.query_string` | `$_SERVER['QUERY_STRING']` | Raw query string |
| `php.input.stream` | `file_get_contents('php://input')` | Raw request body |

#### Environment & CLI

| ID | Pattern | Description |
|----|---------|-------------|
| `php.superglobal.env` | `$_ENV[` | Environment variables |
| `php.getenv` | `getenv()` | Environment variable read |
| `php.argv` | `$argv` | CLI arguments |
| `php.stdin.fgets` | `fgets(STDIN)` | Standard input |

#### File Sources

| ID | Pattern | Description |
|----|---------|-------------|
| `php.fread` | `fread()` | File read |
| `php.file_get_contents` | `file_get_contents()` | File read (generic) |

#### Laravel Framework

| ID | Pattern | Description |
|----|---------|-------------|
| `php.laravel.request.input` | `$request->input()` | Request input |
| `php.laravel.request.get` | `$request->get()` | Request parameter |
| `php.laravel.request.all` | `$request->all()` | All request data |
| `php.laravel.request.query` | `$request->query()` | Query parameters |
| `php.laravel.request.static.input` | `Request::input()` | Static facade input |
| `php.laravel.route.current` | `Route::current()` | Current route data |
| `php.laravel.route.parameter` | `$request->route()` | Route parameters |

#### Symfony Framework

| ID | Pattern | Description |
|----|---------|-------------|
| `php.symfony.request.get` | `$request->get()` | Request parameter |
| `php.symfony.request.query.get` | `$request->query->get()` | Query parameter bag |
| `php.symfony.request.request.get` | `$request->request->get()` | POST parameter bag |

#### CodeIgniter Framework

| ID | Pattern | Description |
|----|---------|-------------|
| `php.codeigniter.input.get` | `$this->input->get()` | GET input |
| `php.codeigniter.input.post` | `$this->input->post()` | POST input |
| `php.codeigniter.input.cookie` | `$this->input->cookie()` | Cookie input |

#### WordPress

| ID | Pattern | Description |
|----|---------|-------------|
| `php.wordpress.get_option` | `get_option()` | Database option value |
| `php.wordpress.get_post_meta` | `get_post_meta()` | Post meta from database |
| `php.wordpress.get_user_meta` | `get_user_meta()` | User meta from database |

#### Cloud & External

| ID | Pattern | Description |
|----|---------|-------------|
| `php.aws.lambda.event` | `$event[` / Lambda handler | AWS Lambda event (Bref runtime) |
| `php.aws.sqs.receive` | `->receiveMessage()` | AWS SQS message |
| `php.aws.s3.getobject` | `->getObject()` | AWS S3 object |
| `php.gcp.pubsub.pull` | `->pull()` | GCP Pub/Sub message |

#### Other

| ID | Pattern | Description |
|----|---------|-------------|
| `php.session_id.source` | `session_id()` | Attacker-controlled session ID |

### Sinks (Dangerous Functions)

#### SQL Injection (CWE-89)

| ID | Function | Severity |
|----|----------|----------|
| `php.mysql.query` | `mysql_query()` | Critical |
| `php.mysqli.query` | `mysqli_query()` | Critical |
| `php.pdo.query` | `PDO::query()` | Critical |
| `php.laravel.db.raw` | `DB::raw()` | Critical |
| `php.laravel.whereRaw` | `->whereRaw()` | Critical |
| `php.laravel.selectRaw` | `->selectRaw()` | Critical |
| `php.laravel.orderByRaw` | `->orderByRaw()` | Critical |
| `php.codeigniter.db.query` | `$this->db->query()` | Critical |
| `php.wordpress.wpdb.query` | `$wpdb->query()` | Critical |
| `php.wordpress.wpdb.get_results` | `$wpdb->get_results()` | Critical |
| `php.wordpress.update_option` | `update_option()` | High |

#### Command Injection (CWE-78)

| ID | Function | Severity |
|----|----------|----------|
| `php.exec` | `exec()` | Critical |
| `php.system` | `system()` | Critical |
| `php.passthru` | `passthru()` | Critical |
| `php.shell_exec` | `shell_exec()` | Critical |
| `php.popen` | `popen()` | Critical |
| `php.proc_open` | `proc_open()` | Critical |
| `php.docker.exec` | Docker `->exec()` / `->containerExec()` | Critical |

#### Code Evaluation (CWE-94)

| ID | Function | Severity |
|----|----------|----------|
| `php.eval` | `eval()` | Critical |
| `php.assert` | `assert()` | Critical |
| `php.preg_replace_e` | `preg_replace()` with `/e` modifier | Critical |
| `php.extract` | `extract()` (variable injection, CWE-621) | High |
| `php.parse_str` | `parse_str()` without second arg (CWE-621) | High |
| `php.redis.eval` | Redis `->eval()` | Critical |

#### XSS / HTML Output (CWE-79)

| ID | Function | Severity |
|----|----------|----------|
| `php.echo` | `echo` | High |
| `php.print` | `print` | High |
| `php.printf` | `printf()` | High |
| `php.laravel.blade.unescaped` | `{!! !!}` Blade syntax | High |
| `php.twig.raw.filter` | Twig `\|raw` filter | High |
| `php.twig.autoescape.false` | Twig `autoescape false` | High |

#### File Operations (CWE-22)

| ID | Function | Severity |
|----|----------|----------|
| `php.include` | `include()` (LFI/RFI, CWE-98) | Critical |
| `php.require` | `require()` (CWE-98) | Critical |
| `php.include_once` | `include_once()` (CWE-98) | Critical |
| `php.require_once` | `require_once()` (CWE-98) | Critical |
| `php.file_put_contents` | `file_put_contents()` | High |
| `php.fwrite` | `fwrite()` | High |
| `php.fopen` | `fopen()` | High |
| `php.move_uploaded_file` | `move_uploaded_file()` (CWE-434) | High |

#### Deserialization & XXE

| ID | Function | Severity |
|----|----------|----------|
| `php.unserialize` | `unserialize()` (CWE-502) | Critical |
| `php.simplexml_load_string` | `simplexml_load_string()` (CWE-611) | High |
| `php.dom.loadxml` | `DOMDocument::loadXML()` (CWE-611) | High |
| `php.simplexml_load_file` | `simplexml_load_file()` (CWE-611) | High |

#### SSRF & Network (CWE-918)

| ID | Function | Severity |
|----|----------|----------|
| `php.file_get_contents.ssrf` | `file_get_contents()` with URL | High |
| `php.curl_exec` | `curl_exec()` | High |
| `php.dns_get_record` | `dns_get_record()` / `gethostbyname()` | High |

#### Headers, Redirects & Mail

| ID | Function | Severity |
|----|----------|----------|
| `php.header` | `header()` (CWE-113) | Medium |
| `php.setcookie` | `setcookie()` (CWE-113) | Medium |
| `php.redirect` | `redirect()` (CWE-601) | High |
| `php.header.location` | `header('Location:...')` (CWE-601) | High |
| `php.mail` | `mail()` (CWE-93) | High |
| `php.phpmailer.addaddress` | PHPMailer `->addAddress()` (CWE-93) | High |

#### Cryptography

| ID | Function | Severity |
|----|----------|----------|
| `php.crypto.md5` | `md5()` (CWE-328) | Medium |
| `php.crypto.sha1` | `sha1()` (CWE-328) | Medium |
| `php.crypto.rand` | `rand()` / `mt_rand()` (CWE-338) | High |
| `php.crypto.mcrypt` | `mcrypt_encrypt()` / `mcrypt_decrypt()` (CWE-327) | High |
| `php.crypto.ecb_mode` | Cipher using electronic codebook mode (CWE-327) | High |

#### Logging (CWE-117)

| ID | Function | Severity |
|----|----------|----------|
| `php.error_log` | `error_log()` | Medium |
| `php.syslog` | `syslog()` | Medium |
| `php.laravel.log.info` | `Log::info()` and other levels | Medium |
| `php.monolog.log` | Monolog `->info()` and other levels | Medium |

#### Other

| ID | Function | Severity |
|----|----------|----------|
| `php.redis.rawcommand` | Redis `->rawCommand()` (CWE-77) | High |
| `php.amqp.publish` | AMQP `->basic_publish()` (CWE-77) | Medium |

### Sanitizers (Functions That Neutralize Taint)

#### HTML Encoding

| ID | Function | Neutralizes |
|----|----------|-------------|
| `php.htmlspecialchars` | `htmlspecialchars()` | XSS/HTML output |
| `php.htmlentities` | `htmlentities()` | XSS/HTML output |
| `php.strip_tags` | `strip_tags()` | XSS/HTML output |

#### Command Escaping

| ID | Function | Neutralizes |
|----|----------|-------------|
| `php.escapeshellarg` | `escapeshellarg()` | Command injection |
| `php.escapeshellcmd` | `escapeshellcmd()` | Command injection |

#### Type Coercion

| ID | Function | Neutralizes |
|----|----------|-------------|
| `php.intval` | `intval()` | SQL injection, command injection |
| `php.int.cast` | `(int)` cast | SQL injection, command injection |

#### Path & SQL

| ID | Function | Neutralizes |
|----|----------|-------------|
| `php.basename` | `basename()` | File path traversal |
| `php.mysqli_real_escape_string` | `mysqli_real_escape_string()` | SQL injection |
| `php.pdo.quote` | `PDO::quote()` | SQL injection |
| `php.prepared.statement` | `PDO::prepare()` | SQL injection |
| `php.mysqli.prepare` | `mysqli::prepare()` | SQL injection |

#### URL & Input Filtering

| ID | Function | Neutralizes |
|----|----------|-------------|
| `php.urlencode` | `urlencode()` | Open redirect |
| `php.filter_input` | `filter_input()` | SQL, XSS, command |
| `php.filter_var` | `filter_var()` | SQL, XSS, command |
| `php.filter_var.validate_url` | `filter_var(FILTER_VALIDATE_URL)` | SSRF, redirect |
| `php.filter_var.validate_ip` | `filter_var(FILTER_VALIDATE_IP)` | SSRF |

#### WordPress Sanitizers

| ID | Function | Neutralizes |
|----|----------|-------------|
| `php.wordpress.wp_kses` | `wp_kses()` | XSS |
| `php.wordpress.wp_kses_post` | `wp_kses_post()` | XSS |
| `php.wordpress.esc_html` | `esc_html()` | XSS |
| `php.wordpress.esc_attr` | `esc_attr()` | XSS |
| `php.wordpress.esc_url` | `esc_url()` | Redirect, SSRF |
| `php.wordpress.esc_sql` | `esc_sql()` | SQL injection |
| `php.wordpress.wpdb.prepare` | `$wpdb->prepare()` | SQL injection |
| `php.wordpress.sanitize_text_field` | `sanitize_text_field()` | XSS, SQL |
| `php.wordpress.absint` | `absint()` | SQL, command |

#### Laravel Sanitizers

| ID | Function | Neutralizes |
|----|----------|-------------|
| `php.laravel.e` | `e()` | XSS |
| `php.laravel.blade.escaped` | `{{ }}` Blade syntax | XSS |
| `php.laravel.csrf_middleware` | `VerifyCsrfToken` / `@csrf` | CSRF |

#### Crypto & Security

| ID | Function | Neutralizes |
|----|----------|-------------|
| `php.crypto.password_hash` | `password_hash()` | Weak crypto |
| `php.crypto.password_verify` | `password_verify()` | Weak crypto |
| `php.crypto.hash_equals` | `hash_equals()` | Timing attacks |
| `php.crypto.random_bytes` | `random_bytes()` / `random_int()` | Insecure random |
| `php.libxml_disable_entity_loader` | `libxml_disable_entity_loader(true)` | XXE |

## Rule Coverage

The following regex-based rules (Layer 1) include PHP in their language list:

### Injection

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-INJ-001 | SQLInjection | SQL queries built with string concatenation or interpolation (`mysqli_query`, `PDO::query`, `$wpdb->query` with `$_GET`/`$_POST` variables) |
| GTSS-INJ-002 | CommandInjection | Shell commands with unsanitized input (`system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`) |
| GTSS-INJ-003 | CodeInjection | Dynamic code execution (`eval()`, `assert()`, `preg_replace` with `/e`) |
| GTSS-INJ-004 | LDAPInjection | LDAP queries built with concatenation (`ldap_search` with variables) |
| GTSS-INJ-005 | TemplateInjection | Server-side template injection in Twig/Blade |
| GTSS-INJ-006 | XPathInjection | XPath queries built with string concatenation |
| GTSS-INJ-007 | NoSQLInjection | NoSQL/MongoDB queries with unsafe patterns |
| GTSS-INJ-008 | GraphQLInjection | GraphQL queries via string concatenation |

### XSS

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-XSS-004 | UnescapedTemplateOutput | Blade `{!! !!}`, Twig `\|raw` filter, Twig `autoescape false` |
| GTSS-XSS-011 | ReflectedXSS | Direct echo/print of `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` |

### Traversal

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-TRV-001 | PathTraversal | File operations with user input (applies to all languages including PHP) |
| GTSS-TRV-002 | FileInclusion | `include`/`require`/`include_once`/`require_once` with user-controlled paths |

### Cryptography

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-CRY-010 | WeakPRNG | `rand()`, `mt_rand()` used for security purposes |
| GTSS-CRY-011 | PredictableSeed | `srand()` / `mt_srand()` with fixed or time-based seeds |
| GTSS-CRY-015 | WeakPasswordHash | `md5($password)` / `sha1($password)` instead of `password_hash()` |

### Secrets

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-SEC-001 | HardcodedPassword | `$password = "..."` and similar hardcoded credential assignments |
| GTSS-SEC-005 | JWTSecret | Hardcoded JWT signing secrets |

### Authentication

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-AUTH-001 | HardcodedCredentialCheck | `if ($password === "admin123")` and similar checks |
| GTSS-AUTH-003 | CORSWildcard | `header('Access-Control-Allow-Origin: *')` |
| GTSS-AUTH-004 | SessionFixation | Login handlers without `session_regenerate_id()` |
| GTSS-AUTH-005 | WeakPasswordPolicy | Password validation with weak minimum length |
| GTSS-AUTH-006 | InsecureCookie | `setcookie()` without Secure/HttpOnly/SameSite flags |

### Generic

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-GEN-001 | DebugModeEnabled | `display_errors = On`, `error_reporting(E_ALL)` in production |
| GTSS-GEN-002 | UnsafeDeserialization | `unserialize()` with untrusted data |
| GTSS-GEN-003 | XXEVulnerability | XML parsing without disabling external entities |
| GTSS-GEN-004 | OpenRedirect | `header('Location: ' . $userInput)` redirects |
| GTSS-GEN-006 | RaceCondition | TOCTOU patterns (check-then-use without locking) |
| GTSS-GEN-008 | CodeAsStringEval | Dangerous calls hidden inside `eval()` strings |
| GTSS-GEN-009 | XMLParserMisconfig | Insecure XML parser configurations |

### Logging

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-LOG-001 | UnsanitizedLogInput | User input written to logs without sanitization |
| GTSS-LOG-002 | CRLFLogInjection | CRLF characters in log entries from user input |
| GTSS-LOG-003 | SensitiveDataInLogs | Passwords, tokens, or keys logged in plaintext |

### Validation

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-VAL-001 | DirectParamUsage | `$_GET`/`$_POST` used directly without validation |
| GTSS-VAL-003 | MissingLengthValidation | User input stored without length checks |

### SSRF

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| GTSS-SSRF-001 | URLFromUserInput | HTTP requests with user-derived URLs (applies to all languages) |

## Example Detections

### 1. SQL Injection via String Interpolation

This code triggers **GTSS-INJ-001** (Layer 1) and taint flow from `php.superglobal.get` to `php.mysqli.query` (Layer 2):

```php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE user_id = '$id'";
$result = mysqli_query($conn, $query);
```

### 2. Reflected XSS via Echo

This code triggers **GTSS-XSS-011** (Layer 1) and taint flow from `php.superglobal.get` to `php.echo` (Layer 2):

```php
$name = $_GET['name'];
echo "<h1>Hello, " . $name . "</h1>";
```

### 3. Command Injection via system()

This code triggers **GTSS-INJ-002** (Layer 1) and taint flow from `php.superglobal.post` to `php.system` (Layer 2):

```php
$target = $_POST['ip'];
system("ping -c 4 " . $target);
```

## Safe Patterns

### 1. PDO Prepared Statements

Parameterized queries prevent SQL injection. The `PDO::prepare()` sanitizer neutralizes SQL injection taint:

```php
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = :id");
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();
```

### 2. htmlspecialchars for Output Encoding

Proper escaping prevents XSS. The `htmlspecialchars` sanitizer neutralizes HTML output taint:

```php
$name = $_GET['name'];
echo "<h1>Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</h1>";
```

### 3. escapeshellarg + Allowlist for Commands

Shell argument escaping combined with validation prevents command injection:

```php
$host = $_POST['host'];
$allowed = ['google.com', 'github.com'];
if (!in_array($host, $allowed, true)) {
    die("Invalid host.");
}
$safe = escapeshellarg($host);
$output = shell_exec("ping -c 4 " . $safe);
```

## Limitations

The following are known gaps or limitations in PHP coverage:

1. **Extension-only detection**: Only `.php` files are scanned. PHP embedded in `.phtml`, `.blade.php`, `.twig`, or `.html` files with `<?php` tags is not detected. Blade template files (`.blade.php`) are also not matched since the extension lookup uses only the final extension.

2. **No Drupal framework support**: While Laravel, Symfony, CodeIgniter, and WordPress have dedicated sources/sinks/sanitizers, Drupal-specific APIs (e.g., `db_query()`, `\Drupal::database()`, `Xss::filter()`) are not covered.

3. **No CakePHP or Yii support**: These frameworks have their own ORM and input handling patterns that are not tracked.

4. **Limited dynamic analysis**: PHP features like variable variables (`$$var`), dynamic method calls (`$obj->$method()`), and `call_user_func()` with variable function names are not tracked through taint analysis.

5. **No type-aware analysis**: The scanner does not parse PHP type hints or PHPDoc annotations, so it cannot distinguish between a `PDO` object's `->query()` and any other object's `->query()` method beyond pattern matching.

6. **Twig/Blade templates in separate files**: Taint analysis tracks Blade `{!! !!}` and Twig `|raw` patterns but only when they appear in `.php` files, not in standalone `.blade.php` or `.twig` template files.

7. **No Composer dependency analysis**: The scanner does not inspect `composer.json` or `composer.lock` for known vulnerable package versions.

8. **`preg_replace` /e modifier**: The `/e` modifier was removed in PHP 7.0, but the scanner still flags it for codebases targeting PHP 5.x or mixed-version environments.
