# Rust Language Support

## Overview

GTSS provides security scanning for Rust code, covering the standard library (`std::process`, `std::fs`, `std::mem`, `std::ptr`), popular web frameworks (Actix-web, Axum, Rocket, Warp), database libraries (sqlx, diesel, rusqlite), HTTP clients (reqwest, hyper), serialization (serde, bincode, rmp), and cryptographic patterns. Rust support includes 10 Rust-specific regex rules, taint source-to-sink tracking with 22 sources, 40 sinks, and 15 sanitizers.

## Detection

Rust files are identified by the `.rs` file extension. Detection is handled in `internal/analyzer/analyzer.go`:

| Extension | Language Constant |
|-----------|-------------------|
| `.rs`     | `rules.LangRust`  |

Files matching `.rs` are scanned through all four analysis layers:
- **Layer 1**: Regex-based rules (348 pattern matching rules on source code)
- **Layer 2**: Tree-sitter AST structural analysis (comment-aware false positive filtering and structural code inspection)
- **Layer 3**: Taint analysis (source-to-sink tracking with sanitizer recognition)
- **Layer 4**: Interprocedural call graph analysis (cross-function data flow)

Test files (paths matching `_test.rs` or under `tests/` directories) are excluded from scanning to reduce false positives.

## Taint Analysis Coverage

The Rust taint catalog is defined in `internal/taint/languages/rust_*.go` and tracks 22 sources, 40 sinks, and 15 sanitizers.

### Sources (User Input Entry Points)

#### Actix-web Framework

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `rust.actix.query` | `web::Query` | Query parameter extraction |
| `rust.actix.path` | `web::Path` | URL path parameter extraction |
| `rust.actix.json` | `web::Json` | JSON request body extraction |
| `rust.actix.form` | `web::Form` | Form data extraction |
| `rust.actix.request` | `HttpRequest` | HTTP request object |

#### Axum Framework

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `rust.axum.query` | `extract::Query` | Query parameter extraction |
| `rust.axum.path` | `extract::Path` | URL path parameter extraction |
| `rust.axum.json` | `extract::Json` | JSON request body extraction |

#### Other Frameworks

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `rust.rocket.param` | `#[get(` | Rocket route parameter |
| `rust.warp.query` | `warp::query` | Warp query parameter filter |
| `rust.warp.body` | `warp::body` | Warp request body filter |
| `rust.hyper.request` | `hyper::Request` | Hyper HTTP request object |

#### Standard Library Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `rust.std.env.args` | `std::env::args()` | Command-line arguments iterator |
| `rust.std.env.var` | `std::env::var()` | Environment variable value |
| `rust.std.io.stdin` | `std::io::stdin()` | Standard input stream |
| `rust.std.io.stdin_read` | `stdin().read_line()` | Read line from stdin |

#### File and Network Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `rust.std.fs.read_to_string` | `fs::read_to_string()` | File contents as string |
| `rust.std.fs.read` | `fs::read()` | File contents as bytes |
| `rust.tokio.net.read` | `.read(&mut buf)` | Network socket read |

#### Deserialization

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `rust.serde.from_str` | `serde_json::from_str()` | JSON deserialization from string |
| `rust.serde.from_slice` | `serde_json::from_slice()` | JSON deserialization from byte slice |

### Sinks (Dangerous Functions)

#### Command Injection (CWE-78)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `rust.exec.command_new` | `Command::new()` | Critical | OS command execution |
| `rust.exec.command_arg` | `.arg()` | High | Command argument with tainted input |

#### SQL Injection (CWE-89)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `rust.sql.sqlx_query` | `sqlx::query()` | Critical | SQLx query execution |
| `rust.sql.diesel_raw` | `diesel::sql_query()` | Critical | Diesel raw SQL query |
| `rust.sql.rusqlite_execute` | `.execute()` | Critical | Rusqlite SQL execution |

#### Path Traversal / File Operations (CWE-22)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `rust.fs.read` | `fs::read()` | High | File read with tainted path |
| `rust.fs.write` | `fs::write()` | High | File write with tainted path |
| `rust.fs.remove_file` | `fs::remove_file()` | High | File removal with tainted path |
| `rust.fs.remove_dir` | `fs::remove_dir_all()` | High | Directory removal with tainted path |
| `rust.tokio.fs.read` | `tokio::fs::read()` | High | Async file read with tainted path |
| `rust.tokio.fs.write` | `tokio::fs::write()` | High | Async file write with tainted path |

#### Unsafe Memory Operations

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `rust.ptr.transmute` | `transmute()` | High | Unsafe type transmutation |
| `rust.ptr.from_raw_parts` | `from_raw_parts()` | High | Unsafe slice from raw pointer |

#### XSS / HTML Output (CWE-79)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `rust.actix.response.body` | `HttpResponse::body()` | High | HTTP response body with tainted data |

#### SSRF / URL Fetch (CWE-918)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `rust.reqwest.get` | `reqwest::get()` | High | HTTP request with tainted URL |
| `rust.reqwest.client_get` | `Client::get()` | High | HTTP client request with tainted URL |

#### Other Sinks

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `rust.redirect` | `Redirect::to()` | High | HTTP redirect with tainted URL |
| `rust.bincode.deserialize` | `bincode::deserialize()` | High | Binary deserialization |
| `rust.log.info` | `info!()` | Medium | Log macro with tainted data |
| `rust.tracing.info` | `tracing::info!()` | Medium | Tracing macro with tainted data |

### Sanitizers

| Sanitizer ID | Pattern | Neutralizes | Description |
|-------------|---------|-------------|-------------|
| `rust.sqlx.query_macro` | `sqlx::query!()` | SQL | Compile-time checked query macro |
| `rust.sqlx.query_as_macro` | `sqlx::query_as!()` | SQL | Compile-time checked typed query macro |
| `rust.sqlx.bind` | `.bind()` | SQL | SQLx parameter binding |
| `rust.diesel.parameterized` | `.filter()` | SQL | Diesel parameterized query filter |
| `rust.rusqlite.params` | `params![]` | SQL | Rusqlite parameterized query |
| `rust.ammonia.clean` | `ammonia::clean()` | HTML, template | Ammonia HTML sanitizer |
| `rust.html_escape` | `html_escape::encode_*()` | HTML, template | HTML escape encoding |
| `rust.validator.validate` | `.validate()` | SQL, command, HTML, file | Validator crate struct validation |
| `rust.url.parse` | `Url::parse()` | URL fetch, redirect | URL parsing and validation |
| `rust.path.canonicalize` | `.canonicalize()` | File | Path canonicalization |
| `rust.path.file_name` | `.file_name()` | File | Extract file name component |
| `rust.path.starts_with` | `.starts_with()` | File | Path prefix containment check |
| `rust.str.parse_int` | `.parse::<integer>()` | SQL, command, file | String to integer parsing |
| `rust.argon2.hash` | `Argon2::hash_password()` | Crypto | Argon2 password hashing |
| `rust.bcrypt.hash` | `bcrypt::hash()` | Crypto | Bcrypt password hashing |

## Rule Coverage

### Rust-Specific Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| GTSS-RS-001 | Unsafe Block Usage | Medium | Detects `unsafe { }` blocks with raw pointer dereferences, transmute, from_raw_parts |
| GTSS-RS-002 | Command Injection | Critical | `Command::new` with `format!`/user input, shell invocation (`sh -c`, `bash -c`) |
| GTSS-RS-003 | SQL Injection | Critical | `sqlx::query`/`diesel::sql_query`/`.execute` with `format!` or string concatenation |
| GTSS-RS-004 | Path Traversal | High | `std::fs`/`tokio::fs` operations with user-controlled paths without canonicalize/starts_with |
| GTSS-RS-005 | Insecure Deserialization | High | `bincode::deserialize`/`rmp_serde::from_slice`/`ciborium::from_reader` from untrusted input |
| GTSS-RS-006 | Insecure TLS | High | `.danger_accept_invalid_certs(true)`, `.danger_accept_invalid_hostnames(true)` |
| GTSS-RS-007 | Panic in Web Handler | Medium | `.unwrap()`/`.expect()` in Actix-web/Axum request handlers |
| GTSS-RS-008 | Insecure Random | Medium | `thread_rng()`/`rand::random()` in security context (token, key, nonce) instead of `OsRng` |
| GTSS-RS-009 | Memory Unsafety Patterns | High | `transmute`, `from_raw_parts`, `mem::forget`, `Box::from_raw`, raw pointer operations |
| GTSS-RS-010 | CORS Misconfiguration | Medium | `CorsLayer::permissive()`, `Cors::permissive()`, any origin with credentials |

### Cross-Language Rules Applicable to Rust

Rules marked with `LangAny` or explicitly including `LangRust` in their `Languages()` method also apply to Rust files. These include:

- **GTSS-SEC-001/002**: Hardcoded passwords and API keys
- **GTSS-CRY-007**: Plaintext protocol (http:// URLs)
- **GTSS-GQL-001/002**: GraphQL introspection and depth limiting (if using async-graphql or juniper)
- **GTSS-AUTH-007**: Privilege escalation patterns (CWE-269) - HIGH
- **GTSS-GEN-012**: Insecure download patterns (CWE-494) - HIGH
- **GTSS-MISC-003**: Missing security headers (CWE-1021, CWE-693) - MEDIUM
- **GTSS-VAL-005**: File upload hardening (CWE-434) - HIGH

### Tauri Framework Rules

Rules from `internal/rules/framework/tauri.go` that target `LangRust`. These apply to Rust backend code in Tauri desktop applications. Findings are only reported when the file contains Tauri project indicators (`tauri::`, `@tauri-apps`, `tauri::command`, etc.).

| Rule ID | Name | Severity | CWE | Description |
|---------|------|----------|-----|-------------|
| GTSS-FW-TAURI-001 | TauriShellAllowlist | Critical | CWE-78 | Detects `Command::new` with variable input in Tauri Rust code, and `tauri::api::shell::open` calls. Flags Rust backend code that spawns processes with frontend-controlled arguments. |
| GTSS-FW-TAURI-003 | TauriIPCInjection | High | CWE-78 | Detects `#[tauri::command]` handler functions that pass unvalidated frontend input to `std::process::Command::new` or `tokio::process::Command::new`. Tracks brace depth to scope findings to the command handler body. |
| GTSS-FW-TAURI-004 | TauriProtocolHandler | High | CWE-939 | Detects `register_uri_scheme_protocol` calls without origin validation (no `origin`/`Origin`/`referer`/`Referer` check within 20 lines), and dangerous URI scheme configurations (`file://`, `smb://`, `nfs://`). |
| GTSS-FW-TAURI-008 | TauriInsecureUpdater | Critical | CWE-295 | Detects `dangerous_insecure_transport_protocol(true)` in Rust updater code, which disables TLS verification for the Tauri updater and enables man-in-the-middle attacks to serve malicious updates. |

## Example Detections

### SQL Injection via format! Macro

```rust
// DETECTED: GTSS-RS-003 (Critical) + taint flow rust.actix.path -> rust.sql.sqlx_query
async fn get_user(path: web::Path<String>, pool: web::Data<PgPool>) -> HttpResponse {
    let username = path.into_inner();
    let row = sqlx::query(&format!("SELECT * FROM users WHERE username = '{}'", username))
        .fetch_one(pool.get_ref())
        .await
        .unwrap();
    HttpResponse::Ok().json(row)
}
```

GTSS flags the `format!` constructing a SQL query with user input (regex rule) and traces the taint from `web::Path` (source) through `username` into `sqlx::query` (sink).

### Command Injection via Shell Invocation

```rust
// DETECTED: GTSS-RS-002 (Critical) + taint flow rust.actix.query -> rust.exec.command_new
async fn ping_host(query: web::Query<PingParams>) -> HttpResponse {
    let host = &query.host;
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 3 {}", host))
        .output()
        .unwrap();
    HttpResponse::Ok().body(String::from_utf8_lossy(&output.stdout).to_string())
}
```

GTSS detects the `Command::new("sh")` shell invocation pattern and the `format!` in `.arg()` with user-controlled data.

### Unsafe Transmute

```rust
// DETECTED: GTSS-RS-001 (High) + GTSS-RS-009 (High)
fn dangerous_cast(val: f64) -> u64 {
    unsafe {
        std::mem::transmute(val)
    }
}
```

GTSS flags the `unsafe` block containing `transmute`, which bypasses type safety and can cause undefined behavior.

## Safe Patterns

### Parameterized SQL Queries

```rust
// SAFE: Parameterized query with .bind()
async fn get_user(pool: &PgPool, name: &str) -> Result<User, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE name = $1", name)
        .fetch_one(pool)
        .await
}
```

The `sqlx::query!` macro checks the query at compile time and the `sqlx::query().bind()` pattern uses parameterized queries. GTSS recognizes both as sanitizers.

### Path Traversal Prevention

```rust
// SAFE: canonicalize + starts_with guard
async fn read_file(filename: &str) -> Result<String, std::io::Error> {
    let base_dir = Path::new("/var/data");
    let requested = base_dir.join(filename);
    let canonical = requested.canonicalize()?;
    if !canonical.starts_with(base_dir) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied"));
    }
    std::fs::read_to_string(&canonical)
}
```

GTSS recognizes the combination of `canonicalize()` (path normalization) plus `starts_with()` (containment check) as a traversal guard and suppresses the finding.

### Error Handling with ? Operator

```rust
// SAFE: ? operator instead of unwrap() in handler
async fn process(body: web::Json<Request>, pool: web::Data<PgPool>) -> Result<HttpResponse, actix_web::Error> {
    let data = body.into_inner();
    let result = do_work(&data)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    Ok(HttpResponse::Ok().json(result))
}
```

Using `?` instead of `.unwrap()` in web handlers prevents panics. GTSS only flags `.unwrap()` and `.expect()` inside handler functions.

## Limitations

The following are known gaps or areas with reduced accuracy in Rust coverage:

- **Macro expansion**: GTSS scans Rust source code as text without macro expansion. Procedural macros, derive macros, and complex declarative macros may hide vulnerable patterns or produce false positives on safe macro invocations.

- **Trait method dispatch**: Taint tracking does not follow trait method dispatch. When tainted data is passed through a trait method and the concrete implementation varies, the taint may not propagate correctly.

- **Lifetime and borrow checker**: GTSS does not model Rust's lifetime or borrow checker rules. Some patterns flagged as unsafe may actually be prevented by the compiler's safety guarantees.

- **Async/await boundaries**: Taint tracking across `.await` points and spawned tasks (`tokio::spawn`, `actix_rt::spawn`) has limited precision. Data flowing through channels or shared state across async boundaries may not be tracked.

- **Conditional compilation**: Code behind `#[cfg(...)]` attributes is scanned regardless of target platform or feature flags. This may produce findings for code that is never compiled in the target configuration.

- **Unsafe in FFI**: While `unsafe` blocks are detected, the safety of FFI boundaries (calling C code via `extern "C"`) requires understanding the C code's contracts, which GTSS cannot verify.

- **Custom derive safety**: Crates like `serde` use derive macros that are generally safe, but GTSS cannot verify that custom `Deserialize` implementations handle untrusted input correctly.

- **Thread safety**: While Rust's type system prevents data races at compile time, GTSS does not verify that `unsafe` code maintains thread safety invariants (e.g., `Send`/`Sync` implementations).
