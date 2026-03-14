# Recommended Security Rules Per Language (2024-2026 Threat Landscape)

Based on analysis of Batou's existing 864 rules, OWASP Top 10 2025, CWE Top 25 2025, recent CVEs, and emerging attack patterns (AI/LLM integration, supply chain, post-quantum crypto).

## Key Themes Driving Recommendations

1. **AI/LLM Prompt Injection** (OWASP LLM Top 10 #1) — User input flowing into LLM API calls
2. **Supply Chain Security** (OWASP A03:2025 NEW) — Malicious dependencies, install hooks, dependency confusion
3. **Exceptional Condition Handling** (OWASP A10:2025 NEW) — Fail-open errors, swallowed exceptions in auth
4. **Post-Quantum Crypto Readiness** — RSA-2048/ECDSA deprecation path per NIST PQC standards
5. **Container Escape** — runC CVEs (CVE-2025-31133, CVE-2025-52565), namespace manipulation
6. **Deserialization Resurgence** — `pickle`/`torch.load`, `BinaryFormatter`, `unserialize`, `Marshal.load`
7. **Memory Safety at FFI Boundaries** — CISA/FBI 2025 alert on buffer overflow exploitation
8. **gRPC/GraphQL Misconfiguration** — Missing TLS, unlimited query depth, exposed introspection
9. **Prototype Pollution** (CWE-1321) — Deep merge attacks in JS/TS ecosystems
10. **Zero Trust Gaps** — Missing auth on internal services, hardcoded trust assumptions

---

## Go

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **gRPC server without TLS** — `grpc.NewServer()` without `grpc.Creds()` | CWE-319 | High | `grpc\.NewServer\(\s*\)` without `credentials\.NewTLS` in scope |
| 2 | **Missing context timeout on HTTP/DB calls** — `http.Get`/`db.Query` without `context.WithTimeout` | CWE-400 | Medium | `http\.(Get\|Post\|Do)\(` without `context\.WithTimeout` nearby |
| 3 | **LLM prompt injection via string concat** — user input concatenated into LLM API calls | CWE-77 | High | Taint: HTTP params → `openai`/`anthropic` client calls |
| 4 | **Unbounded goroutine spawning in loop** — `go func()` in loop without semaphore/pool | CWE-770 | Medium | `for\s.*\{[^}]*go\s+(func\|[a-zA-Z])` without `sync\.WaitGroup` or channel limiter |
| 5 | **Unsafe `reflect` with user input** — `reflect.ValueOf` on user-controlled data | CWE-470 | High | Taint: request params → `reflect.ValueOf`/`reflect.New` |
| 6 | **`fmt.Sprintf` SQL in pgx/sqlc** — format-string SQL passed to `Query`/`Exec` | CWE-89 | Critical | `fmt\.Sprintf\(.*SELECT\|INSERT\|UPDATE\|DELETE` passed to query methods |
| 7 | **Container escape via mount propagation** — `syscall.Mount` with `MS_SHARED`/`MS_SLAVE` | CWE-269 | Critical | `syscall\.Mount\(.*MS_(SHARED\|SLAVE)` |
| 8 | **Deprecated crypto: RSA < 3072 bits** — `rsa.GenerateKey(rand, 2048)` | CWE-327 | High | `rsa\.GenerateKey\(.*,\s*(1024\|2048)\)` |
| 9 | **Fail-open error handling in auth** — `if err != nil { return }` skipping security checks | CWE-755 | Medium | AST: `if err != nil` blocks returning without error propagation in auth functions |
| 10 | **Supply chain: `replace` directive with local path** — `go.mod` replace pointing to filesystem | CWE-829 | High | `replace\s+\S+\s+=>\s+[./]` in `go.mod` |

---

## Python

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **Pickle/torch.load deserialization** — `pickle.loads`, `torch.load` without `weights_only=True` | CWE-502 | Critical | `(pickle\|joblib)\.(loads?\|Unpickler)\(` and `torch\.load\(` without `weights_only=True` |
| 2 | **LLM prompt injection via f-string** — user input interpolated into AI prompts | CWE-77 | High | Taint: `request.*` → `openai`/`anthropic`/`langchain` calls |
| 3 | **AI model loading from untrusted source** — `from_pretrained()` with user-controlled path | CWE-829 | Critical | `from_pretrained\(.*\b(input\|request\|user\|url)\b` |
| 4 | **`asyncio.create_subprocess_shell` injection** — shell command with f-string interpolation | CWE-78 | Critical | `create_subprocess_shell\(.*f["']\|\.format\|%` |
| 5 | **PLY pickle loading** — `yacc(picklefile=...)` loading cached parser tables (CVE-2025-56005) | CWE-502 | High | `yacc\(.*picklefile\s*=` |
| 6 | **Unsafe eval/exec of LLM output** — executing AI-generated code without sandbox | CWE-94 | Critical | `(eval\|exec)\(.*\b(response\|completion\|output\|generated\|llm)\b` |
| 7 | **`tarfile.extractall` path traversal** — missing `filter=` param (CVE-2007-4559, Python 3.12+ fix) | CWE-22 | Critical | `\.extractall\(\)` without `filter=` parameter |
| 8 | **Bare `except: pass` in auth code** — swallowed exceptions in security-critical paths (OWASP A10:2025) | CWE-755 | Medium | `except\s*:\s*pass` in files matching `auth\|login\|crypt\|token` |
| 9 | **Dependency confusion via `--extra-index-url`** — pip configs with private registry without override | CWE-829 | High | `--extra-index-url` in `requirements.txt`/`pyproject.toml` without `--index-url` |
| 10 | **Post-quantum: hardcoded RSA/ECDSA sizes** — key generation with deprecated algorithms | CWE-327 | Medium | `(RSA\|rsa).*generate.*(1024\|2048)` without hybrid PQ |

---

## JavaScript / TypeScript

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **Prototype pollution via deep merge** — recursive merge without `__proto__`/`constructor` guard | CWE-1321 | Critical | `(deepMerge\|merge\|assign\|extend)\(` with `\[key\]` assignment, no `__proto__` check |
| 2 | **LLM prompt injection in template literal** — user input in AI API calls | CWE-77 | High | `` (openai\|anthropic).*`.*\$\{.*(req\|input\|user)\b `` |
| 3 | **npm install hook code execution** — postinstall scripts with network calls or shell execution | CWE-829 | High | `"(preinstall\|postinstall\|install)":\s*"(curl\|wget\|node\s\|sh\s\|bash\s)` |
| 4 | **GraphQL introspection enabled in production** — introspection not disabled | CWE-200 | Medium | `introspection\s*:\s*true` in GraphQL server setup |
| 5 | **GraphQL query depth unlimited** — no depth limiting middleware | CWE-400 | High | `(ApolloServer\|graphqlHTTP)\(` without `depthLimit\|costAnalysis\|validationRules` |
| 6 | **Next.js Server Actions SSRF** — `"use server"` with `fetch(${...})` user-controlled URL | CWE-918 | Critical | `"use server"` with `fetch\(.*\$\{` |
| 7 | **Node.js `vm` module sandbox escape** — `runInNewContext`/`createContext` is not a security boundary | CWE-265 | Critical | `require\s*\(\s*['"]vm['"]\).*runInNewContext\|createContext` |
| 8 | **Prisma raw query injection** — `$queryRaw`/`$executeRaw` with interpolation | CWE-89 | Critical | `` \$queryRaw\s*`\|\$executeRaw\s*` `` with `${...}` |
| 9 | **Exposed secrets in client bundle** — `process.env.SECRET_*` in client-side code | CWE-798 | High | `process\.env\.(DATABASE\|DB_\|SECRET\|API_KEY\|PASSWORD\|TOKEN)` in `src/\|public/\|client/` |
| 10 | **Unsafe eval of AI output** — executing LLM-generated code without sandboxing | CWE-94 | Critical | `(eval\|Function)\(.*\b(response\|completion\|output\|generated\|ai)\b` |

---

## Java

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **Spring Actuator exposed without auth** — `management.endpoints.web.exposure.include=*` | CWE-200 | Critical | `management\.endpoints\.web\.exposure\.include\s*=\s*\*` |
| 2 | **SpEL injection** — `SpelExpressionParser().parseExpression` with user input | CWE-917 | Critical | `SpelExpressionParser\(\)\.parseExpression\(.*request\|param\|input` |
| 3 | **Spring annotation bypass on generics** — `@PreAuthorize` on generic superclasses not enforced (CVE-2025-41248/41249) | CWE-862 | Critical | AST: `@PreAuthorize`/`@Secured` on generic interfaces/abstract classes |
| 4 | **ObjectInputStream without filter** — `new ObjectInputStream()` without `setObjectInputFilter` (Java 17+) | CWE-502 | Critical | `new\s+ObjectInputStream\(` without `setObjectInputFilter\|ObjectInputFilter` |
| 5 | **Jackson polymorphic deserialization** — `@JsonTypeInfo(Id.CLASS)` or `enableDefaultTyping` | CWE-502 | Critical | `@JsonTypeInfo\s*\(.*Id\.CLASS\|enableDefaultTyping` |
| 6 | **gRPC server without TLS** — `ServerBuilder.forPort()` without `useTransportSecurity()` | CWE-319 | High | `ServerBuilder\.forPort\(` without `useTransportSecurity` |
| 7 | **Fail-open exception handling in auth** — catch blocks granting access on failure (OWASP A10:2025) | CWE-755 | High | AST: catch blocks in auth methods returning success/true |
| 8 | **Spring STOMP WebSocket without auth** — STOMP endpoint without authentication interceptor | CWE-306 | High | `registerStompEndpoints\(` without `configureClientInboundChannel` |
| 9 | **Hardcoded weak cipher strings** — `Cipher.getInstance("DES"\|"AES/ECB"\|"RC4")` | CWE-327 | Medium | `Cipher\.getInstance\(\s*"(DES\|DESede\|RC[24]\|AES/ECB\|Blowfish)"` |
| 10 | **Missing Content-Type on multipart upload** — accepting uploads without MIME verification | CWE-434 | High | `MultipartFile.*getBytes\(\)` without `getContentType` check |

---

## PHP

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **`unserialize()` without allowed_classes** — raw unserialize on untrusted data | CWE-502 | Critical | `unserialize\s*\((?!.*allowed_classes)` |
| 2 | **`extract()` with superglobals** — variable injection from user input | CWE-621 | Critical | `extract\(\s*\$_(GET\|POST\|REQUEST\|COOKIE)` |
| 3 | **Laravel Blade `{!! !!}` raw output** — unescaped user content | CWE-79 | High | `\{!!\s*\$` |
| 4 | **`preg_replace` with `/e` modifier** — code execution via regex | CWE-94 | Critical | `preg_replace\s*\(.*['"/][a-z]*e[a-z]*['"]` |
| 5 | **Laravel `$guarded = []`** — mass assignment protection disabled | CWE-915 | High | `\$guarded\s*=\s*\[\s*\]` |
| 6 | **`assert()` with string argument** — code execution (pre-PHP 8.0) | CWE-94 | Critical | `assert\s*\(\s*["'].*\$` |
| 7 | **Laravel APP_KEY in source code** — hardcoded encryption key | CWE-798 | Critical | `APP_KEY\s*=\s*base64:[A-Za-z0-9+/=]{32,}` |
| 8 | **Variable variables `$$` with user input** — indirect variable access | CWE-621 | High | `\$\$_(GET\|POST\|REQUEST\|COOKIE)` |
| 9 | **Redis PubSub unserialize** — deserializing messages without class restriction (CVE-2026-23524) | CWE-502 | Critical | `unserialize\(.*\$message\|\$data.*redis\|pubsub` |
| 10 | **Unsafe file upload path** — `move_uploaded_file` with user-controlled destination | CWE-22 | Critical | Taint: `$_FILES` path → `move_uploaded_file` second arg |

---

## Ruby

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **ERB template injection via `render inline:`** — user input in inline templates | CWE-94 | Critical | `render\s+inline:.*\#\{.*params\|request` |
| 2 | **`constantize` with user input** — arbitrary class instantiation | CWE-470 | Critical | `(constantize\|safe_constantize).*params` |
| 3 | **Rails `where` with string interpolation** — SQL injection | CWE-89 | Critical | `\.where\s*\(\s*["'].*\#\{` |
| 4 | **`instance_eval`/`class_eval` with user input** — code injection | CWE-94 | Critical | `(instance_eval\|class_eval)\s*.*params\|request` |
| 5 | **Rails `render file:` traversal** — directory traversal via params | CWE-22 | Critical | `render\s+file:.*params` |
| 6 | **Active Storage unsafe variant** — dangerous image transformation (CVE-2025-24293) | CWE-94 | High | `\.variant\(.*\b(convert\|define\|process)\b` |
| 7 | **ANSI escape injection in logs** — terminal injection via unsanitized input (CVE-2025-55193) | CWE-117 | Medium | `Rails\.logger\.\w+\(.*params\|request` |
| 8 | **`Rack::Directory` in production** — directory listing enabled (CVE-2026-22860) | CWE-22 | High | `Rack::Directory\.new` |
| 9 | **Mass assignment without strong params** — `Model.new(params)` without `permit` | CWE-915 | High | `\.(new\|create\|update)\(params\b` without `\.permit\(` |
| 10 | **URI credential leakage** — `URI.join` retaining userinfo across hosts (CVE-2025-27221) | CWE-200 | Medium | `URI\.(join\|merge)\(` with credential-bearing URIs |

---

## Kotlin

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **PendingIntent without FLAG_IMMUTABLE** — mutable PendingIntent hijacking | CWE-927 | High | `PendingIntent\.(getActivity\|getService\|getBroadcast)\(` without `FLAG_IMMUTABLE` |
| 2 | **Content provider SQL injection** — `contentResolver.query` with interpolation | CWE-89 | Critical | `contentResolver\.query\(.*\$\{.*\+` |
| 3 | **Ktor CORS wildcard origin** — `anyHost()` allowing all origins | CWE-346 | High | `install\(CORS\).*anyHost\(\)` |
| 4 | **Room `@RawQuery` injection** — `SimpleSQLiteQuery` with string concatenation | CWE-89 | Critical | `SimpleSQLiteQuery\(.*\$\{` |
| 5 | **Trust-all TrustManager** — empty `checkServerTrusted` | CWE-295 | Critical | `checkServerTrusted.*\{\s*\}` |
| 6 | **Exported component without permission** — `exported=true` without `android:permission` | CWE-926 | High | `android:exported\s*=\s*"true"` without `android:permission` |
| 7 | **Jetpack Compose WebView JS enabled** — `javaScriptEnabled = true` with dynamic URL | CWE-79 | High | `AndroidView.*WebView.*javaScriptEnabled\s*=\s*true` |
| 8 | **Implicit broadcast receiver** — `registerReceiver` without `RECEIVER_NOT_EXPORTED` | CWE-927 | Medium | `registerReceiver\(` without `RECEIVER_NOT_EXPORTED` |
| 9 | **Coroutine exception swallowed** — `launch {}` without error handler in security code | CWE-755 | Medium | `launch\s*\{` without `CoroutineExceptionHandler\|supervisorScope\|try` |
| 10 | **Hardcoded API key in source** — string literal API keys | CWE-798 | High | `(val\|var)\s+\w*(apiKey\|apiSecret\|token)\w*\s*=\s*"[A-Za-z0-9+/=_-]{16,}"` |

---

## Swift

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **Core Data predicate injection** — `NSPredicate(format:)` with user input interpolation | CWE-943 | Critical | `NSPredicate\(format:.*\\\(` with user data |
| 2 | **URL scheme hijacking** — `openURL` without `canOpenURL` validation | CWE-939 | High | `openURL\(` without `canOpenURL` validation |
| 3 | **Unsafe URLSession trust override** — `completionHandler(.useCredential)` always | CWE-295 | Critical | `completionHandler\(\.useCredential.*challenge\.proposedCredential` |
| 4 | **WKWebView message handler injection** — `didReceive message` flowing into `evaluateJavaScript` | CWE-79 | High | `didReceive\s+message.*WKScriptMessage` → `evaluateJavaScript` |
| 5 | **`UnsafeRawPointer`/`UnsafeMutablePointer`** — manual memory management | CWE-119 | High | `Unsafe(Raw\|Mutable)Pointer\|withUnsafe` |
| 6 | **Missing SSL pinning in Alamofire** — disabled evaluation or `allHostsMustBeEvaluated: false` | CWE-295 | High | `ServerTrustManager\(.*disableEvaluation\|allHostsMustBeEvaluated:\s*false` |
| 7 | **Hardcoded Firebase/API keys** — inline key material in source | CWE-798 | High | `AIza[0-9A-Za-z_-]{35}\|FirebaseApp\.configure` with inline key |
| 8 | **Unprotected deep link handling** — `application(_:open url:)` without scheme/host validation | CWE-939 | High | `func application.*open.*url.*URL` without `url.scheme ==\|url.host ==` |
| 9 | **Clipboard data exposure** — writing sensitive data to `UIPasteboard.general` | CWE-200 | Medium | `UIPasteboard\.general\.(string\|setValue)\s*=` near sensitive vars |
| 10 | **Force-unwrapping in network handlers** — `data!`/`response!` in URLSession callbacks (OWASP A10:2025) | CWE-755 | Medium | `\b(data\|response)!\b` in URLSession completion handlers |

---

## Rust

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **`std::mem::transmute` type confusion** — transmute between incompatible types | CWE-843 | Critical | `transmute::<` between differently-sized types |
| 2 | **`Box::from_raw` double-free risk** — raw pointer ownership transfer | CWE-415 | Critical | `Box::from_raw\(` |
| 3 | **Integer overflow in unsafe blocks** — unchecked arithmetic (CVE-2026-25541 / bytes crate) | CWE-190 | High | `unsafe\s*\{[^}]*(\.add\(\|\.offset\(\|\+\s*\w+)` without `checked_add` |
| 4 | **FFI boundary without null check** — C function return used without null check | CWE-476 | High | `extern "C"` return `*` used with `.as_ref().unwrap()` |
| 5 | **`libc::` unsafe C functions** — `libc::memcpy`, `libc::strcpy` etc. | CWE-120 | High | `libc::(memcpy\|strcpy\|strcat\|sprintf\|gets)\(` |
| 6 | **Tokio async race condition** — mutable ref held across `.await` without sync | CWE-362 | High | Mutable reference across `.await` without `Mutex`/`RwLock` |
| 7 | **Cargo wildcard dependency** — `dependency = "*"` enabling supply chain attacks | CWE-829 | High | `=\s*"\*"` in `Cargo.toml` |
| 8 | **Diesel raw SQL format injection** — `sql_query(format!(...))` | CWE-89 | Critical | `sql_query\(.*format!\|&format!` |
| 9 | **Unsafe block without safety comment** — `unsafe {}` without `// SAFETY:` documentation | CWE-676 | Medium | `unsafe\s*\{` without preceding `// SAFETY:` |
| 10 | **Missing `#[deny(unsafe_op_in_unsafe_fn)]`** — unsafe fns allowing implicit unsafe ops | CWE-676 | Medium | `pub\s+unsafe\s+fn` without crate-level `#[deny(unsafe_op_in_unsafe_fn)]` |

---

## C#

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **BinaryFormatter usage** — removed in .NET 9, insecure by design | CWE-502 | Critical | `new\s+BinaryFormatter` |
| 2 | **JSON.NET `TypeNameHandling != None`** — polymorphic deserialization | CWE-502 | Critical | `TypeNameHandling\s*=\s*TypeNameHandling\.(All\|Auto\|Objects\|Arrays)` |
| 3 | **Blazor `MarkupString` with user input** — raw HTML rendering | CWE-79 | Critical | `MarkupString\(` with user input |
| 4 | **EF Core `FromSqlRaw` injection** — string interpolation in raw SQL | CWE-89 | Critical | `(FromSqlRaw\|ExecuteSqlRaw)\(\$"` |
| 5 | **Minimal API missing authorization** — endpoints without `.RequireAuthorization()` | CWE-862 | High | `app\.Map(Get\|Post\|Put\|Delete)` without `.RequireAuthorization()` |
| 6 | **gRPC channel without TLS** — `GrpcChannel.ForAddress("http://")` | CWE-319 | High | `GrpcChannel\.ForAddress\(\s*"http://` |
| 7 | **Missing anti-forgery token** — `[HttpPost]` without `[ValidateAntiForgeryToken]` | CWE-352 | High | `\[HttpPost\]` without `\[ValidateAntiForgeryToken\]` |
| 8 | **Regex without timeout (ReDoS)** — `new Regex()` without `MatchTimeout` | CWE-1333 | Medium | `new\s+Regex\(` without `RegexOptions\|MatchTimeout` |
| 9 | **`UseDeveloperExceptionPage` in production** — stack trace exposure | CWE-209 | Medium | `app\.UseDeveloperExceptionPage\(\)` without `#if DEBUG\|IsDevelopment` |
| 10 | **Weak password hashing** — MD5/SHA1/SHA256 for passwords instead of bcrypt/Argon2 | CWE-916 | High | `(MD5\|SHA1\|SHA256)\.Create\(\)` in password context |

---

## Perl

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **Two-argument `open` with user input** — shell injection via pipe | CWE-78 | Critical | `open\s*\(\s*\w+\s*,\s*\$` (two-arg form) |
| 2 | **`Storable::thaw` on untrusted data** — deserialization of network input | CWE-502 | Critical | `Storable::(thaw\|retrieve)\(` with network/file input |
| 3 | **CGI response splitting** — CRLF injection in headers | CWE-113 | High | `print\s+".*\\r\\n.*\$\w+` |
| 4 | **DBI `do()` with interpolation** — SQL injection | CWE-89 | Critical | `\$dbh->do\s*\(\s*["'].*\$` |
| 5 | **`require` with variable** — arbitrary module loading | CWE-94 | Critical | `require\s+\$` (variable module name) |
| 6 | **Regex with user input (ReDoS)** — attacker-controlled patterns | CWE-1333 | High | `=~\s*/.*\$` where variable is user input |
| 7 | **Weak hash for passwords** — `Digest::MD5`/`Digest::SHA1` for passwords | CWE-328 | High | `Digest::(MD5\|SHA1).*password\|passwd` |
| 8 | **MIME::Lite header injection** — user input in email headers | CWE-93 | High | `MIME::Lite->new\(.*To\s*=>.*\$` |
| 9 | **CGI::Cookie parse DoS** — crafted input causing resource exhaustion (CVE-2025-27219) | CWE-400 | Medium | `CGI::Cookie->parse\(` with untrusted input |
| 10 | **Taint mode disabled** — scripts handling network data without `-T` flag | CWE-20 | Medium | `^#!/.*perl` without `-T` in shebang |

---

## Lua

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **OpenResty `ngx.req.get_uri_args` in SQL** — query params in SQL string | CWE-89 | Critical | `ngx\.req\.get_uri_args.*query\|execute` |
| 2 | **Redis injection** — `redis:` calls with `ngx.var`/`args` | CWE-89 | High | `redis.*:.*\(.*ngx\.var\|args\[` |
| 3 | **SSRF via `ngx.location.capture`** — user-controlled URL in subrequest | CWE-918 | Critical | `ngx\.location\.capture\(.*ngx\.var\|args` |
| 4 | **Redis Lua sandbox escape** — dynamic code loading in Redis (CVE-2025-49844) | CWE-416 | Critical | `redis\.call.*loadstring\|redis\.call.*load` |
| 5 | **JWT validation bypass** — `jwt:verify_jwt_obj` without algorithm check | CWE-347 | Critical | `jwt:verify_jwt_obj\(` without `alg` check |
| 6 | **LuaJIT FFI unsafe pointer** — `ffi.cast` to pointer types | CWE-119 | High | `ffi\.cast\(.*"\.*\*"\|ffi\.new\(.*\[` |
| 7 | **LuaSocket without TLS** — `socket.connect` without `ssl.wrap` | CWE-319 | High | `socket\.(connect\|tcp)\(` without `ssl\.wrap` |
| 8 | **`string.dump` code leak** — bytecode dumped in response context | CWE-200 | Medium | `string\.dump\(` in response/output context |
| 9 | **Missing HTTPS redirect** — `ngx.redirect` to HTTP URL | CWE-319 | High | `ngx\.redirect\(.*http://` |
| 10 | **Insecure `math.random`** — weak RNG in auth/token/session context | CWE-330 | High | `math\.random\(` in auth/token/session context |

---

## Groovy

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **Jenkins `readFile`/`writeFile` path traversal** — user-controlled paths in pipeline | CWE-22 | Critical | `(readFile\|writeFile).*\$\{.*params\|input` |
| 2 | **`@Grab` dependency injection** — untrusted repository dependencies | CWE-829 | High | `@Grab\(` without `@GrabResolver` pointing to trusted repo |
| 3 | **Jenkins `load` step arbitrary script** — loading scripts with user-controlled paths | CWE-94 | Critical | `load\s+["'].*\$\{` in Jenkinsfile |
| 4 | **Grails `render text:` XSS** — rendering user params as text | CWE-79 | High | `render\s+text:.*params` |
| 5 | **Spring `@Value` SpEL injection** — SpEL expressions in `@Value` annotations | CWE-917 | Critical | `@Value\s*\(\s*["']\$\{.*\#\{` |
| 6 | **`JsonSlurper` on untrusted URL** — parsing JSON from remote sources | CWE-502 | Medium | `new\s+JsonSlurper\(\)\.parse.*URL\|http` |
| 7 | **Jenkins `httpRequest` SSRF** — user-controlled URL in HTTP request step | CWE-918 | High | `httpRequest\s+url:.*\$\{.*params\|env` |
| 8 | **Grails GORM `executeUpdate` injection** — GString interpolation in HQL | CWE-89 | Critical | `executeUpdate\s*\(\s*["'].*\$\{` |
| 9 | **Pipeline `input` step without timeout** — stalled pipelines (DoS) | CWE-400 | Medium | `input\s+message:` without `timeout\s*\(` wrapper |
| 10 | **`@NonCPS` with security operations** — sandbox-escaped methods doing sensitive work | CWE-94 | High | `@NonCPS` with file I/O or network calls |

---

## Zig

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **Buffer overflow via `@memcpy`** — copying without length validation | CWE-120 | Critical | `@memcpy\(` without bounds check |
| 2 | **`std.c.system()` command injection** — calling C `system()` function | CWE-78 | Critical | `std\.c\.system\(\|std\.c\.popen\(` |
| 3 | **Integer overflow in `@intCast`** — narrowing cast that can panic | CWE-190 | High | `@intCast\(` with type narrowing |
| 4 | **Allocator use-after-free** — using memory after `allocator.free()` | CWE-416 | Critical | `allocator.free(ptr)` followed by `ptr` usage |
| 5 | **Missing `errdefer` for resource cleanup** — allocated resources not freed on error | CWE-401 | Medium | `try.*alloc\(` without `errdefer.*free` |
| 6 | **`@embedFile` with sensitive data** — embedding secrets in binary | CWE-798 | High | `@embedFile\(.*key\|secret\|password\|cert` |
| 7 | **`std.net` without TLS** — plaintext network connections | CWE-319 | High | `std\.net\.Stream\b` without TLS context |
| 8 | **Sentinel-terminated slice bypass** — `@ptrCast` on `[:0]` slices | CWE-120 | High | `@ptrCast\(.*\.ptr\)` to C functions without `[:0]` |
| 9 | **C interop without null termination** — Zig slices to C expecting null-terminated strings | CWE-170 | High | Zig slice `.ptr` passed to C string functions |
| 10 | **`catch unreachable` on fallible ops** — treating errors as impossible | CWE-755 | High | `catch\s+unreachable` |

---

## C / C++

| # | Rule | CWE | Severity | Detection Approach |
|---|------|-----|----------|-------------------|
| 1 | **`sprintf` buffer overflow** — use `snprintf` instead | CWE-121 | Critical | `sprintf\s*\(` |
| 2 | **`gets()` usage** — banned function, always vulnerable | CWE-120 | Critical | `\bgets\s*\(` |
| 3 | **Integer overflow before `malloc`** — unchecked multiplication | CWE-190 | Critical | `malloc\s*\(\s*\w+\s*\*\s*(sizeof\|size\|len)` without overflow check |
| 4 | **Format string vulnerability** — `printf(var)` without format literal | CWE-134 | Critical | `(printf\|fprintf\|sprintf\|syslog)\s*\(\s*\w+\s*\)` |
| 5 | **`system()`/`popen()` with user data** — shell command execution | CWE-78 | Critical | `(system\|popen)\s*\(` with non-literal argument |
| 6 | **`strncpy` without null termination** — missing explicit null terminator | CWE-170 | High | `strncpy\(` without null terminator assignment |
| 7 | **Use-after-free in realloc** — `ptr = realloc(ptr, ...)` pattern | CWE-416 | Critical | `ptr\s*=\s*realloc\s*\(\s*ptr` |
| 8 | **OpenSSL deprecated API** — `SSLv23_method`, `TLSv1_method` | CWE-327 | High | `SSL_library_init\|SSLv23_method\|TLSv1_method` |
| 9 | **Container namespace breakout** — `setns`/`unshare` with CLONE_NEW flags | CWE-269 | Critical | `(setns\|unshare)\s*\(.*CLONE_NEW(NS\|PID\|NET\|USER)` |
| 10 | **Post-quantum: hardcoded RSA/ECDSA params** — deprecated key sizes | CWE-327 | Medium | `RSA_generate_key_ex\(.*,\s*(1024\|2048)\s*,` |

---

## Sources

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) — New categories A03 (Supply Chain) and A10 (Exceptional Conditions)
- [CWE Top 25 2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) — Buffer overflows enter list
- [OWASP LLM Top 10](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) — Prompt injection #1 risk
- [CISA/FBI Buffer Overflow Alert 2025](https://www.cisa.gov/news-events/alerts/2025/02/12/cisa-and-fbi-warn-malicious-cyber-actors-using-buffer-overflow-vulnerabilities-compromise-software)
- [NIST Post-Quantum Cryptography Standards](https://www.nist.gov/pqc) — ML-KEM, ML-DSA, SLH-DSA
- [Spring CVE-2025-41248/41249](https://spring.io/blog/2025/09/15/spring-framework-and-spring-security-fixes-for-CVE-2025-41249-and-CVE-2025-41248/) — Annotation bypass on generics
- [Laravel Reverb CVE-2026-23524](https://dailycve.com/laravel-reverb-insecure-deserialization-cve-2026-23524-critical/) — Redis PubSub deserialization
- [Python PLY CVE-2025-56005](https://www.esecurityplanet.com/threats/cve-2025-56005-python-ply-flaw-enables-remote-code-execution/) — Pickle in parser tables
- [Rust bytes CVE-2026-25541](https://windowsforum.com/threads/rust-bytes-vulnerability-cve-2026-25541-memory-safety-in-bytesmut-reserve.403939/) — Integer overflow in unsafe
- [Redis Lua CVE-2025-49844](https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844) — Sandbox escape
- [Ruby CVE-2025-27221/61594](https://www.ruby-lang.org/en/news/2025/02/26/security-advisories/) — URI credential leakage
- [runC Container Escape CVEs 2025](https://www.esecurityplanet.com/news/runc-vulnerability-container-risk/) — CVE-2025-31133, CVE-2025-52565
- [PickleScan Zero-Days](https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/) — Pickle bypass techniques
- [CISA npm Supply Chain Alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Perl CVE-2025-40909](https://www.ibm.com/support/pages/security-bulletin) — Untrusted search path in threads
- [CGI.pm CVE-2025-27219](https://nvd.nist.gov/) — Cookie parse DoS
