# Kotlin Language Support

## Overview

GTSS provides security scanning for Kotlin code, covering Android applications (SQLite, WebView, Intent, SharedPreferences, exported components), Ktor server-side applications, Spring Boot Kotlin, and kotlinx.serialization. Analysis includes four layers: regex-based pattern rules (348 rules), tree-sitter AST structural analysis (comment-aware false positive filtering and structural code inspection via `internal/analyzer/`), intraprocedural taint tracking (source to sink with sanitizer recognition), and interprocedural call graph analysis.

## Detection

Kotlin files are identified by the `.kt` and `.kts` file extensions. The `DetectLanguage` function in `internal/analyzer/analyzer.go` maps these extensions to the `LangKotlin` language constant.

## Taint Analysis Coverage

Taint analysis tracks data flow from untrusted sources through the program to dangerous sinks, recognizing sanitizer functions that neutralize specific threat categories.

### Sources (21 tracked)

Sources are entry points where untrusted data enters the application.

#### Ktor Framework (6)

| ID | Method | Description |
|---|---|---|
| `kotlin.ktor.queryparameters` | `call.request.queryParameters` | Ktor query parameters |
| `kotlin.ktor.receive` | `call.receive()` | Ktor request body deserialization |
| `kotlin.ktor.headers` | `call.request.headers` | Ktor request headers |
| `kotlin.ktor.parameters` | `call.parameters` | Ktor route parameters |
| `kotlin.ktor.receivemultipart` | `call.receiveMultipart()` | Ktor multipart form data |
| `kotlin.ktor.receivetext` | `call.receiveText()` | Ktor raw request body text |

#### Spring Kotlin (4)

| ID | Annotation | Description |
|---|---|---|
| `kotlin.spring.requestparam` | `@RequestParam` | Request parameter binding |
| `kotlin.spring.requestbody` | `@RequestBody` | Request body deserialization |
| `kotlin.spring.pathvariable` | `@PathVariable` | URL path variable |
| `kotlin.spring.requestheader` | `@RequestHeader` | Request header binding |

#### Android (6)

| ID | Method | Description |
|---|---|---|
| `kotlin.android.intent.getstringextra` | `intent.getStringExtra()` | Android Intent string extra |
| `kotlin.android.intent.extras` | `intent.extras` | Android Intent extras bundle |
| `kotlin.android.bundle.getstring` | `bundle.getString()` | Android Bundle string value |
| `kotlin.android.edittext.gettext` | `EditText.getText()` | Android EditText user input |
| `kotlin.android.contentresolver.query` | `contentResolver.query()` | Android ContentResolver query result |
| `kotlin.android.intent.data` | `intent.data` | Android Intent data URI |

#### Standard Library / Environment (3)

| ID | Method | Description |
|---|---|---|
| `kotlin.readLine` | `readLine()` | Kotlin standard input |
| `kotlin.system.getenv` | `System.getenv()` | Environment variable |
| `kotlin.args` | `fun main(args)` | Command-line arguments |

#### Network / IO (1)

| ID | Method | Description |
|---|---|---|
| `kotlin.bufferedreader.readline` | `readLine()` / `readText()` | BufferedReader input |

#### Deserialization (1)

| ID | Method | Description |
|---|---|---|
| `kotlin.jackson.readvalue` | `ObjectMapper.readValue()` | Jackson deserialized JSON data |

### Sinks (48 tracked)

Sinks are dangerous operations where tainted data can cause vulnerabilities.

#### SQL Injection (CWE-89)

| ID | Method | Severity |
|---|---|---|
| `kotlin.android.rawquery` | `SQLiteDatabase.rawQuery()` | Critical |
| `kotlin.android.execsql` | `SQLiteDatabase.execSQL()` | Critical |
| `kotlin.jpa.createquery` | `EntityManager.createQuery()` | Critical |
| `kotlin.jpa.createnativequery` | `EntityManager.createNativeQuery()` | Critical |
| `kotlin.exposed.exec` | `Transaction.exec()` | Critical |

#### Command Injection (CWE-78)

| ID | Method | Severity |
|---|---|---|
| `kotlin.runtime.exec` | `Runtime.getRuntime().exec()` | Critical |
| `kotlin.processbuilder` | `ProcessBuilder()` | Critical |

#### File Operations / Path Traversal (CWE-22)

| ID | Method | Severity |
|---|---|---|
| `kotlin.file.new` | `File()` | High |
| `kotlin.fileinputstream` | `FileInputStream()` | High |
| `kotlin.android.openfileoutput` | `openFileOutput()` | High |

#### XSS / WebView (CWE-79)

| ID | Method | Severity |
|---|---|---|
| `kotlin.android.webview.loadurl` | `WebView.loadUrl()` | High |
| `kotlin.android.webview.evaluatejavascript` | `WebView.evaluateJavascript()` | Critical |
| `kotlin.ktor.respondtext` | `call.respondText()` | Medium |
| `kotlin.ktor.respondhtml` | `call.respondHtml()` | High |

#### Network / SSRF (CWE-918)

| ID | Method | Severity |
|---|---|---|
| `kotlin.url.openconnection` | `URL().openConnection()` | High |
| `kotlin.url.new` | `URL()` | High |
| `kotlin.okhttp.request` | `Request.Builder().url()` | High |

#### Deserialization (CWE-502)

| ID | Method | Severity |
|---|---|---|
| `kotlin.objectinputstream.readobject` | `ObjectInputStream.readObject()` | Critical |
| `kotlin.gson.fromjson` | `Gson().fromJson()` | Medium |
| `kotlin.serialization.decodefromstring` | `Json.decodeFromString()` | Medium |

#### Log Injection (CWE-117)

| ID | Method | Severity |
|---|---|---|
| `kotlin.log.info` | `Logger.info()` | Medium |
| `kotlin.log.error` | `Logger.error()` | Medium |
| `kotlin.android.log` | `Log.d/i/w/e/v()` | Medium |

#### Redirect (CWE-601)

| ID | Method | Severity |
|---|---|---|
| `kotlin.ktor.respondredirect` | `call.respondRedirect()` | High |

### Sanitizers (16 tracked)

Sanitizers neutralize tainted data for specific sink categories.

#### SQL Parameterization

| ID | Method | Neutralizes |
|---|---|---|
| `kotlin.preparedstatement` | `prepareStatement()` | SQL query |
| `kotlin.android.selectionargs` | `rawQuery(query, arrayOf(...))` | SQL query |
| `kotlin.room.dao` | `@Query/@Insert/@Update/@Delete` | SQL query |
| `kotlin.exposed.parameterized` | Exposed DSL `.select { }` | SQL query |

#### HTML Encoding

| ID | Method | Neutralizes |
|---|---|---|
| `kotlin.html.escapehtml` | `Html.escapeHtml()` / `TextUtils.htmlEncode()` | HTML output |
| `kotlin.spring.htmlutils` | `HtmlUtils.htmlEscape()` | HTML output |

#### URL Encoding

| ID | Method | Neutralizes |
|---|---|---|
| `kotlin.urlencoder.encode` | `URLEncoder.encode()` | HTML output, redirect |

#### Input Validation

| ID | Method | Neutralizes |
|---|---|---|
| `kotlin.regex.matches` | `Regex.matches()` | SQL, command, HTML |
| `kotlin.require` | `require()` / `check()` | SQL, command |
| `kotlin.spring.valid` | `@Valid` / `@Validated` | SQL, command, HTML |
| `kotlin.ktor.receivewithvalidation` | Ktor RequestValidation plugin | SQL, command, HTML |

#### Type Coercion

| ID | Method | Neutralizes |
|---|---|---|
| `kotlin.toint` | `.toInt()` / `.toLong()` / `.toIntOrNull()` | SQL, command, file |

#### Path Traversal Prevention

| ID | Method | Neutralizes |
|---|---|---|
| `kotlin.file.name` | `File.name` | File write |
| `kotlin.path.normalize` | `.normalize()` / `.canonicalPath` | File write |

#### Cryptography

| ID | Method | Neutralizes |
|---|---|---|
| `kotlin.bcrypt` | `BCrypt.hashpw()` | Crypto |
| `kotlin.android.encryptedsharedprefs` | `EncryptedSharedPreferences.create()` | Crypto |

## Rule Coverage

Rules that explicitly include Kotlin in their `Languages()` method, plus rules with `LangAny` that apply to all languages including Kotlin.

### Kotlin-Specific Rules (8 rules)

| Rule ID | Name | What It Detects | Severity |
|---|---|---|---|
| `GTSS-KT-001` | AndroidSQLInjection | `rawQuery()` / `execSQL()` with string concatenation or Kotlin string template interpolation (`${ }`) | Critical |
| `GTSS-KT-002` | AndroidIntentInjection | Implicit intents with user-controlled data via `sendBroadcast()` or `startActivity()` with `putExtra()` / `setData()` | High |
| `GTSS-KT-003` | WebViewJSInjection | `loadUrl("javascript:..." + input)`, `loadUrl("javascript:...${input}")`, `evaluateJavascript()` with concatenation, `addJavascriptInterface()` | Critical |
| `GTSS-KT-004` | InsecureSharedPreferences | Sensitive data (passwords, tokens, API keys, secrets) stored in unencrypted `SharedPreferences` without `EncryptedSharedPreferences` | High |
| `GTSS-KT-005` | ExportedComponents | AndroidManifest.xml components with `android:exported="true"` without `android:permission` protection | Medium |
| `GTSS-KT-006` | KtorCORSMisconfig | Ktor CORS plugin with `anyHost()`, especially combined with `allowCredentials = true` | Medium |
| `GTSS-KT-007` | UnsafeCoroutineException | `GlobalScope.launch { }` / `GlobalScope.async { }` without `CoroutineExceptionHandler` or `SupervisorJob` | Medium |
| `GTSS-KT-008` | KotlinSerializationUntrusted | `Json.decodeFromString()` in context with user input sources (Ktor, Spring, Android intents) | High |

### Cross-Language Rules Applicable to Kotlin

Rules with `LangAny` that also apply when scanning `.kt` files:

| Rule ID | Name | What It Detects |
|---|---|---|
| `GTSS-INJ-001` | SQLInjection | SQL queries built via string concatenation |
| `GTSS-INJ-002` | CommandInjection | OS command construction with unsanitized input |
| `GTSS-SEC-001` | HardcodedPassword | Hardcoded passwords and credentials |
| `GTSS-SEC-002` | APIKeyExposure | Hardcoded API keys from known providers |
| `GTSS-SEC-003` | PrivateKeyInCode | PEM-encoded private keys in source |
| `GTSS-SEC-004` | ConnectionString | Database connection strings with credentials |
| `GTSS-TRV-001` | PathTraversal | File operations with unsanitized user input |
| `GTSS-GEN-001` | DebugModeEnabled | Debug mode left enabled |
| `GTSS-CRY-001` | WeakHashing | Broken hash algorithms used for security |
| `GTSS-AUTH-007` | PrivilegeEscalation | Privilege escalation patterns (CWE-269) |
| `GTSS-GEN-012` | InsecureDownload | Insecure download patterns (CWE-494) |
| `GTSS-MISC-003` | MissingSecurityHeaders | Missing security headers (CWE-1021, CWE-693) |
| `GTSS-VAL-005` | FileUploadHardening | File upload hardening (CWE-434) |

## Example Detections

### Android SQL Injection via String Template

GTSS flags `rawQuery()` with Kotlin string template interpolation:

```kotlin
// DETECTED: GTSS-KT-001 + taint flow kotlin.android.intent.getstringextra -> kotlin.android.rawquery
val userId = intent.getStringExtra("id")
val cursor = db.rawQuery("SELECT * FROM users WHERE id = ${userId}", null)
```

### WebView JavaScript Injection

GTSS detects `loadUrl("javascript:...")` with string concatenation:

```kotlin
// DETECTED: GTSS-KT-003
val userInput = editText.text.toString()
webView.loadUrl("javascript:updateField('" + userInput + "')")
```

### Insecure SharedPreferences

GTSS catches sensitive data stored in unencrypted SharedPreferences:

```kotlin
// DETECTED: GTSS-KT-004
val prefs = context.getSharedPreferences("user_prefs", Context.MODE_PRIVATE)
prefs.edit().putString("password", password).apply()
```

### Ktor CORS Misconfiguration

GTSS detects overly permissive CORS with credentials:

```kotlin
// DETECTED: GTSS-KT-006
install(CORS) {
    anyHost()
    allowCredentials = true
}
```

## Safe Patterns

### Parameterized SQLite Query

GTSS recognizes `rawQuery` with `arrayOf()` selection args as safe:

```kotlin
// SAFE: parameterized query with selection args
val cursor = db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))
```

### Room DAO

GTSS recognizes Room `@Query` annotations as parameterized:

```kotlin
// SAFE: Room DAO with parameterized query
@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE name = :name")
    fun findByName(name: String): User
}
```

### EncryptedSharedPreferences

GTSS recognizes `EncryptedSharedPreferences` as a safe storage mechanism:

```kotlin
// SAFE: encrypted storage for sensitive data
val prefs = EncryptedSharedPreferences.create(
    "secure_prefs", masterKey, context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
prefs.edit().putString("password", password).apply()
```

### Structured Concurrency

GTSS does not flag structured concurrency scopes (viewModelScope, lifecycleScope, coroutineScope):

```kotlin
// SAFE: structured concurrency with proper exception handling
class MyViewModel : ViewModel() {
    fun performTask() {
        viewModelScope.launch {
            val result = riskyOperation()
            processResult(result)
        }
    }
}
```

## Limitations

- **Gradle build files**: `.kts` files used for Gradle build scripts (e.g., `build.gradle.kts`) are detected as Kotlin but may produce false positives since build DSL code is not application code.
- **Kotlin Multiplatform**: Platform-specific source sets (e.g., `iosMain`, `jsMain`) are scanned with the same rules. Platform-specific vulnerabilities (iOS Keychain, browser XSS) may not be covered.
- **Compose UI**: Jetpack Compose `@Composable` functions are not tracked for taint analysis. User input from Compose text fields (`TextField`, `OutlinedTextField`) is not registered as a taint source.
- **Coroutine flow**: Kotlin `Flow`, `StateFlow`, and `SharedFlow` are not tracked for taint propagation. Data flowing through flow operators may lose taint tracking.
- **DSL builders**: Kotlin DSL patterns (type-safe builders, receiver lambdas) may not be fully tracked by taint analysis since the engine does not model Kotlin's receiver types.
- **Spring WebFlux**: Reactive Spring patterns (`Mono`, `Flux`) in Kotlin are not specifically tracked. The taint engine handles standard Spring MVC annotations but not reactive chain operators.
- **Android Navigation**: Navigation component arguments passed via `SafeArgs` are not tracked as taint sources.
- **Ktor plugins**: Custom Ktor plugins that process request data are not tracked. Only built-in `call.receive*()` and `call.request.*` patterns are registered as sources.
