# Swift Language Support

## Overview

Batou provides security scanning for Swift/iOS code, covering URLSession TLS validation, App Transport Security configuration, Keychain storage accessibility, WKWebView injection, SQLite injection, hardcoded secrets, insecure random number generation, insecure data storage, deprecated UIWebView usage, and jailbreak detection bypass patterns. Swift is supported through four analysis layers: regex-based pattern rules (348 rules), tree-sitter AST structural analysis (comment-aware false positive filtering and structural code inspection via `internal/analyzer/`), taint source-to-sink tracking, and interprocedural call graph analysis.

Swift taint analysis uses the tree-sitter AST walker (`internal/taint/tsflow/`) which provides accurate tracking through `property_declaration` assignments, `call_expression` nodes, and `navigation_expression` member accesses by walking the parsed AST.

## Detection

Swift files are identified by the `.swift` file extension. Detection is handled in `internal/analyzer/analyzer.go`:

| Extension | Language Constant |
|-----------|-------------------|
| `.swift`  | `rules.LangSwift` |

Files matching `.swift` are scanned through four analysis layers:
- **Layer 1**: Regex-based rules (348 pattern matching rules on source code)
- **Layer 2**: Tree-sitter AST structural analysis (comment-aware false positive filtering and structural code inspection)
- **Layer 3**: Taint analysis (source-to-sink tracking with sanitizer recognition)
- **Layer 4**: Interprocedural call graph analysis (cross-function data flow)

Test files (paths matching `Test.swift` or `_test.swift`) are excluded from scanning to reduce false positives.

## Taint Analysis Coverage

The Swift taint catalog is defined in `internal/taint/languages/swift_*.go` and tracks 14 sources, 34 sinks, and 10 sanitizers.

### Sources (User Input Entry Points)

#### Network Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `swift.urlsession.datatask` | `URLSession.shared.dataTask` | URLSession network response data |
| `swift.urlrequest` | `URLRequest(url:` | URL request construction |
| `swift.httpcookie` | `HTTPCookieStorage.shared.cookies` | HTTP cookie values |

#### User Interface Input

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `swift.uitextfield.text` | `textField.text` | Text field user input |
| `swift.uitextview.text` | `textView.text` | Text view user input |
| `swift.pasteboard.read` | `UIPasteboard.general.string` | Pasteboard clipboard data |

#### URL and Navigation

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `swift.url.queryitems` | `URLComponents().queryItems` | URL query parameters |
| `swift.wkwebview.navigation` | `navigationAction.request.url` | WKWebView navigation URL |
| `swift.deeplink.url` | `application(_:open url:)` | Deep link / URL scheme input |

#### Storage and Environment

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `swift.userdefaults.read` | `UserDefaults.standard.string(forKey:` | UserDefaults stored value |
| `swift.processinfo.environment` | `ProcessInfo.processInfo.environment` | Process environment variables |
| `swift.commandline.arguments` | `CommandLine.arguments` | Command-line arguments |
| `swift.bundle.resource` | `Bundle.main.path(forResource:` | Bundle resource path |

#### Deserialization

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `swift.jsondecoder` | `JSONDecoder().decode(` | JSON deserialized data |

### Sinks (Dangerous Functions)

#### SQL Injection (CWE-89)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `swift.sqlite3.exec` | `sqlite3_exec(` | Critical | SQLite query execution |
| `swift.sqlite3.prepare` | `sqlite3_prepare_v2(` | High | SQLite prepare statement |

#### Command Execution (CWE-78)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `swift.process.launch` | `Process()` / `NSTask()` | Critical | OS process execution |
| `swift.process.arguments` | `.arguments =` / `.launchPath =` | Critical | Process arguments |

#### JavaScript / HTML Injection (CWE-79)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `swift.wkwebview.evaluatejavascript` | `.evaluateJavaScript(` | High | WebView JavaScript evaluation |
| `swift.wkwebview.loadhtmlstring` | `.loadHTMLString(` | High | WebView HTML loading |

#### File Operations (CWE-22)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `swift.filemanager.createfile` | `FileManager.default.createFile(atPath:` | High | File creation |
| `swift.filemanager.contents` | `FileManager.default.contents(atPath:` | High | File read |
| `swift.filemanager.movecopy` | `FileManager.default.moveItem(` | High | File move/copy |
| `swift.data.write` | `.write(to: URL` | High | Data write to file |

#### Network / SSRF (CWE-918)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `swift.urlsession.request` | `URLSession.shared.dataTask(with:` | High | URL request (SSRF) |

#### Insecure Storage (CWE-922)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `swift.userdefaults.set` | `UserDefaults.standard.set(` | Medium | Insecure UserDefaults storage |
| `swift.keychain.accessible.always` | `kSecAttrAccessibleAlways` | High | Insecure Keychain accessibility |

#### Logging (CWE-532)

| Sink ID | Method | Severity | Description |
|---------|--------|----------|-------------|
| `swift.oslog` | `os_log(` / `Logger().info(` | Medium | OS logging with sensitive data |
| `swift.nslog` | `NSLog(` | Medium | NSLog with sensitive data |

### Sanitizers

| Sanitizer ID | Pattern | Neutralizes | Description |
|-------------|---------|-------------|-------------|
| `swift.data.protection` | `.completeFileProtection` | File write, Crypto | iOS Data Protection API |
| `swift.keychain.secure.access` | `kSecAttrAccessibleWhenUnlocked` | Crypto | Secure Keychain accessibility |
| `swift.security.encrypt` | `SecKeyCreateEncryptedData` / `AES.GCM.seal` | Crypto, File write | Apple Security/CryptoKit encryption |
| `swift.url.validation` | `URL(string:) != nil` | URL fetch, Redirect | URL format validation |
| `swift.string.addingpercentencoding` | `.addingPercentEncoding(` | HTML output, URL fetch | URL percent encoding |
| `swift.sqlite3.bind` | `sqlite3_bind_text(` | SQL query | SQLite parameterized binding |
| `swift.int.init` | `Int(_:)` | SQL query, Command | Integer conversion |
| `swift.contains.check` | `allowedHosts.contains(` | URL fetch, Redirect | Allowlist validation |
| `swift.cryptokit.hash` | `SHA256.hash(` | Crypto | CryptoKit secure hashing |
| `swift.string.xmlescape` | `.replacingOccurrences(of: "<"` | HTML output | HTML entity escaping |

## Rule Coverage

### Swift-Specific Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| BATOU-SWIFT-001 | InsecureURLSession | High | URLSession delegates that disable TLS certificate validation |
| BATOU-SWIFT-002 | ATSBypass | High | App Transport Security bypass (NSAllowsArbitraryLoads) in Info.plist |
| BATOU-SWIFT-003 | InsecureKeychain | High | Keychain items with kSecAttrAccessibleAlways (accessible when locked) |
| BATOU-SWIFT-004 | UIWebViewUsage | Medium | Deprecated UIWebView usage (lacks security features) |
| BATOU-SWIFT-005 | HardcodedSecrets | Critical | Hardcoded API keys, passwords, tokens as string literals |
| BATOU-SWIFT-006 | InsecureRandom | Medium | Insecure random (srand/rand, arc4random without uniform) |
| BATOU-SWIFT-007 | SQLiteInjection | Critical | SQL injection via string interpolation in sqlite3_exec/prepare |
| BATOU-SWIFT-008 | WKWebViewInjection | High | WKWebView evaluateJavaScript/loadHTMLString with user input |
| BATOU-SWIFT-009 | InsecureDataStorage | High | Sensitive data in UserDefaults or NSCoding archives |
| BATOU-SWIFT-010 | JailbreakDetectionBypass | Low | Easily bypassed jailbreak detection checks |

### Cross-Language Rules Applicable to Swift

Rules marked with `LangAny` also apply to Swift files, including:

- BATOU-SEC-001: Hardcoded passwords
- BATOU-SEC-002: API key exposure
- BATOU-CRY-007: Plaintext HTTP URLs
- BATOU-AUTH-007: Privilege escalation patterns (CWE-269) - HIGH
- BATOU-GEN-012: Insecure download patterns (CWE-494) - HIGH
- BATOU-MISC-003: Missing security headers (CWE-1021, CWE-693) - MEDIUM
- BATOU-VAL-005: File upload hardening (CWE-434) - HIGH

## Example Detections

### SQL Injection via String Interpolation

```swift
// DETECTED: BATOU-SWIFT-007 (Critical) + taint flow swift.uitextfield.text -> swift.sqlite3.exec
func searchUser(db: OpaquePointer?, searchField: UITextField) {
    let name = searchField.text ?? ""
    let query = "SELECT * FROM users WHERE name = '\(name)'"
    sqlite3_exec(db, query, nil, nil, nil)
}
```

Batou flags the string interpolation `\(name)` inside a SQL query string passed to `sqlite3_exec`, and traces taint from `textField.text` (source) through `name` into the SQL query (sink).

### WKWebView JavaScript Injection

```swift
// DETECTED: BATOU-SWIFT-008 (High) + taint flow swift.url.queryitems -> swift.wkwebview.evaluatejavascript
func handleDeepLink(url: URL) {
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    let message = components?.queryItems?.first(where: { $0.name == "msg" })?.value ?? ""
    webView.evaluateJavaScript("showMessage('\(message)')")
}
```

Batou detects string interpolation in `evaluateJavaScript` with a value derived from URL query parameters.

### Insecure Keychain Storage

```swift
// DETECTED: BATOU-SWIFT-003 (High)
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,
    kSecValueData as String: tokenData
]
```

Batou flags `kSecAttrAccessibleAlways` because it makes the Keychain item accessible even when the device is locked.

## Safe Patterns

### Parameterized SQLite Queries

```swift
// SAFE: Parameterized query with sqlite3_bind_text
func findUser(db: OpaquePointer?, name: String) {
    var stmt: OpaquePointer?
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, nil)
    sqlite3_bind_text(stmt, 1, name, -1, nil)
    sqlite3_step(stmt)
    sqlite3_finalize(stmt)
}
```

The parameterized query uses `?` placeholders with `sqlite3_bind_text` to safely bind user input. Batou recognizes `sqlite3_bind_*` functions as sanitizers for SQL injection sinks.

### Secure Keychain Storage

```swift
// SAFE: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecValueData as String: tokenData
]
```

Using `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` ensures the item is only accessible when the device is unlocked and prevents backup extraction.

### Static WKWebView JavaScript

```swift
// SAFE: Static JavaScript string without interpolation
webView.evaluateJavaScript("document.title") { result, error in
    // use result
}
```

Batou does not flag `evaluateJavaScript` calls that use static string literals without interpolation or concatenation.

## Limitations

- **SwiftUI views**: Taint tracking through SwiftUI's declarative view builders has limited precision. Data passed through `@State`, `@Binding`, `@ObservedObject` property wrappers may not always propagate taint correctly.

- **Combine/async-await**: Taint tracking does not follow data through Combine publisher chains or across async/await boundaries. A tainted value passed through `.map`, `.flatMap`, or across `await` points may lose its taint status.

- **Third-party libraries**: While SQLite3 and WKWebView sinks are covered, third-party database wrappers (GRDB, SQLite.swift) are only partially detected through their SQLite3 usage patterns.

- **Info.plist detection**: ATS bypass detection (BATOU-SWIFT-002) works on `.plist` XML files. Binary plist files or entitlement files in non-standard locations may not be scanned.

- **Objective-C bridging**: When Swift code calls Objective-C methods via bridging headers, the taint engine may not track data flow across the language boundary.

- **Protocol extensions**: Taint propagation through Swift protocol extensions and default implementations has limited accuracy.

- **Property wrappers**: Custom property wrappers that transform or store tainted data are not tracked by the taint engine.
