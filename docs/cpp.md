# C++ Language Support in GTSS

## Overview

GTSS provides deep security scanning for C++ code across four analysis layers: regex-based rules (Layer 1), tree-sitter AST structural analysis (Layer 2), taint source-to-sink tracking (Layer 3), and interprocedural call graph analysis (Layer 4). C++ coverage emphasizes memory safety, which is the dominant vulnerability class in C/C++ codebases, while also covering injection, cryptographic misuse, secrets exposure, and other categories through both C++-specific and language-agnostic rules.

## Detection

C++ files are identified by file extension in `internal/analyzer/analyzer.go`:

| Extension | Detected As |
|-----------|-------------|
| `.cpp`    | C++         |
| `.cc`     | C++         |
| `.cxx`    | C++         |
| `.c++`    | C++         |
| `.hpp`    | C++         |
| `.hh`     | C++         |
| `.hxx`    | C++         |
| `.h++`    | C++         |

Note: `.h` files are detected as C, not C++. Header-only C++ libraries using `.h` will be analyzed under C rules, which share the same memory safety rule set.

## Taint Analysis Coverage

### Sources (38 total)

Taint sources represent entry points where untrusted data enters the program.

#### iostream / stdin

| Source ID | Function | Category | Description |
|-----------|----------|----------|-------------|
| `cpp.cin.extraction` | `std::cin >>` | User Input | Extraction operator reads user input |
| `cpp.getline.cin` | `std::getline(cin, ...)` | User Input | getline reading from cin |
| `cpp.getline.stream` | `std::getline(...)` | Network | getline reading from any stream |

#### C-inherited stdio

| Source ID | Function | Category | Description |
|-----------|----------|----------|-------------|
| `cpp.cstdio.scanf` | `scanf()` | User Input | Formatted input from stdin |
| `cpp.cstdio.gets` | `gets()` | User Input | Line read from stdin (banned in C11) |
| `cpp.cstdio.fgets` | `fgets()` | File Read | Read from file stream |
| `cpp.cstdio.fread` | `fread()` | File Read | Binary read from file stream |
| `cpp.cstdio.fscanf` | `fscanf()` | File Read | Formatted input from file stream |
| `cpp.cstdio.sscanf` | `sscanf()` | User Input | Parse formatted data from string |
| `cpp.cstdio.getchar` | `getchar()` | User Input | Single character from stdin |
| `cpp.cstdio.fgetc` | `fgetc()` | File Read | Single character from file stream |
| `cpp.cstdlib.getenv` | `getenv()` | Env Variable | Environment variable read |
| `cpp.main.argv` | `argv[]` | CLI Argument | Command-line arguments |
| `cpp.gnu.getline` | `getline(&...)` | File Read | POSIX/GNU getline from stream |

#### POSIX / Socket networking

| Source ID | Function | Category | Description |
|-----------|----------|----------|-------------|
| `cpp.unistd.read` | `read(fd, ...)` | Network | POSIX read from file descriptor |
| `cpp.socket.recv` | `recv()` | Network | Socket receive |
| `cpp.socket.recvfrom` | `recvfrom()` | Network | Socket receive with source address |
| `cpp.socket.recvmsg` | `recvmsg()` | Network | Socket message receive |

#### Web framework sources (Crow, Pistache, cpp-httplib)

| Source ID | Function | Category |
|-----------|----------|----------|
| `cpp.crow.request.url_params` | `req.url_params.get()` | User Input |
| `cpp.crow.request.body` | `req.body` | User Input |
| `cpp.crow.request.url` | `req.url` | User Input |
| `cpp.crow.request.get_header` | `req.get_header_value()` | User Input |
| `cpp.pistache.request.body` | `request.body()` | User Input |
| `cpp.pistache.request.query` | `request.query()` | User Input |
| `cpp.pistache.request.param` | `request.param()` | User Input |
| `cpp.httplib.request.body` | `req.body` | User Input |
| `cpp.httplib.request.get_param` | `req.get_param_value()` | User Input |
| `cpp.httplib.request.get_header` | `req.get_header_value()` | User Input |

#### Qt framework

| Source ID | Function | Category |
|-----------|----------|----------|
| `cpp.qt.qurl` | `QUrl()` | User Input |
| `cpp.qt.qnetworkreply.readall` | `QNetworkReply->readAll()` | Network |
| `cpp.qt.qlineedit.text` | `QLineEdit->text()` | User Input |
| `cpp.qt.qtextedit.toplaintext` | `QTextEdit->toPlainText()` | User Input |

#### Boost.Asio / Boost.Beast

| Source ID | Function | Category |
|-----------|----------|----------|
| `cpp.boost.asio.read` | `boost::asio::read()` | Network |
| `cpp.boost.asio.async_read` | `boost::asio::async_read()` | Network |
| `cpp.boost.asio.read_some` | `.read_some()` | Network |
| `cpp.boost.asio.read_until` | `boost::asio::read_until()` | Network |
| `cpp.boost.beast.http.request.body` | `request.body()` | User Input |
| `cpp.boost.beast.http.request.target` | `request.target()` | User Input |

#### Deserialization / File stream

| Source ID | Function | Category |
|-----------|----------|----------|
| `cpp.ifstream.read` | `ifstream >> / .read()` | File Read |
| `cpp.boost.serialization` | `boost::archive::*_iarchive` | Deserialized |
| `cpp.protobuf.parsefromstring` | `ParseFromString() / ParseFromArray()` | Deserialized |

### Sinks (48 total)

Sinks are dangerous functions that should not receive unsanitized tainted data.

#### Command injection

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.system` | `system()` | Critical | CWE-78 |
| `cpp.popen` | `popen()` | Critical | CWE-78 |
| `cpp.exec` | `execl/execv` family | Critical | CWE-78 |

#### Format string

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.printf.format` | `printf(var)` | Critical | CWE-134 |
| `cpp.sprintf.format` | `sprintf()` | Critical | CWE-134 |
| `cpp.fprintf.format` | `fprintf()` | High | CWE-134 |
| `cpp.snprintf.format` | `snprintf()` | High | CWE-134 |
| `cpp.syslog.format` | `syslog()` | High | CWE-134 |
| `cpp.fmt.format.tainted` | `fmt::format()` | High | CWE-134 |
| `cpp.std.format.tainted` | `std::format()` (C++20) | High | CWE-134 |

#### Buffer overflow

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.strcpy` | `strcpy()` | Critical | CWE-120 |
| `cpp.strcat` | `strcat()` | Critical | CWE-120 |
| `cpp.memcpy` | `memcpy()` | High | CWE-120 |
| `cpp.memmove` | `memmove()` | High | CWE-120 |

#### File operations (path traversal)

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.fopen` | `fopen()` | High | CWE-22 |
| `cpp.ofstream` | `std::ofstream()` | High | CWE-22 |
| `cpp.fstream.open` | `.open()` | High | CWE-22 |
| `cpp.posix.open` | `open(..., O_*)` | High | CWE-22 |
| `cpp.access` | `access()` | Medium | CWE-22 |
| `cpp.remove` | `remove()` | High | CWE-22 |
| `cpp.rename` | `rename()` | High | CWE-22 |
| `cpp.unlink` | `unlink()` | High | CWE-22 |
| `cpp.mkdir` | `mkdir()` | Medium | CWE-22 |

#### SQL injection

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.sql.exec` | `sqlite3_exec / mysql_query / PQexec` | Critical | CWE-89 |
| `cpp.sql.prepare` | `sqlite3_prepare / mysql_stmt_prepare` | High | CWE-89 |

#### Memory management

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.new.array.raw` | `new T[n]` | High | CWE-190 |
| `cpp.malloc.tainted.size` | `malloc(tainted)` | High | CWE-190 |
| `cpp.realloc.tainted.size` | `realloc(ptr, tainted)` | High | CWE-190 |
| `cpp.calloc.tainted.size` | `calloc(tainted, ...)` | High | CWE-190 |
| `cpp.alloca.tainted.size` | `alloca(tainted)` | Critical | CWE-190 |

#### STL unchecked access / smart pointer misuse

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.stl.operator.bracket` | `container[i]` | Medium | CWE-125 |
| `cpp.stl.front.empty` | `.front()` | Medium | CWE-125 |
| `cpp.stl.back.empty` | `.back()` | Medium | CWE-125 |
| `cpp.unique_ptr.get` | `unique_ptr::get()` | Medium | CWE-416 |
| `cpp.unique_ptr.release` | `unique_ptr::release()` | Medium | CWE-401 |
| `cpp.cstr.to.cfunc` | `.c_str()` to C function | Medium | CWE-676 |

#### Network / SSRF

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.curl.setopt.url` | `curl_easy_setopt(CURLOPT_URL)` | High | CWE-918 |
| `cpp.socket.connect` | `connect()` | High | CWE-918 |
| `cpp.send.network` | `send()` | Medium | CWE-319 |

#### Cryptographic sinks

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.rand.insecure` | `rand() / srand()` | High | CWE-338 |
| `cpp.openssl.*` | OpenSSL legacy block cipher + weak hash functions | High/Medium | CWE-327, CWE-328 |
| `cpp.openssl.md5` | `MD5() / MD5_Init()` | Medium | CWE-328 |
| `cpp.openssl.sha1` | `SHA1() / SHA1_Init()` | Medium | CWE-328 |

Note: The `cpp.openssl.*` sink family includes detection for deprecated OpenSSL cipher modes (CWE-327) and weak hash algorithms. See `internal/taint/languages/cpp_sinks.go` for the full list of patterns.

#### XSS / Deserialization / XML / Redirect / Log sinks

| Sink ID | Function | Severity | CWE |
|---------|----------|----------|-----|
| `cpp.crow.response.write` | `crow::response / res.write()` | High | CWE-79 |
| `cpp.pistache.response.send` | `response.send()` | High | CWE-79 |
| `cpp.boost.serialization.input` | `boost::archive::*_iarchive` | Critical | CWE-502 |
| `cpp.protobuf.parse.untrusted` | `ParseFrom*()` | High | CWE-502 |
| `cpp.libxml2.parse` | `xmlParseMemory / xmlParseFile` | High | CWE-611 |
| `cpp.crow.redirect` | `crow::response(301/302)` | High | CWE-601 |
| `cpp.spdlog.info/error/warn` | `spdlog::info/error/warn()` | Medium | CWE-117 |
| `cpp.cout.tainted` | `std::cout <<` | Low | CWE-117 |
| `cpp.cerr.tainted` | `std::cerr <<` | Low | CWE-117 |

### Sanitizers (37 total)

Sanitizers are functions or patterns that neutralize taint, marking data as safe for specific sink categories.

#### Smart pointers (memory safety)

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `cpp.make_unique` | `std::make_unique<T>` | Command/memory sinks |
| `cpp.make_shared` | `std::make_shared<T>` | Command/memory sinks |
| `cpp.unique_ptr.ctor` | `std::unique_ptr<T>` | Command/memory sinks |
| `cpp.shared_ptr.ctor` | `std::shared_ptr<T>` | Command/memory sinks |

#### Bounds-checked access

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `cpp.container.at` | `.at()` | Command/memory sinks |
| `cpp.container.empty.check` | `.empty()` | Command/memory sinks |
| `cpp.container.size.check` | `.size()` | Command/memory sinks |

#### Safe string operations

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `cpp.strncpy` | `strncpy()` | Command/memory sinks |
| `cpp.strncat` | `strncat()` | Command/memory sinks |
| `cpp.snprintf.sanitizer` | `snprintf()` | Command/memory sinks |
| `cpp.strlcpy` | `strlcpy()` | Command/memory sinks |
| `cpp.strlcat` | `strlcat()` | Command/memory sinks |
| `cpp.memcpy_s` | `memcpy_s()` | Command/memory sinks |
| `cpp.string.substr` | `.substr()` | Command/memory sinks |
| `cpp.string.find` | `.find()` | Command/memory sinks |

#### Modern C++ safe types

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `cpp.std.string` | `std::string` | Command/memory sinks |
| `cpp.std.array` | `std::array<T>` | Command/memory sinks |
| `cpp.std.vector` | `std::vector<T>` | Command/memory sinks |
| `cpp.std.span` | `std::span<T>` (C++20) | Command/memory sinks |
| `cpp.std.string_view` | `std::string_view` | Command/memory sinks |
| `cpp.gsl.span` | `gsl::span<T>` | Command/memory sinks |
| `cpp.gsl.not_null` | `gsl::not_null<T>` | Command/memory sinks |

#### Input validation / SQL parameterization

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `cpp.stoi` | `std::stoi/stol/stof/stod()` | SQL + command sinks |
| `cpp.sqlite3.bind` | `sqlite3_bind_*()` | SQL sinks |
| `cpp.mysql.stmt.bind` | `mysql_stmt_bind_param()` | SQL sinks |
| `cpp.sqlite3.mprintf` | `sqlite3_mprintf()` | SQL sinks |

#### HTML/URL encoding

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `cpp.html.escape` | `html_escape() / escapeHtml()` | HTML output sinks |
| `cpp.crow.mustache` | `crow::mustache::` | HTML output sinks |
| `cpp.curl.escape` | `curl_easy_escape()` | Redirect + URL fetch sinks |
| `cpp.basename` | `basename()` | File write sinks |

#### Cryptographic safe alternatives

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `cpp.openssl.rand.bytes` | `RAND_bytes()` | Crypto sinks |
| `cpp.random.device` | `std::random_device` | Crypto sinks |
| `cpp.openssl.aes.gcm` | `EVP_aes_*_gcm()` | Crypto sinks |
| `cpp.openssl.sha256` | `SHA256() / EVP_sha256()` | Crypto sinks |

#### XML safe parsing / RAII

| Sanitizer ID | Pattern | Neutralizes |
|--------------|---------|-------------|
| `cpp.libxml2.disable_entities` | `xmlSubstituteEntitiesDefault(0)` | XPath/XXE sinks |
| `cpp.libxml2.nonet` | `XML_PARSE_NONET` | XPath/XXE sinks |
| `cpp.lock_guard` | `std::lock_guard / scoped_lock / unique_lock` | Command sinks |

## Rule Coverage

### C++-specific rules (memory safety)

These six rules target C/C++ exclusively and are the core of memory safety analysis:

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| `GTSS-MEM-001` | Banned Functions | Critical | `gets()`, `strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `scanf` with `%s`, `atoi/atol` |
| `GTSS-MEM-002` | Format String Vulnerability | Critical | `printf(var)`, `fprintf(fd, var)`, `syslog(pri, var)`, `snprintf(buf, sz, var)` |
| `GTSS-MEM-003` | Buffer Overflow | High | `memcpy` with variable size, `strncpy(dst, src, strlen(src))`, `read/recv` into fixed buffer |
| `GTSS-MEM-004` | Memory Management | High | Double free, use-after-free (tracks `free()`/`delete` then dereference) |
| `GTSS-MEM-005` | Integer Overflow in Allocation | High | `malloc(n * sizeof(...))` overflow, `calloc` with variable count, `realloc` with arithmetic |
| `GTSS-MEM-006` | Null Pointer Dereference | Medium | `malloc/calloc/realloc` return used without NULL check within 5 lines |

### Cross-language rules that apply to C++

Rules with `LangAny` or explicit `LangCPP` in their language list:

| Category | Rule ID | Name | Applies via |
|----------|---------|------|-------------|
| Crypto | `GTSS-CRY-003` | Weak Cipher | `LangAny` fallback |
| Crypto | `GTSS-CRY-004` | Hardcoded IV | `LangAny` fallback |
| Crypto | `GTSS-CRY-005` | Insecure TLS | `LangAny` fallback |
| Crypto | `GTSS-CRY-006` | Weak Key Size | `LangAny` fallback |
| Crypto | `GTSS-CRY-007` | Plaintext Protocol | `LangAny` |
| Crypto | `GTSS-CRY-009` | Predictable Seed | Explicit `LangCPP` (detects `srand(time(NULL))`) |
| Crypto | `GTSS-CRY-010` | Hardcoded Key | `LangAny` fallback |
| Secrets | `GTSS-SEC-002` | API Key Exposure | `LangAny` |
| Secrets | `GTSS-SEC-003` | Private Key in Code | `LangAny` |
| Secrets | `GTSS-SEC-004` | Connection String | `LangAny` |
| Secrets | `GTSS-SEC-006` | Environment Leak | `LangAny` |
| Traversal | `GTSS-TRV-001` | Path Traversal | `LangAny` |
| Traversal | `GTSS-TRV-003` | Archive Extraction | `LangAny` |
| Traversal | `GTSS-TRV-007` | Null Byte File Path | `LangAny` |
| SSRF | `GTSS-SSRF-001` | URL From User Input | `LangAny` |
| SSRF | `GTSS-SSRF-002` | Internal Network Access | `LangAny` |
| Auth | `GTSS-AUTH-007` | Privilege Escalation Patterns | `LangAny` |
| Generic | `GTSS-GEN-012` | Insecure Download Patterns | `LangAny` |
| Misconfig | `GTSS-MISC-003` | Missing Security Headers | `LangAny` |
| Validation | `GTSS-VAL-005` | File Upload Hardening | `LangAny` |

## Example Detections

### Buffer overflow via banned function

```cpp
#include <cstring>

void log_message(const char *message) {
    char buffer[128];
    // GTSS-MEM-001: strcpy has no bounds checking
    strcpy(buffer, message);
}
```

GTSS flags `strcpy()` as a banned function (Critical severity) and suggests using `strlcpy()`, `strncpy()`, or `snprintf()`.

### Use-after-free

```cpp
void process_logout(Session *session) {
    session->invalidate();
    delete session;
    // GTSS-MEM-004: use-after-free on next line
    session->print_info();
}
```

GTSS tracks the `delete session` call and flags subsequent use of `session` on the next line.

### Command injection via system()

```cpp
#include <cstdlib>
#include <string>

void check_host(const std::string &hostname) {
    std::string cmd = "nslookup " + hostname;
    // Taint: argv -> hostname -> cmd -> system()
    int rc = system(cmd.c_str());
}
```

The taint engine traces `argv[]` (source) through string concatenation into `system()` (sink), producing a Critical finding for CWE-78.

## Safe Patterns

### Smart pointers instead of raw new/delete

```cpp
#include <memory>

void create_session(const std::string &user, int id) {
    // Safe: unique_ptr handles deallocation automatically (RAII)
    auto session = std::make_unique<Session>(user, id);
    session->print_info();
    // No manual delete needed -- destructor runs at scope exit
}
```

`std::make_unique` is recognized as a sanitizer. No memory management findings are emitted.

### Bounds-checked container access

```cpp
#include <vector>
#include <stdexcept>

std::string get_user(const std::vector<std::string> &users, size_t index) {
    // Safe: .at() throws std::out_of_range on invalid index
    return users.at(index);
}
```

The `.at()` method is a registered sanitizer, neutralizing the unchecked-access taint sink. The `operator[]` variant without `.at()` would be flagged.

### Safe command execution with execve

```cpp
#include <unistd.h>

int safe_ping(const std::string &hostname) {
    if (!is_valid_hostname(hostname)) return 1;

    pid_t pid = fork();
    if (pid == 0) {
        // Safe: execve with argument array, no shell interpretation
        const char *args[] = {"/usr/bin/ping", "-c", "3",
                              hostname.c_str(), nullptr};
        const char *envp[] = {nullptr};
        execve(args[0], const_cast<char *const *>(args),
               const_cast<char *const *>(envp));
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
```

Using `execve` with a separate argument array avoids shell interpretation. Combined with input validation, this pattern does not trigger command injection findings.

## Limitations

1. **Limited AST analysis.** Tree-sitter AST analysis is now available for C++, providing comment-aware false positive filtering and structural code inspection. However, complex multi-line expressions, macro expansions, and template metaprogramming can still produce false positives or false negatives. For example, a macro wrapping `strncpy` will still be recognized as a sanitizer, but the macro call site may not be correlated to the underlying function.

2. **Header file classification.** Files with the `.h` extension are classified as C rather than C++. C++ header-only libraries using `.h` will be scanned under C rules (which share the same memory rules) but will not receive C++-specific taint catalog entries for modern frameworks like Boost.Asio or Qt.

3. **Limited injection rule coverage.** The `GTSS-INJ-001` (SQL Injection) and `GTSS-INJ-002` (Command Injection) regex rules do not list C++ in their explicit language set. SQL injection and command injection in C++ are instead detected through the taint analysis engine (Layer 2) via the `cpp.sql.exec` and `cpp.system` sinks, which requires source-to-sink data flow to be visible within the scanned code fragment.

4. **No lifetime analysis.** The use-after-free detection (`GTSS-MEM-004`) uses a simplified heuristic that tracks `free()`/`delete` calls and subsequent pointer use within the same function scope. It cannot detect use-after-free across function boundaries, through move semantics, or via iterator invalidation.

5. **No RAII completeness checking.** While GTSS recognizes smart pointers and RAII guards as sanitizers, it does not verify that all raw pointers in a translation unit are properly wrapped. A mix of raw and smart pointers in the same codebase may have gaps.

6. **No template instantiation tracking.** Generic code using templates is not analyzed for all possible instantiations. Detection depends on whether the concrete call pattern matches a sink regex.

7. **Framework coverage scope.** Web framework sources are limited to Crow, Pistache, cpp-httplib, Qt, Boost.Asio, and Boost.Beast. Other C++ web frameworks (Drogon, Oat++, CivetWeb, etc.) are not covered by framework-specific source patterns, though generic patterns like `recv()` and `getenv()` still apply.

8. **No Windows API sources.** Windows-specific APIs (`ReadFile`, `GetCommandLineW`, `RegQueryValueEx`, etc.) are not tracked as taint sources. Detection on Windows-specific C++ code relies on generic patterns only.
