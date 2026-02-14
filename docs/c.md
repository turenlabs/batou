# C Language Support in GTSS

## Overview

GTSS provides deep security scanning for C source files, with particular emphasis on memory safety -- the dominant vulnerability class in C programs. Coverage spans four analysis layers: regex-based rule matching (Layer 1), tree-sitter AST structural analysis providing comment-aware false positive filtering and structural code inspection (Layer 2), taint source-to-sink tracking (Layer 3), and interprocedural call graph analysis (Layer 4). C is one of two languages (alongside C++) with dedicated memory safety rules.

## Detection

C files are identified by file extension in `internal/analyzer/analyzer.go`:

| Extension | Detected As |
|-----------|-------------|
| `.c`      | C           |
| `.h`      | C           |

Header files (`.h`) are classified as C. C++ header extensions (`.hpp`, `.hh`, `.hxx`, `.h++`) are classified as C++ instead.

## Taint Analysis Coverage

The C taint catalog is defined across four files in `internal/taint/languages/`:

- `c_catalog.go` -- registers the `CCatalog` struct
- `c_sources.go` -- 21 taint sources
- `c_sinks.go` -- 40 taint sinks
- `c_sanitizers.go` -- 22 sanitizers

### Sources (Taint Entry Points)

Sources define where untrusted data enters the program.

**Standard Input (stdio)**

| Source ID | Function | Taint Target | Description |
|-----------|----------|-------------|-------------|
| `c.stdin.scanf` | `scanf()` | arg:1 | Formatted input from stdin |
| `c.stdin.fscanf` | `fscanf()` | arg:2 | Formatted input from file stream |
| `c.stdin.sscanf` | `sscanf()` | arg:2 | Formatted input from string |
| `c.stdin.gets` | `gets()` | arg:0 | Unbounded line input from stdin |
| `c.stdin.fgets` | `fgets()` | arg:0 | Line input from file stream |
| `c.stdin.getchar` | `getchar()` | return | Single character from stdin |
| `c.stdin.fgetc` | `fgetc()` | return | Single character from file stream |
| `c.stdin.getline` | `getline()` | arg:0 | POSIX line input with dynamic allocation |
| `c.stdin.read` | `read(STDIN_FILENO, ...)` | arg:1 | POSIX read from stdin fd |

**Command-Line Arguments**

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `c.argv.access` | `argv[...]` | Command-line argument access |
| `c.argc.access` | `argc` | Argument count |

**Environment Variables**

| Source ID | Function | Description |
|-----------|----------|-------------|
| `c.env.getenv` | `getenv()` | Environment variable value |

**Network Input**

| Source ID | Function | Description |
|-----------|----------|-------------|
| `c.net.recv` | `recv()` | Data from network socket |
| `c.net.recvfrom` | `recvfrom()` | Data from socket with source address |
| `c.net.recvmsg` | `recvmsg()` | Message from socket |

**File Input**

| Source ID | Function | Description |
|-----------|----------|-------------|
| `c.file.fread` | `fread()` | Binary data read from file |
| `c.file.read` | `read()` (non-stdin fd) | POSIX read from file descriptor |

**CGI Environment**

| Source ID | Pattern | Description |
|-----------|---------|-------------|
| `c.cgi.query_string` | `getenv("QUERY_STRING")` | CGI query string |
| `c.cgi.request_method` | `getenv("REQUEST_METHOD")` | CGI request method |
| `c.cgi.content_type` | `getenv("CONTENT_TYPE")` | CGI content type |
| `c.cgi.content_length` | `getenv("CONTENT_LENGTH")` | CGI content length |

### Sinks (Dangerous Functions)

Sinks are functions where tainted data can cause harm.

**Buffer Overflow / Memory Corruption (CWE-120, CWE-119, CWE-242)**

| Sink ID | Function | Severity | CWE | Description |
|---------|----------|----------|-----|-------------|
| `c.mem.strcpy` | `strcpy()` | Critical | CWE-120 | Unbounded string copy |
| `c.mem.strcat` | `strcat()` | Critical | CWE-120 | Unbounded string concatenation |
| `c.mem.sprintf` | `sprintf()` | Critical | CWE-120 | Unbounded formatted write |
| `c.mem.vsprintf` | `vsprintf()` | Critical | CWE-120 | Unbounded variadic formatted write |
| `c.mem.memcpy` | `memcpy()` | High | CWE-120 | Memory copy with tainted source/size |
| `c.mem.memmove` | `memmove()` | High | CWE-120 | Memory move with tainted source/size |
| `c.mem.strncpy` | `strncpy()` | High | CWE-120 | Bounded copy with tainted source/size |
| `c.mem.gets` | `gets()` | Critical | CWE-242 | Always vulnerable unbounded stdin read |

**Command Injection (CWE-78)**

| Sink ID | Function | Severity | Description |
|---------|----------|----------|-------------|
| `c.exec.system` | `system()` | Critical | Shell command execution |
| `c.exec.popen` | `popen()` | Critical | Piped command execution |
| `c.exec.execl` | `execl()` | Critical | Process execution |
| `c.exec.execv` | `execv()` | Critical | Process execution with array args |
| `c.exec.execve` | `execve()` | Critical | Process execution with environment |
| `c.exec.execvp` | `execvp()` | Critical | Exec with PATH search |
| `c.exec.execlp` | `execlp()` | Critical | Exec with PATH search (variadic) |
| `c.exec.execle` | `execle()` | Critical | Exec with environment (variadic) |
| `c.exec.execvpe` | `execvpe()` | Critical | Exec with PATH and environment |

**Format String Vulnerability (CWE-134)**

| Sink ID | Function | Severity | Description |
|---------|----------|----------|-------------|
| `c.fmt.printf` | `printf()` | Critical | Tainted format argument |
| `c.fmt.fprintf` | `fprintf()` | Critical | Tainted format to file |
| `c.fmt.snprintf.format` | `snprintf()` | High | Bounded format with tainted format arg |
| `c.fmt.syslog` | `syslog()` | High | Tainted format string in syslog |

**File Operations / Path Traversal (CWE-22, CWE-732)**

| Sink ID | Function | Severity | CWE | Description |
|---------|----------|----------|-----|-------------|
| `c.file.fopen` | `fopen()` | High | CWE-22 | File open with tainted path |
| `c.file.open` | `open()` | High | CWE-22 | POSIX file open with tainted path |
| `c.file.rename` | `rename()` | High | CWE-22 | File rename with tainted path |
| `c.file.unlink` | `unlink()` | High | CWE-22 | File deletion with tainted path |
| `c.file.remove` | `remove()` | High | CWE-22 | File removal with tainted path |
| `c.file.chmod` | `chmod()` | High | CWE-732 | Permission change with tainted path |
| `c.file.access` | `access()` | High | CWE-22 | Access check with tainted path |
| `c.file.stat` | `stat()` | Medium | CWE-22 | Stat with tainted path |
| `c.file.mkdir` | `mkdir()` | High | CWE-22 | Directory creation with tainted path |

**Memory Allocation with Tainted Size (CWE-789)**

| Sink ID | Function | Severity | Description |
|---------|----------|----------|-------------|
| `c.mem.malloc` | `malloc()` | High | Tainted size argument |
| `c.mem.calloc` | `calloc()` | High | Tainted count or size |
| `c.mem.realloc` | `realloc()` | High | Tainted reallocation size |
| `c.mem.alloca` | `alloca()` | Critical | Stack allocation with tainted size |

**SQL Injection (CWE-89)**

| Sink ID | Function | Severity | Description |
|---------|----------|----------|-------------|
| `c.sql.sqlite3_exec` | `sqlite3_exec()` | Critical | SQLite query with tainted SQL |
| `c.sql.mysql_query` | `mysql_query()` | Critical | MySQL query with tainted SQL |
| `c.sql.mysql_real_query` | `mysql_real_query()` | Critical | MySQL real query with tainted SQL |
| `c.sql.pqexec` | `PQexec()` | Critical | PostgreSQL query with tainted SQL |

**Network Output (CWE-319)**

| Sink ID | Function | Severity | Description |
|---------|----------|----------|-------------|
| `c.net.send` | `send()` | Medium | Network send with tainted data |
| `c.net.sendto` | `sendto()` | Medium | Network sendto with tainted data |
| `c.net.write` | `write()` | Medium | POSIX write with tainted data |

### Sanitizers (Taint Neutralizers)

Sanitizers are functions that make tainted data safe for specific sink categories.

**Bounded String Operations** -- neutralize buffer overflow sinks

| Sanitizer ID | Function | Description |
|--------------|----------|-------------|
| `c.bounds.strlcpy` | `strlcpy()` | Bounded string copy |
| `c.bounds.strlcat` | `strlcat()` | Bounded string concatenation |
| `c.bounds.snprintf` | `snprintf()` | Bounded formatted write |
| `c.bounds.strncpy_sized` | `strncpy(..., sizeof(...))` | Bounded copy with sizeof-derived size |
| `c.bounds.strncat` | `strncat()` | Bounded concatenation with length limit |
| `c.bounds.memcpy_s` | `memcpy_s()` | C11 bounds-checked memory copy |

**Input Validation / Numeric Conversion** -- neutralize SQL, command, and file sinks

| Sanitizer ID | Function | Neutralizes | Description |
|--------------|----------|-------------|-------------|
| `c.validate.strtol` | `strtol()` | SQL, command, file | String to long with error checking |
| `c.validate.strtoul` | `strtoul()` | SQL, command, file | String to unsigned long |
| `c.validate.strtod` | `strtod()` | SQL, command | String to double |
| `c.validate.atoi` | `atoi()` | SQL, command | String to integer (numeric restriction) |

**Memory Clearing** -- neutralize crypto sinks

| Sanitizer ID | Function | Description |
|--------------|----------|-------------|
| `c.mem.memset` | `memset()` | Memory clearing for sensitive data |
| `c.mem.explicit_bzero` | `explicit_bzero()` | Cannot be optimized away |
| `c.mem.memset_s` | `memset_s()` | C11 secure clearing |

**SQL Parameterization** -- neutralize SQL injection sinks

| Sanitizer ID | Function | Description |
|--------------|----------|-------------|
| `c.sql.sqlite3_prepare` | `sqlite3_prepare*()` | SQLite prepared statement |
| `c.sql.sqlite3_bind` | `sqlite3_bind_*()` | SQLite parameter binding |
| `c.sql.mysql_real_escape_string` | `mysql_real_escape_string()` | MySQL string escaping |
| `c.sql.mysql_stmt_prepare` | `mysql_stmt_prepare()` | MySQL prepared statement |
| `c.sql.pqexecparams` | `PQexecParams()` | PostgreSQL parameterized query |
| `c.sql.pqprepare` | `PQprepare()` | PostgreSQL prepared statement |
| `c.sql.sqlite3_mprintf` | `sqlite3_mprintf("%q", ...)` | SQLite %q format escaping |

**Path Validation** -- neutralize file operation sinks

| Sanitizer ID | Function | Description |
|--------------|----------|-------------|
| `c.path.basename` | `basename()` | Strips directory traversal components |

## Rule Coverage

Rules that apply to C files fall into two groups: C-specific rules (listed as `LangC` in their Languages) and language-agnostic rules (`LangAny`).

### C-Specific Rules

#### Memory Safety (`internal/rules/memory/memory.go`)

All six memory rules target C and C++ exclusively.

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| GTSS-MEM-001 | Banned Functions | Critical | `gets()`, `strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `scanf` with `%s`, `atoi()`/`atol()` |
| GTSS-MEM-002 | Format String Vulnerability | Critical | `printf(var)`, `fprintf(f, var)`, `syslog(pri, var)`, `snprintf(b, n, var)` -- variable as format string |
| GTSS-MEM-003 | Buffer Overflow | High | `memcpy`/`memmove` with variable size, `strncpy` with `strlen(src)`, `read`/`recv` into fixed buffers |
| GTSS-MEM-004 | Memory Management | High | Double free (calling `free(ptr)` twice), use-after-free (dereferencing freed pointer) |
| GTSS-MEM-005 | Integer Overflow in Allocation | High | `malloc(n * sizeof(...))` multiplication overflow, `calloc` with variable count, `realloc` with arithmetic |
| GTSS-MEM-006 | Null Pointer Dereference | Medium | `malloc`/`calloc`/`realloc` return used without NULL check within 5 lines |

#### Path Traversal (`internal/rules/traversal/traversal.go`)

| Rule ID | Name | Severity | C-Specific Behavior |
|---------|------|----------|---------------------|
| GTSS-TRV-001 | Path Traversal | Critical | Detects `fopen`, `fread`, `fwrite`, `open`, `freopen`, `fdopen`, `remove`, `rename` called with variable arguments (not string literals), flagged when no traversal guard is found |

#### Cryptography (`internal/rules/crypto/crypto.go`)

| Rule ID | Name | Severity | C-Specific Behavior |
|---------|------|----------|---------------------|
| GTSS-CRY-011 | Predictable Seed | High | Detects `srand(time(NULL))` -- time-based seeds make `rand()` output predictable |

### Language-Agnostic Rules (Apply to C via `LangAny`)

These rules use patterns that match across all languages, including C.

| Rule ID | Category | Severity | What It Detects |
|---------|----------|----------|-----------------|
| GTSS-TRV-001 | Traversal | Critical | Dot-dot-slash patterns in file paths (generic fallback) |
| GTSS-TRV-003 | Traversal | High | Unsafe archive extraction (zip slip) |
| GTSS-TRV-008 | Traversal | Medium | Null byte injection in file paths |
| GTSS-SEC-002 | Secrets | High | Hardcoded API keys (AWS, GitHub, Slack, Stripe, etc.) |
| GTSS-SEC-003 | Secrets | Critical | PEM-encoded private keys in source |
| GTSS-SEC-004 | Secrets | High | Database connection strings with embedded credentials |
| GTSS-SEC-006 | Secrets | Medium | Environment variable leaks |
| GTSS-CRY-003 | Crypto | High | Weak/obsolete ciphers |
| GTSS-CRY-004 | Crypto | High | Hardcoded initialization vectors |
| GTSS-CRY-005 | Crypto | High | Insecure TLS configuration |
| GTSS-CRY-006 | Crypto | High | Weak key sizes |
| GTSS-CRY-007 | Crypto | Medium | Plaintext protocols (HTTP, FTP, Telnet) |
| GTSS-SSRF-001 | SSRF | High | URLs constructed from user input |
| GTSS-SSRF-002 | SSRF | High | Access to internal network addresses |
| GTSS-AUTH-007 | Auth | High | Privilege escalation patterns (CWE-269) |
| GTSS-GEN-012 | Generic | High | Insecure download patterns (CWE-494) |
| GTSS-MISC-003 | Misconfig | Medium | Missing security headers (CWE-1021, CWE-693) |
| GTSS-VAL-005 | Validation | High | File upload without proper validation (CWE-434) |

## Example Detections

### Buffer Overflow via strcpy

This triggers **GTSS-MEM-001** (Banned Function) and taint sink **c.mem.strcpy** when the source is user input.

```c
#include <stdio.h>
#include <string.h>

void process_name(const char *input) {
    char buffer[64];
    strcpy(buffer, input);  // FLAGGED: no bounds checking, input may exceed 64 bytes
    printf("Processing: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    process_name(argv[1]);  // argv[1] is tainted
    return 0;
}
```

### Format String Vulnerability

This triggers **GTSS-MEM-002** (Format String Vulnerability) and taint sink **c.fmt.printf**.

```c
void log_message(const char *user_input) {
    printf(user_input);  // FLAGGED: variable used as format string
                         // Attacker can supply "%x%x%x" to read stack memory
}
```

### Command Injection via system()

This triggers taint sink **c.exec.system** (CWE-78) when user input flows into the command string.

```c
void run_diagnostic(const char *hostname) {
    char command[256];
    sprintf(command, "ping -c 3 %s", hostname);
    system(command);  // FLAGGED: tainted input in shell command
}

int main(int argc, char *argv[]) {
    run_diagnostic(argv[1]);  // argv[1] is tainted
    return 0;
}
```

## Safe Patterns

### Bounded String Copy with snprintf

GTSS recognizes `snprintf` as a sanitizer that prevents buffer overflow.

```c
void process_name(const char *input) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s", input);  // SAFE: output bounded to buffer size
    printf("Processing: %s\n", buffer);
}
```

### printf with Literal Format String

GTSS does not flag `printf` when the format string is a literal and user input is a data argument.

```c
void log_message(const char *user_input) {
    printf("%s\n", user_input);  // SAFE: format string is a literal, not a variable
}
```

### Allocation with NULL Check and Overflow Guard

GTSS checks for NULL within 5 lines of a `malloc`/`calloc`/`realloc` call and recognizes overflow guards before allocation.

```c
struct Record *allocate_records(size_t count) {
    if (count > SIZE_MAX / sizeof(struct Record)) {
        return NULL;  // Overflow guard
    }

    struct Record *records = calloc(count, sizeof(struct Record));
    if (records == NULL) {       // SAFE: NULL check present
        return NULL;
    }
    return records;
}
```

## Limitations

1. **No inter-file taint tracking for C.** Taint analysis operates on a single file at a time. If tainted data is passed through a function defined in a different `.c` file, the flow is not tracked across translation units. The call graph (Layer 3) partially mitigates this, but C's separate compilation model limits coverage.

2. **No macro expansion.** GTSS scans source text, not preprocessed output. Macros that wrap dangerous functions (e.g., `#define COPY(d,s) strcpy(d,s)`) are not expanded, so the underlying call is invisible to pattern matching.

3. **No control-flow-sensitive analysis.** The memory management rules (GTSS-MEM-004) use a simple linear scan with function-boundary resets. They cannot track pointer aliasing, conditional frees, or freed pointers passed to other functions.

4. **No SQL injection regex rules for C.** While the taint engine tracks `sqlite3_exec`, `mysql_query`, and `PQexec` as sinks, the regex-based SQL injection rules (GTSS-INJ-001) do not list C in their Languages -- they only apply via taint analysis (Layer 2).

5. **No command injection regex rules for C.** Similarly, the regex-based command injection rules (GTSS-INJ-002) do not list C. Command injection in C is detected solely through taint sinks (`c.exec.system`, `c.exec.popen`, etc.).

6. **Header file ambiguity.** The `.h` extension is always classified as C, even when the header is intended for C++ or mixed C/C++ use. C++-specific rules will not run on `.h` files.

7. **No RTOS or embedded-specific sources.** The source catalog covers POSIX and standard library functions. Embedded-specific input sources (e.g., DMA buffers, hardware registers, RTOS message queues) are not tracked.

8. **Limited sanitizer awareness for custom wrappers.** If a project uses custom safe wrappers around dangerous functions (e.g., a `safe_strcpy` that performs bounds checking), GTSS will not recognize them as sanitizers unless they match one of the known sanitizer patterns.

9. **Confidence decay on unknown functions.** When tainted data passes through an unknown function, taint propagates with 0.8x confidence decay. For C codebases with many small helper functions, this can cause legitimate taint flows to drop below the reporting threshold.
