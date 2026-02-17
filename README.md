# Batou - Runtime SAST For Claude Code

<img width="512" height="512" alt="logo_2" src="https://github.com/user-attachments/assets/a3157fb7-68cb-40af-878f-02dc54f62df9" />


A security scanner that catches vulnerabilities in real-time as AI writes code. Built as a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks), Batou analyzes every file write for security issues across 16 programming languages using a four-layer analysis pipeline.

## How It Works

Batou hooks into Claude Code's `Write`, `Edit`, and `NotebookEdit` operations:

- **PreToolUse**: Scans code before it's written. Blocks critical vulnerabilities (exit code 2) and provides fix guidance.
- **PostToolUse**: Performs deep analysis after writes, giving Claude detailed hints to improve code security.

```
Claude writes code → Batou intercepts → 4-layer scan → Block critical vulns / Hint fixes to Claude
```

## Four-Layer Analysis Pipeline

Each layer builds on the previous one. Every file write passes through all four layers in sequence. Parsed trees and taint flows are shared across layers — each file is parsed once per parser type, and Layer 3's precise dataflow results feed directly into Layer 4's interprocedural analysis.

### Layer 1: Regex Pattern Matching (676 rules, 43 categories)

Fast first pass that matches known vulnerability signatures against source code. Rules are compiled `regexp.MustCompile` patterns organized by category (injection, xss, crypto, secrets, etc.) and by language (Go, Python, Java, etc.). Multi-line preprocessing joins backslash continuations and normalizes CRLF before matching.

**What it catches:** Known vulnerability patterns with high confidence — SQL injection via string concatenation, hardcoded secrets, dangerous function calls, disabled security features, insecure crypto configurations, framework misconfigurations.

**What it misses:** Context-dependent vulnerabilities where a pattern appears in comments or non-executable code, and dataflow vulnerabilities where tainted data passes through multiple variables before reaching a sink.

### Layer 2: AST Analysis (Tree-sitter, 15 languages)

Parses every file into a full abstract syntax tree using tree-sitter grammars compiled into the binary via CGo. The AST serves two purposes:

1. **False positive suppression** — Regex findings that land inside comment AST nodes are filtered out. Findings in string literals are intentionally kept (SQL/XSS patterns in strings are often real vulnerabilities).
2. **Structural inspection** — 13 language-specific analyzers (Go, Python, Java, JS/TS, PHP, Ruby, C/C++, Kotlin, Swift, Rust, C#, Lua, Groovy, Perl) examine AST structure for patterns that regex cannot express.

**What it catches:** Security-relevant code structure that regex patterns can't distinguish — e.g., a function call pattern that only matters when it's actually executed code vs. appearing in a comment.

**Shared trees:** The tree-sitter tree parsed here is cached and reused by Layer 3's `tsflow` engine (Python, JS, Java, and 12 other languages), eliminating a redundant re-parse. For Go files, a separate `go/ast` parse is performed once and shared between Layer 3's `astflow` engine and Layer 4's call graph builder.

### Layer 3: Taint Analysis (1,069 catalog entries, 3 engines)

Source-to-sink dataflow tracking. Identifies where user-controlled input (sources) flows through the program into dangerous operations (sinks), accounting for sanitization along the way. Three specialized engines handle different languages:

| Engine | Languages | Shared tree | How it works |
|--------|-----------|-------------|-------------|
| **astflow** | Go | `go/ast` (shared with L4) | Uses `go/ast` for precise tracking through goroutines, channels, select statements, and Go-specific idioms |
| **tsflow** | Python, JS/TS, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy | tree-sitter (shared from L2) | Generic tree-sitter walker with per-language config tables for each of 15 languages |
| **regex fallback** | Others | none | Pattern-based approximation for languages without tree-sitter support |

Each language has a **taint catalog** defining sources (user input entry points), sinks (dangerous functions), and sanitizers (functions that neutralize taint). The scanner routes automatically: Go code goes to `astflow`, languages supported by `tsflow` go there, everything else falls back to regex.

Unknown function calls propagate taint with 0.8x confidence decay — if data passes through a function not in the catalog, it's still tracked but at reduced confidence.

**What it catches:** Vulnerabilities where user input flows through variable assignments, function parameters, and return values before reaching a dangerous operation — even when no single line of code looks vulnerable on its own.

**What it passes forward:** The precise `TaintFlow` objects (source, sink, intermediate steps, confidence) are cached and passed directly to Layer 4, so interprocedural analysis uses exact dataflow paths rather than re-deriving them from regex.

### Layer 4: Call Graph (Interprocedural Analysis)

Persistent cross-function and cross-file taint tracking that survives across file writes within a Claude Code session. When Layer 3 finds that a function receives tainted input, the call graph records this. On subsequent file writes, if another function calls the tainted function, the taint propagates across the call boundary.

**Precise taint signatures:** Layer 4 receives the exact `TaintFlow` objects from Layer 3 to build function taint signatures. When flows overlap a function's line range, the signature uses precise source parameters, sink calls, and sanitizer presence from the actual dataflow analysis. When flows aren't available (e.g., regex fallback languages), it falls back to regex-based signature derivation.

**Cross-file analysis:** When a caller lives in a different file than the one being edited, Layer 4 loads that file from disk (with a 2MB size limit and caching) to analyze the call site. This means taint propagation works across file boundaries, not just within the currently-edited file.

**What it catches:** Vulnerabilities split across multiple functions or files — e.g., a handler function that reads user input and passes it to a utility function that eventually writes to a database. Neither function looks vulnerable alone, but the call chain creates a taint flow.

**What it tracks:** Function signatures, parameter taint state, return value taint state, and call edges between functions. The graph persists for the duration of the Claude Code session.

## What It Detects

**676 rules across 43 categories:**

| Category | Examples |
|----------|---------|
| Injection | SQL injection, command injection, template injection, NoSQL, LDAP, XPath, header injection |
| XSS | innerHTML, DOM XSS, reflected XSS, server-side rendering XSS, dangerouslySetInnerHTML, v-html |
| Path Traversal | Path traversal, file inclusion, zip slip, null byte injection |
| Crypto | Weak hashing (MD5/SHA1), ECB mode, static IVs, disabled TLS, weak PRNG, timing attacks |
| Secrets | Hardcoded passwords, API keys, private keys, JWT secrets, connection strings, .env files |
| SSRF | User-controlled URLs, internal IP access, DNS rebinding, redirect following |
| Auth | Missing auth checks, CORS wildcards, session fixation, timing attacks, privilege escalation |
| Generic | Unsafe deserialization, open redirects, TOCTOU, insecure temp files, disabled security features, hardcoded IPs |
| Logging | Log injection, CRLF injection, sensitive data in logs |
| Validation | Missing input validation, type coercion, ReDoS, integer overflow, missing null checks |
| Memory | Banned C functions, format strings, buffer overflow, use-after-free, integer overflow |
| XXE | Java, JavaScript, Python, C# XML external entity injection |
| Deserialization | Python pickle, Java ObjectInputStream, C# BinaryFormatter, Ruby Marshal, PHP unserialize |
| CORS | Wildcard + credentials, reflected origin |
| SSTI | Server-side template injection across frameworks |
| JWT | Algorithm confusion, weak signing, missing verification |
| Session | Fixation, predictable IDs, insecure storage |
| Upload | Unrestricted file upload, missing type validation |
| Race Condition | TOCTOU, concurrent state mutation |
| Kotlin | Android SQLi, Intent injection, WebView, SharedPrefs, Ktor CORS |
| Swift | ATS bypass, Keychain, UIWebView, SQLite injection, WKWebView |
| Rust | Unsafe blocks, command injection, transmute, TLS bypass |
| C# | EF SQLi, BinaryFormatter, Blazor JSInterop, LDAP injection |
| Perl | Command/SQL/code injection, CGI XSS, regex DoS, LDAP |
| Lua | os.execute, loadstring, OpenResty SQLi/XSS, debug lib |
| Groovy | .execute(), GroovyShell, Jenkins pipeline, GString injection |
| Frameworks | Spring, Express, Django, Flask, Rails, Laravel, React, Tauri - framework-specific misconfigs |

**16 languages:** Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy

## Installation

### Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash
```

### Install with Project Setup

```bash
# Download install script and configure hooks for a specific project
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash -s -- --setup /path/to/your/project

# Or install globally for all Claude Code sessions
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash -s -- --global
```

### Build from Source

```bash
# Requires Go 1.21+ with CGo and a C compiler (gcc or clang)
git clone https://github.com/turenlabs/batou.git
cd batou
make build && make install
```

## Configuration

Batou hooks are configured in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/batou-hook.sh",
            "timeout": 30,
            "statusMessage": "Batou: Scanning for vulnerabilities..."
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/batou-hook.sh",
            "timeout": 30,
            "statusMessage": "Batou: Deep security scan..."
          }
        ]
      }
    ]
  }
}
```

## False Positive Suppression

If Batou flags code you know is safe, you can suppress findings with inline `batou:ignore` directives. Use the comment syntax for your language (`//`, `#`, `--`, etc.).

### Single-line suppression

Place the directive on the line above the flagged code:

```go
// batou:ignore BATOU-INJ-001 -- query uses parameterized input
db.Query("SELECT * FROM users WHERE id = " + id)
```

```python
# batou:ignore secrets -- test fixture, not a real credential
password = "test-password-for-ci"
```

```javascript
// batou:ignore all -- this entire line is a known false positive
eval(trustedExpression);
```

### Block suppression

Suppress all findings within a range of lines:

```go
// batou:ignore-start injection
rows := db.Query(dynamicSQL)
process(rows)
// batou:ignore-end
```

### Supported targets

| Target | Example | What it suppresses |
|--------|---------|--------------------|
| Rule ID | `BATOU-INJ-001` | That specific rule only |
| Category | `injection` | All rules in the category |
| `all` | `all` | Every Batou rule |

Multiple targets can be listed on one directive: `batou:ignore BATOU-INJ-001 secrets -- reason`.

An optional reason after `--` is recommended for auditability.

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-cover

# Quick manual test
echo '{"hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"app.py","content":"import pickle\npickle.loads(user_data)"}}' | ./bin/batou
```

### Test Suite

- **2,000+ tests** across 60+ packages
- **430+ test fixtures** across 16 languages (vulnerable + safe code samples)
- Race-condition free (verified with `-race`)

## Project Stats

```
Go source files:    271
Go test files:      82
Total Go lines:     ~132,000
Binary size:        ~4 MB
External deps:      1 (tree-sitter, compiled into binary)
Regex rules:        676
AST analyzers:      15 languages
Rule categories:    43
Languages:          16
Taint entries:      1,069
Taint engines:      3 (astflow, tsflow, regex)
File extensions:    50+
Test fixtures:      430+
Test cases:         2,000+
```

## How It Improves AI Code

Batou is designed specifically for AI-generated code patterns. Research shows AI code assistants produce vulnerable code at high rates for certain CWEs:

- **CWE-117** (Log Injection): 88% AI failure rate
- **CWE-79/80** (XSS): 86% AI failure rate
- **CWE-20** (Input Validation): #1 most common AI vulnerability
- **CWE-89** (SQL Injection): Persistent across all AI models

Batou prioritizes rules based on these failure rates, catching the vulnerabilities AI is most likely to introduce.

## License

MIT
