# GTSS - Generation Time Security Scanning

<img width="1560" height="2062" alt="gtss" src="https://github.com/user-attachments/assets/81d1cfb5-7dd7-4445-87ce-d2ddd8c17d8a" />


A security scanner that catches vulnerabilities in real-time as AI writes code. Built as a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks), GTSS analyzes every file write for security issues across 16 programming languages.

## How It Works

GTSS hooks into Claude Code's `Write`, `Edit`, and `NotebookEdit` operations:

- **PreToolUse**: Scans code before it's written. Blocks critical vulnerabilities (exit code 2) and provides fix guidance.
- **PostToolUse**: Performs deep analysis after writes, giving Claude detailed hints to improve code security.

```
Claude writes code → GTSS intercepts → Scan (regex + AST + taint + call graph) → Block or Hint
```

## What It Detects

**348 rules across 34 categories:**

| Category | Rules | Examples |
|----------|-------|---------|
| Injection | INJ-001 to INJ-009 | SQL injection, command injection, template injection, NoSQL, LDAP, XPath, header injection |
| XSS | XSS-001 to XSS-015 | innerHTML, DOM XSS, reflected XSS, server-side rendering XSS, Java response writer |
| Traversal | TRV-001 to TRV-010 | Path traversal, file inclusion, zip slip, null byte, prototype pollution |
| Crypto | CRY-001 to CRY-018 | Weak hashing, ECB mode, static IVs, disabled TLS, weak PRNG, timing attacks |
| Secrets | SEC-001 to SEC-006 | Hardcoded passwords, API keys, private keys, JWT secrets, .env files |
| SSRF | SSRF-001 to SSRF-004 | User-controlled URLs, internal IP access, DNS rebinding, redirect following |
| Auth | AUTH-001 to AUTH-007 | Missing auth checks, CORS wildcards, session fixation, timing attacks, privilege escalation |
| Generic | GEN-001 to GEN-012 | Unsafe deserialization, XXE, open redirects, TOCTOU, mass assignment, YAML deser, insecure downloads |
| Logging | LOG-001 to LOG-003 | Log injection, CRLF injection, sensitive data in logs |
| Validation | VAL-001 to VAL-005 | Missing input validation, type coercion, length checks, enum validation, file upload hardening |
| Memory | MEM-001 to MEM-006 | Banned C functions, format strings, buffer overflow, use-after-free, integer overflow |
| XXE | XXE-001 to XXE-004 | Java, JavaScript, Python, C# XML external entity injection |
| NoSQL | NOSQL-001 to NOSQL-003 | MongoDB $where, operator injection, raw query injection |
| Deserialization | DESER-001 to DESER-004 | Python/Java/C# deser, Ruby dynamic eval, PHP dangerous patterns |
| Prototype Pollution | PROTO-001 to PROTO-002 | Deep merge/extend pollution, direct __proto__ assignment |
| Mass Assignment | MASS-001 to MASS-004 | JS, Python, Ruby, Java mass assignment |
| CORS | CORS-001 to CORS-002 | Wildcard + credentials, reflected origin |
| GraphQL | GQL-001 to GQL-002 | Introspection enabled, no depth limiting |
| Misconfiguration | MISC-001 to MISC-003 | Debug mode, verbose error disclosure, missing security headers |
| Redirect | REDIR-001 to REDIR-002 | Open redirect, bypassable allowlist |
| Kotlin | KT-001 to KT-008 | Android SQLi, Intent injection, WebView, SharedPrefs, Ktor CORS |
| Swift | SWIFT-001 to SWIFT-010 | ATS bypass, Keychain, UIWebView, SQLite injection, WKWebView |
| Rust | RS-001 to RS-010 | Unsafe blocks, Command injection, transmute, TLS bypass |
| C# | CS-001 to CS-012 | EF SQLi, BinaryFormatter, Blazor JSInterop, LDAP |
| Perl | PL-001 to PL-010 | Command/SQL/code injection, CGI XSS, regex DoS, LDAP |
| Lua | LUA-001 to LUA-008 | os.execute, loadstring, OpenResty SQLi/XSS, debug lib |
| Groovy | GVY-001 to GVY-010 | .execute(), GroovyShell, Jenkins pipeline, GString injection |
| Framework: Spring | FW-SPRING-001 to 010 | CSRF disable, actuator, native query, session fixation |
| Framework: Express/React | FW-EXPRESS/REACT | Helmet, session, stack trace, dynamic require, dangerouslySetInnerHTML |
| Framework: Django/Flask/Rails/Laravel/Tauri | FW-* | Framework-specific misconfigs, SSTI, mass assignment, IPC |

**16 languages supported:** Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy (+ Tauri framework)

## Four-Layer Analysis

1. **Regex Rules** - Fast pattern matching for 348 known vulnerability signatures with multi-line preprocessing
2. **AST Analysis** - Tree-sitter structural analysis for 13 languages, providing comment-aware false positive filtering and deep code structure inspection
3. **Taint Analysis** - Source-to-sink dataflow tracking with 1,184 taint entries (sources, sinks, sanitizers per language)
4. **Call Graph** - Persistent interprocedural analysis tracking taint across function boundaries

## Installation

### Prerequisites

- Go 1.21+ with CGo support (for tree-sitter AST parsing)
- C compiler (gcc or clang)
- Claude Code CLI

### Quick Install

```bash
git clone https://github.com/turenio/gtss.git
cd gtss
./install.sh
```

### Install with Project Setup

```bash
# Install binary + configure hooks for a specific project
./install.sh --setup /path/to/your/project

# Or install globally for all Claude Code sessions
./install.sh --global
```

### Manual Install

```bash
# Build
make build

# Install binary
make install

# Setup hooks in a project
make setup PROJECT=/path/to/your/project
```

## Configuration

GTSS hooks are configured in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/gtss-hook.sh",
            "timeout": 30,
            "statusMessage": "GTSS: Scanning for vulnerabilities..."
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
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/gtss-hook.sh",
            "timeout": 30,
            "statusMessage": "GTSS: Deep security scan..."
          }
        ]
      }
    ]
  }
}
```

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-cover

# Quick manual test
echo '{"hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"app.py","content":"import pickle\npickle.loads(user_data)"}}' | ./bin/gtss
```

### Test Suite

- **2,380 tests** across 59 packages
- **430+ test fixtures** across 16 languages (vulnerable + safe code samples)
- Dedicated benchmarks for WebGoat, OWASP Juice Shop, DVWA, and RailsGoat vulnerability patterns
- Zero false positives on safe code
- Race-condition free (verified with `-race`)

## Project Stats

```
Go source files:    196
Go test files:      78
Total Go lines:     ~86,000
Binary size:        ~4 MB
External deps:      1 (tree-sitter, compiled into binary)
Regex rules:        348
AST analyzers:      13 languages
Rule categories:    34
Languages:          16
Taint entries:      1,184
File extensions:    50+
Test fixtures:      430+
Test cases:         2,380
```

## How It Improves AI Code

GTSS is designed specifically for AI-generated code patterns. Research shows AI code assistants produce vulnerable code at high rates for certain CWEs:

- **CWE-117** (Log Injection): 88% AI failure rate
- **CWE-79/80** (XSS): 86% AI failure rate
- **CWE-20** (Input Validation): #1 most common AI vulnerability
- **CWE-89** (SQL Injection): Persistent across all AI models

GTSS prioritizes rules based on these failure rates, catching the vulnerabilities AI is most likely to introduce.

## License

MIT
