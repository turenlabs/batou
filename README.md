# GTSS - Generation Time Security Scanning

[![Architecture](https://img.shields.io/badge/architecture-excalidraw-6965db)](https://excalidraw.com/#json=Y_aI4C8JAMHOkHY9T5ojj,94pBf-Q-VasP2l606DwPvQ)

A security scanner that catches vulnerabilities in real-time as AI writes code. Built as a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks), GTSS analyzes every file write for security issues across 16 programming languages using a four-layer analysis pipeline.

## How It Works

GTSS hooks into Claude Code's `Write`, `Edit`, and `NotebookEdit` operations:

- **PreToolUse**: Scans code before it's written. Blocks critical vulnerabilities (exit code 2) and provides fix guidance.
- **PostToolUse**: Performs deep analysis after writes, giving Claude detailed hints to improve code security.

```
Claude writes code → GTSS intercepts → 4-layer scan → Block critical vulns / Hint fixes to Claude
```

## Four-Layer Analysis Pipeline

Each layer builds on the previous one. Every file write passes through all four layers in sequence, and findings from earlier layers inform later ones.

### Layer 1: Regex Pattern Matching (862 rules, 44 categories)

Fast first pass that matches known vulnerability signatures against source code. Rules are compiled `regexp.MustCompile` patterns organized by category (injection, xss, crypto, secrets, etc.) and by language (Go, Python, Java, etc.). Multi-line preprocessing joins backslash continuations and normalizes CRLF before matching.

**What it catches:** Known vulnerability patterns with high confidence - SQL injection via string concatenation, hardcoded secrets, dangerous function calls, disabled security features, insecure crypto configurations, framework misconfigurations.

**What it misses:** Context-dependent vulnerabilities where a pattern appears in comments or non-executable code, and dataflow vulnerabilities where tainted data passes through multiple variables before reaching a sink.

### Layer 2: AST Analysis (Tree-sitter, 15 languages)

Parses every file into a full abstract syntax tree using tree-sitter grammars compiled into the binary via CGo. The AST serves two purposes:

1. **False positive suppression** - Regex findings that land inside comment AST nodes are filtered out. Findings in string literals are intentionally kept (SQL/XSS patterns in strings are often real vulnerabilities).
2. **Structural inspection** - 13 language-specific analyzers (Go, Python, Java, JS/TS, PHP, Ruby, C/C++, Kotlin, Swift, Rust, C#, Lua, Groovy, Perl) examine AST structure for patterns that regex cannot express.

**What it catches:** Security-relevant code structure that regex patterns can't distinguish - e.g., a function call pattern that only matters when it's actually executed code vs. appearing in a comment.

**What it enables:** The parsed AST trees are passed to Layer 3 and Layer 4 for dataflow analysis, avoiding re-parsing.

### Layer 3: Taint Analysis (1,631 catalog entries, 3 engines)

Source-to-sink dataflow tracking. Identifies where user-controlled input (sources) flows through the program into dangerous operations (sinks), accounting for sanitization along the way. Three specialized engines handle different languages:

| Engine | Languages | How it works |
|--------|-----------|-------------|
| **astflow** | Go | Uses `go/ast` for precise tracking through goroutines, channels, select statements, and Go-specific idioms |
| **tsflow** | Python, JS/TS, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy | Generic tree-sitter walker with per-language config tables for each of 15 languages |
| **regex fallback** | Others | Pattern-based approximation for languages without tree-sitter support |

Each language has a **taint catalog** defining sources (user input entry points), sinks (dangerous functions), and sanitizers (functions that neutralize taint). The scanner routes automatically: Go code goes to `astflow`, languages supported by `tsflow` go there, everything else falls back to regex.

Unknown function calls propagate taint with 0.8x confidence decay - if data passes through a function not in the catalog, it's still tracked but at reduced confidence.

**What it catches:** Vulnerabilities where user input flows through variable assignments, function parameters, and return values before reaching a dangerous operation - even when no single line of code looks vulnerable on its own.

### Layer 4: Call Graph (Interprocedural Analysis)

Persistent cross-function taint tracking that survives across file writes within a Claude Code session. When Layer 3 finds that a function receives tainted input, the call graph records this. On subsequent file writes, if another function calls the tainted function, the taint propagates across the call boundary.

**What it catches:** Vulnerabilities split across multiple functions or files - e.g., a handler function that reads user input and passes it to a utility function that eventually writes to a database. Neither function looks vulnerable alone, but the call chain creates a taint flow.

**What it tracks:** Function signatures, parameter taint state, return value taint state, and call edges between functions. The graph persists for the duration of the Claude Code session.

## What It Detects

**862 rules across 44 categories:**

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

- **2,000+ tests** across 60+ packages
- **430+ test fixtures** across 16 languages (vulnerable + safe code samples)
- Dedicated benchmarks for WebGoat, OWASP Juice Shop, DVWA, and RailsGoat vulnerability patterns
- Race-condition free (verified with `-race`)

## Project Stats

```
Go source files:    271
Go test files:      82
Total Go lines:     ~132,000
Binary size:        ~4 MB
External deps:      1 (tree-sitter, compiled into binary)
Regex rules:        862
AST analyzers:      15 languages
Rule categories:    44
Languages:          16
Taint entries:      1,631
Taint engines:      3 (astflow, tsflow, regex)
File extensions:    50+
Test fixtures:      430+
Test cases:         2,000+
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
