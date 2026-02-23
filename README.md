# Batou - Runtime SAST For Claude Code

<img width="512" height="512" alt="logo_2" src="https://github.com/user-attachments/assets/a3157fb7-68cb-40af-878f-02dc54f62df9" />

A security scanner that catches vulnerabilities in real-time as AI writes code. Built as a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks), Batou analyzes every file write across 17 languages using regex, AST, taint analysis, and interprocedural call graph tracking.

High-confidence findings (confirmed by multiple layers) block the write. Lower-confidence findings produce hints — Claude sees the advice without being interrupted by false positives.

## How It Works

```
Claude writes code → Batou intercepts → 4-layer scan → Confidence scoring → Block / Hint
```

| Layer | What | How |
|-------|------|-----|
| 1. Regex | 684 pattern rules across 45 categories | Fast pattern matching for known vulnerability signatures |
| 2. AST | Tree-sitter parsing for 15 languages | Suppresses false positives in comments, structural analysis |
| 3. Taint | Source-to-sink dataflow (1,123 catalog entries) | Tracks user input through variables to dangerous functions |
| 4. Call Graph | Interprocedural analysis across files | Persistent cross-function taint tracking within a session |

Parsed trees and taint flows are shared across layers — each file is parsed once.

**Blocking threshold:** `Severity >= Critical AND ConfidenceScore >= 0.7`

| Scenario | Score | Result |
|----------|-------|--------|
| Regex-only Critical | 0.3–0.5 | Hint only |
| AST-confirmed | 0.7 | Blocked |
| Taint-confirmed | ~0.85–0.95 | Blocked |
| Multiple layers agree | up to 1.0 | Blocked |

## Installation

```bash
# Quick install
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash

# Install + configure hooks for a project
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash -s -- --setup /path/to/project

# Or install globally
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash -s -- --global

# Build from source (requires Go 1.21+, CGo, gcc/clang)
git clone https://github.com/turenlabs/batou.git && cd batou && make build && make install
```

## What It Detects

**684 rules, 45 categories, 17 languages**

Injection, XSS, path traversal, crypto weaknesses, hardcoded secrets, SSRF, auth issues, XXE, deserialization, CORS, SSTI, JWT flaws, session issues, file upload, race conditions, log injection, input validation, memory safety, and framework-specific misconfigs (Spring, Express, Django, Flask, Rails, Laravel, React, Tauri).

**Languages:** Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy, Zig

## False Positive Suppression

Suppress findings with inline directives when you know the code is safe:

```go
// batou:ignore BATOU-INJ-001 -- query uses parameterized input
db.Query("SELECT * FROM users WHERE id = " + id)
```

```python
# batou:ignore secrets -- test fixture, not a real credential
password = "test-password-for-ci"
```

Block suppression for multiple lines:

```go
// batou:ignore-start injection
rows := db.Query(dynamicSQL)
process(rows)
// batou:ignore-end
```

**Targets:** specific rule ID (`BATOU-INJ-001`), category (`injection`), or `all`. Always include a reason after `--`.

## Testing

```bash
make test          # Run all tests with race detector
make test-cover    # Run with coverage
```

2,000+ tests, 430+ fixtures across 17 languages.

## License

MIT
