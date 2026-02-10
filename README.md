# GTSS - Generation Time Security Scanning

A security scanner that catches vulnerabilities in real-time as AI writes code. Built as a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks), GTSS analyzes every file write for security issues across 8 programming languages.

## How It Works

GTSS hooks into Claude Code's `Write`, `Edit`, and `NotebookEdit` operations:

- **PreToolUse**: Scans code before it's written. Blocks critical vulnerabilities (exit code 2) and provides fix guidance.
- **PostToolUse**: Performs deep analysis after writes, giving Claude detailed hints to improve code security.

```
Claude writes code → GTSS intercepts → Scan (rules + taint + call graph) → Block or Hint
```

## What It Detects

**76+ rules across 11 categories:**

| Category | Rules | Examples |
|----------|-------|---------|
| Injection | INJ-001 to INJ-007 | SQL injection, command injection, template injection, NoSQL, LDAP, XPath, deserialization |
| XSS | XSS-001 to XSS-011 | innerHTML, DOM XSS, reflected XSS, server-side rendering XSS, missing content type |
| Traversal | TRV-001 to TRV-009 | Path traversal, file inclusion, zip slip, null byte, prototype pollution |
| Crypto | CRY-001 to CRY-011 | Weak hashing, ECB mode, static IVs, disabled TLS verification, weak PRNG |
| Secrets | SEC-001 to SEC-006 | Hardcoded passwords, API keys, private keys, JWT secrets, .env files |
| SSRF | SSRF-001 to SSRF-004 | User-controlled URLs, internal IP access, DNS rebinding, redirect following |
| Auth | AUTH-001 to AUTH-006 | Missing auth checks, CORS wildcards, session fixation, timing attacks |
| Generic | GEN-001 to GEN-009 | Unsafe deserialization, XXE, open redirects, TOCTOU, mass assignment |
| Logging | LOG-001 to LOG-003 | Log injection, CRLF injection, sensitive data in logs |
| Validation | VAL-001 to VAL-004 | Missing input validation, type coercion, length checks, enum validation |
| Memory | MEM-001 to MEM-006 | Banned C functions, format strings, buffer overflow, use-after-free, integer overflow |

**8 languages supported:** Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++

## Three-Layer Analysis

1. **Regex Rules** - Fast pattern matching for known vulnerability signatures
2. **Taint Analysis** - Source-to-sink dataflow tracking with 1,138+ taint entries (sources, sinks, sanitizers per language)
3. **Call Graph** - Persistent interprocedural analysis tracking taint across function boundaries

## Installation

### Prerequisites

- Go 1.21+
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

- **404 tests** across 14 packages
- **164 test fixtures** across 8 languages (vulnerable + safe code samples)
- Fixtures sourced from patterns in OWASP Juice Shop, DVWA, WebGoat, RailsGoat, DVPWA, and more
- Zero false positives on safe code
- Race-condition free (verified with `-race`)

## Project Stats

```
Go source files:    85
Go test files:      16
Total Go lines:     ~26,000
Binary size:        3.5 MB
External deps:      0
Rules:              76+
Taint entries:      1,138+
File extensions:    37
Test fixtures:      164
Test cases:         404
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
