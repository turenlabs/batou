# I Built a Security Scanner That Watches AI Write Code in Real Time

AI coding assistants are fast. They generate hundreds of lines in seconds. But speed creates a problem: vulnerabilities ship just as quickly as features. SQL injection, hardcoded secrets, command injection -- these show up constantly in AI-generated code, and most developers don't catch them until a security review weeks later.

So I built Batou (Generation Time Security Scanning), a tool that intercepts every file write from Claude Code, scans it for vulnerabilities, and either blocks the write or teaches the AI to fix its own mistakes -- all before the code hits disk.

## The Problem With Post-Hoc Security

Traditional security scanning happens after the fact. You write code, commit it, push it, and eventually a SAST tool flags issues in CI. By then, the context is gone. The developer has moved on. The fix becomes a chore.

With AI-assisted development, this loop gets worse. AI generates code faster than any human reviewer can audit. Studies show AI code assistants produce vulnerable code at alarming rates for specific weakness categories:

- **88%** failure rate for log injection (CWE-117)
- **86%** failure rate for XSS (CWE-79/80)
- **SQL injection** (CWE-89) persists across all AI models
- **Missing input validation** (CWE-20) is the single most common AI vulnerability

The question isn't whether AI writes vulnerable code. It's whether you catch it before it ships.

## Shifting Left to Generation Time

Batou takes a different approach. Instead of scanning after code is written, it scans *as* code is being written. It hooks into Claude Code's tool system using the [hooks API](https://docs.anthropic.com/en/docs/claude-code/hooks), intercepting `Write`, `Edit`, and `NotebookEdit` operations.

The flow is simple:

```
Claude generates code
    -> Batou intercepts the write
    -> Three-layer security scan runs (~16-20ms)
    -> Critical vulns? Block the write.
    -> Non-critical? Send hints back to Claude.
    -> Claude fixes its own code.
```

The key insight is the **hint system**. When Batou finds a vulnerability, it doesn't just flag it -- it sends detailed fix guidance back to Claude as `additionalContext`. Claude reads the hint and rewrites the code correctly. The AI learns from its own mistakes in real time.

Here's what that looks like in practice. Claude writes a Python handler with a SQL injection vulnerability:

```python
def get_user(request):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()
```

Batou catches it and sends this hint back:

```
Tainted data flows from user_input to sql_query (line 2 -> 3)

Why: User-controlled data enters via Flask query parameters (line 2),
flows through [args -> user_id -> execute], and reaches SQL query
execution with potentially tainted input (line 3) without sanitization.

Fix:
  # Instead of:
  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  # Use parameterized queries:
  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

Claude reads the hint, understands the issue, and rewrites the code with a parameterized query. No human intervention needed.

## Three Layers of Analysis

Batou doesn't rely on a single detection method. It runs three complementary analysis layers on every write:

### Layer 1: Pattern Matching

76+ regex-based rules across 11 categories catch known vulnerability signatures. These rules are tuned for the specific patterns AI tends to produce -- string concatenation in SQL queries, `eval()` with user input, hardcoded secrets with high Shannon entropy, missing CSRF tokens, and more.

The rule categories cover injection, XSS, path traversal, weak cryptography, hardcoded secrets, SSRF, auth issues, input validation, logging vulnerabilities, memory safety (C/C++), and generic security anti-patterns.

### Layer 2: Taint Analysis

Pattern matching alone produces too many false positives. Batou's taint engine tracks data flow from *sources* (user input, request parameters, file reads) through variable assignments and function calls to *sinks* (SQL queries, shell commands, HTML output).

If user input flows to a dangerous function without passing through a sanitizer, that's a real vulnerability. If the same pattern uses a parameterized query or escapes output, the taint is neutralized and no finding is reported.

The taint catalog covers 8 languages with 1,100+ entries mapping framework-specific sources, sinks, and sanitizers. It knows that `request.args.get()` is a Flask source, `cursor.execute()` is a SQL sink, and parameterized queries are sanitizers -- for every major web framework across Go, Python, JavaScript, TypeScript, Java, PHP, Ruby, C, and C++.

### Layer 3: Interprocedural Call Graph

The most sophisticated layer maintains a persistent call graph across the session. When you write a function that takes user input and passes it to another function that executes a query, Batou tracks the taint across function boundaries.

The call graph persists to disk (`.gtss/` directory), so it builds up context over the course of a coding session. The longer you work, the smarter it gets.

## Zero Dependencies, Pure Go

Batou is written in pure Go with zero external dependencies. The entire `go.mod` has no `require` entries. This was a deliberate design choice:

- **No supply chain risk** -- there's nothing to get compromised in a dependency
- **Fast compilation** -- builds in seconds
- **Single binary** -- drop it anywhere, no runtime needed
- **Small footprint** -- ~3.5MB binary

The scanner runs in under 20ms for typical files, with a 10-second hard timeout and panic recovery per rule. It won't slow down your workflow or crash your editor.

## The Hook Architecture

Claude Code hooks provide two interception points:

**PreToolUse** runs before the file is written. Batou scans the content and returns one of two exit codes:
- `0` (allow) -- the write proceeds, with optional hints attached
- `2` (block) -- the write is rejected, and Claude receives the reason plus fix guidance

**PostToolUse** runs after the write completes. Batou performs deeper analysis and sends hints as `additionalContext`. This is where the call graph and interprocedural analysis shine -- they can reference the full session context.

A critical design detail: hints are always output *before* a potential block. This ensures Claude always receives the security feedback, even when the write is blocked. Claude gets the "why" and the "how to fix" simultaneously.

## What It Catches

Some real examples from testing against common AI-generated code patterns:

**SQL Injection** -- String concatenation, f-strings, template literals, `.format()`, `%s` formatting, and ORM raw queries across all supported languages.

**Command Injection** -- `os.system()`, `subprocess.call(shell=True)`, `exec.Command` with shell expansion, `child_process.exec()`, PHP `system()`/`exec()`, Ruby backticks and `system()`.

**XSS** -- `innerHTML`, `dangerouslySetInnerHTML`, `document.write()`, template `|safe` filters, `Html.Raw()`, `html_safe`, unescaped ERB, missing Content-Type headers.

**Hardcoded Secrets** -- API keys with entropy validation (catches real keys, ignores placeholders like `your-api-key-here`), private PEM keys, connection strings with embedded credentials, JWT signing secrets.

**Weak Cryptography** -- Outdated hash algorithms used for security purposes, deprecated symmetric ciphers, insecure block cipher modes, `Math.random()` for security, short asymmetric keys, static initialization vectors.

**Memory Safety (C/C++)** -- `gets()`, `strcpy()`, `sprintf()`, format string vulnerabilities, double-free detection, unchecked `malloc()` returns, integer overflow in allocation size calculations.

## Building It

```bash
git clone https://github.com/turenlabs/batou.git
cd batou
./install.sh --setup /path/to/your/project
```

The install script builds the binary, copies it into your project's `.claude/hooks/` directory, and configures the hook in `.claude/settings.json`. From that point on, every file write in Claude Code passes through Batou.

## What's Next

Batou currently covers the most common vulnerability patterns across 8 languages, but there's room to grow:

- **More languages** -- Rust and C# taint catalogs are partially started
- **Framework-specific rules** -- Deeper coverage for Spring Boot, Django, Express, Laravel, Rails
- **Cross-file analysis** -- Tracking taint flows across module boundaries beyond the current call graph
- **SARIF output** -- For integration with CI/CD pipelines and IDE extensions
- **Configuration** -- Per-project rule enable/disable and severity tuning

The core idea -- scanning at generation time and feeding hints back to the AI -- is applicable beyond Claude Code. Any AI coding tool with a hook or plugin system could use this approach to catch vulnerabilities before they exist.

## Try It

Batou is open source under the MIT license. If you're using Claude Code and want to stop AI-generated vulnerabilities at the source, give it a shot.

The code is at [github.com/turenlabs/batou](https://github.com/turenlabs/batou).

---

*Batou is built by [Turen](https://turen.io). We build tools that make AI-assisted development safer.*
