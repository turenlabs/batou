# Batou CLAUDE.md Snippet

Copy the section below into your project's `CLAUDE.md` so Claude understands how Batou works and can respond to its findings correctly.

---

## Copy below this line

```markdown
## Batou Security Scanner

This project uses [Batou](https://github.com/turenlabs/batou), a security scanner that runs as a Claude Code hook. Batou intercepts every `Write`, `Edit`, and `NotebookEdit` tool call and scans the code for vulnerabilities in real-time.

### How it works

Batou runs a 4-layer analysis on every file you write:

1. **Regex rules** — 684 pattern-matching rules across 45 categories (injection, XSS, traversal, crypto, secrets, SSRF, memory safety, etc.)
2. **AST analysis** — Tree-sitter structural analysis that suppresses false positives in comments
3. **Taint analysis** — Source-to-sink dataflow tracking (1,123 catalog entries) that follows user input through variables to dangerous functions
4. **Call graph** — Interprocedural analysis that tracks taint across function boundaries and files

**Blocking threshold:** A finding blocks the write only when `Severity >= Critical AND ConfidenceScore >= 0.7`. Regex-only findings (score 0.3-0.5) produce hints instead of blocks. Multi-layer confirmation (regex + taint, or regex + AST) boosts confidence and can trigger blocks.

**Supported languages:** Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy, Zig

### When Batou blocks a write

If Batou blocks your write, it means a high-confidence critical vulnerability was detected. You should:

1. Read the finding carefully — it includes the CWE ID, OWASP category, and a description of the vulnerability
2. Fix the vulnerability using the suggested approach in the hint
3. Do NOT suppress the finding unless you are certain it is a false positive
4. Common fixes:
   - **Injection (CWE-78, CWE-89):** Use parameterized queries or argument arrays instead of string concatenation
   - **Path traversal (CWE-22):** Validate and canonicalize file paths before use
   - **Hardcoded secrets (CWE-798):** Use environment variables or a secrets manager
   - **XSS (CWE-79):** Escape output or use framework-provided safe rendering
   - **Unsafe memory (CWE-457, CWE-588):** Add bounds checks or use safe alternatives

### When Batou gives a hint (does not block)

Hints are lower-confidence findings. Consider the advice but use your judgment. If the code is intentionally written that way (e.g., a test fixture, a safe wrapper), you can proceed or suppress.

### Suppressing false positives

If you are certain a finding is a false positive, suppress it with an inline directive:

```
// batou:ignore BATOU-INJ-001 -- query uses parameterized input
db.Query("SELECT * FROM users WHERE id = " + id)
```

Block suppression for multiple lines:

```
// batou:ignore-start injection
rows := db.Query(dynamicSQL)
process(rows)
// batou:ignore-end
```

- **Targets:** exact rule ID (`BATOU-INJ-001`), category name (`injection`), or `all`
- **Comment styles:** `//`, `#`, `--`, `/*`, `<!--`, `rem` — any comment prefix works
- **Always include a reason** after `--` explaining why the suppression is safe
- Use suppression sparingly — prefer fixing the vulnerability over suppressing it
```
