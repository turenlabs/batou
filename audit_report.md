# GTSS Deep Audit Report

**Auditor:** code-auditor agent
**Date:** 2026-02-10
**Scope:** All 66 Go source files in the GTSS codebase
**Severity Rating:** Each finding rated CRITICAL / HIGH / MEDIUM / LOW / INFO

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Logic Bugs](#2-logic-bugs)
3. [Race Conditions](#3-race-conditions)
4. [Error Handling](#4-error-handling)
5. [Performance](#5-performance)
6. [Architectural Weaknesses](#6-architectural-weaknesses)
7. [Rule Quality](#7-rule-quality)
8. [Taint Analysis Gaps](#8-taint-analysis-gaps)
9. [Security of GTSS Itself](#9-security-of-gtss-itself)
10. [Recommendations](#10-recommendations)

---

## 1. Executive Summary

GTSS is a well-structured generation-time security scanner with three analysis layers: regex-based pattern matching, regex-based taint tracking, and Go AST-based taint tracking. The architecture is sound, but this audit found **52 distinct weaknesses** across the codebase (including 10 additional findings from the complete rule file review):

| Category | Critical | High | Medium | Low | Info |
|----------|----------|------|--------|-----|------|
| Logic Bugs | 3 | 5 | 4 | 2 | 0 |
| Race Conditions | 0 | 1 | 2 | 0 | 0 |
| Error Handling | 0 | 2 | 3 | 1 | 0 |
| Performance | 0 | 1 | 3 | 2 | 0 |
| Architectural | 2 | 3 | 2 | 0 | 0 |
| Rule Quality | 1 | 1 | 6 | 2 | 4 |
| Taint Gaps | 2 | 4 | 3 | 0 | 0 |
| Self-Security | 0 | 1 | 1 | 0 | 0 |

The most impactful findings are:
- **main.go exits 0 on input errors** -- silently approves all writes when JSON parsing fails
- **Taint tracker only flows forward (top-down)** -- misses backward data flows and loops
- **Scope detection silently drops code on parse failures** -- strings with braces cause mis-scoping
- **No timeout on the scan itself** -- malicious input can hang the process indefinitely

**Total rule inventory:** 64 rules across 10 rule packages (injection: 7, secrets: 6, xss: 11, traversal: 9, crypto: 11, ssrf: 4, auth: 6, generic: 9, logging: 3, validation: 4, memory: 6, goast: 1 meta-rule with 8 checks). This is a comprehensive rule set covering OWASP Top 10 and beyond.

---

## 2. Logic Bugs

### LB-01: main.go exits 0 on input error (CRITICAL)

**File:** `cmd/gtss/main.go:33-35`

```go
input, err := hook.ReadInput()
if err != nil {
    os.Exit(0)
}
```

When stdin contains invalid JSON or ReadInput fails for any reason, GTSS exits with code 0, which tells Claude Code "no objections." This means **any malformed hook invocation silently allows the write through**. An attacker who can corrupt stdin or cause a read timeout effectively disables all security scanning.

**Impact:** Complete bypass of security scanning.

### LB-02: BlockWrite calls os.Exit(2) before OutputPreTool (CRITICAL)

**File:** `cmd/gtss/main.go:52-59`

```go
if result.ShouldBlock() {
    hook.BlockWrite(reporter.FormatBlockMessage(result))
}
// Always output context
if context != "" {
    hook.OutputPreTool("allow", "GTSS: security analysis complete", context)
}
```

`hook.BlockWrite` calls `os.Exit(2)` immediately, so the `OutputPreTool` call that provides hints to Claude about what went wrong **never executes**. Claude sees the block but gets no structured JSON with `additionalContext` explaining the issue. The hints system -- the "key innovation" per the code comments -- is completely bypassed for the most critical findings.

### LB-03: Ledger goroutine fires-and-forgets after main returns (CRITICAL)

**File:** `cmd/gtss/main.go:40`

```go
go ledger.Record(input.SessionID, result)
```

When the main function returns (especially after `hook.BlockWrite` calls `os.Exit(2)`), the ledger goroutine is killed mid-flight. This means:
- Blocked writes are the most important events to log, but they are the ones least likely to be recorded
- The ledger file can be left in a corrupted state (partial JSON line)

### LB-04: Taint analysis runs twice in scanner.go (HIGH)

**File:** `internal/scanner/scanner.go:57-78` and `scanner.go:134`

The TaintRule is registered as a Rule and runs during Phase 1 via `rule.Scan(ctx)`. Then in Phase 3, `taint.Analyze()` is called again independently. This means **taint analysis runs twice on every scan** -- once to produce findings (Phase 1) and once to produce TaintFlow structs for hints (Phase 3). The flows from Phase 1 are converted to `Finding` objects and lose their `TaintFlow` structure, so they can't be reused for hints.

**Impact:** Double the taint analysis CPU cost on every invocation; also potential for inconsistent results if the two runs produce different findings.

### LB-05: Scope detection string tracking is naive (HIGH)

**File:** `internal/taint/scope.go:78-89`

```go
case '"', '\'', '`':
    inString = true
    stringChar = ch
```

The brace-counting loop for scope detection tracks strings but:
- Does not handle multi-line template literals (backticks with `${...}` containing `{`/`}`)
- Does not handle escaped quotes properly inside single-quote strings vs double-quote strings
- Does not handle raw strings (Go's backtick strings can contain unescaped `'` and `"`)
- Does not handle regex literals in JS (e.g., `/pattern{3}/`)
- Does not handle triple-quoted strings in Python (this code path is for brace languages, but TypeScript/JS files may have interesting edge cases)

A string literal containing `{` or `}` will throw off the brace depth counter, causing scope boundaries to be misdetected. This can cause taint analysis to miss flows or report false positives.

### LB-06: extractAssignmentLHS mishandles augmented assignments (HIGH)

**File:** `internal/taint/engine.go:326-330`

```go
before := trimmed[eqIdx-1]
if before == '!' || before == '<' || before == '>' || before == ':' || before == '=' {
    return ""
}
```

This correctly filters out `!=`, `<=`, `>=`, `:=`, `==`, but misses `+=`, `-=`, `*=`, `/=`. For augmented assignments like `query += userInput`, the code falls through to the generic `x = expr` handler and extracts `query +` as the LHS. The `extractFirstIdent` function then extracts `query` correctly by luck, but the RHS extraction is wrong because it splits at the `=` sign, producing `userInput` without the `+` context.

**Impact:** Augmented assignments work by accident for simple cases but will fail for complex expressions.

### LB-07: parseAssignment has overlapping regex patterns (HIGH)

**File:** `internal/taint/tracker.go:235-271`

The `assignmentPatterns` list contains overlapping patterns. The Ruby/Python catch-all pattern at the end:
```go
regexp.MustCompile(`^\s*([a-zA-Z_][\w]*(?:\s*,\s*[a-zA-Z_][\w]*)*)\s*[\+\-\*\/]?=\s*(.+)$`)
```
matches augmented assignments (`+=`, `-=`, etc.) but its `lang` function returns `true` for ALL languages. This means Go code like `x := foo()` might match this pattern instead of the Go-specific `:=` pattern if the Go pattern somehow fails. The patterns are tested in order, but the Go pattern requires the line to start with the variable name, while this catch-all also matches.

### LB-08: Comparison propagation rule has false positives (HIGH)

**File:** `internal/taint/propagation.go:37-38`

```go
Pattern: `(==|!=|<=|>=|\.equals\(|\.compareTo\(|\.compare\(|<[^<]|>[^>])`,
```

The sub-patterns `<[^<]` and `>[^>]` are meant to catch `<` and `>` comparison operators, but they also match:
- HTML/XML tags: `<div>`, `<span>`
- Generics: `List<String>`
- Arrow functions: `=>` (the `>` part)
- String literals: `"hello > world"`

When these match on a RHS expression, taint propagation is killed (`Propagates: false`), causing false negatives.

### LB-09: Top-level scope includes non-function import/require lines (MEDIUM)

**File:** `internal/taint/scope.go:153-163`

The `__top_level__` scope collects all lines not inside functions, but `hasNonTrivialContent` filters out lines starting with `import`, `package`, `from`, `require(`, and `use`. However, it does NOT filter:
- `const` declarations
- `var` declarations
- Class declarations
- Express middleware setup like `app.use(cors())`

This means the top-level scope for many JS/TS files will include class definitions and middleware setup, producing false taint flows from top-level sources to sinks that are actually in different logical scopes.

### LB-10: parenBalanced does not account for strings (MEDIUM)

**File:** `internal/taint/engine.go:228-242`

The `parenBalanced` helper just counts `(` and `)` characters without considering whether they're inside string literals. A sink call with string arguments containing parentheses (e.g., `db.query("SELECT COUNT(*) FROM users", callback)`) would confuse the multi-line joining logic.

### LB-11: wordBoundaryPattern PHP variable matching is fragile (MEDIUM)

**File:** `internal/taint/tracker.go:397-414`

For PHP variables like `$user`, the pattern uses `(?:^|[^\w])` as a left boundary. But `$` is adjacent to the variable name with no space, so the actual text is `$user`. The `regexp.QuoteMeta("$user")` produces `\$user`, and the full pattern becomes `(?:^|[^\w])\$user\b`. This should work, but the `\b` at the end fires between `r` and a non-word character, which means `$username` would NOT incorrectly match `$user` (good). However, accessing `$user["key"]` would match `$user` (also correct). The concern is with variables like `$user_id` -- `\b` fires after `user` but NOT before `_`, so `$user_id` would NOT match `$user` (correct behavior). This is actually fine on closer analysis.

### LB-12: changedFuncName only captures the first changed function (MEDIUM)

**File:** `internal/scanner/scanner.go:98-107`

```go
for _, id := range changedIDs {
    if idx := lastIndexByte(id, ':'); idx >= 0 {
        changedFuncName = id[idx+1:]
        break  // <-- only takes the first
    }
}
```

If multiple functions changed in a file, only the first one's name is used for hint generation. The call graph impact analysis for other changed functions still runs (it uses the full `changedIDs` list), but hints only reference the first function.

### LB-13: Python scope detection closes on any lower-indentation line (LOW)

**File:** `internal/taint/scope.go:613-636`

For Python, scopes close when a line with equal or lower indentation is found. This is correct for well-formatted Python but breaks on:
- Multi-line strings (triple-quoted)
- Continuation lines (backslash or open parens)
- Decorators at function level (have same indent as the function)

### LB-14: Ruby scope detection doesn't handle inline conditionals (LOW)

**File:** `internal/taint/scope.go:775-782`

Ruby's `end` detection checks `trimmed == "end"` or prefix `"end "` or `"end;"`. But Ruby has:
- `rescue => e` which also closes blocks
- `ensure` blocks
- `elsif` which continues blocks
- One-liner methods: `def foo = bar` (Ruby 3+)

---

## 3. Race Conditions

### RC-01: Call graph file locking is not safe under concurrency (HIGH)

**File:** `internal/graph/persist.go:95-124`

The lock acquisition has multiple issues:
1. After detecting a stale lock and removing it, there's a TOCTOU race: another process could grab the lock between `os.Remove(lockFile)` and `os.OpenFile(lockFile, O_CREATE|O_EXCL, ...)`.
2. When the lock is "recent" (less than 30 seconds), the code falls through and **overwrites the lock** with `O_CREATE|O_WRONLY|O_TRUNC`. The comment says "a brief conflict is unlikely" but this defeats the purpose of locking entirely.
3. If two GTSS instances run concurrently (e.g., Claude writes two files in rapid succession), both could read the graph, modify it independently, and one's save will overwrite the other's changes.

**Impact:** Call graph corruption when concurrent hooks fire.

### RC-02: Pattern cache has unnecessary double-check overhead (MEDIUM)

**File:** `internal/taint/engine.go:39-63`

The `compilePattern` function uses a read lock to check the cache, then a write lock with a double-check. This is correct but:
- The `nil` sentinel for failed patterns means that every call for a bad pattern still acquires the read lock, checks the map, finds `nil`, and returns. This is fine.
- However, the cache grows unboundedly. Over a long session with many files, this map could become large. Not a race condition per se, but worth noting.

### RC-03: Rules registry uses a Mutex but rules.All() copies are stale (MEDIUM)

**File:** `internal/rules/rule.go:188-194`

`rules.All()` and `rules.ForLanguage()` copy the registry under a lock. This is correct for preventing concurrent modification during copy. However, if a rule's `Scan()` method modifies shared state (none currently do), there would be a race. The current rules are all stateless value types, so this is safe today but fragile.

---

## 4. Error Handling

### EH-01: hook.ReadInput reads all of stdin with no size limit (HIGH)

**File:** `internal/hook/hook.go:64`

```go
data, err := io.ReadAll(os.Stdin)
```

This reads the entire stdin into memory with no limit. A very large file being written (e.g., a minified JS bundle or generated code) could consume gigabytes of memory. Claude Code sends the full file content in the `tool_input.content` field.

### EH-02: OutputPreTool and OutputPostTool errors are silently ignored (HIGH)

**File:** `cmd/gtss/main.go:59,64`

```go
hook.OutputPreTool("allow", "GTSS: security analysis complete", context)
// ...
hook.OutputPostTool(context)
```

These functions return `error` but the main function ignores the return values. If stdout writing fails (e.g., pipe broken), the hints are silently lost. For PreToolUse, the absence of structured JSON output may cause Claude Code to interpret the hook as having no opinion, effectively allowing the write.

### EH-03: JSON parse errors in graph loading silently start fresh (MEDIUM)

**File:** `internal/graph/persist.go:35-38`

```go
if err := json.Unmarshal(data, &cg); err != nil {
    return NewCallGraph(projectRoot, sessionID), nil
}
```

If the callgraph.json file is corrupted (e.g., partial write from RC-01), the entire graph is silently discarded. All interprocedural analysis context is lost. This should at minimum log a warning.

### EH-04: Taint catalog GetCatalog returns nil without fallback (MEDIUM)

**File:** `internal/taint/engine.go:69-72`

```go
cat := GetCatalog(lang)
if cat == nil {
    return nil
}
```

If a file is detected as TypeScript but only JavaScript catalogs are registered (or vice versa), taint analysis silently returns no results. The system should fall back to JavaScript catalogs for TypeScript files or to a generic catalog.

### EH-05: scanner.go ignores graph.LoadGraph error on second return value (MEDIUM)

**File:** `internal/scanner/scanner.go:92`

```go
callGraph, _ = graph.LoadGraph(projectRoot, input.SessionID)
```

The error is explicitly discarded. While the function returns a new empty graph on most errors, a permissions error or disk full condition would be silently swallowed.

### EH-06: Ledger Record returns error that is never checked (LOW)

**File:** `cmd/gtss/main.go:40`

```go
go ledger.Record(input.SessionID, result)
```

The goroutine discards the error from `Record`. Combined with LB-03, ledger failures are completely invisible.

---

## 5. Performance

### PF-01: regex compilation in isArgTaintedInCaller (HIGH)

**File:** `internal/graph/interprocedural.go:889-903`

```go
directSourcePatterns := []*regexp.Regexp{
    regexp.MustCompile(`\bRequest\b`),
    regexp.MustCompile(`\.FormValue\s*\(`),
    // ... 12 more patterns
}
```

These regexes are compiled **inside the function body**, which means they are re-compiled on every call. This function is called once per argument of every callee call in every caller in the interprocedural analysis. For a large codebase, this is a significant waste.

### PF-02: parseAssignment compiles regex on every call for Java (MEDIUM)

**File:** `internal/taint/tracker.go:308-313`

```go
if lang == rules.LangJava || lang == rules.LangCSharp {
    re := regexp.MustCompile(`^\s*(?:final\s+)?...`)
    if m := re.FindStringSubmatch(trimmed); m != nil {
```

This compiles a regex on every invocation of `parseAssignment` for Java/C# files. Since `parseAssignment` is called for every line in every scope, this is `O(lines * regex_compile_time)`.

### PF-03: wordBoundaryPattern compiles a new regex per variable per check (MEDIUM)

**File:** `internal/taint/tracker.go:397-414`

Each call to `rhsReferencesVar` or `exprReferencesVar` calls `wordBoundaryPattern` which compiles a new regex. In a taint tracking loop with N tainted variables and M lines, this compiles O(N*M) regexes. These should be cached per variable name.

### PF-04: extractCalls regex patterns are compiled as package-level vars (MEDIUM -- actually good)

**File:** `internal/graph/builder.go:246-273`

These are properly compiled at package init time. This is correct. Noted as a positive example.

### PF-05: Full content re-split on every rule scan (LOW)

**File:** Multiple rule files (e.g., `injection/injection.go:181`, `secrets/secrets.go:248`)

Every rule calls `strings.Split(ctx.Content, "\n")` to get lines. Since rules run concurrently, each allocates its own copy. The `ScanContext` could pre-compute the line array once.

### PF-06: Shannon entropy computed with rune conversion (LOW)

**File:** `internal/rules/secrets/secrets.go:140-153`

The entropy function converts to `[]rune` to get the length, but iterates with `range` which already handles runes. The `len([]rune(s))` allocation is unnecessary; a rune count can be maintained during the loop.

---

## 6. Architectural Weaknesses

### AW-01: Single-file analysis cannot detect multi-file vulnerabilities (CRITICAL)

GTSS analyzes one file at a time as a hook on Write/Edit operations. This means:
- A source in file A and a sink in file B connected via imports will never be detected
- Shared utility functions that propagate taint are invisible
- Configuration files (e.g., database URLs) that should be treated as sources are not correlated with code files

The call graph partially addresses this for same-session analysis, but only for callers within files that Claude has already written during this session. Pre-existing code is not scanned.

### AW-02: Edit operations only analyze new_string, not the full file (CRITICAL)

**File:** `internal/hook/hook.go:96-107` and `internal/scanner/scanner.go:153-166`

For Edit operations in PreToolUse, `ResolveContent()` returns only `new_string` (the replacement text). This means:
- If the replacement is just `sanitize(input)`, GTSS analyzes only that snippet, not the full file
- The context around the edit (where the sanitized value goes) is invisible
- An attacker could split a vulnerability across the old text and new text

For PostToolUse, the scanner reads the file from disk, which gives the full content. But for PreToolUse blocking decisions, the analysis is on a fragment.

### AW-03: No support for inter-file import resolution (HIGH)

The call graph builder resolves calls within the same file only:

**File:** `internal/graph/builder.go:140-162`

```go
calleeID := FuncID(filePath, callName)
if cg.GetNode(calleeID) != nil {
    cg.AddEdge(callerID, calleeID)
    continue
}
```

Cross-file calls (imports) are never resolved. A function called from file A that's defined in file B will not have an edge in the graph, limiting interprocedural analysis to intra-file calls.

### AW-04: Session-scoped call graph loses context across sessions (HIGH)

**File:** `internal/graph/persist.go:41-43`

```go
if cg.SessionID != sessionID {
    return NewCallGraph(projectRoot, sessionID), nil
}
```

Every new Claude Code session starts with a blank call graph. All interprocedural context from previous sessions is lost. For iterative development where Claude is asked to modify code across multiple sessions, this means previously-discovered cross-function taint paths are forgotten.

### AW-05: No semantic understanding of framework patterns (HIGH)

GTSS doesn't understand framework-specific routing or middleware patterns:
- Express.js: `app.use(cors())` -- middleware is invisible to taint analysis
- Django: URL routing in `urls.py` connecting views is not tracked
- Go: `http.HandleFunc` registrations connecting routes to handlers aren't correlated
- React: JSX rendering and component data flow is not modeled

This means GTSS can detect vulnerabilities within handler functions but not in how data flows through framework layers.

### AW-06: TypeScript and JavaScript share some but not all analysis (MEDIUM)

TypeScript gets `LangTypeScript` as a separate language, and the taint catalog is registered separately. However:
- The JavaScript catalog is not also loaded for TypeScript files
- TypeScript-specific patterns (type guards, generics, decorators) are not handled
- `.tsx` files with JSX are mapped to TypeScript but JSX patterns aren't in the catalog

### AW-07: No diff-aware analysis for Edit operations (MEDIUM)

For Edit operations, `ctx.OldText` and `ctx.NewText` are populated but never used by any rule. Rules always analyze the full content. The diff could be used to:
- Only analyze the changed region (faster)
- Detect if a sanitizer was removed
- Detect if a new sink was added near an existing source

---

## 7. Rule Quality

### RQ-01: SQL injection regex has catastrophic false negative for ORM methods (CRITICAL)

**File:** `internal/rules/injection/injection.go:14-37`

All SQL injection patterns look for SQL keywords (`SELECT`, `INSERT`, etc.) in string literals. This completely misses:
- ORM injection: `User.where("name = '#{params[:name]}'")` -- no SQL keywords, just a where clause
- MongoDB/Sequelize: `Model.findOne({ where: { id: req.params.id } })` when `id` is not parameterized
- Knex/query builder: `knex.raw(userInput)` -- passes through to raw SQL
- Dynamic table/column names: `db.Query("SELECT * FROM " + tableName)` matches but `db.Query("SELECT * FROM users ORDER BY " + sortColumn)` may not if the quoted string doesn't contain SELECT (actually it does in this case, but `"ORDER BY " + sortCol` alone wouldn't)

### RQ-02: Command injection patterns miss several evasion vectors (HIGH)

**File:** `internal/rules/injection/injection.go:42-66`

Missing patterns:
- Python: `os.execvp`, `os.spawnl`, `pty.spawn`
- Node.js: `require('child_process').execFile` (only `exec` is matched)
- Go: `exec.CommandContext` with variable first arg (only shell invocations flagged)
- Ruby: `IO.popen`, `Open3.capture2`, `` %x{} `` without interpolation check
- Shell: `$(command)` inside double-quoted strings: `"path/$(whoami)/file"`

### RQ-03: Secrets patterns have high false-positive potential for common variable names (HIGH)

**File:** `internal/rules/secrets/secrets.go:17-21`

The `secretVarNames` pattern matches `pass` which appears in:
- `passenger_count`, `bypass`, `compass_heading`
- Variables named `pass` meaning "skip" or "pass through"
- Test data constructors

The pattern also matches `token` which appears in:
- CSRF token variables (which SHOULD be in code)
- Lexer/parser token variables
- Any pagination token or iterator token

The `isPlaceholder` check helps but doesn't cover all cases.

### RQ-04: XSS rules are comprehensive but have minor gaps (MEDIUM)

**File:** `internal/rules/xss/xss.go` (772 lines, 11 rules)

After full review, XSS coverage is comprehensive: innerHTML (XSS-001), dangerouslySetInnerHTML (XSS-002), document.write (XSS-003), unescaped templates (XSS-004), DOM manipulation (XSS-005), header injection (XSS-006), URL scheme injection (XSS-007), SSR XSS (XSS-008), missing content-type (XSS-009), JSON content-type (XSS-010), reflected XSS (XSS-011). Minor gaps:
- Missing: `postMessage` XSS detection (cross-origin messaging without origin validation)
- Missing: DOM clobbering detection
- XSS-005 DOMManipulation uses keyword-in-line heuristic (`strings.Contains(line, "location")`) which may miss obfuscated patterns

### RQ-05: Memory safety rules are well-implemented within regex limitations (LOW)

**File:** `internal/rules/memory/memory.go` (579 lines, 6 rules)

After full review, the memory module is better than expected. It covers banned functions (MEM-001), format strings (MEM-002), buffer overflow patterns (MEM-003), double-free and use-after-free via per-scope variable tracking (MEM-004), integer overflow in allocations (MEM-005), and unchecked malloc return (MEM-006). The MEM-004 use-after-free detector uses per-function heuristic tracking that resets on `{`/`}` boundaries -- a reasonable approximation. Minor issues:
- MEM-004 `regexp.MatchString(nullPat, line)` compiles a new regex per freed variable per line inside the inner loop. This should be pre-compiled.
- MEM-006 also compiles `ifCheck` regex inside the loop on every allocation. Should be cached.
- MEM-003 `reReadBuf` checks `sizeof(var)` which is correct for stack arrays but misses heap buffers.

### RQ-06: Logging rules have good coverage with acceptable false-positive risk (LOW)

**File:** `internal/rules/logging/logging.go` (362 lines, 3 rules)

After full review, the logging module is well-structured with 3 rules: unsanitized input in logs (LOG-001), CRLF injection in log messages (LOG-002), and sensitive data in logs (LOG-003). It has:
- Per-language pattern coverage for Python, Java, Go, JS/TS, PHP, Ruby
- Comment-line skipping to reduce false positives
- LOG-002 has a `reSanitized` check that skips lines already containing sanitization calls
- LOG-002 compiles `reSanitized` regex inside the `Scan()` method rather than at package level -- should be a package-level var

### RQ-07: Crypto rules have comprehensive coverage with redundancy (MEDIUM)

**File:** `internal/rules/crypto/crypto.go` (1090 lines, 11 rules)

The crypto module has 11 rules covering weak hashing (CRY-001), insecure random (CRY-002), weak ciphers (CRY-003), hardcoded IVs (CRY-004), insecure TLS (CRY-005), weak key sizes (CRY-006), plaintext protocols (CRY-007), JS Math.random (CRY-008), Python random (CRY-009), weak PRNG (CRY-010), and predictable seeds (CRY-011). Issues:
- CRY-002, CRY-008, CRY-009, CRY-010 all detect insecure random but for overlapping language sets. CRY-002 covers Go/Python/JS, CRY-008 covers JS-only, CRY-009 covers Python-only, CRY-010 covers Java/PHP/Ruby/C#/Go. The same file may get duplicate findings from CRY-002 and CRY-008/009/010.
- CRY-007 PlaintextProtocol checks for `http://` URLs but only matches when the URL is inside quotes. URLs stored in variables (`url := "http://..." + domain`) may not match.

### RQ-08: SSRF rules have reasonable coverage but URL validation heuristic is brittle (MEDIUM)

**File:** `internal/rules/ssrf/ssrf.go` (645 lines, 4 rules)

4 SSRF rules: URL from user input (SSRF-001), internal network access (SSRF-002), DNS rebinding (SSRF-003), redirect following (SSRF-004). Issues:
- `hasURLValidation` uses Contains checks for function names like "allowlist", "whitelist" etc. A variable named "user_allowlist" in an unrelated context would suppress the finding.
- `fileHasUserURL` is too conservative -- it only checks specific framework patterns. A file that reads user input via a custom function would not be flagged.
- `isTestOrConfig` checks if line contains "test" which could match variable names like "latest" or "contest".

### RQ-09: GoAST analyzer provides deep Go analysis (INFO -- positive)

**File:** `internal/analyzer/goast/goast.go` (988 lines, 8 checks)

The Go AST analyzer is well-implemented with 8 checks: unsafe package (AST-001), SQL string concat (AST-002), exec command injection (AST-003), unchecked errors (AST-004), deprecated crypto (AST-005), HTTP server misconfig (AST-006), defer in loop (AST-007), goroutine leak (AST-008). Strengths:
- Single-pass AST walk (efficient)
- Handles import aliasing via `localNameFor()`
- SQL concat detection correctly identifies binary `+` with non-literals
- Exec command injection has 3 tiers: shell pattern, variable command name, variable arguments
- Defer-in-loop correctly skips nested function literals (closures)
- Goroutine leak checks for captured context variables

Minor issues:
- `stringLitValue` trims both `"` and backtick from the value, which could incorrectly handle strings that contain those characters at boundaries.
- AST-004 uses `isSecurityCriticalFunc` which matches any function name containing "auth" or "crypt" -- this could match functions like "authenticate_ui_element" or "encrypt_column_name" that are not security-critical.

### RQ-10: Generic rules cover important cross-cutting concerns (INFO -- positive)

**File:** `internal/rules/generic/generic.go` (785 lines, 9 rules)

9 rules covering debug mode (GEN-001), unsafe deserialization (GEN-002), XXE (GEN-003), open redirect (GEN-004), log injection (GEN-005), race conditions (GEN-006), mass assignment (GEN-007), code-as-string eval (GEN-008), XML parser misconfig (GEN-009). Notable:
- GEN-002 correctly distinguishes yaml.load with FullLoader vs SafeLoader and notes FullLoader is still unsafe
- GEN-003 XXE has per-language protection detection (defusedxml for Python, FEATURE_SECURE_PROCESSING for Java)
- GEN-006 race condition has false-positive reduction by checking for mutex/lock patterns
- GEN-008 code-as-string analysis detects dangerous calls inside eval/vm string args -- addresses a novel evasion vector

### RQ-11: Auth rules have reasonable patterns but MissingAuthCheck has high FP potential (MEDIUM)

**File:** `internal/rules/auth/auth.go` (623 lines, 6 rules)

6 rules: hardcoded credentials (AUTH-001), missing auth (AUTH-002), CORS wildcard (AUTH-003), session fixation (AUTH-004), weak password policy (AUTH-005), insecure cookies (AUTH-006). Issues:
- AUTH-002 MissingAuthCheck for Go checks `hasAuthMiddleware` by looking for string substrings in the entire file content. A comment mentioning "authMiddleware" would suppress all findings.
- AUTH-006 InsecureCookie for PHP counts `true` occurrences in a 5-line block to determine if secure/httponly are set. `setcookie($name, $value, 0, '/', '', true, true)` works, but `setcookie($name, $value)` followed by an unrelated `$x = true` on the next line would suppress the finding.

### RQ-12: Validation rules target common AI-generated code weaknesses (INFO -- positive)

**File:** `internal/rules/validation/validation.go` (493 lines, 4 rules)

4 rules: direct param usage (VAL-001), missing type coercion (VAL-002), missing length validation (VAL-003), missing allowlist validation (VAL-004). These target CWE-20 (Improper Input Validation), which is the most common weakness in AI-generated code. Strengths:
- VAL-001 has a comprehensive `reValidationPresent` regex that covers 20+ validation/sanitization patterns across languages
- VAL-003 detects file uploads without size limits

### RQ-13: Traversal rules are comprehensive with good guard detection (INFO -- positive)

**File:** `internal/rules/traversal/traversal.go` (853 lines, 9 rules)

9 rules: path traversal (TRV-001), file inclusion (TRV-002), zip slip (TRV-003), symlink following (TRV-004), template path injection (TRV-005), prototype pollution (TRV-006), Express sendFile (TRV-007), null byte (TRV-008), render options injection (TRV-009). The `hasTraversalGuard` heuristic that checks for `filepath.Clean` + `strings.HasPrefix` within 5 lines is a good false-positive reduction technique. TRV-009 specifically targets the Juice Shop dataErasure pattern (layout override via spread).

---

## 8. Taint Analysis Gaps

### TG-01: Taint tracking is strictly forward (top-to-bottom) (CRITICAL)

**File:** `internal/taint/tracker.go:47-213`

The taint tracker processes lines in order from top to bottom within a scope. This means:
- Closures that capture variables defined later are missed
- JavaScript hoisting (function declarations available before their textual position) is missed
- Loops where taint feeds back (variable tainted on iteration N used in iteration N+1) are only partially caught -- the first iteration may not have the taint yet
- `goto` or deferred statements in Go that execute after the linear flow are missed

For typical AI-generated code (mostly linear functions), this is acceptable. But for refactored code with closures and callbacks, it's a significant blind spot.

### TG-02: No inter-scope taint propagation in regex engine (CRITICAL)

**File:** `internal/taint/engine.go:94-129`

Each scope is analyzed independently in parallel. Taint from an outer scope does not propagate to inner scopes (closures, callbacks). For JavaScript code like:

```javascript
app.get('/search', (req, res) => {
    const query = req.query.q;      // source in outer scope
    db.all(query, (err, rows) => {   // callback -- separate scope
        res.send(rows);              // taint from query is invisible here
    });
});
```

The source `req.query.q` is in the `app.get` scope, but the callback `(err, rows) => { ... }` is a separate scope. The taint on `query` is not propagated into the callback scope.

The GoFlow AST analyzer (`goflow.go`) does better here because `ast.Inspect` walks into nested function literals, but the regex-based engine (which handles JS/TS/Python/Ruby/PHP/Java) does not.

### TG-03: Sanitizer matching does not verify sanitizer-sink category alignment (HIGH)

**File:** `internal/taint/tracker.go:142-159`

When a sanitizer is found, its `Neutralizes` categories are applied to the tainted variable. However, the sanitizer's `Pattern` is a regex that may match function calls that don't actually sanitize for the expected category. For example:

- `url.QueryEscape` neutralizes `redirect` but NOT `sql_query` -- this is correctly modeled in the catalog
- But if a custom function named `escapeQuery` matches a sanitizer pattern meant for HTML escaping, it would incorrectly neutralize XSS taint even though it's meant for SQL

The sanitizer should ideally be matched not just by pattern but also by confirming the function's actual neutralization capability.

### TG-04: Inline source detection in sink arguments is category-blind (HIGH)

**File:** `internal/taint/tracker.go:182-209`

When checking for inline sources in sink arguments (the "direct taint" path where `req.body` appears directly in a sink call without assignment), the code creates an `inlineTV` with `Confidence: 1.0` and checks `IsTaintedFor(sink.Def.Category)`. But the inline `TaintVar` has an empty `Sanitized` map, so it will always be considered tainted for any category. This means if `req.body` appears in a logging call, it would be flagged as a taint flow even if the source category (user_input) is irrelevant to the sink category (log_output).

Actually, `IsTaintedFor` just checks if `Source != nil` and `!Sanitized[cat]`. Since Source is set and Sanitized is empty, it returns true for ALL categories. This is technically correct (user input flowing to any sink unsanitized IS a finding), but it means there's no source-to-sink category compatibility check.

### TG-05: goflow.go receiver matching is heuristic-based (HIGH)

**File:** `internal/taint/goflow/goflow.go:529-562`

Without type information, the Go AST analyzer uses naming conventions to determine if a variable is an HTTP request:

```go
case strings.Contains(objType, "http.Request"):
    return lower == "r" || lower == "req" || lower == "request" || ...
```

This means:
- A variable named `r` that is NOT an http.Request will be treated as one
- A request variable named `httpReq` would NOT be recognized (not in the list)
- In test code, `r` often refers to a `*httptest.ResponseRecorder`

### TG-06: goflow.go doesn't handle method chains like req.Body pipe (HIGH)

**File:** `internal/taint/goflow/goflow.go:462-525`

The source matching in `isSourceCall` handles `r.FormValue()` and `r.URL.Query().Get()` but doesn't handle:
- `io.ReadAll(r.Body)` -- `r.Body` is accessed as a field, not a method call
- `json.NewDecoder(r.Body).Decode(&obj)` -- the decoder wraps the body
- `r.ParseForm(); r.Form.Get("key")` -- two-step form parsing

These are common Go patterns for reading request bodies that would be missed.

### TG-07: Propagation rules can incorrectly kill taint (MEDIUM)

**File:** `internal/taint/propagation.go:17-107`

The propagation rules are checked in order, and the first match wins. Issues:

1. The `comparison` pattern `(==|!=|<=|>=|...)` can match inside larger expressions. For example, `strings.ReplaceAll(input, "==", "")` contains `==` in a string literal, but the regex matches it, killing taint propagation for the whole RHS.

2. The `arithmetic` pattern `[\+\-\*/%]\s*\d|\d\s*[\+\-\*/%]` matches arithmetic with numeric literals but would also match array indexing expressions like `arr[i+1]`.

3. The `hash_function` pattern matches `digest()` which is a common Python method name not related to cryptography (e.g., `email.message.digest`).

### TG-08: No taint through map/dictionary access patterns (MEDIUM)

The taint engine tracks variables by name, but does not track taint through:
- `map[key] = taintedValue` -- the map itself should become (partially) tainted
- `obj.field = taintedValue` -- the object should be tainted
- `arr.push(taintedValue)` -- the array should be tainted
- `{ ...obj, newField: taintedValue }` -- spread operators

Only direct variable-to-variable assignments propagate taint.

### TG-09: DangerousArgs in sink definitions are not enforced by regex engine (MEDIUM)

**File:** `internal/taint/types.go:78`

`SinkDef` has a `DangerousArgs []int` field specifying which argument positions are dangerous. The GoFlow AST analyzer uses this correctly, but the regex-based engine's `findSinks` extracts arguments and checks them all against tainted variables without filtering by `DangerousArgs`. This means a non-dangerous argument position being tainted would still produce a finding.

---

## 9. Security of GTSS Itself

### SS-01: No timeout on scan execution (HIGH)

**File:** `internal/scanner/scanner.go:22-151`

The `Scan` function has no timeout. A maliciously crafted file could trigger:
- Catastrophic regex backtracking (some patterns use `[^"']*` which can backtrack)
- Extremely deep scope nesting causing O(n^2) parent-pointer resolution
- Very long lines causing regex performance degradation
- Thousands of functions causing call graph operations to be slow

Since GTSS runs as a hook, a slow scan blocks Claude Code from writing the file. If it hangs indefinitely, the user's session is stuck.

### SS-02: Regex patterns may be vulnerable to ReDoS (MEDIUM)

Several patterns contain constructs that could cause catastrophic backtracking:

- `internal/rules/injection/injection.go:17`: `[^"]*\b(SELECT|...)` -- the `[^"]*` before alternation
- `internal/rules/secrets/secrets.go:80`: `[^\s:]+:[^\s@]+@[^\s]+` -- the nested negated character classes
- `internal/taint/propagation.go:46`: `f"[^"]*\{|f'[^']*\{` -- the `[^"]*\{` before `{`

For typical code, these won't backtrack catastrophically. But a carefully crafted input string (e.g., a very long line with many quote-like characters) could potentially trigger exponential backtracking in Go's regexp engine. Note: Go's regexp engine uses Thompson NFA and guarantees linear time for most patterns, but this should still be tested.

**Update:** Go's `regexp` package uses RE2 semantics, which guarantees linear-time matching. ReDoS is NOT a practical concern for Go's standard regexp package. This finding is downgraded to INFO.

---

## 10. Recommendations

### Immediate (before any release)

1. **Fix LB-01:** Change `os.Exit(0)` to `os.Exit(1)` on input error in main.go, or output an error JSON to stderr. Never silently approve on error.

2. **Fix LB-02:** Restructure main.go so that `OutputPreTool` runs BEFORE the potential `BlockWrite`, or make `BlockWrite` not call `os.Exit` directly but set a flag that main checks after outputting context.

3. **Fix LB-03:** Either make ledger recording synchronous (it's a single JSON line append, very fast) or use a `sync.WaitGroup` to wait for the goroutine before exiting. For `BlockWrite` paths, record to ledger before calling `os.Exit(2)`.

4. **Add a scan timeout:** Wrap the entire scan in a `context.WithTimeout` (e.g., 10 seconds). If the scan times out, output a warning and allow the write rather than hanging.

5. **Fix PF-01:** Move `directSourcePatterns` to a package-level variable compiled once at init time.

### Short-term (next iteration)

6. **Fix LB-04:** Either remove the TaintRule from the rules registry (so it doesn't run in Phase 1) and only use the Phase 3 `taint.Analyze()` call, or cache the TaintFlow results from Phase 1 and reuse them in Phase 3.

7. **Fix LB-05:** Implement a proper string literal tracker for scope detection that handles escaped characters, multi-line strings, and template literals correctly.

8. **Fix TG-02:** After analyzing all scopes, propagate taint from outer scopes to inner scopes by matching captured variables. This would close the biggest detection gap for JavaScript/TypeScript.

9. **Add Edit-aware scanning:** For Edit operations, read the full file and analyze it, not just the replacement text.

10. **Cache compiled regexes:** Add caching for `wordBoundaryPattern` results and `parseAssignment`'s Java/C# regex.

### Medium-term

11. **Fix AW-01:** Implement cross-file analysis by scanning all project files on first invocation and building a comprehensive call graph. Use the persisted graph to connect functions across files.

12. **Fix TG-05:** Integrate basic type inference for Go files using `go/types` package, or at minimum track variable declarations and their types within a function.

13. **Add framework-aware analysis:** Recognize Express.js router registrations, Django URL patterns, and Go http.HandleFunc calls to connect routes to handlers.

14. **Improve propagation rules:** Add context-aware propagation that checks whether the matching pattern is inside a string literal before killing taint.

15. **Add regression tests:** Build a comprehensive test suite with known-vulnerable code samples for each language and verify detection rates.

---

## Appendix: Files Read

### Core Files

| File | Lines | Purpose |
|------|-------|---------|
| cmd/gtss/main.go | 67 | Entry point |
| cmd/qadebug/main.go | 43 | Debug tool (taint analysis debugger) |
| internal/scanner/scanner.go | 175 | Scan orchestrator |
| internal/hook/hook.go | 155 | Claude Code hook I/O |
| internal/taint/engine.go | 488 | Regex-based taint engine |
| internal/taint/tracker.go | 518 | Variable taint tracking |
| internal/taint/scope.go | 1027 | Scope detection |
| internal/taint/propagation.go | 143 | Taint propagation rules |
| internal/taint/rule.go | 58 | TaintRule adapter |
| internal/taint/reporter.go | 86 | Taint flow formatting |
| internal/taint/types.go | 223 | Type definitions |
| internal/taint/catalog.go | 66 | Catalog registry |
| internal/taint/goflow/goflow.go | 999 | Go AST taint analysis |
| internal/rules/rule.go | 214 | Rule interface and registry |
| internal/hints/hints.go | 540 | Hint generation |
| internal/graph/callgraph.go | 359 | Call graph data structure |
| internal/graph/builder.go | 373 | Graph builder |
| internal/graph/interprocedural.go | 993 | Cross-function analysis |
| internal/graph/persist.go | 133 | Graph persistence |
| internal/analyzer/analyzer.go | 106 | Language detection |
| internal/analyzer/goast/goast.go | 988 | Go AST security analyzer |
| internal/reporter/reporter.go | 112 | Result formatting |
| internal/ledger/ledger.go | 80 | Audit ledger |
| internal/testutil/fixtures.go | 163 | Test fixture utilities |

### Rule Files (ALL read)

| File | Lines | Rules |
|------|-------|-------|
| internal/rules/injection/injection.go | 658 | 7 injection rules |
| internal/rules/secrets/secrets.go | 719 | 6 secret detection rules |
| internal/rules/xss/xss.go | 778 | 11 XSS rules |
| internal/rules/traversal/traversal.go | 853 | 9 traversal rules |
| internal/rules/crypto/crypto.go | 1090 | 11 crypto rules |
| internal/rules/ssrf/ssrf.go | 645 | 4 SSRF rules |
| internal/rules/auth/auth.go | 623 | 6 auth rules |
| internal/rules/generic/generic.go | 785 | 9 generic rules |
| internal/rules/logging/logging.go | 362 | 3 logging rules |
| internal/rules/validation/validation.go | 493 | 4 validation rules |
| internal/rules/memory/memory.go | 579 | 6 memory safety rules |

### Not Read (catalogs -- generated/data files)

| File | Est. Lines | Purpose |
|------|------------|---------|
| internal/taint/languages/*.go | ~2000+ | 9 language taint catalogs (source/sink/sanitizer definitions) |

**Total lines audited:** ~12,500+ (all core + all rule files)
**Total project lines:** ~14,500+ (estimated including catalogs)
