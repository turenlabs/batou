# Four-Layer Architecture Review

## Overview

The GTSS scan pipeline runs four layers in sequence:

```
Phase 1: Regex rules + TaintRule (concurrent goroutines)
Phase 2: Call graph update + interprocedural analysis
     ↓   AST false-positive filter
     ↓   Deduplication (taint > AST > interprocedural > regex)
Phase 3: Taint analysis (again) → Hints generation
```

When multiple layers flag the same `(line, CWE)`, the dedup system keeps the
highest-fidelity finding and merges tags from suppressed duplicates. This is a
sound layered-defense design. The problems are in how the layers connect.

---

## Layer 1: Regex Rules

**348 rules, 34 categories, concurrent execution with per-rule panic recovery.**

### What works well

- Per-rule goroutines with panic recovery (`scanner.go:148-165`) — one broken
  rule cannot crash the scan
- Language-specific pattern variants (e.g., 11 SQL injection patterns covering
  `fmt.Sprintf`, f-strings, template literals, PHP interpolation, Ruby `.where`)
- One finding per line prevents noise floods
- 10-second global timeout with graceful degradation

### What doesn't

1. **Line-by-line matching misses multi-line vulnerabilities.** A SQL query split
   across lines with `+` concatenation is invisible to per-line regex. The
   `JoinContinuationLines` preprocessor only handles backslash continuations
   and Python implicit joins — not general multi-line string concatenation in
   Go, Java, JS, or Ruby.

2. **The preprocessor only runs for Python, Shell, and C/C++.** Languages like
   Go, Java, JS, and Ruby get no continuation joining (`scanner.go:112`).

3. **`isCommentLine()` in rules is redundant.** The AST-based `FilterFindings`
   (`scanner.go:222`) does the same job with higher fidelity using actual parse
   trees. The regex pre-filter in individual rules adds complexity without value.

---

## Layer 2: AST Analysis

**Tree-sitter parsing for 15+ languages, 13 language-specific analyzers,
comment-based false-positive filtering.**

### What works well

- The false-positive filter suppresses findings in comments but preserves
  findings in string literals — SQL patterns in strings are real vulnerabilities
- 2-second parse timeout prevents tree-sitter from hanging on adversarial input
- The `TreeFromContext(sctx)` pattern using `interface{}` avoids circular imports

### What doesn't

1. **Go uses `go/ast` while all others use tree-sitter.** The Go analyzer gets
   precise type information, import alias resolution, and receiver type matching.
   Other analyzers get surface-level structural checks via tree-sitter nodes.
   This creates an implicit two-tier system that isn't acknowledged.

2. **The AST filter runs on interprocedural findings from other files.**
   At `scanner.go:222`, `FilterFindings(tree, findings)` runs on ALL findings
   including those from `PropagateInterproc()`. The tree was parsed from the
   current file only. If an interprocedural finding references a line that
   happens to coincide with a comment in the current file's AST, it gets
   incorrectly suppressed. The filter should skip findings whose `FilePath`
   doesn't match the parsed tree's source file.

3. **`isASTRuleID` uses `strings.Contains(ruleID, "AST")` (`dedup.go:126`).**
   This is fragile. A tag-based approach (like taint uses with `"taint-analysis"`)
   would be more robust and consistent.

---

## Layer 3: Taint Analysis

**Three engines (astflow for Go, tsflow for 15 languages, regex fallback),
confidence decay model, 1,631 catalog entries across 16 languages.**

### What works well

- Automatic engine routing by language (`scanner.go:267-273`) selects the best
  available engine
- Confidence decay (0.8× for unknown functions, per-operation multipliers like
  0.95 for string concat, 0.0 for hashing) is well-modeled
- Per-category sanitization (`Sanitized map[SinkCategory]bool`) correctly handles
  partial sanitization (e.g., `html.EscapeString` neutralizes XSS but not SQLi)

### What doesn't

1. **TaintRule always calls the regex fallback engine.** This is the most
   significant architectural issue. At `rule.go:34`, `TaintRule.Scan()` calls
   `taint.Analyze()` — the regex-based fallback in `engine.go`. It does NOT
   route to `astflow.AnalyzeGo()` or `tsflow.Analyze()`. Only Phase 3
   (`scanner.go:267-273`) does proper routing. This means:
   - **Taint findings used for blocking decisions come from the weakest engine**
   - **AST-based taint analysis only feeds hints, not findings or blocking**
   - The three-engine architecture is effectively a presentation-layer feature

2. **Taint analysis runs twice.** Phase 1 runs it via TaintRule (producing
   `Finding` objects). Phase 3 runs it again (producing `TaintFlow` objects for
   hints). Within a 10-second budget this doubles the taint cost. A single
   execution producing both types would be cleaner.

3. **TaintRule.Languages() only covers 9 of 16 supported languages.** Kotlin,
   Swift, Rust, C#, Perl, Lua, and Groovy have tsflow configs and taint
   catalogs but are excluded from `rule.go:23-28`. These languages get taint
   hints in Phase 3 but never get taint findings for dedup or blocking. A
   critical taint flow in Kotlin code appears in hints but never triggers
   `BlockWrite`.

4. **Scope detection in the regex engine is regex-based even when AST is
   available.** The fallback engine uses `DetectScopes()` which regex-matches
   function signatures and counts braces. For languages with tree-sitter
   support, the parse tree could provide exact function boundaries.

---

## Layer 4: Call Graph

**Persistent `.gtss/callgraph.json`, content-hash change detection, two-path
interprocedural analysis (tainted args → callee sinks, tainted returns →
caller sinks), 5-level transitive caller traversal.**

### What works well

- Atomic writes with lockfile prevent corruption
- Session-aware storage discards stale graphs from previous sessions
- Content-hash-based change detection avoids re-analyzing unchanged functions
- Best-effort design — graph failures never block scans (`scanner.go:194`)

### What doesn't

1. **No cross-file call resolution.** `builder.go` only resolves calls within
   the same file. If `main.go` calls `handleUser()` defined in `handlers.go`,
   the edge is never recorded. This limits interprocedural analysis to
   co-located functions, which drastically reduces value in real codebases.

2. **The generic builder uses regex for call detection.** For non-Go languages,
   `buildGenericNodes()` uses regex patterns (`pyCallRe`, `jsMethodRe`) to find
   calls. These miss computed function names, method chaining, and destructured
   imports. The tree-sitter tree is already parsed and available.

3. **Taint signature computation is a parallel model.** `ComputeTaintSig()`
   matches patterns like `*http.Request` and `db.Query` as strings rather than
   using the taint catalogs or AST. This creates a second, simpler model that
   can diverge from the actual taint analysis.

4. **Dedup ranks interprocedural below both AST and taint.**
   `tierInterprocedural = 20` vs `tierAST = 30` vs `tierTaint = 40`
   (`dedup.go:12-15`). A cross-function taint flow through a helper function is
   arguably higher fidelity than a single-function taint finding. When both fire
   on the same line, the interprocedural finding's cross-function context gets
   suppressed.

5. **Only the first changed function is tracked for hints.** At
   `scanner.go:205-206`, one `changedFuncName` is captured. Edits modifying
   multiple functions only show call graph context for the first one.

---

## Cross-Cutting Issues

1. **No feedback between layers.** Each layer runs independently. If the AST
   filter suppresses a regex finding, taint analysis doesn't know. If taint
   finds a sanitized path, the regex rule still fires and gets suppressed only
   at dedup.

2. **Hint dedup with findings is coarse.** At `hints.go:63-66`, taint flow hints
   suppress ALL findings on the same sink line, regardless of whether they're
   about the same vulnerability type.

3. **Test file detection happens after full analysis.** At `scanner.go:232-238`,
   test files have findings downgraded. But the full pipeline (regex, AST,
   taint, call graph, hints) has already run. An early check could save time.

---

## Recommended Fixes (by impact)

| Priority | Fix | Why |
|----------|-----|-----|
| 1 | Route TaintRule through astflow/tsflow | Elevates blocking from regex-quality to AST-quality taint |
| 2 | Add 7 missing languages to TaintRule | Kotlin/Swift/Rust/C#/Perl/Lua/Groovy get blocking, not just hints |
| 3 | Unify double taint execution | Single pass producing both Findings and TaintFlows |
| 4 | Skip cross-file findings in AST filter | Prevent incorrect suppression of interprocedural findings |
| 5 | Add cross-file call resolution | Make Layer 4 useful for real multi-file codebases |
| 6 | Use AST for call graph building | Replace regex call detection with tree-sitter queries |
| 7 | Reconsider interprocedural dedup tier | Cross-function analysis arguably deserves higher rank |
