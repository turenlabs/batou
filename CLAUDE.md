# Batou - Code guard for your AI agents

## Project Overview

Batou is a security scanner that runs as a Claude Code hook, analyzing code for vulnerabilities at write time. It intercepts `Write`, `Edit`, and `NotebookEdit` tool calls via PreToolUse (can block) and PostToolUse (provides hints) hooks.

## Architecture

```
batou-core/cmd/batou/main.go   Entry point — default: reads a Claude Code hook event from stdin, runs the scanner, outputs hints. Also: `batou scan <dir>` (repo scanner) and `batou findings` (findings-cache report)
batou-core/scanner/         Core scan orchestrator (concurrent rule execution + preprocessing)
batou-core/scanner/dirscan/ `batou scan DIR` subcommand: parallel directory walk over a shared in-memory call graph, JSONL or `--sarif` output, `--fail-on` CI gate, cross-file finalize pass
batou-rules/rules/          45 rule categories (751 regex-based rules)
batou-core/ast/             Tree-sitter AST parsing (parser, query, filter, context)
batou-core/analyzer/        Language detection + 16 AST security analyzer packages
batou-core/taint/           Taint types + regex fallback engine (source -> sink tracking with sanitizers)
batou-core/taint/astflow/   Go-specific AST taint walker (uses go/ast, tracks channels/goroutines)
batou-core/taint/ssaflow/   Go SSA taint engine (golang.org/x/tools/go/ssa): def-use chains, cross-function fixpoint summaries, module-local cross-package builds. ON by default; opt out with BATOU_SSAFLOW=0
batou-core/taint/tsflow/    Tree-sitter taint walker (17 language configs; Zig's config is inert — no grammar)
batou-core/taint/languages/ Language-specific taint catalogs (17 languages, 73 files)
batou-core/hints/           Hint generation for Claude feedback (language-specific fix examples)
batou-core/graph/           Persistent call graph + interprocedural analysis
batou-core/hook/            Hook I/O (JSON stdin/stdout, exit codes)
batou-core/reporter/        Result formatting (block messages with CWE/OWASP refs)
batou-core/suppress/        Inline suppression parsing and matching (batou:ignore directives)
batou-core/findings/        Findings persistence + lifecycle tracking (new/recurring/fixed/suppressed)
batou-core/ledger/          Session audit logging
batou-core/testutil/        Test framework helpers
```

## Key Concepts

- **Four-layer analysis** (layers share parsed trees and taint flows — no redundant re-parsing):
  - Layer 1: Regex rules (751 pattern-matching rules across 45 categories — count via `python3 batou-rules/tools/check_rules.py --coverage`)
  - Layer 2: AST analysis (16 analyzer packages covering 18 languages — `cast` handles C+C++, `jsast` handles JS+TS). All are tree-sitter-based except `zigast` (no Zig grammar exists; it is a lexical/structural analyzer, external-origin-gated, emitting `BATOU-ZIG-AST-###` Layer-2 findings). Tree-sitter tree is cached and shared with Layer 3's tsflow engine.
  - Layer 3: Taint analysis (source-to-sink dataflow drawing on 10,651 catalog entries across 17 languages — count via `check_rules.py --taint`) run by four engines (see below). TaintFlow objects are cached and passed to Layer 4 for precise interprocedural signatures.
  - Layer 4: Call graph (persistent interprocedural taint tracking across function boundaries, cross-file caller loading from disk). Behavior differs by mode — see "Layer 4: hook mode vs scan mode" below.
- **Confidence scoring**: Each finding gets a computed `ConfidenceScore` (0.0–1.0) reflecting which analysis layers confirmed it. Blocking uses `RiskScore = Severity.ImpactWeight × ConfidenceScore >= 0.7`. Impact weights: Critical=1.0, High=0.8, Medium=0.5, Low=0.25. This means regex-only Critical findings (score 0.3–0.5) become hints instead of blocks, while multi-layer-confirmed findings still block.
- **Shared parse cache** (each file parsed once per parser type):
  - tree-sitter tree: parsed in Layer 2 → reused by tsflow (Layer 3) via `AnalyzeWithTree()`
  - go/ast parse: parsed once → shared between astflow (Layer 3) via `AnalyzeGoWithAST()` and call graph builder (Layer 4) via `UpdateFileWithAST()`. Cached in `ScanContext.GoASTFile`.
  - Layer 3 `TaintFlow` objects → passed to Layer 4's `ComputeTaintSig()` for precise signature derivation (falls back to regex when flows are nil)
- **Four taint engines** (routing lives in `batou-core/taintrule/rule.go` and is mirrored in `scanner.go` Phase 3):
  - `astflow`: Go-specific, uses `go/ast` for precise tracking through channels, select, goroutines, and Go idioms. Accepts pre-parsed `GoParseResult` via `AnalyzeGoWithAST()`.
  - `ssaflow`: Go-specific second engine, runs **alongside** astflow (additive, never replaces it). Builds SSA via `golang.org/x/tools/go/ssa` and walks def-use chains: intra-procedural flows (confidence 0.9), cross-function fixpoint summaries (confidence 0.85, converges or caps at 10 iterations), and module-local cross-package summaries via `packages.Load` with a per-module program cache. **ON by default**; opt out with `BATOU_SSAFLOW=0` (or `off`/`false`/`no`). Duplicate astflow/ssaflow flows collapse in dedup by (line, CWE).
  - `tsflow`: Generic tree-sitter walker with 17 per-language config tables (Python, JS, TS, Java, PHP, Ruby, C, C++, C#, Kotlin, Rust, Swift, Lua, Groovy, Perl, Shell, Zig). Accepts pre-parsed tree via `AnalyzeWithTree()`. A file routes here only when `tsflow.Supports(lang) && ast.SupportsLanguage(lang)` — Zig has a config but no tree-sitter grammar, so it never routes here.
  - `taint.Analyze`: Regex-based fallback for languages without a registered tree-sitter grammar (today that means Zig), consuming the same catalog Patterns.
- **Layer 4: hook mode vs scan mode** (they are NOT the same):
  - **Hook mode** (per-write): loads the persistent `.batou/callgraph.json` for the project root via `graph.LoadGraphForHook()` — which **adopts a scan-built project graph** when one exists (marker: non-nil `PackageIndex`, only populated by dirscan finalize) — updates the graph with the written file, and runs `graph.PropagateInterprocTyped()` on the changed functions. When a scan-built graph is present, the hook also runs the **incremental cross-file lane**: `graph.ResolveCrossFileEdgesForFile()` re-resolves edges for the edited file only (bounded: 64 inbound callers, one hop) and `graph.WalkCrossFileTaintFlowsForCaller()` walks the file's outbound one-hop pairs (cap 200) against persisted callee signatures — cross-file Critical sinks can block the write at confidence 0.8. Kill switch: `BATOU_HOOK_CROSSFILE=0`. Graphs over 32MB (`BATOU_HOOK_CROSSFILE_MAX_MB`) are declined with `SkipPersist` set so a hook save can never clobber a large scan-built graph. Graceful no-op when no scan graph exists (plain session graph, same as before). Cross-file callers not in the current file are still loaded from disk on demand (`loadCallerFile`, 2MB cap via `maxCallerFileSize` in `graph/interprocedural.go`).
  - **Scan mode** (`batou scan`, `scanner/dirscan/`): workers share one in-memory `SharedCallGraph` (per-file saves are no-ops; the hook cross-file lane is bypassed in this mode); after the walk, `finalizeCrossFileEdges` runs the full `graph.ResolveCrossFileEdges()` — multi-hop interprocedural taint and cross-language service-boundary routes — emits its extra findings, and persists the graph once. Running `batou scan` once is what arms the hook's cross-file lane for the project.
- **`batou scan` output filtering**: by default only data-flow-confirmed findings are emitted (regex-tier dropped). Secrets/crypto/misconfig findings are legitimately regex-only, so they are invisible unless you pass `--with-regex` (or `--regex-only`). `--sarif` emits one SARIF 2.1.0 document (taint paths as codeFlows, `partialFingerprints`, srcroot-relative artifact URIs) instead of JSONL. `--fail-on none|any|blocking|critical|high` exits 3 when an *emitted* finding matches (output filters apply first).
- **Preprocessing**: CRLF normalization, multi-line continuation joining (backslash + implicit), unicode identifier support. **Important**: suppress.Parse and rules both operate on preprocessed content so line numbers stay aligned.
- **AST false-positive filter**: Suppresses regex findings inside comment AST nodes (not strings — SQL/XSS patterns in strings are intentional)
- **Hook I/O**: JSON on stdin, exit code 0 (allow), 2 (block). JSON stdout with `additionalContext` for Claude
- **Dependencies** (batou-core go.mod): `github.com/smacker/go-tree-sitter` (grammars compiled in via CGo), `golang.org/x/tools` (ssaflow's SSA + packages loading), `github.com/gofrs/flock` (file locking for the persisted call graph and findings store).
- **Taint catalogs**: Each language has sources (user input), sinks (dangerous functions), and sanitizers
- **AI feedback loop**: Hints include language-specific fix examples, CWE/OWASP references, and architectural advice

## Confidence Scoring

Each finding carries a `ConfidenceScore float64` (0.0–1.0) computed by the pipeline. The score determines whether a Critical finding blocks the write or just produces a hint.

### Base Scores by Analysis Tier

| Tier | Base Score | Constant |
|------|-----------|----------|
| Regex (low conf) | 0.3 | `ConfBaseRegexLow` |
| Regex (medium conf) | 0.4 | `ConfBaseRegexMedium` |
| Regex (high conf) | 0.5 | `ConfBaseRegexHigh` |
| AST | 0.7 | `ConfBaseAST` |
| Taint | flow's float64 | preserved from `TaintFlow.Confidence` |
| Interprocedural | 0.8 | `ConfBaseInterproc` |

### Multi-layer Boost

When dedup groups findings by (line, CWE), the winner gets `+0.1` per additional confirming tier (`ConfMultiLayerBoost`). Example: regex (0.5) + taint (0.85) on the same line → taint wins, boosted to 0.95.

### Blocking Threshold

`RiskScore >= 0.7` (`RiskBlockThreshold`) where `RiskScore = Severity.ImpactWeight × ConfidenceScore`

### Pipeline Order

1. Rules run concurrently → findings collected
2. `AssignBaseConfidenceScore()` — sets base score per tier (preserves taint/interproc pre-set scores)
3. `DeduplicateFindings()` — groups by (line, CWE), boosts winner for multi-layer agreement
4. Suppress directives applied
5. Edge-case adjustments: BATOU-TIMEOUT/BATOU-PANIC → 0.2, test files cap at 0.3
6. `SyncConfidenceString()` — syncs float64 back to "high"/"medium"/"low" string label

### Key Files

- `batou-core/scanner/confidence.go` — constants, `AssignBaseConfidenceScore()`, `BoostConfidenceForMultiLayer()`
- `batou-core/scanner/dedup.go` — `countDistinctTiers()`, multi-layer boost during dedup
- `batou-rules/rules/rule.go` — `Finding.ConfidenceScore`, `Finding.ShouldBlock()`, `Finding.SyncConfidenceString()`
- `batou-core/reporter/reporter.go` — `ScanResult.ShouldBlock()` iterates findings using `f.ShouldBlock()`

## False Positive Suppression (`batou:ignore`)

Developers and Claude can suppress findings with inline directives in code comments:

- **Single-line**: `// batou:ignore <target> [-- reason]` — suppresses the next code line
- **Block**: `// batou:ignore-start <target>` ... `// batou:ignore-end` — suppresses all lines in between
- **Targets**: exact rule ID (`BATOU-INJ-001`), category name (`injection`), or `all`
- **Comment styles**: `//`, `#`, `--`, `/*`, `<!--`, `rem` — any prefix works, parsed via regex (no AST dependency)
- **Pipeline position**: Parsed from **preprocessed** content (so line numbers match rule findings), applied after all rules run via `suppress.Apply()`. Suppressed findings are partitioned out but still logged for audit.
- **Category mapping**: `rules.CategoryForRule()` is the single source of truth for rule-to-category mapping — used by both suppress and hints. Adding a new category requires one map entry.
- **Multiple targets**: `batou:ignore BATOU-INJ-001 secrets -- reason here`

## Rule Categories

injection, xss, traversal, crypto, secrets, ssrf, auth, generic, logging, validation, memory, xxe, nosql, deser, prototype, massassign, cors, graphql, misconfig, redirect, kotlin, swift, rust, csharp, perl, lua, groovy, zig, golang, java, jsts, python, php, ruby, framework (spring, express, django, flask, rails, laravel, react, tauri), container, encoding, ssti, jwt, session, upload, race, websocket, oauth, header

## Languages Supported

Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy, Shell/Bash, Zig

**AST analysis via tree-sitter**: Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C/C++, Kotlin, Swift, Rust, C#, Lua, Groovy, Perl (vendored grammar in `batou-core/ast/perl`), Shell (bash grammar)

**Zig**: no tree-sitter grammar exists, so Zig gets the regex fallback taint engine (`taint.Analyze`) plus the dedicated lexical `zigast` analyzer — tsflow's `zigConfig()` is registered but never routes (see `taintrule/rule.go`)

## Building & Testing

```bash
make build          # Build binary to bin/batou (requires CGO_ENABLED=1)
make test           # Run all tests with race detector
go test ./... -v    # Verbose test output
go build ./...      # Compile check
```

Note: Tree-sitter requires CGo. The Makefile sets `CGO_ENABLED=1` automatically.

## OWASP Benchmark

Batou is benchmarked against the official [OWASP Benchmark](https://owasp.org/www-project-benchmark) for Java and Python — the industry-standard SAST evaluation tool with ground-truth CSV files mapping each test case to a CWE and whether it's a true positive or false positive.

### Running the Benchmarks

```bash
make bench-owasp-clone   # Shallow-clone BenchmarkJava + BenchmarkPython to testdata/external/
make bench-owasp         # Run both benchmarks (30m timeout, ~3,970 test cases)
```

Individual benchmarks:
```bash
CGO_ENABLED=1 go test -v -run 'TestOWASPBenchJava' -timeout 30m ./batou-core/scanner/
CGO_ENABLED=1 go test -v -run 'TestOWASPBenchPython' -timeout 30m ./batou-core/scanner/
```

Results are written to `testdata/owasp-bench/{java,python}/results.json`.

The OWASP benchmark is **local-only** — it is not run in CI. Run it with `make bench-owasp` (above), or run the smaller offline CVE ground-truth benches with `make bench-{gocve,pycve,jscve}` (committed fixtures, no network).

Each CVE bench emits its scorecard via `t.Log` — grep the output for `Overall: TPRate=`.

### Regression-checking a PR

Run the offline CVE benches on both refs and diff the Overall line:

```bash
make bench-gocve bench-pycve   # on the baseline ref, then again on the PR ref
# ... diff the two "Overall: TPRate=... FPRate=... Youden=..." lines
```

For the OWASP benchmark (local-only), run `make bench-owasp` on each ref and diff `testdata/owasp-bench/{java,python}/results.json` (or the `Overall: TPRate=` log lines).

### Reference scorecard (2026-06-09)

- **Java**: 2,740 test cases — Overall TPRate **94.5%** / FPRate **16.8%** / Youden **+77.7%**. Perfect (100%/0%) on `crypto`, `securecookie`, `weakrand`; `cmdi` 91.3%/0%. Weakest: `hash` (69.0% TP, deliberately not gamed), `ldapi`/`trustbound`/`sqli`/`xss` FPR 34-38% (regex-tier hints on unknown-origin values — the wrapper-class flows a single-file scan cannot resolve).
- **Python**: 1,230 test cases — Overall TPRate **98.0%** / FPRate **5.9%** / Youden **+92.1%**. Weakest: `xxe`/`deserialization` FPR 33-35%, `cmdi` 100% FPR (0 safe TN cases in corpus).
- Scores are measured at minConf=0 (every emitted finding counts, including hint-tier regex). Per-category regression floors live in `owaspFloorsFor()` in owasp_bench_test.go — bumping them requires justification in the PR.
- **Never add benchmark-specific names to shipped detection logic.** Fix recall/precision with generalizable mechanisms or accept the honest score.

### Test Harness Architecture

- `batou-core/scanner/owasp_bench_test.go` — Main harness (CSV parser, CWE matcher, scorecard, JSON output)
- Expected results CSVs: `expectedresults-1.2.csv` (Java), `expectedresults-0.1.csv` (Python)
- Test case paths: Java at `src/main/java/org/owasp/benchmark/testcode/BenchmarkTestXXXXX.java`, Python at `testcode/BenchmarkTestXXXXX.py`
- Scoring: Per-category TP/FP/TN/FN with TPRate, FPRate, and Youden index
- **Floors gate the test**: `owaspFloorsFor()` carries per-category baselines with a 5-percentage-point safety margin; the Scorecard subtest fails (`REGRESSION: ...`) when a category's TPRate drops below its floor or FPRate rises above its ceiling. The corpus is gitignored (`testdata/external/`) and CI does not clone it, so the benches `t.Skip` in CI — the floors gate any local run of the scanner package test suite once the corpus is present.
- Parallel subtests wrapped in `t.Run("Cases", ...)` barrier, then `t.Run("Scorecard", ...)`

### Key Patterns for OWASP Benchmark Rules

When adding rules to improve OWASP Benchmark scores:

- **Multi-line Python**: The preprocessor joins parenthesized continuations (`RESPONSE += (\n  f'...'\n)` → single line). Regex patterns must handle the `( ` prefix after `+=`. Example: `rePyFStringHTML` uses `\(?\s*f["']` to match both `+= f'...'` and `+= ( f'...' )`.
- **User-input proximity**: For Python, `rePyRequestSource` must include `request.form`, `request.cookies`, `request.values`, `request.query_string` — not just `request.GET/POST/args/params/data`.
- **Variable indirection**: OWASP Benchmark often assigns `param = request.getParameter(...)` then passes `param` through several intermediate variables before reaching the sink. Regex rules need wide variable name patterns or nearby-line lookback for request sources.
- **Safe vs vulnerable distinction**: OWASP Benchmark false-positive cases use the same dangerous function but with hardcoded/sanitized inputs. FP reduction strategies:
  - `pyHasEvalGuard()` — detects validation guards (e.g., `startswith` check) before eval/exec
  - `pyLastAssignmentIsSafe()` — backward scan for last unconditional assignment to check if RHS has taint keywords
- **NO benchmark-specific names in shipped code**: detection logic must never key on identifiers that only exist in a benchmark corpus (`get_safe_value`, `getTheParameter`/`getTheValue`/`SeparateClassRequest`, `doSomething`, "safe" code comments). That is benchmark fitting: it inflates TPR / deflates FPR without generalizing, and it corrupts the one external ground-truth measurement we have. Generalize the underlying mechanism (e.g. same-file constant-return helper analysis) or accept the honest score.
- **Java servlet patterns**: XSS in OWASP Benchmark uses `response.getWriter().println(var)` (BATOU-XSS-029), not HTML string concat. Weak random uses `new Random()` / `Math.random()` (BATOU-CRY-019). Trust boundary uses `session.setAttribute(var, ...)` / `session.putValue(var, ...)` (BATOU-SESS-011).
- **CWE matching**: The harness matches by CWE number (normalizing `"CWE-89"` to `"89"`), not by rule ID. A rule firing with the wrong CWE won't count as a detection even if it found a real issue.

## Test Structure

- `batou-rules/rules/*/` - Each rule category has a `*_test.go` file
- `batou-core/analyzer/*/` - Each AST analyzer has a `*_test.go` file (goast, pyast, javaast, etc.)
- `batou-core/taint/` - engine_test.go, scope_test.go, tracker_test.go
- `batou-core/taint/astflow/` - Go-specific AST taint flow tests (channels, select, goroutines)
- `batou-core/taint/ssaflow/` - SSA engine tests (def-use, cross-function summaries, cross-package, value/context filters)
- `batou-core/taint/tsflow/` - Tree-sitter taint walker tests
- `batou-core/graph/` - interprocedural_test.go (cross-function analysis), resolve tests (cross-file pass)
- `batou-core/scanner/` - scanner_test.go (integration), preprocess_test.go (multi-line joining), owasp_bench_test.go (OWASP Benchmark harness)
- `batou-core/hook/` - hook_test.go (I/O layer tests)
- `batou-core/hints/hints_test.go` - Hint generation tests (language-specific fix examples)
- `batou-rules/testdata/fixtures/{lang}/vulnerable/` and `batou-core/testdata/fixtures/{lang}/vulnerable/` - Vulnerable code samples (should trigger rules); each module carries its own fixtures tree
- `batou-rules/testdata/fixtures/{lang}/safe/` and `batou-core/testdata/fixtures/{lang}/safe/` - Safe code samples (should NOT trigger rules)
- `batou-core/testutil/` - Test helpers (ScanContent, MustFindRule, LoadFixture, etc.)

## Generating New Rules

Use `batou-rules/tools/generate_rules.py` to generate regex rules and taint catalog entries from YAML definitions instead of writing Go code manually. Requires `pyyaml` (`pip install pyyaml`). The repo root is auto-detected from the script location, so it runs from any CWD.

```bash
python3 batou-rules/tools/generate_rules.py rules.yaml              # generate + verify (runs gofmt + go build)
python3 batou-rules/tools/generate_rules.py --dry-run rules.yaml    # preview generated Go code without writing
python3 batou-rules/tools/generate_rules.py --no-verify rules.yaml  # generate without running go build
```

See `batou-rules/tools/example_rules.yaml` for the full YAML schema covering regex rules and taint entries (sources, sinks, sanitizers). The generator:

- Auto-assigns rule IDs by scanning existing `BATOU-{PREFIX}-###` in `batou-rules/rules/`
- Validates regex patterns for Go RE2 compatibility (rejects lookahead/lookbehind)
- Generates `_gen.go` files for existing categories, `{category}.go` for new ones
- Inserts taint entries into existing catalog files in `batou-core/taint/languages/` or generates all 4 files for new languages
- Updates `batou-core/cmd/batou/main.go` blank imports for new rule categories
- Runs `gofmt` and per-module `go build ./...` to verify generated code compiles

## Checking Rule Coverage & Duplicates

Use `batou-rules/tools/check_rules.py` to audit rules for duplicates, ID gaps, coverage stats, and taint catalog health. No dependencies beyond Python stdlib. The repo root is auto-detected from the script location, so it runs from any CWD.

```bash
python3 batou-rules/tools/check_rules.py              # full report (duplicates, gaps, coverage, taint, taint dups)
python3 batou-rules/tools/check_rules.py --duplicates # only show duplicate rule IDs (exits non-zero if found)
python3 batou-rules/tools/check_rules.py --gaps       # only show missing ID numbers per prefix
python3 batou-rules/tools/check_rules.py --coverage   # rule counts per prefix + CWE coverage
python3 batou-rules/tools/check_rules.py --taint      # taint catalog entry counts per language
python3 batou-rules/tools/check_rules.py --taint-dups # duplicate taint entry IDs, same-file vs cross-file
                                                      # (exits non-zero on same-file duplicates)
```

Run after adding new rules or taint entries to verify no accidental ID collisions or numbering gaps. Cross-file shared IDs can be intentional (e.g. javax/jakarta pattern variants); same-file duplicates are copy-paste errors or shadowed near-variants and should be cleaned up.

## Common Patterns

- Rules implement `rules.Rule` interface with `ID()`, `Scan()`, `Languages()`, `Severity()`
- AST analyzers: create package in `batou-core/analyzer/{lang}ast/`, use `ast.TreeFromContext(sctx)` to get the parsed tree
- Taint catalogs register via `init()` functions
- New rules: create file in `batou-rules/rules/{category}/`, add blank import in `batou-core/cmd/batou/main.go` (or use `batou-rules/tools/generate_rules.py`)
- New language: create 4 files in `batou-core/taint/languages/` (catalog, sources, sinks, sanitizers), then add a `langConfig` in `batou-core/taint/tsflow/langconfig.go` (or use `batou-rules/tools/generate_rules.py` for the catalog files)
- `ScanContext.Tree` is `interface{}` — rules call `ast.TreeFromContext(sctx)` to get typed `*ast.Tree` (tree-sitter)
- `ScanContext.GoASTFile` is `interface{}` — caches `*astflow.GoParseResult` (`*token.FileSet` + `*ast.File`) for sharing between astflow and call graph builder

## Important Notes

- The scanner has a 10-second timeout with panic recovery per rule
- Stdin is limited to 50MB to prevent OOM
- `BlockWrite` runs AFTER `OutputPreTool` so Claude always gets hints
- Per-step propagation decay: the regex fallback engine multiplies confidence by 0.8 when taint passes through an unknown function (`unknownFunctionDecay`, `taint/tracker.go`); astflow and tsflow use `propagationConfidence()` (0.85 for unknown calls, 0.9–0.95 for concat/indexing/string ops); ssaflow emits fixed confidences instead (0.9 intra-procedural, 0.85 cross-function)
- Scanner routes taint analysis: Go → `astflow.AnalyzeGoWithAST` (reuses cached `go/ast`) plus `ssaflow.AnalyzeGo` appended unless `BATOU_SSAFLOW=0`; `tsflow.Supports(lang) && ast.SupportsLanguage(lang)` → `tsflow.AnalyzeWithTree` (reuses cached tree-sitter tree); else → `taint.Analyze` (regex fallback — Zig lands here)
- Layer 3 taint flows are cached in `sctx.TaintFlows` and passed to Layer 4's `PropagateInterproc()` for precise interprocedural signatures
- Layer 4 loads cross-file callers from disk (2MB limit, cached) when they aren't in the current file contents
- Test file paths matter - use non-test paths like `/app/handler.go` to avoid `isTestFile()` exclusion
- CRLF normalization happens early in scan pipeline (before regex rules)
- Multi-line preprocessing (`JoinContinuationLines`) is applied for Python, Shell, C/C++ before regex scanning; original content is preserved for AST parsing
- AST filter runs after rule execution to suppress false positives in comments
- Blocking uses `RiskScore >= 0.7` where `RiskScore = Severity.ImpactWeight × ConfidenceScore` — regex-only Critical findings (score 0.3–0.5) produce hints, not blocks
- Taint findings preserve their flow's float64 confidence; `AssignBaseConfidenceScore` only sets a fallback (0.6) when the score is zero
- Scanner tests must import `_ "github.com/turenlabs/batou-core/taintrule"` for taint findings to appear in the pipeline
- `Finding.SyncConfidenceString()` must be called after all score adjustments to keep the string label in sync
