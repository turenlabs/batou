# Batou - Code guard for your AI agents

## Project Overview

Batou is a security scanner that runs as a Claude Code hook, analyzing code for vulnerabilities at write time. It intercepts `Write`, `Edit`, and `NotebookEdit` tool calls via PreToolUse (can block) and PostToolUse (provides hints) hooks.

## Architecture

```
cmd/batou/main.go          Entry point - reads hook JSON from stdin, runs scanner, outputs hints
internal/scanner/           Core scan orchestrator (concurrent rule execution + preprocessing)
internal/rules/             43 rule categories (676 regex-based rules)
internal/ast/               Tree-sitter AST parsing (parser, query, filter, context)
internal/analyzer/          Language detection + 15 AST security analyzers
internal/taint/             Taint analysis engine (source -> sink tracking with sanitizers)
internal/taint/astflow/     Go-specific AST taint walker (uses go/ast, tracks channels/goroutines)
internal/taint/tsflow/      Tree-sitter taint walker for 15 languages (Python, JS/TS, Java, Perl, etc.)
internal/taint/languages/   Language-specific taint catalogs (16 languages, 56+ files)
internal/hints/             Hint generation for Claude feedback (language-specific fix examples)
internal/graph/             Persistent call graph + interprocedural analysis
internal/hook/              Hook I/O (JSON stdin/stdout, exit codes)
internal/reporter/          Result formatting (block messages with CWE/OWASP refs)
internal/ledger/            Session audit logging
internal/testutil/          Test framework helpers
bench/eval/                 Vulnerability app benchmarks (WebGoat, Juice Shop, DVWA, RailsGoat)
```

## Key Concepts

- **Four-layer analysis** (layers share parsed trees and taint flows — no redundant re-parsing):
  - Layer 1: Regex rules (676 pattern-matching rules across 43 categories)
  - Layer 2: AST analysis (tree-sitter structural analysis for 15 languages). Tree-sitter tree is cached and shared with Layer 3's tsflow engine.
  - Layer 3: Taint analysis (source-to-sink dataflow with 1,069 entries across three engines). TaintFlow objects are cached and passed to Layer 4 for precise interprocedural signatures.
  - Layer 4: Call graph (persistent interprocedural taint tracking across function boundaries, cross-file caller loading from disk)
- **Shared parse cache** (each file parsed once per parser type):
  - tree-sitter tree: parsed in Layer 2 → reused by tsflow (Layer 3) via `AnalyzeWithTree()`
  - go/ast parse: parsed once → shared between astflow (Layer 3) via `AnalyzeGoWithAST()` and call graph builder (Layer 4) via `UpdateFileWithAST()`. Cached in `ScanContext.GoASTFile`.
  - Layer 3 `TaintFlow` objects → passed to Layer 4's `ComputeTaintSig()` for precise signature derivation (falls back to regex when flows are nil)
- **Three taint engines** (scanner routes automatically by language):
  - `astflow`: Go-specific, uses `go/ast` for precise tracking through channels, select, goroutines, and Go idioms. Accepts pre-parsed `GoParseResult` via `AnalyzeGoWithAST()`.
  - `tsflow`: Generic tree-sitter walker for 15 languages (Python, JS, TS, Java, PHP, Ruby, C, C++, C#, Kotlin, Rust, Swift, Lua, Groovy, Perl) with per-language config tables. Accepts pre-parsed tree via `AnalyzeWithTree()`.
  - `taint.Analyze`: Regex-based fallback for languages without tree-sitter support
- **Preprocessing**: CRLF normalization, multi-line continuation joining (backslash + implicit), unicode identifier support
- **AST false-positive filter**: Suppresses regex findings inside comment AST nodes (not strings — SQL/XSS patterns in strings are intentional)
- **Hook I/O**: JSON on stdin, exit code 0 (allow), 2 (block). JSON stdout with `additionalContext` for Claude
- **One dependency**: `github.com/smacker/go-tree-sitter` (compiled into binary via CGo). Core is pure Go stdlib.
- **Taint catalogs**: Each language has sources (user input), sinks (dangerous functions), and sanitizers
- **AI feedback loop**: Hints include language-specific fix examples, CWE/OWASP references, and architectural advice

## Rule Categories

injection, xss, traversal, crypto, secrets, ssrf, auth, generic, logging, validation, memory, xxe, nosql, deser, prototype, massassign, cors, graphql, misconfig, redirect, kotlin, swift, rust, csharp, perl, lua, groovy, golang, java, jsts, python, php, ruby, framework (spring, express, django, flask, rails, laravel, react, tauri)

## Languages Supported

Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy

**AST analysis via tree-sitter**: Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C/C++, Kotlin, Swift, Rust, C#, Lua, Groovy, Perl

## Building & Testing

```bash
make build          # Build binary to bin/batou (requires CGO_ENABLED=1)
make test           # Run all tests with race detector
go test ./... -v    # Verbose test output
go build ./...      # Compile check
```

Note: Tree-sitter requires CGo. The Makefile sets `CGO_ENABLED=1` automatically.

## Test Structure

- `internal/rules/*/` - Each rule category has a `*_test.go` file
- `internal/analyzer/*/` - Each AST analyzer has a `*_test.go` file (goast, pyast, javaast, etc.)
- `internal/taint/` - engine_test.go, scope_test.go, tracker_test.go
- `internal/taint/astflow/` - Go-specific AST taint flow tests (channels, select, goroutines)
- `internal/taint/tsflow/` - Tree-sitter taint walker tests (15 languages)
- `internal/graph/` - interprocedural_test.go (cross-function analysis)
- `internal/scanner/` - scanner_test.go (integration), preprocess_test.go (multi-line joining)
- `internal/hook/` - hook_test.go (I/O layer tests)
- `internal/hints/hints_test.go` - Hint generation tests (language-specific fix examples)
- `bench/eval/vulnapps_test.go` - WebGoat/Juice Shop/DVWA/RailsGoat benchmark
- `testdata/fixtures/{lang}/vulnerable/` - Vulnerable code samples (should trigger rules)
- `testdata/fixtures/{lang}/safe/` - Safe code samples (should NOT trigger rules)
- `internal/testutil/` - Test helpers (ScanContent, MustFindRule, LoadFixture, etc.)

## Generating New Rules

Use `tools/generate_rules.py` to generate regex rules and taint catalog entries from YAML definitions instead of writing Go code manually. Requires `pyyaml` (`pip install pyyaml`).

```bash
python tools/generate_rules.py rules.yaml              # generate + verify (runs gofmt + go build)
python tools/generate_rules.py --dry-run rules.yaml    # preview generated Go code without writing
python tools/generate_rules.py --no-verify rules.yaml  # generate without running go build
```

See `tools/example_rules.yaml` for the full YAML schema covering regex rules and taint entries (sources, sinks, sanitizers). The generator:

- Auto-assigns rule IDs by scanning existing `BATOU-{PREFIX}-###` in the codebase
- Validates regex patterns for Go RE2 compatibility (rejects lookahead/lookbehind)
- Generates `_gen.go` files for existing categories, `{category}.go` for new ones
- Inserts taint entries into existing catalog files or generates all 4 files for new languages
- Updates `cmd/batou/main.go` blank imports for new rule categories
- Runs `gofmt` and `go build ./...` to verify generated code compiles

## Checking Rule Coverage & Duplicates

Use `tools/check_rules.py` to audit rules for duplicates, ID gaps, coverage stats, and taint catalog health. No dependencies beyond Python stdlib.

```bash
python tools/check_rules.py              # full report (duplicates, gaps, coverage, taint)
python tools/check_rules.py --duplicates # only show duplicate rule IDs (exits non-zero if found)
python tools/check_rules.py --gaps       # only show missing ID numbers per prefix
python tools/check_rules.py --coverage   # rule counts per prefix + CWE coverage
python tools/check_rules.py --taint      # taint catalog entry counts per language
```

Run after adding new rules to verify no accidental ID collisions or numbering gaps.

## Common Patterns

- Rules implement `rules.Rule` interface with `ID()`, `Scan()`, `Languages()`, `Severity()`
- AST analyzers: create package in `internal/analyzer/{lang}ast/`, use `ast.TreeFromContext(sctx)` to get the parsed tree
- Taint catalogs register via `init()` functions
- New rules: create file in `internal/rules/{category}/`, add blank import in `cmd/batou/main.go` (or use `tools/generate_rules.py`)
- New language: create 4 files in `internal/taint/languages/` (catalog, sources, sinks, sanitizers), then add a `langConfig` in `internal/taint/tsflow/langconfig.go` (or use `tools/generate_rules.py` for the catalog files)
- `ScanContext.Tree` is `interface{}` — rules call `ast.TreeFromContext(sctx)` to get typed `*ast.Tree` (tree-sitter)
- `ScanContext.GoASTFile` is `interface{}` — caches `*astflow.GoParseResult` (`*token.FileSet` + `*ast.File`) for sharing between astflow and call graph builder

## Important Notes

- The scanner has a 10-second timeout with panic recovery per rule
- Stdin is limited to 50MB to prevent OOM
- `BlockWrite` runs AFTER `OutputPreTool` so Claude always gets hints
- Taint analysis uses 0.8x confidence decay for unknown function propagation (applies to all three engines)
- Scanner routes taint analysis: Go → `astflow.AnalyzeGoWithAST` (reuses cached `go/ast`), `tsflow.Supports(lang)` → `tsflow.AnalyzeWithTree` (reuses cached tree-sitter tree, 15 languages including Perl), else → `taint.Analyze` (regex fallback)
- Layer 3 taint flows are cached in `sctx.TaintFlows` and passed to Layer 4's `PropagateInterproc()` for precise interprocedural signatures
- Layer 4 loads cross-file callers from disk (2MB limit, cached) when they aren't in the current file contents
- Test file paths matter - use non-test paths like `/app/handler.go` to avoid `isTestFile()` exclusion
- CRLF normalization happens early in scan pipeline (before regex rules)
- Multi-line preprocessing (`JoinContinuationLines`) is applied for Python, Shell, C/C++ before regex scanning; original content is preserved for AST parsing
- AST filter runs after rule execution to suppress false positives in comments
