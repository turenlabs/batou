# GTSS - Generation Time Security Scanning

## Project Overview

GTSS is a security scanner that runs as a Claude Code hook, analyzing code for vulnerabilities at write time. It intercepts `Write`, `Edit`, and `NotebookEdit` tool calls via PreToolUse (can block) and PostToolUse (provides hints) hooks.

## Architecture

```
cmd/gtss/main.go          Entry point - reads hook JSON from stdin, runs scanner, outputs hints
internal/scanner/          Core scan orchestrator (concurrent rule execution + taint analysis)
internal/rules/            30 rule categories (234 regex-based rules)
internal/taint/            Taint analysis engine (source -> sink tracking with sanitizers)
internal/taint/languages/  Language-specific taint catalogs (16 languages, 56+ files)
internal/hints/            Hint generation for Claude feedback
internal/graph/            Persistent call graph + interprocedural analysis
internal/hook/             Hook I/O (JSON stdin/stdout, exit codes)
internal/analyzer/         Language detection
internal/reporter/         Result formatting
internal/ledger/           Session audit logging
internal/testutil/         Test framework helpers
```

## Key Concepts

- **Three-layer analysis**: Layer 1 (regex rules), Layer 2 (taint source->sink tracking), Layer 3 (interprocedural call graph)
- **Hook I/O**: JSON on stdin, exit code 0 (allow), 2 (block). JSON stdout with `additionalContext` for Claude
- **Zero dependencies**: Pure Go stdlib only (`go.mod` has no `require` entries)
- **Taint catalogs**: Each language has sources (user input), sinks (dangerous functions), and sanitizers

## Rule Categories

injection, xss, traversal, crypto, secrets, ssrf, auth, generic, logging, validation, memory, xxe, nosql, deser, prototype, massassign, cors, graphql, misconfig, redirect, kotlin, swift, rust, csharp, perl, lua, groovy, framework (spring, express, django, flask, rails, laravel, react, tauri)

## Languages Supported

Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy

## Building & Testing

```bash
make build          # Build binary to bin/gtss
make test           # Run all tests with race detector
go test ./... -v    # Verbose test output
go build ./...      # Compile check
```

## Test Structure

- `internal/rules/*/` - Each rule category has a `*_test.go` file
- `internal/taint/` - engine_test.go, scope_test.go, tracker_test.go
- `internal/scanner/scanner_test.go` - Integration tests
- `internal/hints/hints_test.go` - Hint generation tests
- `testdata/fixtures/{lang}/vulnerable/` - Vulnerable code samples (should trigger rules)
- `testdata/fixtures/{lang}/safe/` - Safe code samples (should NOT trigger rules)
- `internal/testutil/` - Test helpers (ScanContent, MustFindRule, LoadFixture, etc.)

## Common Patterns

- Rules implement `rules.Rule` interface with `ID()`, `Scan()`, `Languages()`, `Severity()`
- Taint catalogs register via `init()` functions
- New rules: create file in `internal/rules/{category}/`, add blank import in `cmd/gtss/main.go`
- New language: create 4 files in `internal/taint/languages/` (catalog, sources, sinks, sanitizers)

## Important Notes

- The scanner has a 10-second timeout with panic recovery per rule
- Stdin is limited to 50MB to prevent OOM
- `BlockWrite` runs AFTER `OutputPreTool` so Claude always gets hints
- Taint analysis uses 0.8x confidence decay for unknown function propagation
- Test file paths matter - use non-test paths like `/app/handler.go` to avoid `isTestFile()` exclusion
