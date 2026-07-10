# Batou

Runtime SAST for AI coding agents. Catches vulnerabilities as code is written, not after.

Built as a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks), Batou intercepts every `Write`, `Edit`, and `NotebookEdit` tool call. High-risk findings block the write. Lower-risk findings produce inline hints that guide the agent to fix the issue.

## Installation

### Homebrew (recommended)

```bash
brew install turenlabs/tap/batou && batou-setup
```

This installs the binary and configures Claude Code hooks automatically.

To update:

```bash
brew upgrade batou
```

### Install script

```bash
# Quick install (downloads binary + configures hooks globally)
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash

# Install + configure hooks for a specific project
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash -s -- --setup /path/to/project

# Or install + configure hooks globally
curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash -s -- --global
```

### Build from source

```bash
# Requires Go 1.21+, CGo, gcc/clang
git clone https://github.com/turenlabs/batou.git && cd batou && make build && make install
```

## CLI usage

```
batou                  (hook mode) read a Claude Code hook event on stdin, scan the touched
                       file, emit security hints. Invoked automatically by the PreToolUse/
                       PostToolUse hooks — not meant to be run by hand.
batou scan <dir>       scan a directory tree; emit one JSON finding per line (JSONL) to stdout
batou findings         report the project-local findings cache (.batou/findings.json)
batou version          print version
batou help             show usage
```

`batou scan` is the ad-hoc repo scanner. It prints one JSON object per finding (JSONL — **not** a
JSON array), so pipe it through `jq` with `-s` if you need to slurp the stream into one value:

```bash
batou scan ./src > findings.jsonl
batou scan --exclude .batou,node_modules /path/to/repo | jq -s 'length'
batou scan --quiet . | jq -c 'select(.taint_path != null) | {file:.file, line:.line, rule:.rule_id}'
```

**Default behavior changed 2026-05-13.** By default `batou scan` emits only AST / taint /
interprocedural-confirmed findings. Regex-tier (Layer-1) findings — **including `BATOU-SECRETS-*`
(hardcoded API keys, AWS keys, etc.), weak-crypto, and misconfig rules** — are HIDDEN by default
because they're the dominant false-positive source on real codebases. The hook path (`batou` with
no args, driven by Claude Code) is unaffected and still surfaces every finding.

Restore the old "emit everything" behavior with `--with-regex`, or run the regex tier on its own
(e.g. for a secrets-only pass) with `--regex-only`:

```bash
batou scan ./src | jq -s 'length'                    # default: dataflow-confirmed only
batou scan --with-regex ./src | jq -s 'length'       # include regex-tier (incl. secrets/crypto)
batou scan --regex-only ./src | jq -s 'length'       # secrets-and-crypto-only pass
batou scan --min-confidence 0.7 ./src                # drop everything below 0.7 confidence
```

`--min-confidence FLOAT` is the orthogonal lever (`0.7` keeps AST/interproc-confirmed plus
high-confidence taint findings); it can be combined with `--with-regex` or `--regex-only`.
`--no-regex` is accepted as a silent compat alias for the new default.

`batou scan` writes/updates `.batou/callgraph.json` (the persistent call graph) relative to the
current directory; pass `--exclude .batou` to keep it out of a re-scan, or `--output FILE` to
write the JSONL to a file instead of stdout. For a one-shot CI scan where the on-disk graph
would just be noise, pass `--no-callgraph` to skip persistence entirely (the graph is still
built in memory for interprocedural analysis during the scan). To write the graph somewhere
other than the cwd, pass `--callgraph PATH`. The two flags are mutually exclusive. Run
`batou scan --help` for the full flag list.

**Shell wrapper gotcha (zsh vs bash).** When wrapping `batou scan` in shell scripts, note that
zsh does NOT word-split unquoted parameter expansions by default while bash does. Code that
builds a flag string and passes it unquoted —

```bash
flags="--quiet --with-regex"
batou scan $flags ./src
```

— works in bash (which splits `$flags` into two arguments) but breaks in zsh, which passes the
whole string as a single argument and Go's flag parser then rejects it with
`flag provided but not defined: -quiet --with-regex`. Use a bash array, or write each
invocation explicitly:

```bash
flags=(--quiet --with-regex)
batou scan "${flags[@]}" ./src
```

### JSONL output fields

Each line is a single JSON object. Stable triage fields a reviewer reaches for:

- `file`, `line`, `rule_id`, `severity`, `title`, `cwe`, `owasp`, `language`
- `confidence` (high/medium/low) and `confidence_score` (0.0–1.0)
- `matched_text` — short excerpt from the matched code
- `taint_path` — structured source→sink steps for taint / interprocedural findings (null otherwise)
- **`source_type`** — taint source category (`user_input`, `network`, `file_read`, `env_var`, …). Present on taint / interprocedural findings only; omitted on regex/AST.
- **`sink_type`** — taint sink category (`sql_query`, `command_exec`, `html_output`, `code_eval`, …). Present on taint / interprocedural findings only.
- **`is_test_file`** — bool, true if the path looks like a test / fixture / mock / spec.
- **`is_docs_file`** — bool, true for `/docs/`, `/doc/`, `/site/`, or `.md`/`.rst`/`.adoc`/`.markdown`/`.asciidoc` extensions.
- **`is_generated_or_vendor`** — bool, true for `vendor/`, `node_modules/`, `__generated__/`, `third_party/`, common lockfiles (`package-lock.json`, `yarn.lock`, `go.sum`, `Cargo.lock`, `composer.lock`, etc.), `*.min.js`/`*.min.css`/`*.bundle.js`/`*.pb.go`/`*_pb.go`/`*_pb2.py`/`*.generated.*` files.

The three `is_*` flags are derived from the file path only — they are cheap and present on every record. `source_type`/`sink_type` come from the taint engine's source/sink classifiers and are omitted (not set to empty string) for non-taint findings.

Common triage filter — high-confidence findings in non-test, non-vendor production code:

```bash
batou scan ./src \
  | jq -c 'select(.confidence_score >= 0.7 and .is_test_file != true and .is_generated_or_vendor != true)'
```

Or pull just the SQL-injection taint flows:

```bash
batou scan ./src | jq -c 'select(.sink_type == "sql_query")'
```

Running bare `batou` from a terminal (no stdin pipe) just prints this usage — the no-arg mode is
only meant to be driven by the Claude Code hook, which pipes a JSON event on stdin.

## Architecture

```
Agent writes code
    |
    v
PreToolUse hook fires
    |
    v
Layer 1: Regex rules (684 patterns, 45 categories)
Layer 2: AST analysis (tree-sitter, 15 languages)
Layer 3: Taint analysis (source -> sink tracking, 3 engines)
Layer 4: Call graph (interprocedural, cross-file, persistent)
    |
    v
Risk scoring: RiskScore = Severity.ImpactWeight * ConfidenceScore
    |
    +-- RiskScore >= 0.7 --> BLOCK (write rejected)
    +-- RiskScore < 0.7  --> HINT (agent sees advice, write allowed)
```

Each file is parsed once. Trees, taint flows, and AST results are cached and shared across layers.

## Languages

Go, Python, JavaScript/TypeScript, Java, PHP, Ruby, C, C++, Kotlin, Swift, Rust, C#, Perl, Lua, Groovy, Zig

**AST analysis:** All of the above via tree-sitter
**Taint analysis:** Go (go/ast), 16 languages (tree-sitter), regex fallback for others

## What It Detects

**684 rules across 45 categories:**

Injection (SQL, command, code), XSS, path traversal, weak crypto, hardcoded secrets, SSRF, auth/authz, XXE, deserialization, CORS, SSTI, JWT, session management, file upload, race conditions, log injection, input validation, memory safety, OAuth, WebSocket, header injection, encoding issues.

**Framework-specific rules:** FastAPI, Django, Flask, Express, Spring, Rails, Laravel, React, Tauri, NestJS.

**ORM taint tracking:** SQLAlchemy, Django ORM, Prisma, Sequelize, TypeORM, Drizzle, Hibernate, MyBatis, JOOQ, GORM, sqlx, ent, bun, ActiveRecord, Eloquent, Doctrine, Entity Framework, Dapper, Diesel, SQLx (Rust), Peewee, Tortoise ORM.

## Risk Scoring

Findings carry a `RiskScore` computed from severity and confidence:

```
RiskScore = Severity.ImpactWeight * ConfidenceScore

Impact weights: Critical=1.0, High=0.8, Medium=0.5, Low=0.25
Confidence: 0.0-1.0, computed by which layers confirmed the finding
```

| Scenario | Confidence | RiskScore | Result |
|----------|-----------|-----------|--------|
| Regex-only Critical | 0.3-0.5 | 0.3-0.5 | Hint |
| AST-confirmed High | 0.7 | 0.56 | Hint |
| Taint-confirmed Critical | 0.85 | 0.85 | Block |
| Multi-layer agreement | 0.95+ | 0.95+ | Block |

The key insight: a Critical regex-only finding (low confidence) becomes a hint, while a High-severity finding confirmed by taint analysis can block. Confidence matters more than severity alone.

## Suppression

Suppress findings with inline directives:

```python
# batou:ignore BATOU-INJ-001 -- parameterized query
db.execute(query, params)
```

Block suppression for multiple lines:

```python
# batou:ignore-start injection -- all queries in this block use ORM
results = User.objects.filter(name=name)
orders = Order.objects.filter(user=user)
# batou:ignore-end
```

**Targets:** exact rule ID (`BATOU-INJ-001`), category (`injection`, `framework`, `jwt`, etc.), or `all`.

**All 45 rule categories are suppressible by name.** Adding a new category requires one entry in the `CategoryForRule()` map in `batou-rules/rules/rule.go`.

### Agent behavior with suppression

Batou detects when an AI agent adds `batou:ignore` directives and emits a `BATOU-SUPPRESS-REVIEW` finding telling the agent to fix the code instead of suppressing. The hint output says:

> "Fix the underlying issue. Only suppress as a last resort."

This prevents agents from carpet-bombing files with suppress comments instead of writing secure code.

## Findings Lifecycle

Findings are tracked across scans in `.batou/findings.json`:

- **new** -- first time this finding appears
- **recurring** -- seen in a previous scan, still present
- **fixed** -- was active, no longer appears in scan
- **suppressed** -- active finding transitioned via `batou:ignore`

The findings store uses file locking (`flock`) to prevent corruption from concurrent hook invocations. Corrupted JSON files self-heal on next open.

Lifecycle events are included in the hook output so external dashboards and metrics sinks can track them.

## Project Structure

```
batou-rules/rules/          45 rule categories (684 regex rules)
batou-core/scanner/          Scan orchestrator, confidence scoring, dedup
batou-core/suppress/         Inline suppression parsing and matching
batou-core/taint/            Taint analysis (3 engines: astflow, tsflow, regex)
batou-core/taint/languages/  Per-language taint catalogs (17 languages)
batou-core/analyzer/         Tree-sitter AST analyzers (15 languages)
batou-core/graph/            Persistent call graph + interprocedural analysis
batou-core/hints/            Hint generation for agent feedback
batou-core/reporter/         Result formatting (block messages, risk labels)
batou-core/findings/         Findings persistence + lifecycle tracking
batou-core/hook/             Hook I/O (JSON stdin/stdout, exit codes)
batou-core/ledger/           Session audit logging
batou-core/cmd/batou/        Entry point (hook mode + `scan`/`findings` subcommands)
```

## Building

Requires Go 1.25+, CGo enabled (for tree-sitter).

```bash
make build      # Build binary to bin/batou
make test       # Run all tests with race detector
```

## Testing

```bash
go test ./batou-core/... ./batou-rules/... -race   # Full test suite
go test ./batou-core/scanner/ -run TestCategorySuppress_Pipeline  # Suppress lifecycle
go test ./batou-core/findings/ -run TestConcurrent  # File locking
go test ./batou-core/suppress/ -v  # All category mappings
```

### OWASP Benchmark

Batou is benchmarked against the [OWASP Benchmark](https://owasp.org/www-project-benchmark) for Java and Python:

```bash
make bench-owasp-clone   # Clone test data
make bench-owasp         # Run benchmarks (~3,970 test cases)
```

Current scores (all emitted findings, minConf=0): Java 94.5% TPR / 16.8% FPR (Youden +77.7%), Python 98.0% TPR / 5.9% FPR (Youden +92.1%).

## License

MIT
