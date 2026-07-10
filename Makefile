.PHONY: build install clean test lint audit-catalog audit-catalog-python bench-hook bench-owasp-java-clone bench-owasp-python-clone bench-owasp-clone bench-owasp bench-railsgoat-clone bench-railsgoat bench-discourse-clone bench-discourse bench-gocve bench-gocve-stage bench-pycve bench-pycve-stage bench-jscve bench-jscve-stage bench-javacve bench-javacve-stage bench-rubycve bench-rubycve-stage bench-phpcve bench-phpcve-stage bench-compare scorecard scorecard-offline

# Build output
BIN_DIR := bin
BINARY := $(BIN_DIR)/batou

# Go settings — CGO is required for tree-sitter AST parsing
GO := go
CGO_ENABLED := 1
GOFLAGS := -trimpath
# VERSION must be defined before LDFLAGS — LDFLAGS uses := (immediate expansion),
# so $(VERSION) would be empty if defined afterward.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X 'main.version=$(VERSION)'

# Default target
all: build

# Build the Batou binary
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./batou-core/cmd/batou

# Build for all platforms (CGO cross-compilation requires appropriate C toolchain)
build-all:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/batou-darwin-arm64 ./batou-core/cmd/batou
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/batou-darwin-amd64 ./batou-core/cmd/batou
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/batou-linux-amd64 ./batou-core/cmd/batou
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/batou-linux-arm64 ./batou-core/cmd/batou

# Install to user directory
install: build
	@mkdir -p $(HOME)/.batou/bin
	cp $(BINARY) $(HOME)/.batou/bin/batou
	@echo "Batou installed to $(HOME)/.batou/bin/batou"
	@echo "Run 'batou-setup' to configure hooks in your project"

# Install hook configuration into target project
# Usage: make setup PROJECT=/path/to/your/project
setup:
ifndef PROJECT
	$(error PROJECT is required. Usage: make setup PROJECT=/path/to/project)
endif
	@mkdir -p $(PROJECT)/.claude/hooks
	@cp .claude/hooks/batou-hook.sh $(PROJECT)/.claude/hooks/batou-hook.sh
	@chmod +x $(PROJECT)/.claude/hooks/batou-hook.sh
	@if [ -f $(PROJECT)/.claude/settings.json ]; then \
		echo "WARNING: $(PROJECT)/.claude/settings.json exists."; \
		echo "Please merge Batou hooks manually from .claude/settings.json"; \
	else \
		cp .claude/settings.json $(PROJECT)/.claude/settings.json; \
		echo "Batou hooks installed in $(PROJECT)/.claude/settings.json"; \
	fi
	@echo "Batou setup complete for $(PROJECT)"

# Run tests
test:
	$(GO) test -v -race -count=1 -timeout 25m ./...

# Run tests with coverage
test-cover:
	$(GO) test -v -race -coverprofile=coverage.out -timeout 25m ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Audit the sink catalog: cross-check each DangerousArgs position
# against the real Go signature via go/types. Catches entries where
# a dangerous position points at a parameter whose type cannot carry
# user-controlled string data (time.Time, context.Context, error,
# *os.File, sync.Mutex, channels, functions, numerics).
audit-catalog:
	$(GO) run ./batou-core/cmd/audit-catalog

# Audit the Python sink catalog: mirror of audit-catalog for Python.
# Resolves each free-function sink to its real Python signature via
# `python3 -c "import inspect; ..."`, then flags DangerousArgs positions
# whose parameter type or name indicates non-taintable data (int, bool,
# socket.socket, threading.Lock, bufsize, timeout, port, etc.).
# Skips third-party modules (no pip install). If python3 is missing,
# the auditor exits 0 with a warning so this target is safe on
# Python-less machines.
audit-catalog-python:
	$(GO) run ./batou-core/cmd/audit-python-catalog

# Lint
lint:
	@if command -v golangci-lint &>/dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found, running go vet"; \
		$(GO) vet ./...; \
	fi

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

# Measure end-to-end write-time hook latency: pipe realistic PreToolUse /
# PostToolUse Write events into a freshly built bin/batou N=20 times and
# report p50/p95 wall-clock per invocation — cold (no .batou/) and warm
# (~MB-scale .batou/callgraph.json) so the call-graph load/save cost is
# visible. In-process pipeline benchmarks live in
# batou-core/scanner/hooklatency_bench_test.go (BenchmarkHookPipeline).
bench-hook: build
	@python3 tools/bench_hook.py

# Clone OWASP BenchmarkJava to testdata/external/
bench-owasp-java-clone:
	@mkdir -p testdata/external
	@if [ ! -d testdata/external/BenchmarkJava ]; then \
		git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git testdata/external/BenchmarkJava; \
	else \
		echo "BenchmarkJava already cloned"; \
	fi

# Clone OWASP BenchmarkPython to testdata/external/
bench-owasp-python-clone:
	@mkdir -p testdata/external
	@if [ ! -d testdata/external/BenchmarkPython ]; then \
		git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython.git testdata/external/BenchmarkPython; \
	else \
		echo "BenchmarkPython already cloned"; \
	fi

# Clone both OWASP Benchmark repos
bench-owasp-clone: bench-owasp-java-clone bench-owasp-python-clone

# Run OWASP Benchmark tests (requires prior clone)
bench-owasp:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestOWASPBench' -timeout 30m ./batou-core/scanner/

# Clone OWASP RailsGoat (Ruby vulnerable app)
bench-railsgoat-clone:
	@mkdir -p testdata/external
	@if [ ! -d testdata/external/railsgoat ]; then \
		git clone --depth 1 https://github.com/OWASP/railsgoat.git testdata/external/railsgoat; \
	else \
		echo "railsgoat already cloned"; \
	fi

# Run RailsGoat bench (requires prior clone)
bench-railsgoat: bench-railsgoat-clone
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestRailsGoatBench' -timeout 10m ./batou-core/scanner/

# Clone Discourse (real-world Rails app for crash testing)
bench-discourse-clone:
	@mkdir -p testdata/external
	@if [ ! -d testdata/external/discourse ]; then \
		git clone --depth 1 https://github.com/discourse/discourse.git testdata/external/discourse; \
	else \
		echo "discourse already cloned"; \
	fi

# Run Discourse crash test (requires prior clone, ~400k LoC)
bench-discourse: bench-discourse-clone
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestDiscourseBench' -timeout 30m ./batou-core/scanner/

# Re-stage the Go CVE benchmark fixtures from the in-tree manifest.
# Reads tools/gocve_manifest.yaml + tools/gocve_fixtures/ and writes
# testdata/gocve-bench/CVE-*/{vuln,safe,expected.json}.
bench-gocve-stage:
	python3 tools/fetch_gocve_fixtures.py

# Run the Go CVE benchmark harness (testdata/gocve-bench is committed,
# so this works offline; bench-gocve-stage only needs to run when the
# manifest changes).
bench-gocve:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestGoCVEBench' -timeout 15m ./batou-core/scanner/

# Re-stage the Python CVE benchmark fixtures from the in-tree manifest.
# Reads tools/pycve_manifest.yaml + tools/pycve_fixtures/ and writes
# testdata/pycve-bench/CVE-*/{vuln,safe,expected.json}.
bench-pycve-stage:
	python3 tools/fetch_pycve_fixtures.py

# Run the Python CVE benchmark harness (testdata/pycve-bench is committed,
# so this works offline; bench-pycve-stage only needs to run when the
# manifest changes).
bench-pycve:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestPyCVEBench' -timeout 15m ./batou-core/scanner/

# JS/TS CVE benchmark fixtures live in testdata/jscve-bench/CVE-*/; no
# external staging script yet — fixtures are hand-curated and committed
# in-tree. This target is reserved for symmetry with bench-pycve-stage
# and will host the fetcher once the corpus outgrows manual curation.
bench-jscve-stage:
	@echo "bench-jscve-stage: testdata/jscve-bench fixtures are curated in-tree; nothing to stage."

# Run the JS/TS CVE benchmark harness (testdata/jscve-bench is committed,
# so this works offline).
bench-jscve:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestJsCVEBench' -timeout 15m ./batou-core/scanner/

# Java CVE benchmark fixtures live in testdata/javacve-bench/{CVE-*,classic-*}/;
# no external staging script — fixtures are hand-curated and committed in-tree.
# This target is reserved for symmetry with bench-pycve-stage and will host a
# fetcher if the corpus outgrows manual curation.
bench-javacve-stage:
	@echo "bench-javacve-stage: testdata/javacve-bench fixtures are curated in-tree; nothing to stage."

# Run the Java CVE benchmark harness (testdata/javacve-bench is committed,
# so this works offline).
bench-javacve:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestJavaCVEBench' -timeout 15m ./batou-core/scanner/

# Ruby CVE benchmark fixtures live in testdata/rubycve-bench/{CVE-*,classic-*}/;
# no external staging script — fixtures are hand-curated and committed in-tree.
# This target is reserved for symmetry with bench-pycve-stage and will host a
# fetcher if the corpus outgrows manual curation.
bench-rubycve-stage:
	@echo "bench-rubycve-stage: testdata/rubycve-bench fixtures are curated in-tree; nothing to stage."

# Run the Ruby CVE benchmark harness (testdata/rubycve-bench is committed,
# so this works offline).
bench-rubycve:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestRubyCVEBench' -timeout 15m ./batou-core/scanner/

# Stage the PHP CVE corpus — fixtures are committed in-tree, nothing to do.
bench-phpcve-stage:
	@echo "bench-phpcve-stage: testdata/phpcve-bench fixtures are curated in-tree; nothing to stage."

# Run the PHP CVE benchmark harness (testdata/phpcve-bench is committed).
bench-phpcve:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestPHPCVEBench' -timeout 15m ./batou-core/scanner/

# Dual-lane scorecard: every bench now logs a REPORT-lane and a BLOCK-lane
# (RiskScore>=0.7, Finding.ShouldBlock) Overall line. This runs all benches in
# one `go test` invocation and surfaces both lanes side by side — the report
# lane prints "Overall: TPRate=" / "Overall: TPRate=" and the block lane prints
# "Overall (BLOCK lane): TPRate=" / "Overall (BLOCK lane): TPRate=". OWASP rows
# require a prior `make bench-owasp-clone` (the OWASP corpus is gitignored and
# the benches t.Skip without it; the six CVE corpora are committed in-tree).
bench-compare:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -timeout 40m \
	  -run 'TestOWASPBench|TestGoCVEBench|TestJsCVEBench|TestPyCVEBench|TestJavaCVEBench|TestRubyCVEBench|TestPHPCVEBench' \
	  ./batou-core/scanner/ 2>&1 | grep -E 'Scorecard|Overall \(BLOCK lane\):|Overall: TPRate='

# ---------------------------------------------------------------------------
# Consolidated reference-SAST-gap scorecard (pure measurement infra; no engine changes)
# ---------------------------------------------------------------------------
# Aggregates the six committed, offline CVE benches into ONE table
# (per language | Batou TPR | Batou FPR | corpus | N | reference-SAST column) plus a
# corpus gap-map over all supported languages. Writes a human-readable scorecard
# to stdout and a diffable JSON artifact to testdata/scorecard/scorecard.json.
# reference-SAST rows are honest: "unsupported" for PHP/Perl/Lua/Groovy/Zig/Shell (no
# reference-SAST analyzer), and "supported (no primary-source number)" elsewhere — we do
# not fabricate a reference-SAST TPR/FPR. OWASP rows are folded in only if
# testdata/owasp-bench was already generated (`make bench-owasp`).

# Refresh the six CVE benches first (fresh numbers), then aggregate.
scorecard: bench-gocve bench-jscve bench-pycve bench-javacve bench-rubycve bench-phpcve
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestConsolidatedScorecard' -timeout 5m ./batou-core/scanner/

# Aggregate the committed results.json WITHOUT re-running the benches. Fully
# offline and fast; uses whatever numbers are currently on disk.
scorecard-offline:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test -v -run 'TestConsolidatedScorecard' -timeout 5m ./batou-core/scanner/

# Dev: build and watch for changes
dev: build
	@echo "Batou binary built at $(BINARY)"
	@echo "To test: echo '{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"test.go\",\"content\":\"package main\"}}' | ./$(BINARY)"
