.PHONY: build install clean test lint

# Build output
BIN_DIR := bin
BINARY := $(BIN_DIR)/batou

# Go settings — CGO is required for tree-sitter AST parsing
GO := go
CGO_ENABLED := 1
GOFLAGS := -trimpath
LDFLAGS := -s -w -X 'main.version=$(VERSION)'
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Default target
all: build

# Build the Batou binary
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/batou

# Build for all platforms (CGO cross-compilation requires appropriate C toolchain)
build-all:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/batou-darwin-arm64 ./cmd/batou
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/batou-darwin-amd64 ./cmd/batou
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/batou-linux-amd64 ./cmd/batou
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/batou-linux-arm64 ./cmd/batou

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
	$(GO) test -v -race -count=1 ./...

# Run tests with coverage
test-cover:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

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

# Dev: build and watch for changes
dev: build
	@echo "Batou binary built at $(BINARY)"
	@echo "To test: echo '{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"test.go\",\"content\":\"package main\"}}' | ./$(BINARY)"
