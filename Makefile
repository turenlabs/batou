.PHONY: build install clean test lint

# Build output
BIN_DIR := bin
BINARY := $(BIN_DIR)/gtss

# Go settings
GO := go
GOFLAGS := -trimpath
LDFLAGS := -s -w -X 'main.version=$(VERSION)'
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Default target
all: build

# Build the GTSS binary
build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/gtss

# Build for all platforms
build-all:
	@mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gtss-darwin-arm64 ./cmd/gtss
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gtss-darwin-amd64 ./cmd/gtss
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gtss-linux-amd64 ./cmd/gtss
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/gtss-linux-arm64 ./cmd/gtss

# Install to user directory
install: build
	@mkdir -p $(HOME)/.gtss/bin
	cp $(BINARY) $(HOME)/.gtss/bin/gtss
	@echo "GTSS installed to $(HOME)/.gtss/bin/gtss"
	@echo "Run 'gtss-setup' to configure hooks in your project"

# Install hook configuration into target project
# Usage: make setup PROJECT=/path/to/your/project
setup:
ifndef PROJECT
	$(error PROJECT is required. Usage: make setup PROJECT=/path/to/project)
endif
	@mkdir -p $(PROJECT)/.claude/hooks
	@cp .claude/hooks/gtss-hook.sh $(PROJECT)/.claude/hooks/gtss-hook.sh
	@chmod +x $(PROJECT)/.claude/hooks/gtss-hook.sh
	@if [ -f $(PROJECT)/.claude/settings.json ]; then \
		echo "WARNING: $(PROJECT)/.claude/settings.json exists."; \
		echo "Please merge GTSS hooks manually from .claude/settings.json"; \
	else \
		cp .claude/settings.json $(PROJECT)/.claude/settings.json; \
		echo "GTSS hooks installed in $(PROJECT)/.claude/settings.json"; \
	fi
	@echo "GTSS setup complete for $(PROJECT)"

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
	@echo "GTSS binary built at $(BINARY)"
	@echo "To test: echo '{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"test.go\",\"content\":\"package main\"}}' | ./$(BINARY)"
