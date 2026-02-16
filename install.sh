#!/usr/bin/env bash
#
# Batou - Code guard for your AI agents
# Installation Script
#
# Installs the Batou binary and configures Claude Code hooks
# for a target project.
#
# Usage:
#   ./install.sh                    # Build and install Batou binary
#   ./install.sh --setup /path/to   # Also configure hooks in a project
#   ./install.sh --global           # Install hooks in ~/.claude/settings.json
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

BATOU_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="$HOME/.batou"
BIN_DIR="$INSTALL_DIR/bin"

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════╗"
    echo "  ║                                                       ║"
    echo "  ║  ██████╗  █████╗ ████████╗ ██████╗ ██╗   ██╗         ║"
    echo "  ║  ██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██║   ██║         ║"
    echo "  ║  ██████╔╝███████║   ██║   ██║   ██║██║   ██║         ║"
    echo "  ║  ██╔══██╗██╔══██║   ██║   ██║   ██║██║   ██║         ║"
    echo "  ║  ██████╔╝██║  ██║   ██║   ╚██████╔╝╚██████╔╝         ║"
    echo "  ║  ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝         ║"
    echo "  ║                                                       ║"
    echo "  ║   Code guard for your AI agents                       ║"
    echo "  ║                                                       ║"
    echo "  ╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

check_deps() {
    info "Checking dependencies..."

    if ! command -v go &>/dev/null; then
        error "Go is not installed. Please install Go 1.21+ from https://go.dev"
        exit 1
    fi

    GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
    info "Go version: $GO_VERSION"
    success "Dependencies satisfied"
}

build_batou() {
    info "Building Batou..."
    cd "$BATOU_DIR"

    mkdir -p bin
    go build -trimpath -ldflags "-s -w" -o bin/batou ./cmd/batou

    if [[ ! -x bin/batou ]]; then
        error "Build failed"
        exit 1
    fi

    success "Batou binary built: $BATOU_DIR/bin/batou"
}

install_binary() {
    info "Installing Batou to $BIN_DIR..."

    mkdir -p "$BIN_DIR"
    cp "$BATOU_DIR/bin/batou" "$BIN_DIR/batou"
    chmod +x "$BIN_DIR/batou"

    # Create ledger directory
    mkdir -p "$INSTALL_DIR/ledger"

    success "Batou installed to $BIN_DIR/batou"

    # Check if on PATH
    if ! echo "$PATH" | tr ':' '\n' | grep -q "$BIN_DIR"; then
        warn "$BIN_DIR is not on your PATH"
        info "Add to your shell profile:"
        echo "  export PATH=\"\$HOME/.batou/bin:\$PATH\""
    fi
}

setup_hooks() {
    local project_dir="$1"

    info "Setting up Batou hooks in $project_dir..."

    # Create .claude/hooks directory
    mkdir -p "$project_dir/.claude/hooks"

    # Copy hook script
    cp "$BATOU_DIR/.claude/hooks/batou-hook.sh" "$project_dir/.claude/hooks/batou-hook.sh"
    chmod +x "$project_dir/.claude/hooks/batou-hook.sh"

    # Handle settings.json
    local settings_file="$project_dir/.claude/settings.json"

    if [[ -f "$settings_file" ]]; then
        # Check if Batou hooks already configured
        if grep -q "batou-hook" "$settings_file" 2>/dev/null; then
            success "Batou hooks already configured in $settings_file"
            return
        fi

        warn "$settings_file exists. Merging Batou hooks..."

        # Use a temp file for safe merge
        local tmp_file
        tmp_file=$(mktemp)

        # Merge using Go's json capabilities or jq if available
        if command -v jq &>/dev/null; then
            jq -s '
                def merge_hooks:
                    .[0].hooks as $existing |
                    .[1].hooks as $new |
                    ($existing // {}) as $e |
                    ($new // {}) as $n |
                    {hooks: ($e * $n)} + (.[0] | del(.hooks));
                merge_hooks
            ' "$settings_file" "$BATOU_DIR/.claude/settings.json" > "$tmp_file"
            mv "$tmp_file" "$settings_file"
            success "Merged Batou hooks into existing settings"
        else
            warn "jq not found. Please manually merge hooks from:"
            echo "  $BATOU_DIR/.claude/settings.json"
            echo "  into: $settings_file"
        fi
    else
        cp "$BATOU_DIR/.claude/settings.json" "$settings_file"
        success "Batou hooks installed in $settings_file"
    fi
}

setup_global() {
    info "Setting up Batou hooks globally..."

    local settings_file="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    # For global install, the hook script path needs to reference ~/.batou
    local hook_script="$INSTALL_DIR/hooks/batou-hook.sh"
    mkdir -p "$INSTALL_DIR/hooks"

    cat > "$hook_script" << 'HOOKEOF'
#!/usr/bin/env bash
set -euo pipefail
BATOU_BIN="$HOME/.batou/bin/batou"
if [[ -x "$BATOU_BIN" ]]; then
    exec "$BATOU_BIN"
fi
exit 0
HOOKEOF
    chmod +x "$hook_script"

    # Create or merge settings
    local batou_hooks
    batou_hooks=$(cat << JSONEOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "$hook_script",
            "timeout": 30,
            "statusMessage": "Batou: Scanning for vulnerabilities..."
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "$hook_script",
            "timeout": 30,
            "statusMessage": "Batou: Deep security scan..."
          }
        ]
      }
    ]
  }
}
JSONEOF
)

    if [[ -f "$settings_file" ]]; then
        if grep -q "batou" "$settings_file" 2>/dev/null; then
            success "Batou hooks already in global settings"
            return
        fi
        warn "Global settings exist. Please manually merge Batou hooks."
        echo "  Batou hook config:"
        echo "$batou_hooks" | head -20
    else
        echo "$batou_hooks" > "$settings_file"
        success "Batou hooks installed globally in $settings_file"
    fi
}

# --- Main ---

banner

MODE="install"
PROJECT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --setup)
            MODE="setup"
            PROJECT_DIR="${2:-.}"
            shift 2
            ;;
        --global)
            MODE="global"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --setup /path    Install + configure hooks in a project"
            echo "  --global         Install + configure hooks globally"
            echo "  --help           Show this help"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

check_deps
build_batou
install_binary

case "$MODE" in
    setup)
        PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"
        setup_hooks "$PROJECT_DIR"
        ;;
    global)
        setup_global
        ;;
esac

echo ""
success "Batou installation complete!"
echo ""
info "Quick test:"
echo "  echo '{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"test.py\",\"content\":\"import pickle\\npickle.loads(user_data)\"}}' | $BIN_DIR/batou"
echo ""
info "To scan code as it's written, Batou hooks are active in Claude Code."
echo ""
