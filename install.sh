#!/usr/bin/env bash
#
# Batou - Code guard for your AI agents
# Installation Script
#
# Downloads the latest Batou binary from GitHub releases and optionally
# configures Claude Code hooks for a target project.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/turenlabs/batou/main/install.sh | bash
#   ./install.sh                    # Download and install latest binary
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

REPO="turenlabs/batou"
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

detect_platform() {
    local os arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Darwin) os="darwin" ;;
        Linux)  os="linux" ;;
        *)
            error "Unsupported OS: $os"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

get_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    local version

    if command -v curl &>/dev/null; then
        version=$(curl -fsSL "$url" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget &>/dev/null; then
        version=$(wget -qO- "$url" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        error "curl or wget is required"
        exit 1
    fi

    if [[ -z "$version" ]]; then
        error "Failed to fetch latest version from GitHub"
        exit 1
    fi

    echo "$version"
}

download_binary() {
    local version="$1"
    local platform="$2"
    local artifact="batou-${platform}"
    local url="https://github.com/${REPO}/releases/download/${version}/${artifact}"

    info "Downloading Batou ${version} for ${platform}..."

    mkdir -p "$BIN_DIR"
    local tmp_file
    tmp_file=$(mktemp)

    if command -v curl &>/dev/null; then
        if ! curl -fSL --progress-bar -o "$tmp_file" "$url"; then
            rm -f "$tmp_file"
            error "Download failed. Check that a release exists for ${platform}"
            error "URL: $url"
            exit 1
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --show-progress -O "$tmp_file" "$url"; then
            rm -f "$tmp_file"
            error "Download failed. Check that a release exists for ${platform}"
            error "URL: $url"
            exit 1
        fi
    fi

    mv "$tmp_file" "$BIN_DIR/batou"
    chmod +x "$BIN_DIR/batou"

    # Create ledger directory
    mkdir -p "$INSTALL_DIR/ledger"

    success "Batou ${version} installed to $BIN_DIR/batou"

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

    mkdir -p "$project_dir/.claude/hooks"

    # Write the hook script directly (no need for a source repo checkout)
    cat > "$project_dir/.claude/hooks/batou-hook.sh" << 'HOOKEOF'
#!/usr/bin/env bash
set -euo pipefail
BATOU_BIN=""
if [[ -x "$HOME/.batou/bin/batou" ]]; then
    BATOU_BIN="$HOME/.batou/bin/batou"
elif command -v batou &>/dev/null; then
    BATOU_BIN="$(command -v batou)"
fi
if [[ -z "$BATOU_BIN" ]]; then
    exit 0
fi
exec "$BATOU_BIN"
HOOKEOF
    chmod +x "$project_dir/.claude/hooks/batou-hook.sh"

    # Handle settings.json
    local settings_file="$project_dir/.claude/settings.json"
    local hook_config
    hook_config=$(cat << 'JSONEOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/batou-hook.sh",
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
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/batou-hook.sh",
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
        if grep -q "batou-hook" "$settings_file" 2>/dev/null; then
            success "Batou hooks already configured in $settings_file"
            return
        fi

        warn "$settings_file exists."
        if command -v jq &>/dev/null; then
            local tmp_file
            tmp_file=$(mktemp)
            echo "$hook_config" | jq -s '.[0] * .[1]' "$settings_file" - > "$tmp_file"
            mv "$tmp_file" "$settings_file"
            success "Merged Batou hooks into existing settings"
        else
            warn "jq not found. Please manually add Batou hooks to $settings_file"
            echo "$hook_config"
        fi
    else
        echo "$hook_config" > "$settings_file"
        success "Batou hooks installed in $settings_file"
    fi
}

setup_global() {
    info "Setting up Batou hooks globally..."

    local settings_file="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

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
        if command -v jq &>/dev/null; then
            local tmp_file
            tmp_file=$(mktemp)
            echo "$batou_hooks" | jq -s '.[0] * .[1]' "$settings_file" - > "$tmp_file"
            mv "$tmp_file" "$settings_file"
            success "Merged Batou hooks into global settings"
        else
            warn "$settings_file exists. Install jq to auto-merge, or add manually:"
            echo "$batou_hooks"
        fi
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

PLATFORM=$(detect_platform)
VERSION=$(get_latest_version)

info "Detected platform: $PLATFORM"
info "Latest version: $VERSION"

download_binary "$VERSION" "$PLATFORM"

case "$MODE" in
    install)
        # Default: install globally so hooks work out of the box
        setup_global
        ;;
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
