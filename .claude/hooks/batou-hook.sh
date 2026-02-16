#!/usr/bin/env bash
#
# Batou Hook Entry Point
#
# This script is called by Claude Code hooks on Write/Edit events.
# It receives JSON on stdin and delegates to the compiled Batou binary.
#
# If the Batou binary is not found, it silently exits to avoid
# breaking the hook chain.
#

set -euo pipefail

# Resolve the Batou binary location
# Priority: 1) project-local build  2) user install  3) system install
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

BATOU_BIN=""

if [[ -x "$PROJECT_DIR/bin/batou" ]]; then
    BATOU_BIN="$PROJECT_DIR/bin/batou"
elif [[ -x "$HOME/.batou/bin/batou" ]]; then
    BATOU_BIN="$HOME/.batou/bin/batou"
elif command -v batou &>/dev/null; then
    BATOU_BIN="$(command -v batou)"
fi

# If no binary found, exit silently
if [[ -z "$BATOU_BIN" ]]; then
    exit 0
fi

# Pipe stdin directly to the Batou binary
exec "$BATOU_BIN"
