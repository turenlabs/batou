#!/usr/bin/env bash
#
# GTSS Hook Entry Point
#
# This script is called by Claude Code hooks on Write/Edit events.
# It receives JSON on stdin and delegates to the compiled GTSS binary.
#
# If the GTSS binary is not found, it silently exits to avoid
# breaking the hook chain.
#

set -euo pipefail

# Resolve the GTSS binary location
# Priority: 1) project-local build  2) user install  3) system install
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

GTSS_BIN=""

if [[ -x "$PROJECT_DIR/bin/gtss" ]]; then
    GTSS_BIN="$PROJECT_DIR/bin/gtss"
elif [[ -x "$HOME/.gtss/bin/gtss" ]]; then
    GTSS_BIN="$HOME/.gtss/bin/gtss"
elif command -v gtss &>/dev/null; then
    GTSS_BIN="$(command -v gtss)"
fi

# If no binary found, exit silently
if [[ -z "$GTSS_BIN" ]]; then
    exit 0
fi

# Pipe stdin directly to the GTSS binary
exec "$GTSS_BIN"
