#!/bin/bash
# Safe equivalents — quoting and literals defeat the structural (AST) checks.
# Uses local/literal values (not $1) so neither the AST analyzer nor the taint
# engine should flag this file.
set -euo pipefail

src="/srv/app/data"
dst="/srv/app/backup"

# Quoted expansions: no word-splitting / globbing.
cp "$src" "$dst"
mv "$src" "$dst"

# eval / source of static, trusted values only.
eval "echo done"
source /etc/profile

# Fixed command name, fixed argument.
bash ./run.sh build

# echo is low-value and intentionally out of the consequential-command list.
echo "deploying $src"
