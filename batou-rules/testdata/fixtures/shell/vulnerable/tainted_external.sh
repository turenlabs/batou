#!/bin/bash
# Externally-tainted shell injection — proves the AST analyzer's external-origin
# gate fires on genuinely user-controlled operands (CGI/web env, stdin via read,
# network fetch), NOT just on every occurrence of the dangerous shape.

# CWE-78: CGI request env var consumed directly, then word-split into a file cmd.
cp $QUERY_STRING /var/www/uploads/dest

# CWE-78: request env var assigned, then word-split into a network/file command.
target=$HTTP_X_FORWARDED_FOR
rm $target

# CWE-78: value read from stdin (interactive prompt), word-split unquoted.
read -p "Enter path: " userpath
tar -xf $userpath

# CWE-78: command substitution of a network fetch → remotely controlled, then
# used as the command name (arbitrary program execution).
plugin=$(curl -s http://config.internal/plugin-name)
$plugin --run

# CWE-78: transitive — derived from a request env var, word-split into a command.
base=$REQUEST_URI
dir="${base}/cache"
rm $dir
