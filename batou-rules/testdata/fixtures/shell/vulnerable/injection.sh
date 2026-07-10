#!/bin/bash
# Vulnerable shell patterns — structural (AST) detection.
#
# Two rule families with different gating:
#  - eval / source / sh -c of DYNAMIC data (002/003/004) fire on any non-literal
#    argument regardless of provenance (re-parsing a constructed string as code
#    is dangerous on its own).
#  - word-splitting (001) and variable command name (005) fire ONLY on
#    EXTERNALLY-derived operands (CGI/web env, stdin via read, network fetch).
#    Local/positional/constant operands are intentionally NOT flagged.

# CWE-78: eval of dynamic data (ungated — re-parses a runtime string as code).
expr=$REQUEST
eval "$expr"

# CWE-95: source / . of a variable-controlled path (ungated).
cfgfile=$2
source "$cfgfile"
. $cfgfile

# CWE-78: bash -c building an inline program from a variable (ungated).
payload=$3
bash -c "run $payload"

# CWE-78: unquoted word-splitting of an EXTERNAL value (read from stdin).
read userpath
cp $userpath /dest

# CWE-78: command name taken from an EXTERNAL value (CGI request env var).
action=$QUERY_STRING
$action --do-it
