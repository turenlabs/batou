package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *ShellCatalog) Sinks() []taint.SinkDef {
	return []taint.SinkDef{
		// --- Command Injection: eval (CWE-78) ---
		// tsflow: command name "eval" matches via MethodName.
		{
			ID:            "shell.cmd.eval",
			Category:      taint.SnkCommand,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])eval\s`,
			ObjectType:    "",
			MethodName:    "eval",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "eval executes its argument string as shell code — tainted input yields arbitrary command execution",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Command Injection: sh/bash -c (CWE-78) ---
		// tsflow: command names sh/bash/dash/ksh/zsh match via MethodName; the
		// regex Pattern further requires the -c flag so plain `bash script.sh`
		// (not an inline-code sink) doesn't fire in the regex engine.
		{
			ID:            "shell.cmd.sh_c",
			Category:      taint.SnkCommand,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])(?:sh|bash|dash|ksh|zsh)\s+(?:-[a-z]*\s+)*-c\b`,
			ObjectType:    "",
			MethodName:    "sh/bash/dash/ksh/zsh",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "sh -c / bash -c runs a string as shell code — tainted input yields arbitrary command execution",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Command Injection: command substitution with a variable (CWE-78) ---
		// $(... $var ...) and `... $var ...` re-parse expanded variables as a
		// command line. Regex-engine sink (no single command name to anchor).
		{
			ID:            "shell.cmd.subst_dollar",
			Category:      taint.SnkCommand,
			Language:      rules.LangShell,
			Pattern:       `\$\([^)]*\$[A-Za-z_@*]`,
			ObjectType:    "",
			MethodName:    "command_substitution",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "$(...) command substitution interpolating a variable — expanded value is re-parsed as a command (command injection)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.cmd.subst_backtick",
			Category:      taint.SnkCommand,
			Language:      rules.LangShell,
			Pattern:       "`[^`]*\\$[A-Za-z_@*]",
			ObjectType:    "",
			MethodName:    "backtick_substitution",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Backtick command substitution interpolating a variable — expanded value is re-parsed as a command (command injection)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Command Injection: xargs (CWE-78) ---
		// tsflow: command name "xargs" matches via MethodName. xargs runs its
		// argument command once per input token; tainted input becomes argv.
		{
			ID:            "shell.cmd.xargs",
			Category:      taint.SnkCommand,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])xargs\b`,
			ObjectType:    "",
			MethodName:    "xargs",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "xargs builds and runs a command from untrusted stdin tokens (command injection / argument injection)",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Code Eval: source / . of a variable path (CWE-95) ---
		// tsflow: command names "source" and "." match via MethodName.
		{
			ID:            "shell.eval.source",
			Category:      taint.SnkEval,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])(?:source|\.)\s+["']?\$`,
			ObjectType:    "",
			MethodName:    "source/.",
			DangerousArgs: []int{0},
			Severity:      rules.Critical,
			Description:   "source / . of a variable-controlled path executes the target file in the current shell (arbitrary code execution)",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Path Traversal: file commands taking a variable path (CWE-22) ---
		// tsflow: command names cp/mv/rm/cat/ln/chmod/chown/touch/mkdir/rmdir
		// match via MethodName. The regex Pattern requires a $-expansion in the
		// argument so a hardcoded path doesn't fire in the regex engine.
		{
			ID:            "shell.path.file_cmd",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])(?:cp|mv|rm|cat|ln|chmod|chown|touch|mkdir|rmdir)\s+(?:-[^\s]+\s+)*["']?\$`,
			ObjectType:    "",
			MethodName:    "cp/mv/rm/cat/ln/chmod/chown/touch/mkdir/rmdir",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "File command operating on a variable-controlled path — unsanitized input enables path traversal / arbitrary file access",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- Path Traversal: redirection target controlled by a variable (CWE-22) ---
		// Regex-engine sink: `> $file` / `>> $file` writes to a variable path.
		{
			ID:            "shell.path.redirect",
			Category:      taint.SnkFileWrite,
			Language:      rules.LangShell,
			Pattern:       `>>?\s*["']?(?:\S*\$|\$)`,
			ObjectType:    "",
			MethodName:    "redirect_write",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Output redirection (> / >>) to a variable-controlled path — unsanitized input enables path traversal / arbitrary file write",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
		},

		// --- SSRF: curl/wget with a variable URL (CWE-918) ---
		// tsflow: command names curl/wget match via MethodName. Regex Pattern
		// requires a $-expansion in the URL argument.
		{
			ID:            "shell.ssrf.curl_wget",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])(?:curl|wget)\s+(?:-[^\s]+\s+)*["']?(?:\S*\$|\$)`,
			ObjectType:    "",
			MethodName:    "curl/wget",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "curl / wget fetching a variable-controlled URL — unvalidated input enables server-side request forgery",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- SSRF: scp/sftp/nc/ftp/rsync with a variable host in arg-1 (CWE-918) ---
		// tsflow: command names scp/sftp/nc/ncat/netcat/ftp/rsync match via
		// MethodName. For these tools the remote host/URL is the first positional
		// argument, so the regex Pattern requires a $-expansion right after the
		// command (modulo flags). A hardcoded host doesn't fire. A tainted host
		// lets an attacker redirect the connection to an internal endpoint (SSRF).
		{
			ID:            "shell.ssrf.netfetch",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])(?:scp|sftp|nc|ncat|netcat|ftp|rsync)\s+(?:-[^\s]+\s+)*["']?(?:\S*\$|\$)`,
			ObjectType:    "",
			MethodName:    "scp/sftp/nc/ncat/netcat/ftp/rsync",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "Network tool (scp/sftp/nc/netcat/ftp/rsync) connecting to a variable-controlled host — unvalidated input enables server-side request forgery",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- SSRF: git network subcommands cloning/fetching a variable URL (CWE-918) ---
		// tsflow: command name "git" matches via MethodName. git's remote URL is
		// not arg-1 (a subcommand comes first), so the Pattern is anchored to the
		// network subcommands (clone/fetch/pull/ls-remote) followed by a tainted
		// URL. Restricting to those subcommands avoids false-positives on
		// `git commit -m "...$var..."` and other local-only git usage.
		{
			ID:            "shell.ssrf.git_remote",
			Category:      taint.SnkURLFetch,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])git\s+(?:-[^\s]+\s+)*(?:clone|fetch|pull|ls-remote)\s+(?:-[^\s]+\s+)*["']?(?:\S*\$|\$)`,
			ObjectType:    "",
			MethodName:    "git",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "git clone/fetch/pull/ls-remote of a variable-controlled URL — unvalidated input enables server-side request forgery",
			CWEID:         "CWE-918",
			OWASPCategory: "A10:2021-Server-Side Request Forgery",
		},

		// --- jq filter injection: jq program built from a variable (CWE-95) ---
		// jq's filter language is a full, Turing-complete expression language.
		// Building the filter program by interpolating a shell variable lets an
		// attacker break out of the intended expression and run arbitrary jq:
		// read any field, use `input`/`inputs`/`$ENV`/`env`, exfiltrate via
		// `@base64`/`@sh`, or (with --args) reach further. The *safe* form passes
		// untrusted values as data with `--arg`/`--argjson` (see sanitizers).
		// tsflow: command name "jq" matches via MethodName. The regex Pattern
		// requires a $-expansion inside the (quoted) filter argument so a static
		// hardcoded filter does not fire in the regex engine. DangerousArgs {-1}
		// (matching the rest of this catalog, e.g. shell.path.file_cmd) scans all
		// args in the tsflow engine; a tainted *data-file* path passed to jq is a
		// lower-value but real path-traversal-class concern, so flagging it here
		// is acceptable, while the precise regex Pattern keeps the regex-engine
		// path filter-only. Scoped to the `jq` command word (ObjectType "") so
		// unrelated shell never over-matches.
		{
			ID:            "shell.jq.filter_inject",
			Category:      taint.SnkEval,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])jq\s+(?:-[^\s]+\s+|--[a-z]+\s+\S+\s+)*["'][^"']*\$[A-Za-z_{]`,
			ObjectType:    "",
			MethodName:    "jq",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "jq filter program built by interpolating a variable — tainted input is parsed as jq filter code (jq injection / arbitrary jq evaluation). Use --arg/--argjson to pass values as data.",
			CWEID:         "CWE-95",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Command Injection: indirect variable expansion ${!var} (CWE-78) ---
		// ${!name} expands to the value of the variable *named by* $name. When the
		// indirection key is attacker-controlled (e.g. a CLI arg $1), the attacker
		// chooses which variable to dereference, and the expanded value typically
		// flows into a command/eval. Regex-engine sink (parameter expansion is not
		// a call node, so ObjectType/MethodName stay empty — the `${!` form is
		// itself distinctive enough to anchor without a receiver gate).
		{
			ID:            "shell.cmd.indirect_expand",
			Category:      taint.SnkCommand,
			Language:      rules.LangShell,
			Pattern:       `\$\{!`,
			ObjectType:    "",
			MethodName:    "indirect_expansion",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "${!var} indirect expansion dereferences a variable named by another variable — an attacker-controlled name yields arbitrary variable read / command injection",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- SQL Injection via CLI database clients (CWE-89) ---
		// Ops / CI / deploy scripts routinely shell out to a database client and
		// interpolate a shell variable straight into the query string
		// (`mysql -e "SELECT ... $row ..."`). Because the shell expands $row
		// before the client ever sees it, an attacker-controlled value injects
		// arbitrary SQL. tsflow matches the bare command word (mysql, psql, …)
		// via MethodName and, with DangerousArgs -1, fires when *any* argument
		// (the query, the -e value, a positional SQL string) carries taint. The
		// regex Pattern is anchored on the query-execution flag (-e / -c / …)
		// followed by a $-expansion so the regex-fallback engine and the audit
		// harness only see the genuine inline-query form, not `mysql < dump.sql`.
		{
			ID:            "shell.sql.mysql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])(?:mysql|mariadb)\s+[^\n]*?--?(?:e|execute)\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "mysql/mariadb",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "mysql/mariadb CLI executing an inline query (-e/--execute) built from a shell variable — tainted input yields SQL injection",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.sql.psql",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])psql\s+[^\n]*?--?(?:c|command)\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "psql",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "psql CLI executing an inline command (-c/--command) built from a shell variable — tainted input yields SQL injection",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.sql.sqlite3",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])sqlite3\s+\S+\s+["'][^"]*\$`,
			ObjectType:    "",
			MethodName:    "sqlite3",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "sqlite3 CLI running a positional SQL statement built from a shell variable — tainted input yields SQL injection",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.sql.cqlsh",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])cqlsh\s+[^\n]*?--?(?:e|execute)\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "cqlsh",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "cqlsh (Cassandra) executing an inline CQL statement (-e/--execute) built from a shell variable — tainted input yields CQL injection",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.sql.clickhouse",
			Category:      taint.SnkSQLQuery,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])clickhouse-client\s+[^\n]*?--?(?:q|query)\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "clickhouse-client",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "clickhouse-client executing an inline query (--query/-q) built from a shell variable — tainted input yields SQL injection",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- NoSQL Injection via CLI datastore clients (CWE-943) ---
		// mongosh/mongo --eval runs a JavaScript snippet against the database and
		// redis-cli builds a Redis command line; interpolating a shell variable
		// into either lets an attacker inject query/command operators. tsflow
		// matches the command word and fires on any tainted argument; the regex
		// Pattern is anchored on --eval (mongo) / a $-expansion (redis-cli).
		{
			ID:            "shell.nosql.mongo",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])(?:mongosh|mongo)\s+[^\n]*?--eval\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "mongosh/mongo",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "mongosh/mongo --eval running a JavaScript snippet built from a shell variable — tainted input yields NoSQL/JavaScript injection",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.nosql.redis_cli",
			Category:      taint.SnkNoSQL,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])redis-cli\s+(?:-[^\s]+\s+)*[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "redis-cli",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "redis-cli building a Redis command (e.g. EVAL/SET) from a shell variable — tainted input yields command/Lua-script injection into the datastore",
			CWEID:         "CWE-943",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- Code Injection via interpreter inline-eval flags (CWE-94) ---
		// A scripting interpreter invoked with its "run this string as code" flag
		// (python -c, perl -e/-E, ruby -e, node -e/--eval, php -r) treats its
		// argument as a program in that language. Interpolating a shell variable
		// into that argument is arbitrary code execution in the interpreter —
		// distinct from `sh -c` (SnkCommand) because the injected payload is
		// Python/Perl/Ruby/JS/PHP, not shell. tsflow matches the command word and
		// fires on any tainted argument; the regex Pattern is anchored on the
		// specific eval flag plus a $-expansion to keep the Layer-1 fallback tight.
		{
			ID:            "shell.code.python_c",
			Category:      taint.SnkEval,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])python[0-9.]*\s+(?:-[^\s]+\s+)*-c\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "python/python2/python3",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "python -c runs its argument as a Python program — a shell variable interpolated into the -c string yields arbitrary Python code execution",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.code.perl_e",
			Category:      taint.SnkEval,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])perl\s+(?:-[^\s]+\s+)*-[eE]\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "perl",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "perl -e/-E runs its argument as a Perl program — a shell variable interpolated into the -e string yields arbitrary Perl code execution",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.code.ruby_e",
			Category:      taint.SnkEval,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])ruby\s+(?:-[^\s]+\s+)*-e\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "ruby",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "ruby -e runs its argument as a Ruby program — a shell variable interpolated into the -e string yields arbitrary Ruby code execution",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.code.node_eval",
			Category:      taint.SnkEval,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])node(?:js)?\s+(?:-[^\s]+\s+)*(?:-e|--eval)\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "node/nodejs",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "node -e/--eval runs its argument as JavaScript — a shell variable interpolated into the eval string yields arbitrary Node.js code execution",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
		{
			ID:            "shell.code.php_r",
			Category:      taint.SnkEval,
			Language:      rules.LangShell,
			Pattern:       `(?:^|[^\w.-])php\s+(?:-[^\s]+\s+)*-r\b[^\n]*\$`,
			ObjectType:    "",
			MethodName:    "php",
			DangerousArgs: []int{-1},
			Severity:      rules.Critical,
			Description:   "php -r runs its argument as PHP code — a shell variable interpolated into the -r string yields arbitrary PHP code execution",
			CWEID:         "CWE-94",
			OWASPCategory: "A03:2021-Injection",
		},
	}
}
