package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *ShellCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- Positional parameters / CLI arguments ($1, $2, $@, $*, $#) ---
		// These are the canonical untrusted entry point for a shell script.
		// Matched by the regex engine; the tsflow engine sees them as
		// simple_expansion nodes (no command name), so they primarily anchor
		// regex-fallback flows and second-order proximity.
		{
			ID:          "shell.arg.positional",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangShell,
			Pattern:     `\$(?:[1-9][0-9]*|@|\*|#)`,
			ObjectType:  "",
			MethodName:  "positional_param",
			Description: "Shell positional parameter / argument ($1, $2, $@, $*)",
			Assigns:     "return",
		},
		{
			ID:          "shell.arg.positional_braced",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangShell,
			Pattern:     `\$\{(?:[1-9][0-9]*|@|\*)`,
			ObjectType:  "",
			MethodName:  "positional_param_braced",
			Description: "Shell braced positional parameter (${1}, ${2}, ${@})",
			Assigns:     "return",
		},

		// --- `read` builtin (interactive / piped stdin into $REPLY or named var) ---
		// tsflow: command name "read" matches via MethodName.
		{
			ID:          "shell.read.builtin",
			Category:    taint.SrcUserInput,
			Language:    rules.LangShell,
			Pattern:     `(?:^|[^\w.-])read\s+(?:-[a-zA-Z]+\s+)*`,
			ObjectType:  "",
			MethodName:  "read",
			Description: "Shell read builtin captures untrusted stdin into a variable",
			Assigns:     "return",
		},
		{
			ID:          "shell.read.reply",
			Category:    taint.SrcUserInput,
			Language:    rules.LangShell,
			Pattern:     `\$REPLY\b`,
			ObjectType:  "",
			MethodName:  "REPLY",
			Description: "Default $REPLY variable populated by `read` (untrusted stdin)",
			Assigns:     "return",
		},

		// --- CGI / web-server environment variables (attacker-controlled) ---
		// QUERY_STRING, HTTP_* headers, REQUEST_*, REMOTE_* are set from the
		// HTTP request in CGI scripts and are fully attacker-controlled.
		{
			ID:          "shell.env.cgi",
			Category:    taint.SrcUserInput,
			Language:    rules.LangShell,
			Pattern:     `\$\{?(?:QUERY_STRING|HTTP_[A-Z_]+|REQUEST_[A-Z]+|REMOTE_[A-Z]+|CONTENT_[A-Z]+|PATH_INFO)\b`,
			ObjectType:  "",
			MethodName:  "cgi_env",
			Description: "CGI request environment variable (QUERY_STRING, HTTP_*, REQUEST_*, REMOTE_*) — attacker-controlled",
			Assigns:     "return",
		},

		// --- jq output parsed from an untrusted JSON document (external data) ---
		// `var=$(jq -r '.field' untrusted.json)` extracts a value from a JSON
		// document the script did not produce (an API response, an uploaded
		// file, a webhook body). That value is attacker-influenced and routinely
		// flows into a command/eval/file sink without further validation. jq's
		// own filter is static here; the *taint* is the extracted JSON value.
		// tsflow: command name "jq" matches via MethodName so the assigned
		// variable is seeded. Scoped to the `jq` command word (ObjectType "").
		{
			ID:          "shell.json.jq_output",
			Category:    taint.SrcExternal,
			Language:    rules.LangShell,
			Pattern:     `(?:^|[^\w.-])jq\s`,
			ObjectType:  "",
			MethodName:  "jq",
			Description: "jq output: a value extracted from an untrusted JSON document (API response / uploaded file / webhook) — attacker-influenced external data",
			Assigns:     "return",
		},

		// --- curl/wget output captured into a variable (untrusted network data) ---
		// tsflow: command name "curl"/"wget" matches via MethodName.
		{
			ID:          "shell.net.curl",
			Category:    taint.SrcNetwork,
			Language:    rules.LangShell,
			Pattern:     `(?:^|[^\w.-])curl\s`,
			ObjectType:  "",
			MethodName:  "curl",
			Description: "curl output captured from a remote endpoint (untrusted network data)",
			Assigns:     "return",
		},
		{
			ID:          "shell.net.wget_stdout",
			Category:    taint.SrcNetwork,
			Language:    rules.LangShell,
			Pattern:     `(?:^|[^\w.-])wget\s+(?:-[^\s]+\s+)*-O\s*-`,
			ObjectType:  "",
			MethodName:  "wget",
			Description: "wget -O - streams a remote response to stdout (untrusted network data)",
			Assigns:     "return",
		},
	}
}
