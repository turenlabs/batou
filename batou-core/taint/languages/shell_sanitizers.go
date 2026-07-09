package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *ShellCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- printf %q safe-quoting (the canonical shell escaper) ---
		// `printf %q` (or `printf -v out %q`) emits a string that is safely
		// reusable as shell input — the standard defence for command-injection
		// sinks. Uses @argpattern so plain `printf '%s'` doesn't qualify.
		{
			ID:          "shell.printf_q",
			Language:    rules.LangShell,
			Pattern:     `printf\s+(?:-v\s+\w+\s+)?["']?%q`,
			ObjectType:  "@argpattern",
			MethodName:  "printf",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkEval},
			Description: "printf %q safely quotes a string for reuse as shell input (neutralizes command/eval injection)",
		},

		// NOTE: realpath(1) and readlink -f are intentionally NOT registered
		// as standalone CWE-22 sanitizers (mirrors the filepath.Clean note in
		// go_sanitizers.go and the os.path.normpath/realpath note in
		// python_sanitizers.go). Canonicalization alone does not reject
		// escapes: `realpath ../../etc/passwd` prints "/etc/passwd" — a real
		// path OUTSIDE the safe base. A complete defence is canonicalize +
		// containment (e.g. `case "$(realpath -- "$p")" in "$base"/*) ... `);
		// the canonicalize step by itself must not kill the taint flow.

		// --- basename: strips directory components (path-traversal defence) ---
		// tsflow: command name "basename" matches via MethodName.

		// --- ${var//pattern/} character stripping (allowlist scrub) ---
		// Parameter-expansion substitution that strips dangerous characters
		// before the value reaches a command/eval sink. Regex-engine only
		// (parameter expansion is not a call node); @argpattern keeps it gated.
		{
			ID:          "shell.param_strip",
			Language:    rules.LangShell,
			Pattern:     `\$\{[A-Za-z_][A-Za-z0-9_]*//`,
			ObjectType:  "@argpattern",
			MethodName:  "param_substitution",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkEval, taint.SnkFileWrite},
			Description: "${var//pattern/} parameter-expansion substitution strips/replaces dangerous characters (allowlist scrub)",
		},

		// --- jq --arg / --argjson parameterized value binding (jq-injection defence) ---
		// `jq --arg name "$x" '... $name ...'` binds the untrusted value to a jq
		// variable as *data* — it is never parsed as filter code, so it cannot
		// alter the program (the shell analogue of a prepared statement). This is
		// jq's own recommended way to interpolate external values and neutralizes
		// the jq filter-injection sink. @argpattern gates on the `--arg`/
		// `--argjson` flag so a plain `jq '...'` call does not qualify.
		{
			ID:          "shell.jq_arg",
			Language:    rules.LangShell,
			Pattern:     `(?:^|[^\w.-])jq\s+(?:-[^\s]+\s+)*--arg(?:json)?\s`,
			ObjectType:  "@argpattern",
			MethodName:  "jq",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "jq --arg/--argjson binds an untrusted value as data (never parsed as filter code) — neutralizes jq filter injection (prepared-statement analogue)",
		},

		// --- =~ anchored numeric/alnum allowlist regex test ---
		// `[[ $x =~ ^[0-9]+$ ]]` is the idiomatic validation guard that
		// restricts a variable to a safe character class before use.
		{
			ID:          "shell.regex_allowlist",
			Language:    rules.LangShell,
			Pattern:     `=~\s*\^[^$]`,
			ObjectType:  "@argpattern",
			MethodName:  "regex_match_test",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkEval, taint.SnkFileWrite},
			Description: "[[ $x =~ ^... ]] anchored allowlist regex test validates a variable against a safe character class",
		},

		// --- tr -cd / -dc complement-delete allowlist scrub ---
		// `tr -cd '[:alnum:]'` (or -dc) deletes every character OUTSIDE the
		// allowlisted set, stripping shell metacharacters, whitespace, and
		// path-traversal punctuation. tsflow: command name "tr" would match any
		// `tr` call, so @argpattern gates on a flag cluster containing BOTH the
		// complement (c) and delete (d) flags — `tr 'A-Z' 'a-z'` (translate) and
		// bare `tr -d` (blocklist) are deliberately excluded.
		{
			ID:          "shell.tr_allowlist",
			Language:    rules.LangShell,
			Pattern:     `\btr\s+-[A-Za-z]*c[A-Za-z]*d[A-Za-z]*\b|\btr\s+-[A-Za-z]*d[A-Za-z]*c[A-Za-z]*\b`,
			ObjectType:  "@argpattern",
			MethodName:  "tr",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkEval, taint.SnkFileWrite},
			Description: "tr -cd/-dc deletes all characters outside an allowlisted set (e.g. tr -cd '[:alnum:]') — strips shell metacharacters and path-traversal chars",
		},

		// --- printf %d / %i numeric coercion ---
		// `printf '%d' "$x"` forces an integer conversion: any shell
		// metacharacters or injection payload collapse to a number (non-numeric
		// input yields 0 plus a stderr format error), so the result is safe to
		// splice into a command or eval. tsflow: command name "printf" matches
		// any printf, so @argpattern gates on a `%d`/`%i` conversion (the
		// existing shell.printf_q entry gates on `%q` for string quoting).
		{
			ID:          "shell.printf_d",
			Language:    rules.LangShell,
			Pattern:     `printf\s+(?:-v\s+\w+\s+)?["']?%[0-9.*+ -]*[di]`,
			ObjectType:  "@argpattern",
			MethodName:  "printf",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkEval, taint.SnkFileWrite},
			Description: "printf %d/%i coerces a value to an integer — collapses injection payloads to a number (command/eval/path injection mitigation)",
		},

		// --- sed 's/[^allowlist]//g' complement-delete allowlist scrub ---
		// `sed 's/[^[:alnum:]]//g'` (or any `s/[^...]//` substitution with an
		// empty replacement) deletes every character OUTSIDE the allowlisted
		// class — the `sed` analogue of the existing `tr -cd` scrub — stripping
		// shell metacharacters, whitespace, and path-traversal punctuation
		// before the value reaches a command/eval/file sink. tsflow: command
		// name "sed" would match any `sed` call, so @argpattern gates on a
		// complement substitution (`s/[^...]//`); a plain `sed 's/foo/bar/'`
		// translation or a `sed 's/[^x]/Y/'` non-empty replacement is excluded.
		{
			ID:          "shell.sed_allowlist",
			Language:    rules.LangShell,
			Pattern:     `\bsed\b\s+(?:-[A-Za-z]+\s+|--[A-Za-z-]+\s+)*["']?s/\[\^[^/]*//`,
			ObjectType:  "@argpattern",
			MethodName:  "sed",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand, taint.SnkEval, taint.SnkFileWrite},
			Description: "sed 's/[^allowlist]//g' deletes all characters outside an allowlisted set (complement-delete scrub) — strips shell metacharacters and path-traversal chars (tr -cd analogue)",
		},
	}
}
