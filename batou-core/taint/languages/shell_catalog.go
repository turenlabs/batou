package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ShellCatalog provides taint-tracking definitions for the Shell/Bash language.
//
// Matching model note: the tsflow engine (which the scanner routes Shell to via
// the bash tree-sitter grammar) matches sources/sinks/sanitizers by the *command
// name* returned from the `command_name` node (e.g. "eval", "curl", "sh", "cp"),
// not by the regex Pattern. Pattern is honoured by the regex fallback engine and
// is what the audit harness verifies. Both are populated here: MethodName carries
// the bare bash command word (ObjectType "" so a receiver-less command matches),
// and Pattern is a verified RE2 regex that matches the vulnerable raw source line.
type ShellCatalog struct{}

func init() {
	taint.RegisterCatalog(&ShellCatalog{})
}

func (c *ShellCatalog) Language() rules.Language {
	return rules.LangShell
}
