package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// ZigCatalog provides taint-tracking definitions for the Zig language.
type ZigCatalog struct{}

func init() {
	taint.RegisterCatalog(&ZigCatalog{})
}

func (c *ZigCatalog) Language() rules.Language {
	return rules.LangZig
}
