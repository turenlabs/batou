package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// CCatalog provides taint-tracking definitions for the C language.
type CCatalog struct{}

func init() {
	taint.RegisterCatalog(&CCatalog{})
}

func (c *CCatalog) Language() rules.Language {
	return rules.LangC
}
