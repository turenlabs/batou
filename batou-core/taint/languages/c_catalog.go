package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// CCatalog provides taint-tracking definitions for the C language.
type CCatalog struct{}

func init() {
	taint.RegisterCatalog(&CCatalog{})
}

func (c *CCatalog) Language() rules.Language {
	return rules.LangC
}
