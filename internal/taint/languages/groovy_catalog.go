package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// GroovyCatalog provides taint-tracking definitions for the Groovy language.
type GroovyCatalog struct{}

func init() {
	taint.RegisterCatalog(&GroovyCatalog{})
}

func (c *GroovyCatalog) Language() rules.Language {
	return rules.LangGroovy
}
