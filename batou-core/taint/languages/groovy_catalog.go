package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// GroovyCatalog provides taint-tracking definitions for the Groovy language.
type GroovyCatalog struct{}

func init() {
	taint.RegisterCatalog(&GroovyCatalog{})
}

func (c *GroovyCatalog) Language() rules.Language {
	return rules.LangGroovy
}
