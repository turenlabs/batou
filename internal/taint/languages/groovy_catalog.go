package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// GroovyCatalog provides taint-tracking definitions for the Groovy language.
type GroovyCatalog struct{}

func init() {
	taint.RegisterCatalog(&GroovyCatalog{})
}

func (c *GroovyCatalog) Language() rules.Language {
	return rules.LangGroovy
}
