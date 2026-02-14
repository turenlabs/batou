package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// CCatalog provides taint-tracking definitions for the C language.
type CCatalog struct{}

func init() {
	taint.RegisterCatalog(&CCatalog{})
}

func (c *CCatalog) Language() rules.Language {
	return rules.LangC
}
