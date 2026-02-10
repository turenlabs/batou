package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// CCatalog provides taint-tracking definitions for the C language.
type CCatalog struct{}

func init() {
	taint.RegisterCatalog(&CCatalog{})
}

func (c *CCatalog) Language() rules.Language {
	return rules.LangC
}
