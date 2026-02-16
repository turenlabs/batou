package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// GoCatalog provides taint-tracking definitions for the Go language.
type GoCatalog struct{}

func init() {
	taint.RegisterCatalog(&GoCatalog{})
}

func (c *GoCatalog) Language() rules.Language {
	return rules.LangGo
}
