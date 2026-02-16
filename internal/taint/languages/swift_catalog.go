package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// SwiftCatalog provides taint-tracking definitions for the Swift language.
type SwiftCatalog struct{}

func init() {
	taint.RegisterCatalog(&SwiftCatalog{})
}

func (c *SwiftCatalog) Language() rules.Language {
	return rules.LangSwift
}
