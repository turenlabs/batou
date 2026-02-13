package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// SwiftCatalog provides taint-tracking definitions for the Swift language.
type SwiftCatalog struct{}

func init() {
	taint.RegisterCatalog(&SwiftCatalog{})
}

func (c *SwiftCatalog) Language() rules.Language {
	return rules.LangSwift
}
