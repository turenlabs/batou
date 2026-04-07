package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// KotlinCatalog provides taint-tracking definitions for the Kotlin language.
type KotlinCatalog struct{}

func init() {
	taint.RegisterCatalog(&KotlinCatalog{})
}

func (c *KotlinCatalog) Language() rules.Language {
	return rules.LangKotlin
}
