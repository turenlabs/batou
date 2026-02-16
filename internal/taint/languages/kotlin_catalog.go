package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// KotlinCatalog provides taint-tracking definitions for the Kotlin language.
type KotlinCatalog struct{}

func init() {
	taint.RegisterCatalog(&KotlinCatalog{})
}

func (c *KotlinCatalog) Language() rules.Language {
	return rules.LangKotlin
}
