package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// rubyCatalog implements LanguageCatalog for Ruby.
type rubyCatalog struct{}

func (rubyCatalog) Language() rules.Language { return rules.LangRuby }

func init() {
	taint.RegisterCatalog(rubyCatalog{})
}
