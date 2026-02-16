package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// rubyCatalog implements LanguageCatalog for Ruby.
type rubyCatalog struct{}

func (rubyCatalog) Language() rules.Language { return rules.LangRuby }

func init() {
	taint.RegisterCatalog(rubyCatalog{})
}
