package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// rubyCatalog implements LanguageCatalog for Ruby.
type rubyCatalog struct{}

func (rubyCatalog) Language() rules.Language { return rules.LangRuby }

func init() {
	taint.RegisterCatalog(rubyCatalog{})
}
