package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// rubyCatalog implements LanguageCatalog for Ruby.
type rubyCatalog struct{}

func (rubyCatalog) Language() rules.Language { return rules.LangRuby }

func init() {
	taint.RegisterCatalog(rubyCatalog{})
}
