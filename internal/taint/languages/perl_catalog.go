package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// perlCatalog implements LanguageCatalog for Perl.
type perlCatalog struct{}

func (perlCatalog) Language() rules.Language { return rules.LangPerl }

func init() {
	taint.RegisterCatalog(perlCatalog{})
}
