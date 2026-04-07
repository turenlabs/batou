package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// perlCatalog implements LanguageCatalog for Perl.
type perlCatalog struct{}

func (perlCatalog) Language() rules.Language { return rules.LangPerl }

func init() {
	taint.RegisterCatalog(perlCatalog{})
}
