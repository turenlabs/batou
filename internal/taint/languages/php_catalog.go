package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// phpCatalog implements LanguageCatalog for PHP.
type phpCatalog struct{}

func (phpCatalog) Language() rules.Language { return rules.LangPHP }

func init() {
	taint.RegisterCatalog(phpCatalog{})
}
