package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// phpCatalog implements LanguageCatalog for PHP.
type phpCatalog struct{}

func (phpCatalog) Language() rules.Language { return rules.LangPHP }

func init() {
	taint.RegisterCatalog(phpCatalog{})
}
