package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// phpCatalog implements LanguageCatalog for PHP.
type phpCatalog struct{}

func (phpCatalog) Language() rules.Language { return rules.LangPHP }

func init() {
	taint.RegisterCatalog(phpCatalog{})
}
