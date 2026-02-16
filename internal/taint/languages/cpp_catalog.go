package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// cppCatalog implements LanguageCatalog for C++.
type cppCatalog struct{}

func (cppCatalog) Language() rules.Language { return rules.LangCPP }

func init() {
	taint.RegisterCatalog(cppCatalog{})
}
