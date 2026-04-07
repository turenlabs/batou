package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// cppCatalog implements LanguageCatalog for C++.
type cppCatalog struct{}

func (cppCatalog) Language() rules.Language { return rules.LangCPP }

func init() {
	taint.RegisterCatalog(cppCatalog{})
}
