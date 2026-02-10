package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// cppCatalog implements LanguageCatalog for C++.
type cppCatalog struct{}

func (cppCatalog) Language() rules.Language { return rules.LangCPP }

func init() {
	taint.RegisterCatalog(cppCatalog{})
}
