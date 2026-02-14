package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// cppCatalog implements LanguageCatalog for C++.
type cppCatalog struct{}

func (cppCatalog) Language() rules.Language { return rules.LangCPP }

func init() {
	taint.RegisterCatalog(cppCatalog{})
}
