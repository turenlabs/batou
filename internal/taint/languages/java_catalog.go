package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// javaCatalog implements LanguageCatalog for Java.
type javaCatalog struct{}

func (javaCatalog) Language() rules.Language { return rules.LangJava }

func init() {
	taint.RegisterCatalog(javaCatalog{})
}
