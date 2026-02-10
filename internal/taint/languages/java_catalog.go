package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// javaCatalog implements LanguageCatalog for Java.
type javaCatalog struct{}

func (javaCatalog) Language() rules.Language { return rules.LangJava }

func init() {
	taint.RegisterCatalog(javaCatalog{})
}
