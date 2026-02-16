package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// javaCatalog implements LanguageCatalog for Java.
type javaCatalog struct{}

func (javaCatalog) Language() rules.Language { return rules.LangJava }

func init() {
	taint.RegisterCatalog(javaCatalog{})
}
