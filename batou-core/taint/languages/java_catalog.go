package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// javaCatalog implements LanguageCatalog for Java.
type javaCatalog struct{}

func (javaCatalog) Language() rules.Language { return rules.LangJava }

func init() {
	taint.RegisterCatalog(javaCatalog{})
}
