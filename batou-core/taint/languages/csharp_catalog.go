package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// CSharpCatalog provides taint-tracking definitions for the C# language.
type CSharpCatalog struct{}

func init() {
	taint.RegisterCatalog(&CSharpCatalog{})
}

func (c *CSharpCatalog) Language() rules.Language {
	return rules.LangCSharp
}
