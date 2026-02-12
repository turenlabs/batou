package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// CSharpCatalog provides taint-tracking definitions for the C# language.
type CSharpCatalog struct{}

func init() {
	taint.RegisterCatalog(&CSharpCatalog{})
}

func (c *CSharpCatalog) Language() rules.Language {
	return rules.LangCSharp
}
