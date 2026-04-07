package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// PythonCatalog provides taint-tracking definitions for the Python language.
type PythonCatalog struct{}

func init() {
	taint.RegisterCatalog(&PythonCatalog{})
}

func (c *PythonCatalog) Language() rules.Language {
	return rules.LangPython
}
