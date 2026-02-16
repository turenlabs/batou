package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// PythonCatalog provides taint-tracking definitions for the Python language.
type PythonCatalog struct{}

func init() {
	taint.RegisterCatalog(&PythonCatalog{})
}

func (c *PythonCatalog) Language() rules.Language {
	return rules.LangPython
}
