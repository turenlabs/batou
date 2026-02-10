package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// PythonCatalog provides taint-tracking definitions for the Python language.
type PythonCatalog struct{}

func init() {
	taint.RegisterCatalog(&PythonCatalog{})
}

func (c *PythonCatalog) Language() rules.Language {
	return rules.LangPython
}
