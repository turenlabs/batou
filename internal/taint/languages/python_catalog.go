package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// PythonCatalog provides taint-tracking definitions for the Python language.
type PythonCatalog struct{}

func init() {
	taint.RegisterCatalog(&PythonCatalog{})
}

func (c *PythonCatalog) Language() rules.Language {
	return rules.LangPython
}
