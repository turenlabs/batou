package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// RustCatalog provides taint-tracking definitions for the Rust language.
type RustCatalog struct{}

func init() {
	taint.RegisterCatalog(&RustCatalog{})
}

func (c *RustCatalog) Language() rules.Language {
	return rules.LangRust
}
