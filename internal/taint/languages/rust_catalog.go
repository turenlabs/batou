package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// RustCatalog provides taint-tracking definitions for the Rust language.
type RustCatalog struct{}

func init() {
	taint.RegisterCatalog(&RustCatalog{})
}

func (c *RustCatalog) Language() rules.Language {
	return rules.LangRust
}
