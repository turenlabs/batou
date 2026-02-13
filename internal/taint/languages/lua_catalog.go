package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// LuaCatalog provides taint-tracking definitions for the Lua language.
type LuaCatalog struct{}

func init() {
	taint.RegisterCatalog(&LuaCatalog{})
}

func (c *LuaCatalog) Language() rules.Language {
	return rules.LangLua
}
