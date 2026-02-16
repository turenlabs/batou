package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

// LuaCatalog provides taint-tracking definitions for the Lua language.
type LuaCatalog struct{}

func init() {
	taint.RegisterCatalog(&LuaCatalog{})
}

func (c *LuaCatalog) Language() rules.Language {
	return rules.LangLua
}
