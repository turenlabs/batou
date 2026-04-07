package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// LuaCatalog provides taint-tracking definitions for the Lua language.
type LuaCatalog struct{}

func init() {
	taint.RegisterCatalog(&LuaCatalog{})
}

func (c *LuaCatalog) Language() rules.Language {
	return rules.LangLua
}
