package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// jsCatalog implements LanguageCatalog for JavaScript.
type jsCatalog struct{}

func (jsCatalog) Language() rules.Language { return rules.LangJavaScript }

func (jsCatalog) Sources() []taint.SourceDef {
	out := make([]taint.SourceDef, len(jsSources))
	copy(out, jsSources)
	for i := range out {
		out[i].Language = rules.LangJavaScript
	}
	return out
}

func (jsCatalog) Sinks() []taint.SinkDef {
	out := make([]taint.SinkDef, len(jsSinks))
	copy(out, jsSinks)
	for i := range out {
		out[i].Language = rules.LangJavaScript
	}
	return out
}

func (jsCatalog) Sanitizers() []taint.SanitizerDef {
	out := make([]taint.SanitizerDef, len(jsSanitizers))
	copy(out, jsSanitizers)
	for i := range out {
		out[i].Language = rules.LangJavaScript
	}
	return out
}

// tsCatalog implements LanguageCatalog for TypeScript (same definitions as JS).
type tsCatalog struct{}

func (tsCatalog) Language() rules.Language { return rules.LangTypeScript }

func (tsCatalog) Sources() []taint.SourceDef {
	out := make([]taint.SourceDef, len(jsSources))
	copy(out, jsSources)
	for i := range out {
		out[i].Language = rules.LangTypeScript
		out[i].ID = "ts." + out[i].ID[3:] // replace "js." prefix with "ts."
	}
	return out
}

func (tsCatalog) Sinks() []taint.SinkDef {
	out := make([]taint.SinkDef, len(jsSinks))
	copy(out, jsSinks)
	for i := range out {
		out[i].Language = rules.LangTypeScript
		out[i].ID = "ts." + out[i].ID[3:]
	}
	return out
}

func (tsCatalog) Sanitizers() []taint.SanitizerDef {
	out := make([]taint.SanitizerDef, len(jsSanitizers))
	copy(out, jsSanitizers)
	for i := range out {
		out[i].Language = rules.LangTypeScript
		out[i].ID = "ts." + out[i].ID[3:]
	}
	return out
}

func init() {
	taint.RegisterCatalog(jsCatalog{})
	taint.RegisterCatalog(tsCatalog{})
}
