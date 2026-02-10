package taint

import (
	"sync"

	"github.com/turen/gtss/internal/rules"
)

// CatalogRegistry holds all registered language catalogs.
var (
	catalogs   = make(map[rules.Language]LanguageCatalog)
	catalogsMu sync.RWMutex
)

// RegisterCatalog adds a language catalog to the global registry.
func RegisterCatalog(cat LanguageCatalog) {
	catalogsMu.Lock()
	defer catalogsMu.Unlock()
	catalogs[cat.Language()] = cat
}

// GetCatalog returns the catalog for a given language, or nil if none exists.
func GetCatalog(lang rules.Language) LanguageCatalog {
	catalogsMu.RLock()
	defer catalogsMu.RUnlock()
	return catalogs[lang]
}

// AllCatalogs returns all registered catalogs.
func AllCatalogs() []LanguageCatalog {
	catalogsMu.RLock()
	defer catalogsMu.RUnlock()
	out := make([]LanguageCatalog, 0, len(catalogs))
	for _, c := range catalogs {
		out = append(out, c)
	}
	return out
}

// SourcesForLanguage returns all source definitions for a language.
func SourcesForLanguage(lang rules.Language) []SourceDef {
	cat := GetCatalog(lang)
	if cat == nil {
		return nil
	}
	return cat.Sources()
}

// SinksForLanguage returns all sink definitions for a language.
func SinksForLanguage(lang rules.Language) []SinkDef {
	cat := GetCatalog(lang)
	if cat == nil {
		return nil
	}
	return cat.Sinks()
}

// SanitizersForLanguage returns all sanitizer definitions for a language.
func SanitizersForLanguage(lang rules.Language) []SanitizerDef {
	cat := GetCatalog(lang)
	if cat == nil {
		return nil
	}
	return cat.Sanitizers()
}
