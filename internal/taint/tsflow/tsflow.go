// Package tsflow implements tree-sitter-based taint analysis for non-Go languages.
//
// It uses the tree-sitter AST (via internal/ast) with language-specific
// configuration tables to track taint flow through assignments, calls,
// and attribute accesses. This provides more accurate tracking than the
// regex-based engine for reassignment, aliasing, and complex expressions.
//
// Supported languages: Python, JavaScript, TypeScript, Java, PHP, Ruby,
// C, C++, C#, Kotlin, Rust, Swift, Lua, Groovy, Perl.
// Go uses its own go/ast-based analyzer in internal/taint/astflow.
package tsflow

import (
	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// Supports returns true if tsflow has a configuration for the given language.
func Supports(lang rules.Language) bool {
	return getConfig(lang) != nil
}

// Analyze runs tree-sitter-based taint analysis on source code.
// Returns nil if the language is unsupported, unparseable, or has no catalog.
func Analyze(content string, filePath string, lang rules.Language) []taint.TaintFlow {
	cfg := getConfig(lang)
	if cfg == nil {
		return nil
	}

	tree := ast.Parse([]byte(content), lang)
	if tree == nil {
		return nil
	}

	cat := taint.GetCatalog(lang)
	if cat == nil {
		return nil
	}

	sources := cat.Sources()
	sinks := cat.Sinks()
	sanitizers := cat.Sanitizers()

	matcher := newTSMatcher(sources, sinks, sanitizers, cfg)

	return walkTree(tree, cfg, matcher, filePath)
}
