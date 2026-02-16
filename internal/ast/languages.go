package ast

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/bash"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/groovy"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/kotlin"
	"github.com/smacker/go-tree-sitter/lua"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/ruby"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/sql"
	"github.com/smacker/go-tree-sitter/swift"
	ts_typescript "github.com/smacker/go-tree-sitter/typescript/typescript"
	"github.com/smacker/go-tree-sitter/yaml"

	perlgrammar "github.com/turenlabs/batou/internal/ast/perl"
	"github.com/turenlabs/batou/internal/rules"
)

// langRegistry maps rules.Language constants to tree-sitter Language pointers.
// Languages without a tree-sitter grammar (e.g. Perl) are not present and
// will gracefully return nil from lookupLanguage.
var langRegistry = map[rules.Language]*sitter.Language{
	rules.LangGo:         golang.GetLanguage(),
	rules.LangPython:     python.GetLanguage(),
	rules.LangJavaScript: javascript.GetLanguage(),
	rules.LangTypeScript: ts_typescript.GetLanguage(),
	rules.LangJava:       java.GetLanguage(),
	rules.LangPHP:        php.GetLanguage(),
	rules.LangRuby:       ruby.GetLanguage(),
	rules.LangC:          c.GetLanguage(),
	rules.LangCPP:        cpp.GetLanguage(),
	rules.LangCSharp:     csharp.GetLanguage(),
	rules.LangKotlin:     kotlin.GetLanguage(),
	rules.LangSwift:      swift.GetLanguage(),
	rules.LangRust:       rust.GetLanguage(),
	rules.LangLua:        lua.GetLanguage(),
	rules.LangGroovy:     groovy.GetLanguage(),
	rules.LangPerl:       perlgrammar.GetLanguage(),
	rules.LangShell:      bash.GetLanguage(),
	rules.LangSQL:        sql.GetLanguage(),
	rules.LangYAML:       yaml.GetLanguage(),
	// Docker/Terraform/JSON: not critical for security AST analysis.
}

// lookupLanguage returns the tree-sitter language for the given rules.Language,
// or nil if no grammar is registered.
func lookupLanguage(lang rules.Language) *sitter.Language {
	return langRegistry[lang]
}

// SupportsLanguage returns true if tree-sitter parsing is available for lang.
func SupportsLanguage(lang rules.Language) bool {
	return langRegistry[lang] != nil
}
