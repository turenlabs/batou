// Package astflow implements AST-driven taint analysis for Go source code
// using go/ast and the catalog system from internal/taint.
//
// Unlike the regex-based engine, astflow parses Go code into a full AST and
// matches sources/sinks/sanitizers by inspecting *ast.CallExpr nodes against
// catalog entries indexed by method name. This catches taint propagation
// through reassignment, aliasing, and complex expressions that regex cannot.
//
// The package returns []taint.TaintFlow for seamless integration with the
// existing scanner and hint generation pipeline.
package astflow

import (
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

// GoParseResult holds a parsed Go file and its FileSet so that multiple
// layers (taint analysis, call graph builder) can share the same parse.
type GoParseResult struct {
	Fset *token.FileSet
	File *ast.File
}

// ParseGo parses Go source code and returns the result. Returns nil on error.
func ParseGo(content string, filePath string) *GoParseResult {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, content, parser.ParseComments|parser.AllErrors)
	if err != nil || file == nil {
		return nil
	}
	return &GoParseResult{Fset: fset, File: file}
}

// AnalyzeGo runs AST-driven taint analysis on Go source code.
// It parses the file, builds a type environment and catalog matcher,
// then walks each function body tracking taint flows.
func AnalyzeGo(content string, filePath string) []taint.TaintFlow {
	return AnalyzeGoWithAST(content, filePath, nil)
}

// AnalyzeGoWithAST is like AnalyzeGo but accepts a pre-parsed Go AST to
// avoid redundant parsing. If parsed is nil, it falls back to parsing.
func AnalyzeGoWithAST(content string, filePath string, parsed *GoParseResult) []taint.TaintFlow {
	cat := taint.GetCatalog(rules.LangGo)
	if cat == nil {
		return nil
	}

	if parsed == nil {
		parsed = ParseGo(content, filePath)
		if parsed == nil {
			return nil
		}
	}

	fset := parsed.Fset
	file := parsed.File

	sources := cat.Sources()
	sinks := cat.Sinks()
	sanitizers := cat.Sanitizers()

	// Build type environment from the parsed file.
	typeEnv := BuildTypeEnv(file)

	// Build catalog matcher with O(1) method name lookup.
	matcher := NewCatalogMatcher(sources, sinks, sanitizers, typeEnv)

	var allFlows []taint.TaintFlow

	// Walk every function declaration and function literal.
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body == nil {
				return true
			}
			scopeName := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				scopeName = receiverTypeName(fn.Recv.List[0].Type) + "." + scopeName
			}
			flows := walkFunc(fset, fn.Type, fn.Body, scopeName, filePath, matcher)
			allFlows = append(allFlows, flows...)

		case *ast.FuncLit:
			if fn.Body == nil {
				return true
			}
			flows := walkFunc(fset, fn.Type, fn.Body, "__closure__", filePath, matcher)
			allFlows = append(allFlows, flows...)
		}
		return true
	})

	return allFlows
}

// receiverTypeName extracts a readable type name from a receiver type expression.
func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return "*" + receiverTypeName(e.X)
	case *ast.SelectorExpr:
		return selectorString(e)
	}
	return ""
}
