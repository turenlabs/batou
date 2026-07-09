package graph

import (
	"go/ast"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/astflow"
	"github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// goExtractor is the reference TypeExtractor implementation. It is a thin
// adapter over the existing Go-specific machinery in this package
// (GoTypeInfo, buildGoTypeInfo, TypeEnv, languages.LookupGoSourceType) so
// Go behavior is preserved byte-for-byte. Per-language extractors added
// by the loop mirror this structure but walk tree-sitter trees instead of
// Go's native AST.
type goExtractor struct{}

func (goExtractor) Language() rules.Language { return rules.LangGo }

// ExtractFunctions walks every top-level FuncDecl in ctx.GoFile and returns
// a FuncSignature per declaration with Params/Returns populated from the
// Go type environment. Mirrors the core of populateTypedParams (see
// interprocedural.go:1345) but emits one signature per function rather
// than mutating a single TaintSignature.
func (goExtractor) ExtractFunctions(ctx *ExtractContext) []FuncSignature {
	if ctx == nil {
		return nil
	}
	parsed := ctx.goParseResult()
	if parsed == nil || parsed.File == nil {
		return nil
	}
	info := buildGoTypeInfo(parsed.File)
	if info == nil || info.FuncDecls == nil {
		return nil
	}

	sigs := make([]FuncSignature, 0, len(info.FuncDecls))
	for name, fn := range info.FuncDecls {
		if fn == nil || fn.Type == nil {
			continue
		}
		sig := FuncSignature{Name: name}
		if parsed.Fset != nil {
			if pos := parsed.Fset.Position(fn.Pos()); pos.IsValid() {
				sig.StartLine = pos.Line
			}
			if pos := parsed.Fset.Position(fn.End()); pos.IsValid() {
				sig.EndLine = pos.Line
			}
		}
		sig.Params = goExtractParamsFromType(fn.Type, info.TypeEnv)
		sig.Returns = goExtractReturnsFromType(fn.Type, info.TypeEnv)
		sigs = append(sigs, sig)
	}
	return sigs
}

// ResolveVarType returns the canonical type of varName in the file
// represented by ctx. The line argument is accepted for interface
// compatibility with per-language extractors that scope lookups by line;
// the Go TypeEnv is file-scoped so the line is not consulted here.
func (goExtractor) ResolveVarType(ctx *ExtractContext, varName string, line int) string {
	if ctx == nil {
		return ""
	}
	parsed := ctx.goParseResult()
	if parsed == nil || parsed.File == nil {
		if ctx.Content != nil {
			parsed = astflow.ParseGo(string(ctx.Content), ctx.FilePath)
		}
		if parsed == nil || parsed.File == nil {
			return ""
		}
	}
	env := astflow.BuildTypeEnv(parsed.File)
	if env == nil {
		return ""
	}
	raw := env.VarType(varName)
	if raw == "" {
		return ""
	}
	return env.CanonicalizeType(raw)
}

// goParseResult safely unpacks ctx.GoFile into *astflow.GoParseResult.
func (c *ExtractContext) goParseResult() *astflow.GoParseResult {
	if c == nil {
		return nil
	}
	r, _ := c.GoFile.(*astflow.GoParseResult)
	return r
}

// goExtractParamsFromType builds typed ParamTaint metadata from an
// *ast.FuncType — shared between top-level FuncDecls and closure literals
// (FuncLit), which carry the same *ast.FuncType but no Name/Recv. The
// shape mirrors the Params-building loop in populateTypedParams
// (interprocedural.go); the loop-produced per-language extractors emit
// one ParamTaint per positional parameter, with canonical types resolved
// through the language's TypeEnv and source/sink categories looked up
// from the language-specific catalog.
func goExtractParamsFromType(ft *ast.FuncType, env *astflow.TypeEnv) []ParamTaint {
	if ft == nil || ft.Params == nil {
		return nil
	}
	var params []ParamTaint
	idx := 0
	for _, field := range ft.Params.List {
		rawType := astflow.ExprToTypeString(field.Type)
		var canonical string
		if env != nil {
			canonical = env.CanonicalizeType(rawType)
		} else {
			canonical = rawType
		}
		names := fieldNames(field)
		if len(names) == 0 {
			names = []string{""}
		}
		for _, name := range names {
			pt := ParamTaint{
				Index:         idx,
				Name:          name,
				Type:          rawType,
				CanonicalType: canonical,
			}
			if cat, ok := languages.LookupGoSourceType(canonical); ok {
				pt.IsSourceType = true
				pt.SourceCategory = cat
			}
			if info, ok := languages.LookupGoSinkType(canonical); ok {
				pt.IsSinkType = true
				pt.SinkCategory = info.Category
			}
			params = append(params, pt)
			idx++
		}
	}
	return params
}

// goExtractReturnsFromType builds typed ReturnTaint metadata from an
// *ast.FuncType — shared between FuncDecl and FuncLit handling so
// closure nodes get the same typed-return metadata as top-level funcs.
// Mirrors the Returns-building loop in populateTypedParams
// (interprocedural.go).
func goExtractReturnsFromType(ft *ast.FuncType, env *astflow.TypeEnv) []ReturnTaint {
	if ft == nil || ft.Results == nil {
		return nil
	}
	var returns []ReturnTaint
	idx := 0
	for _, field := range ft.Results.List {
		rawType := astflow.ExprToTypeString(field.Type)
		var canonical string
		if env != nil {
			canonical = env.CanonicalizeType(rawType)
		} else {
			canonical = rawType
		}
		names := fieldNames(field)
		if len(names) == 0 {
			names = []string{""}
		}
		for _, name := range names {
			rt := ReturnTaint{
				Index:         idx,
				Name:          name,
				Type:          rawType,
				CanonicalType: canonical,
			}
			if cat, ok := languages.LookupGoSourceType(canonical); ok {
				rt.IsSourceType = true
				rt.SourceCategory = cat
			}
			returns = append(returns, rt)
			idx++
		}
	}
	return returns
}

// goTypeCatalog is the Go-language TypeCatalog derived from the same
// taint/languages catalog that drives LookupGoSourceType / LookupGoSinkType.
// It is exposed here so per-language TypeCatalogs (populated by the loop)
// can be tested against a concrete reference.
// Keys use the canonical form produced by astflow.TypeEnv.CanonicalizeType:
// short package names (not import paths), with the leading `*` preserved
// for pointer types. See typed_summary_test.go for the authoritative
// examples ("*http.Request", "*sql.DB", "echo.Context").
var goTypeCatalog = &TypeCatalog{
	// http.ResponseWriter is intentionally absent — it's the outbound side
	// of an HTTP handler, not a taint source. See the matching comment on
	// interprocedural.go: sourceParamPatterns.
	SourceParam: map[string]taint.SourceCategory{
		"*http.Request":       taint.SrcUserInput,
		"*gin.Context":        taint.SrcUserInput,
		"echo.Context":        taint.SrcUserInput,
		"*echo.Context":       taint.SrcUserInput,
		"*fiber.Ctx":          taint.SrcUserInput,
		"*sql.Row":            taint.SrcDatabase,
		"*sql.Rows":           taint.SrcDatabase,
		"*gorm.DB":            taint.SrcDatabase,
		"io.Reader":           taint.SrcNetwork,
		"io.ReadCloser":       taint.SrcNetwork,
		"net.Conn":            taint.SrcNetwork,
	},
}

// GoTypeCatalog returns the Go reference TypeCatalog. Exposed for tests
// and as the canonical example per-language catalogs can compare against.
func GoTypeCatalog() *TypeCatalog { return goTypeCatalog }

func init() {
	RegisterExtractor(goExtractor{})
}
