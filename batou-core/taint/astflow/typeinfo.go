package astflow

import (
	"go/ast"
	"strings"
)

// TypeEnv provides lightweight type information extracted from a single Go file's AST.
// It resolves import aliases, function parameter types, and variable declaration types
// without requiring go/types or cross-file analysis.
type TypeEnv struct {
	// importAliases maps local alias -> full import path (e.g. "exec" -> "os/exec")
	importAliases map[string]string
	// varTypes maps variable name -> type string (e.g. "db" -> "*sql.DB")
	varTypes map[string]string
}

// stdlibFieldTypes maps base_type.field -> result_type for common stdlib types.
var stdlibFieldTypes = map[string]string{
	"*http.Request.URL":            "*url.URL",
	"*http.Request.Header":         "http.Header",
	"*http.Request.Body":           "io.ReadCloser",
	"*http.Request.Form":           "url.Values",
	"*http.Request.PostForm":       "url.Values",
	"*http.Request.MultipartForm":  "*multipart.Form",
	"*http.Request.TLS":            "*tls.ConnectionState",
	"*http.Request.Host":           "string",
	"*http.Request.RemoteAddr":     "string",
	"*http.Request.RequestURI":     "string",
	"*url.URL.Host":                "string",
	"*url.URL.Path":                "string",
	"*url.URL.RawQuery":            "string",
	"*url.URL.Fragment":            "string",
	"*url.URL.Scheme":              "string",
	"url.Values":                   "map[string][]string",
}

// BuildTypeEnv constructs a TypeEnv from a parsed Go file.
func BuildTypeEnv(file *ast.File) *TypeEnv {
	env := &TypeEnv{
		importAliases: make(map[string]string),
		varTypes:      make(map[string]string),
	}

	// Extract import aliases.
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// Default alias is the last component of the import path.
			parts := strings.Split(path, "/")
			alias = parts[len(parts)-1]
		}
		if alias != "_" && alias != "." {
			env.importAliases[alias] = path
		}
	}

	// Walk top-level declarations for variable types and function params.
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					env.extractVarTypes(vs)
				}
			}
		case *ast.FuncDecl:
			env.extractFuncParamTypes(d)
		}
	}

	return env
}

// extractVarTypes extracts types from var/const declarations.
func (env *TypeEnv) extractVarTypes(vs *ast.ValueSpec) {
	if vs.Type == nil {
		return
	}
	typeStr := exprToTypeString(vs.Type)
	if typeStr == "" {
		return
	}
	for _, name := range vs.Names {
		if name.Name != "_" {
			env.varTypes[name.Name] = typeStr
		}
	}
}

// extractFuncParamTypes extracts parameter types from a function declaration.
func (env *TypeEnv) extractFuncParamTypes(fn *ast.FuncDecl) {
	if fn.Type == nil || fn.Type.Params == nil {
		return
	}
	for _, field := range fn.Type.Params.List {
		typeStr := exprToTypeString(field.Type)
		if typeStr == "" {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" {
				env.varTypes[name.Name] = typeStr
			}
		}
	}
	// Also extract receiver type if present.
	if fn.Recv != nil {
		for _, field := range fn.Recv.List {
			typeStr := exprToTypeString(field.Type)
			if typeStr == "" {
				continue
			}
			for _, name := range field.Names {
				if name.Name != "_" {
					env.varTypes[name.Name] = typeStr
				}
			}
		}
	}
}

// ResolveImport returns the full import path for a local alias.
func (env *TypeEnv) ResolveImport(alias string) string {
	return env.importAliases[alias]
}

// VarType returns the known type for a variable, or "" if unknown.
func (env *TypeEnv) VarType(name string) string {
	return env.varTypes[name]
}

// SetVarType records a variable's type (used during analysis for assignments).
func (env *TypeEnv) SetVarType(name, typeStr string) {
	env.varTypes[name] = typeStr
}

// FieldType returns the type of a field access on a base type, using the
// hardcoded stdlib map. Returns "" if unknown.
func (env *TypeEnv) FieldType(baseType, field string) string {
	key := baseType + "." + field
	return stdlibFieldTypes[key]
}

// ExprToTypeString renders an AST type expression to a string representation
// using the default alias (last path component) for package-qualified types.
// Returns "" for type parameters, generics, and unsupported constructs.
//
// TODO(typed-summaries-phase2): generics — *ast.IndexExpr / *ast.IndexListExpr
// and type-parameter identifiers currently return "".
func ExprToTypeString(expr ast.Expr) string {
	return exprToTypeString(expr)
}

// CanonicalizeType rewrites aliased package references to their default alias
// form. E.g. "*h.Request" with an alias `h -> "net/http"` becomes "*http.Request".
// If no matching import is found, typeStr is returned unchanged.
func (env *TypeEnv) CanonicalizeType(typeStr string) string {
	if env == nil || typeStr == "" {
		return typeStr
	}
	ptr := ""
	rest := typeStr
	for strings.HasPrefix(rest, "*") {
		ptr += "*"
		rest = rest[1:]
	}
	dot := strings.Index(rest, ".")
	if dot < 0 {
		return typeStr
	}
	alias := rest[:dot]
	selector := rest[dot+1:]
	importPath := env.importAliases[alias]
	if importPath == "" {
		return typeStr
	}
	defaultAlias := defaultAliasForPath(importPath)
	if defaultAlias == "" {
		return typeStr
	}
	return ptr + defaultAlias + "." + selector
}

// defaultAliasForPath returns the conventional Go alias for an import path.
// It trims a trailing versioned segment like "/v2" or "/v3" so that
// "github.com/labstack/echo/v4" → "echo".
func defaultAliasForPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]
	if isVersionSegment(last) && len(parts) >= 2 {
		last = parts[len(parts)-2]
	}
	return last
}

func isVersionSegment(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// exprToTypeString renders an AST type expression to a string representation.
func exprToTypeString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		base := exprToTypeString(e.X)
		if base != "" {
			return base + "." + e.Sel.Name
		}
		return e.Sel.Name
	case *ast.StarExpr:
		inner := exprToTypeString(e.X)
		if inner != "" {
			return "*" + inner
		}
	case *ast.ArrayType:
		elt := exprToTypeString(e.Elt)
		if elt != "" {
			return "[]" + elt
		}
	case *ast.MapType:
		k := exprToTypeString(e.Key)
		v := exprToTypeString(e.Value)
		if k != "" && v != "" {
			return "map[" + k + "]" + v
		}
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.Ellipsis:
		if e.Elt != nil {
			elt := exprToTypeString(e.Elt)
			if elt != "" {
				return "..." + elt
			}
		}
		return "..."
	}
	return ""
}
