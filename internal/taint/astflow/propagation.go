package astflow

import (
	"go/ast"
	"go/token"
	"strings"
)

// exprIsTainted checks whether an AST expression references any tainted variable.
// Walks into selector expressions, binary expressions, call arguments, index
// expressions, and composite literals.
func exprIsTainted(expr ast.Expr, tm *TaintMap) (*taintState, bool) {
	if expr == nil {
		return nil, false
	}

	switch e := expr.(type) {
	case *ast.Ident:
		if ts := tm.Get(e.Name); ts != nil && ts.source != nil {
			return ts, true
		}

	case *ast.SelectorExpr:
		return exprIsTainted(e.X, tm)

	case *ast.BinaryExpr:
		if ts, ok := exprIsTainted(e.X, tm); ok {
			return ts, true
		}
		if ts, ok := exprIsTainted(e.Y, tm); ok {
			return ts, true
		}

	case *ast.CallExpr:
		for _, arg := range e.Args {
			if ts, ok := exprIsTainted(arg, tm); ok {
				return ts, true
			}
		}

	case *ast.IndexExpr:
		return exprIsTainted(e.X, tm)

	case *ast.SliceExpr:
		return exprIsTainted(e.X, tm)

	case *ast.UnaryExpr:
		if e.Op == token.ARROW { // <-ch (channel receive)
			return exprIsTainted(e.X, tm)
		}
		return exprIsTainted(e.X, tm) // &x, *x

	case *ast.ParenExpr:
		return exprIsTainted(e.X, tm)

	case *ast.TypeAssertExpr:
		return exprIsTainted(e.X, tm)

	case *ast.StarExpr:
		return exprIsTainted(e.X, tm)

	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if ts, tainted := exprIsTainted(kv.Value, tm); tainted {
					return ts, true
				}
			} else {
				if ts, tainted := exprIsTainted(elt, tm); tainted {
					return ts, true
				}
			}
		}
	}

	return nil, false
}

// propagationConfidence returns the confidence decay factor for taint
// propagating through a given expression.
func propagationConfidence(expr ast.Expr) float64 {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return 0.95 // String concatenation
		}
		return 0.9

	case *ast.CallExpr:
		sel := selectorString(e.Fun)
		lower := strings.ToLower(sel)

		// String operations preserve taint with high confidence.
		if strings.Contains(lower, "toupper") || strings.Contains(lower, "tolower") ||
			strings.Contains(lower, "trimspace") || strings.Contains(lower, "trim") ||
			strings.Contains(lower, "replace") || strings.Contains(lower, "join") {
			return 0.95
		}

		// Type conversion.
		if strings.Contains(lower, "string(") || strings.Contains(lower, "byte") {
			return 0.9
		}

		// Format functions.
		if strings.Contains(lower, "sprintf") || strings.Contains(lower, "format") {
			return 0.95
		}

		// Unknown function call.
		return 0.85

	case *ast.CompositeLit:
		return 0.85

	case *ast.IndexExpr, *ast.SliceExpr:
		return 0.9

	default:
		return 1.0
	}
}

// identName extracts the identifier name from an expression.
func identName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return identName(e.X)
	}
	return ""
}

// selectorString gets "pkg.Method" or "receiver.Method" from a function expression.
func selectorString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		base := selectorString(e.X)
		if base != "" {
			return base + "." + e.Sel.Name
		}
		return e.Sel.Name

	case *ast.Ident:
		return e.Name

	case *ast.CallExpr:
		return selectorString(e.Fun)
	}
	return ""
}

// deepReceiverName walks into nested selector/call expressions to find the
// root receiver identifier name.
func deepReceiverName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return deepReceiverName(e.X)
	case *ast.CallExpr:
		return deepReceiverName(e.Fun)
	case *ast.IndexExpr:
		return deepReceiverName(e.X)
	}
	return ""
}

// unwrapCall extracts a *ast.CallExpr from an expression, handling parenthesization.
func unwrapCall(expr ast.Expr) (*ast.CallExpr, bool) {
	switch e := expr.(type) {
	case *ast.CallExpr:
		return e, true
	case *ast.ParenExpr:
		return unwrapCall(e.X)
	}
	return nil, false
}

// exprToString renders an AST expression back to a rough string representation.
func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprToString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + exprToString(e.X)
	case *ast.ArrayType:
		return "[]" + exprToString(e.Elt)
	case *ast.MapType:
		return "map[" + exprToString(e.Key) + "]" + exprToString(e.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.Ellipsis:
		if e.Elt != nil {
			return "..." + exprToString(e.Elt)
		}
		return "..."
	}
	return ""
}
