package astflow

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/turenlabs/batou-core/taint"
)

// exprIsTainted checks whether an AST expression references any tainted variable.
// Walks into selector expressions, binary expressions, call arguments, index
// expressions, and composite literals.
//
// Shallow field sensitivity:
//   - `obj.field` returns ts for "obj.field" if tainted, else for "obj" if tainted.
//   - `obj` (bare ident) returns ts for "obj" if tainted, else any "obj.*" field
//     if tainted (the sink may internally read any field — over-approximation).
//   - `obj.a.b` truncates to first-level: equivalent to `obj.a`.
func exprIsTainted(expr ast.Expr, tm *TaintMap) (*taintState, bool) {
	if expr == nil {
		return nil, false
	}

	switch e := expr.(type) {
	case *ast.Ident:
		if ts := tm.Get(e.Name); ts != nil && ts.source != nil {
			return ts, true
		}
		// Whole-object read at a sink — conservatively report if any field
		// of this object carries taint.
		if ts := tm.AnyFieldTainted(e.Name); ts != nil {
			return ts, true
		}

	case *ast.SelectorExpr:
		// Full-chain selector key (e.g. "r.URL.Path") — used by selector
		// sources seeded into the TaintMap before the main pass. Lets
		// nested reads like `os.ReadFile(r.URL.Path)` resolve to the
		// seeded taint state without truncation.
		if key := exprToString(e); key != "" {
			if ts := tm.Get(key); ts != nil && ts.source != nil {
				return ts, true
			}
		}
		// Shallow field-sensitive read: if X is a bare ident, look up
		// "X.Sel" as a distinct taint key. Nested selectors (a.b.c)
		// truncate at the first level: treated as obj.a.
		if base, field, ok := firstLevelField(e); ok {
			if ts := tm.Get(fieldKey(base, field)); ts != nil && ts.source != nil {
				return ts, true
			}
			// Must-alias resolution: a field written through a copy of the
			// same object (`b := a; b.Field = src`) is read through any
			// alias-equivalent base (`sink(a.Field)`). Only the base ident is
			// substituted; the field name is unchanged, so a sibling field is
			// never tainted by this.
			for _, ar := range tm.aliasRoots(base) {
				if ar == base {
					continue
				}
				if ts := tm.Get(fieldKey(ar, field)); ts != nil && ts.source != nil {
					return ts, true
				}
			}
		}
		return exprIsTainted(e.X, tm)

	case *ast.BinaryExpr:
		if ts, ok := exprIsTainted(e.X, tm); ok {
			return ts, true
		}
		if ts, ok := exprIsTainted(e.Y, tm); ok {
			return ts, true
		}

	case *ast.CallExpr:
		// The call may itself BE an inline source whose result was never bound
		// to a local variable — e.g. the inner `r.FormValue("x")` in
		// `db.Query(r.FormValue("x"))`. The walker seeds such source calls under
		// the synthetic `__expr__` key, but only as the walk descends, which is
		// too late for a sink (the outer call) checked on the same node before
		// its child source. Resolve it eagerly here via the analysis-scoped
		// matcher, exactly as the sink path does, so an unbound inline source
		// argument seeds a transient taint state. (Checked first so a true
		// source call is attributed to its source rather than to a tainted
		// argument it happens to carry.)
		if tm != nil && tm.matcher != nil {
			if src := tm.matcher.MatchSource(e); src != nil {
				return inlineSourceState(e, src), true
			}
		}
		for _, arg := range e.Args {
			if ts, ok := exprIsTainted(arg, tm); ok {
				return ts, true
			}
		}
		// Protobuf-style zero-arg accessor on a tainted receiver:
		// `req.GetShellCmd()` returns a field of the tainted message `req`.
		// gRPC handlers read request fields exclusively through these
		// generated getters, so propagate taint from receiver to result.
		// Tightly scoped to GetXxx() with no arguments to avoid tainting
		// arbitrary method results.
		if len(e.Args) == 0 {
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok &&
				strings.HasPrefix(sel.Sel.Name, "Get") && len(sel.Sel.Name) > 3 {
				if ts, ok := exprIsTainted(sel.X, tm); ok {
					return ts, true
				}
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

// inlineSourceState synthesises a transient taintState for an inline source
// call expression that was never bound to a local variable. Mirrors the
// `__expr__` seed the walker sets for source calls (walker.go), so an unbound
// inline source used directly as a sink/sanitizer/propagation argument carries
// the same taint a bound variable would.
func inlineSourceState(call *ast.CallExpr, src *taint.SourceDef) *taintState {
	name := selectorString(call.Fun)
	if name == "" {
		name = "__expr__"
	}
	return &taintState{
		varName:    name,
		source:     src,
		sourceLine: 0,
		sanitized:  make(map[taint.SinkCategory]bool),
		confidence: 1.0,
		steps: []taint.FlowStep{{
			Line:        0,
			Description: "tainted by " + src.MethodName,
			VarName:     name,
		}},
	}
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

// firstLevelField extracts (base, field) for a shallow field access of the
// form `base.field`. Truncates nested selectors at the first level:
//   - obj.field      -> ("obj", "field", true)
//   - obj.a.b        -> ("obj", "a", true) — first level only
//   - (*obj).field   -> ("obj", "field", true) — pointer auto-deref
//   - pkg.Func()...  -> ("", "", false) if base is not an identifier we track
//   - obj[i].field   -> ("", "", false) — not an identifier-named field
//
// Returns false when the receiver isn't a plain identifier we'd otherwise
// track in the TaintMap, keeping field sensitivity narrowly scoped to the
// "DTO struct .Field" pattern this implementation targets.
func firstLevelField(sel *ast.SelectorExpr) (string, string, bool) {
	if sel == nil || sel.Sel == nil {
		return "", "", false
	}

	// Walk down through any chain of selectors to the root receiver.
	// At each step `cur` holds the deepest SelectorExpr seen so far;
	// when cur.X becomes a plain ident (or pointer-deref of an ident),
	// cur.Sel is the "first level" field we want.
	cur := sel
	for {
		switch x := cur.X.(type) {
		case *ast.Ident:
			return x.Name, cur.Sel.Name, true
		case *ast.StarExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				return id.Name, cur.Sel.Name, true
			}
			return "", "", false
		case *ast.ParenExpr:
			if star, ok := x.X.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok {
					return id.Name, cur.Sel.Name, true
				}
			}
			if id, ok := x.X.(*ast.Ident); ok {
				return id.Name, cur.Sel.Name, true
			}
			return "", "", false
		case *ast.SelectorExpr:
			cur = x
		default:
			return "", "", false
		}
	}
}

// lhsTaintKey resolves an assignment LHS expression to a TaintMap key.
// Returns:
//   - ("varName", "", true)        for plain identifier `varName` — caller
//     should also clear any "varName.*" field keys (the binding is replaced).
//   - ("varName", "fieldName", true) for shallow field access `varName.fieldName`
//     (or truncated `varName.fieldName.x` -> `varName.fieldName`).
//   - ("", "", false)              for unsupported LHS (index expr, map key,
//     slice index, etc.) — out of scope for this PR.
func lhsTaintKey(expr ast.Expr) (base, field string, ok bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		if e.Name == "" || e.Name == "_" {
			return "", "", false
		}
		return e.Name, "", true
	case *ast.StarExpr:
		// *p = ... — treat as rebinding p for our purposes.
		if id, ok := e.X.(*ast.Ident); ok && id.Name != "" && id.Name != "_" {
			return id.Name, "", true
		}
		return "", "", false
	case *ast.SelectorExpr:
		if base, field, ok := firstLevelField(e); ok {
			return base, field, true
		}
		return "", "", false
	}
	return "", "", false
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
