// Go cross-file RETURN-VALUE FIELD-SENSITIVITY (CH3).
//
// The cross-file return summary was whole-object (index-keyed): a callee
// that returns a struct with ONE tainted field marks its ENTIRE return as
// tainted (TaintedReturns[0]), so a caller that reads only a CLEAN sibling
// field off the returned struct is over-tainted — a false positive.
//
//	func build(r *http.Request) Result {
//	    return Result{Name: r.FormValue("n"), Page: "static.html"}
//	}
//	// caller:
//	res := build(r)
//	http.ServeFile(w, req, res.Page)   // res.Page is the LITERAL — NOT a vuln
//	db.Query(res.Name)                 // res.Name IS tainted — still a vuln
//
// This file adds the PRODUCER half of per-field return taint for Go: it
// scans a callee body for `return T{Field: <source>, Other: "clean"}`
// composite-literal returns (and field-built `r.Field = src; return r`
// shapes) and records the per-field tainted access paths under return
// index 0 in TaintSignature.TaintedReturnPaths ("0.Name"). The consumer
// half lives in checkCallerUsesTaintedReturn (interprocedural.go), which
// gates the caller's sink read on the EXACT field path off the return
// variable, mirroring the JS field-sensitive return gate (PR3).
//
// It REUSES the same bounded access-path abstraction
// (tsflow.BoundAccessPath / PrefixTaintedPath) and the JS object-literal
// structural helpers (jsSplitTopLevelCommas / jsTopLevelColon /
// jsStripOuterBraces / jsBalancedBraces / jsUnquoteKey) — Go struct
// literals share the `{Field: value, ...}` shape. Source detection uses
// the Go directSourcePatterns catalog already compiled in this package.
//
// SAFETY: when a partial-struct tainted return is recorded here,
// TaintedReturns (whole-return, index-keyed) is left UNSET for that shape,
// so a caller's whole-object read (`sink(res)`) stays silent. That is the
// intended FP reduction: a struct value is not itself a string sink
// argument, and the per-field paths still drive the precise read. Returns
// that the scanner cannot decompose (non-literal, computed-key, deep)
// fall through to the existing whole-return heuristic with zero change.

package graph

import (
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/tsflow"
)

// goSourceExpr reports whether a Go RHS expression is a direct taint
// source per the package's directSourcePatterns / sourceParamPatterns
// catalogs (e.g. `r.FormValue("x")`, `os.Getenv(...)`).
func goSourceExpr(expr string) bool {
	for _, re := range directSourcePatterns {
		if re.MatchString(expr) {
			return true
		}
	}
	for re := range sourceParamPatterns {
		if re.MatchString(expr) {
			return true
		}
	}
	return false
}

// scanGoBodyForTaintedReturnPaths scans a Go callee body for a
// `return T{Field: <source>, ...}` composite-literal return whose fields
// carry catalog sources, recording the per-field tainted access paths
// under return index 0. Also handles field-built returns
// (`r := T{}; r.Field = src; return r`). Returns nil when no
// decomposable tainted-field return is present (the caller then falls
// back to whole-return behaviour).
//
//	return Result{Name: r.FormValue("n"), Page: "static"}
//	  → TaintedReturnPaths["0.Name"] = [user_input]   (Page stays out)
func scanGoBodyForTaintedReturnPaths(body string) map[string][]taint.SourceCategory {
	lines := strings.Split(body, "\n")
	out := map[string][]taint.SourceCategory{}

	// Per-variable field taint built up before a `return v`
	// (`v.Name = r.FormValue(...)`). Key: bounded "var.field". Value: cats.
	varFieldTaint := map[string][]taint.SourceCategory{}

	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Field assignment building a struct: `v.Name = r.FormValue("n")`
		// or `v.Name := ...`. Only dotted LHS (a field write) matters here.
		if eq := goAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := strings.TrimSpace(trimmed[eq+1:])
			lhsPath := goLeadingAccessPath(lhs)
			if lhsPath != "" && lhsPath == lhs && strings.Contains(lhsPath, ".") {
				key := tsflow.BoundAccessPath(lhsPath)
				if goSourceExpr(rhs) {
					varFieldTaint[key] = appendUniqueCatList(
						varFieldTaint[key], []taint.SourceCategory{goReturnSourceCat(rhs)})
				} else {
					// Overwrite with a clean / unknown RHS clears the path.
					delete(varFieldTaint, key)
				}
			}
		}

		// `return ...` — either a composite literal or a bare variable
		// that was built field-by-field above.
		if !strings.HasPrefix(trimmed, "return ") {
			continue
		}
		expr := strings.TrimSpace(trimmed[len("return "):])
		if expr == "" {
			continue
		}

		// `return T{...}` composite literal: capture the balanced braces.
		if lit := goReturnCompositeLiteral(expr); lit != "" {
			for path, cats := range goCompositeLiteralTaintedPaths(lit) {
				key := tsflow.BoundAccessPath("0." + path)
				out[key] = appendUniqueCatList(out[key], cats)
			}
			continue
		}

		// `return v` where v was built field-by-field.
		retVar := goLeadingIdent(expr)
		if retVar == "" {
			continue
		}
		for key, cats := range varFieldTaint {
			base, ok := tsflow.IsFieldKey(key)
			if !ok || base != retVar {
				continue
			}
			suffix := strings.TrimPrefix(key, retVar+".")
			outKey := tsflow.BoundAccessPath("0." + suffix)
			out[outKey] = appendUniqueCatList(out[outKey], cats)
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// goReturnSourceCat picks a source category for a tainted RHS. The Go
// directSourcePatterns are dominated by request/CLI inputs; default to
// SrcUserInput, matching the whole-return heuristic's category.
func goReturnSourceCat(rhs string) taint.SourceCategory {
	return taint.SrcUserInput
}

// goReturnCompositeLiteral returns the balanced `{...}` body of a
// `T{...}` composite literal at the start of expr, or "" when expr is not
// a composite-literal return. The type name (and any leading `&`) before
// the brace is skipped; only the brace body is returned.
func goReturnCompositeLiteral(expr string) string {
	expr = strings.TrimSpace(expr)
	expr = strings.TrimPrefix(expr, "&")
	brace := strings.Index(expr, "{")
	if brace < 0 {
		return ""
	}
	// Everything before the first brace must look like a type expression
	// (identifiers, dots, brackets for slices/maps, no call parens) so we
	// don't mistake `return f(x){...}` shapes. A bare `{` (brace at 0) is
	// a map/slice/struct literal with inferred type — also fine.
	head := strings.TrimSpace(expr[:brace])
	if !goIsTypeHead(head) {
		return ""
	}
	return jsBalancedBraces(expr[brace:])
}

// goIsTypeHead reports whether s is a plausible Go type expression head
// preceding a composite-literal brace (e.g. "Result", "pkg.User",
// "[]T", "map[string]T", or "" for an inferred-type literal). Rejects
// anything containing a call paren so function literals don't match.
func goIsTypeHead(s string) bool {
	if s == "" {
		return true
	}
	if strings.Contains(s, "(") || strings.Contains(s, ")") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || c == '.' || c == '[' || c == ']' || c == '*' || c == ' ':
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// goCompositeLiteralTaintedPaths parses a Go composite-literal body and
// returns the dotted field paths whose value is a catalog source
// expression. Nested composite literals recurse with a dotted prefix.
//
//	{Name: r.FormValue("n"), Inner: Sub{ID: r.URL.Query().Get("x")}, P: "k"}
//	  → {"Name": [user_input], "Inner.ID": [user_input]}
//
// Positional (un-keyed) elements are skipped — without a field name they
// cannot be addressed by a caller's field read, so the precise path
// abstraction does not apply.
func goCompositeLiteralTaintedPaths(literal string) map[string][]taint.SourceCategory {
	out := map[string][]taint.SourceCategory{}
	inner := jsStripOuterBraces(literal)
	if inner == "" {
		return out
	}
	for _, entry := range jsSplitTopLevelCommas(inner) {
		colon := jsTopLevelColon(entry)
		if colon < 0 {
			continue // positional element — unaddressable
		}
		keyRaw := strings.TrimSpace(entry[:colon])
		val := strings.TrimSpace(entry[colon+1:])
		key := jsUnquoteKey(keyRaw)
		if key == "" {
			continue
		}
		// Nested composite literal value: `Inner: Sub{...}` or `Inner: {...}`.
		if nested := goReturnCompositeLiteral(val); nested != "" {
			for subPath, cats := range goCompositeLiteralTaintedPaths(nested) {
				out[key+"."+subPath] = cats
			}
			continue
		}
		if goSourceExpr(val) {
			out[key] = []taint.SourceCategory{goReturnSourceCat(val)}
		}
	}
	return out
}

// goAssignEq returns the index of the single `=`/`:=` assignment operator
// in a Go line, or -1 when the line is not a simple assignment. Mirrors
// the JS jsAssignEq logic: skips `==`/`!=`/`<=`/`>=` comparisons and the
// `:=` colon (returns the `=` index for `:=`).
func goAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, !=, <=, >=.
		if i+1 < len(line) && line[i+1] == '=' {
			i++
			continue
		}
		if i > 0 {
			p := line[i-1]
			if p == '=' || p == '!' || p == '<' || p == '>' {
				continue
			}
		}
		return i
	}
	return -1
}

// goLeadingAccessPath returns the leading dotted identifier chain at the
// start of s (`v.Name.X = ...` → "v.Name.X"). Go identifiers are
// [a-zA-Z0-9_]; a trailing dot is trimmed. Used on a TRIMMED LHS.
func goLeadingAccessPath(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '.' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') {
			i++
			continue
		}
		break
	}
	return strings.TrimRight(s[:i], ".")
}

// goLeadingIdent returns the leading bare identifier of s (no dots), or ""
// when s does not start with an identifier. Used to read `return v`.
func goLeadingIdent(s string) string {
	path := goLeadingAccessPath(s)
	if path == "" || strings.Contains(path, ".") {
		return ""
	}
	return path
}
