package cast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
)

// cast_bounds_guard.go recognises a LENGTH/BOUNDS GUARD preceding a memory-copy
// sink (BATOU-CAST-004). When a copy whose size is a parameter-controlled length
// is preceded by an early-exit size check that constrains that copy — e.g.
//
//	char buf[128];
//	if (sdslen(o->ptr) > sizeof(buf)-1) goto invalid;   // bounds guard
//	memcpy(buf, o->ptr, sdslen(o->ptr)+1);              // bounded — not an OOB write
//
// the out-of-bounds-write finding is a false positive. This mirrors the Python
// eval-guard concept (rules.PyHasEvalGuard) for the C memory sink class, and is
// the AST analyzer twin of the tsflow taint-engine recogniser in
// batou-core/taint/tsflow/c_bounds_guard.go.
//
// Conservative by construction (recall preservation is paramount):
//   - The guard must be a SIZE/LENGTH COMPARISON (sizeof / *_MAX-style macro /
//     length call, plus a relational operator). A NULL-check or flag test does
//     not qualify, so a copy preceded only by `if (p == NULL) goto` still fires.
//   - The guard must have an EARLY-EXIT body (return / goto / break / continue).
//   - The guard condition must REFERENCE THIS COPY (share an identifier with the
//     copy's dst / src / size arguments), tying the bound to this memcpy.

// hasPrecedingBoundsGuard reports whether the copy call `sink` (with its named
// arguments `args`) is preceded in its enclosing function by a length/bounds
// guard that constrains this copy.
func (c *cChecker) hasPrecedingBoundsGuard(sink *ast.Node, args []*ast.Node) bool {
	if sink == nil {
		return false
	}
	// Build the guard-token set from the SOURCE (arg 1) and SIZE (last) arguments
	// only — NOT the destination (arg 0). A guard's `sizeof(dst)` term naturally
	// mentions the destination buffer, so keying off the destination would let an
	// unrelated check (`if (other > sizeof(dst)-1) return;`) masquerade as a
	// guard on this copy. Every genuine guarded shape constrains the source or
	// the copy length.
	copyTokens := make(map[string]bool)
	for i, a := range args {
		if i == 0 {
			continue // skip destination buffer
		}
		for _, id := range identifiersIn(a) {
			copyTokens[id] = true
		}
	}
	if len(copyTokens) == 0 {
		return false
	}

	var fnDef *ast.Node
	for _, anc := range sink.Ancestors() {
		if anc.Type() == "function_definition" {
			fnDef = anc
			break
		}
	}
	if fnDef == nil {
		return false
	}
	sinkRow := sink.StartRow()

	guarded := false
	fnDef.Walk(func(w *ast.Node) bool {
		if guarded {
			return false
		}
		if w.Type() != "if_statement" {
			return true
		}
		// Bounded lookback: the guard must sit in the small window of lines
		// immediately above the copy (mirrors PyHasEvalGuard). This prevents an
		// unrelated length-check elsewhere in a large function — one that merely
		// shares a variable name with the copy — from suppressing this finding.
		if w.StartRow() >= sinkRow || sinkRow-w.StartRow() > castMaxGuardLookback {
			return true
		}
		if castIfIsBoundsGuard(w, copyTokens) {
			guarded = true
			return false
		}
		return true
	})
	return guarded
}

// castMaxGuardLookback bounds how many source lines above a copy a bounds guard
// may appear and still gate that copy. Genuine guarded cases sit within ~6
// lines; 8 covers them with margin while excluding far, unrelated matches.
const castMaxGuardLookback = 8

// castIfIsBoundsGuard reports whether an if_statement is a length/bounds guard
// referencing one of copyTokens with an early-exit body.
func castIfIsBoundsGuard(ifStmt *ast.Node, copyTokens map[string]bool) bool {
	cond := ifStmt.ChildByFieldName("condition")
	if cond == nil {
		named := ifStmt.NamedChildren()
		if len(named) > 0 {
			cond = named[0]
		}
	}
	if cond == nil {
		return false
	}
	if !castCondIsSizeComparison(cond) {
		return false
	}
	if !castCondReferencesTokens(cond, copyTokens) {
		return false
	}
	conseq := ifStmt.ChildByFieldName("consequence")
	if conseq == nil {
		named := ifStmt.NamedChildren()
		if len(named) >= 2 {
			conseq = named[1]
		}
	}
	if conseq == nil {
		return false
	}
	return castBranchHasEarlyExit(conseq)
}

// castCondIsSizeComparison reports whether a condition is a relational
// comparison involving a bounding term (sizeof / length call / *_MAX-style
// macro).
func castCondIsSizeComparison(cond *ast.Node) bool {
	hasRelational := false
	hasBound := false
	cond.Walk(func(w *ast.Node) bool {
		switch w.Type() {
		case "binary_expression":
			if op := w.ChildByFieldName("operator"); op != nil {
				switch op.Text() {
				case ">", ">=", "<", "<=", "==", "!=":
					hasRelational = true
				}
			}
		case "sizeof_expression":
			hasBound = true
		case "call_expression":
			if castIsLengthCall(w) {
				hasBound = true
			}
		case "identifier":
			if castIsSizeConstName(w.Text()) {
				hasBound = true
			}
		}
		return true
	})
	return hasRelational && hasBound
}

func castIsLengthCall(call *ast.Node) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	if fn.Type() == "identifier" {
		return castIsLengthName(fn.Text())
	}
	if fn.Type() == "field_expression" {
		if f := fn.ChildByFieldName("field"); f != nil {
			return castIsLengthName(f.Text())
		}
	}
	return false
}

func castIsLengthName(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "strlen", "strnlen", "sdslen", "wcslen", "wcsnlen":
		return true
	}
	return strings.HasSuffix(lower, "len") || strings.HasSuffix(lower, "length") ||
		strings.HasSuffix(lower, "_size")
}

func castIsSizeConstName(name string) bool {
	if name == "" {
		return false
	}
	switch name {
	case "PATH_MAX", "NAME_MAX", "BUFSIZ", "SIZE_MAX", "INT_MAX", "UINT_MAX", "LINE_MAX":
		return true
	}
	if name != strings.ToUpper(name) {
		return false
	}
	for _, suf := range []string{"_MAX", "_LEN", "_SIZE", "_LIMIT", "_NAMELEN", "_CAP", "_BYTES", "_WIDTH"} {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

func castCondReferencesTokens(cond *ast.Node, copyTokens map[string]bool) bool {
	found := false
	cond.Walk(func(w *ast.Node) bool {
		if found {
			return false
		}
		if w.Type() == "identifier" && copyTokens[w.Text()] {
			found = true
			return false
		}
		return true
	})
	return found
}

func castBranchHasEarlyExit(body *ast.Node) bool {
	found := false
	body.Walk(func(w *ast.Node) bool {
		if found {
			return false
		}
		switch w.Type() {
		case "return_statement", "goto_statement", "break_statement", "continue_statement":
			found = true
			return false
		case "call_expression":
			fn := w.ChildByFieldName("function")
			if fn != nil && fn.Type() == "identifier" {
				switch strings.ToLower(fn.Text()) {
				case "longjmp", "siglongjmp", "abort", "exit", "_exit", "panic":
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}
