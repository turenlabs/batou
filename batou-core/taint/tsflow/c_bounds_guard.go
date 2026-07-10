package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// c_bounds_guard.go implements a C/C++ LENGTH/BOUNDS-GUARD recogniser for memory
// -copy sinks (memcpy/memmove/strncpy/strncat/...). It mirrors the Python
// eval-guard idea (rules.PyHasEvalGuard) for a different sink class: a copy
// whose size or source is constrained by a preceding `if (len > LIMIT) return;`
// check in the SAME function is bounded, and the SnkMemory finding is an
// out-of-bounds-write false positive.
//
// This addresses the dominant real-world C memory FP shape seen on Redis:
//
//	char buf[128];
//	if (sdslen(o->ptr) > sizeof(buf)-1) goto invalid;   // bounds guard
//	memcpy(buf, o->ptr, sdslen(o->ptr)+1);              // bounded — not an OOB write
//
//	if (strlen(filepath) > PATH_MAX) goto invalid_args; // bounds guard
//	memcpy(temp_filepath, filepath, strlen(filepath)+1);
//
//	if (*used + sizeof(payloadHeader) + len > size) return 0; // bounds guard on len
//	memcpy((char *)header + sizeof(payloadHeader), payload, len);
//
// DESIGN PRINCIPLES (conservative — recall preservation is paramount):
//
//   - The guard must be a SIZE/LENGTH COMPARISON: its condition must contain a
//     bounding term (sizeof, a *_MAX / *_LEN / *_SIZE / *_LIMIT macro, or a
//     length call such as strlen/sdslen) AND a relational operator (`>`, `>=`,
//     `<`, `<=`, `!=`, `==`). A bare NULL-check or format/field validation does
//     NOT qualify — that is why an UNGUARDED copy preceded only by
//     `if (strrchr(x,':') == NULL) goto` still fires.
//   - The guard must have an EARLY-EXIT body (return / goto / break / continue /
//     longjmp). A check whose body merely logs is not a rejection of the bad
//     case and proves nothing about the fall-through copy.
//   - The guard must REFERENCE THE COPY: its condition must share an identifier
//     with the copy's destination, source, or size expression. This is what
//     ties the bound to THIS memcpy rather than to some unrelated value, so a
//     function with one length check does not silence every copy it contains.
//   - It only suppresses the SnkMemory category, and only for C/C++. Every other
//     language and sink category is byte-unchanged.

// cMemoryCopySinks are the C/C++ memory-copy intrinsics whose SnkMemory finding
// a preceding length/bounds guard can neutralise. Keyed by the lowercase callee
// name. strcpy/strcat are intentionally INCLUDED: a `strlen(src) < sizeof(dst)`
// guard above a strcpy bounds it just as well as it bounds a memcpy.
var cMemoryCopySinks = map[string]bool{
	"memcpy":  true,
	"memmove": true,
	"memccpy": true,
	"strncpy": true,
	"strncat": true,
	"strcpy":  true,
	"strcat":  true,
	"bcopy":   true,
	"strlcpy": true,
	"strlcat": true,
	"wmemcpy": true,
	"wcsncpy": true,
}

// cHasBoundsGuardForCopy reports whether the memory-copy call node `sink` is
// preceded, within its enclosing function, by a length/bounds guard that
// constrains this copy. Returns false (no suppression) for any non-copy sink,
// any non-C/C++ language, or when no qualifying guard is found.
func cHasBoundsGuardForCopy(sink *ast.Node, cfg *langConfig) bool {
	if sink == nil || cfg == nil {
		return false
	}
	if cfg.language != rules.LangC && cfg.language != rules.LangCPP {
		return false
	}
	name := strings.ToLower(cfg.extractCallName(sink))
	if !cMemoryCopySinks[name] {
		return false
	}

	// Tokens that identify THIS copy: identifiers appearing in the dst, src and
	// size arguments. A guard must reference at least one of them.
	copyTokens := cCopyIdentifierSet(sink, cfg)
	if len(copyTokens) == 0 {
		return false
	}

	// Find the enclosing function body and the sink's start row.
	fnBody := cEnclosingFunctionBody(sink)
	if fnBody == nil {
		return false
	}
	sinkRow := sink.StartRow()

	guarded := false
	fnBody.Walk(func(w *ast.Node) bool {
		if guarded {
			return false
		}
		if w.Type() != "if_statement" {
			return true
		}
		// The guard must appear in the small window of lines IMMEDIATELY ABOVE
		// the copy. This mirrors PyHasEvalGuard's bounded lookback and is what
		// keeps the recogniser from matching an unrelated length-check elsewhere
		// in a large function that happens to share a variable name with the
		// copy. The guard's body (the rejection block) may span several lines, so
		// the guard's START row, not its end, must be within the window.
		if w.StartRow() >= sinkRow || sinkRow-w.StartRow() > cMaxGuardLookback {
			return true
		}
		if cIfIsBoundsGuardForTokens(w, copyTokens, cfg) {
			guarded = true
			return false
		}
		return true
	})
	return guarded
}

// cMaxGuardLookback bounds how many source lines above a copy a bounds guard may
// appear and still be considered to gate that copy. Every genuine guarded case
// observed on Redis sits within 6 lines (the rejection block plus a comment);
// an unrelated length-check elsewhere in a large function is dozens of lines
// away. 8 lines covers the real shape with margin while excluding the far
// matches.
const cMaxGuardLookback = 8

// cCopyIdentifierSet returns the set of identifier names appearing in the
// SOURCE (arg 1) and SIZE (last) arguments of a copy call. The DESTINATION (arg
// 0) is deliberately excluded: a guard's `sizeof(dst)` term naturally mentions
// the destination buffer, so keying off the destination would let an unrelated
// check (`if (other > sizeof(dst)-1) return;`) masquerade as a guard on this
// copy. Every genuine guarded shape constrains the source or the copy length,
// so requiring the guard to reference one of those is both sufficient and far
// less FP-prone.
func cCopyIdentifierSet(sink *ast.Node, cfg *langConfig) map[string]bool {
	args := cfg.extractCallArgs(sink)
	set := make(map[string]bool)
	for i, a := range args {
		if i == 0 {
			continue // skip destination buffer
		}
		for _, id := range cIdentifiersIn(a) {
			set[id] = true
		}
	}
	return set
}

// cEnclosingFunctionBody returns the compound_statement body of the
// function_definition enclosing node n, or nil if none.
func cEnclosingFunctionBody(n *ast.Node) *ast.Node {
	for _, anc := range n.Ancestors() {
		if anc.Type() == "function_definition" {
			if b := anc.ChildByFieldName("body"); b != nil {
				return b
			}
			// Fall back to the first compound_statement child.
			for _, c := range anc.NamedChildren() {
				if c.Type() == "compound_statement" {
					return c
				}
			}
			return nil
		}
	}
	return nil
}

// cIfIsBoundsGuardForTokens reports whether an if_statement is a length/bounds
// guard that (a) has a size/length comparison condition, (b) references one of
// copyTokens in that condition, and (c) has an early-exit consequence.
func cIfIsBoundsGuardForTokens(ifStmt *ast.Node, copyTokens map[string]bool, cfg *langConfig) bool {
	condNode := ifStmt.ChildByFieldName("condition")
	if condNode == nil {
		// Fall back to the first named child if the condition field is absent.
		named := ifStmt.NamedChildren()
		if len(named) > 0 {
			condNode = named[0]
		}
	}
	if condNode == nil {
		return false
	}
	if !cConditionIsSizeComparison(condNode) {
		return false
	}
	// The condition must reference the copy (share an identifier with it).
	if !cConditionReferencesTokens(condNode, copyTokens) {
		return false
	}
	// The if-body (or the whole statement) must contain an early exit.
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
	return cBranchHasEarlyExit(conseq)
}

// cConditionIsSizeComparison reports whether a condition subtree is a relational
// comparison that involves a bounding term: a sizeof expression, a length call,
// or a *_MAX / *_LEN / *_SIZE / *_LIMIT / *_NAMELEN style size constant. This is
// the signal that the if-check bounds a buffer size rather than testing some
// unrelated predicate (NULL-check, flag test, etc.).
func cConditionIsSizeComparison(cond *ast.Node) bool {
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
			if cIsLengthCall(w) {
				hasBound = true
			}
		case "identifier":
			if cIsSizeConstName(w.Text()) {
				hasBound = true
			}
		}
		return true
	})
	return hasRelational && hasBound
}

// cIsLengthCall reports whether a call_expression is a string/buffer length
// function whose result is a size (strlen, sdslen, wcslen, strnlen, *_len(...)).
func cIsLengthCall(call *ast.Node) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	if fn.Type() == "identifier" {
		return cIsLengthName(fn.Text())
	}
	// field_expression like obj->len() — take the field name.
	if fn.Type() == "field_expression" {
		if f := fn.ChildByFieldName("field"); f != nil {
			return cIsLengthName(f.Text())
		}
	}
	return false
}

func cIsLengthName(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "strlen", "strnlen", "sdslen", "wcslen", "wcsnlen":
		return true
	}
	// Generic *_len / *length() / *_size() helpers (Redis `stringObjectLen`,
	// `sdslen`, `obj_len`, `buf_length`, etc.).
	return strings.HasSuffix(lower, "len") || strings.HasSuffix(lower, "length") ||
		strings.HasSuffix(lower, "_size")
}

// cIsSizeConstName reports whether an identifier looks like a size/limit macro:
// ALL-CAPS ending in _MAX / _LEN / _SIZE / _LIMIT / _NAMELEN / _CAP, or the
// bare well-known limits PATH_MAX / NAME_MAX / BUFSIZ / SIZE_MAX.
func cIsSizeConstName(name string) bool {
	if name == "" {
		return false
	}
	switch name {
	case "PATH_MAX", "NAME_MAX", "BUFSIZ", "SIZE_MAX", "INT_MAX", "UINT_MAX", "LINE_MAX":
		return true
	}
	// Must be an ALL-CAPS macro-style identifier to avoid matching ordinary
	// lowercase locals.
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

// cConditionReferencesTokens reports whether any identifier in the condition
// subtree appears in the copy-token set. Ties the guard to THIS copy.
func cConditionReferencesTokens(cond *ast.Node, copyTokens map[string]bool) bool {
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

// cBranchHasEarlyExit reports whether a statement subtree contains a return,
// goto, break, continue, or longjmp — the rejection idioms a bounds guard uses
// to skip the copy when the length check fails.
func cBranchHasEarlyExit(body *ast.Node) bool {
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
			// longjmp / abort / exit / panic-style early termination.
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

// cIdentifiersIn returns every plain identifier appearing in an expression
// subtree, skipping type names inside sizeof(type).
func cIdentifiersIn(n *ast.Node) []string {
	if n == nil {
		return nil
	}
	var ids []string
	n.Walk(func(c *ast.Node) bool {
		if c.Type() == "sizeof_expression" {
			return false
		}
		if c.Type() == "identifier" {
			ids = append(ids, c.Text())
		}
		return true
	})
	return ids
}

// cMemorySinkIsBoundsGuarded is the entry point the walker calls before emitting
// a SnkMemory taint finding on a C/C++ copy sink. It is a no-op (returns false)
// for any other sink category, keeping the change surgically scoped.
func cMemorySinkIsBoundsGuarded(sink *ast.Node, cat taint.SinkCategory, cfg *langConfig) bool {
	if cat != taint.SnkMemory {
		return false
	}
	return cHasBoundsGuardForCopy(sink, cfg)
}
