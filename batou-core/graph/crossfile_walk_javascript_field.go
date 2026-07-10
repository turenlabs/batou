// JavaScript / TypeScript cross-file ACCESS-PATH FIELD-SENSITIVITY (PR3).
//
// Today the cross-file summary is whole-param / whole-return
// (index-keyed): a sink that reads `opts.cmd` is recorded only as "param
// 0 reaches a sink", so the call site `o.cmd = "ls"; o.other =
// req.body.cmd; run(o)` over-approximates — the whole `o` looks tainted
// even though the sink reads the literal field. This file adds a precise,
// bounded, 1-hop field overlay:
//
//   - Sink seeding strips the matched param prefix from the sink-line
//     text and bounds the suffix into SinkRef.ArgFieldPath ("cmd").
//   - At the call site, when ArgFieldPath != "", the walker composes
//     callerArgPath = BoundAccessPath(arg + "." + ArgFieldPath) and gates
//     on the caller's intra-file per-field taint for THAT EXACT path
//     (proper-prefix walk, mirroring tsflow.prefixTainted). So
//     `o.cmd = req.body.cmd` fires; `o.cmd = "ls"` stays silent.
//   - Return composition records TaintedReturnPaths["0.user.id"]; the
//     caller `r = callee(); sink(r.user.id)` composes
//     BoundAccessPath(r + ".user.id") and fires only when a tainted prefix
//     exists; `sink(r.name)` stays quiet.
//
// All of it REUSES the tsflow access-path abstraction
// (tsflow.BoundAccessPath / tsflow.PrefixTaintedPath / tsflow.IsFieldKey)
// so the bound and prefix-walk rules stay identical to the per-file
// engine. Whole-param / whole-return flows (ArgFieldPath=="",
// TaintedReturnPaths==nil — legacy graphs, other languages) fall through
// to the existing index-keyed logic: zero behaviour change.

package graph

import (
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/tsflow"
)

// jsParamFieldFlow describes how a single sink consumes a parameter: the
// param index and, when the sink reads a specific field off that param,
// the bounded field access path (e.g. "cmd" for `exec(opts.cmd)`). An
// empty fieldPath means whole-param consumption (`exec(opts)`).
type jsParamFieldFlow struct {
	paramIdx  int
	fieldPath string
}

// findJavaScriptParamFlowToSinkField is the field-sensitive param-flow
// matcher. It returns the source-param index whose name appears in the
// sink line AND the bounded field access path the sink reads off that
// param.
//
// Two binding shapes are handled:
//
//   - Plain object param `function run(opts){ exec(opts.cmd); }`: the
//     param name `opts` is matched as a token in the sink expression,
//     then the access path that has `opts` as its root is extracted and
//     the `opts.` prefix stripped → fieldPath "cmd".
//   - Destructured param `function run({cmd}){ exec(cmd); }`: the
//     ParamTaint row carries FieldName "cmd" and Name "cmd"; the bare
//     name `cmd` is matched in the sink and rebinds to field path "cmd"
//     (the field of the underlying object the caller passes).
//
// fieldPath is "" when the sink reads the whole param (`exec(opts)`),
// preserving legacy whole-param behaviour for that sink.
func findJavaScriptParamFlowToSinkField(lines []string, sinkLineIdx int, sig *TaintSignature) jsParamFieldFlow {
	none := jsParamFieldFlow{paramIdx: -1}
	if sig == nil || sinkLineIdx < 0 || sinkLineIdx >= len(lines) {
		return none
	}
	sinkLine := lines[sinkLineIdx]

	// Prefer SourceParams when set; fall back to plain Params (the JS
	// extractor doesn't tag IsSourceType pre-PR-BBjs).
	tryParam := func(idx int) (jsParamFieldFlow, bool) {
		// Destructured rows: a ParamTaint row sharing this index whose
		// FieldName is set and whose bare Name appears in the sink rebinds
		// to the field path.
		for _, p := range sig.Params {
			if p.Index != idx || p.FieldName == "" || p.Name == "" {
				continue
			}
			if containsToken(sinkLine, p.Name) {
				return jsParamFieldFlow{paramIdx: idx, fieldPath: tsflow.BoundAccessPath(p.FieldName)}, true
			}
		}
		// Plain object param: match the param NAME and extract the field
		// path the sink reads off it.
		name := paramNameFromSig(sig, idx)
		if name == "" {
			return none, false
		}
		if !containsToken(sinkLine, name) {
			return none, false
		}
		fp := jsSinkFieldPathForParam(sinkLine, name)
		return jsParamFieldFlow{paramIdx: idx, fieldPath: fp}, true
	}

	if len(sig.SourceParams) > 0 {
		for paramIdx := range sig.SourceParams {
			if f, ok := tryParam(paramIdx); ok {
				return f
			}
		}
		// No source param matched — but a destructured row may live on a
		// non-source index; fall through to the generic param scan below.
	}

	// Generic scan over all params (covers the legacy fallback and
	// destructured rows on plain indices).
	seen := map[int]bool{}
	for _, p := range sig.Params {
		if seen[p.Index] {
			continue
		}
		seen[p.Index] = true
		if f, ok := tryParam(p.Index); ok {
			return f
		}
	}
	return none
}

// jsSinkFieldPathForParam extracts the bounded field access path that the
// sink line reads off the parameter named `param`. Given sink text
// `cp.exec(opts.cmd)` and param "opts" it returns "cmd"; given
// `cp.exec(opts.a.b.c.d)` it bounds to "a.b" (root opts + the bounded
// suffix). Returns "" when the param is consumed whole (`cp.exec(opts)`),
// when it is subscripted (`opts['cmd']` — out of scope for the shallow
// dotted abstraction), or when no `param.<field>` access is present.
func jsSinkFieldPathForParam(sinkLine, param string) string {
	// Find a `param.` occurrence at a token boundary so `opts` doesn't
	// match inside `myopts`.
	search := sinkLine
	offset := 0
	for {
		idx := strings.Index(search, param+".")
		if idx < 0 {
			return ""
		}
		// Token-boundary check on the left of the match.
		abs := offset + idx
		if abs > 0 && isJSIdentByte(sinkLine[abs-1]) {
			// Not a token boundary — advance past this occurrence.
			offset = abs + 1
			search = sinkLine[offset:]
			continue
		}
		// Collect the dotted access path starting at `param`.
		rest := sinkLine[abs:]
		path := jsLeadingAccessPath(rest)
		// path starts with "param."; strip the root + dot to get the
		// suffix, then bound the full path and re-strip so the BOUND is
		// applied with the root counted (matching the per-file engine,
		// where boundAccessPath operates on the full root-anchored path).
		bounded := tsflow.BoundAccessPath(path)
		suffix := strings.TrimPrefix(bounded, param+".")
		if suffix == bounded {
			// param wasn't actually the root (shouldn't happen) — bail.
			return ""
		}
		return suffix
	}
}

// jsLeadingAccessPath returns the leading dotted identifier chain at the
// start of s (`opts.cmd.x) ...` → "opts.cmd.x"). Stops at the first byte
// that isn't a JS identifier byte or a dot. A trailing dot (e.g. from
// `opts.` with nothing after) is trimmed.
func jsLeadingAccessPath(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '.' || isJSIdentByte(c) {
			i++
			continue
		}
		break
	}
	return strings.TrimRight(s[:i], ".")
}

// isJSIdentByte reports whether b can appear in a JS identifier.
func isJSIdentByte(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// buildJavaScriptCallerTaintedPaths scans the caller body up to (and
// including) callLineIdx and returns the set of bounded access paths that
// are tainted by a catalog source. It records BOTH:
//
//   - field assignments `o.cmd = req.body.cmd` → tainted path "o.cmd"
//     (and NOT "o" — so a sibling `o.other = "x"` read stays clean), and
//   - bare bindings `const x = req.body.q` → tainted path "x".
//
// The returned set feeds tsflow.PrefixTaintedPath: a composed caller arg
// path `o.cmd` is tainted iff some proper prefix of it (here exactly
// "o.cmd") is in the set. Literal / sanitized RHS assignments are NOT
// recorded, so `o.cmd = "ls"` leaves "o.cmd" out of the set.
//
// Keys are bounded with tsflow.BoundAccessPath so deep writes collapse to
// the same key a deep read query will.
func buildJavaScriptCallerTaintedPaths(callerLines []string, callLineIdx int) map[string]bool {
	out := map[string]bool{}
	limit := callLineIdx
	if limit >= len(callerLines) {
		limit = len(callerLines) - 1
	}
	for i := 0; i <= limit; i++ {
		line := callerLines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		eq := jsAssignEqExported(trimmed)
		if eq <= 0 {
			continue
		}
		lhs := strings.TrimSpace(trimmed[:eq])
		lhs = strings.TrimPrefix(lhs, "const ")
		lhs = strings.TrimPrefix(lhs, "let ")
		lhs = strings.TrimPrefix(lhs, "var ")
		lhs = strings.TrimSpace(lhs)
		rhs := trimmed[eq+1:]

		// LHS must be a plain identifier or a dotted access path
		// (`o.cmd`, `o.a.b`). Subscripts / destructuring patterns are out
		// of scope for the shallow dotted abstraction.
		lhsPath := jsLeadingAccessPath(lhs)
		if lhsPath == "" || lhsPath != strings.TrimSpace(lhs) {
			continue
		}
		key := tsflow.BoundAccessPath(lhsPath)

		if javascriptSanitizerRe.MatchString(rhs) {
			// Sanitized RHS clears any prior taint on this exact path.
			delete(out, key)
			continue
		}
		if javascriptSourceExprRe.MatchString(rhs) {
			out[key] = true
			continue
		}
		// RHS is a bare tainted variable already in the set
		// (`p = req.body; o.cmd = p`)? Propagate the taint to the LHS path.
		rhsPath := jsLeadingAccessPath(strings.TrimSpace(rhs))
		if rhsPath != "" {
			if tsflow.PrefixTaintedPath(tsflow.BoundAccessPath(rhsPath), out) {
				out[key] = true
				continue
			}
		}
		// Literal / non-tainted RHS: this assignment OVERWRITES the path,
		// so drop any stale taint (`o.cmd = req.body.cmd; o.cmd = "ls"`
		// must end clean).
		delete(out, key)
	}
	return out
}

// jsAssignEqExported is jsAssignEq, duplicated here only to avoid an
// import cycle risk — kept identical. Returns the index of the single `=`
// assignment operator, or -1.
func jsAssignEqExported(line string) int {
	return jsAssignEq(line)
}

// javaScriptCallerArgFieldTainted reports whether the composed caller arg
// field path is tainted in the caller's intra-file context. Used at the
// call-site sink gate when SinkRef.ArgFieldPath != "".
//
//	arg="o", argFieldPath="cmd" → query "o.cmd"; fires iff a tainted
//	prefix of "o.cmd" exists in the caller body.
//
// When the arg itself is already a dotted path (`run(o.payload)` with the
// sink reading `.cmd`) the composition is `o.payload.cmd`, bounded.
func javaScriptCallerArgFieldTainted(arg, argFieldPath string, taintedPaths map[string]bool) bool {
	arg = strings.TrimSpace(arg)
	if arg == "" || argFieldPath == "" {
		return false
	}
	// The arg must be a plain identifier or dotted path to compose with a
	// field suffix. Subscripted / call-expression args don't compose.
	argPath := jsLeadingAccessPath(arg)
	if argPath == "" || argPath != arg {
		return false
	}
	composed := tsflow.BoundAccessPath(argPath + "." + argFieldPath)
	return tsflow.PrefixTaintedPath(composed, taintedPaths)
}

// scanJavaScriptBodyForTaintedReturnPaths scans the callee body for a
// `return <object-literal>` whose fields carry catalog sources, and
// records the per-field tainted access paths under return index 0. This
// is the producer half of return-path composition.
//
//	return { user: { id: req.query.id }, name: "x" };
//	  → TaintedReturnPaths["0.user.id"] = [user_input]   (name stays out)
//
// Also handles `return v;` where `v` was built field-by-field
// (`const v = {}; v.user = req.query.id; return v;`) — those paths are
// "0.user", etc. Returns nil when no object-literal / field-built return
// with tainted fields is found (callers then fall back to whole-return).
func scanJavaScriptBodyForTaintedReturnPaths(body string) map[string][]taint.SourceCategory {
	lines := strings.Split(body, "\n")
	out := map[string][]taint.SourceCategory{}

	// Track per-variable field taint built up before a `return v`.
	// Key: "var.field.field" (bounded). Value: source cats.
	varFieldTaint := map[string][]taint.SourceCategory{}

	recordObjectLiteral := func(prefix, literal string) {
		for path, cats := range jsObjectLiteralTaintedPaths(literal) {
			key := tsflow.BoundAccessPath(prefix + "." + path)
			out[key] = appendUniqueCatList(out[key], cats)
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Field-built returns: `v.user.id = req.query.id`.
		if eq := jsAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			lhs = strings.TrimPrefix(lhs, "const ")
			lhs = strings.TrimPrefix(lhs, "let ")
			lhs = strings.TrimPrefix(lhs, "var ")
			lhs = strings.TrimSpace(lhs)
			rhs := trimmed[eq+1:]
			lhsPath := jsLeadingAccessPath(lhs)
			if lhsPath != "" && lhsPath == lhs && strings.Contains(lhsPath, ".") {
				key := tsflow.BoundAccessPath(lhsPath)
				if javascriptSourceExprRe.MatchString(rhs) && !javascriptSanitizerRe.MatchString(rhs) {
					varFieldTaint[key] = appendUniqueCatList(varFieldTaint[key], []taint.SourceCategory{taint.SrcUserInput})
				} else {
					delete(varFieldTaint, key)
				}
			}
		}
		// `return { ...object literal... }` — capture the FULL balanced
		// brace expression directly (jsReturnStmtRe stops at the first `}`,
		// which truncates a nested object literal, so we can't use it here).
		if ret := jsReturnObjectLiteral(trimmed); ret != "" {
			recordObjectLiteral("0", ret)
			continue
		}
		// `return <expr>` anywhere on the line (non-object forms).
		for _, m := range jsReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" {
				continue
			}
			// `return v` where v was built field-by-field.
			retVar := jsLastIdent(expr)
			if retVar == "" {
				continue
			}
			for key, cats := range varFieldTaint {
				// key is "v.user.id" → contribute "0.user.id".
				if base, ok := tsflow.IsFieldKey(key); ok && base == retVar {
					suffix := strings.TrimPrefix(key, retVar+".")
					outKey := tsflow.BoundAccessPath("0." + suffix)
					out[outKey] = appendUniqueCatList(out[outKey], cats)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// jsObjectLiteralTaintedPaths parses a (single-line) JS object literal and
// returns the dotted field paths whose value is a catalog source
// expression, mapped to their source categories. Nested object literals
// recurse with a dotted prefix.
//
//	{ user: { id: req.query.id }, name: "x" }
//	  → { "user.id": [user_input] }
//
// This is a deliberately small, brace-and-comma aware scanner — it is NOT
// a full JS parser. It handles the canonical handler-getter shape; deeper
// or computed-key literals fall through to whole-return.
func jsObjectLiteralTaintedPaths(literal string) map[string][]taint.SourceCategory {
	out := map[string][]taint.SourceCategory{}
	inner := jsStripOuterBraces(literal)
	if inner == "" {
		return out
	}
	for _, entry := range jsSplitTopLevelCommas(inner) {
		colon := jsTopLevelColon(entry)
		if colon < 0 {
			continue
		}
		keyRaw := strings.TrimSpace(entry[:colon])
		val := strings.TrimSpace(entry[colon+1:])
		key := jsUnquoteKey(keyRaw)
		if key == "" {
			continue
		}
		if strings.HasPrefix(val, "{") {
			for subPath, cats := range jsObjectLiteralTaintedPaths(val) {
				out[key+"."+subPath] = cats
			}
			continue
		}
		if javascriptSanitizerRe.MatchString(val) {
			continue
		}
		if javascriptSourceExprRe.MatchString(val) {
			out[key] = []taint.SourceCategory{taint.SrcUserInput}
		}
	}
	return out
}

// jsReturnObjectLiteral returns the balanced `{...}` object literal of a
// `return { ... }` statement on the line, or "" when the line isn't a
// return of a brace-wrapped literal. Brace-balance aware so nested object
// literals are captured whole (jsReturnStmtRe truncates at the first `}`).
func jsReturnObjectLiteral(line string) string {
	idx := strings.Index(line, "return")
	if idx < 0 {
		return ""
	}
	// `return` must be a token (preceded by start / non-ident).
	if idx > 0 && isJSIdentByte(line[idx-1]) {
		return ""
	}
	rest := strings.TrimSpace(line[idx+len("return"):])
	if rest == "" || rest[0] != '{' {
		return ""
	}
	lit := jsBalancedBraces(rest)
	if lit == "" {
		return ""
	}
	return lit
}

// jsBalancedBraces returns the substring of s from the leading `{` through
// its matching `}` (inclusive), or "" when s doesn't start with `{` or is
// unbalanced. String contents are skipped so braces inside string literals
// don't confuse the matcher.
func jsBalancedBraces(s string) string {
	if len(s) == 0 || s[0] != '{' {
		return ""
	}
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[:i+1]
			}
		}
	}
	return ""
}

// jsStripOuterBraces trims one matched leading `{` and trailing `}` from a
// trimmed literal, returning the inner text. Returns "" when s isn't
// brace-wrapped.
func jsStripOuterBraces(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' {
		return ""
	}
	// Find the matching closing brace for the first '{'.
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return strings.TrimSpace(s[1:i])
			}
		}
	}
	return ""
}

// jsSplitTopLevelCommas splits s on commas that are NOT nested inside
// braces / brackets / parens, so `a: 1, b: { c: 2, d: 3 }` yields
// ["a: 1", "b: { c: 2, d: 3 }"].
func jsSplitTopLevelCommas(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(s) {
		parts = append(parts, strings.TrimSpace(s[start:]))
	}
	return parts
}

// jsTopLevelColon returns the index of the first colon in s that is not
// nested inside braces / brackets / parens, or -1.
func jsTopLevelColon(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case ':':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// jsUnquoteKey strips surrounding quotes from an object key and validates
// it is a plain identifier. Returns "" for computed keys (`[expr]`) or
// non-identifier keys.
func jsUnquoteKey(k string) string {
	k = strings.TrimSpace(k)
	if len(k) >= 2 && (k[0] == '"' || k[0] == '\'') && k[len(k)-1] == k[0] {
		k = k[1 : len(k)-1]
	}
	if k == "" {
		return ""
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if c == '_' || c == '$' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return ""
	}
	return k
}

// boundReturnPath composes a return-path key "retIdx.field.field" and
// bounds it with the SAME abstraction the per-file engine uses
// (tsflow.BoundAccessPath), so deep return field reads collapse to the
// same key the producer seeded.
//
//	boundReturnPath("0", "user.id")     == "0.user.id"
//	boundReturnPath("0", "a.b.c.d")     == "0.a.b.c"   (bounded)
func boundReturnPath(retIdx, fieldPath string) string {
	if fieldPath == "" {
		return retIdx
	}
	return tsflow.BoundAccessPath(retIdx + "." + fieldPath)
}

// returnPathTainted reports whether a composed return-path read
// (`0.user.id`) hits a tainted return path, using the proper-prefix walk
// so a tainted `0.user` taints reads of `0.user.id` but not the sibling
// `0.name`.
func returnPathTainted(path string, taintedReturnPaths map[string][]taint.SourceCategory) bool {
	if len(taintedReturnPaths) == 0 {
		return false
	}
	set := make(map[string]bool, len(taintedReturnPaths))
	for k := range taintedReturnPaths {
		set[k] = true
	}
	return tsflow.PrefixTaintedPath(path, set)
}

// appendUniqueCatList merges src categories into dst, de-duplicating.
func appendUniqueCatList(dst, src []taint.SourceCategory) []taint.SourceCategory {
	for _, c := range src {
		dst = appendUniqueCat(dst, c)
	}
	return dst
}

// jsArgRootIsDirectlyTainted reports whether the arg expression is tainted
// at its ROOT because it is a direct catalog source (`req.body`) or a
// source-typed caller param (`req`), as opposed to a plain local object
// whose individual fields were assigned. This is the field-gate fallback:
// when a sink reads `param.cmd` and the caller passes a direct source
// (`run(req.body)`), the whole arg IS tainted at the source so the
// field-composed read of `req.body.cmd` is genuinely tainted even though
// no intra-file field assignment recorded it.
//
// It deliberately does NOT run the backward local-variable field trace —
// that is exactly what the field-path gate replaces, and re-admitting it
// would resurrect the over-approximation `o.cmd = "ls"` is supposed to
// suppress.
func jsArgRootIsDirectlyTainted(argExpr string, callerLines []string, callLineIdx int, callerSig *TaintSignature) bool {
	argTrim := strings.TrimSpace(argExpr)
	if argTrim == "" {
		return false
	}

	// Source-typed caller param: arg's root identifier is a source param.
	if callerSig != nil && len(callerSig.SourceParams) > 0 && len(callerSig.Params) > 0 {
		root := argTrim
		if dotIdx := strings.Index(root, "."); dotIdx > 0 {
			root = root[:dotIdx]
		}
		if bracketIdx := strings.Index(root, "["); bracketIdx > 0 {
			root = root[:bracketIdx]
		}
		root = strings.TrimSpace(root)
		for _, p := range callerSig.Params {
			if p.Name == "" || p.Name != root {
				continue
			}
			if _, isSource := callerSig.SourceParams[p.Index]; isSource {
				return true
			}
		}
	}

	// Direct catalog source expression in the arg itself (`req.body`).
	if javascriptSourceExprRe.MatchString(argExpr) {
		return true
	}

	// A bare local bound directly to a whole source (`const b = req.body;
	// run(b)`): the whole object b is tainted at its root, so the sink's
	// field read of `b.cmd` is a sub-path of a tainted root. We only honour
	// a WHOLE-object source binding here (RHS is a direct source, LHS is a
	// bare identifier) — NOT a field assignment, which the path gate owns.
	argVar := argTrim
	if dotIdx := strings.Index(argVar, "."); dotIdx > 0 {
		// arg is itself a field access — handled by the path gate, not here.
		return false
	}
	if bracketIdx := strings.Index(argVar, "["); bracketIdx > 0 {
		return false
	}
	argVar = strings.TrimSpace(argVar)
	if argVar == "" {
		return false
	}
	for i := callLineIdx - 1; i >= 0; i-- {
		line := callerLines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		eqIdx := jsAssignEq(trimmed)
		if eqIdx <= 0 {
			continue
		}
		lhs := strings.TrimSpace(trimmed[:eqIdx])
		lhs = strings.TrimPrefix(lhs, "const ")
		lhs = strings.TrimPrefix(lhs, "let ")
		lhs = strings.TrimPrefix(lhs, "var ")
		lhs = strings.TrimSpace(lhs)
		// Only a WHOLE-object binding to argVar (no field path on the LHS).
		if lhs != argVar {
			continue
		}
		rhs := trimmed[eqIdx+1:]
		if javascriptSanitizerRe.MatchString(rhs) {
			return false
		}
		if javascriptSourceExprRe.MatchString(rhs) {
			return true
		}
		// Bound to a literal / non-source — root not tainted.
		return false
	}
	return false
}
