package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// pythonPathGuardResult is returned by inferPythonPathGuard when a Python
// path-traversal-specific guard combo is recognised in an if-condition. It
// identifies the tainted variable that the guard validates and the sink
// categories the guard neutralises (always a subset of the path sinks:
// SnkFileRead, SnkFileWrite, SnkUpload).
//
// Mirrors Go's PR-HH design: single canonicalisation calls (normpath, resolve,
// realpath) are NOT sanitizers on their own — only the COMBO with a
// containment check (startswith / is_relative_to / commonpath ==) counts.
type pythonPathGuardResult struct {
	varName    string
	categories []taint.SinkCategory
}

// pythonPathSinkCategories is the set of sink categories that path-traversal
// guards neutralise. Always all-three (file read, write, upload) because the
// guards check the path / filename itself rather than any specific operation.
var pythonPathSinkCategories = []taint.SinkCategory{
	taint.SnkFileRead, taint.SnkFileWrite, taint.SnkUpload,
}

// inferPythonPathGuard inspects an if-statement's condition and reports
// whether it is a Python path-traversal guard combo on a tainted variable.
//
// Recognised positive patterns (the if-branch is the safe path):
//
//   - x.startswith(BASE)                  — after normalize/resolve
//   - x.is_relative_to(BASE)              — pathlib (Py 3.9+) containment
//   - str(x).startswith(str(BASE))        — string-comparison variant
//   - os.path.commonpath([BASE, x]) == BASE
//   - x.is_absolute() == False            — explicit reject-absolute check
//   - not x.is_absolute()                 — same intent
//
// Recognised negative patterns (the if-branch raises/returns, so fall-through
// is safe — detection is via processIfBranchAware's existing early-return
// handling combined with our category-scoped sanitisation):
//
//   - ".." in x / "../" in x              — manual rejection of escape seq
//   - x.is_absolute()                     — reject-absolute (early-return body)
//   - not x.startswith(BASE)              — reject anything outside BASE
//
// When the recognised variable was itself produced by os.path.normpath /
// os.path.realpath / os.path.abspath / Path(...).resolve(), the
// `pathDerivedFrom` link on the taint state lets the caller back-propagate
// path-category sanitisation to the original tainted source.
//
// Returns nil if no Python path-guard pattern was recognised.
func inferPythonPathGuard(cond *ast.Node, tm *taintMap, cfg *langConfig) *pythonPathGuardResult {
	if cond == nil || cfg == nil || cfg.language != rules.LangPython {
		return nil
	}

	// Unwrap parenthesised expressions: `if (x.startswith(...))`.
	cond = pyUnwrapParen(cond)

	// Boolean operators: `A and B`, `A or B` — recurse into both sides;
	// the first match wins. Python tree-sitter uses `boolean_operator`;
	// `binary_expression` is a defensive fallback.
	if cond.Type() == "boolean_operator" || cond.Type() == "binary_expression" {
		named := cond.NamedChildren()
		left := cond.ChildByFieldName("left")
		if left == nil && len(named) > 0 {
			left = named[0]
		}
		if r := inferPythonPathGuard(left, tm, cfg); r != nil {
			return r
		}
		right := cond.ChildByFieldName("right")
		if right == nil && len(named) > 1 {
			right = named[1]
		}
		return inferPythonPathGuard(right, tm, cfg)
	}

	// Negation: `not <inner>`. For symmetric path guards we treat negated
	// path-guard methods the same as positive ones — `not x.startswith(BASE)`
	// in a rejection if-body and `x.startswith(BASE)` in a safe if-body both
	// validate `x` against BASE.
	if cond.Type() == "not_operator" || cond.Type() == "unary_expression" {
		named := cond.NamedChildren()
		for _, c := range named {
			if r := inferPythonPathGuard(c, tm, cfg); r != nil {
				return r
			}
		}
		return nil
	}

	// Comparison patterns: `x == y`, `x != y`. Two cases of interest:
	//   - `commonpath([BASE, x]) == BASE` — containment via commonpath
	//   - `x.is_absolute() == False`      — reject absolute
	if cond.Type() == "comparison_operator" || cond.Type() == "binary_expression" {
		if r := pyMatchCommonpathEquality(cond, tm, cfg); r != nil {
			return r
		}
		if r := pyMatchIsAbsoluteCompare(cond, tm, cfg); r != nil {
			return r
		}
	}

	// Method-call patterns: `x.startswith(BASE)`, `x.is_relative_to(BASE)`,
	// `x.is_absolute()`. Tree-sitter Python represents these as a `call`
	// node whose `function` is an `attribute`.
	if cond.Type() == "call" {
		if r := pyMatchPathMethodCall(cond, tm, cfg); r != nil {
			return r
		}
	}

	// `".." in x` / `"../" in x` — Python `in` with a string-literal LHS and
	// a tainted RHS. (The complementary `x in [..]` allowlist pattern is
	// already handled by detectAllowlistCheck; we keep this branch narrow.)
	if cond.Type() == "comparison_operator" {
		if r := pyMatchDotDotInTainted(cond, tm, cfg); r != nil {
			return r
		}
	}

	return nil
}

// pyUnwrapParen strips parenthesised_expression nodes from a tree-sitter
// Python node, returning the inner expression.
func pyUnwrapParen(n *ast.Node) *ast.Node {
	for n != nil && n.Type() == "parenthesized_expression" {
		named := n.NamedChildren()
		if len(named) != 1 {
			break
		}
		n = named[0]
	}
	return n
}

// pyMatchPathMethodCall recognises path-specific guard method calls on a
// tainted variable:
//
//	x.is_relative_to(<arg>)    — pathlib (Py 3.9+) containment, ONLY a path guard
//	x.is_absolute()            — reject-absolute when paired with early return
//	x.startswith(<arg>)        — ONLY when the receiver carries a
//	                             pathDerivedFrom link or the literal arg
//	                             looks path-shaped (contains '/' or '\\')
//
// We deliberately do NOT match bare `startswith` / `endswith` calls that
// have no path context — those remain the domain of the generic
// detectValidationGuard, which clears taint for all categories (necessary
// for non-path string validation patterns such as the OWASP codeinj
// `not bar.startswith('\”)` quote-guard that protects eval()).
func pyMatchPathMethodCall(call *ast.Node, tm *taintMap, cfg *langConfig) *pythonPathGuardResult {
	methodName := strings.ToLower(cfg.extractCallName(call))
	if !pyIsPathGuardMethod(methodName) {
		return nil
	}

	// Find the receiver.
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return nil
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return nil
	}

	// Resolve the tainted base receiver.
	res := pyTaintedBaseInNode(obj, tm, cfg)
	if res == nil {
		return nil
	}

	// For startswith / endswith, gate on path context — either the
	// receiver was produced by a path canonicaliser, or the literal
	// argument looks path-shaped (contains '/' or '\\'). is_relative_to
	// and is_absolute are unambiguously path guards and need no gate.
	if methodName == "startswith" || methodName == "endswith" {
		if !pyHasPathContext(res.varName, call, tm, cfg) {
			return nil
		}
	}

	return &pythonPathGuardResult{
		varName:    res.varName,
		categories: pythonPathSinkCategories,
	}
}

// pyMatchBareStatementPathGuard recognises the CWE-22 containment idiom that
// appears as a BARE EXPRESSION STATEMENT (not an if-condition), where the
// guard works by RAISING rather than returning a bool that gates a branch:
//
//	file_path = unresolved.resolve()
//	file_path.relative_to(base)        # raises ValueError if file_path escapes base
//	... open(file_path)                # safe: the except clause already returned 404
//
// `Path.relative_to(base)` raises ValueError when the receiver is not within
// `base`; aiohttp's static file server, Flask blueprints, and many hand-rolled
// download handlers wrap exactly this call in `try: ... except (ValueError, ...):
// raise HTTPNotFound()`. Because the result is discarded, the if-only
// inferPythonPathGuard never sees it, and because nothing is assigned, the
// assignment-RHS sanitizer path never sees it either — so the path taint on the
// receiver survives all the way to the file sink and produces a false positive.
//
// We clear ONLY the path-traversal sink categories (read/write/upload) on the
// tainted receiver variable, leaving any SQL/command/etc. taint intact — the
// containment check says nothing about those.
//
// Anchoring (FP-only, never drops a real flow):
//   - `relative_to` is pathlib-specific and has no string-validation namesake,
//     so a bare `x.relative_to(base)` on a tainted `x` is unambiguously a
//     containment guard. (is_relative_to — the bool form — is handled as an
//     if-guard elsewhere; this is the raising form.)
//   - `realpath(...).startswith(...)` / `os.path.realpath(...).startswith(...)`
//     is recognised only when the startswith receiver is itself a realpath()
//     canonicalisation, mirroring the `normpath(x).startswith(BASE)` if-guard
//     but in the (rarer) bare-statement boolean-expression form.
//
// Returns nil when the node is not a recognised bare-statement path guard.
func pyMatchBareStatementPathGuard(call *ast.Node, tm *taintMap, cfg *langConfig) *pythonPathGuardResult {
	if call == nil || call.Type() != "call" {
		return nil
	}
	methodName := strings.ToLower(cfg.extractCallName(call))

	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return nil
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return nil
	}

	switch methodName {
	case "relative_to":
		// Receiver must carry path taint. `relative_to` raises on escape, so
		// the bare call is a containment guard. No path-context gate needed —
		// the method name is pathlib-exclusive.
		res := pyTaintedBaseInNode(obj, tm, cfg)
		if res == nil {
			return nil
		}
		res.categories = pythonPathSinkCategories
		return res

	case "startswith", "endswith":
		// Bare boolean-expression form of the realpath/normpath containment
		// check. Only treat it as a path guard when the receiver was produced
		// by a path canonicaliser (pathDerivedFrom) — gated exactly like the
		// if-condition startswith path to avoid stealing generic string
		// validation guards.
		res := pyTaintedBaseInNode(obj, tm, cfg)
		if res == nil {
			return nil
		}
		if !pyHasPathContext(res.varName, call, tm, cfg) {
			return nil
		}
		res.categories = pythonPathSinkCategories
		return res
	}
	return nil
}

// pyIsPathGuardMethod returns true for method names that may signal a
// path-traversal guard. startswith / endswith are gated further by
// pyHasPathContext — they're only path guards when the receiver came from
// a path canonicaliser or the argument is path-shaped.
func pyIsPathGuardMethod(name string) bool {
	switch name {
	case "startswith", "endswith",
		"is_relative_to",
		"is_absolute":
		return true
	}
	return false
}

// pyHasPathContext returns true when a startswith/endswith call on
// `varName` has enough surrounding context to be confidently classified
// as a path guard rather than a generic string-validation guard.
//
// Two signals count as path context:
//
//  1. The taint state for `varName` records a pathDerivedFrom link, meaning
//     this value was produced by normpath / realpath / abspath / resolve.
//  2. At least one of the call's string-literal arguments looks
//     path-shaped — contains a forward slash. We intentionally do NOT
//     accept identifier arguments as a path signal (a bare BASE could be
//     any string — falsely accepting it would re-introduce the OWASP
//     codeinj FPs where `not bar.startswith('\”)` guards eval()), and
//     we don't accept backslashes (the OWASP fixtures use `'\”` to
//     enforce a quoted-string literal, which technically contains a
//     backslash but is not a path separator).
func pyHasPathContext(varName string, call *ast.Node, tm *taintMap, cfg *langConfig) bool {
	if ts := tm.get(varName); ts != nil && ts.pathDerivedFrom != "" {
		return true
	}
	for _, arg := range cfg.extractCallArgs(call) {
		if arg == nil {
			continue
		}
		if arg.Type() != "string" && arg.Type() != "string_literal" &&
			arg.Type() != "concatenated_string" {
			continue
		}
		// Strip surrounding quotes when present.
		text := pyStringLiteralBody(arg.Text())
		if strings.Contains(text, "/") {
			return true
		}
	}
	return false
}

// pyStringLiteralBody strips a Python string literal's surrounding quotes
// (single, double, triple) leaving the literal content. Returns the
// original input when the shape isn't recognised — callers can still
// substring-search safely.
func pyStringLiteralBody(s string) string {
	// Strip string prefixes (b, r, f, br, rb, …) — Python supports any
	// case combination.
	i := 0
	for i < len(s) && (s[i] == 'b' || s[i] == 'B' || s[i] == 'r' || s[i] == 'R' ||
		s[i] == 'f' || s[i] == 'F' || s[i] == 'u' || s[i] == 'U') {
		i++
	}
	s = s[i:]
	if len(s) < 2 {
		return s
	}
	if strings.HasPrefix(s, `"""`) && strings.HasSuffix(s, `"""`) && len(s) >= 6 {
		return s[3 : len(s)-3]
	}
	if strings.HasPrefix(s, `'''`) && strings.HasSuffix(s, `'''`) && len(s) >= 6 {
		return s[3 : len(s)-3]
	}
	q := s[0]
	if (q == '"' || q == '\'') && s[len(s)-1] == q {
		return s[1 : len(s)-1]
	}
	return s
}

// pyMatchCommonpathEquality recognises:
//
//	os.path.commonpath([BASE, x]) == BASE
//	commonpath([BASE, x]) == BASE
//
// where one side is a commonpath() call referencing a tainted variable and
// the other side is the base.
func pyMatchCommonpathEquality(cmp *ast.Node, tm *taintMap, cfg *langConfig) *pythonPathGuardResult {
	// Tree-sitter Python comparison_operator: children are
	// [left, operator(==/!=), right] — operator is anonymous.
	named := cmp.NamedChildren()
	if len(named) < 2 {
		return nil
	}

	// Confirm the operator is `==` or `!=` (both work as containment guards).
	op := ""
	for i := 0; i < cmp.ChildCount(); i++ {
		c := cmp.Child(i)
		if !c.IsNamed() {
			if t := c.Text(); t == "==" || t == "!=" {
				op = t
				break
			}
		}
	}
	if op == "" {
		return nil
	}

	left, right := named[0], named[len(named)-1]
	if r := pyExtractCommonpathTaint(left, tm, cfg); r != nil {
		return r
	}
	if r := pyExtractCommonpathTaint(right, tm, cfg); r != nil {
		return r
	}
	return nil
}

// pyExtractCommonpathTaint matches a node of the form
// `os.path.commonpath([..., x, ...])` or `commonpath([..., x, ...])` and
// returns the first tainted identifier found in its argument list.
func pyExtractCommonpathTaint(n *ast.Node, tm *taintMap, cfg *langConfig) *pythonPathGuardResult {
	if n == nil || !cfg.callTypes[n.Type()] {
		return nil
	}
	name := strings.ToLower(cfg.extractCallName(n))
	if name != "commonpath" {
		return nil
	}
	args := cfg.extractCallArgs(n)
	for _, a := range args {
		if r := pyTaintedBaseInNode(a, tm, cfg); r != nil {
			return &pythonPathGuardResult{
				varName:    r.varName,
				categories: pythonPathSinkCategories,
			}
		}
	}
	return nil
}

// pyMatchIsAbsoluteCompare recognises `x.is_absolute() == False` (or `!= True`)
// as an explicit reject-absolute guard. Returns the tainted base variable.
func pyMatchIsAbsoluteCompare(cmp *ast.Node, tm *taintMap, cfg *langConfig) *pythonPathGuardResult {
	named := cmp.NamedChildren()
	if len(named) < 2 {
		return nil
	}
	for _, side := range []*ast.Node{named[0], named[len(named)-1]} {
		if side == nil || !cfg.callTypes[side.Type()] {
			continue
		}
		name := strings.ToLower(cfg.extractCallName(side))
		if name != "is_absolute" {
			continue
		}
		fn := side.ChildByFieldName("function")
		if fn == nil || fn.Type() != "attribute" {
			continue
		}
		obj := fn.ChildByFieldName("object")
		if obj == nil {
			continue
		}
		if r := pyTaintedBaseInNode(obj, tm, cfg); r != nil {
			return &pythonPathGuardResult{
				varName:    r.varName,
				categories: pythonPathSinkCategories,
			}
		}
	}
	return nil
}

// pyMatchDotDotInTainted recognises `".." in x` / `"../" in x` — a manual
// rejection of path-traversal sequences. Tree-sitter Python parses this as a
// comparison_operator with children [string, "in", identifier].
func pyMatchDotDotInTainted(cmp *ast.Node, tm *taintMap, cfg *langConfig) *pythonPathGuardResult {
	// Find the `in` operator token.
	hasIn := false
	for i := 0; i < cmp.ChildCount(); i++ {
		c := cmp.Child(i)
		if !c.IsNamed() && c.Text() == "in" {
			hasIn = true
			break
		}
	}
	if !hasIn {
		return nil
	}
	named := cmp.NamedChildren()
	if len(named) < 2 {
		return nil
	}
	lhs, rhs := named[0], named[len(named)-1]

	// LHS must be a string literal whose body contains a path-shaped
	// substring. The body is stripped of surrounding quotes to avoid
	// false matches on raw lexeme contents (e.g. `'\''` — a quoted
	// apostrophe used to guard against quote injection — has a literal
	// '\' in its raw form but no path content).
	if lhs == nil || (lhs.Type() != "string" && lhs.Type() != "string_literal") {
		return nil
	}
	body := pyStringLiteralBody(lhs.Text())
	// Reject when the body is a single character that is itself the
	// path-indicator characters but in an unambiguously non-path
	// context (a one-char literal like '/' is implausible as a path
	// fragment; the OWASP fixtures don't use that shape, and we'd
	// rather false-negative than re-introduce xpathi FPs).
	if !strings.Contains(body, "..") && !strings.Contains(body, "/") {
		return nil
	}
	// RHS must be a tainted variable (identifier or attribute chain).
	if r := pyTaintedBaseInNode(rhs, tm, cfg); r != nil {
		return &pythonPathGuardResult{
			varName:    r.varName,
			categories: pythonPathSinkCategories,
		}
	}
	return nil
}

// pyTaintedBaseInNode walks a sub-expression (identifier, attribute access,
// chained call) and returns the first tainted base variable found in the
// taint map. Mirrors taintedIdentInNode but recurses into call objects so
// `Path(BASE).joinpath(x).resolve()` resolves back to whichever of those
// idents is tainted.
func pyTaintedBaseInNode(n *ast.Node, tm *taintMap, cfg *langConfig) *pythonPathGuardResult {
	if n == nil {
		return nil
	}

	switch n.Type() {
	case "identifier", "variable_name":
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return &pythonPathGuardResult{varName: name}
		}
		return nil

	case "attribute":
		// Try the whole `obj.field` key first (field-sensitive taint),
		// then fall back to the base object.
		full := n.Text()
		if ts := tm.get(full); ts != nil && ts.source != nil {
			return &pythonPathGuardResult{varName: full}
		}
		obj := n.ChildByFieldName("object")
		return pyTaintedBaseInNode(obj, tm, cfg)

	case "call":
		// Recurse into the receiver chain (e.g. Path(x).resolve()) and
		// into each argument (e.g. commonpath([..., x])).
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "attribute" {
			obj := fn.ChildByFieldName("object")
			if r := pyTaintedBaseInNode(obj, tm, cfg); r != nil {
				return r
			}
		}
		args := cfg.extractCallArgs(n)
		for _, a := range args {
			if r := pyTaintedBaseInNode(a, tm, cfg); r != nil {
				return r
			}
		}
		return nil

	case "list", "tuple", "set":
		named := n.NamedChildren()
		for _, c := range named {
			if r := pyTaintedBaseInNode(c, tm, cfg); r != nil {
				return r
			}
		}
		return nil

	case "parenthesized_expression":
		return pyTaintedBaseInNode(pyUnwrapParen(n), tm, cfg)
	}

	return nil
}

// applyPythonPathGuard marks the given variable (and any path-derivation
// origin recorded on its taint state) as sanitized for the listed
// categories — without deleting the variable from the taint map. Used by
// processIfBranchAware when a Python-specific path-guard combo is recognised
// so that ONLY the file-traversal sinks are neutralised; other categories
// (SQL, command, etc.) remain tainted on the same variable.
func applyPythonPathGuard(tm *taintMap, res *pythonPathGuardResult) {
	if res == nil || tm == nil {
		return
	}
	pyMarkSanitized(tm, res.varName, res.categories)
	if ts := tm.get(res.varName); ts != nil && ts.pathDerivedFrom != "" {
		pyMarkSanitized(tm, ts.pathDerivedFrom, res.categories)
	}
}

// pyMarkSanitized adds the given sink categories to the taint state's
// sanitized set, without changing the variable's source / confidence /
// flow steps. Idempotent.
func pyMarkSanitized(tm *taintMap, varName string, cats []taint.SinkCategory) {
	ts := tm.get(varName)
	if ts == nil {
		return
	}
	if ts.sanitized == nil {
		ts.sanitized = make(map[taint.SinkCategory]bool)
	}
	for _, c := range cats {
		ts.sanitized[c] = true
	}
}

// pyResolveTaintOriginInReceiver returns the name of the tainted variable
// that feeds the receiver of a Python path-canonicaliser call, if any.
// Used by propagateCallResultInterproc to set pathDerivedFrom on a receiver-
// tainted .resolve() / .normpath() / etc. call result whose receiver is a
// `Path(base) / x` or `x.joinpath(y)` style expression, so a downstream
// containment guard (startswith / is_relative_to) clears the original
// variable's path-sink taint.
//
// The returned name MUST identify the user-input-bearing operand (the
// non-base side of the join), not the constant base. We approximate this
// by returning the first tainted identifier reached in the receiver
// sub-tree — which is the actual user-input variable on the OWASP
// Benchmark Python "(testfiles / bar).resolve()" shape because `testfiles`
// is a pathlib.Path of a hardcoded constant and is never tainted.
//
// Returns "" if no tainted variable can be identified.
func pyResolveTaintOriginInReceiver(call *ast.Node, tm *taintMap, cfg *langConfig) string {
	if call == nil {
		return ""
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return ""
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return ""
	}
	// Walk the receiver: parenthesised binary `/` joins, .joinpath() chains,
	// Path(x), and bare idents all converge on pyTaintedBaseInNode, which
	// returns the first tainted identifier reached.
	if r := pyTaintedBaseInNode(obj, tm, cfg); r != nil {
		return r.varName
	}
	// Also inspect a binary_operator receiver directly (PR-PATHpy): tree-sitter
	// Python parses `testfiles / bar` as a `binary_operator` with two operand
	// fields. pyTaintedBaseInNode doesn't handle this type explicitly, so we
	// scan its named children for a tainted identifier.
	if obj.Type() == "binary_operator" || obj.Type() == "binary_expression" {
		for _, c := range obj.NamedChildren() {
			if r := pyTaintedBaseInNode(c, tm, cfg); r != nil {
				return r.varName
			}
		}
	}
	// And a parenthesised binary_operator like `(testfiles / bar)`.
	if obj.Type() == "parenthesized_expression" {
		inner := pyUnwrapParen(obj)
		if inner != nil && (inner.Type() == "binary_operator" || inner.Type() == "binary_expression") {
			for _, c := range inner.NamedChildren() {
				if r := pyTaintedBaseInNode(c, tm, cfg); r != nil {
					return r.varName
				}
			}
		}
	}
	return ""
}

// isPythonPathCanonicalizer reports whether a call expression is a known
// path canonicalisation function whose output should record a back-link to
// the input via taintState.pathDerivedFrom. These functions are NOT
// sanitizers on their own — but a downstream containment guard on the
// result also validates the original tainted input for the path sinks.
//
// Recognised:
//   - os.path.normpath(x)
//   - os.path.realpath(x)
//   - os.path.abspath(x)
//   - Path(x).resolve()           — receiver call on a Path-like object
//   - x.resolve()                 — bare receiver call
//
// The caller decides which argument to link from (the first argument for
// free functions, the receiver for chained-call canonicalizers).
func isPythonPathCanonicalizer(n *ast.Node, cfg *langConfig) (kind string, ok bool) {
	if n == nil || !cfg.callTypes[n.Type()] {
		return "", false
	}
	name := strings.ToLower(cfg.extractCallName(n))
	switch name {
	case "normpath", "realpath", "abspath":
		return "freefunc", true
	case "resolve":
		// `.resolve()` is so generic that we only trust it as a path
		// canonicalizer when the receiver looks Path-shaped — but the
		// guard recogniser uses pathDerivedFrom only opportunistically,
		// so accepting any `.resolve()` here is acceptable.
		return "method", true
	}
	return "", false
}
