package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
)

// barrier_guards.go implements language-configurable BARRIER-GUARD
// flow-sensitivity. A "barrier guard" is a validation check
// in an if-condition that makes a tainted value safe on the guarded path —
// e.g. `if (/^[0-9]+$/.test(id)) { use(id) }` (JS), `if (id.matches("[A-Za-z0-9]+"))`
// (Java), or `if (typeof id === "number")`. Mature SAST tools model these; this lifts
// the Python path-guard mechanism (inferPythonPathGuard / applyPythonPathGuard)
// into a shared, per-langConfig-driven mechanism so JS/TS and Java get it too.
//
// DESIGN PRINCIPLES (conservative — recall preservation is paramount):
//
//   - Category-scoped, not wholesale. Like applyPythonPathGuard, a guard marks
//     the SPECIFIC validated variable as sanitized for the SPECIFIC sink
//     categories it neutralises. It NEVER deletes the variable from the taint
//     map, so a different sink category (or a different variable) still fires.
//   - Strict-charset proof. A regex/format guard only sanitizes injection sinks
//     when we can PROVE the validation constrains the value to a safe character
//     set (alphanumerics + a short list of innocuous separators). A regex that
//     permits ANY metacharacter, or is unanchored, sanitizes nothing — we
//     would rather miss the FP suppression than silence a real vuln.
//   - A length check, an emptiness check, or a loose `.includes("x")` test
//     sanitizes NOTHING — those don't constrain the value's content.
//   - Opt-in per language. Driven by langConfig.barrierGuards; nil for every
//     language that doesn't wire it, so their taint flows are byte-unchanged.

// barrierGuardResult identifies a tainted variable that an if-condition guard
// validates, and the sink categories the guard neutralises on the guarded path.
type barrierGuardResult struct {
	varName    string
	categories []taint.SinkCategory
}

// barrierGuardConfig holds the per-language node-type shapes the barrier-guard
// recogniser needs. The recognition logic in inferBarrierGuard is shared; this
// config tells it which tree-sitter node types and method/operator spellings to
// look for in the host language.
type barrierGuardConfig struct {
	// regexTestMethods are method names that test a value against a regex and
	// return a boolean on the GUARDED (true) path. The value being validated is
	// found per-language (the regex receiver's argument for JS `re.test(x)`, or
	// the call receiver for Java `x.matches(re)`).
	regexTestMethods map[string]bool

	// numericTypeofKeyword, when non-empty, enables recognition of
	// `typeof x === "number"` (JS/TS) as a numeric barrier guard.
	enableTypeofNumber bool

	// enableJavaNumericParse enables recognition of `Integer.parseInt(x)` /
	// `Long.parseLong(x)` etc. appearing in a guard condition as a numeric
	// coercion barrier (Java).
	enableJavaNumericParse bool

	// regexFuncGuards are FREE-FUNCTION names that validate a value against a
	// regex passed as a STRING-LITERAL argument, with the validated variable as
	// a LATER positional argument. PHP `preg_match("/^[0-9]+$/", $x)` is the
	// canonical shape (pattern arg0, variable arg1). Unlike regexTestMethods
	// (which are receiver methods), these are bare calls with no receiver. The
	// pattern argument is scanned with the SAME scanSafeRegexBody charset proof
	// (fail-closed on metacharacters, anchors required), so only a strict
	// charset regex sanitizes. Empty for languages that don't use this shape.
	regexFuncGuards map[string]bool

	// charsetFuncGuards are FREE-FUNCTION names that, when they return true,
	// prove their (first) argument is constrained to a SAFE CHARACTER SET or a
	// numeric value — e.g. PHP `ctype_digit($x)` (decimal digits only),
	// `ctype_alnum($x)` (alphanumerics only), `is_numeric($x)` (a numeric
	// string). On the guarded path the value carries no injection
	// metacharacter, so all safeCharsetCategories are neutralised. These need
	// NO regex to scan — the function itself is the proof. Empty for languages
	// that don't use this shape.
	charsetFuncGuards map[string]bool

	// regexMatchMethods are RECEIVER METHODS whose argument is a REGEX-LITERAL
	// node (not a string) and whose receiver is the validated variable — Ruby
	// `x.match?(/\A[0-9]+\z/)`. The regex node's body is extracted per-language
	// (langRegexLiteralBody) and scanned with scanSafeRegexBody. Distinct from
	// regexTestMethods, where JS passes the variable as the argument and Java
	// passes a string-literal pattern. Empty for languages that don't use it.
	regexMatchMethods map[string]bool

	// enableRubyRegexMatchOp enables recognition of the Ruby `x =~ /\A\d+\z/`
	// binary match operator as a barrier guard on the left-hand variable when
	// the right-hand regex literal constrains to a safe charset.
	enableRubyRegexMatchOp bool

	// numericCoercionFuncs are coercion calls that, appearing in a guard
	// condition, prove their argument parses to a numeric value on the guarded
	// path. Ruby `Integer(x)` raises ArgumentError on a non-numeric string, so a
	// condition that calls `Integer(x)` only proceeds when x is numeric. The
	// receiver (if any) must be empty / a bare callee name. Empty for languages
	// that don't use this shape.
	numericCoercionFuncs map[string]bool

	// numericCoercionMethods are receiver METHODS that coerce their receiver to
	// a numeric value — Ruby `x.to_i`. When such a call appears inside a guard
	// COMPARISON (`x.to_i > 0`), the receiver `x` is being range-checked as a
	// number on the guarded path. Conservative: only recognised as the operand
	// of a comparison (mirrors Java parseInt-in-comparison). Empty otherwise.
	numericCoercionMethods map[string]bool

	// langRegexLiteralBody, when non-nil, extracts the de-delimited pattern body
	// of a host-language REGEX-LITERAL node (Ruby `/.../`, where the body is
	// split across escape_sequence / string_content children). Used by the
	// regexMatchMethods / =~ paths. nil for languages whose regex guards use
	// string-literal patterns (PHP/Java) or JS regex nodes (handled inline).
	langRegexLiteralBody func(*ast.Node) string

	// argUnwrap, when non-nil, unwraps a call-argument WRAPPER node to the inner
	// expression before identifier/literal inspection — PHP wraps each call
	// argument in an `argument` node (`function_call_expression > arguments >
	// argument > variable_name`). nil for languages whose extractCallArgs
	// already yields bare expression nodes (JS/Java/Ruby).
	argUnwrap func(*ast.Node) *ast.Node
}

// jsBarrierGuardConfig returns the barrier-guard config for JavaScript (shared
// by TypeScript via tsConfig). Recognises `/re/.test(x)` regex guards and
// `typeof x === "number"` numeric type guards.
func jsBarrierGuardConfig() *barrierGuardConfig {
	return &barrierGuardConfig{
		regexTestMethods:   map[string]bool{"test": true},
		enableTypeofNumber: true,
	}
}

// javaBarrierGuardConfig returns the barrier-guard config for Java. Recognises
// `x.matches("re")` / `Pattern.matches("re", x)` regex guards and
// `Integer.parseInt(x)` numeric-coercion guards.
func javaBarrierGuardConfig() *barrierGuardConfig {
	return &barrierGuardConfig{
		regexTestMethods:       map[string]bool{"matches": true},
		enableJavaNumericParse: true,
	}
}

// phpBarrierGuardConfig returns the barrier-guard config for PHP. Recognises
// `preg_match("/^[0-9]+$/", $x)` strict-charset regex guards, the ctype /
// is_numeric charset predicates (`ctype_digit($x)`, `ctype_alnum($x)`,
// `is_numeric($x)`), all as FREE-FUNCTION calls (no receiver). PHP wraps each
// call argument in an `argument` node, so argUnwrap peels that off before the
// shared identifier/literal inspection runs.
func phpBarrierGuardConfig() *barrierGuardConfig {
	return &barrierGuardConfig{
		regexFuncGuards: map[string]bool{"preg_match": true},
		charsetFuncGuards: map[string]bool{
			"ctype_digit": true,
			"ctype_alnum": true,
			"is_numeric":  true,
		},
		argUnwrap: phpUnwrapArgument,
	}
}

// rubyBarrierGuardConfig returns the barrier-guard config for Ruby. Recognises
// `x.match?(/\A[0-9]+\z/)` strict-charset regex method guards, the `x =~ /.../`
// match operator, `Integer(x)` numeric-coercion guards, and `x.to_i`
// numeric-coercion comparisons. Ruby regex literals are `regex` nodes whose
// body is split across escape_sequence / string_content children, so
// langRegexLiteralBody reassembles the de-delimited pattern.
func rubyBarrierGuardConfig() *barrierGuardConfig {
	return &barrierGuardConfig{
		regexMatchMethods:      map[string]bool{"match?": true},
		enableRubyRegexMatchOp: true,
		numericCoercionFuncs:   map[string]bool{"Integer": true},
		numericCoercionMethods: map[string]bool{"to_i": true},
		langRegexLiteralBody:   rubyRegexLiteralBody,
	}
}

// phpUnwrapArgument peels a PHP `argument` wrapper node down to its inner
// expression. tree-sitter-php models every call argument as
// `arguments > argument > <expr>`, so the bare identifier / literal the
// barrier-guard recogniser wants is one level below the node extractCallArgs
// hands back. A no-op for any node that isn't an `argument` wrapper.
func phpUnwrapArgument(n *ast.Node) *ast.Node {
	if n == nil || n.Type() != "argument" {
		return n
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			return c
		}
	}
	return n
}

// rubyRegexLiteralBody reassembles the de-delimited body of a Ruby `regex`
// literal node `/.../`. tree-sitter-ruby splits the body across
// `escape_sequence` (e.g. `\A`, `\z`, `\d`) and `string_content` children,
// with `/` delimiter tokens at the ends. We concatenate the inner pieces in
// source order, dropping only the delimiter `/` tokens. Ruby anchors `\A`/`\z`
// are normalised to `^`/`$` so the shared regexConstrainsToSafeCharset anchor
// check (which expects `^...$`) accepts them. An interpolation child
// (`interpolation` / `#{...}`) makes the pattern non-static, so we bail to ""
// (fail closed — an interpolated regex proves nothing about the value).
func rubyRegexLiteralBody(reg *ast.Node) string {
	if reg == nil || reg.Type() != "regex" {
		return ""
	}
	var b strings.Builder
	for i := 0; i < reg.ChildCount(); i++ {
		c := reg.Child(i)
		switch c.Type() {
		case "/", "regex_flags":
			// delimiter or trailing flags — skip.
			continue
		case "escape_sequence":
			b.WriteString(c.Text())
		case "string_content":
			b.WriteString(c.Text())
		default:
			if !c.IsNamed() {
				// stray punctuation token inside the literal — keep it so the
				// charset scan can reject anything dangerous.
				b.WriteString(c.Text())
				continue
			}
			// A named child we don't model (interpolation, etc.) → not static.
			return ""
		}
	}
	body := b.String()
	// Normalise Ruby anchors to the `^...$` form the shared anchor check wants.
	// CRITICAL: only emit a `^` / `$` anchor when the corresponding Ruby anchor
	// (`\A` start, `\z` / `\Z` end) was actually present. An UNANCHORED Ruby
	// regex (`/[0-9]+/`) proves only that the value CONTAINS the pattern, not
	// that the whole string matches — so it must come back unanchored and be
	// REJECTED by the "test"-path anchor requirement. Adding anchors
	// unconditionally would silence a real vuln (recall loss).
	hasStart := strings.HasPrefix(body, `\A`)
	if hasStart {
		body = strings.TrimPrefix(body, `\A`)
	}
	trimmed := rubyTrimEndAnchor(body)
	hasEnd := trimmed != body
	body = trimmed
	if body == "" {
		return ""
	}
	if hasStart {
		body = "^" + body
	}
	if hasEnd {
		body = body + "$"
	}
	return body
}

// rubyTrimEndAnchor strips a trailing Ruby end-of-string anchor (`\z` or `\Z`)
// from a regex body. `\z` matches only at the very end; `\Z` allows an optional
// trailing newline, which is still within our safe model for charset proofs.
func rubyTrimEndAnchor(s string) string {
	if strings.HasSuffix(s, `\z`) {
		return strings.TrimSuffix(s, `\z`)
	}
	if strings.HasSuffix(s, `\Z`) {
		return strings.TrimSuffix(s, `\Z`)
	}
	return s
}

// safeCharsetCategories is the set of sink categories that a value constrained
// to a SAFE CHARACTER SET (alphanumerics + innocuous separators, no shell / SQL
// / HTML / path / template metacharacters) cannot exploit. A strict anchored
// regex, a numeric-only regex, or a numeric type/parse check all neutralise
// every one of these.
//
// Deliberately EXCLUDES SnkCrypto and SnkDeserialize: constraining a value to
// `[A-Za-z0-9]` does not make it safe to use as a crypto key/secret nor safe to
// deserialise (a base64-safe charset is still a valid serialised payload).
var safeCharsetCategories = []taint.SinkCategory{
	taint.SnkSQLQuery, taint.SnkNoSQL, taint.SnkCSV, taint.SnkUpload,
	taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput,
	taint.SnkEval, taint.SnkRedirect, taint.SnkLDAP, taint.SnkXPath,
	taint.SnkHeader, taint.SnkTemplate, taint.SnkLog, taint.SnkURLFetch,
	taint.SnkTrustBoundary, taint.SnkRegexDoS, taint.SnkPrototype,
}

// inferBarrierGuard inspects an if-statement's condition and reports whether it
// is a recognised barrier guard on a tainted variable. Returns nil when the
// language hasn't opted in (cfg.barrierGuards == nil) or no guard is found.
//
// Recognised positive shapes (the if-branch is the guarded/safe path):
//
//	JS/TS:  /^[0-9]+$/.test(x)            strict-charset regex literal
//	        SAFE_RE.test(x)              (only when the regex literal is inline)
//	        typeof x === "number"         numeric type check
//	Java:   x.matches("[A-Za-z0-9]+")     strict-charset regex (String.matches)
//	        Pattern.matches("\\d+", x)    strict-charset regex (Pattern.matches)
//	        Integer.parseInt(x) ...       numeric coercion in the condition
//
// Negated forms (`if (!/.../.test(x)) return;`) are NOT specially handled here:
// the walker's branchHasEarlyReturn fall-through path applies the same
// sanitisation to the post-if taint map, and a negated guard whose body returns
// is the dominant rejection idiom — see processIfBranchAware.
func inferBarrierGuard(cond *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	if cond == nil || cfg == nil || cfg.barrierGuards == nil {
		return nil
	}
	return inferBarrierGuardRec(cond, tm, cfg, 0)
}

// inferBarrierGuardRec is the recursive worker. depth guards against runaway
// recursion on pathological boolean trees.
func inferBarrierGuardRec(cond *ast.Node, tm *taintMap, cfg *langConfig, depth int) *barrierGuardResult {
	if cond == nil || depth > 16 {
		return nil
	}

	// Unwrap parentheses.
	for cond.Type() == "parenthesized_expression" {
		named := cond.NamedChildren()
		if len(named) != 1 {
			break
		}
		cond = named[0]
	}

	// Boolean operators: `A && B`, `A || B`. A barrier guard on EITHER operand
	// validates that variable. Recurse into both sides; the first match wins.
	// (We only ever ADD sanitisation for a variable that is actually validated
	// by one of the operands, so descending both sides is conservative.)
	switch cond.Type() {
	case "binary_expression", "boolean_operator", "binary":
		// "binary" is tree-sitter-ruby's node type for BOTH boolean operators
		// (`a && b`) and comparison / match operators (`x > 0`, `x =~ /re/`).
		op := boolOperatorToken(cond)
		named := cond.NamedChildren()
		left := cond.ChildByFieldName("left")
		if left == nil && len(named) > 0 {
			left = named[0]
		}
		right := cond.ChildByFieldName("right")
		if right == nil && len(named) > 1 {
			right = named[len(named)-1]
		}
		switch op {
		case "&&", "and":
			// Conjunction: the if-body runs only when BOTH operands held, so a
			// guard on EITHER operand definitely validated its variable on the
			// path into the body. Recurse into both sides; first match wins.
			//
			// We deliberately do NOT recurse for `||` / `or`: with `A || guard(x)`
			// the body can run when A is true and guard(x) is false, so x is NOT
			// validated on all paths into the body — treating it as sanitized
			// there would silence a real vuln. Recall preservation > FP cleanup.
			if r := inferBarrierGuardRec(left, tm, cfg, depth+1); r != nil {
				return r
			}
			if r := inferBarrierGuardRec(right, tm, cfg, depth+1); r != nil {
				return r
			}
		case "=~":
			// Ruby `x =~ /\A\d+\z/` match operator — the left operand is the
			// validated variable, the right operand the regex literal. Only a
			// strict-charset anchored regex sanitizes (fail-closed otherwise).
			if cfg.barrierGuards.enableRubyRegexMatchOp {
				if r := matchRubyRegexMatchOp(left, right, tm, cfg); r != nil {
					return r
				}
			}
		default:
			// Comparison operator (`>`, `>=`, `==`, …): the only barrier shapes
			// that hide inside a comparison are numeric-coercion guards such as
			// `Integer.parseInt(x) > 0` (Java) or `x.to_i > 0` (Ruby). Descend
			// into the operands looking ONLY for a numeric-coercion call (regex
			// guards are never the operand of a comparison, so we don't descend
			// for those — keeps it tight).
			for _, side := range []*ast.Node{left, right} {
				if side == nil || !cfg.callTypes[side.Type()] {
					continue
				}
				if cfg.barrierGuards.enableJavaNumericParse {
					if r := matchJavaNumericParseGuard(side, tm, cfg); r != nil {
						return r
					}
				}
				if len(cfg.barrierGuards.numericCoercionMethods) > 0 {
					if r := matchNumericCoercionMethodGuard(side, tm, cfg); r != nil {
						return r
					}
				}
				if len(cfg.barrierGuards.numericCoercionFuncs) > 0 {
					if r := matchNumericCoercionFuncGuard(side, tm, cfg); r != nil {
						return r
					}
				}
			}
		}
	}

	// typeof x === "number" / "bigint" — numeric type guard (JS/TS).
	if cfg.barrierGuards.enableTypeofNumber {
		if r := matchTypeofNumberGuard(cond, tm, cfg); r != nil {
			return r
		}
	}

	// Regex `.test()` / `.matches()` call shapes and Java numeric-parse guards.
	if cfg.callTypes[cond.Type()] {
		if r := matchRegexTestGuard(cond, tm, cfg); r != nil {
			return r
		}
		if cfg.barrierGuards.enableJavaNumericParse {
			if r := matchJavaNumericParseGuard(cond, tm, cfg); r != nil {
				return r
			}
		}
		// PHP free-function regex/charset guards: preg_match("...", $x),
		// ctype_digit($x), is_numeric($x).
		if len(cfg.barrierGuards.regexFuncGuards) > 0 {
			if r := matchRegexFuncGuard(cond, tm, cfg); r != nil {
				return r
			}
		}
		if len(cfg.barrierGuards.charsetFuncGuards) > 0 {
			if r := matchCharsetFuncGuard(cond, tm, cfg); r != nil {
				return r
			}
		}
		// Ruby receiver-regex method guard: x.match?(/\A\d+\z/).
		if len(cfg.barrierGuards.regexMatchMethods) > 0 {
			if r := matchRegexMatchMethodGuard(cond, tm, cfg); r != nil {
				return r
			}
		}
		// Ruby bare numeric-coercion guard: `if Integer(id)` (no comparison).
		if len(cfg.barrierGuards.numericCoercionFuncs) > 0 {
			if r := matchNumericCoercionFuncGuard(cond, tm, cfg); r != nil {
				return r
			}
		}
	}

	return nil
}

// boolOperatorToken returns the operator spelling of a binary/boolean operator
// node (e.g. "&&", "||", "and", "or", "===", ">"), or "" if none found.
func boolOperatorToken(n *ast.Node) string {
	if op := n.ChildByFieldName("operator"); op != nil {
		return op.Text()
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if !c.IsNamed() {
			if t := c.Text(); t != "" {
				return t
			}
		}
	}
	return ""
}

// matchRegexTestGuard recognises a regex-validation call on a tainted variable
// and, when the regex constrains the value to a safe character set, returns the
// validated variable with the full safe-charset category set.
//
// Two host-language shapes are handled via cfg.barrierGuards.regexTestMethods:
//
//	JS/TS:  /<pattern>/.test(x)   — receiver is the regex literal, x is arg 0
//	Java:   x.matches("<pat>")    — receiver x is the variable, pattern is arg 0
//	Java:   Pattern.matches("<pat>", x) — static, pattern arg 0, x arg 1
func matchRegexTestGuard(call *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	method := strings.ToLower(cfg.extractCallName(call))
	if !cfg.barrierGuards.regexTestMethods[method] {
		return nil
	}

	// Resolve (patternText, validatedVar) for each recognised shape.
	pattern, varName := extractRegexGuardParts(call, method, tm, cfg)
	if pattern == "" || varName == "" {
		return nil
	}
	if !regexConstrainsToSafeCharset(pattern, method) {
		return nil
	}
	return &barrierGuardResult{varName: varName, categories: safeCharsetCategories}
}

// extractRegexGuardParts pulls the regex pattern text and the validated tainted
// variable name out of a regex-test call, per host-language shape. Returns
// ("", "") when the shape doesn't match or no tainted variable is involved.
func extractRegexGuardParts(call *ast.Node, method string, tm *taintMap, cfg *langConfig) (pattern, varName string) {
	fn := call.ChildByFieldName("function")
	args := cfg.extractCallArgs(call)

	// Shape A (JS): /re/.test(x)  — function is a member_expression whose
	// `object` is a `regex` node; the validated variable is the first argument.
	if fn != nil && fn.Type() == "member_expression" {
		obj := fn.ChildByFieldName("object")
		if obj != nil && obj.Type() == "regex" {
			pat := jsRegexPatternText(obj)
			if pat == "" {
				return "", ""
			}
			if len(args) == 0 {
				return "", ""
			}
			if v := taintedBareIdentName(args[0], tm, cfg); v != "" {
				return pat, v
			}
			return "", ""
		}
	}

	// Shape B (Java): x.matches("re")  — receiver is the variable, pattern is
	// the first (string-literal) argument.
	if method == "matches" {
		recv := cfg.extractCallReceiver(call)
		if recv != "" && recv != "Pattern" {
			if ts := tm.get(recv); ts != nil && ts.source != nil {
				if len(args) >= 1 {
					if pat, ok := stringLiteralText(args[0]); ok {
						return unescapeJavaStringForRegex(pat), recv
					}
				}
			}
		}
		// Shape C (Java): Pattern.matches("re", x) — static call, pattern arg 0,
		// variable arg 1.
		if recv == "Pattern" && len(args) >= 2 {
			if pat, ok := stringLiteralText(args[0]); ok {
				if v := taintedBareIdentName(args[1], tm, cfg); v != "" {
					return unescapeJavaStringForRegex(pat), v
				}
			}
		}
	}

	return "", ""
}

// unescapeJavaStringForRegex collapses Java source-level string escapes into the
// runtime regex string. The only escape that matters for our safe-charset scan
// is the doubled backslash: in Java source `"\\d+"` is the runtime string
// `\d+`, i.e. the regex `\d+`. Without this collapse, scanSafeRegexBody would
// see `\\d+` (escaped backslash + literal `d`) and reject a perfectly safe
// digit guard. Any escape we don't model is left as-is, which only ever costs
// an FP-suppression (fails closed), never recall.
func unescapeJavaStringForRegex(s string) string {
	if !strings.Contains(s, `\\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '\\' {
			b.WriteByte('\\')
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// jsRegexPatternText returns the body of a JS regex literal node `/pat/flags`,
// stripping the surrounding slashes and trailing flags. Returns "" when a
// case-insensitive (`i`) flag is present — an `i` flag widens the accepted set
// and we conservatively decline to treat such a regex as a barrier (the
// safe-charset check below already covers letters, so this only loses the rare
// FP-suppression, never recall).
func jsRegexPatternText(reg *ast.Node) string {
	// The regex literal has a `regex_pattern` child for the body and an
	// optional `regex_flags` child.
	var body string
	var flags string
	for i := 0; i < reg.ChildCount(); i++ {
		c := reg.Child(i)
		switch c.Type() {
		case "regex_pattern":
			body = c.Text()
		case "regex_flags":
			flags = c.Text()
		}
	}
	if body == "" {
		// Fall back to stripping slashes from the raw text.
		raw := reg.Text()
		if len(raw) >= 2 && raw[0] == '/' {
			if idx := strings.LastIndex(raw, "/"); idx > 0 {
				body = raw[1:idx]
				flags = raw[idx+1:]
			}
		}
	}
	if strings.ContainsAny(flags, "iu") {
		// `i` widens letter matching; `u` may enable unicode property classes
		// we don't model. Both are handled fine by the charset analysis for the
		// common safe cases, but to stay strictly conservative we decline.
		// (Letters are already in the safe set, so `i` rarely matters; declining
		// only costs an occasional FP-suppression.)
		return ""
	}
	return body
}

// stringLiteralText returns the unquoted body of a string-literal node and true,
// or ("", false) for non-string nodes. Handles the common single/double-quote
// forms used by Java/JS/TS string literals plus PHP's `encapsed_string` /
// `string` nodes (which carry a `string_content` child).
func stringLiteralText(n *ast.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Type() {
	case "string_literal", "string":
		s := n.Text()
		if len(s) >= 2 {
			q := s[0]
			if (q == '"' || q == '\'') && s[len(s)-1] == q {
				return s[1 : len(s)-1], true
			}
		}
		// string node may wrap a string_fragment / string_content child.
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.Type() == "string_fragment" || c.Type() == "string_content" {
				return c.Text(), true
			}
		}
		return s, true
	case "encapsed_string":
		// PHP double/single-quoted string. The pattern body is the
		// `string_content` child. If there is an `interpolation` /
		// `variable_name` child, the string is NOT static, so bail — an
		// interpolated regex proves nothing. Concatenate only string_content,
		// rejecting on any non-static piece.
		var body string
		seen := false
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			switch c.Type() {
			case "string_content":
				body += c.Text()
				seen = true
			case `"`, "'", "encapsed_string_chars":
				continue
			default:
				if c.IsNamed() {
					// interpolation / variable_name etc. → not a static literal.
					return "", false
				}
			}
		}
		if !seen {
			return "", false
		}
		return body, true
	}
	return "", false
}

// regexConstrainsToSafeCharset reports whether a regex pattern PROVABLY limits
// the matched value to a safe character set: alphanumerics plus a short list of
// innocuous separators (`_`, `-`, `.` for Java where `.` is literal only inside
// a class, space). The check requires the pattern to be FULLY ANCHORED
// (`^...$`) so it constrains the whole string, then verifies every character
// class and literal in the body is drawn from the safe alphabet.
//
// Anything we don't recognise — alternation, backreferences, unbounded `.`,
// metacharacters outside a class, lookarounds — fails CLOSED (returns false),
// so an ambiguous regex never silences a sink.
func regexConstrainsToSafeCharset(pattern, method string) bool {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return false
	}

	// Java String.matches / Pattern.matches are IMPLICITLY fully anchored
	// (the whole input must match). JS .test() is NOT — it matches a substring
	// unless `^...$` anchors are present, so an unanchored JS pattern (e.g.
	// `/[0-9]/`) only proves the string CONTAINS a digit, not that it is
	// digits-only. Require explicit anchors for the non-implicit-anchor case.
	if method == "matches" {
		// Implicitly anchored; strip any explicit anchors the author added.
		p = strings.TrimPrefix(p, "^")
		p = strings.TrimSuffix(p, "$")
	} else {
		if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
			return false
		}
		p = strings.TrimPrefix(p, "^")
		p = strings.TrimSuffix(p, "$")
	}
	if p == "" {
		return false
	}

	return scanSafeRegexBody(p)
}

// scanSafeRegexBody walks a (de-anchored) regex body and returns true only when
// every token is provably safe. It accepts:
//
//   - literal alphanumerics and safe separators outside classes
//   - character classes `[...]` whose contents are alphanumerics / safe ranges
//     / safe separators (e.g. `[A-Za-z0-9_-]`)
//   - escape sequences `\d`, `\w` (digit / word — both safe alphabets)
//   - quantifiers `+ * ? { }` applied to a safe atom
//
// It REJECTS (returns false on) anything else: `.` (any char), `\S`, `\D`,
// `\W`, alternation `|`, groups `()`, backrefs, lookarounds, and any literal
// metacharacter that could carry an injection payload.
func scanSafeRegexBody(p string) bool {
	i := 0
	n := len(p)
	for i < n {
		c := p[i]
		switch c {
		case '[':
			// Character class — find the closing ']' and validate contents.
			end := indexCloseBracket(p, i+1)
			if end < 0 {
				return false
			}
			class := p[i+1 : end]
			if !safeCharClass(class) {
				return false
			}
			i = end + 1
			// Optional quantifier after the class.
			i = skipQuantifier(p, i)
		case '\\':
			// Escape sequence outside a class.
			if i+1 >= n {
				return false
			}
			e := p[i+1]
			switch e {
			case 'd', 'w':
				// \d (digits), \w (word chars [A-Za-z0-9_]) — safe alphabets.
				i += 2
				i = skipQuantifier(p, i)
			default:
				// \S, \D, \W, \., \/, \s, etc. — not provably safe.
				return false
			}
		case '(', ')', '|', '.', '*', '+', '?', '{', '}', '$', '^':
			// Bare metacharacters outside a class: groups/alternation/any-char/
			// dangling quantifiers/anchors mid-pattern are all out of our safe
			// model. (Quantifiers are only reached here when not preceded by a
			// valid atom, which is itself a sign of a pattern we don't model.)
			return false
		default:
			// A bare literal character. Only alphanumerics and a short list of
			// innocuous separators are safe as literals — a literal `'`, `;`,
			// `<`, `"`, `/`, space etc. could be an injection metacharacter, so
			// reject anything outside the safe literal alphabet.
			if !isSafeLiteralByte(c) {
				return false
			}
			i++
			i = skipQuantifier(p, i)
		}
	}
	return true
}

// indexCloseBracket returns the index of the matching ']' for a character class
// that started at `start` (the index just after the '['). Handles an escaped
// `\]` and a leading literal `]` (which in regex denotes a literal bracket).
// Returns -1 if unterminated.
func indexCloseBracket(p string, start int) int {
	i := start
	// A ']' as the very first char of a class is a literal, not the terminator.
	if i < len(p) && p[i] == ']' {
		i++
	}
	for i < len(p) {
		if p[i] == '\\' {
			i += 2
			continue
		}
		if p[i] == ']' {
			return i
		}
		i++
	}
	return -1
}

// safeCharClass validates the contents of a `[...]` character class. A negated
// class (`[^...]`) is REJECTED (it admits everything except a few chars, which
// is the opposite of constraining to a safe set). Inside the class we accept
// alphanumeric ranges, individual alphanumerics, safe separators, and the safe
// escapes `\d` / `\w`.
func safeCharClass(class string) bool {
	if class == "" {
		return false
	}
	if class[0] == '^' {
		// Negated class admits arbitrary characters → not safe.
		return false
	}
	i := 0
	n := len(class)
	for i < n {
		c := class[i]
		if c == '\\' {
			if i+1 >= n {
				return false
			}
			e := class[i+1]
			switch e {
			case 'd', 'w':
				i += 2
				continue
			case '-', '.', '_':
				// escaped safe separators
				i += 2
				continue
			default:
				return false
			}
		}
		// Range like a-z / A-Z / 0-9.
		if i+2 < n && class[i+1] == '-' && class[i+2] != ']' {
			lo, hi := c, class[i+2]
			if !isSafeRange(lo, hi) {
				return false
			}
			i += 3
			continue
		}
		// Single literal inside the class.
		if !isSafeClassByte(c) {
			return false
		}
		i++
	}
	return true
}

// isSafeRange reports whether a regex range lo-hi is a safe alphanumeric range.
func isSafeRange(lo, hi byte) bool {
	switch {
	case lo == '0' && hi == '9':
		return true
	case lo == 'a' && hi == 'z':
		return true
	case lo == 'A' && hi == 'Z':
		return true
	}
	// Sub-ranges within the alphanumeric bands are also safe (e.g. a-f).
	if isAlnumByte(lo) && isAlnumByte(hi) && lo <= hi {
		// Both endpoints alphanumeric AND in the same band (both digits, both
		// lower, or both upper).
		if (isDigitByte(lo) && isDigitByte(hi)) ||
			(isLowerByte(lo) && isLowerByte(hi)) ||
			(isUpperByte(lo) && isUpperByte(hi)) {
			return true
		}
	}
	return false
}

// isSafeClassByte reports whether a single literal byte inside a char class is
// safe (alphanumeric or an innocuous separator).
func isSafeClassByte(c byte) bool {
	return isAlnumByte(c) || c == '_' || c == '-' || c == '.'
}

// isSafeLiteralByte reports whether a bare literal byte (outside a class) is
// safe. Slightly stricter than isSafeClassByte: `.` outside a class is the
// any-char metacharacter and is handled separately, so only alphanumerics and
// `_`/`-` are accepted as bare literals.
func isSafeLiteralByte(c byte) bool {
	return isAlnumByte(c) || c == '_' || c == '-'
}

func isAlnumByte(c byte) bool { return isDigitByte(c) || isLowerByte(c) || isUpperByte(c) }
func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }
func isLowerByte(c byte) bool { return c >= 'a' && c <= 'z' }
func isUpperByte(c byte) bool { return c >= 'A' && c <= 'Z' }

// skipQuantifier advances past a regex quantifier (`*`, `+`, `?`, `{n,m}`) and
// any lazy `?` suffix, if one immediately follows position i.
func skipQuantifier(p string, i int) int {
	if i >= len(p) {
		return i
	}
	switch p[i] {
	case '*', '+', '?':
		i++
	case '{':
		// {n}, {n,}, {n,m} — accept only digits and a comma inside the braces.
		j := i + 1
		for j < len(p) && p[j] != '}' {
			if !isDigitByte(p[j]) && p[j] != ',' {
				return i // malformed → don't consume; caller will reject later
			}
			j++
		}
		if j < len(p) && p[j] == '}' {
			i = j + 1
		}
	}
	// Lazy/possessive suffix.
	if i < len(p) && (p[i] == '?' || p[i] == '+') {
		i++
	}
	return i
}

// matchTypeofNumberGuard recognises `typeof x === "number"` / `typeof x ===
// "bigint"` (and `==` variants) on a tainted variable — JS/TS numeric type
// guards. On the guarded path the value is a JS number, which carries no string
// payload, so all safe-charset categories are neutralised.
func matchTypeofNumberGuard(cond *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	if cond.Type() != "binary_expression" {
		return nil
	}
	op := boolOperatorToken(cond)
	if op != "===" && op != "==" {
		return nil
	}
	left := cond.ChildByFieldName("left")
	right := cond.ChildByFieldName("right")
	if left == nil || right == nil {
		return nil
	}

	// Identify the `typeof x` operand and the `"number"` string operand.
	typeofVar, ok := typeofOperandVar(left, tm, cfg)
	cmpStr := right
	if !ok {
		typeofVar, ok = typeofOperandVar(right, tm, cfg)
		cmpStr = left
	}
	if !ok || typeofVar == "" {
		return nil
	}
	lit, isStr := stringLiteralText(cmpStr)
	if !isStr {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(lit)) {
	case "number", "bigint", "boolean":
		return &barrierGuardResult{varName: typeofVar, categories: safeCharsetCategories}
	}
	return nil
}

// typeofOperandVar returns the variable name when `n` is a `typeof x` unary
// expression whose operand is a tainted bare identifier.
func typeofOperandVar(n *ast.Node, tm *taintMap, cfg *langConfig) (string, bool) {
	if n == nil || n.Type() != "unary_expression" {
		return "", false
	}
	if op := n.ChildByFieldName("operator"); op == nil || op.Text() != "typeof" {
		// Fall back to scanning for the `typeof` keyword token.
		found := false
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() && c.Text() == "typeof" {
				found = true
				break
			}
		}
		if !found {
			return "", false
		}
	}
	arg := n.ChildByFieldName("argument")
	if arg == nil {
		// arg may be the last named child.
		named := n.NamedChildren()
		if len(named) > 0 {
			arg = named[len(named)-1]
		}
	}
	if v := taintedBareIdentName(arg, tm, cfg); v != "" {
		return v, true
	}
	return "", false
}

// matchJavaNumericParseGuard recognises `Integer.parseInt(x)` /
// `Long.parseLong(x)` / `Double.parseDouble(x)` etc. when they appear directly
// in a guard condition on a tainted variable. Successful parse → numeric value,
// no string payload. Java throws NumberFormatException on malformed input, so a
// condition that calls parseInt only proceeds when x is numeric.
func matchJavaNumericParseGuard(call *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	method := cfg.extractCallName(call)
	switch method {
	case "parseInt", "parseLong", "parseShort", "parseByte",
		"parseDouble", "parseFloat":
	default:
		return nil
	}
	recv := cfg.extractCallReceiver(call)
	switch recv {
	case "Integer", "Long", "Short", "Byte", "Double", "Float":
	default:
		return nil
	}
	args := cfg.extractCallArgs(call)
	if len(args) == 0 {
		return nil
	}
	if v := taintedBareIdentName(args[0], tm, cfg); v != "" {
		return &barrierGuardResult{varName: v, categories: safeCharsetCategories}
	}
	return nil
}

// unwrapArg applies the per-language argument-wrapper unwrap (PHP `argument`
// nodes) if configured, returning the inner expression node. A no-op when the
// language doesn't wrap call arguments.
func unwrapArg(n *ast.Node, cfg *langConfig) *ast.Node {
	if cfg.barrierGuards != nil && cfg.barrierGuards.argUnwrap != nil {
		return cfg.barrierGuards.argUnwrap(n)
	}
	return n
}

// taintedArgIdentName is taintedBareIdentName after unwrapping a call-argument
// wrapper node (PHP `argument`). Used by the free-function guard matchers whose
// arguments arrive wrapped.
func taintedArgIdentName(n *ast.Node, tm *taintMap, cfg *langConfig) string {
	return taintedBareIdentName(unwrapArg(n, cfg), tm, cfg)
}

// matchRegexFuncGuard recognises a PHP-style free-function regex validator:
// `preg_match("/^[0-9]+$/", $x)` — the pattern is a string-literal in arg0 and
// the validated variable is arg1. Only a strict-charset anchored regex (proved
// by scanSafeRegexBody) sanitizes; a loose/metachar pattern returns nil. The
// regex is treated as a JS-style `.test()` pattern (NOT implicitly anchored —
// preg_match matches a SUBSTRING by default, so explicit `^...$` anchors are
// required, which the "test" method-class enforces).
func matchRegexFuncGuard(call *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	name := cfg.extractCallName(call)
	if !cfg.barrierGuards.regexFuncGuards[name] {
		return nil
	}
	// preg_match must be a FREE function (no receiver/scope). A method/scoped
	// call named preg_match is not the builtin.
	if cfg.extractCallReceiver(call) != "" {
		return nil
	}
	args := cfg.extractCallArgs(call)
	if len(args) < 2 {
		return nil
	}
	pat, ok := stringLiteralText(unwrapArg(args[0], cfg))
	if !ok || pat == "" {
		return nil
	}
	pat = unwrapPHPRegexDelimiters(pat)
	if pat == "" {
		return nil
	}
	v := taintedArgIdentName(args[1], tm, cfg)
	if v == "" {
		return nil
	}
	// "test" semantics: explicit anchors required (substring match otherwise).
	if !regexConstrainsToSafeCharset(pat, "test") {
		return nil
	}
	return &barrierGuardResult{varName: v, categories: safeCharsetCategories}
}

// unwrapPHPRegexDelimiters strips a PHP PCRE delimiter pair from a preg_match
// pattern string. PHP patterns are delimited (`/.../`, `#...#`, `~...~`,
// `{...}`), optionally with trailing modifier flags (`/.../i`). We strip the
// leading delimiter, find its matching closing delimiter, and drop any trailing
// modifiers. A case-insensitive (`i`) or multi-line (`m`) modifier — which
// would widen the matched set or change anchor semantics — fails CLOSED
// (returns "") so we never over-sanitize. Returns "" when no valid delimiter
// pair is present.
func unwrapPHPRegexDelimiters(p string) string {
	if len(p) < 2 {
		return ""
	}
	open := p[0]
	var close byte
	switch open {
	case '/', '#', '~', '!', '@', '%':
		close = open
	case '{':
		close = '}'
	case '(':
		close = ')'
	case '[':
		close = ']'
	case '<':
		close = '>'
	default:
		// No recognised delimiter — refuse to guess (fail closed).
		return ""
	}
	// Find the LAST closing delimiter (modifiers follow it).
	idx := strings.LastIndexByte(p, close)
	if idx <= 0 {
		return ""
	}
	body := p[1:idx]
	mods := p[idx+1:]
	// Reject modifiers that widen matching or alter anchor semantics. `i`
	// (case-insensitive), `m` (multiline ^/$), `s` (dotall), `x` (extended),
	// `u` (unicode). Letters are already in the safe set, so declining `i`
	// only costs an FP-suppression; declining `m` is required for soundness
	// (`^...$` would no longer anchor the whole string).
	if strings.ContainsAny(mods, "imsxuU") {
		return ""
	}
	if body == "" {
		return ""
	}
	return body
}

// matchCharsetFuncGuard recognises a PHP-style free-function charset predicate:
// `ctype_digit($x)`, `ctype_alnum($x)`, `is_numeric($x)`. When the predicate
// returns true the argument is provably constrained to digits / alphanumerics /
// a numeric string — no injection metacharacter — so all safeCharsetCategories
// are neutralised on the guarded path. No regex to scan: the function IS the
// proof.
func matchCharsetFuncGuard(call *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	name := cfg.extractCallName(call)
	if !cfg.barrierGuards.charsetFuncGuards[name] {
		return nil
	}
	if cfg.extractCallReceiver(call) != "" {
		return nil
	}
	args := cfg.extractCallArgs(call)
	if len(args) == 0 {
		return nil
	}
	if v := taintedArgIdentName(args[0], tm, cfg); v != "" {
		return &barrierGuardResult{varName: v, categories: safeCharsetCategories}
	}
	return nil
}

// matchRegexMatchMethodGuard recognises a Ruby receiver-regex method guard:
// `x.match?(/\A[0-9]+\z/)` — the receiver `x` is the validated variable and the
// argument is a REGEX LITERAL node whose body is extracted via
// langRegexLiteralBody. Only a strict-charset anchored regex sanitizes. The
// extracted body is normalised to `^...$` form, so it is validated with the
// implicit-anchor ("matches") path NO — we keep the explicit-anchor "test" path
// since langRegexLiteralBody only emits `^...$` when Ruby `\A...\z` anchors are
// present (an unanchored Ruby regex like `/[0-9]/` keeps no anchors and is
// rejected by the test-path anchor requirement). This preserves the rule that
// only a whole-string charset constraint sanitizes.
func matchRegexMatchMethodGuard(call *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	method := cfg.extractCallName(call)
	if !cfg.barrierGuards.regexMatchMethods[method] {
		return nil
	}
	recv := cfg.extractCallReceiver(call)
	if recv == "" {
		return nil
	}
	ts := tm.get(recv)
	if ts == nil || ts.source == nil {
		return nil
	}
	args := cfg.extractCallArgs(call)
	if len(args) == 0 {
		return nil
	}
	reg := unwrapArg(args[0], cfg)
	if reg == nil || cfg.barrierGuards.langRegexLiteralBody == nil {
		return nil
	}
	pat := cfg.barrierGuards.langRegexLiteralBody(reg)
	if pat == "" {
		return nil
	}
	if !regexConstrainsToSafeCharset(pat, "test") {
		return nil
	}
	return &barrierGuardResult{varName: recv, categories: safeCharsetCategories}
}

// matchRubyRegexMatchOp recognises the Ruby `x =~ /\A\d+\z/` binary match
// operator (and its mirror `/\A\d+\z/ =~ x`). The variable operand is the
// validated tainted variable; the regex operand must constrain to a safe
// charset. Only an anchored strict-charset regex sanitizes.
func matchRubyRegexMatchOp(left, right *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	if cfg.barrierGuards.langRegexLiteralBody == nil {
		return nil
	}
	// Identify which side is the variable and which is the regex literal.
	tryPair := func(varNode, regNode *ast.Node) *barrierGuardResult {
		if varNode == nil || regNode == nil || regNode.Type() != "regex" {
			return nil
		}
		v := taintedBareIdentName(varNode, tm, cfg)
		if v == "" {
			return nil
		}
		pat := cfg.barrierGuards.langRegexLiteralBody(regNode)
		if pat == "" || !regexConstrainsToSafeCharset(pat, "test") {
			return nil
		}
		return &barrierGuardResult{varName: v, categories: safeCharsetCategories}
	}
	if r := tryPair(left, right); r != nil {
		return r
	}
	return tryPair(right, left)
}

// matchNumericCoercionFuncGuard recognises a free-function numeric coercion in a
// guard condition — Ruby `Integer(x)` (callee is the `Integer` constant, no
// receiver). `Integer(str)` raises ArgumentError on a non-numeric string, so a
// guard that calls it only proceeds when x is numeric → no string payload.
func matchNumericCoercionFuncGuard(call *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	name := cfg.extractCallName(call)
	if !cfg.barrierGuards.numericCoercionFuncs[name] {
		return nil
	}
	// Must be a bare/constant callee with no receiver (a method `obj.Integer(x)`
	// is not the Kernel#Integer coercion).
	if cfg.extractCallReceiver(call) != "" {
		return nil
	}
	args := cfg.extractCallArgs(call)
	if len(args) == 0 {
		return nil
	}
	if v := taintedArgIdentName(args[0], tm, cfg); v != "" {
		return &barrierGuardResult{varName: v, categories: safeCharsetCategories}
	}
	return nil
}

// matchNumericCoercionMethodGuard recognises a receiver numeric-coercion method
// — Ruby `x.to_i` — appearing as the operand of a guard comparison (`x.to_i >
// 0`). The receiver `x` is range-checked as an integer on the guarded path.
// Recognised only inside a comparison (the caller restricts this), mirroring
// the Java parseInt-in-comparison rule.
func matchNumericCoercionMethodGuard(call *ast.Node, tm *taintMap, cfg *langConfig) *barrierGuardResult {
	method := cfg.extractCallName(call)
	if !cfg.barrierGuards.numericCoercionMethods[method] {
		return nil
	}
	recv := cfg.extractCallReceiver(call)
	if recv == "" {
		return nil
	}
	if ts := tm.get(recv); ts != nil && ts.source != nil {
		return &barrierGuardResult{varName: recv, categories: safeCharsetCategories}
	}
	return nil
}

// taintedBareIdentName returns the name of a bare tainted identifier node, or
// "" if the node is not a single tainted identifier. Stricter than walking
// compound expressions — we only sanitize the EXACT variable the guard names,
// never a sub-expression, to keep the guard bounded.
func taintedBareIdentName(n *ast.Node, tm *taintMap, cfg *langConfig) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case cfg.identType, "identifier", "variable_name":
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return name
		}
	}
	return ""
}

// applyBarrierGuard marks the guarded variable as sanitized for the guard's
// categories on the given taint map, without deleting it (so other categories
// and other variables remain tainted). Mirrors applyPythonPathGuard.
func applyBarrierGuard(tm *taintMap, res *barrierGuardResult) {
	if res == nil || tm == nil {
		return
	}
	ts := tm.get(res.varName)
	if ts == nil {
		return
	}
	if ts.sanitized == nil {
		ts.sanitized = make(map[taint.SinkCategory]bool)
	}
	for _, c := range res.categories {
		ts.sanitized[c] = true
	}
}
