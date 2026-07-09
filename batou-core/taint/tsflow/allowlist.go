package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// allowlistCheckResult holds the result of detecting an allowlist/membership
// check in an if-condition. If found, varName is the tainted variable that
// is being validated by the check.
//
// categories, when non-empty, scopes the guard to a specific sink-category
// set: the walker marks the variable sanitized for ONLY those categories
// instead of deleting it wholesale (see applyAllowlistClear). A nil/empty
// slice keeps the historical category-blind behaviour — the variable is
// removed from the taint map entirely. Only validation shapes we can
// positively classify (path-containment checks like x.contains("..")) carry
// a category set; every unrecognised shape stays wholesale so existing FP
// suppression does not flip.
type allowlistCheckResult struct {
	varName    string
	categories []taint.SinkCategory
}

// pathContainmentClearedCategories is the sink-category set that a PATH-
// CONTAINMENT validation guard (`x.contains("..")`, `x.startsWith("../")`,
// PHP `strpos($p, '..') !== false`) keeps cleared on the validated path:
//
//   - filesystem path traversal (SnkFileRead / SnkFileWrite / SnkUpload) —
//     the categories the check actually constrains (mirrors Python's
//     pythonPathSinkCategories, which already scopes the same `".." in x`
//     shape this way);
//   - URL-path manipulation (SnkURLFetch / SnkRedirect) — a ".." check on a
//     value embedded in a URL is the URL-side path-traversal guard, and the
//     historical wholesale clear suppressed these flows too, so keeping them
//     cleared preserves the engine's FP behaviour (FPR-flat).
//
// Every category NOT in this set — SQL, NoSQL, command, eval, XSS, LDAP,
// XPath, header, template, log, deserialize, … — stays TAINTED through the
// guard: a dot-dot containment check proves nothing about injection safety,
// and clearing those wholesale silenced real vulnerabilities (e.g. a
// path-containment check before executeQuery hid a SQL injection).
var pathContainmentClearedCategories = []taint.SinkCategory{
	taint.SnkFileRead, taint.SnkFileWrite, taint.SnkUpload,
	taint.SnkURLFetch, taint.SnkRedirect,
}

// detectAllowlistCheck examines an if-statement's condition node and returns
// the name of any tainted variable being checked against an allowlist/denylist.
// Returns nil if no allowlist pattern is found.
//
// Recognized patterns:
//   - Python:  `x in ALLOWED` / `x not in DENIED` / comparison operators
//   - JS/TS:   `ALLOWED.includes(x)` / `ALLOWED.indexOf(x) !== -1`
//   - Java/C#/Kotlin: `ALLOWED.contains(x)`
//   - Ruby:    `ALLOWED.include?(x)` (via call node with method "include?")
//   - PHP:     `in_array(x, ALLOWED)`
//   - General: any call of includes/contains/include/has/indexOf on a tainted arg
func detectAllowlistCheck(cond *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	if cond == nil {
		return nil
	}

	// Unwrap parenthesized expressions.
	for cond.Type() == "parenthesized_expression" {
		named := cond.NamedChildren()
		if len(named) != 1 {
			break
		}
		cond = named[0]
	}

	// Strategy 1: Python `in` operator — binary_operator with operator "in" or "not in".
	// Tree-sitter Python: comparison_operator with children: expr, "in", expr
	// or: not_operator wrapping comparison_operator with "in"
	if r := checkPythonIn(cond, tm, cfg); r != nil {
		return r
	}

	// Strategy 2: Method call pattern — obj.includes(x), obj.contains(x), etc.
	if r := checkMembershipCall(cond, tm, cfg); r != nil {
		return r
	}

	// Strategy 3: Comparison with indexOf — obj.indexOf(x) !== -1
	if r := checkIndexOfComparison(cond, tm, cfg); r != nil {
		return r
	}

	// Strategy 4: PHP in_array(x, arr)
	if r := checkFreeFunction(cond, tm, cfg); r != nil {
		return r
	}

	// Strategy 5: Negation wrapper — `not (x in ...)` or `!(...)` still validates x
	if r := checkNegation(cond, tm, cfg); r != nil {
		return r
	}

	// Strategy 6: boolean_operator / binary_expression `A or B` / `A and B`
	// — a guard like `url.netloc not in [..] or url.scheme != 'https'` is a
	// chain of boolean_operator nodes whose LHS is a real allowlist check.
	// Recurse into both sides; the first side that matches wins.
	if cond.Type() == "boolean_operator" || cond.Type() == "binary_expression" {
		named := cond.NamedChildren()
		left := cond.ChildByFieldName("left")
		if left == nil && len(named) > 0 {
			left = named[0]
		}
		if r := detectAllowlistCheck(left, tm, cfg); r != nil {
			return r
		}
		right := cond.ChildByFieldName("right")
		if right == nil && len(named) > 1 {
			right = named[1]
		}
		return detectAllowlistCheck(right, tm, cfg)
	}

	return nil
}

// checkPythonIn detects Python's `x in COLLECTION` pattern.
// Tree-sitter represents this as a comparison_operator node with children:
//
//	[identifier("x"), "in", identifier("ALLOWED")]
//
// For `not in`: [identifier("x"), "not in"(anon), identifier("DENIED")]
// The anonymous operator node has type "in" or "not in".
//
// Also detects the inverse substring-validation pattern:
//
//	`'../' in bar` / `'..' in tainted`
//
// where the LHS is a string literal and the RHS is a tainted variable.
// This is the Python equivalent of `bar.contains('../')` — a validation
// guard that, when paired with an early return in the consequence, clears
// taint on the fallthrough path.
func checkPythonIn(n *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	if n.Type() != "comparison_operator" {
		return nil
	}

	// Look for an "in" or "not in" operator token among the children.
	hasIn := false
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if !c.IsNamed() {
			text := c.Text()
			if text == "in" || text == "not in" {
				hasIn = true
			}
		}
	}
	if !hasIn {
		return nil
	}

	named := n.NamedChildren()
	if len(named) < 2 {
		return nil
	}

	// Standard form: `x in ALLOWED` — LHS variable being tested.
	if r := taintedIdentInNode(named[0], tm, cfg); r != nil {
		return r
	}

	// Inverse substring-guard form: `'../' in bar`. LHS must be a string
	// literal AND the RHS must be a bare tainted identifier — not a call
	// or subscript expression like `request.form.getlist(name)` — so we
	// don't accidentally treat membership checks against tainted
	// collections (`"key" in tainted_dict.values()`) as validation guards.
	if isStringLiteralNode(named[0]) {
		if r := taintedBareIdent(named[1], tm, cfg); r != nil {
			return r
		}
	}

	return nil
}

// taintedBareIdent returns the variable name if the node is a single tainted
// identifier (no attribute access, no call, no subscript). This is stricter
// than taintedIdentInNode, which walks compound expressions.
func taintedBareIdent(n *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	if n == nil {
		return nil
	}
	switch n.Type() {
	case cfg.identType, "identifier", "variable_name":
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return &allowlistCheckResult{varName: name}
		}
	}
	return nil
}

// isStringLiteralNode returns true when the node represents a Python string
// literal (used by checkPythonIn to recognise substring-validation guards
// like `'../' in path`).
func isStringLiteralNode(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "string_literal", "concatenated_string":
		return true
	}
	return false
}

// checkMembershipCall detects patterns like:
//   - ALLOWED.includes(x)       (JS/TS)
//   - ALLOWED.contains(x)       (Java/Kotlin/C#)
//   - ALLOWED.include?(x)       (Ruby)
//   - ALLOWED.has(x)            (JS Set)
//   - Set.contains(x)           (Swift)
func checkMembershipCall(n *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	if !cfg.callTypes[n.Type()] {
		return nil
	}

	methodName := strings.ToLower(cfg.extractCallName(n))
	if !isMembershipMethod(methodName) {
		return nil
	}

	// Check if any argument is tainted.
	args := cfg.extractCallArgs(n)
	for _, arg := range args {
		if r := taintedIdentInNode(arg, tm, cfg); r != nil {
			return r
		}
	}
	return nil
}

// checkIndexOfComparison detects patterns like:
//
//	ALLOWED.indexOf(x) !== -1
//	ALLOWED.indexOf(x) >= 0
//
// Tree-sitter: binary_expression with left = call_expression containing indexOf
func checkIndexOfComparison(n *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	nodeType := n.Type()
	if nodeType != "binary_expression" && nodeType != "comparison_operator" {
		return nil
	}

	left := n.ChildByFieldName("left")
	if left == nil {
		return nil
	}

	// Check if left side is an indexOf/index call.
	if !cfg.callTypes[left.Type()] {
		return nil
	}
	methodName := strings.ToLower(cfg.extractCallName(left))
	if methodName != "indexof" && methodName != "index" && methodName != "findindex" {
		return nil
	}

	args := cfg.extractCallArgs(left)
	for _, arg := range args {
		if r := taintedIdentInNode(arg, tm, cfg); r != nil {
			return r
		}
	}
	return nil
}

// checkFreeFunction detects patterns like PHP's `in_array($x, $allowed)`.
func checkFreeFunction(n *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	if !cfg.callTypes[n.Type()] {
		return nil
	}

	methodName := strings.ToLower(cfg.extractCallName(n))
	if methodName != "in_array" && methodName != "array_search" {
		return nil
	}

	// First argument is the needle (tainted variable).
	args := cfg.extractCallArgs(n)
	if len(args) == 0 {
		return nil
	}
	return taintedIdentInNode(args[0], tm, cfg)
}

// checkNegation unwraps negation operators and recursively checks the inner expression.
// Handles: `not (x in ALLOWED)` (Python), `!(ALLOWED.includes(x))` (JS),
// `!in_array($x, $allowed)` (PHP, where `!expr` is a unary_op_expression).
func checkNegation(n *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	nodeType := n.Type()
	if nodeType != "not_operator" && nodeType != "unary_expression" &&
		nodeType != "unary_op_expression" {
		return nil
	}

	// For unary_expression / unary_op_expression, verify it's a "!" operator.
	if nodeType == "unary_expression" || nodeType == "unary_op_expression" {
		op := n.ChildByFieldName("operator")
		if op == nil {
			// Look for "!" token in children.
			found := false
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if !c.IsNamed() && c.Text() == "!" {
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		} else if op.Text() != "!" {
			return nil
		}
	}

	// Check named children for the inner condition.
	named := n.NamedChildren()
	for _, child := range named {
		if r := detectAllowlistCheck(child, tm, cfg); r != nil {
			return r
		}
	}
	return nil
}

// isMembershipMethod returns true if the method name indicates a membership/containment check.
func isMembershipMethod(name string) bool {
	switch name {
	case "includes", "contains", "include?", "include", "has",
		"hasownproperty", "containskey", "containsvalue",
		"indexof", "findindex":
		return true
	}
	return false
}

// detectValidationGuard detects patterns where a tainted variable calls a
// validation/checking method with a literal argument, indicating input validation.
// This is the inverse of detectAllowlistCheck: instead of COLLECTION.contains(tainted),
// it detects tainted.contains("bad_value"), tainted.starts_with("//"), etc.
//
// Recognized patterns:
//   - Rust/JS/general: x.contains(".."), x.starts_with("//"), x.ends_with(".txt")
//   - Rust: x.is_empty(), x.is_ascii(), x.len() > N
//   - Rust: x.chars().all(|c| ...) — character validation closures
//   - Negation: !x.contains("..") { return } still validates x
//
// Returns the tainted variable name if a validation pattern is found.
func detectValidationGuard(cond *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	if cond == nil {
		return nil
	}

	// Unwrap parenthesized expressions.
	for cond.Type() == "parenthesized_expression" {
		named := cond.NamedChildren()
		if len(named) != 1 {
			break
		}
		cond = named[0]
	}

	// Unwrap negation: !x.contains("..") still validates x. PHP uses
	// `unary_op_expression` for the `!` operator.
	inner := cond
	if inner.Type() == "unary_expression" || inner.Type() == "not_operator" ||
		inner.Type() == "unary_op_expression" {
		named := inner.NamedChildren()
		if len(named) == 1 {
			inner = named[0]
			// Unwrap parenthesized inside negation
			for inner.Type() == "parenthesized_expression" {
				named = inner.NamedChildren()
				if len(named) != 1 {
					break
				}
				inner = named[0]
			}
		}
	}

	// Check for method call on tainted variable: x.method(literal)
	if cfg.callTypes[inner.Type()] {
		methodName := strings.ToLower(cfg.extractCallName(inner))
		if isValidationMethod(methodName) {
			recv := cfg.extractCallReceiver(inner)
			if recv != "" {
				// Path-containment shapes (x.contains("..")) only validate
				// the path/filename — scope the guard to the path categories
				// instead of clearing the variable wholesale. nil for every
				// other shape (status quo).
				cats := pathContainmentGuardCategories(inner, methodName, cfg)
				// Check the base receiver (before chained calls like x.chars().all())
				baseRecv := extractBaseReceiver(inner, cfg)
				if baseRecv != "" {
					if ts := tm.get(baseRecv); ts != nil && ts.source != nil {
						return &allowlistCheckResult{varName: baseRecv, categories: cats}
					}
				}
				if ts := tm.get(recv); ts != nil && ts.source != nil {
					return &allowlistCheckResult{varName: recv, categories: cats}
				}
			}
		}
		// Free-function validator: <callname>(taintvar) where callname carries
		// strong validator semantics (is_safe_*, is_valid_*, validate_*, etc.).
		// Used to recognise project-local guard helpers such as
		// `_is_safe_git_url(url)` that callers wrap around a tainted variable
		// before passing it to a sink. Conservative: requires both (a) a
		// validator-shaped name and (b) the tainted variable appearing as a
		// positional argument, so plain function calls like `process(url)`
		// don't accidentally clear taint.
		if isFreeFunctionValidatorName(methodName) {
			// Bare call form has no receiver — only treat as a validator when
			// the receiver is empty (avoids matching `obj.is_valid_email(x)`
			// which we have no signal about).
			if cfg.extractCallReceiver(inner) == "" {
				args := cfg.extractCallArgs(inner)
				for _, arg := range args {
					if arg == nil {
						continue
					}
					if arg.Type() == cfg.identType || arg.Type() == "identifier" {
						name := arg.Text()
						if ts := tm.get(name); ts != nil && ts.source != nil {
							return &allowlistCheckResult{varName: name}
						}
					}
				}
			}
		}

		// PHP built-in containment / format-validation guards: the canonical
		// flat-script rejection idiom tests a tainted variable with a built-in
		// (`strpos($p, '..') !== false`, `preg_match('#^/#', $p)`,
		// `filter_var($u, FILTER_VALIDATE_URL)`, `ctype_alnum($x)`) and then
		// `die()`/`return`s. The tainted variable appears as a positional
		// ARGUMENT (PHP wraps it in an `argument` node), not a receiver, so the
		// receiver-method path above never sees it. Recognise these so the
		// early-exit fall-through clears the variable's taint. FP-safe: only
		// fires when (a) the function name is a known PHP guard builtin and
		// (b) a currently-tainted variable is a direct argument — and taint is
		// only cleared when the consequence early-exits.
		if cfg.language == rules.LangPHP && isPHPGuardFunctionName(methodName) &&
			cfg.extractCallReceiver(inner) == "" {
			args := cfg.extractCallArgs(inner)
			// strpos($p, '..') / str_contains($p, '..') with a path-shaped
			// needle is the PHP spelling of the path-containment guard —
			// scope it to the path categories. nil for every other guard
			// builtin (preg_match, filter_var, ctype_*, …): status quo.
			cats := phpNeedleContainmentCategories(methodName, args, cfg)
			for _, arg := range args {
				if arg == nil {
					continue
				}
				// Unwrap PHP `argument` wrapper to its inner expression.
				a := arg
				if a.Type() == "argument" {
					if inner := firstNamedChild(a); inner != nil {
						a = inner
					}
				}
				if a.Type() == cfg.identType || a.Type() == "variable_name" {
					name := a.Text()
					if ts := tm.get(name); ts != nil && ts.source != nil {
						return &allowlistCheckResult{varName: name, categories: cats}
					}
				}
			}
		}
	}

	// Check binary expressions: x.contains("..") || x.contains("/")
	// Also boolean_operator (tree-sitter-python's node for `and`/`or`) — the
	// codeinj quote-guard pattern is `not x.startswith('\'') or not x.endswith('\'') or ...`,
	// which is a chain of boolean_operator nodes that previously fell through here.
	if inner.Type() == "binary_expression" || inner.Type() == "binary_operator" ||
		inner.Type() == "boolean_operator" {
		left := inner.ChildByFieldName("left")
		if r := detectValidationGuard(left, tm, cfg); r != nil {
			return r
		}
		right := inner.ChildByFieldName("right")
		return detectValidationGuard(right, tm, cfg)
	}

	return nil
}

// extractBaseReceiver walks through chained method calls to find the
// root variable. For example, for x.chars().all(|c| ...), it returns "x".
func extractBaseReceiver(n *ast.Node, cfg *langConfig) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	if fn.Type() != "field_expression" {
		return ""
	}
	val := fn.ChildByFieldName("value")
	if val == nil {
		return ""
	}
	// If the value is itself a call expression, recurse
	if cfg.callTypes[val.Type()] {
		return extractBaseReceiver(val, cfg)
	}
	if val.Type() == "identifier" || val.Type() == cfg.identType {
		return val.Text()
	}
	return ""
}

// isValidationMethod returns true if the method name indicates a validation/checking
// operation that would be used in an input guard.
func isValidationMethod(name string) bool {
	switch name {
	case "contains", "starts_with", "ends_with", "startswith", "endswith",
		"is_empty", "is_ascii", "is_alphanumeric",
		"all", "any", "none",
		"len", "length",
		"is_match", "matches",
		"starts_with?", "ends_with?", "include?",
		// Swift/Foundation prefix-suffix containment checks (used in
		// `guard url.hasPrefix("https://") else { throw }` scheme/path guards).
		"hasprefix", "hassuffix":
		return true
	}
	return false
}

// isFreeFunctionValidatorName returns true when a bare function name reads
// as a project-local validator helper — `is_safe_url`, `_is_valid_input`,
// `validate_dest`, `check_path`, etc. These wrap a tainted argument in a
// boolean test and are conventionally used inside an early-return guard:
//
//	if not _is_safe_git_url(url):
//	    return 400, "bad input"
//	subprocess.run(["git", "clone", "--", url, dest])
//
// We deliberately only recognise prefix/`is_*` shapes that strongly signal a
// validator (e.g. `process`, `get`, `compute` aren't matched). The leading
// underscore is allowed because Python convention marks module-private
// helpers that way.
func isFreeFunctionValidatorName(name string) bool {
	if name == "" {
		return false
	}
	stripped := strings.TrimLeft(name, "_")
	if stripped == "" {
		return false
	}
	for _, prefix := range []string{
		"is_safe", "is_valid", "is_allowed", "is_clean",
		"validate", "check_", "assert_",
		"ensure_", "verify_", "sanitize", "sanitise",
	} {
		if strings.HasPrefix(stripped, prefix) {
			return true
		}
	}
	// `safe_*` is a common naming convention too (e.g. `safe_url`,
	// `safe_path`) — accept when the name is at least 6 chars to avoid
	// matching short tokens.
	if strings.HasPrefix(stripped, "safe_") && len(stripped) >= 6 {
		return true
	}
	return false
}

// isPHPGuardFunctionName reports whether a bare PHP built-in function is a
// containment / format-validation check conventionally used in an input guard:
//
//	if (strpos($path, '..') !== false) { die("bad"); }
//	if (!preg_match('#^/[a-z]+$#', $name)) { die("bad"); }
//	if (filter_var($url, FILTER_VALIDATE_URL) === false) { die("bad"); }
//	if (!ctype_alnum($id)) { die("bad"); }
//
// These take the tainted variable as an argument and return a boolean/needle
// position used to reject malicious input. The list is deliberately scoped to
// validation-shaped builtins (no general string functions like substr) so it
// can only mark a guard, never neutralise an unrelated transform. Taint is
// cleared only when the guarded branch early-exits (caller responsibility).
func isPHPGuardFunctionName(name string) bool {
	switch name {
	case "strpos", "stripos", "strrpos", "mb_strpos",
		"str_contains", "str_starts_with", "str_ends_with",
		"preg_match", "preg_match_all",
		"filter_var", "filter_input",
		"ctype_alnum", "ctype_alpha", "ctype_digit", "ctype_xdigit",
		"is_numeric", "in_array", "array_key_exists":
		return true
	}
	return false
}

// isContainmentGuardMethod reports whether a validation-method name is a
// CONTAINMENT / PREFIX / SUFFIX check — the only isValidationMethod shapes
// whose literal argument tells us WHAT the guard validates. Regex matchers
// (matches / is_match), length/emptiness checks, and char-walk closures stay
// out: their arguments don't classify the guard's domain.
func isContainmentGuardMethod(name string) bool {
	switch name {
	case "contains", "include?",
		"starts_with", "startswith", "ends_with", "endswith",
		"starts_with?", "ends_with?",
		"hasprefix", "hassuffix":
		return true
	}
	return false
}

// pathContainmentGuardCategories classifies a recognised receiver-method
// validation guard: when the method is a containment/prefix/suffix check and
// one of its string-literal arguments is a dot-dot path fragment (contains
// ".."), the guard is a PATH-CONTAINMENT check and only neutralises the
// path-traversal categories — return pathContainmentClearedCategories so the
// walker scopes the clearing. Any other shape returns nil, which keeps the
// historical wholesale clear (status quo).
//
// A literal containing "://" is a URL-prefix allowlist
// (x.startsWith("https://trusted/")), not a filesystem check — those return
// nil (wholesale) so SSRF/redirect FP suppression is untouched.
func pathContainmentGuardCategories(call *ast.Node, methodName string, cfg *langConfig) []taint.SinkCategory {
	if !isContainmentGuardMethod(methodName) {
		return nil
	}
	for _, arg := range cfg.extractCallArgs(call) {
		if literalIsPathContainment(unwrapArg(arg, cfg)) {
			return pathContainmentClearedCategories
		}
	}
	return nil
}

// phpNeedleContainmentCategories classifies a PHP free-function guard: the
// strpos family and the str_contains / str_starts_with / str_ends_with
// builtins take the needle as their SECOND argument — when that needle is a
// dot-dot literal, the guard is the PHP spelling of the path-containment
// check (`if (strpos($p, '..') !== false) die();`) and only the path
// categories are validated. Every other guard builtin (preg_match,
// filter_var, ctype_*, is_numeric, in_array, array_key_exists) returns nil:
// we can't classify what those validate, so the wholesale clear stays.
func phpNeedleContainmentCategories(fn string, args []*ast.Node, cfg *langConfig) []taint.SinkCategory {
	switch fn {
	case "strpos", "stripos", "strrpos", "mb_strpos",
		"str_contains", "str_starts_with", "str_ends_with":
	default:
		return nil
	}
	if len(args) < 2 {
		return nil
	}
	// PHP wraps each call argument in an `argument` node.
	needle := args[1]
	if needle != nil && needle.Type() == "argument" {
		if inner := firstNamedChild(needle); inner != nil {
			needle = inner
		}
	}
	if literalIsPathContainment(needle) {
		return pathContainmentClearedCategories
	}
	return nil
}

// literalIsPathContainment reports whether a node is a string literal whose
// body is a dot-dot path fragment ("..", "../", "..\\..", …). URL-shaped
// literals (containing "://") are excluded — those mark URL allowlist guards,
// which keep the wholesale behaviour.
func literalIsPathContainment(n *ast.Node) bool {
	lit, ok := stringLiteralText(n)
	if !ok {
		return false
	}
	if strings.Contains(lit, "://") {
		return false
	}
	return strings.Contains(lit, "..")
}

// taintedIdentInNode finds the first tainted identifier inside a node.
// Returns an allowlistCheckResult with the variable name, or nil.
func taintedIdentInNode(n *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	if n == nil {
		return nil
	}

	// Direct identifier check.
	if n.Type() == cfg.identType || n.Type() == "identifier" || n.Type() == "variable_name" {
		name := n.Text()
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return &allowlistCheckResult{varName: name}
		}
		return nil
	}

	// Walk into the node to find a tainted identifier.
	var result *allowlistCheckResult
	n.Walk(func(c *ast.Node) bool {
		if result != nil {
			return false
		}
		if c.Type() == cfg.identType || c.Type() == "identifier" || c.Type() == "variable_name" {
			name := c.Text()
			if ts := tm.get(name); ts != nil && ts.source != nil {
				result = &allowlistCheckResult{varName: name}
				return false
			}
		}
		return true
	})
	return result
}
