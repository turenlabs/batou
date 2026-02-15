package tsflow

import (
	"strings"

	"github.com/turenio/gtss/internal/ast"
)

// allowlistCheckResult holds the result of detecting an allowlist/membership
// check in an if-condition. If found, varName is the tainted variable that
// is being validated by the check.
type allowlistCheckResult struct {
	varName string
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

	return nil
}

// checkPythonIn detects Python's `x in COLLECTION` pattern.
// Tree-sitter represents this as a comparison_operator node with children:
//   [identifier("x"), "in", identifier("ALLOWED")]
// For `not in`: [identifier("x"), "not in"(anon), identifier("DENIED")]
// The anonymous operator node has type "in" or "not in".
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

	// The first named child is the value being tested.
	named := n.NamedChildren()
	if len(named) < 2 {
		return nil
	}

	return taintedIdentInNode(named[0], tm, cfg)
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
//   ALLOWED.indexOf(x) !== -1
//   ALLOWED.indexOf(x) >= 0
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
// Handles: `not (x in ALLOWED)` (Python), `!(ALLOWED.includes(x))` (JS)
func checkNegation(n *ast.Node, tm *taintMap, cfg *langConfig) *allowlistCheckResult {
	nodeType := n.Type()
	if nodeType != "not_operator" && nodeType != "unary_expression" {
		return nil
	}

	// For unary_expression, verify it's a "!" operator.
	if nodeType == "unary_expression" {
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
