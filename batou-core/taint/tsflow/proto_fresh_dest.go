package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Fresh-destination suppression for merge-style prototype-pollution sinks.
//
// PR-CATjs-2: Real-world JS/TS scans (Ghost, Outline, n8n) showed ~17 FPs
// where the prototype_pollution sink fires on shapes like:
//
//     Object.assign({}, req.body)
//     const obj = {}; Object.assign(obj, req.body);
//     _.merge({}, src);
//     array.reduce((acc, v) => Object.assign(acc, ...), {});
//
// In each case the destination (arg 0) is a fresh local object literal
// or empty container that is never assigned anywhere else in the scope.
// A fresh local cannot serve as the bridge that pollutes Object.prototype
// for the rest of the process — the merge-style sinks copy keys into the
// destination, so a __proto__-bearing source only mutates the throwaway
// local. We therefore skip flow emission when arg 0 is one of those
// shapes for the merge-style sinks (Object.assign / _.merge / _.mergeWith /
// _.defaultsDeep / Hoek.merge / Hoek.applyToDefaults).
//
// IMPORTANT: this suppression deliberately does NOT cover _.set,
// _.setWith, or _.zipObjectDeep. Those sinks traverse a user-controlled
// PATH (e.g. "__proto__.isAdmin") on the destination, and a fresh local
// `{}` is still vulnerable — `{}.__proto__` resolves to Object.prototype.
// CVE-2020-8203 lives in this shape and must remain detected.

// jsProtoMergeStyleMethods lists the method names where a fresh destination
// renders the call inert. Lower-cased lookup so we can include namespaced
// variants without doubling the entries.
var jsProtoMergeStyleMethods = map[string]bool{
	"assign":          true, // Object.assign
	"merge":           true, // _.merge / lodash.merge / Hoek.merge / hoek.merge
	"mergewith":       true, // _.mergeWith / lodash.mergeWith
	"defaultsdeep":    true, // _.defaultsDeep / lodash.defaultsDeep
	"applytodefaults": true, // Hoek.applyToDefaults / hoek.applyToDefaults
}

// isMergeStyleProtoSink reports whether the matched sink is one whose
// destination can be neutralised by a fresh local. Path-traversing sinks
// (_.set/_.setWith/_.zipObjectDeep) deliberately excluded.
func isMergeStyleProtoSink(sink *taint.SinkDef) bool {
	if sink == nil || sink.Category != taint.SnkPrototype {
		return false
	}
	return jsProtoMergeStyleMethods[strings.ToLower(sink.MethodName)]
}

// isJSFreshProtoDest returns true if arg 0 of the call is provably a
// fresh local object/array container. Only used for JS/TS — other
// languages don't have the same Object.assign / lodash idioms and the
// node-type checks would not match.
//
// Recognised shapes for arg 0:
//   - Empty object literal `{}` (tree-sitter `object` node with zero named children)
//   - Empty array literal `[]` (tree-sitter `array` node with zero named children)
//   - `Object.create(null)` (call_expression whose function text equals that)
//   - `new Object()` (new_expression with no args)
//   - A bare identifier previously declared in scope with one of the above
//     RHSes AND not subsequently assigned (tracked in tm.freshLocalEmpty).
func isJSFreshProtoDest(arg *ast.Node, tm *taintMap, cfg *langConfig) bool {
	if arg == nil || cfg == nil {
		return false
	}
	if cfg.language != rules.LangJavaScript && cfg.language != rules.LangTypeScript {
		return false
	}
	return isFreshEmptyExpr(arg, tm)
}

// isFreshEmptyExpr is the underlying expression-level check, shared with
// the var-decl recorder so we mark `const x = {}` the same way we'd skip
// an inline `{}`.
func isFreshEmptyExpr(n *ast.Node, tm *taintMap) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "object":
		// Empty object literal: no named children means no key-value pairs.
		// Properties are named children of the object node in the JS grammar.
		return countNamedChildren(n) == 0
	case "array":
		return countNamedChildren(n) == 0
	case "new_expression":
		// `new Object()` — constructor "Object" with no/empty arguments.
		ctor := n.ChildByFieldName("constructor")
		if ctor == nil || ctor.Text() != "Object" {
			return false
		}
		argsNode := n.ChildByFieldName("arguments")
		if argsNode == nil {
			return true
		}
		return countNamedChildren(argsNode) == 0
	case "call_expression":
		// `Object.create(null)`.
		fn := n.ChildByFieldName("function")
		if fn == nil || fn.Text() != "Object.create" {
			return false
		}
		argsNode := n.ChildByFieldName("arguments")
		if argsNode == nil {
			return false
		}
		// Exactly one named arg, "null".
		var only *ast.Node
		for i := 0; i < argsNode.ChildCount(); i++ {
			c := argsNode.Child(i)
			if !c.IsNamed() {
				continue
			}
			if only != nil {
				return false
			}
			only = c
		}
		return only != nil && only.Text() == "null"
	case "identifier":
		if tm == nil {
			return false
		}
		name := n.Text()
		if !tm.freshLocalEmpty[name] {
			return false
		}
		// A subsequent assignment that put the identifier into the taint
		// map (or any other map) means we can no longer assume it's the
		// throwaway local declared earlier. A user-input parameter, for
		// instance, will be in tm.vars with a non-nil source.
		if ts := tm.get(name); ts != nil && ts.source != nil {
			return false
		}
		return true
	case "parenthesized_expression":
		// `({}, req.body)` — unwrap.
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return isFreshEmptyExpr(c, tm)
			}
		}
	}
	return false
}

// countNamedChildren returns the number of named (non-syntax) children
// under n. Used to distinguish empty `{}`/`[]` from non-empty literals.
func countNamedChildren(n *ast.Node) int {
	c := 0
	for i := 0; i < n.ChildCount(); i++ {
		if n.Child(i).IsNamed() {
			c++
		}
	}
	return c
}

// recordFreshLocalEmptyIfJS is called from processVarDeclInterproc after the
// LHS/RHS are extracted. If the language is JS/TS and the RHS is a fresh
// empty container expression, the LHS is recorded so a later merge-style
// proto sink can recognise it as a safe destination.
//
// Reduce accumulator inference: if the RHS is `<arr>.reduce(<callback>, {})`,
// we additionally mark the callback's accumulator parameter (first param of
// the arrow / function) as a fresh empty within the surrounding tm. This
// lets `.reduce((acc, v) => Object.assign(acc, ...), {})` suppress its
// inner sink. The accumulator name is conservative — we record into the
// same scope's tm because tsflow doesn't open a child scope for the
// callback in this code path; if name collides with a later binding it'll
// be cleared by the assignment hook.
func recordFreshLocalEmptyIfJS(lhsName string, rhs *ast.Node, tm *taintMap, cfg *langConfig) {
	if cfg == nil || tm == nil || lhsName == "" {
		return
	}
	if cfg.language != rules.LangJavaScript && cfg.language != rules.LangTypeScript {
		return
	}
	// Belt-and-suspenders: cloneMap was missing this field historically; if a
	// caller hands us a clone produced by an older code path the map can be
	// nil. Bail rather than panic.
	if tm.freshLocalEmpty == nil {
		return
	}
	if rhs != nil && isFreshEmptyExpr(rhs, tm) {
		tm.freshLocalEmpty[lhsName] = true
	}
}

// noteReduceAccumulatorFreshness scans an expression for any
// `.reduce(callback, {})` shapes and, when the initial value is a fresh
// empty literal, marks the callback's first parameter (the accumulator) as
// fresh in tm. Called from the walker on any expression so the recording
// can happen for both assignment RHSes and bare-statement reduce calls.
func noteReduceAccumulatorFreshness(n *ast.Node, tm *taintMap, cfg *langConfig) {
	if n == nil || tm == nil || cfg == nil {
		return
	}
	if cfg.language != rules.LangJavaScript && cfg.language != rules.LangTypeScript {
		return
	}
	walkReduceCalls(n, tm, cfg)
}

func walkReduceCalls(n *ast.Node, tm *taintMap, cfg *langConfig) {
	if n == nil {
		return
	}
	if n.Type() == "call_expression" {
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "member_expression" {
			prop := fn.ChildByFieldName("property")
			if prop != nil && prop.Text() == "reduce" {
				argsNode := n.ChildByFieldName("arguments")
				if argsNode != nil {
					var args []*ast.Node
					for i := 0; i < argsNode.ChildCount(); i++ {
						c := argsNode.Child(i)
						if c.IsNamed() {
							args = append(args, c)
						}
					}
					if len(args) >= 2 && isFreshEmptyExpr(args[1], tm) {
						markFirstParamFresh(args[0], tm)
					}
				}
			}
		}
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			walkReduceCalls(c, tm, cfg)
		}
	}
}

// markFirstParamFresh records the first parameter of an arrow / function
// expression as fresh. Handles both `(acc, v) => ...` and `function (acc,
// v) { ... }` shapes.
func markFirstParamFresh(callback *ast.Node, tm *taintMap) {
	if callback == nil {
		return
	}
	t := callback.Type()
	if t != "arrow_function" && t != "function" && t != "function_expression" {
		return
	}
	// arrow_function: parameter can be a single bare identifier (`x => ...`)
	// or a formal_parameters node.
	if t == "arrow_function" {
		param := callback.ChildByFieldName("parameter")
		if param != nil && param.Type() == "identifier" {
			tm.freshLocalEmpty[param.Text()] = true
			return
		}
	}
	params := callback.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	for i := 0; i < params.ChildCount(); i++ {
		c := params.Child(i)
		if !c.IsNamed() {
			continue
		}
		// First named child is the first parameter.
		switch c.Type() {
		case "identifier":
			tm.freshLocalEmpty[c.Text()] = true
		case "required_parameter", "optional_parameter":
			// TS parameter wrappers — find inner identifier.
			pat := c.ChildByFieldName("pattern")
			if pat != nil && pat.Type() == "identifier" {
				tm.freshLocalEmpty[pat.Text()] = true
			}
		}
		return
	}
}
