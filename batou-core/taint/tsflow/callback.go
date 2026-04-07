package tsflow

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
)

// callbackPattern describes how taint propagates through a callback method.
type callbackPattern struct {
	methodName       string
	callbackArgIdx   int  // which argument is the callback (0-based)
	paramIdx         int  // which callback param receives taint (0-based)
	propagatesReturn bool // does callback return value taint the call result
}

// callbackPatterns lists methods that propagate taint into callbacks.
// The receiver's taint flows into the callback's parameter at paramIdx.
var callbackPatterns = []callbackPattern{
	// Promise methods
	{methodName: "then", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: true},
	{methodName: "catch", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: true},
	{methodName: "finally", callbackArgIdx: 0, paramIdx: -1, propagatesReturn: false},

	// Collection callbacks
	{methodName: "map", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: true},
	{methodName: "flatMap", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: true},
	{methodName: "filter", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: false},
	{methodName: "forEach", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: false},
	{methodName: "reduce", callbackArgIdx: 0, paramIdx: 1, propagatesReturn: true},
	{methodName: "find", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: true},
	{methodName: "some", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: false},
	{methodName: "every", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: false},

	// Event emitters
	{methodName: "on", callbackArgIdx: 1, paramIdx: 0, propagatesReturn: false},
	{methodName: "addListener", callbackArgIdx: 1, paramIdx: 0, propagatesReturn: false},
	{methodName: "subscribe", callbackArgIdx: 0, paramIdx: 0, propagatesReturn: false},
}

// callbackPatternMap is a lookup by method name for fast matching.
var callbackPatternMap map[string]*callbackPattern

func init() {
	callbackPatternMap = make(map[string]*callbackPattern, len(callbackPatterns))
	for i := range callbackPatterns {
		callbackPatternMap[callbackPatterns[i].methodName] = &callbackPatterns[i]
	}
}

// isCallbackPropagationCall returns the callback pattern for a method name,
// or nil if the method doesn't propagate taint through callbacks.
func isCallbackPropagationCall(methodName string) *callbackPattern {
	return callbackPatternMap[methodName]
}

// processCallbackPropagation handles taint propagation through callback methods.
// When taintedReceiver.then(data => sink(data)) is encountered:
//  1. Gets receiver taint state
//  2. Extracts the callback function from call arguments
//  3. Seeds the callback parameter with receiver taint (0.9x decay)
//  4. Walks the callback body
//  5. If propagatesReturn, marks the call result as tainted
func processCallbackPropagation(
	n *ast.Node,
	tm *taintMap,
	cfg *langConfig,
	matcher *tsMatcher,
	scopeName string,
	fb *flowBuilder,
	summaries map[string]*TaintSummary,
	pattern *callbackPattern,
) {
	// Get receiver taint.
	receiver := cfg.extractCallReceiver(n)
	if receiver == "" {
		return
	}
	receiverTs := tm.get(receiver)
	if receiverTs == nil {
		return
	}

	// Extract callback argument.
	args := cfg.extractCallArgs(n)
	if pattern.callbackArgIdx >= len(args) {
		return
	}
	callbackNode := args[pattern.callbackArgIdx]
	if callbackNode == nil {
		return
	}

	// Unwrap to the actual function node (arrow_function, function, etc.)
	cbFunc := unwrapCallback(callbackNode, cfg)
	if cbFunc == nil {
		return
	}

	// Extract callback parameters.
	params := cfg.extractFuncParams(cbFunc)
	if pattern.paramIdx < 0 || pattern.paramIdx >= len(params) {
		return
	}
	targetParam := params[pattern.paramIdx]

	// Clone taint map and seed the callback parameter with receiver taint.
	cbTm := tm.cloneMap()
	cbTs := &taintState{
		varName:    targetParam,
		source:     receiverTs.source,
		sourceLine: receiverTs.sourceLine,
		sanitized:  cloneSanitized(receiverTs.sanitized),
		confidence: receiverTs.confidence * 0.9,
		steps: append(append([]taint.FlowStep{}, receiverTs.steps...), taint.FlowStep{
			VarName:     targetParam,
			Description: "propagated via ." + pattern.methodName + "() callback",
			Line:        int(n.StartRow()) + 1,
		}),
	}
	cbTm.set(targetParam, cbTs)

	// Walk the callback body.
	body := cfg.extractFuncBody(cbFunc)
	if body == nil {
		return
	}
	walkBodyInterproc(body, cbTm, cfg, matcher, scopeName, fb, summaries)

	// If the callback return propagates, check if the body returns
	// a tainted value and mark the overall call result as tainted.
	if pattern.propagatesReturn {
		returnTs := findReturnTaint(body, cbTm, cfg)
		if returnTs != nil {
			// The call expression result (e.g. x = arr.map(...)) gets taint.
			// This is handled by the caller via the taint map: we mark
			// the "virtual" call result so propagateCallResult can pick it up.
			// For chained calls like .then().then(), the receiver of the
			// next call inherits taint from the previous call's result.
			// We achieve this by updating the receiver in the original taint map.
			tm.set(receiver, returnTs)
		}
	}
}

// unwrapCallback extracts the actual function node from a callback argument.
// Handles: arrow_function, function, function_expression, identifier (refs).
func unwrapCallback(n *ast.Node, cfg *langConfig) *ast.Node {
	if n == nil {
		return nil
	}
	if cfg.funcTypes[n.Type()] {
		return n
	}
	// Might be wrapped in parenthesized_expression.
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() && cfg.funcTypes[c.Type()] {
			return c
		}
	}
	return nil
}

// findReturnTaint looks for return statements in a function body and
// checks if the returned expression is tainted.
func findReturnTaint(body *ast.Node, tm *taintMap, cfg *langConfig) *taintState {
	var result *taintState

	// For arrow functions with expression body (no block), the body IS the return.
	if body.Type() != "statement_block" && body.Type() != "block" {
		return resolveExprTaint(body, tm, cfg)
	}

	body.Walk(func(n *ast.Node) bool {
		if result != nil {
			return false // already found
		}
		if n.Type() == "return_statement" {
			// Return value is the first named child after "return" keyword.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					result = resolveExprTaint(c, tm, cfg)
					return false
				}
			}
		}
		// Don't descend into nested function definitions.
		if cfg.funcTypes[n.Type()] && n != body {
			return false
		}
		return true
	})

	return result
}

// resolveExprTaint returns the taint state for an expression node,
// checking identifiers and member expressions against the taint map.
func resolveExprTaint(n *ast.Node, tm *taintMap, cfg *langConfig) *taintState {
	if n == nil {
		return nil
	}
	switch n.Type() {
	case "identifier":
		return tm.get(n.Text())
	case "member_expression":
		obj := n.ChildByFieldName("object")
		if obj != nil {
			return tm.get(obj.Text())
		}
	case "call_expression":
		// For chained calls like resp.json(), check if receiver is tainted.
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "member_expression" {
			obj := fn.ChildByFieldName("object")
			if obj != nil {
				return tm.get(obj.Text())
			}
		}
	}
	return nil
}

// cloneSanitized creates a copy of a sanitized categories map.
func cloneSanitized(src map[taint.SinkCategory]bool) map[taint.SinkCategory]bool {
	if src == nil {
		return nil
	}
	dst := make(map[taint.SinkCategory]bool, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
