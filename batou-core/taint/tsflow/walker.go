package tsflow

import (
	"strconv"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// walkTree finds all function definitions in the tree and analyzes each one.
// It performs a two-pass analysis: first pass identifies which local functions
// propagate tainted parameters to their return value; second pass uses this
// information for interprocedural taint tracking.
func walkTree(tree *ast.Tree, cfg *langConfig, matcher *tsMatcher, filePath string) []taint.TaintFlow {
	root := tree.Root()
	if root == nil {
		return nil
	}

	// Find all function definitions.
	funcNodes := ast.FindByTypes(root, cfg.funcTypes)

	// Build a map of local function names → their AST nodes for interprocedural analysis.
	localFuncs := make(map[string]*ast.Node, len(funcNodes))
	for _, fnNode := range funcNodes {
		name := cfg.extractFuncName(fnNode)
		if name != "" {
			localFuncs[name] = fnNode
		}
	}

	// Pass 1: Build per-function taint summaries. For each function, seed each
	// parameter individually and track which ones propagate to the return value.
	summaries := buildTaintSummaries(funcNodes, cfg, matcher)

	var allFlows []taint.TaintFlow

	// Pass 2: Walk each function with interprocedural info.
	for _, fnNode := range funcNodes {
		scopeName := cfg.extractFuncName(fnNode)
		if scopeName == "" {
			scopeName = "__anonymous__"
		}
		body := cfg.extractFuncBody(fnNode)
		if body == nil {
			continue
		}

		flows := walkFuncInterproc(body, fnNode, scopeName, filePath, cfg, matcher, summaries)
		allFlows = append(allFlows, flows...)
	}

	return allFlows
}

// buildTaintSummaries analyzes each function to build rich taint summaries.
// For each parameter, it determines whether that parameter's taint propagates
// to the return value, and which sink categories are sanitized along the way.
// This enables context-sensitive interprocedural analysis: only arguments
// whose corresponding parameter propagates taint will taint the call result.
func buildTaintSummaries(funcNodes []*ast.Node, cfg *langConfig, matcher *tsMatcher) map[string]*TaintSummary {
	result := make(map[string]*TaintSummary)
	for _, fnNode := range funcNodes {
		name := cfg.extractFuncName(fnNode)
		if name == "" {
			continue
		}
		body := cfg.extractFuncBody(fnNode)
		if body == nil {
			continue
		}
		params := cfg.extractFuncParams(fnNode)

		summary := &TaintSummary{
			FuncName:    name,
			ParamFlows:  make([]map[taint.SinkCategory]bool, len(params)),
			ReturnTaint: make(map[int]bool),
			Sanitizes:   make(map[int]map[taint.SinkCategory]bool),
			IsPure:      true,
		}

		if len(params) == 0 {
			// No params — register the function as local but non-propagating.
			result[name] = summary
			continue
		}

		// For each parameter, seed it individually and check if its taint
		// reaches the return value. This gives per-parameter precision.
		for i, p := range params {
			tm := newTaintMap()
			src := &taint.SourceDef{
				ID:         "param." + strconv.Itoa(i) + "." + p,
				Category:   taint.SrcUserInput,
				Language:   cfg.language,
				MethodName: "parameter:" + p,
			}
			tm.set(p, &taintState{
				varName:    p,
				source:     src,
				sourceLine: 0,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps:      []taint.FlowStep{{Description: "param " + p}},
			})

			// Walk body with nil summaries (pass 1 — conservative for unknown calls).
			fb := newFlowBuilder("")
			walkBodyInterproc(body, tm, cfg, matcher, name, fb, nil)

			if returnsTainted(body, tm, cfg) {
				summary.ReturnTaint[i] = true
				summary.IsPure = false

				// Check sanitized categories for this parameter.
				if cats := returnSanitizedCategories(body, tm, cfg, matcher); cats != nil {
					summary.Sanitizes[i] = cats
				}
			}

			// Check if this param reached any sinks (via flows found).
			if len(fb.flows) > 0 {
				summary.IsPure = false
				sinkCats := make(map[taint.SinkCategory]bool)
				for _, f := range fb.flows {
					sinkCats[f.Sink.Category] = true
				}
				summary.ParamFlows[i] = sinkCats
			}
		}

		result[name] = summary
	}
	return result
}

// returnsTainted checks if any return statement in the body returns a tainted value.
func returnsTainted(body *ast.Node, tm *taintMap, cfg *langConfig) bool {
	found := false
	body.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		if n.Type() == "return_statement" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					if _, ok := nodeIsTainted(c, tm, cfg); ok {
						found = true
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

// returnSanitizedCategories returns the set of sink categories that are
// neutralized in ALL tainted return values. If the function sanitizes for
// XSS but not SQLi, only SnkHTMLOutput is returned.
func returnSanitizedCategories(body *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) map[taint.SinkCategory]bool {
	var allSanitized []map[taint.SinkCategory]bool
	body.Walk(func(n *ast.Node) bool {
		if n.Type() == "return_statement" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if !c.IsNamed() {
					continue
				}
				// Check if the returned expression is a sanitizer call
				// (e.g., return encodeForHTML(val)).
				call := unwrapToCall(c, cfg)
				if cfg.callTypes[call.Type()] {
					if san, sanitizedArg := matcher.matchSanitizer(call); san != nil {
						if _, ok := nodeIsTainted(sanitizedArg, tm, cfg); ok {
							cats := make(map[taint.SinkCategory]bool, len(san.Neutralizes))
							for _, cat := range san.Neutralizes {
								cats[cat] = true
							}
							allSanitized = append(allSanitized, cats)
							continue
						}
					}
				}
				// Check if variable already has sanitized categories.
				if ts, ok := nodeIsTainted(c, tm, cfg); ok && len(ts.sanitized) > 0 {
					allSanitized = append(allSanitized, ts.sanitized)
				}
			}
		}
		return true
	})
	if len(allSanitized) == 0 {
		return nil
	}
	// Intersect: only categories sanitized in ALL return paths.
	result := make(map[taint.SinkCategory]bool)
	for cat := range allSanitized[0] {
		if allSanitized[0][cat] {
			result[cat] = true
		}
	}
	for _, san := range allSanitized[1:] {
		for cat := range result {
			if !san[cat] {
				delete(result, cat)
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// walkFuncInterproc performs intraprocedural taint analysis with interprocedural
// awareness: calls to local functions known to propagate taint are treated as
// taint-propagating.
func walkFuncInterproc(body *ast.Node, fnNode *ast.Node, scopeName, filePath string, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary) []taint.TaintFlow {
	tm := newTaintMap()
	fb := newFlowBuilder(filePath)

	// Seed taint for framework parameters.
	seedParams(fnNode, tm, cfg, matcher)

	// Walk the body with taint tracking + interprocedural info.
	walkBodyInterproc(body, tm, cfg, matcher, scopeName, fb, summaries)

	return fb.flows
}

// walkBodyInterproc extends walkBody with interprocedural call tracking and
// switch statement handling.
func walkBodyInterproc(body *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	body.Walk(func(n *ast.Node) bool {
		nodeType := n.Type()

		// Handle if-statements with branch-aware taint merging.
		// Walks each branch with a cloned taint map, then merges results
		// (union: variable is tainted if tainted in ANY branch).
		if cfg.ifTypes[nodeType] && cfg.extractIfCondition != nil {
			processIfBranchAware(n, tm, cfg, matcher, scopeName, fb, summaries)
			return false // we handled children
		}

		// Handle switch statements — walk case bodies to propagate taint.
		if nodeType == "switch_expression" || nodeType == "switch_statement" {
			processSwitchInterproc(n, tm, cfg, matcher, scopeName, fb, summaries)
			return false // we handled children
		}

		// Handle switch_block / switch_block_statement_group — walk case contents.
		if nodeType == "switch_block_statement_group" || nodeType == "switch_block" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return false
		}

		// Handle enhanced for loop — propagate taint from iterable to loop variable.
		if nodeType == "enhanced_for_statement" {
			processEnhancedFor(n, tm, cfg)
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return false
		}

		// Handle Python for-in loops: for x in iterable — propagate taint from
		// iterable to loop variable (e.g., for name in request.headers.keys()).
		if nodeType == "for_statement" && string(cfg.language) == "python" {
			processPythonForLoop(n, tm, cfg, matcher, scopeName, fb, summaries)
			return false
		}

		// Handle for/while/do loops — walk the body.
		if nodeType == "for_statement" ||
			nodeType == "while_statement" || nodeType == "do_statement" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return false
		}

		// Handle try-catch — walk both try body and catch bodies.
		if nodeType == "try_statement" || nodeType == "try_with_resources_statement" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return false
		}

		// Handle assignments: x = expr
		if cfg.assignTypes[nodeType] {
			processAssignInterproc(n, tm, cfg, matcher, summaries)
			return true
		}

		// Handle variable declarations: var x = expr / let x = expr
		if cfg.varDeclTypes[nodeType] {
			processVarDeclInterproc(n, tm, cfg, matcher, summaries)
			return true
		}

		// Handle call expressions: check source, sanitizer, sink
		if cfg.callTypes[nodeType] {
			processCallInterproc(n, tm, cfg, matcher, scopeName, fb, summaries)
			return true
		}

		// Handle attribute access as source.
		if cfg.attrTypes[nodeType] {
			processAttr(n, tm, cfg, matcher)
		}

		return true
	})
}

// processSwitchInterproc handles switch statements by walking all case bodies
// with the current taint map, allowing taint to propagate through switch/case.
func processSwitchInterproc(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	// Try to evaluate the switch condition to a constant.
	// Pattern: switch (switchTarget) where switchTarget = guess.charAt(1)
	// and guess = "ABC".
	cond := n.ChildByFieldName("condition")
	if cond != nil {
		// Unwrap parenthesized_expression around condition.
		inner := cond
		if inner.Type() == "parenthesized_expression" {
			for i := 0; i < inner.ChildCount(); i++ {
				c := inner.Child(i)
				if c.IsNamed() {
					inner = c
					break
				}
			}
		}
		if targetVal, ok := evalConstExpr(inner, tm); ok {
			// Find the matching case and only walk that one.
			if walkMatchingSwitchCase(n, targetVal, tm, cfg, matcher, scopeName, fb, summaries) {
				return
			}
		}
	}

	// Fallback: walk all children of the switch statement.
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
		}
	}
}

// walkMatchingSwitchCase finds the case matching targetVal and only walks that case body.
// Returns true if a match was found and handled.
func walkMatchingSwitchCase(n *ast.Node, targetVal int64, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) bool {
	body := n.ChildByFieldName("body")
	if body == nil {
		return false
	}

	var defaultCase *ast.Node
	for i := 0; i < body.ChildCount(); i++ {
		group := body.Child(i)
		if !group.IsNamed() {
			continue
		}
		// Check each switch_label in this group.
		isDefault := false
		matched := false
		for j := 0; j < group.ChildCount(); j++ {
			label := group.Child(j)
			if label.Type() != "switch_label" {
				continue
			}
			// Check if this is a "default" label.
			for k := 0; k < label.ChildCount(); k++ {
				lc := label.Child(k)
				if !lc.IsNamed() && lc.Text() == "default" {
					isDefault = true
				}
				if lc.IsNamed() {
					if v, ok := evalConstExpr(lc, tm); ok && v == targetVal {
						matched = true
					}
				}
			}
		}
		if isDefault {
			defaultCase = group
		}
		if matched {
			walkBodyInterproc(group, tm, cfg, matcher, scopeName, fb, summaries)
			return true
		}
	}

	// No case matched — walk default if present.
	if defaultCase != nil {
		walkBodyInterproc(defaultCase, tm, cfg, matcher, scopeName, fb, summaries)
		return true
	}
	return false
}

// processIfAllowlistInterproc is like processIfAllowlist but uses walkBodyInterproc.
// processIfBranchAware walks if/else branches with proper taint map
// snapshot and merge. Each branch gets a clone of the current taint map;
// after both branches are walked, the results are merged (union: a variable
// is tainted if tainted in ANY branch). This prevents false positives from
// safe assignments in never-taken branches clearing taint, and prevents
// false negatives from tainted assignments in always-taken branches being
// overwritten by the else branch.
func processIfBranchAware(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	cond := cfg.extractIfCondition(n)
	consequence := cfg.extractIfConsequence(n)
	alternative := cfg.extractIfAlternative(n)

	// Special case: allowlist check or validation guard in condition →
	// the if-branch has the variable sanitized, else-branch keeps it tainted.
	check := detectAllowlistCheck(cond, tm, cfg)
	if check == nil {
		// Try validation guard: x.contains("..") { return } clears taint on fallthrough
		check = detectValidationGuard(cond, tm, cfg)
	}
	if check != nil && consequence != nil {
		branchTm := tm.cloneMap()
		branchTm.delete(check.varName)
		walkBodyInterproc(consequence, branchTm, cfg, matcher, scopeName, fb, summaries)
		if alternative != nil {
			walkBodyInterproc(alternative, tm, cfg, matcher, scopeName, fb, summaries)
		} else if branchHasEarlyReturn(consequence) {
			// The allowlist rejection branch returns/raises — code after the
			// if only executes when the check passed. Clear taint on the
			// validated variable for the fallthrough path.
			tm.delete(check.varName)
		}
		return
	}

	// Constant condition: if we can evaluate the condition to a compile-time
	// constant, only walk the branch that actually executes. This eliminates
	// FPs from patterns like: if ((7*18)+num > 200) bar = "safe"; else bar = param;
	if cond != nil {
		if val, ok := evalConstExpr(cond, tm); ok {
			if val != 0 {
				// Condition is always true — only consequence executes.
				if consequence != nil {
					walkBodyInterproc(consequence, tm, cfg, matcher, scopeName, fb, summaries)
				}
			} else {
				// Condition is always false — only alternative executes.
				if alternative != nil {
					walkBodyInterproc(alternative, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return
		}
	}

	// General case: walk each branch with separate flow builders.
	// Flows found in BOTH branches are kept at full confidence.
	// Flows found in only ONE branch get decayed confidence (0.6x)
	// since that branch may not execute.
	if consequence == nil {
		return
	}

	preBranch := tm.cloneMap()

	// Walk if-branch with its own flow builder.
	ifTm := tm.cloneMap()
	ifFb := newFlowBuilder(fb.filePath)
	walkBodyInterproc(consequence, ifTm, cfg, matcher, scopeName, ifFb, summaries)

	if alternative != nil {
		// Walk else-branch with its own flow builder.
		elseTm := preBranch.cloneMap()
		elseFb := newFlowBuilder(fb.filePath)
		walkBodyInterproc(alternative, elseTm, cfg, matcher, scopeName, elseFb, summaries)

		// Merge flows: flows in both branches keep full confidence,
		// flows in only one branch get decayed.
		mergedFlows := mergeBranchFlows(ifFb.flows, elseFb.flows)
		fb.flows = append(fb.flows, mergedFlows...)

		// Merge taint maps (union for subsequent code).
		ifTm.mergeFrom(elseTm)
	} else {
		// No else branch — if-branch flows get decayed confidence
		// (the branch may not execute).
		for i := range ifFb.flows {
			ifFb.flows[i].Confidence *= branchSingleWeight
		}
		fb.flows = append(fb.flows, ifFb.flows...)
		ifTm.mergeFrom(preBranch)
	}

	tm.replaceFrom(ifTm)
}

// isDeterministicCondition returns true if the if-condition is a compile-time
// constant expression (arithmetic on integer literals with a comparison).
// These appear in OWASP Benchmark as always-true/false guards:
//
//	if 7 * 42 > 200:       → pure constant, always true
//	if (294 > 200):         → literal comparison
//
// When detected, the walker uses intersection merge (must-taint) instead of
// weighted merge (may-taint), aggressively eliminating FPs from dead branches.
// branchHasEarlyReturn checks if a branch body contains a return or raise/throw
// statement, indicating the code after the if only executes when this branch
// is NOT taken.
func branchHasEarlyReturn(body *ast.Node) bool {
	if body == nil {
		return false
	}
	found := false
	body.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		switch n.Type() {
		case "return_statement", "raise_statement", "throw_statement",
			"throw_expression":
			found = true
			return false
		}
		return true
	})
	return found
}

// evalConstExpr attempts to evaluate a constant integer expression using known
// local constants from the taint map. Returns (value, true) if the expression
// can be fully evaluated, (0, false) otherwise.
// Handles: integer literals, identifiers mapped to consts, +, -, *, /, >,
// <, >=, <=, ==, !=, parenthesized expressions.
func evalConstExpr(n *ast.Node, tm *taintMap) (int64, bool) {
	if n == nil {
		return 0, false
	}
	switch n.Type() {
	case "decimal_integer_literal", "integer", "number", "int_literal",
		"hex_integer_literal", "octal_integer_literal":
		text := n.Text()
		v, err := strconv.ParseInt(text, 0, 64)
		if err != nil {
			return 0, false
		}
		return v, true

	case "identifier":
		if tm != nil {
			if v, ok := tm.consts[n.Text()]; ok {
				return v, true
			}
		}
		return 0, false

	case "parenthesized_expression":
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return evalConstExpr(c, tm)
			}
		}
		return 0, false

	case "binary_expression", "binary_operator":
		left := n.ChildByFieldName("left")
		right := n.ChildByFieldName("right")
		if left == nil || right == nil {
			return 0, false
		}
		lv, lok := evalConstExpr(left, tm)
		rv, rok := evalConstExpr(right, tm)
		if !lok || !rok {
			return 0, false
		}
		// Extract operator from unnamed children.
		op := ""
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() {
				t := c.Text()
				if t == "+" || t == "-" || t == "*" || t == "/" ||
					t == ">" || t == "<" || t == ">=" || t == "<=" ||
					t == "==" || t == "!=" {
					op = t
					break
				}
			}
		}
		switch op {
		case "+":
			return lv + rv, true
		case "-":
			return lv - rv, true
		case "*":
			return lv * rv, true
		case "/":
			if rv == 0 {
				return 0, false
			}
			return lv / rv, true
		case ">":
			return boolToInt(lv > rv), true
		case "<":
			return boolToInt(lv < rv), true
		case ">=":
			return boolToInt(lv >= rv), true
		case "<=":
			return boolToInt(lv <= rv), true
		case "==":
			return boolToInt(lv == rv), true
		case "!=":
			return boolToInt(lv != rv), true
		}
		return 0, false

	case "unary_expression", "unary_operator":
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				v, ok := evalConstExpr(c, tm)
				if !ok {
					return 0, false
				}
				// Check for negation operator.
				if i > 0 {
					prev := n.Child(i - 1)
					if prev != nil && prev.Text() == "-" {
						return -v, true
					}
				}
				return v, true
			}
		}
		return 0, false

	// Method invocation: handle str.charAt(N) where str is a known string constant.
	case "method_invocation":
		if tm == nil {
			return 0, false
		}
		nameNode := n.ChildByFieldName("name")
		objNode := n.ChildByFieldName("object")
		if nameNode == nil || objNode == nil {
			return 0, false
		}
		if nameNode.Text() != "charAt" {
			return 0, false
		}
		strVal, ok := tm.strConsts[objNode.Text()]
		if !ok {
			return 0, false
		}
		// Extract the integer argument.
		argsNode := n.ChildByFieldName("arguments")
		if argsNode == nil {
			return 0, false
		}
		for i := 0; i < argsNode.ChildCount(); i++ {
			c := argsNode.Child(i)
			if c.IsNamed() {
				idx, ok := evalConstExpr(c, tm)
				if !ok || idx < 0 || int(idx) >= len(strVal) {
					return 0, false
				}
				return int64(strVal[idx]), true
			}
		}
		return 0, false

	// Character literal: 'A' → 65
	case "character_literal":
		text := n.Text()
		if len(text) == 3 && text[0] == '\'' && text[2] == '\'' {
			return int64(text[1]), true
		}
		return 0, false
	}
	return 0, false
}

// trackStrConst records a string constant if the RHS is a string literal.
func trackStrConst(varName string, rhs *ast.Node, tm *taintMap) {
	if rhs == nil {
		return
	}
	if rhs.Type() == "string_literal" || rhs.Type() == "string" {
		text := rhs.Text()
		// Strip surrounding quotes.
		if len(text) >= 2 && (text[0] == '"' || text[0] == '\'') {
			tm.strConsts[varName] = text[1 : len(text)-1]
		}
	}
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// isAllLiteralMatch checks if a node is a match/switch expression where every
// arm either returns a literal value or is an early-exit (return/break/continue).
// Such expressions produce untainted results regardless of the scrutinee's taint,
// because the output can only be one of the hardcoded literal values.
func isAllLiteralMatch(n *ast.Node) bool {
	t := n.Type()
	if t != "match_expression" && t != "switch_expression" {
		return false
	}
	// Find the match_block / switch_body child.
	var body *ast.Node
	for _, c := range n.NamedChildren() {
		ct := c.Type()
		if ct == "match_block" || ct == "switch_body" || ct == "switch_block" {
			body = c
			break
		}
	}
	if body == nil {
		return false
	}

	armCount := 0
	for _, arm := range body.NamedChildren() {
		at := arm.Type()
		if at != "match_arm" && at != "switch_case" && at != "switch_default" {
			continue
		}
		armCount++
		// The value is the last named child that isn't the pattern.
		children := arm.NamedChildren()
		var value *ast.Node
		if n := len(children); n > 0 {
			last := children[n-1]
			ct := last.Type()
			if ct != "match_pattern" && ct != "case_pattern" {
				value = last
			}
		}
		if value == nil {
			return false
		}
		if !isLiteralOrEarlyExit(value) {
			return false
		}
	}
	return armCount >= 2 // need at least 2 arms to be a meaningful match
}

// isLiteralOrEarlyExit checks if a node is a literal value or an early exit
// statement (return, break, continue).
func isLiteralOrEarlyExit(n *ast.Node) bool {
	t := n.Type()
	switch t {
	case "string_literal", "integer_literal", "float_literal",
		"boolean_literal", "char_literal", "number_literal",
		"string", "number", "true", "false", "nil", "null_literal":
		return true
	case "return_expression", "return_statement", "break_expression",
		"break_statement", "continue_expression", "continue_statement":
		return true
	case "block", "expression_statement":
		// Block containing a single statement — check the inner expression.
		children := n.NamedChildren()
		if len(children) == 1 {
			return isLiteralOrEarlyExit(children[0])
		}
	case "unary_expression", "prefix_expression":
		// e.g., -1
		children := n.NamedChildren()
		if len(children) == 1 {
			return isLiteralOrEarlyExit(children[0])
		}
	}
	return false
}

// unwrapToCall unwraps cast_expression and parenthesized_expression wrappers
// to find the inner call node. Java frequently uses casts around map/list .get()
// calls, e.g., (String) map.get("key"). Returns the inner call node if found,
// otherwise returns the original node unchanged.
func unwrapToCall(n *ast.Node, cfg *langConfig) *ast.Node {
	for {
		switch n.Type() {
		case "cast_expression":
			// Java/C cast: (Type) expr — the value field contains the inner expression.
			inner := n.ChildByFieldName("value")
			if inner == nil {
				return n
			}
			n = inner
		case "parenthesized_expression":
			// (expr) — unwrap parentheses.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					n = c
					break
				}
			}
			continue
		case "match_expression":
			// Rust: match expr { ... } — unwrap to the matched expression.
			value := n.ChildByFieldName("value")
			if value == nil {
				return n
			}
			n = value
			continue
		default:
			return n
		}
	}
}

// processAssignInterproc extends processAssign with interprocedural call tracking.
func processAssignInterproc(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary) {
	lhsName := cfg.extractAssignLHS(n)
	if lhsName == "" || lhsName == "_" {
		return
	}

	rhs := cfg.extractAssignRHS(n)
	if rhs == nil {
		return
	}

	line := int(n.StartRow()) + 1
	_ = line

	// Match/switch with all-literal arms → untainted result.
	if isAllLiteralMatch(rhs) {
		tm.delete(lhsName)
		return
	}

	// Unwrap cast/parens to find the inner call node (e.g., (String) map.get("key")).
	rhsCall := unwrapToCall(rhs, cfg)

	// Check if RHS is a sanitizer call.
	if cfg.callTypes[rhsCall.Type()] {
		if san, sanitizedArg := matcher.matchSanitizer(rhsCall); san != nil {
			// Check argument taint first; fall back to receiver taint for
			// zero-argument receiver methods (e.g., path.canonicalize()).
			var ts *taintState
			var ok bool
			if sanitizedArg != nil {
				ts, ok = nodeIsTainted(sanitizedArg, tm, cfg)
			}
			if !ok {
				recv := cfg.extractCallReceiver(rhsCall)
				if recv != "" {
					if rts := tm.get(recv); rts != nil && rts.source != nil {
						ts, ok = rts, true
					}
				}
			}
			if ok {
				newTs := ts.clone(lhsName, line, "sanitized by "+san.MethodName, 1.0)
				for _, cat := range san.Neutralizes {
					newTs.sanitized[cat] = true
				}
				tm.set(lhsName, newTs)
				return
			}
		}
	}

	// Check if RHS is or contains a taint source.
	if src := findSourceInExpr(rhs, matcher, cfg); src != nil {
		tm.set(lhsName, &taintState{
			varName:    lhsName,
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     lhsName,
			}},
		})
		return
	}

	// For call expressions: check for list.get(N) with per-index tracking
	// before falling back to generic interprocedural propagation.
	if cfg.callTypes[rhsCall.Type()] {
		rhsCallName := cfg.extractCallName(rhsCall)
		rhsReceiver := cfg.extractCallReceiver(rhsCall)
		if rhsReceiver != "" && rhsCallName == "get" {
			args := cfg.extractCallArgs(rhsCall)
			if len(args) > 0 {
				argText := strings.TrimSpace(args[0].Text())

				// map.get("key") — per-key taint lookup.
				keyText := strings.Trim(argText, "\"'")
				if keyText != argText { // was quoted → it's a string key
					if elemTs, tracked := tm.mapGet(rhsReceiver, keyText); tracked {
						if elemTs != nil {
							newTs := elemTs.clone(lhsName, line, "map.get(\""+keyText+"\")", 0.95)
							tm.set(lhsName, newTs)
						} else {
							// Safe key — clear any previous taint (last-write-wins).
							tm.delete(lhsName)
						}
						// Key resolved — don't fall through.
						return
					}
				}

				// list.get(N) — per-index taint lookup.
				if li, ok := tm.lists[rhsReceiver]; ok && li != nil {
					if idx, err := strconv.Atoi(argText); err == nil {
						elemTs := tm.listGet(rhsReceiver, idx)
						if elemTs != nil {
							newTs := elemTs.clone(lhsName, line, "list.get("+argText+")", 0.95)
							tm.set(lhsName, newTs)
						} else {
							// Safe index — clear any previous taint (last-write-wins).
							tm.delete(lhsName)
						}
						// Index resolved — don't fall through.
						return
					}
				}
			}
		}
		// Before generic call propagation, try constant evaluation
		// (e.g., guess.charAt(1) where guess is a known string constant).
		if v, ok := evalConstExpr(rhsCall, tm); ok {
			tm.consts[lhsName] = v
			return
		}
		propagateCallResultInterproc(lhsName, line, rhsCall, tm, cfg, summaries)
		return
	}

	// Non-call RHS: check if it references any tainted variable.
	if ts, ok := nodeIsTainted(rhs, tm, cfg); ok {
		decay := propagationConfidence(rhs)
		newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
		tm.set(lhsName, newTs)
	} else {
		// Track constants for constant condition/switch evaluation.
		if v, ok := evalConstExpr(rhs, tm); ok {
			tm.consts[lhsName] = v
		}
		trackStrConst(lhsName, rhs, tm)
	}
}

// processVarDeclInterproc extends processVarDecl with interprocedural call tracking.
func processVarDeclInterproc(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary) {
	lhsName, rhs := extractVarDeclParts(n, cfg)
	if lhsName == "" || lhsName == "_" || rhs == nil {
		return
	}

	line := int(n.StartRow()) + 1

	// Match/switch with all-literal arms produces an untainted result regardless
	// of the scrutinee's taint.  e.g., match param.as_str() { "a" => "x", _ => return }
	if isAllLiteralMatch(rhs) {
		tm.delete(lhsName)
		return
	}

	// Unwrap cast/parens to find the inner call node (e.g., (String) map.get("key")).
	rhsCall := unwrapToCall(rhs, cfg)

	// Check if RHS is a sanitizer call.
	if cfg.callTypes[rhsCall.Type()] {
		if san, sanitizedArg := matcher.matchSanitizer(rhsCall); san != nil {
			// Check argument taint first; fall back to receiver taint for
			// zero-argument receiver methods (e.g., path.canonicalize()).
			var ts *taintState
			var ok bool
			if sanitizedArg != nil {
				ts, ok = nodeIsTainted(sanitizedArg, tm, cfg)
			}
			if !ok {
				recv := cfg.extractCallReceiver(rhsCall)
				if recv != "" {
					if rts := tm.get(recv); rts != nil && rts.source != nil {
						ts, ok = rts, true
					}
				}
			}
			if ok {
				newTs := ts.clone(lhsName, line, "sanitized by "+san.MethodName, 1.0)
				for _, cat := range san.Neutralizes {
					newTs.sanitized[cat] = true
				}
				tm.set(lhsName, newTs)
				return
			}
		}
	}

	// Check if RHS is or contains a taint source.
	if src := findSourceInExpr(rhs, matcher, cfg); src != nil {
		tm.set(lhsName, &taintState{
			varName:    lhsName,
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     lhsName,
			}},
		})
		return
	}

	// For call expressions: check for list.get(N) / map.get("key") with
	// per-index/per-key tracking before falling back to generic propagation.
	if cfg.callTypes[rhsCall.Type()] {
		rhsCallName := cfg.extractCallName(rhsCall)
		rhsReceiver := cfg.extractCallReceiver(rhsCall)
		if rhsReceiver != "" && rhsCallName == "get" {
			args := cfg.extractCallArgs(rhsCall)
			if len(args) > 0 {
				argText := strings.TrimSpace(args[0].Text())

				// map.get("key") — per-key taint lookup.
				keyText := strings.Trim(argText, "\"'")
				if keyText != argText { // was quoted → it's a string key
					if elemTs, tracked := tm.mapGet(rhsReceiver, keyText); tracked {
						if elemTs != nil {
							newTs := elemTs.clone(lhsName, line, "map.get(\""+keyText+"\")", 0.95)
							tm.set(lhsName, newTs)
						} else {
							// Safe key — clear any previous taint (last-write-wins).
							tm.delete(lhsName)
						}
						// Key resolved — don't fall through.
						return
					}
				}

				// list.get(N) — per-index taint lookup.
				if li, ok := tm.lists[rhsReceiver]; ok && li != nil {
					if idx, err := strconv.Atoi(argText); err == nil {
						elemTs := tm.listGet(rhsReceiver, idx)
						if elemTs != nil {
							newTs := elemTs.clone(lhsName, line, "list.get("+argText+")", 0.95)
							tm.set(lhsName, newTs)
						} else {
							// Safe index — clear any previous taint (last-write-wins).
							tm.delete(lhsName)
						}
						// Index resolved — don't fall through.
						return
					}
				}
			}
		}
		// Before generic call propagation, try constant evaluation
		// (e.g., guess.charAt(1) where guess is a known string constant).
		if v, ok := evalConstExpr(rhsCall, tm); ok {
			tm.consts[lhsName] = v
			return
		}
		propagateCallResultInterproc(lhsName, line, rhsCall, tm, cfg, summaries)
		return
	}

	// Non-call RHS: check if it references any tainted variable.
	if ts, ok := nodeIsTainted(rhs, tm, cfg); ok {
		decay := propagationConfidence(rhs)
		newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
		tm.set(lhsName, newTs)
	} else {
		// Track integer constants for constant condition evaluation.
		if v, ok := evalConstExpr(rhs, tm); ok {
			tm.consts[lhsName] = v
		}
		trackStrConst(lhsName, rhs, tm)
	}
}

// propagateCallResultInterproc determines if a call expression's result should
// be considered tainted for assignment purposes. Strategy:
//  1. Receiver taint always propagates (e.g., taintedStr.toUpperCase())
//  2. For LOCAL functions (found in summaries map): use per-parameter summaries
//     to only propagate taint from arguments whose corresponding parameter
//     actually flows to the return value (context-sensitive)
//  3. For EXTERNAL functions (not in local map): propagate from args
//     (conservative — unknown functions might pass data through)
func propagateCallResultInterproc(lhsName string, line int, rhs *ast.Node, tm *taintMap, cfg *langConfig, summaries map[string]*TaintSummary) {
	// Check receiver taint (e.g., taintedStr.toUpperCase()).
	if ts := callReceiverTainted(rhs, tm, cfg); ts != nil {
		decay := propagationConfidence(rhs)
		newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
		tm.set(lhsName, newTs)
		return
	}

	callName := cfg.extractCallName(rhs)

	// Check interprocedural summaries for local functions.
	if summaries != nil {
		summary, isLocal := summaries[callName]
		if isLocal {
			if !summary.anyParamPropagates() {
				return // local non-propagating function — don't taint
			}

			// Context-sensitive: only propagate taint from arguments whose
			// corresponding parameter flows to the return value.
			args := cfg.extractCallArgs(rhs)
			for i, arg := range args {
				if !summary.paramPropagates(i) {
					continue // this parameter doesn't flow to return
				}
				ts, ok := nodeIsTainted(arg, tm, cfg)
				if !ok {
					continue // argument isn't tainted
				}
				newTs := ts.clone(lhsName, line, "propagated through "+callName+"()", 0.85)
				// Apply per-parameter sanitization from the summary.
				if sanCats := summary.sanitizedCategories(i); sanCats != nil {
					for cat := range sanCats {
						newTs.sanitized[cat] = true
					}
				}
				tm.set(lhsName, newTs)
				return
			}
			return // local function — no tainted propagating arg found
		}
	}

	// External/library function: propagate from args (conservative).
	args := cfg.extractCallArgs(rhs)
	for _, arg := range args {
		if ts, ok := nodeIsTainted(arg, tm, cfg); ok {
			decay := propagationConfidence(rhs)
			newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
			tm.set(lhsName, newTs)
			return
		}
	}

	// No taint propagated from this call — but do NOT clear existing taint
	// here. The caller (processAssignInterproc) handles clearing for non-call
	// RHS. For calls, the conservative choice is to preserve existing taint
	// since the function may return the receiver or args in ways we can't track.
}

// callReceiverTainted checks if a call expression's receiver (object) is tainted.
// This is used for propagation: taintedObj.method() returns a tainted result.
// Unlike nodeIsTainted on the full call, this does NOT check arguments.
func callReceiverTainted(n *ast.Node, tm *taintMap, cfg *langConfig) *taintState {
	receiver := cfg.extractCallReceiver(n)
	if receiver != "" {
		if ts := tm.get(receiver); ts != nil && ts.source != nil {
			return ts
		}
	}
	// Also check the receiver AST node recursively (for chained calls).
	fn := n.ChildByFieldName("function")
	if fn == nil {
		fn = n.ChildByFieldName("name")
	}
	if fn != nil {
		obj := fn.ChildByFieldName("object")
		if obj == nil {
			obj = fn.ChildByFieldName("value")
		}
		if obj != nil {
			if ts, ok := nodeIsTainted(obj, tm, cfg); ok {
				return ts
			}
		}
	}
	return nil
}

// processCallInterproc extends processCall with interprocedural awareness
// and callback taint propagation (.then, .map, .filter, etc.).
func processCallInterproc(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	// Delegate to the base processCall for source/sink matching.
	processCall(n, tm, cfg, matcher, scopeName, fb)

	// Check for callback propagation patterns (JS/TS only).
	if cfg.language == "javascript" || cfg.language == "typescript" {
		callName := cfg.extractCallName(n)
		if pattern := isCallbackPropagationCall(callName); pattern != nil {
			processCallbackPropagation(n, tm, cfg, matcher, scopeName, fb, summaries, pattern)
		}
	}
}

// seedParams seeds taint for common framework parameters.
func seedParams(fnNode *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	// Check if this function is a web handler (has route annotations).
	// If so, all parameters are user-controlled.
	isHandler := isWebHandlerFunc(fnNode, cfg)

	params := cfg.extractFuncParams(fnNode)
	for _, paramName := range params {
		lower := strings.ToLower(paramName)
		// Seed if: common input name, OR web handler param, OR annotated param.
		shouldSeed := isInputParamName(lower) || isHandler
		if !shouldSeed && cfg.language == rules.LangJava {
			shouldSeed = hasInputAnnotation(fnNode, paramName)
		}
		if !shouldSeed {
			continue
		}

		conf := 0.6
		desc := "function parameter with input-like name"
		if isHandler {
			conf = 0.9
			desc = "web handler parameter (user-controlled)"
		}

		src := &taint.SourceDef{
			ID:          string(cfg.language) + ".param." + paramName,
			Category:    taint.SrcUserInput,
			Language:    cfg.language,
			MethodName:  "parameter:" + paramName,
			Description: desc,
		}
		tm.set(paramName, &taintState{
			varName:    paramName,
			source:     src,
			sourceLine: 0,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: conf,
			steps: []taint.FlowStep{{
				Line:        0,
				Description: "parameter " + paramName + " assumed tainted",
				VarName:     paramName,
			}},
		})
	}
}

// extractVarDeclParts extracts the variable name and RHS value from a
// variable declaration node, handling the various tree-sitter structures.
func extractVarDeclParts(n *ast.Node, cfg *langConfig) (string, *ast.Node) {
	// Try standard field names for the variable name.
	nameNode := n.ChildByFieldName("name")
	if nameNode == nil {
		nameNode = n.ChildByFieldName("declarator") // C/C++: init_declarator
	}
	if nameNode == nil {
		nameNode = n.ChildByFieldName("pattern") // Rust: let_declaration
	}

	// Try standard field names for the RHS value.
	rhs := n.ChildByFieldName("value")

	// C#: value is inside an equals_value_clause initializer.
	if rhs == nil {
		if init := n.ChildByFieldName("initializer"); init != nil {
			for i := 0; i < init.ChildCount(); i++ {
				c := init.Child(i)
				if c.IsNamed() {
					rhs = c
					break
				}
			}
		}
	}

	// Kotlin/Swift: property_declaration — name is in a nested
	// variable_declaration child, value is the expression after "=".
	if nameNode == nil || rhs == nil {
		var foundName *ast.Node
		var foundValue *ast.Node
		afterEquals := false
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() && c.Text() == "=" {
				afterEquals = true
				continue
			}
			if !afterEquals {
				if foundName == nil {
					if c.Type() == cfg.identType || c.Type() == "identifier" {
						foundName = c
					} else if c.Type() == "variable_declaration" || c.Type() == "variable_declarator" {
						// Drill into the wrapper to find the identifier.
						foundName = findFirstIdent(c, cfg.identType)
					}
				}
			} else if foundValue == nil && c.IsNamed() {
				foundValue = c
			}
		}
		if nameNode == nil && foundName != nil {
			nameNode = foundName
		}
		if rhs == nil && foundValue != nil {
			rhs = foundValue
		}
	}

	if nameNode == nil {
		return "", nil
	}

	lhsName := extractIdentText(nameNode, cfg.identType)
	return lhsName, rhs
}

// extractIdentText extracts the identifier text from a node, drilling into
// wrapper nodes like pointer_declarator, variable_declarator, etc.
func extractIdentText(n *ast.Node, identType string) string {
	if n == nil {
		return ""
	}
	if n.Type() == "identifier" || n.Type() == identType {
		return n.Text()
	}
	// Walk to find the first identifier inside wrapper nodes.
	var found string
	n.Walk(func(c *ast.Node) bool {
		if c.Type() == "identifier" || (identType != "" && c.Type() == identType) {
			found = c.Text()
			return false
		}
		return true
	})
	return found
}

// findFirstIdent finds the first identifier-like node inside a wrapper.
func findFirstIdent(n *ast.Node, identType string) *ast.Node {
	if n == nil {
		return nil
	}
	if n.Type() == "identifier" || n.Type() == identType {
		return n
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.Type() == "identifier" || c.Type() == identType {
			return c
		}
	}
	return nil
}

// processCall handles call expressions — checking for source, sanitizer, and sink.
func processCall(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder) {
	line := int(n.StartRow()) + 1

	// Check as source (record in taint map under __expr__ for chaining).
	if src := matcher.matchSourceCall(n); src != nil {
		tm.set("__expr__", &taintState{
			varName:    "__expr__",
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     "__expr__",
			}},
		})
	}

	// List/accumulator method handling with per-index taint tracking.
	callName := cfg.extractCallName(n)
	receiver := cfg.extractCallReceiver(n)

	// .add() / .append() — track which index is tainted.
	if receiver != "" && (callName == "add" || callName == "append") {
		args := cfg.extractCallArgs(n)
		if len(args) > 0 {
			ts, isTainted := nodeIsTainted(args[0], tm, cfg)
			if isTainted {
				tm.listAdd(receiver, ts)
				// Also mark the whole receiver as tainted (for backward compat
				// with code that checks receiver taint directly).
				newTs := ts.clone(receiver, line, "accumulated via ."+callName+"()", 0.95)
				tm.set(receiver, newTs)
			} else {
				tm.listAdd(receiver, nil) // safe/literal element
			}
		}
	}

	// .remove(N) — shift list indices.
	if receiver != "" && callName == "remove" {
		args := cfg.extractCallArgs(n)
		if len(args) > 0 {
			idxText := args[0].Text()
			if idx, err := strconv.Atoi(strings.TrimSpace(idxText)); err == nil {
				tm.listRemove(receiver, idx)
			}
		}
	}

	// .put("key", value) — track per-key taint for maps/dicts.
	if receiver != "" && callName == "put" {
		args := cfg.extractCallArgs(n)
		if len(args) >= 2 {
			keyText := args[0].Text()
			// Strip quotes from string key
			keyText = strings.Trim(keyText, "\"'")
			ts, isTainted := nodeIsTainted(args[1], tm, cfg)
			if isTainted {
				tm.mapPut(receiver, keyText, ts)
				// Also mark whole receiver as tainted for backward compat
				newTs := ts.clone(receiver, line, "map.put("+keyText+")", 0.95)
				tm.set(receiver, newTs)
			} else {
				tm.mapPut(receiver, keyText, nil) // safe value
			}
		}
	}

	// Other accumulator methods (.write, .extend, .insert, .update) —
	// use the original whole-receiver tainting.
	if receiver != "" && isAccumulatorMethod(callName) &&
		callName != "add" && callName != "append" && callName != "remove" &&
		callName != "put" {
		args := cfg.extractCallArgs(n)
		for _, arg := range args {
			if ts, ok := nodeIsTainted(arg, tm, cfg); ok {
				newTs := ts.clone(receiver, line, "accumulated via ."+callName+"()", 0.95)
				tm.set(receiver, newTs)
				break
			}
		}
	}

	// Check as sink.
	sink, dangerousArgs := matcher.matchSinkCall(n)
	if sink != nil {
		found := false
		for _, argNode := range dangerousArgs {
			ts, ok := nodeIsTainted(argNode, tm, cfg)
			if !ok {
				continue
			}
			if !ts.isTaintedFor(sink.Category) {
				continue
			}
			// Check if the argument expression contains an inline sanitizer
			// call that neutralizes this sink category (e.g., res.send(escapeHtml(name))).
			if containsInlineSanitizer(argNode, matcher, cfg, sink.Category) {
				continue
			}
			fb.addFlow(ts, sink, line, scopeName)
			found = true
		}
		// If no tainted args found, check if the receiver is tainted.
		// Handles methods like pathlib.Path.read_text() where the tainted
		// data is the object itself, not a method argument.
		if !found {
			if ts := callReceiverTainted(n, tm, cfg); ts != nil {
				if ts.isTaintedFor(sink.Category) {
					fb.addFlow(ts, sink, line, scopeName)
				}
			}
		}
	}
}

// containsInlineSanitizer recursively walks an expression AST node looking
// for a sanitizer call that neutralizes the given sink category. This handles
// patterns like res.send(escapeHtml(userInput)) where the sanitizer is not
// assigned to a variable first.
func containsInlineSanitizer(n *ast.Node, matcher *tsMatcher, cfg *langConfig, sinkCat taint.SinkCategory) bool {
	if n == nil {
		return false
	}
	nodeType := n.Type()

	// Direct call — check if it's a sanitizer that neutralizes this category.
	if cfg.callTypes[nodeType] {
		if san, _ := matcher.matchSanitizer(n); san != nil {
			for _, cat := range san.Neutralizes {
				if cat == sinkCat {
					return true
				}
			}
		}
		// Check arguments recursively (sanitizer might be nested deeper).
		args := cfg.extractCallArgs(n)
		for _, arg := range args {
			if containsInlineSanitizer(arg, matcher, cfg, sinkCat) {
				return true
			}
		}
		return false
	}

	// Binary expression — check both sides.
	if nodeType == "binary_expression" || nodeType == "binary_operator" ||
		nodeType == "concatenated_string" || nodeType == "string_binary_expression" {
		left := n.ChildByFieldName("left")
		if containsInlineSanitizer(left, matcher, cfg, sinkCat) {
			return true
		}
		right := n.ChildByFieldName("right")
		return containsInlineSanitizer(right, matcher, cfg, sinkCat)
	}

	// Template string — check substitutions.
	if nodeType == "template_string" || nodeType == "template_substitution" ||
		nodeType == "interpolation" || nodeType == "string_interpolation" {
		for i := 0; i < n.ChildCount(); i++ {
			if containsInlineSanitizer(n.Child(i), matcher, cfg, sinkCat) {
				return true
			}
		}
	}

	// Parenthesized expression — unwrap.
	if nodeType == "parenthesized_expression" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return containsInlineSanitizer(c, matcher, cfg, sinkCat)
			}
		}
	}

	return false
}

// processAttr handles attribute access as potential sources (e.g., request.args).
// When found as a standalone expression (not RHS of assignment), we track it
// under the full text to support patterns like `sink(request.args.get("x"))`.
func processAttr(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	if src := matcher.matchSourceAttr(n); src != nil {
		fullText := n.Text()
		line := int(n.StartRow()) + 1
		if tm.get(fullText) == nil {
			tm.set(fullText, &taintState{
				varName:    fullText,
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "tainted by " + src.MethodName,
					VarName:     fullText,
				}},
			})
		}
	}
}

// findSourceInExpr checks if an expression is or contains a taint source.
// Handles: direct source calls, source attribute accesses, calls on source
// receivers (e.g., request.args.get("name")), subscripts on source
// attributes (e.g., request.form["key"]), and variable-based sources
// (e.g., PHP $_GET, $_POST superglobals).
func findSourceInExpr(n *ast.Node, matcher *tsMatcher, cfg *langConfig) *taint.SourceDef {
	if n == nil {
		return nil
	}

	// Direct source call: input(), os.getenv("X")
	if cfg.callTypes[n.Type()] {
		if src := matcher.matchSourceCall(n); src != nil {
			return src
		}
		// Call on source receiver: request.args.get("name"), env::var("CMD").unwrap()
		// For languages that use "function" field (Python/JS/Kotlin), fn is the function part.
		// For languages that use "object"+"name" fields (PHP member_call_expression), check object.
		fn := n.ChildByFieldName("function")
		if fn == nil {
			// PHP member_call_expression: "name" is the method, "object" is the receiver chain.
			obj := n.ChildByFieldName("object")
			if obj != nil && cfg.attrTypes[obj.Type()] {
				if src := matcher.matchSourceAttr(obj); src != nil {
					return src
				}
				return findSourceInExpr(obj, matcher, cfg)
			}
		}
		if fn != nil && cfg.attrTypes[fn.Type()] {
			// First check if fn itself is a source attribute.
			// Handles $request->query->get() where fn=$request->query is the source.
			if src := matcher.matchSourceAttr(fn); src != nil {
				return src
			}
			obj := fn.ChildByFieldName("object")
			if obj == nil {
				obj = fn.ChildByFieldName("value") // Rust: field_expression uses "value" not "object"
			}
			if obj == nil {
				// Kotlin navigation_expression doesn't use field names —
				// the first named child is the object (receiver chain).
				named := fn.NamedChildren()
				if len(named) > 0 {
					obj = named[0]
				}
			}
			if obj != nil {
				return findSourceInExpr(obj, matcher, cfg)
			}
		}
		return nil
	}

	// Source attribute: request.args, request.form, req.query, req.body
	// Recurse into nested attributes (e.g., req.query.name → check req.query)
	if cfg.attrTypes[n.Type()] {
		if src := matcher.matchSourceAttr(n); src != nil {
			return src
		}
		// Check the object of this attribute (handles req.query.name → req.query)
		obj := n.ChildByFieldName("object")
		if obj == nil {
			// Kotlin navigation_expression uses positional children, not field names.
			named := n.NamedChildren()
			if len(named) > 0 {
				obj = named[0]
			}
		}
		if obj != nil {
			return findSourceInExpr(obj, matcher, cfg)
		}
		return nil
	}

	// Subscript on source: request.form["key"], $_GET["name"], params[:cmd], queryParameters["id"]
	if n.Type() == "subscript" || n.Type() == "subscript_expression" || n.Type() == "element_reference" || n.Type() == "indexing_expression" {
		obj := n.ChildByFieldName("object")
		if obj == nil {
			obj = n.ChildByFieldName("value")
		}
		if obj == nil && n.ChildCount() > 0 {
			obj = n.Child(0)
		}
		return findSourceInExpr(obj, matcher, cfg)
	}

	// Variable that matches a source by name (e.g., PHP $_GET, $_POST, $_REQUEST)
	name := n.Text()
	if candidates := matcher.sourcesByMethod[name]; len(candidates) > 0 {
		for _, src := range candidates {
			if src.ObjectType == "" {
				return src
			}
		}
	}

	return nil
}

// processEnhancedFor handles Java enhanced for loops (for (Type var : iterable)).
// If the iterable is tainted, the loop variable inherits taint.
func processEnhancedFor(n *ast.Node, tm *taintMap, cfg *langConfig) {
	// enhanced_for_statement structure: type, name (identifier), value (expression), body
	varName := ""
	var iterableNode *ast.Node

	nameNode := n.ChildByFieldName("name")
	if nameNode != nil {
		varName = nameNode.Text()
	}
	iterableNode = n.ChildByFieldName("value")

	if varName == "" || iterableNode == nil {
		return
	}

	line := int(n.StartRow()) + 1

	// Check if the iterable is tainted.
	if ts, ok := nodeIsTainted(iterableNode, tm, cfg); ok {
		newTs := ts.clone(varName, line, "iterated from "+ts.varName, 0.95)
		tm.set(varName, newTs)
	}
}

// processPythonForLoop handles Python for-in loops (for x in iterable).
// If the iterable is tainted or a source, the loop variable inherits taint.
// Also handles calls on sources: for name in request.form.keys().
func processPythonForLoop(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	// Python for_statement: left (pattern_list or identifier), right (expression), body (block)
	varNode := n.ChildByFieldName("left")
	iterNode := n.ChildByFieldName("right")

	varName := ""
	if varNode != nil {
		if varNode.Type() == "identifier" {
			varName = varNode.Text()
		} else if varNode.Type() == "pattern_list" && varNode.ChildCount() > 0 {
			// for k, v in dict.items() — taint first identifier
			for i := 0; i < varNode.ChildCount(); i++ {
				c := varNode.Child(i)
				if c.Type() == "identifier" {
					varName = c.Text()
					break
				}
			}
		}
	}

	if varName != "" && iterNode != nil {
		line := int(n.StartRow()) + 1

		// Check if iterable is a source (e.g., request.form.keys())
		if src := findSourceInExpr(iterNode, matcher, cfg); src != nil {
			tm.set(varName, &taintState{
				varName:    varName,
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "iterated from " + src.MethodName,
					VarName:     varName,
				}},
			})
		} else if ts, ok := nodeIsTainted(iterNode, tm, cfg); ok {
			// Iterable variable is tainted
			newTs := ts.clone(varName, line, "iterated from "+ts.varName, 0.95)
			tm.set(varName, newTs)
		}
	}

	// Walk all children (body, else clause, etc.)
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
		}
	}
}

// isAccumulatorMethod returns true for methods that store their argument into
// the receiver object (e.g., list.append, StringIO.write, dict.update).
func isAccumulatorMethod(name string) bool {
	switch name {
	case "write", "append", "extend", "insert", "add", "update", "put":
		return true
	}
	return false
}

// isInputParamName checks if a parameter name suggests it carries user input.
func isInputParamName(lower string) bool {
	inputNames := []string{
		"userinput", "input", "data", "body", "payload",
		"rawdata", "rawbody", "rawinput", "userdata",
		"formdata", "postdata", "querystring", "params",
		"query", "form", "path",
	}
	for _, n := range inputNames {
		if lower == n {
			return true
		}
	}
	return false
}

// Web handler annotations that indicate a method receives HTTP requests.
var webHandlerAnnotations = []string{
	"GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
	"RequestMapping",
	"GET", "POST", "PUT", "DELETE", "PATCH",
	"app.route", "app.get", "app.post", "app.put", "app.delete",
	"router.get", "router.post",
	"Hono", "new Hono",
	"Query(", "Path(", "Json(", "Form(",
}

// Input annotations that mark a specific parameter as user-controlled.
var inputParamAnnotations = []string{
	"RequestParam", "PathVariable", "RequestBody", "RequestHeader",
	"CookieValue", "MatrixVariable", "RequestPart",
	"QueryParam", "PathParam", "FormParam", "HeaderParam", "CookieParam",
}

// isWebHandlerFunc checks if a function node has web handler annotations.
func isWebHandlerFunc(fnNode *ast.Node, cfg *langConfig) bool {
	if fnNode == nil {
		return false
	}
	fnText := fnNode.Text()
	if len(fnText) > 500 {
		fnText = fnText[:500]
	}
	for _, ann := range webHandlerAnnotations {
		if strings.Contains(fnText, ann) {
			return true
		}
	}
	return false
}

// hasInputAnnotation checks if a specific parameter in a Java function has
// an input annotation like @RequestParam, @PathVariable, etc.
func hasInputAnnotation(fnNode *ast.Node, paramName string) bool {
	if fnNode == nil {
		return false
	}
	params := fnNode.ChildByFieldName("parameters")
	if params == nil {
		return false
	}
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() != "formal_parameter" {
			continue
		}
		name := p.ChildByFieldName("name")
		if name == nil || name.Text() != paramName {
			continue
		}
		pText := p.Text()
		for _, ann := range inputParamAnnotations {
			if strings.Contains(pText, "@"+ann) {
				return true
			}
		}
	}
	return false
}

