package tsflow

import (
	"strings"

	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/taint"
)

// walkTree finds all function definitions in the tree and analyzes each one.
func walkTree(tree *ast.Tree, cfg *langConfig, matcher *tsMatcher, filePath string) []taint.TaintFlow {
	root := tree.Root()
	if root == nil {
		return nil
	}

	var allFlows []taint.TaintFlow

	// Find all function definitions.
	funcNodes := ast.FindByTypes(root, cfg.funcTypes)
	for _, fnNode := range funcNodes {
		scopeName := cfg.extractFuncName(fnNode)
		if scopeName == "" {
			scopeName = "__anonymous__"
		}
		body := cfg.extractFuncBody(fnNode)
		if body == nil {
			continue
		}

		flows := walkFunc(body, fnNode, scopeName, filePath, cfg, matcher)
		allFlows = append(allFlows, flows...)
	}

	return allFlows
}

// walkFunc performs intraprocedural taint analysis on a single function body.
func walkFunc(body *ast.Node, fnNode *ast.Node, scopeName, filePath string, cfg *langConfig, matcher *tsMatcher) []taint.TaintFlow {
	tm := newTaintMap()
	fb := newFlowBuilder(filePath)

	// Seed taint for framework parameters.
	seedParams(fnNode, tm, cfg, matcher)

	// Walk the body with taint tracking.
	walkBody(body, tm, cfg, matcher, scopeName, fb)

	return fb.flows
}

// walkBody walks AST nodes, tracking taint through assignments, calls, and
// allowlist-guarded branches.
func walkBody(body *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder) {
	body.Walk(func(n *ast.Node) bool {
		nodeType := n.Type()

		// Handle if-statements with allowlist/validation checks.
		if cfg.ifTypes[nodeType] && cfg.extractIfCondition != nil {
			return processIfAllowlist(n, tm, cfg, matcher, scopeName, fb)
		}

		// Handle assignments: x = expr
		if cfg.assignTypes[nodeType] {
			processAssign(n, tm, cfg, matcher)
			return true
		}

		// Handle variable declarations: var x = expr / let x = expr / const x = expr
		if cfg.varDeclTypes[nodeType] {
			processVarDecl(n, tm, cfg, matcher)
			return true
		}

		// Handle call expressions: check source, sanitizer, sink
		if cfg.callTypes[nodeType] {
			processCall(n, tm, cfg, matcher, scopeName, fb)
			return true
		}

		// Handle attribute access as source: request.args, request.body, etc.
		if cfg.attrTypes[nodeType] {
			processAttr(n, tm, cfg, matcher)
			// Don't return — keep walking children
		}

		return true
	})
}

// processIfAllowlist handles if-statements by checking whether the condition
// contains an allowlist/membership validation on a tainted variable. If so,
// the then-branch is walked with taint cleared for that variable. The
// else-branch (if any) is walked with the original taint map. Returns false
// to prevent the outer walk from descending into children (we handle them here).
func processIfAllowlist(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder) bool {
	cond := cfg.extractIfCondition(n)
	check := detectAllowlistCheck(cond, tm, cfg)

	consequence := cfg.extractIfConsequence(n)
	alternative := cfg.extractIfAlternative(n)

	if check != nil && consequence != nil {
		// Walk the then-branch with taint cleared for the validated variable.
		branchTm := tm.cloneMap()
		branchTm.delete(check.varName)
		walkBody(consequence, branchTm, cfg, matcher, scopeName, fb)

		// Walk the else-branch (if any) with the original taint map.
		if alternative != nil {
			walkBody(alternative, tm, cfg, matcher, scopeName, fb)
		}

		// Don't descend into children — we handled them.
		return false
	}

	// No allowlist detected; let normal walk descend into the if-statement children.
	return true
}

// seedParams seeds taint for common framework parameters.
func seedParams(fnNode *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	params := cfg.extractFuncParams(fnNode)
	for _, paramName := range params {
		lower := strings.ToLower(paramName)
		// Seed common input parameter names at lower confidence.
		if isInputParamName(lower) {
			src := &taint.SourceDef{
				ID:          string(cfg.language) + ".param." + paramName,
				Category:    taint.SrcExternal,
				Language:    cfg.language,
				MethodName:  "parameter:" + paramName,
				Description: "function parameter with input-like name",
			}
			tm.set(paramName, &taintState{
				varName:    paramName,
				source:     src,
				sourceLine: 0,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 0.6,
				steps: []taint.FlowStep{{
					Line:        0,
					Description: "parameter " + paramName + " assumed tainted",
					VarName:     paramName,
				}},
			})
		}
	}
}

// processAssign handles assignment statements.
func processAssign(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	lhsName := cfg.extractAssignLHS(n)
	if lhsName == "" || lhsName == "_" {
		return
	}

	rhs := cfg.extractAssignRHS(n)
	if rhs == nil {
		return
	}

	line := int(n.StartRow()) + 1 // tree-sitter rows are 0-based

	// Check if RHS is a sanitizer call (check before sources so sanitization wins).
	if cfg.callTypes[rhs.Type()] {
		if san, sanitizedArg := matcher.matchSanitizer(rhs); san != nil {
			if ts, ok := nodeIsTainted(sanitizedArg, tm, cfg); ok {
				newTs := ts.clone(lhsName, line, "sanitized by "+san.MethodName, 1.0)
				for _, cat := range san.Neutralizes {
					newTs.sanitized[cat] = true
				}
				tm.set(lhsName, newTs)
				return
			}
		}
	}

	// Check if RHS is or contains a taint source (call, attribute, or call-on-source).
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

	// Check if RHS references any tainted variable.
	if ts, ok := nodeIsTainted(rhs, tm, cfg); ok {
		decay := propagationConfidence(rhs)
		newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
		tm.set(lhsName, newTs)
	}
}

// processVarDecl handles variable declarations across languages.
// Different languages use different tree-sitter structures:
//   - JS/Java: variable_declarator with "name" + "value" fields
//   - C/C++:   init_declarator with "declarator" + "value" fields
//   - Rust:    let_declaration with "pattern" + "value" fields
//   - C#:      variable_declarator with "name" + initializer (equals_value_clause)
//   - Kotlin:  property_declaration with nested variable_declaration + direct child value
//   - Lua:     variable_declaration with "name" (variable_declarator) + "value" fields
func processVarDecl(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	lhsName, rhs := extractVarDeclParts(n, cfg)
	if lhsName == "" || lhsName == "_" || rhs == nil {
		return
	}

	line := int(n.StartRow()) + 1

	// Check if RHS is a sanitizer call.
	if cfg.callTypes[rhs.Type()] {
		if san, sanitizedArg := matcher.matchSanitizer(rhs); san != nil {
			if ts, ok := nodeIsTainted(sanitizedArg, tm, cfg); ok {
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

	if ts, ok := nodeIsTainted(rhs, tm, cfg); ok {
		decay := propagationConfidence(rhs)
		newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
		tm.set(lhsName, newTs)
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

	// Check as sink.
	sink, dangerousArgs := matcher.matchSinkCall(n)
	if sink != nil {
		for _, argNode := range dangerousArgs {
			ts, ok := nodeIsTainted(argNode, tm, cfg)
			if !ok {
				continue
			}
			if !ts.isTaintedFor(sink.Category) {
				continue
			}
			fb.addFlow(ts, sink, line, scopeName)
		}
	}
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
		fn := n.ChildByFieldName("function")
		if fn == nil {
			fn = n.ChildByFieldName("name")
		}
		if fn != nil && cfg.attrTypes[fn.Type()] {
			obj := fn.ChildByFieldName("object")
			if obj == nil {
				obj = fn.ChildByFieldName("value") // Rust: field_expression uses "value" not "object"
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
		if obj != nil {
			return findSourceInExpr(obj, matcher, cfg)
		}
		return nil
	}

	// Subscript on source: request.form["key"], $_GET["name"], params[:cmd]
	if n.Type() == "subscript" || n.Type() == "subscript_expression" || n.Type() == "element_reference" {
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

// isInputParamName checks if a parameter name suggests it carries user input.
func isInputParamName(lower string) bool {
	inputNames := []string{
		"userinput", "input", "data", "body", "payload",
		"rawdata", "rawbody", "rawinput", "userdata",
		"formdata", "postdata", "querystring", "params",
	}
	for _, n := range inputNames {
		if lower == n {
			return true
		}
	}
	return false
}
