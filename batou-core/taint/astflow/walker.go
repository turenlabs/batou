package astflow

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// walkFunc performs intraprocedural taint analysis on a single function body.
func walkFunc(
	fset *token.FileSet,
	fnType *ast.FuncType,
	body *ast.BlockStmt,
	scopeName string,
	filePath string,
	matcher *CatalogMatcher,
) []taint.TaintFlow {

	tm := NewTaintMap()
	fb := NewFlowBuilder(filePath)

	// Track Content-Type headers set in this function.
	contentTypeSet := ""

	// Pre-compute set of sink calls nested inside sanitizer calls.
	// E.g., filepath.Clean(filepath.Join("/data", name)) — suppress the inner Join sink.
	suppressedPositions := buildSuppressedSinkPositions(fset, body, matcher)

	// Track validation links: boolVar → taintedVar for indirect guard patterns.
	// E.g., matched, _ := regexp.MatchString(pattern, name) → validationLinks["matched"] = "name"
	validationLinks := make(map[string]string)

	// Seed taint for HTTP handler parameters.
	if fnType != nil && fnType.Params != nil {
		seedHTTPHandlerParams(fset, fnType.Params, tm)
	}

	// Walk every statement in the body.
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}

		switch stmt := n.(type) {
		case *ast.AssignStmt:
			processAssign(fset, stmt, tm, matcher, validationLinks)

		case *ast.ExprStmt:
			if call, ok := stmt.X.(*ast.CallExpr); ok {
				// Track Content-Type header setting.
				if ct := extractContentType(call); ct != "" {
					contentTypeSet = ct
				}
				checkSinkCall(fset, call, tm, matcher, scopeName, fb, contentTypeSet, suppressedPositions)
			}

		case *ast.DeferStmt:
			checkSinkCall(fset, stmt.Call, tm, matcher, scopeName, fb, contentTypeSet, suppressedPositions)

		case *ast.GoStmt:
			checkSinkCall(fset, stmt.Call, tm, matcher, scopeName, fb, contentTypeSet, suppressedPositions)

		case *ast.IfStmt:
			// Detect early-return guard patterns:
			// if !condition { return } or if condition { http.Error(...); return }
			processGuardPattern(fset, stmt, tm, matcher, validationLinks)

		case *ast.RangeStmt:
			processRange(fset, stmt, tm)

		case *ast.DeclStmt:
			if gd, ok := stmt.Decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
				for _, spec := range gd.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						processVarSpec(fset, vs, tm, matcher)
					}
				}
			}

		case *ast.ForStmt:
			if assign, ok := stmt.Init.(*ast.AssignStmt); ok {
				processAssign(fset, assign, tm, matcher, validationLinks)
			}

		case *ast.SendStmt: // ch <- taintedValue
			chanName := identName(stmt.Chan)
			if chanName == "" {
				break
			}
			line := fset.Position(stmt.Pos()).Line

			// Check if the value being sent is a sanitizer call.
			if call, ok := unwrapCall(stmt.Value); ok {
				if san, sanitizedExpr := matcher.MatchSanitizer(call); san != nil {
					if ts, ok := exprIsTainted(sanitizedExpr, tm); ok {
						newTs := ts.clone(chanName, line, "sanitized by "+san.MethodName+" and sent to channel", 0.9)
						for _, cat := range san.Neutralizes {
							newTs.sanitized[cat] = true
						}
						tm.Set(chanName, newTs)
						break
					}
				}
			}

			// Fallback: propagate taint without sanitization.
			if ts, ok := exprIsTainted(stmt.Value, tm); ok {
				tm.Set(chanName, ts.clone(chanName, line, "sent to channel "+chanName, 0.9))
			}

		case *ast.SelectStmt: // select { case v := <-ch: ... }
			if stmt.Body != nil {
				for _, clause := range stmt.Body.List {
					if cc, ok := clause.(*ast.CommClause); ok && cc.Comm != nil {
						if assign, ok := cc.Comm.(*ast.AssignStmt); ok {
							processAssign(fset, assign, tm, matcher, validationLinks)
						}
					}
				}
			}
		}

		// Check every call expression for source/sink, including nested ones.
		if call, ok := n.(*ast.CallExpr); ok {
			// Check as source.
			if src := matcher.MatchSource(call); src != nil {
				line := fset.Position(call.Pos()).Line
				varName := "__expr__"
				tm.Set(varName, &taintState{
					varName:    varName,
					source:     src,
					sourceLine: line,
					sanitized:  make(map[taint.SinkCategory]bool),
					confidence: 1.0,
					steps: []taint.FlowStep{{
						Line:        line,
						Description: "tainted by " + src.MethodName,
						VarName:     varName,
					}},
				})
			}

			// Check as sink.
			checkSinkCall(fset, call, tm, matcher, scopeName, fb, contentTypeSet, suppressedPositions)
		}

		return true
	})

	return fb.Flows()
}

// seedHTTPHandlerParams inspects function parameters and auto-taints variables
// that represent common HTTP input parameter names.
func seedHTTPHandlerParams(
	fset *token.FileSet,
	params *ast.FieldList,
	tm *TaintMap,
) {
	for _, field := range params.List {
		typeName := exprToString(field.Type)
		for _, name := range field.Names {
			varName := name.Name

			// Skip request types — they're not tainted themselves, but methods
			// called on them introduce taint (matched by CatalogMatcher).
			if isRequestType(typeName) {
				continue
			}

			// Parameters with common input names at lower confidence.
			if isInputParamName(varName) {
				src := &taint.SourceDef{
					ID:          "go.param." + varName,
					Category:    taint.SrcExternal,
					Language:    rules.LangGo,
					MethodName:  "parameter:" + varName,
					Description: "function parameter with input-like name",
				}
				line := fset.Position(name.Pos()).Line
				tm.Set(varName, &taintState{
					varName:    varName,
					source:     src,
					sourceLine: line,
					sanitized:  make(map[taint.SinkCategory]bool),
					confidence: 0.6,
					steps: []taint.FlowStep{{
						Line:        line,
						Description: "parameter " + varName + " assumed tainted",
						VarName:     varName,
					}},
				})
			}
		}
	}
}

// processAssign handles := and = assignment statements.
func processAssign(
	fset *token.FileSet,
	stmt *ast.AssignStmt,
	tm *TaintMap,
	matcher *CatalogMatcher,
	validationLinks map[string]string,
) {
	for i, lhs := range stmt.Lhs {
		lhsName := identName(lhs)
		if lhsName == "" || lhsName == "_" {
			continue
		}

		var rhs ast.Expr
		if i < len(stmt.Rhs) {
			rhs = stmt.Rhs[i]
		} else if len(stmt.Rhs) == 1 {
			// Multi-value return: x, err := someFunc()
			rhs = stmt.Rhs[0]
		} else {
			continue
		}

		line := fset.Position(stmt.Pos()).Line

		// Track validation links: if RHS is a validation function call
		// (regexp.MatchString, strings.Contains, etc.) that takes a tainted arg,
		// record that this LHS bool validates that tainted variable.
		if call, ok := unwrapCall(rhs); ok {
			if taintedVar := extractValidationTarget(call, tm); taintedVar != "" {
				validationLinks[lhsName] = taintedVar
			}
		}

		// Check if RHS is a source call.
		if call, ok := unwrapCall(rhs); ok {
			if src := matcher.MatchSource(call); src != nil {
				tm.Set(lhsName, &taintState{
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
				continue
			}

			// Check if RHS is a sanitizer call.
			if san, sanitizedExpr := matcher.MatchSanitizer(call); san != nil {
				if ts, ok := exprIsTainted(sanitizedExpr, tm); ok {
					newTs := ts.clone(lhsName, line, "sanitized by "+san.MethodName, 1.0)
					for _, cat := range san.Neutralizes {
						newTs.sanitized[cat] = true
					}
					tm.Set(lhsName, newTs)
					continue
				}
			}
		}

		// Check if the RHS expression references any tainted variable.
		if ts, ok := exprIsTainted(rhs, tm); ok {
			decay := propagationConfidence(rhs)
			newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)

			// Apply sanitization from sanitizer calls nested inside the RHS
			// (e.g., "prefix" + url.PathEscape(tainted)).
			applySanitizersInExpr(rhs, newTs, matcher)

			tm.Set(lhsName, newTs)
			continue
		}

		// If the RHS is a safe literal/constant, clear taint on LHS.
		// This handles patterns like: if !allowed[x] { x = "safe" }
		if isSafeLiteral(rhs) && tm.Has(lhsName) {
			tm.Set(lhsName, &taintState{
				varName:   lhsName,
				sanitized: make(map[taint.SinkCategory]bool),
			})
		}
	}
}

// processVarSpec handles var declarations: var x = expr
func processVarSpec(
	fset *token.FileSet,
	vs *ast.ValueSpec,
	tm *TaintMap,
	matcher *CatalogMatcher,
) {
	for i, name := range vs.Names {
		varName := name.Name
		if varName == "_" {
			continue
		}
		if i >= len(vs.Values) {
			continue
		}
		rhs := vs.Values[i]
		line := fset.Position(vs.Pos()).Line

		if call, ok := unwrapCall(rhs); ok {
			if src := matcher.MatchSource(call); src != nil {
				tm.Set(varName, &taintState{
					varName:    varName,
					source:     src,
					sourceLine: line,
					sanitized:  make(map[taint.SinkCategory]bool),
					confidence: 1.0,
					steps: []taint.FlowStep{{
						Line:        line,
						Description: "tainted by " + src.MethodName,
						VarName:     varName,
					}},
				})
				continue
			}

			if san, sanitizedExpr := matcher.MatchSanitizer(call); san != nil {
				if ts, ok := exprIsTainted(sanitizedExpr, tm); ok {
					newTs := ts.clone(varName, line, "sanitized by "+san.MethodName, 1.0)
					for _, cat := range san.Neutralizes {
						newTs.sanitized[cat] = true
					}
					tm.Set(varName, newTs)
					continue
				}
			}
		}

		if ts, ok := exprIsTainted(rhs, tm); ok {
			decay := propagationConfidence(rhs)
			newTs := ts.clone(varName, line, "assigned to "+varName, decay)
			tm.Set(varName, newTs)
		}
	}
}

// processRange handles range statements: for k, v := range taintedSlice { ... }
func processRange(
	fset *token.FileSet,
	stmt *ast.RangeStmt,
	tm *TaintMap,
) {
	ts, ok := exprIsTainted(stmt.X, tm)
	if !ok {
		return
	}
	line := fset.Position(stmt.Pos()).Line

	if stmt.Key != nil {
		if name := identName(stmt.Key); name != "" && name != "_" {
			tm.Set(name, ts.clone(name, line, "range key from "+ts.varName, 0.9))
		}
	}
	if stmt.Value != nil {
		if name := identName(stmt.Value); name != "" && name != "_" {
			tm.Set(name, ts.clone(name, line, "range value from "+ts.varName, 0.9))
		}
	}
}

// checkSinkCall checks if a call is a known sink and whether any argument
// reaching a dangerous position is tainted.
func checkSinkCall(
	fset *token.FileSet,
	call *ast.CallExpr,
	tm *TaintMap,
	matcher *CatalogMatcher,
	scopeName string,
	fb *FlowBuilder,
	contentTypeSet string,
	suppressedPositions map[token.Pos]bool,
) {
	sink, dangerousArgs := matcher.MatchSink(call)
	if sink == nil {
		return
	}

	// Suppress sinks nested inside sanitizer calls (e.g., filepath.Join inside filepath.Clean).
	if len(suppressedPositions) > 0 && suppressedPositions[call.Pos()] {
		return
	}


	// Suppress XSS sinks when Content-Type is non-HTML (text/plain, application/json).
	if sink.Category == taint.SnkHTMLOutput && isNonHTMLContentType(contentTypeSet) {
		return
	}

	// Suppress html/template Execute — auto-escaping prevents XSS/template injection.
	if sink.Category == taint.SnkTemplate && isHTMLTemplateExecute(call, matcher) {
		return
	}

	// Suppress typed struct deserialization — Go type system constrains input.
	if sink.Category == taint.SnkDeserialize && isTypedStructTarget(call) {
		return
	}

	// Suppress file-path sinks (e.g., filepath.Join) when the call is the argument
	// to a known sanitizer that neutralizes SnkFileWrite/SnkFileRead. This handles patterns like
	// filepath.Clean(filepath.Join("/data", name)) where Join is a sink but Clean sanitizes.
	if (sink.Category == taint.SnkFileWrite || sink.Category == taint.SnkFileRead) && sink.Severity <= rules.Medium {
		// Check if any tainted arg is also sanitized at a higher level in this expression.
		// We do this by checking if a sanitizer neutralizing this category exists for the
		// same variable in the taint map.
		allArgsSanitized := true
		for _, argExpr := range dangerousArgs {
			ts, ok := exprIsTainted(argExpr, tm)
			if !ok {
				continue
			}
			if ts.isTaintedFor(sink.Category) {
				allArgsSanitized = false
				break
			}
		}
		if allArgsSanitized {
			return
		}
	}

	for _, argExpr := range dangerousArgs {
		ts, ok := exprIsTainted(argExpr, tm)
		if !ok {
			continue
		}
		if !ts.isTaintedFor(sink.Category) {
			continue
		}

		// Suppress log injection when using %q format verb (quotes/escapes output).
		if sink.Category == taint.SnkLog && isQuotedFormatCall(call, argExpr) {
			continue
		}

		line := fset.Position(call.Pos()).Line
		fb.AddFlow(ts, sink, line, scopeName)
	}
}

// isRequestType checks if a type name looks like an HTTP request type.
func isRequestType(typeName string) bool {
	lower := strings.ToLower(typeName)
	return strings.Contains(lower, "request") ||
		strings.Contains(lower, "http.request") ||
		strings.Contains(lower, "gin.context") ||
		strings.Contains(lower, "echo.context") ||
		strings.Contains(lower, "fiber.ctx")
}

// isInputParamName checks if a parameter name suggests it carries user input.
func isInputParamName(name string) bool {
	lower := strings.ToLower(name)
	inputNames := []string{
		"userinput", "input", "data", "body", "payload",
		"rawdata", "rawbody", "rawinput", "userdata",
		"formdata", "postdata", "querystring",
	}
	for _, n := range inputNames {
		if lower == n {
			return true
		}
	}
	return false
}

// processGuardPattern detects early-return guard patterns and sanitizes
// tainted variables that pass the guard. Supports:
//   - if !allowed[var] { return }        (allowlist map check)
//   - if !strings.HasPrefix(var, ...) { return }  (prefix validation)
//   - if !regexp.MatchString(..., var) { return }  (regex validation)
//   - if err != nil || parsed.Host != "..." { return }  (URL validation)
//   - if err != nil { return }           (error check after sanitizer assignment)
func processGuardPattern(
	fset *token.FileSet,
	stmt *ast.IfStmt,
	tm *TaintMap,
	matcher *CatalogMatcher,
	validationLinks map[string]string,
) {
	if !bodyHasReturn(stmt.Body) {
		return
	}

	// Collect tainted variables referenced in the condition and sanitize them.
	// Also resolve indirect validation links (e.g., "matched" → "name").
	guardedVars := extractGuardedVars(stmt.Cond, tm, validationLinks)
	if len(guardedVars) == 0 {
		return
	}

	line := fset.Position(stmt.Pos()).Line
	categories := inferGuardCategories(stmt.Cond)

	for _, varName := range guardedVars {
		ts := tm.Get(varName)
		if ts == nil || ts.source == nil {
			continue
		}
		newTs := ts.clone(varName, line, "validated by guard condition", 1.0)
		for _, cat := range categories {
			newTs.sanitized[cat] = true
		}
		tm.Set(varName, newTs)
	}
}

// bodyHasReturn checks if a block statement contains a return statement.
func bodyHasReturn(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	for _, stmt := range body.List {
		if _, ok := stmt.(*ast.ReturnStmt); ok {
			return true
		}
	}
	return false
}

// extractGuardedVars finds tainted variable names referenced in a guard condition.
// Also resolves indirect validation links: if "matched" appears in the condition
// and validationLinks["matched"] = "name", then "name" is added as a guarded var.
func extractGuardedVars(cond ast.Expr, tm *TaintMap, validationLinks map[string]string) []string {
	var vars []string
	seen := make(map[string]bool)

	ast.Inspect(cond, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.Ident:
			// Direct tainted variable in condition.
			if !seen[e.Name] && tm.Get(e.Name) != nil && tm.Get(e.Name).source != nil {
				vars = append(vars, e.Name)
				seen[e.Name] = true
			}
			// Indirect: this identifier is a validation result (bool) that
			// validates a tainted variable (e.g., matched → name).
			if target, ok := validationLinks[e.Name]; ok {
				if !seen[target] && tm.Get(target) != nil && tm.Get(target).source != nil {
					vars = append(vars, target)
					seen[target] = true
				}
			}
		}
		return true
	})

	return vars
}

// inferGuardCategories determines which sink categories a guard condition protects against.
func inferGuardCategories(cond ast.Expr) []taint.SinkCategory {
	// Default: guard protects against all common injection categories.
	allCategories := []taint.SinkCategory{
		taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead,
		taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch,
		taint.SnkLog, taint.SnkTemplate, taint.SnkHeader,
		taint.SnkEval, taint.SnkLDAP, taint.SnkXPath,
		taint.SnkDeserialize,
	}

	// Check for specific guard function calls that hint at the category.
	hasSpecificGuard := false
	var specific []taint.SinkCategory

	ast.Inspect(cond, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel := selectorString(call.Fun)
		lower := strings.ToLower(sel)

		switch {
		case strings.Contains(lower, "hasprefix"):
			hasSpecificGuard = true
			specific = append(specific, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkRedirect, taint.SnkURLFetch)
		case strings.Contains(lower, "matchstring"):
			hasSpecificGuard = true
			specific = append(specific, taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkLog)
		}
		return true
	})

	// Check for map index guard: if !allowed[var]
	ast.Inspect(cond, func(n ast.Node) bool {
		if _, ok := n.(*ast.IndexExpr); ok {
			hasSpecificGuard = false // allowlist maps protect all categories
		}
		return true
	})

	if hasSpecificGuard && len(specific) > 0 {
		return specific
	}
	return allCategories
}

// extractContentType detects w.Header().Set("Content-Type", "...") calls
// and returns the content type value.
func extractContentType(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Set" {
		return ""
	}
	if len(call.Args) < 2 {
		return ""
	}
	// Check first arg is "Content-Type".
	firstArg, ok := call.Args[0].(*ast.BasicLit)
	if !ok || firstArg.Kind != token.STRING {
		return ""
	}
	headerName := strings.Trim(firstArg.Value, `"`)
	if !strings.EqualFold(headerName, "Content-Type") {
		return ""
	}
	// Extract value.
	secondArg, ok := call.Args[1].(*ast.BasicLit)
	if !ok || secondArg.Kind != token.STRING {
		return ""
	}
	return strings.Trim(secondArg.Value, `"`)
}

// isNonHTMLContentType checks if the content type is non-HTML (text/plain, application/json, etc.).
func isNonHTMLContentType(ct string) bool {
	if ct == "" {
		return false
	}
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "text/plain") ||
		strings.Contains(lower, "application/json") ||
		strings.Contains(lower, "application/xml") ||
		strings.Contains(lower, "application/octet-stream")
}

// isHTMLTemplateExecute checks if a template Execute call uses html/template
// (which auto-escapes). Uses import resolution via the CatalogMatcher's TypeEnv.
func isHTMLTemplateExecute(call *ast.CallExpr, matcher *CatalogMatcher) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Execute" && sel.Sel.Name != "ExecuteTemplate") {
		return false
	}

	// Walk backwards to find the template's creation package.
	// Check if the receiver was created from html/template by inspecting
	// the receiver's chain for an html/template import alias.
	recvName := deepReceiverName(sel.X)
	if recvName == "" {
		return false
	}

	// If the TypeEnv has import info, check for html/template.
	if matcher.typeEnv != nil {
		// Check common template creation patterns.
		importPath := matcher.typeEnv.ResolveImport(recvName)
		if importPath == "html/template" {
			return true
		}
		// Check all imports for html/template aliased.
		for alias, path := range matcher.typeEnv.importAliases {
			if path == "html/template" {
				// If template var was created from this alias, it's safe.
				varType := matcher.typeEnv.VarType(recvName)
				if strings.Contains(varType, alias) || strings.Contains(varType, "html") {
					return true
				}
				// Heuristic: if html/template is imported, and the template var
				// is named t/tmpl/tpl, assume it's html/template.
				lower := strings.ToLower(recvName)
				if lower == "t" || lower == "tmpl" || lower == "tpl" {
					return true
				}
				// The import exists — we can be reasonably confident.
				return true
			}
		}
	}

	return false
}

// isTypedStructTarget checks if a deserialization call targets a typed struct
// (not interface{} or map[string]interface{}). Typed struct deserialization
// constrains input via Go's type system.
func isTypedStructTarget(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	methodName := sel.Sel.Name

	switch methodName {
	case "Decode":
		// json.NewDecoder(...).Decode(&typedStruct)
		if len(call.Args) < 1 {
			return false
		}
		return isPointerToNamedStruct(call.Args[0])

	case "Unmarshal":
		// json.Unmarshal(data, &typedStruct)
		if len(call.Args) < 2 {
			return false
		}
		return isPointerToNamedStruct(call.Args[1])
	}
	return false
}

// isPointerToNamedStruct checks if an expression is &namedStruct (address of a named variable).
func isPointerToNamedStruct(expr ast.Expr) bool {
	unary, ok := expr.(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return false
	}
	// &structVar — the variable is a named struct instance.
	if id, ok := unary.X.(*ast.Ident); ok {
		// Skip common interface/map variable names.
		lower := strings.ToLower(id.Name)
		if lower == "result" || lower == "data" || lower == "out" || lower == "obj" || lower == "v" {
			return false
		}
		return true
	}
	// &StructType{} — composite literal of a named type.
	if lit, ok := unary.X.(*ast.CompositeLit); ok {
		if lit.Type != nil {
			return true
		}
	}
	return false
}

// isSafeLiteral checks if an expression is a constant literal value
// (string, int, float, bool) that cannot carry taint.
func isSafeLiteral(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return e.Name == "true" || e.Name == "false" || e.Name == "nil"
	case *ast.UnaryExpr:
		// -1, +2, etc.
		if _, ok := e.X.(*ast.BasicLit); ok {
			return true
		}
	}
	return false
}

// applySanitizersInExpr walks an expression tree and applies sanitization
// from any sanitizer calls found within it. This handles patterns like:
// target = "https://api.com/" + url.PathEscape(userInput)
func applySanitizersInExpr(expr ast.Expr, ts *taintState, matcher *CatalogMatcher) {
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if san, _ := matcher.MatchSanitizer(call); san != nil {
			for _, cat := range san.Neutralizes {
				ts.sanitized[cat] = true
			}
		}
		return true
	})
}

// isQuotedFormatCall checks if a log/printf call uses %q format verb for the
// given argument, which quotes and escapes the string value.
func isQuotedFormatCall(call *ast.CallExpr, argExpr ast.Expr) bool {
	if len(call.Args) < 1 {
		return false
	}
	// First arg should be the format string.
	fmtLit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || fmtLit.Kind != token.STRING {
		return false
	}
	fmtStr := fmtLit.Value
	// Check if format string contains %q.
	return strings.Contains(fmtStr, "%q")
}

// buildSuppressedSinkPositions pre-scans the AST to find sink calls that are
// nested inside sanitizer calls. These inner sinks should be suppressed because
// the outer sanitizer neutralizes them. E.g., filepath.Clean(filepath.Join("/data", name))
// — the inner filepath.Join is a SnkFileWrite sink but filepath.Clean sanitizes it.
func buildSuppressedSinkPositions(
	_ *token.FileSet,
	body *ast.BlockStmt,
	matcher *CatalogMatcher,
) map[token.Pos]bool {
	suppressed := make(map[token.Pos]bool)
	if body == nil {
		return suppressed
	}

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// Check if this call is a sanitizer.
		san, _ := matcher.MatchSanitizer(call)
		if san == nil {
			return true
		}
		// Walk the sanitizer's arguments to find nested sink calls.
		for _, arg := range call.Args {
			ast.Inspect(arg, func(inner ast.Node) bool {
				innerCall, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				sink, _ := matcher.MatchSink(innerCall)
				if sink == nil {
					return true
				}
				// Check if the sanitizer neutralizes this sink's category.
				for _, cat := range san.Neutralizes {
					if cat == sink.Category {
						suppressed[innerCall.Pos()] = true
						break
					}
				}
				return true
			})
		}
		return true
	})

	return suppressed
}

// extractValidationTarget checks if a call expression is a validation function
// (regexp.MatchString, strings.Contains, etc.) and returns the name of the
// tainted variable being validated, or "" if not applicable.
func extractValidationTarget(call *ast.CallExpr, tm *TaintMap) string {
	sel := selectorString(call.Fun)
	lower := strings.ToLower(sel)

	// Known validation functions that take a tainted argument.
	isValidation := strings.Contains(lower, "matchstring") ||
		strings.Contains(lower, "match") ||
		strings.Contains(lower, "contains") ||
		strings.Contains(lower, "hasprefix") ||
		strings.Contains(lower, "hassuffix") ||
		strings.Contains(lower, "equalfold")

	if !isValidation {
		return ""
	}

	// Find the first tainted argument in the call.
	for _, arg := range call.Args {
		name := identName(arg)
		if name != "" && tm.Get(name) != nil && tm.Get(name).source != nil {
			return name
		}
	}
	return ""
}
