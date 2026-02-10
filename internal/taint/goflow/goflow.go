// Package goflow implements AST-based intraprocedural taint analysis for Go source code.
//
// Unlike the regex-based engine in the parent taint package, goflow parses Go
// code into a full AST using go/ast and go/parser, then walks each function
// body tracking how tainted data flows through assignments, calls, binary
// expressions, composite literals, and range statements.
//
// This catches flows that regex cannot, such as:
//
//	name := r.FormValue("name")     // source
//	upper := strings.ToUpper(name)  // propagation
//	greeting := "Hello, " + upper   // propagation via concat
//	safe := html.EscapeString(greeting) // sanitizer
//	fmt.Fprintf(w, safe)            // OK — sanitized
//
//	id := r.FormValue("id")         // source
//	query := "SELECT * FROM users WHERE id = " + id // propagation
//	db.Query(query)                 // TAINT FLOW: user_input → sql_query
package goflow

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// GoFlowAnalyzer implements rules.Rule using Go AST taint analysis.
type GoFlowAnalyzer struct{}

func init() {
	rules.Register(&GoFlowAnalyzer{})
}

func (g *GoFlowAnalyzer) ID() string          { return "GTSS-FLOW" }
func (g *GoFlowAnalyzer) Name() string         { return "Go Taint Flow Analysis" }
func (g *GoFlowAnalyzer) Description() string  { return "AST-based intraprocedural taint tracking for Go source code" }
func (g *GoFlowAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (g *GoFlowAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

// Scan parses Go source and runs taint analysis on every function body.
func (g *GoFlowAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangGo {
		return nil
	}

	cat := taint.GetCatalog(rules.LangGo)
	if cat == nil {
		return nil
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, ctx.FilePath, ctx.Content, parser.AllErrors)
	if err != nil || file == nil {
		return nil
	}

	sources := cat.Sources()
	sinks := cat.Sinks()
	sanitizers := cat.Sanitizers()

	var findings []rules.Finding

	// Walk every function declaration.
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body == nil {
				return true
			}
			scopeName := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				scopeName = receiverTypeName(fn.Recv.List[0].Type) + "." + scopeName
			}
			flows := analyzeFunc(fset, fn.Type, fn.Body, scopeName, ctx.FilePath, sources, sinks, sanitizers)
			for i := range flows {
				findings = append(findings, flows[i].ToFinding())
			}
		case *ast.FuncLit:
			if fn.Body == nil {
				return true
			}
			flows := analyzeFunc(fset, fn.Type, fn.Body, "__closure__", ctx.FilePath, sources, sinks, sanitizers)
			for i := range flows {
				findings = append(findings, flows[i].ToFinding())
			}
		}
		return true
	})

	return findings
}

// ---------- taint state ----------

// taintState tracks the taint status of a single variable inside a function.
type taintState struct {
	varName    string
	source     *taint.SourceDef
	sourceLine int
	sanitized  map[taint.SinkCategory]bool
	confidence float64
	steps      []taint.FlowStep
}

// clone returns a deep copy with an appended flow step.
func (ts *taintState) clone(newVar string, line int, desc string, confDecay float64) *taintState {
	san := make(map[taint.SinkCategory]bool, len(ts.sanitized))
	for k, v := range ts.sanitized {
		san[k] = v
	}
	steps := make([]taint.FlowStep, len(ts.steps), len(ts.steps)+1)
	copy(steps, ts.steps)
	steps = append(steps, taint.FlowStep{
		Line:        line,
		Description: desc,
		VarName:     newVar,
	})
	return &taintState{
		varName:    newVar,
		source:     ts.source,
		sourceLine: ts.sourceLine,
		sanitized:  san,
		confidence: ts.confidence * confDecay,
		steps:      steps,
	}
}

// isTaintedFor returns true if the variable is tainted and NOT sanitized for cat.
func (ts *taintState) isTaintedFor(cat taint.SinkCategory) bool {
	if ts.source == nil {
		return false
	}
	return !ts.sanitized[cat]
}

// ---------- core analysis ----------

// analyzeFunc performs intraprocedural taint analysis on a single function body.
func analyzeFunc(
	fset *token.FileSet,
	fnType *ast.FuncType,
	body *ast.BlockStmt,
	scopeName string,
	filePath string,
	sources []taint.SourceDef,
	sinks []taint.SinkDef,
	sanitizers []taint.SanitizerDef,
) []taint.TaintFlow {

	taintMap := make(map[string]*taintState)
	var flows []taint.TaintFlow

	// Seed taint for HTTP handler parameters.
	if fnType != nil && fnType.Params != nil {
		seedHTTPHandlerParams(fset, fnType.Params, sources, taintMap)
	}

	// Walk every statement in the body.
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			processAssign(fset, stmt, taintMap, sources, sanitizers)

		case *ast.ExprStmt:
			if call, ok := stmt.X.(*ast.CallExpr); ok {
				checkSinkCall(fset, call, taintMap, sinks, scopeName, filePath, &flows)
			}

		case *ast.RangeStmt:
			processRange(fset, stmt, taintMap)

		case *ast.DeclStmt:
			if gd, ok := stmt.Decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
				for _, spec := range gd.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						processVarSpec(fset, vs, taintMap, sources, sanitizers)
					}
				}
			}

		case *ast.ReturnStmt:
			// For now we just check if return values reach sinks within the same
			// function (e.g., deferred calls). Full interprocedural is out of scope.

		case *ast.IfStmt:
			// We still walk into the if body via ast.Inspect; nothing extra needed.

		case *ast.ForStmt:
			// Process init statement if it's an assignment.
			if assign, ok := stmt.Init.(*ast.AssignStmt); ok {
				processAssign(fset, assign, taintMap, sources, sanitizers)
			}
		}

		// Check every call expression, even those nested inside other expressions
		// (e.g., db.Query(foo + bar) inside an if).
		if call, ok := n.(*ast.CallExpr); ok {
			// Check as source.
			if src, varName := isSourceCall(call, sources); src != nil {
				line := fset.Position(call.Pos()).Line
				if varName == "" {
					varName = "__expr__"
				}
				taintMap[varName] = &taintState{
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
				}
			}

			// Check as sink.
			checkSinkCall(fset, call, taintMap, sinks, scopeName, filePath, &flows)

			// Check as sanitizer — only relevant if it's the RHS of an assignment
			// which is handled in processAssign. Here we handle standalone calls
			// like html.EscapeString(x) that might be args to other calls.
		}

		return true
	})

	return flows
}

// ---------- parameter seeding ----------

// seedHTTPHandlerParams inspects function parameters and auto-taints variables
// that represent HTTP request objects or common input parameters.
func seedHTTPHandlerParams(
	fset *token.FileSet,
	params *ast.FieldList,
	sources []taint.SourceDef,
	taintMap map[string]*taintState,
) {
	for _, field := range params.List {
		typeName := exprToString(field.Type)
		for _, name := range field.Names {
			varName := name.Name

			// Auto-taint parameters whose type contains "Request" or match
			// common HTTP handler signatures.
			if isRequestType(typeName) {
				// The request variable itself is not tainted, but methods
				// called on it will introduce taint. We track the variable
				// name so isSourceCall can match receiver names later.
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
				taintMap[varName] = &taintState{
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
				}
			}
		}
	}
}

// ---------- assignment processing ----------

// processAssign handles := and = assignment statements, propagating taint
// from RHS to LHS and checking for source/sanitizer calls in the RHS.
func processAssign(
	fset *token.FileSet,
	stmt *ast.AssignStmt,
	taintMap map[string]*taintState,
	sources []taint.SourceDef,
	sanitizers []taint.SanitizerDef,
) {
	// Process each LHS/RHS pair.
	for i, lhs := range stmt.Lhs {
		lhsName := identName(lhs)
		if lhsName == "" || lhsName == "_" {
			continue
		}

		// Determine the corresponding RHS expression.
		var rhs ast.Expr
		if i < len(stmt.Rhs) {
			rhs = stmt.Rhs[i]
		} else if len(stmt.Rhs) == 1 {
			// Multi-value return: x, err := someFunc()
			// All LHS vars potentially receive taint from the single RHS call.
			rhs = stmt.Rhs[0]
		} else {
			continue
		}

		line := fset.Position(stmt.Pos()).Line

		// Check if RHS is a source call.
		if call, ok := unwrapCall(rhs); ok {
			if src, _ := isSourceCall(call, sources); src != nil {
				taintMap[lhsName] = &taintState{
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
				}
				continue
			}

			// Check if RHS is a sanitizer call.
			if san, sanitizedExpr := isSanitizerCall(call, sanitizers); san != nil {
				// Check if the argument to the sanitizer is tainted.
				if ts, ok := exprIsTainted(sanitizedExpr, taintMap); ok {
					newTs := ts.clone(lhsName, line, "sanitized by "+san.MethodName, 1.0)
					for _, cat := range san.Neutralizes {
						newTs.sanitized[cat] = true
					}
					taintMap[lhsName] = newTs
					continue
				}
			}
		}

		// Check if the RHS expression references any tainted variable.
		if ts, ok := exprIsTainted(rhs, taintMap); ok {
			decay := propagationConfidence(rhs)
			newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
			taintMap[lhsName] = newTs
		}
	}
}

// processVarSpec handles var declarations: var x = expr
func processVarSpec(
	fset *token.FileSet,
	vs *ast.ValueSpec,
	taintMap map[string]*taintState,
	sources []taint.SourceDef,
	sanitizers []taint.SanitizerDef,
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
			if src, _ := isSourceCall(call, sources); src != nil {
				taintMap[varName] = &taintState{
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
				}
				continue
			}

			if san, sanitizedExpr := isSanitizerCall(call, sanitizers); san != nil {
				if ts, ok := exprIsTainted(sanitizedExpr, taintMap); ok {
					newTs := ts.clone(varName, line, "sanitized by "+san.MethodName, 1.0)
					for _, cat := range san.Neutralizes {
						newTs.sanitized[cat] = true
					}
					taintMap[varName] = newTs
					continue
				}
			}
		}

		if ts, ok := exprIsTainted(rhs, taintMap); ok {
			decay := propagationConfidence(rhs)
			newTs := ts.clone(varName, line, "assigned to "+varName, decay)
			taintMap[varName] = newTs
		}
	}
}

// processRange handles range statements: for k, v := range taintedSlice { ... }
func processRange(
	fset *token.FileSet,
	stmt *ast.RangeStmt,
	taintMap map[string]*taintState,
) {
	ts, ok := exprIsTainted(stmt.X, taintMap)
	if !ok {
		return
	}
	line := fset.Position(stmt.Pos()).Line

	if stmt.Key != nil {
		if name := identName(stmt.Key); name != "" && name != "_" {
			taintMap[name] = ts.clone(name, line, "range key from "+ts.varName, 0.9)
		}
	}
	if stmt.Value != nil {
		if name := identName(stmt.Value); name != "" && name != "_" {
			taintMap[name] = ts.clone(name, line, "range value from "+ts.varName, 0.9)
		}
	}
}

// ---------- source matching ----------

// isSourceCall checks whether a call expression matches a known taint source.
// Returns the matching SourceDef and the variable name that should receive taint.
func isSourceCall(call *ast.CallExpr, sources []taint.SourceDef) (*taint.SourceDef, string) {
	sel := selectorString(call.Fun)

	for i := range sources {
		src := &sources[i]
		if matchesSourcePattern(sel, call, src) {
			return src, ""
		}
	}

	return nil, ""
}

// matchesSourcePattern checks if a call matches a source definition using
// heuristics based on method name and receiver variable name patterns.
func matchesSourcePattern(sel string, call *ast.CallExpr, src *taint.SourceDef) bool {
	// Direct package-level function match: os.Getenv, io.ReadAll, etc.
	if src.ObjectType == "" && src.MethodName != "" {
		if sel == src.MethodName {
			return true
		}
		// Handle dotted package names: os.Getenv
		parts := strings.Split(src.MethodName, ".")
		if len(parts) == 1 && strings.HasSuffix(sel, "."+parts[0]) {
			return true
		}
	}

	// Method call on receiver: r.FormValue, c.Query, etc.
	if src.ObjectType != "" && src.MethodName != "" {
		selExpr, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		methodName := selExpr.Sel.Name

		// Check for chained method matches like URL.Query
		methodParts := strings.Split(src.MethodName, "/")
		matched := false
		for _, mp := range methodParts {
			dotParts := strings.Split(mp, ".")
			finalMethod := dotParts[len(dotParts)-1]
			if methodName == finalMethod {
				matched = true
				break
			}
		}
		if !matched && methodName != src.MethodName {
			return false
		}

		// Match receiver variable name against common patterns for this object type.
		recvName := identName(selExpr.X)
		if recvName != "" && matchesReceiverType(recvName, src.ObjectType) {
			return true
		}

		// Handle chained calls like r.URL.Query().Get(...)
		if innerSel, ok := selExpr.X.(*ast.SelectorExpr); ok {
			innerRecv := identName(innerSel.X)
			if innerRecv != "" && matchesReceiverType(innerRecv, src.ObjectType) {
				return true
			}
		}

		// Handle call chains: r.URL.Query().Get(...)
		if innerCall, ok := selExpr.X.(*ast.CallExpr); ok {
			innerSel := selectorString(innerCall.Fun)
			if strings.Contains(innerSel, ".URL.Query") || strings.Contains(innerSel, ".Query") {
				innerRecv := deepReceiverName(innerCall.Fun)
				if innerRecv != "" && matchesReceiverType(innerRecv, src.ObjectType) {
					return true
				}
			}
		}
	}

	return false
}

// matchesReceiverType checks if a receiver variable name plausibly corresponds
// to a given type. Without full type information, we use naming conventions.
func matchesReceiverType(varName string, objType string) bool {
	lower := strings.ToLower(varName)

	switch {
	case strings.Contains(objType, "http.Request"):
		return lower == "r" || lower == "req" || lower == "request" ||
			lower == "httpreq" || lower == "httprequest"
	case strings.Contains(objType, "http.ResponseWriter"):
		return lower == "w" || lower == "resp" || lower == "response" ||
			lower == "rw" || lower == "writer"
	case strings.Contains(objType, "gin.Context"):
		return lower == "c" || lower == "ctx" || lower == "ginctx"
	case strings.Contains(objType, "echo.Context"):
		return lower == "c" || lower == "ctx" || lower == "echoctx"
	case strings.Contains(objType, "fiber.Ctx"):
		return lower == "c" || lower == "ctx" || lower == "fctx"
	case strings.Contains(objType, "sql.DB"):
		return lower == "db" || lower == "conn" || lower == "database"
	case strings.Contains(objType, "sql.Tx"):
		return lower == "tx" || lower == "txn"
	case strings.Contains(objType, "sql.Rows"):
		return lower == "rows" || lower == "row" || lower == "result"
	case strings.Contains(objType, "sql.Stmt"):
		return lower == "stmt" || lower == "statement"
	case strings.Contains(objType, "bufio.Scanner"):
		return lower == "scanner" || lower == "s" || lower == "sc"
	case strings.Contains(objType, "net.Conn"):
		return lower == "conn" || lower == "c" || lower == "connection"
	case strings.Contains(objType, "ldap.Conn"):
		return lower == "conn" || lower == "l" || lower == "ldap" || lower == "ldapconn"
	}

	return false
}

// ---------- sink matching ----------

// checkSinkCall checks if a call is a known sink and whether any argument
// reaching a dangerous position is tainted.
func checkSinkCall(
	fset *token.FileSet,
	call *ast.CallExpr,
	taintMap map[string]*taintState,
	sinks []taint.SinkDef,
	scopeName string,
	filePath string,
	flows *[]taint.TaintFlow,
) {
	for i := range sinks {
		sink := &sinks[i]
		dangerousArgs := matchSinkCall(call, sink)
		if dangerousArgs == nil {
			continue
		}

		for _, argExpr := range dangerousArgs {
			ts, ok := exprIsTainted(argExpr, taintMap)
			if !ok {
				continue
			}
			if !ts.isTaintedFor(sink.Category) {
				continue
			}

			line := fset.Position(call.Pos()).Line
			flow := taint.TaintFlow{
				Source:     *ts.source,
				Sink:       *sink,
				SourceLine: ts.sourceLine,
				SinkLine:   line,
				Steps:      ts.steps,
				FilePath:   filePath,
				ScopeName:  scopeName,
				Confidence: ts.confidence,
			}
			*flows = append(*flows, flow)
		}
	}
}

// matchSinkCall checks if a call matches a sink definition and returns the
// argument expressions at the dangerous positions.
func matchSinkCall(call *ast.CallExpr, sink *taint.SinkDef) []ast.Expr {
	sel := selectorString(call.Fun)

	matched := false

	// Package-level function: exec.Command, os.Open, http.Get, etc.
	if sink.ObjectType == "" && sink.MethodName != "" {
		if sel == sink.MethodName {
			matched = true
		}
		// Check with package prefix: exec.Command, os.Open, etc.
		parts := strings.Split(sink.MethodName, ".")
		if !matched && len(parts) == 1 && strings.HasSuffix(sel, "."+parts[0]) {
			matched = true
		}
		// Match patterns like "fmt.Fprintf" directly.
		if !matched && sel != "" {
			selParts := strings.Split(sel, ".")
			sinkParts := strings.Split(sink.MethodName, ".")
			if len(selParts) >= 1 && len(sinkParts) >= 1 &&
				selParts[len(selParts)-1] == sinkParts[len(sinkParts)-1] {
				// Method name matches; check package prefix if applicable.
				if len(sinkParts) >= 2 && len(selParts) >= 2 &&
					selParts[len(selParts)-2] == sinkParts[len(sinkParts)-2] {
					matched = true
				} else if len(sinkParts) == 1 {
					matched = true
				}
			}
		}
	}

	// Method call on receiver: db.Query, w.Write, etc.
	if !matched && sink.ObjectType != "" && sink.MethodName != "" {
		selExpr, ok := call.Fun.(*ast.SelectorExpr)
		if ok {
			methodName := selExpr.Sel.Name
			if methodName == sink.MethodName {
				recvName := identName(selExpr.X)
				if recvName != "" && matchesReceiverType(recvName, sink.ObjectType) {
					matched = true
				}
			}
		}
	}

	// Special case: fmt.Fprintf(w, ...) — check that first arg looks like a ResponseWriter.
	if !matched && sink.MethodName == "Fprintf" && sink.Category == taint.SnkHTMLOutput {
		if sel == "fmt.Fprintf" || strings.HasSuffix(sel, ".Fprintf") {
			if len(call.Args) > 0 {
				firstArg := identName(call.Args[0])
				if matchesReceiverType(firstArg, "http.ResponseWriter") {
					matched = true
				}
			}
		}
	}

	// Special case: template.HTML(x)
	if !matched && sink.MethodName == "HTML" && sink.Category == taint.SnkHTMLOutput {
		if sel == "template.HTML" || strings.HasSuffix(sel, ".HTML") {
			matched = true
		}
	}

	if !matched {
		return nil
	}

	// Collect the argument expressions at dangerous positions.
	var dangerous []ast.Expr
	for _, argIdx := range sink.DangerousArgs {
		if argIdx == -1 {
			// Any argument is dangerous.
			dangerous = append(dangerous, call.Args...)
			break
		}
		if argIdx >= 0 && argIdx < len(call.Args) {
			dangerous = append(dangerous, call.Args[argIdx])
		}
	}

	return dangerous
}

// ---------- sanitizer matching ----------

// isSanitizerCall checks if a call is a known sanitizer. Returns the sanitizer
// definition and the expression being sanitized (typically the first argument).
func isSanitizerCall(call *ast.CallExpr, sanitizers []taint.SanitizerDef) (*taint.SanitizerDef, ast.Expr) {
	sel := selectorString(call.Fun)

	for i := range sanitizers {
		san := &sanitizers[i]

		matched := false

		// Package-level sanitizer: html.EscapeString, url.QueryEscape, etc.
		if san.ObjectType == "" && san.MethodName != "" {
			if sel == san.MethodName {
				matched = true
			}
			parts := strings.Split(san.MethodName, ".")
			if !matched && len(parts) == 1 && strings.HasSuffix(sel, "."+parts[0]) {
				matched = true
			}
			if !matched && sel != "" {
				selParts := strings.Split(sel, ".")
				sanParts := strings.Split(san.MethodName, ".")
				if len(selParts) >= 1 && len(sanParts) >= 1 &&
					selParts[len(selParts)-1] == sanParts[len(sanParts)-1] {
					if len(sanParts) >= 2 && len(selParts) >= 2 &&
						selParts[len(selParts)-2] == sanParts[len(sanParts)-2] {
						matched = true
					}
				}
			}
		}

		// Method call on known sanitizer receiver.
		if !matched && san.ObjectType != "" && san.MethodName != "" {
			if selExpr, ok := call.Fun.(*ast.SelectorExpr); ok {
				if selExpr.Sel.Name == san.MethodName {
					recvName := identName(selExpr.X)
					if recvName != "" && matchesReceiverType(recvName, san.ObjectType) {
						matched = true
					}
				}
			}
		}

		if matched && len(call.Args) > 0 {
			return san, call.Args[0]
		}
	}

	return nil, nil
}

// ---------- taint propagation through expressions ----------

// exprIsTainted checks whether an AST expression references any tainted variable.
// Walks into selector expressions, binary expressions, call arguments, index
// expressions, and composite literals.
func exprIsTainted(expr ast.Expr, taintMap map[string]*taintState) (*taintState, bool) {
	if expr == nil {
		return nil, false
	}

	switch e := expr.(type) {
	case *ast.Ident:
		if ts, ok := taintMap[e.Name]; ok && ts.source != nil {
			return ts, true
		}

	case *ast.SelectorExpr:
		// e.g., taintedVar.Field — check if the base is tainted.
		return exprIsTainted(e.X, taintMap)

	case *ast.BinaryExpr:
		// String concatenation or other binary ops: if either side is tainted, result is tainted.
		if ts, ok := exprIsTainted(e.X, taintMap); ok {
			return ts, true
		}
		if ts, ok := exprIsTainted(e.Y, taintMap); ok {
			return ts, true
		}

	case *ast.CallExpr:
		// Check if any argument to the call is tainted.
		for _, arg := range e.Args {
			if ts, ok := exprIsTainted(arg, taintMap); ok {
				return ts, true
			}
		}

	case *ast.IndexExpr:
		// arr[idx] — check if the array/map is tainted.
		return exprIsTainted(e.X, taintMap)

	case *ast.SliceExpr:
		// arr[low:high] — check if the array is tainted.
		return exprIsTainted(e.X, taintMap)

	case *ast.UnaryExpr:
		// &x, *x, etc.
		return exprIsTainted(e.X, taintMap)

	case *ast.ParenExpr:
		return exprIsTainted(e.X, taintMap)

	case *ast.TypeAssertExpr:
		// x.(type) — check if x is tainted.
		return exprIsTainted(e.X, taintMap)

	case *ast.StarExpr:
		// *ptr
		return exprIsTainted(e.X, taintMap)

	case *ast.CompositeLit:
		// Check if any element is tainted.
		for _, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if ts, tainted := exprIsTainted(kv.Value, taintMap); tainted {
					return ts, true
				}
			} else {
				if ts, tainted := exprIsTainted(elt, taintMap); tainted {
					return ts, true
				}
			}
		}
	}

	return nil, false
}

// propagationConfidence returns the confidence decay factor for taint
// propagating through a given expression.
func propagationConfidence(expr ast.Expr) float64 {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return 0.95 // String concatenation
		}
		return 0.9

	case *ast.CallExpr:
		sel := selectorString(e.Fun)
		lower := strings.ToLower(sel)

		// String operations preserve taint with high confidence.
		if strings.Contains(lower, "toupper") || strings.Contains(lower, "tolower") ||
			strings.Contains(lower, "trimspace") || strings.Contains(lower, "trim") ||
			strings.Contains(lower, "replace") || strings.Contains(lower, "join") {
			return 0.95
		}

		// Type conversion decays slightly more.
		if strings.Contains(lower, "string(") || strings.Contains(lower, "byte") {
			return 0.9
		}

		// Format functions.
		if strings.Contains(lower, "sprintf") || strings.Contains(lower, "format") {
			return 0.95
		}

		// Unknown function call — moderate decay.
		return 0.85

	case *ast.CompositeLit:
		return 0.85

	case *ast.IndexExpr, *ast.SliceExpr:
		return 0.9

	default:
		return 1.0
	}
}

// ---------- AST helper functions ----------

// identName extracts the identifier name from an expression.
// Returns "" for non-identifier expressions.
func identName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return identName(e.X)
	}
	return ""
}

// selectorString gets "pkg.Method" or "receiver.Method" from a function expression.
func selectorString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		base := selectorString(e.X)
		if base != "" {
			return base + "." + e.Sel.Name
		}
		return e.Sel.Name

	case *ast.Ident:
		return e.Name

	case *ast.CallExpr:
		// For chained calls like r.URL.Query().Get, we get the inner selector.
		return selectorString(e.Fun)
	}
	return ""
}

// deepReceiverName walks into nested selector/call expressions to find the
// root receiver identifier name.
func deepReceiverName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return deepReceiverName(e.X)
	case *ast.CallExpr:
		return deepReceiverName(e.Fun)
	case *ast.IndexExpr:
		return deepReceiverName(e.X)
	}
	return ""
}

// receiverTypeName extracts a readable type name from a receiver type expression.
func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return "*" + receiverTypeName(e.X)
	case *ast.SelectorExpr:
		return selectorString(e)
	}
	return ""
}

// unwrapCall extracts a *ast.CallExpr from an expression, handling parenthesization.
func unwrapCall(expr ast.Expr) (*ast.CallExpr, bool) {
	switch e := expr.(type) {
	case *ast.CallExpr:
		return e, true
	case *ast.ParenExpr:
		return unwrapCall(e.X)
	}
	return nil, false
}

// exprToString renders an AST expression back to a rough string representation.
// Used for type matching heuristics.
func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprToString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + exprToString(e.X)
	case *ast.ArrayType:
		return "[]" + exprToString(e.Elt)
	case *ast.MapType:
		return "map[" + exprToString(e.Key) + "]" + exprToString(e.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.Ellipsis:
		if e.Elt != nil {
			return "..." + exprToString(e.Elt)
		}
		return "..."
	}
	return ""
}

// ---------- heuristic helpers ----------

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
