package astflow

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
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
			processAssign(fset, stmt, tm, matcher)

		case *ast.ExprStmt:
			if call, ok := stmt.X.(*ast.CallExpr); ok {
				checkSinkCall(fset, call, tm, matcher, scopeName, fb)
			}

		case *ast.DeferStmt:
			checkSinkCall(fset, stmt.Call, tm, matcher, scopeName, fb)

		case *ast.GoStmt:
			checkSinkCall(fset, stmt.Call, tm, matcher, scopeName, fb)

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
				processAssign(fset, assign, tm, matcher)
			}

		case *ast.SendStmt: // ch <- taintedValue
			if ts, ok := exprIsTainted(stmt.Value, tm); ok {
				chanName := identName(stmt.Chan)
				if chanName != "" {
					line := fset.Position(stmt.Pos()).Line
					tm.Set(chanName, ts.clone(chanName, line, "sent to channel "+chanName, 0.9))
				}
			}

		case *ast.SelectStmt: // select { case v := <-ch: ... }
			if stmt.Body != nil {
				for _, clause := range stmt.Body.List {
					if cc, ok := clause.(*ast.CommClause); ok && cc.Comm != nil {
						if assign, ok := cc.Comm.(*ast.AssignStmt); ok {
							processAssign(fset, assign, tm, matcher)
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
			checkSinkCall(fset, call, tm, matcher, scopeName, fb)
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
			tm.Set(lhsName, newTs)
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
) {
	sink, dangerousArgs := matcher.MatchSink(call)
	if sink == nil {
		return
	}

	for _, argExpr := range dangerousArgs {
		ts, ok := exprIsTainted(argExpr, tm)
		if !ok {
			continue
		}
		if !ts.isTaintedFor(sink.Category) {
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
