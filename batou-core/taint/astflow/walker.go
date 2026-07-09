package astflow

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// walkFunc performs intraprocedural taint analysis on a single function body.
func walkFunc(
	fset *token.FileSet,
	fnType *ast.FuncType,
	body *ast.BlockStmt,
	scopeName string,
	recvType string,
	filePath string,
	matcher *CatalogMatcher,
) []taint.TaintFlow {

	tm := NewTaintMap()
	tm.matcher = matcher
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
		seedHTTPHandlerParams(fset, fnType.Params, recvType, tm)
	}

	// Seed taint for primitive selector sources (e.g. r.URL.Path, r.Body,
	// r.RemoteAddr) so they propagate through assignments and reach sinks
	// in the main pass below.
	seedSelectorSources(fset, body, tm, matcher)

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

// seedSelectorSources pre-walks the function body and seeds the taint map
// with synthetic entries for primitive selector sources — non-call reads of
// fields on source-typed receivers such as `r.URL.Path`, `r.Body`,
// `r.RemoteAddr`, `r.Host`. The key is the rendered selector chain (e.g.
// "r.URL.Path") so the exprIsTainted full-chain lookup finds it without
// truncating to a single field level.
//
// Selectors that are the Fun position of a CallExpr (e.g. r.FormValue) are
// skipped — those remain the responsibility of MatchSource.
func seedSelectorSources(
	fset *token.FileSet,
	body *ast.BlockStmt,
	tm *TaintMap,
	matcher *CatalogMatcher,
) {
	if body == nil || matcher == nil {
		return
	}
	// Track selectors that appear as `call.Fun` so we don't double-match
	// them as selector sources during the inspect walk below.
	skip := make(map[*ast.SelectorExpr]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				skip[sel] = true
			}
		}
		return true
	})

	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if skip[sel] {
			return true
		}
		src := matcher.MatchSelectorSource(sel)
		if src == nil {
			return true
		}
		key := exprToString(sel)
		if key == "" {
			return true
		}
		if existing := tm.Get(key); existing != nil && existing.source != nil {
			return true
		}
		line := fset.Position(sel.Pos()).Line
		tm.Set(key, &taintState{
			varName:    key,
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     key,
			}},
		})
		return true
	})
}

// seedHTTPHandlerParams inspects function parameters and auto-taints variables
// that represent common HTTP input parameter names, plus framework-shaped RPC
// entry points (gRPC server handlers and gqlgen GraphQL resolvers) whose typed
// parameters carry client-supplied data.
//
// recvType is the function's receiver type name (e.g. "*queryResolver"), empty
// for free functions and closures. It is used only to recognise gqlgen resolver
// methods.
func seedHTTPHandlerParams(
	fset *token.FileSet,
	params *ast.FieldList,
	recvType string,
	tm *TaintMap,
) {
	// gRPC server handlers and gqlgen resolvers both take context.Context as the
	// first parameter. Requiring that shape keeps the framework-param seeding
	// from firing on arbitrary helper functions, holding the false-positive rate
	// down. (This block is Go-only: it lives in the Go-specific astflow engine.)
	firstParamIsContext := firstParamIsContextContext(params)
	resolverMethod := firstParamIsContext && languages.IsGoGraphQLResolverReceiver(recvType)

	for _, field := range params.List {
		typeName := exprToString(field.Type)
		canonType := exprToTypeString(field.Type)

		// gRPC request message parameter: `req *pb.MethodRequest`. The message
		// carries every client-supplied field; field/getter reads on it are
		// attacker-controlled. Only seed inside the RPC handler shape.
		isGRPCReq := firstParamIsContext && languages.IsGoGRPCRequestParamType(canonType)

		// Archive-entry parameter: `f *zip.File` / `h *tar.Header`. These types
		// only ever hold an entry from an untrusted archive a caller opened, so
		// every field (`.Name`, `.Linkname`) is attacker-controlled. This closes
		// the dominant refactored zip-slip / tar-slip shape where the sink lives
		// in a per-entry helper that receives the entry as a parameter (the
		// inline OpenReader/Next form is already caught by the catalog sources).
		// The type alone is unambiguous external origin, so — unlike the gRPC
		// check — this is NOT gated on a leading context.Context parameter.
		isArchiveEntry := languages.IsGoArchiveEntryParamType(canonType)

		for _, name := range field.Names {
			varName := name.Name
			if varName == "_" {
				continue
			}

			if isGRPCReq {
				seedFrameworkParam(fset, tm, name, varName,
					"go.grpc.request."+varName, taint.SrcUserInput,
					"gRPC request message "+canonType+" (client-controlled fields)", 0.9)
				continue
			}

			if isArchiveEntry {
				seedFrameworkParam(fset, tm, name, varName,
					"go.archive.entryparam."+varName, taint.SrcExternal,
					"archive entry parameter "+canonType+" (attacker-controlled .Name/.Linkname; zip-slip/tar-slip CWE-22)", 0.9)
				continue
			}

			// gqlgen resolver argument: a non-context scalar/struct parameter on
			// a *...Resolver method is the field's client-supplied GraphQL
			// argument (CWE-89 / CWE-78 / CWE-943 when it reaches a sink).
			if resolverMethod && isGraphQLResolverArgType(canonType) {
				seedFrameworkParam(fset, tm, name, varName,
					"go.gqlgen.resolverarg."+varName, taint.SrcUserInput,
					"gqlgen resolver argument "+varName+" (client-supplied GraphQL input)", 0.9)
				continue
			}

			// Skip request types — they're not tainted themselves, but methods
			// called on them introduce taint (matched by CatalogMatcher).
			if isRequestType(typeName) {
				continue
			}

			// Parameters with common input names at lower confidence.
			if isInputParamName(varName) {
				src := &taint.SourceDef{
					ID:       "go.param." + varName,
					Category: taint.SrcExternal,
					Language: rules.LangGo,
					// param-name: marker (not the plain "parameter:" prefix) so
					// the external-origin block gate recognises this as the weak,
					// name-only fabricator (a parameter whose NAME merely looks
					// input-like is NOT proof of external reachability) and caps
					// it to a hint. Genuine framework-bound params use
					// seedFrameworkParam, which keeps the "parameter:" prefix.
					MethodName:  "param-name:" + varName,
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

// seedFrameworkParam seeds a single framework entry-point parameter into the
// taint map as a user-input source.
func seedFrameworkParam(
	fset *token.FileSet,
	tm *TaintMap,
	name *ast.Ident,
	varName, id string,
	cat taint.SourceCategory,
	desc string,
	conf float64,
) {
	if existing := tm.Get(varName); existing != nil && existing.source != nil {
		return
	}
	src := &taint.SourceDef{
		ID:          id,
		Category:    cat,
		Language:    rules.LangGo,
		MethodName:  "parameter:" + varName,
		Description: desc,
	}
	line := fset.Position(name.Pos()).Line
	tm.Set(varName, &taintState{
		varName:    varName,
		source:     src,
		sourceLine: line,
		sanitized:  make(map[taint.SinkCategory]bool),
		confidence: conf,
		steps: []taint.FlowStep{{
			Line:        line,
			Description: desc,
			VarName:     varName,
		}},
	})
}

// firstParamIsContextContext reports whether the first parameter's type is
// context.Context — the universal leading parameter of gRPC server handlers and
// gqlgen resolver methods.
func firstParamIsContextContext(params *ast.FieldList) bool {
	if params == nil || len(params.List) == 0 {
		return false
	}
	return exprToTypeString(params.List[0].Type) == "context.Context"
}

// isGraphQLResolverArgType reports whether a gqlgen resolver method parameter
// type should be treated as a client-supplied argument. gqlgen passes scalars
// (string/int/float/bool), pointers to those, and input-object structs
// (commonly *model.X). It does NOT pass context.Context (handled separately),
// channels, or interface/error types as data arguments.
func isGraphQLResolverArgType(canonType string) bool {
	t := strings.TrimPrefix(canonType, "*")
	switch t {
	case "", "context.Context", "error":
		return false
	}
	// Scalars and common gqlgen-mapped types.
	switch t {
	case "string", "int", "int32", "int64", "float64", "float32", "bool":
		return true
	}
	// Slices of scalars (e.g. []string) — list arguments.
	if strings.HasPrefix(t, "[]") {
		return true
	}
	// Input-object structs are package-qualified (e.g. model.NewUser). Require a
	// dot so bare interface aliases are not auto-tainted.
	if strings.Contains(t, ".") {
		return true
	}
	return false
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
		base, field, ok := lhsTaintKey(lhs)
		if !ok {
			continue
		}
		// Shallow field-sensitive key. For plain idents field == "" and
		// lhsName == base; for `obj.field` we get a distinct per-field key.
		var lhsName string
		if field == "" {
			lhsName = base
		} else {
			lhsName = fieldKey(base, field)
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

		// Intra-function must-alias bookkeeping for plain-ident rebinds.
		// Rebinding `base` breaks any alias edge it was part of, and a straight
		// `base = <bareIdent>` copy records a fresh edge so a field write
		// through one name is seen through the other (see exprIsTainted /
		// TaintMap.aliases). Done before the taint branches below — it never
		// touches taint state, only the alias graph.
		if field == "" {
			tm.breakAlias(base)
			if id, ok := rhs.(*ast.Ident); ok && id.Name != "" && id.Name != "_" {
				tm.recordAlias(base, id.Name)
			}
		}

		// Track validation links: if RHS is a validation function call
		// (regexp.MatchString, strings.Contains, etc.) that takes a tainted arg,
		// record that this LHS bool validates that tainted variable.
		// Only meaningful for plain-ident LHS (validation booleans).
		if field == "" {
			if call, ok := unwrapCall(rhs); ok {
				if taintedVar := extractValidationTarget(call, tm); taintedVar != "" {
					validationLinks[lhsName] = taintedVar
				}
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
				// Rebinding a plain ident replaces its prior fields.
				if field == "" {
					tm.ClearFields(base)
				}
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
					if field == "" {
						tm.ClearFields(base)
					}
					continue
				}
			}

			// Check if RHS is a format call whose verbs all destroy
			// attacker-controlled content: fmt.Sprintf("%x", md5.Sum(data))
			// yields hex digits only, no matter what data contains, so the
			// result cannot carry path separators, quotes, or shell
			// metacharacters.
			if isContentDestroyingFormatCall(call) {
				if ts, ok := exprIsTainted(rhs, tm); ok {
					newTs := ts.clone(lhsName, line, "content destroyed by hex/numeric format verbs", 1.0)
					for _, cat := range allGuardCategories() {
						newTs.sanitized[cat] = true
					}
					tm.Set(lhsName, newTs)
					if field == "" {
						tm.ClearFields(base)
					}
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
			if field == "" {
				tm.ClearFields(base)
			}
			continue
		}

		// RHS is not tainted. Clear any prior taint on this key.
		//   - plain ident `x = safe`         -> clear "x" AND "x.*" fields.
		//   - field `obj.f = safe`           -> clear only "obj.f" (leave obj
		//                                       and obj.other untouched).
		// Only do this for safe literals (to match prior behaviour for
		// pattern: if !allowed[x] { x = "safe" }) — generic non-tainted RHS
		// shouldn't clobber an existing assignment record because we may have
		// missed a source.
		if isSafeLiteral(rhs) {
			if tm.Has(lhsName) {
				tm.Set(lhsName, &taintState{
					varName:   lhsName,
					sanitized: make(map[taint.SinkCategory]bool),
				})
			}
			if field == "" {
				tm.ClearFields(base)
			}
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

		// Must-alias bookkeeping: a fresh `var b = a` declaration breaks any
		// stale alias for b and records `b -> a` when the RHS is a bare ident.
		tm.breakAlias(varName)
		if id, ok := rhs.(*ast.Ident); ok && id.Name != "" && id.Name != "_" {
			tm.recordAlias(varName, id.Name)
		}

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
				// Fresh declaration replaces any prior per-field taint.
				tm.ClearFields(varName)
				continue
			}

			if san, sanitizedExpr := matcher.MatchSanitizer(call); san != nil {
				if ts, ok := exprIsTainted(sanitizedExpr, tm); ok {
					newTs := ts.clone(varName, line, "sanitized by "+san.MethodName, 1.0)
					for _, cat := range san.Neutralizes {
						newTs.sanitized[cat] = true
					}
					tm.Set(varName, newTs)
					tm.ClearFields(varName)
					continue
				}
			}
		}

		if ts, ok := exprIsTainted(rhs, tm); ok {
			decay := propagationConfidence(rhs)
			newTs := ts.clone(varName, line, "assigned to "+varName, decay)
			tm.Set(varName, newTs)
			tm.ClearFields(varName)
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

		// Suppress when a registered sanitizer for THIS sink category wraps a
		// genuinely-tainted value INLINE at the sink — e.g.
		// ctx.Redirect(url.QueryEscape(userInput)). astflow otherwise only
		// applies sanitizers on an assignment RHS (applySanitizersInExpr), so an
		// escape applied directly inside the sink call would fire a false block.
		if sinkArgInlineSanitized(argExpr, sink.Category, tm, matcher) {
			continue
		}

		// Suppress log injection when using %q format verb (quotes/escapes output).
		if sink.Category == taint.SnkLog && isQuotedFormatCall(call, argExpr) {
			continue
		}

		// Suppress the text/template Parse SSTI sink (go.text.template.parse)
		// when the tainted template BODY originates from a file read. Loading
		// a template definition from a file or embedded FS — the dominant,
		// benign `t.New(name).Parse(fs.ReadFile(...))` template-loader pattern
		// — is not attacker-controlled template injection. The genuine
		// SSTI/RCE flaw is a REQUEST-controlled template body, which still
		// fires (its source is user_input/external, not file_read).
		if sink.ID == "go.text.template.parse" && ts.source != nil &&
			ts.source.Category == taint.SrcFileRead {
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
//   - if !isValidName(var) { return }    (validation-named helper)
//   - if var != "literal" { return }     (pins var to a constant — var only)
//
// Soundness: merely MENTIONING a tainted variable in an early-return
// condition is NOT validation. Pure nil-check / empty-string / len / err
// shapes (`if name == "" { return }`, `if len(name) > 100 { return }`,
// `if err != nil { return }`) sanitize nothing — inferGuardCategories
// returns nil for them and only the `var != <literal>` comparison form
// grants a per-variable exception.
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

	// Validator-guard sanitization in the if-init clause:
	//   if err := validate.Struct(input); err != nil { return }
	// The init runs `validate.Struct(input)` — a catalog sanitizer that
	// returns only an error, so its result is never the sanitized value and
	// the assignment-side sanitizer handling never sees it. But because the
	// body fail-closes (return on validation error), `input` is validated for
	// all code after the guard. Apply the sanitizer's Neutralizes categories
	// to the validated argument's taint. Mirrors the assignment-side sanitizer
	// handling, just keyed off the init call rather than an `x = san(y)` LHS.
	if assign, ok := stmt.Init.(*ast.AssignStmt); ok {
		for _, rhs := range assign.Rhs {
			call, ok := unwrapCall(rhs)
			if !ok {
				continue
			}
			san, sanitizedExpr := matcher.MatchSanitizer(call)
			if san == nil || sanitizedExpr == nil {
				continue
			}
			ts, ok := exprIsTainted(sanitizedExpr, tm)
			if !ok || ts.source == nil {
				continue
			}
			varName := ts.varName
			line := fset.Position(stmt.Pos()).Line
			newTs := ts.clone(varName, line, "validated by "+san.MethodName+" guard", 1.0)
			for _, cat := range san.Neutralizes {
				newTs.sanitized[cat] = true
			}
			tm.Set(varName, newTs)
		}
	}

	// Collect tainted variables referenced in the condition and sanitize them.
	// Also resolve indirect validation links (e.g., "matched" → "name").
	guardedVars := extractGuardedVars(stmt.Cond, tm, validationLinks)
	if len(guardedVars) == 0 {
		return
	}

	line := fset.Position(stmt.Pos()).Line
	categories := inferGuardCategories(stmt.Cond, tm, validationLinks)

	// Per-variable sound constant pin: `if v != <literal> { return }` means
	// v equals the literal in all code after the guard, regardless of any
	// other validation semantics in the condition.
	constPinned := constEqualityGuardedVars(stmt.Cond, tm)

	for _, varName := range guardedVars {
		cats := categories
		if len(cats) == 0 {
			if !constPinned[varName] {
				continue
			}
			cats = allGuardCategories()
		}
		ts := tm.Get(varName)
		if ts == nil || ts.source == nil {
			continue
		}
		newTs := ts.clone(varName, line, "validated by guard condition", 1.0)
		for _, cat := range cats {
			newTs.sanitized[cat] = true
		}
		tm.Set(varName, newTs)
	}
}

// bodyHasReturn checks if a block statement contains an early-exit statement
// that skips the rest of the surrounding flow on guard failure. This includes
// `return`, `continue`, and `break` — all three short-circuit before the body
// after the guard runs, so any sanitisation applied to the guarded variables
// is valid for that later code.
func bodyHasReturn(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	for _, stmt := range body.List {
		switch s := stmt.(type) {
		case *ast.ReturnStmt:
			return true
		case *ast.BranchStmt:
			// `continue` and `break` are both early-exit for our purposes:
			// inside a loop they skip the rest of the iteration after the
			// guard, which is the canonical zip-slip / tar-slip fix shape
			// (see TestAnalyzeGo_ZipSlip_IsLocal_Sanitized).
			if s.Tok == token.CONTINUE || s.Tok == token.BREAK {
				return true
			}
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

// allGuardCategories returns the full set of sink categories a strong
// (allowlist-style) guard protects against.
func allGuardCategories() []taint.SinkCategory {
	return []taint.SinkCategory{
		taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead,
		taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkURLFetch,
		taint.SnkLog, taint.SnkTemplate, taint.SnkHeader,
		taint.SnkEval, taint.SnkLDAP, taint.SnkXPath,
		taint.SnkDeserialize,
	}
}

// inferGuardCategories determines which sink categories a guard condition
// protects against. It returns nil when the condition carries no
// recognizable validation semantics — a bare nil-check, empty-string
// equality, len comparison, or err != nil mentioning a tainted variable is
// NOT a sanitizer and must not clear any category.
func inferGuardCategories(cond ast.Expr, tm *TaintMap, validationLinks map[string]string) []taint.SinkCategory {
	// Check for specific guard function calls that hint at the category.
	hasSpecificGuard := false
	var specific []taint.SinkCategory

	// Generic validation evidence that justifies all-category clearing:
	//   - an allowlist map lookup keyed by a tainted value (allowed[name])
	//   - a validation-named call taking (or invoked on) a tainted value
	//   - a validation-result boolean linked to a tainted value
	validationEvidence := false
	allowlistGuard := false

	ast.Inspect(cond, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CallExpr:
			sel := selectorString(e.Fun)
			lower := strings.ToLower(sel)

			switch {
			case strings.Contains(lower, "hasprefix"):
				hasSpecificGuard = true
				specific = append(specific, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkRedirect, taint.SnkURLFetch)
			case strings.Contains(lower, "matchstring"):
				hasSpecificGuard = true
				specific = append(specific, taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkLog)
			// Path-traversal guards (PR-HH):
			//   - filepath.IsLocal(x)  — Go 1.20+, returns false on any escape;
			//     `if !filepath.IsLocal(x) { return }` is a complete CWE-22 guard.
			//   - filepath.IsAbs(x)    — used as a negative guard:
			//     `if filepath.IsAbs(x) { return }` rejects absolute paths.
			//   - strings.Contains(x, "..") — used as a ".." rejection guard:
			//     `if strings.Contains(x, "..") { return }`.
			//   - filepath.Rel(base, x) with error check — caller intends a
			//     containment check.
			// Recognising these as guards (rather than as standalone sanitizers)
			// keeps us precise: each only neutralises the taint when paired with
			// the return-on-failure check inside an if-body.
			case strings.Contains(lower, "filepath.islocal"), strings.Contains(lower, "islocal"):
				hasSpecificGuard = true
				specific = append(specific, taint.SnkFileWrite, taint.SnkFileRead)
			case strings.Contains(lower, "filepath.isabs"), strings.Contains(lower, "isabs"):
				hasSpecificGuard = true
				specific = append(specific, taint.SnkFileWrite, taint.SnkFileRead)
			case strings.Contains(lower, "strings.contains") || lower == "contains":
				hasSpecificGuard = true
				specific = append(specific, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkLog)
			case strings.Contains(lower, "filepath.rel"):
				hasSpecificGuard = true
				specific = append(specific, taint.SnkFileWrite, taint.SnkFileRead)
			default:
				if isValidationNamedCall(e, tm) {
					validationEvidence = true
				}
			}

		case *ast.IndexExpr:
			// Allowlist map/set lookup keyed by the tainted value:
			// `if !allowed[name] { return }`. Requires the INDEX to be
			// tainted — an arbitrary index expression in the condition is
			// not an allowlist check.
			if _, ok := exprIsTainted(e.Index, tm); ok {
				allowlistGuard = true
			}

		case *ast.Ident:
			// Validation-result boolean linked to a tainted value, e.g.
			// matched, _ := regexp.MatchString(pattern, name)
			// if !matched { return }
			if _, ok := validationLinks[e.Name]; ok {
				validationEvidence = true
			}
		}
		return true
	})

	// Allowlist maps protect all categories (and take precedence over any
	// category-specific guard function also present in the condition).
	if allowlistGuard {
		return allGuardCategories()
	}
	if hasSpecificGuard && len(specific) > 0 {
		return specific
	}
	if validationEvidence {
		return allGuardCategories()
	}
	return nil
}

// validationNamePrefixes lists name prefixes that signal a boolean
// validation/sanitization helper (isValid, hasAccess, validateInput,
// checkName, allowHost, matchPattern, sanitizePath, verifyToken).
var validationNamePrefixes = []string{
	"validate", "valid", "sanitize", "sanitise", "check",
	"is", "has", "allow", "allows", "match", "matches", "verify",
}

// hasValidationPrefix reports whether a function/method name starts with a
// validation-ish prefix at a camelCase / snake_case word boundary. The
// boundary check prevents "hash..." matching "has" and "issue..." matching
// "is".
func hasValidationPrefix(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range validationNamePrefixes {
		if !strings.HasPrefix(lower, p) {
			continue
		}
		rest := name[len(p):]
		if rest == "" {
			return true
		}
		c := rest[0]
		if c == '_' || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return true
		}
	}
	return false
}

// isValidationNamedCall reports whether a call expression looks like a
// validation helper applied to a tainted value: the callee's final name
// component has a validation-ish prefix AND the tainted value appears as an
// argument or as the method receiver.
func isValidationNamedCall(call *ast.CallExpr, tm *TaintMap) bool {
	sel := selectorString(call.Fun)
	if sel == "" {
		return false
	}
	name := sel
	if idx := strings.LastIndex(sel, "."); idx >= 0 {
		name = sel[idx+1:]
	}
	if !hasValidationPrefix(name) {
		return false
	}
	for _, arg := range call.Args {
		if _, ok := exprIsTainted(arg, tm); ok {
			return true
		}
	}
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		if _, ok := exprIsTainted(fun.X, tm); ok {
			return true
		}
	}
	return false
}

// constEqualityGuardedVars finds tainted variables compared against a
// literal with != inside the guard condition: `if v != "x" { return }`
// pins v to the literal "x" for all code after the guard, which is a sound
// single-value allowlist for v (and only v).
func constEqualityGuardedVars(cond ast.Expr, tm *TaintMap) map[string]bool {
	pinned := make(map[string]bool)
	ast.Inspect(cond, func(n ast.Node) bool {
		be, ok := n.(*ast.BinaryExpr)
		if !ok || be.Op != token.NEQ {
			return true
		}
		var ident *ast.Ident
		switch {
		case isBasicLit(be.Y):
			ident, _ = be.X.(*ast.Ident)
		case isBasicLit(be.X):
			ident, _ = be.Y.(*ast.Ident)
		}
		if ident == nil {
			return true
		}
		if ts := tm.Get(ident.Name); ts != nil && ts.source != nil {
			pinned[ident.Name] = true
		}
		return true
	})
	return pinned
}

// isBasicLit reports whether the expression is a basic literal (string,
// int, float, char), i.e. a compile-time constant value.
func isBasicLit(expr ast.Expr) bool {
	_, ok := expr.(*ast.BasicLit)
	return ok
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

// sinkArgInlineSanitized reports whether a dangerous sink argument wraps a
// genuinely-tainted value INLINE in a sanitizer registered for this sink's
// category — e.g. ctx.Redirect(url.QueryEscape(userInput)) or
// ctx.Redirect("/x/" + util.PathEscapeSegments(branch)). astflow normally only
// applies sanitizers on an assignment RHS (applySanitizersInExpr), so an escape
// applied directly at the sink would otherwise fire a false block. This mirrors
// the trusted assignment-side semantics at the sink: a registered sanitizer
// whose Neutralizes list includes cat, wrapping a value that is itself tainted,
// neutralizes that category for this argument.
//
// It is demotion-only and post-match: it can only SUPPRESS an already-matched
// tainted flow, never create one. Genuine TPs are preserved — a raw
// ctx.Redirect(tainted) (no sanitizer) still fires, and a sibling-escape like
// url.QueryEscape("const") + tainted still fires because the wrapped value is a
// constant, not the tainted operand.
func sinkArgInlineSanitized(argExpr ast.Expr, cat taint.SinkCategory, tm *TaintMap, matcher *CatalogMatcher) bool {
	if matcher == nil {
		return false
	}
	found := false
	ast.Inspect(argExpr, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		san, sanitizedExpr := matcher.MatchSanitizer(call)
		if san == nil || sanitizedExpr == nil {
			return true
		}
		neutralizes := false
		for _, c := range san.Neutralizes {
			if c == cat {
				neutralizes = true
				break
			}
		}
		if !neutralizes {
			return true
		}
		// Only suppress when the value the sanitizer wraps is itself genuinely
		// tainted. url.QueryEscape("constant") wraps nothing dangerous and must
		// not mask a tainted sibling operand in the same argument.
		if ts, ok := exprIsTainted(sanitizedExpr, tm); ok && ts.source != nil {
			found = true
			return false
		}
		return true
	})
	return found
}

// isContentDestroyingFormatCall reports whether a call is fmt.Sprintf or
// fmt.Appendf with a constant format string whose verbs all destroy
// attacker-controlled content (%x/%X hex-encode, %d/%o/%b numeric, %t bool,
// %p pointer, %T type, %e/%E/%f/%F/%g/%G float). Content-passing verbs
// (%s, %v, %q, %c, %U, %w) disqualify the format.
func isContentDestroyingFormatCall(call *ast.CallExpr) bool {
	sel := selectorString(call.Fun)
	var fmtArgIdx int
	switch sel {
	case "fmt.Sprintf":
		fmtArgIdx = 0
	case "fmt.Appendf":
		fmtArgIdx = 1
	default:
		return false
	}
	if len(call.Args) <= fmtArgIdx {
		return false
	}
	lit, ok := call.Args[fmtArgIdx].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	return formatVerbsDestroyContent(lit.Value)
}

// formatVerbsDestroyContent scans a format string and reports whether it
// contains at least one verb and every verb maps its argument to a
// constrained character set (hex digits, decimal digits, bool words, ...).
func formatVerbsDestroyContent(format string) bool {
	hasVerb := false
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		// Skip flags, width, precision, and argument-index characters.
		for i < len(format) && strings.ContainsRune("+-# 0123456789.[]*", rune(format[i])) {
			i++
		}
		if i >= len(format) {
			return false
		}
		switch format[i] {
		case '%':
			// Literal percent.
		case 'x', 'X', 'd', 'o', 'O', 'b', 'e', 'E', 'f', 'F', 'g', 'G', 't', 'p', 'T':
			hasVerb = true
		default:
			// %s, %v, %q, %c, %U, %w, or unknown — content may survive.
			return false
		}
	}
	return hasVerb
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
		strings.Contains(lower, "equalfold") ||
		strings.Contains(lower, "islocal") ||
		strings.Contains(lower, "isabs")

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
