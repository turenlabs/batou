package astflow

import (
	"go/ast"
	"strings"

	"github.com/turenlabs/batou/internal/taint"
)

// CatalogMatcher indexes catalog entries by method name for O(1) lookup
// and matches *ast.CallExpr against SourceDef/SinkDef/SanitizerDef.
type CatalogMatcher struct {
	sourcesByMethod    map[string][]*taint.SourceDef
	sinksByMethod      map[string][]*taint.SinkDef
	sanitizersByMethod map[string][]*taint.SanitizerDef
	typeEnv            *TypeEnv
}

// NewCatalogMatcher builds an indexed matcher from catalog entries.
// Compound method names like "Query/Param/PostForm" are split and indexed
// under each component.
func NewCatalogMatcher(
	sources []taint.SourceDef,
	sinks []taint.SinkDef,
	sanitizers []taint.SanitizerDef,
	typeEnv *TypeEnv,
) *CatalogMatcher {
	m := &CatalogMatcher{
		sourcesByMethod:    make(map[string][]*taint.SourceDef),
		sinksByMethod:      make(map[string][]*taint.SinkDef),
		sanitizersByMethod: make(map[string][]*taint.SanitizerDef),
		typeEnv:            typeEnv,
	}

	for i := range sources {
		src := &sources[i]
		for _, name := range extractMethodNames(src.MethodName) {
			m.sourcesByMethod[name] = append(m.sourcesByMethod[name], src)
		}
	}
	for i := range sinks {
		sink := &sinks[i]
		for _, name := range extractMethodNames(sink.MethodName) {
			m.sinksByMethod[name] = append(m.sinksByMethod[name], sink)
		}
	}
	for i := range sanitizers {
		san := &sanitizers[i]
		for _, name := range extractMethodNames(san.MethodName) {
			m.sanitizersByMethod[name] = append(m.sanitizersByMethod[name], san)
		}
	}

	return m
}

// extractMethodNames splits compound method names on "/" and extracts the
// final component after any "." for each part.
// "Query/Param/PostForm" -> ["Query", "Param", "PostForm"]
// "os.Args" -> ["Args"]
// "FormValue" -> ["FormValue"]
// "URL.Query" -> ["Query"]
// "slog.Info" -> ["Info"]
func extractMethodNames(methodName string) []string {
	parts := strings.Split(methodName, "/")
	var names []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Take the last dot-separated component.
		dotParts := strings.Split(p, ".")
		name := dotParts[len(dotParts)-1]
		// Skip wildcard-like patterns.
		if name != "" && name != "*" {
			names = append(names, name)
		}
	}
	return names
}

// MatchSource checks if a call expression matches a known taint source.
func (m *CatalogMatcher) MatchSource(call *ast.CallExpr) *taint.SourceDef {
	methodName := extractCallMethodName(call)
	if methodName == "" {
		return nil
	}

	candidates := m.sourcesByMethod[methodName]
	for _, src := range candidates {
		if m.matchesCall(call, src.ObjectType, src.MethodName) {
			return src
		}
	}

	return nil
}

// MatchSink checks if a call expression matches a known sink.
// Returns the sink and the dangerous argument expressions.
func (m *CatalogMatcher) MatchSink(call *ast.CallExpr) (*taint.SinkDef, []ast.Expr) {
	methodName := extractCallMethodName(call)
	if methodName == "" {
		return nil, nil
	}

	candidates := m.sinksByMethod[methodName]
	for _, sink := range candidates {
		if m.matchesCall(call, sink.ObjectType, sink.MethodName) {
			// Special case: fmt.Fprintf/Fprint/Fprintln to ResponseWriter.
			if sink.Category == taint.SnkHTMLOutput && isFmtWriteFunc(sink.MethodName) {
				if len(call.Args) > 0 {
					firstArg := identName(call.Args[0])
					if !matchesReceiverType(firstArg, "http.ResponseWriter") {
						continue
					}
				}
			}

			dangerous := collectDangerousArgs(call, sink.DangerousArgs)
			return sink, dangerous
		}
	}

	return nil, nil
}

// MatchSanitizer checks if a call expression matches a known sanitizer.
// Returns the sanitizer and the expression being sanitized (first arg).
func (m *CatalogMatcher) MatchSanitizer(call *ast.CallExpr) (*taint.SanitizerDef, ast.Expr) {
	methodName := extractCallMethodName(call)
	if methodName == "" {
		return nil, nil
	}

	candidates := m.sanitizersByMethod[methodName]
	for _, san := range candidates {
		if m.matchesCall(call, san.ObjectType, san.MethodName) {
			if len(call.Args) > 0 {
				return san, call.Args[0]
			}
			return san, nil
		}
	}

	return nil, nil
}

// matchesCall checks if a call expression plausibly matches a catalog entry
// with the given objectType and methodName.
func (m *CatalogMatcher) matchesCall(call *ast.CallExpr, objectType, methodName string) bool {
	// Package-level function: exec.Command, os.Getenv, etc.
	if objectType == "" {
		return m.matchesPackageCall(call, methodName)
	}

	// Method call on receiver: r.FormValue, db.Query, etc.
	return m.matchesMethodCall(call, objectType, methodName)
}

// matchesPackageCall checks if a call matches a package-level function.
func (m *CatalogMatcher) matchesPackageCall(call *ast.CallExpr, methodName string) bool {
	sel := selectorString(call.Fun)
	if sel == "" {
		return false
	}

	// Direct match: "exec.Command" == "exec.Command"
	if sel == methodName {
		return true
	}

	// Match by final method name with package verification via imports.
	selExpr, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	callMethod := selExpr.Sel.Name

	// Check each component of compound method names.
	for _, candidate := range strings.Split(methodName, "/") {
		candidate = strings.TrimSpace(candidate)
		dotParts := strings.Split(candidate, ".")
		finalMethod := dotParts[len(dotParts)-1]

		if callMethod != finalMethod {
			continue
		}

		// If methodName has a package prefix, verify it.
		if len(dotParts) >= 2 {
			pkgAlias := identName(selExpr.X)
			expectedPkg := dotParts[0]
			if pkgAlias == expectedPkg {
				return true
			}
			// Check if import alias resolves to expected package.
			if m.typeEnv != nil {
				importPath := m.typeEnv.ResolveImport(pkgAlias)
				if importPath != "" {
					pathParts := strings.Split(importPath, "/")
					if pathParts[len(pathParts)-1] == expectedPkg {
						return true
					}
				}
			}
		}

		// Simple method name match (single component like "Command").
		if len(dotParts) == 1 {
			return true
		}
	}

	return false
}

// matchesMethodCall checks if a call matches a method call on a receiver.
func (m *CatalogMatcher) matchesMethodCall(call *ast.CallExpr, objectType, methodName string) bool {
	selExpr, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	callMethod := selExpr.Sel.Name

	// Check if the method name matches any component.
	matched := false
	for _, candidate := range strings.Split(methodName, "/") {
		candidate = strings.TrimSpace(candidate)
		dotParts := strings.Split(candidate, ".")
		finalMethod := dotParts[len(dotParts)-1]
		if callMethod == finalMethod {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	// Try TypeEnv for precise type match.
	recvName := identName(selExpr.X)
	if recvName != "" && m.typeEnv != nil {
		knownType := m.typeEnv.VarType(recvName)
		if knownType != "" && typeMatches(knownType, objectType) {
			return true
		}
	}

	// Fallback: receiver name heuristic (from goflow).
	if recvName != "" && matchesReceiverType(recvName, objectType) {
		return true
	}

	// Handle chained calls: r.URL.Query().Get(...)
	if innerSel, ok := selExpr.X.(*ast.SelectorExpr); ok {
		innerRecv := identName(innerSel.X)
		if innerRecv != "" && matchesReceiverType(innerRecv, objectType) {
			return true
		}
	}

	// Handle call chains: r.URL.Query().Get(...)
	if innerCall, ok := selExpr.X.(*ast.CallExpr); ok {
		innerRecv := deepReceiverName(innerCall.Fun)
		if innerRecv != "" && matchesReceiverType(innerRecv, objectType) {
			return true
		}
	}

	return false
}

// typeMatches checks if a known type matches a catalog object type.
func typeMatches(knownType, catalogType string) bool {
	if knownType == catalogType {
		return true
	}
	// Handle pointer/non-pointer differences.
	if strings.TrimPrefix(knownType, "*") == strings.TrimPrefix(catalogType, "*") {
		return true
	}
	// Handle partial match: "sql.DB" matches "*sql.DB".
	return strings.Contains(catalogType, strings.TrimPrefix(knownType, "*")) ||
		strings.Contains(knownType, strings.TrimPrefix(catalogType, "*"))
}

// extractCallMethodName extracts the final method/function name from a call.
func extractCallMethodName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

// collectDangerousArgs returns argument expressions at the dangerous positions.
func collectDangerousArgs(call *ast.CallExpr, dangerousArgs []int) []ast.Expr {
	var dangerous []ast.Expr
	for _, argIdx := range dangerousArgs {
		if argIdx == -1 {
			dangerous = append(dangerous, call.Args...)
			break
		}
		if argIdx >= 0 && argIdx < len(call.Args) {
			dangerous = append(dangerous, call.Args[argIdx])
		}
	}
	return dangerous
}

// isFmtWriteFunc checks if a method name is a fmt write function.
func isFmtWriteFunc(name string) bool {
	return name == "Fprintf" || name == "Fprint" || name == "Fprintln"
}

// matchesReceiverType checks if a receiver variable name plausibly corresponds
// to a given type using naming conventions (fallback heuristic).
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
	case strings.Contains(objType, "gorm.DB"):
		return lower == "db" || lower == "conn" || lower == "gdb" || lower == "gorm"
	case strings.Contains(objType, "redis.Client"):
		return lower == "rdb" || lower == "client" || lower == "redis"
	case strings.Contains(objType, "json.Decoder"):
		return lower == "dec" || lower == "decoder"
	case strings.Contains(objType, "zap.Logger"):
		return lower == "logger" || lower == "log" || lower == "zap" || lower == "sugar"
	case strings.Contains(objType, "template.Template"):
		return lower == "tmpl" || lower == "tpl" || lower == "t" || lower == "template"
	case strings.Contains(objType, "bluemonday.Policy"):
		return lower == "p" || lower == "policy" || lower == "sanitizer"
	case strings.Contains(objType, "validator.Validate"):
		return lower == "validate" || lower == "v" || lower == "validator"
	case strings.Contains(objType, "docker.Client"):
		return lower == "cli" || lower == "client" || lower == "docker"
	case strings.Contains(objType, "kafka.Writer"):
		return lower == "writer" || lower == "w" || lower == "producer"
	}

	return false
}
