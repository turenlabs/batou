package graph

import (
	"go/ast"
	"regexp"
	"strings"
	"time"

	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
	"github.com/turenio/gtss/internal/taint/astflow"
)

// UpdateFile parses a file and updates the call graph with its function
// nodes and call relationships. Returns the list of function IDs that
// were updated (so we know which callers to re-analyze).
func UpdateFile(cg *CallGraph, filePath string, content string, lang rules.Language) []string {
	return UpdateFileWithAST(cg, filePath, content, lang, nil)
}

// UpdateFileWithAST is like UpdateFile but accepts a pre-parsed Go AST
// to avoid redundant parsing. The parsed parameter is only used for Go
// files; for other languages it is ignored. If nil, falls back to parsing.
func UpdateFileWithAST(cg *CallGraph, filePath string, content string, lang rules.Language, parsed *astflow.GoParseResult) []string {
	switch lang {
	case rules.LangGo:
		return buildGoNodes(cg, filePath, content, parsed)
	default:
		return buildGenericNodes(cg, filePath, content, lang)
	}
}

// buildGoNodes uses go/ast to extract function declarations and call
// relationships from Go source code.
func buildGoNodes(cg *CallGraph, filePath string, content string, parsed *astflow.GoParseResult) []string {
	if parsed == nil {
		parsed = astflow.ParseGo(content, filePath)
		if parsed == nil {
			return nil
		}
	}

	fset := parsed.Fset
	f := parsed.File

	// Snapshot old nodes from this file so we can detect changes.
	oldNodes := make(map[string]*FuncNode)
	for _, node := range cg.NodesInFile(filePath) {
		oldNodes[node.ID] = node
	}

	// Remove old nodes for this file before adding new ones.
	cg.RemoveFile(filePath)

	var updatedIDs []string
	// Map from function node ID to the list of callees (raw names) found in its body.
	callMap := make(map[string][]string)

	// Extract package name.
	pkgName := ""
	if f.Name != nil {
		pkgName = f.Name.Name
	}

	// Walk all FuncDecl nodes to create FuncNodes.
	for _, decl := range f.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		// Build function name: "FuncName" or "Receiver.Method".
		funcName := funcDecl.Name.Name
		if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
			recvType := exprTypeName(funcDecl.Recv.List[0].Type)
			if recvType != "" {
				funcName = recvType + "." + funcDecl.Name.Name
			}
		}

		id := FuncID(filePath, funcName)
		startPos := fset.Position(funcDecl.Pos())
		endPos := fset.Position(funcDecl.End())

		// Extract the function body text for hashing.
		bodyStart := fset.Position(funcDecl.Body.Lbrace).Offset
		bodyEnd := fset.Position(funcDecl.Body.Rbrace).Offset + 1
		bodyText := ""
		if bodyStart >= 0 && bodyEnd <= len(content) && bodyStart < bodyEnd {
			bodyText = content[bodyStart:bodyEnd]
		}
		hash := ContentHash(bodyText)

		// Check if the content actually changed.
		if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
			// Content unchanged — re-add the old node as-is to preserve taint sig.
			cg.AddNode(old)
			continue
		}

		// Extract parameters.
		var params []string
		if funcDecl.Type.Params != nil {
			for _, field := range funcDecl.Type.Params.List {
				for _, name := range field.Names {
					params = append(params, name.Name)
				}
			}
		}

		node := &FuncNode{
			ID:          id,
			FilePath:    filePath,
			Name:        funcName,
			Package:     pkgName,
			StartLine:   startPos.Line,
			EndLine:     endPos.Line,
			ContentHash: hash,
			LastScanAt:  time.Now(),
			Language:    rules.LangGo,
		}
		cg.AddNode(node)
		updatedIDs = append(updatedIDs, id)

		// Walk the function body for call expressions.
		var calls []string
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			callExpr, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := callExpr.Fun.(type) {
			case *ast.SelectorExpr:
				// pkg.Func() or receiver.Method()
				if ident, ok := fun.X.(*ast.Ident); ok {
					calls = append(calls, ident.Name+"."+fun.Sel.Name)
				}
			case *ast.Ident:
				// Direct function call: Func()
				calls = append(calls, fun.Name)
			}
			return true
		})
		callMap[id] = calls
	}

	// Resolve call edges. For each call, try to find a matching node in the graph.
	// We check: same file with exact name, or same file with selector match.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			// Try exact match in the same file first.
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
				continue
			}
			// Try matching just the function name part (for method calls where
			// the receiver might differ in how we recorded the ID).
			parts := strings.SplitN(callName, ".", 2)
			if len(parts) == 2 {
				// Look for any node in the graph whose name ends with .MethodName
				// in the same file.
				for _, node := range cg.NodesInFile(filePath) {
					if strings.HasSuffix(node.Name, "."+parts[1]) {
						cg.AddEdge(callerID, node.ID)
						break
					}
				}
			}
		}
	}

	return updatedIDs
}

// exprTypeName extracts the type name from a receiver expression.
func exprTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprTypeName(t.X)
	case *ast.IndexExpr:
		// Generic type: Type[T]
		return exprTypeName(t.X)
	default:
		return ""
	}
}

// buildGenericNodes uses scope detection + regex patterns to extract
// function declarations and call relationships for non-Go languages.
func buildGenericNodes(cg *CallGraph, filePath string, content string, lang rules.Language) []string {
	scopes := taint.DetectScopes(content, lang)

	// Snapshot old nodes for change detection.
	oldNodes := make(map[string]*FuncNode)
	for _, node := range cg.NodesInFile(filePath) {
		oldNodes[node.ID] = node
	}

	// Remove old nodes for this file.
	cg.RemoveFile(filePath)

	var updatedIDs []string
	callMap := make(map[string][]string)

	for _, scope := range scopes {
		if scope.Name == "__top_level__" {
			continue
		}

		id := FuncID(filePath, scope.Name)
		hash := ContentHash(scope.Body)

		// Check if unchanged.
		if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
			cg.AddNode(old)
			continue
		}

		node := &FuncNode{
			ID:          id,
			FilePath:    filePath,
			Name:        scope.Name,
			StartLine:   scope.StartLine,
			EndLine:     scope.EndLine,
			ContentHash: hash,
			LastScanAt:  time.Now(),
			Language:    lang,
		}
		cg.AddNode(node)
		updatedIDs = append(updatedIDs, id)

		// Extract call relationships from the scope body using language-specific patterns.
		calls := extractCalls(scope.Body, lang)
		callMap[id] = calls
	}

	// Resolve call edges within the same file.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
			}
		}
	}

	return updatedIDs
}

// Language-specific call extraction patterns.
var (
	// Python: funcname( or obj.method(
	pyCallRe = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*\(`)
	pyMethodRe = regexp.MustCompile(`\b\w+\.([a-zA-Z_]\w*)\s*\(`)

	// JavaScript/TypeScript: funcname(, obj.method(, new ClassName(
	jsCallRe  = regexp.MustCompile(`\b([a-zA-Z_$]\w*)\s*\(`)
	jsMethodRe = regexp.MustCompile(`\b\w+\.([a-zA-Z_$]\w*)\s*\(`)
	jsNewRe   = regexp.MustCompile(`\bnew\s+([a-zA-Z_$]\w*)\s*\(`)

	// Java: methodName(, ClassName.method(, new ClassName(
	javaCallRe   = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*\(`)
	javaMethodRe = regexp.MustCompile(`\b([A-Z]\w*)\.([a-zA-Z_]\w*)\s*\(`)
	javaNewRe    = regexp.MustCompile(`\bnew\s+([A-Z]\w*)\s*\(`)

	// PHP: funcname(, $obj->method(, ClassName::method(
	phpCallRe    = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*\(`)
	phpMethodRe  = regexp.MustCompile(`->([a-zA-Z_]\w*)\s*\(`)
	phpStaticRe  = regexp.MustCompile(`([A-Z]\w*)::([a-zA-Z_]\w*)\s*\(`)

	// Ruby: funcname(, obj.method (may or may not have parens)
	rubyCallRe   = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*[\(]`)
	rubyMethodRe = regexp.MustCompile(`\b\w+\.([a-zA-Z_]\w*)`)

	// C/C++: funcname(, obj.method(, obj->method(, Class::method(
	cCallRe    = regexp.MustCompile(`\b([a-zA-Z_]\w*)\s*\(`)
	cArrowRe   = regexp.MustCompile(`->([a-zA-Z_]\w*)\s*\(`)
	cScopeRe   = regexp.MustCompile(`\b([a-zA-Z_]\w*)::([a-zA-Z_]\w*)\s*\(`)
)

// Common keywords that should not be treated as function calls.
var callKeywords = map[string]bool{
	"if": true, "else": true, "for": true, "while": true, "do": true,
	"switch": true, "case": true, "return": true, "break": true, "continue": true,
	"try": true, "catch": true, "finally": true, "throw": true, "throws": true,
	"class": true, "interface": true, "struct": true, "enum": true,
	"import": true, "from": true, "package": true, "require": true,
	"var": true, "let": true, "const": true, "type": true, "def": true,
	"func": true, "function": true, "async": true, "await": true,
	"new": true, "delete": true, "typeof": true, "instanceof": true,
	"print": true, "println": true, "printf": true, "fmt": true,
	"nil": true, "null": true, "true": true, "false": true,
	"self": true, "this": true, "super": true, "cls": true,
}

// extractCalls returns a deduplicated list of function/method names called in the body.
func extractCalls(body string, lang rules.Language) []string {
	seen := make(map[string]bool)
	var result []string

	addCall := func(name string) {
		if name == "" || callKeywords[name] || seen[name] {
			return
		}
		seen[name] = true
		result = append(result, name)
	}

	switch lang {
	case rules.LangPython:
		for _, m := range pyCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range pyMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}

	case rules.LangJavaScript, rules.LangTypeScript:
		for _, m := range jsCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range jsMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range jsNewRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}

	case rules.LangJava, rules.LangCSharp:
		for _, m := range javaCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range javaMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[2])
		}
		for _, m := range javaNewRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}

	case rules.LangPHP:
		for _, m := range phpCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range phpMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range phpStaticRe.FindAllStringSubmatch(body, -1) {
			addCall(m[2])
		}

	case rules.LangRuby:
		for _, m := range rubyCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range rubyMethodRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}

	case rules.LangC, rules.LangCPP:
		for _, m := range cCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range cArrowRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
		for _, m := range cScopeRe.FindAllStringSubmatch(body, -1) {
			addCall(m[2])
		}

	default:
		// Fallback: look for generic function call pattern identifier(
		for _, m := range pyCallRe.FindAllStringSubmatch(body, -1) {
			addCall(m[1])
		}
	}

	return result
}
