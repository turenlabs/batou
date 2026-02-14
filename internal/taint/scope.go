package taint

import (
	"strings"
	"unicode"

	"github.com/turen/gtss/internal/rules"
)

// DetectScopes analyzes source code and returns a list of Scope structs
// representing function/method/closure boundaries.
func DetectScopes(content string, lang rules.Language) []Scope {
	lines := strings.Split(content, "\n")

	switch lang {
	case rules.LangPython:
		return detectScopesPython(lines)
	case rules.LangRuby:
		return detectScopesRuby(lines)
	default:
		return detectScopesBrace(lines, lang)
	}
}

// detectScopesBrace handles brace-delimited languages: Go, JS, TS, Java, PHP, C, C++, C#, Shell, Rust.
func detectScopesBrace(lines []string, lang rules.Language) []Scope {
	type pending struct {
		name       string
		startLine  int
		params     []string
		braceDepth int
		parent     *Scope
	}

	var scopes []Scope
	var stack []*pending
	globalBraceDepth := 0
	inString := false
	stringChar := byte(0)

	// Collect top-level lines (not inside any function).
	var topLevelLines []string
	topLevelStart := 1

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and single-line comments for function detection.
		isComment := strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*")

		// Detect function/method start before counting braces on this line.
		if !isComment && !inString && len(stack) == 0 {
			if name, params, ok := detectFuncStart(trimmed, lang); ok {
				stack = append(stack, &pending{
					name:       name,
					startLine:  lineNum,
					params:     params,
					braceDepth: globalBraceDepth,
				})
			}
		} else if !isComment && !inString && len(stack) > 0 {
			// Detect nested function/closure inside an existing scope.
			if name, params, ok := detectFuncStart(trimmed, lang); ok {
				var parentScope *Scope
				// The parent will be resolved when we close.
				_ = parentScope
				stack = append(stack, &pending{
					name:       name,
					startLine:  lineNum,
					params:     params,
					braceDepth: globalBraceDepth,
				})
			}
		}

		// Count braces on this line, respecting strings.
		for i := 0; i < len(line); i++ {
			ch := line[i]

			if inString {
				if ch == '\\' && i+1 < len(line) {
					i++ // skip escaped character
					continue
				}
				if ch == stringChar {
					inString = false
				}
				continue
			}

			switch ch {
			case '"', '\'', '`':
				inString = true
				stringChar = ch
			case '{':
				globalBraceDepth++
			case '}':
				globalBraceDepth--

				// Check if we close a pending scope.
				if len(stack) > 0 {
					top := stack[len(stack)-1]
					if globalBraceDepth == top.braceDepth {
						// Scope closed.
						bodyLines := extractLines(lines, top.startLine, lineNum)
						scope := Scope{
							Name:      top.name,
							StartLine: top.startLine,
							EndLine:   lineNum,
							Params:    top.params,
							Body:      strings.Join(bodyLines, "\n"),
							Lines:     bodyLines,
						}
						// If there's a parent pending, set the parent pointer when parent closes.
						if len(stack) > 1 {
							// We'll set parent later; for now, store nil.
						}
						scopes = append(scopes, scope)
						stack = stack[:len(stack)-1]
					}
				}
			case '/':
				// Skip line comments.
				if i+1 < len(line) && line[i+1] == '/' {
					i = len(line)
				}
			}
		}

		// Track top-level lines.
		if len(stack) == 0 {
			topLevelLines = append(topLevelLines, line)
		}
	}

	// Set parent pointers for nested scopes.
	for i := range scopes {
		for j := range scopes {
			if i == j {
				continue
			}
			// If scope i is fully contained within scope j, j is a potential parent.
			if scopes[i].StartLine > scopes[j].StartLine && scopes[i].EndLine < scopes[j].EndLine {
				if scopes[i].Parent == nil || (scopes[j].StartLine > scopes[i].Parent.StartLine) {
					scopes[i].Parent = &scopes[j]
				}
			}
		}
	}

	// Add a top-level scope if there's meaningful content outside functions.
	if hasNonTrivialContent(topLevelLines) {
		allBody := strings.Join(topLevelLines, "\n")
		topScope := Scope{
			Name:      "__top_level__",
			StartLine: topLevelStart,
			EndLine:   len(lines),
			Body:      allBody,
			Lines:     topLevelLines,
		}
		scopes = append(scopes, topScope)
	}

	return scopes
}

// detectFuncStart checks if a trimmed line starts a function/method definition.
// Returns (name, params, true) on match.
func detectFuncStart(trimmed string, lang rules.Language) (string, []string, bool) {
	switch lang {
	case rules.LangGo:
		return detectGoFunc(trimmed)
	case rules.LangJavaScript, rules.LangTypeScript:
		return detectJSFunc(trimmed)
	case rules.LangJava, rules.LangCSharp:
		return detectJavaFunc(trimmed)
	case rules.LangPHP:
		return detectPHPFunc(trimmed)
	case rules.LangShell:
		return detectShellFunc(trimmed)
	case rules.LangRust:
		return detectRustFunc(trimmed)
	case rules.LangC, rules.LangCPP:
		return detectCFunc(trimmed)
	default:
		return "", nil, false
	}
}

// detectGoFunc detects Go function/method declarations.
func detectGoFunc(line string) (string, []string, bool) {
	// "func Name(" or "func (recv) Name("
	if !strings.HasPrefix(line, "func ") {
		return "", nil, false
	}
	rest := line[5:]

	// Method with receiver: (recv Type) Name(
	if strings.HasPrefix(rest, "(") {
		closeIdx := strings.Index(rest, ")")
		if closeIdx < 0 {
			return "", nil, false
		}
		rest = strings.TrimSpace(rest[closeIdx+1:])
	}

	// Extract function name.
	parenIdx := strings.Index(rest, "(")
	if parenIdx < 0 {
		return "", nil, false
	}
	name := strings.TrimSpace(rest[:parenIdx])
	if name == "" {
		name = "__anon__"
	}

	params := extractParamNames(rest[parenIdx:])
	return name, params, true
}

// detectJSFunc detects JavaScript/TypeScript function definitions.
func detectJSFunc(line string) (string, []string, bool) {
	// Strip "export" and "export default" prefixes so that
	// "export function ...", "export default function ...",
	// "export const ..." etc. are handled by the existing checks below.
	if strings.HasPrefix(line, "export default ") {
		line = line[15:]
	} else if strings.HasPrefix(line, "export ") {
		line = line[7:]
	}

	// Express router handlers: router.get/post/put/delete/use(path, (req...)
	if strings.HasPrefix(line, "router.") || strings.HasPrefix(line, "app.") {
		if name, params, ok := detectExpressRouterHandler(line); ok {
			return name, params, true
		}
	}

	// "function name("
	if strings.HasPrefix(line, "function ") {
		rest := line[9:]
		// "function*" for generators.
		if strings.HasPrefix(rest, "*") {
			rest = strings.TrimSpace(rest[1:])
		}
		parenIdx := strings.Index(rest, "(")
		if parenIdx < 0 {
			return "", nil, false
		}
		name := strings.TrimSpace(rest[:parenIdx])
		if name == "" {
			name = "__anon__"
		}
		params := extractParamNames(rest[parenIdx:])
		return name, params, true
	}

	// "async function name("
	if strings.HasPrefix(line, "async function ") {
		rest := line[15:]
		if strings.HasPrefix(rest, "*") {
			rest = strings.TrimSpace(rest[1:])
		}
		parenIdx := strings.Index(rest, "(")
		if parenIdx < 0 {
			return "", nil, false
		}
		name := strings.TrimSpace(rest[:parenIdx])
		if name == "" {
			name = "__anon__"
		}
		params := extractParamNames(rest[parenIdx:])
		return name, params, true
	}

	// "const/let/var name = (" or "const/let/var name = async ("
	// or "const name = function("
	for _, kw := range []string{"const ", "let ", "var "} {
		if strings.HasPrefix(line, kw) {
			rest := line[len(kw):]
			eqIdx := strings.Index(rest, "=")
			if eqIdx < 0 {
				continue
			}
			name := strings.TrimSpace(rest[:eqIdx])
			rhs := strings.TrimSpace(rest[eqIdx+1:])

			// Arrow function or function expression.
			if strings.Contains(rhs, "=>") || strings.HasPrefix(rhs, "function") ||
				strings.HasPrefix(rhs, "async") || strings.HasPrefix(rhs, "(") {
				params := extractParamNames(rhs)
				return name, params, true
			}
		}
	}

	// Class method: "name(" or "async name(" at certain indentation.
	// Also handles "get name()", "set name()", "static name(".
	// Require a body-opening "{" AFTER the parameter list to distinguish
	// declarations from plain calls (e.g., "next(new Error(...))" is a
	// call with no body brace and should not match).
	for _, prefix := range []string{"async ", "static ", "static async ", "get ", "set ", ""} {
		if prefix != "" && !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := line
		if prefix != "" {
			rest = line[len(prefix):]
		}
		// Must start with an identifier then "(".
		if len(rest) > 0 && isIdentStart(rest[0]) {
			parenIdx := strings.Index(rest, "(")
			if parenIdx > 0 {
				name := strings.TrimSpace(rest[:parenIdx])
				if isValidIdentifier(name) && !isJSKeyword(name) && hasBodyBrace(line) {
					params := extractParamNames(rest[parenIdx:])
					return name, params, true
				}
			}
		}
	}

	return "", nil, false
}

// hasBodyBrace returns true if the line contains a "{" that opens a function
// body — i.e., a "{" that appears AFTER the outermost closing ")" of the
// parameter list. This distinguishes "render(req) {" (declaration) from
// "solveIf(cb, () => { })" (call with callback containing braces).
func hasBodyBrace(line string) bool {
	// Find the last ")" at depth 0 (outermost close paren).
	depth := 0
	lastCloseParen := -1
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				lastCloseParen = i
			}
		}
	}
	if lastCloseParen < 0 {
		return false
	}
	// Check for "{" after the outermost close paren.
	return strings.Contains(line[lastCloseParen:], "{")
}

// detectExpressRouterHandler detects Express-style router handler definitions:
//
//	router.get('/path', async (req, res) => {
//	app.post('/api', (req: Request, res: Response) => {
func detectExpressRouterHandler(line string) (string, []string, bool) {
	// Find the HTTP method: router.get, app.post, etc.
	dotIdx := strings.Index(line, ".")
	if dotIdx < 0 {
		return "", nil, false
	}
	rest := line[dotIdx+1:]

	// Extract the HTTP method name (get, post, put, delete, use, all, patch).
	parenIdx := strings.Index(rest, "(")
	if parenIdx < 0 {
		return "", nil, false
	}
	method := strings.TrimSpace(rest[:parenIdx])
	switch method {
	case "get", "post", "put", "delete", "patch", "use", "all":
		// valid
	default:
		return "", nil, false
	}

	prefix := line[:dotIdx] // "router" or "app"
	name := prefix + "." + method

	// Extract the callback parameters — find the callback function's
	// parameter list. Look for patterns like "(req, res) =>" or
	// "function(req, res)" within the arguments.
	args := rest[parenIdx:]

	// Find the callback's param list by searching for the last "(...)
	// pattern that precedes "=>" or "{" (arrow function or function body).
	// This skips the outer call's route path argument.
	var params []string
	// Search for a nested "(" that starts a callback parameter list.
	// We look for "(" after a comma (past the route path argument).
	commaIdx := strings.Index(args, ",")
	if commaIdx >= 0 {
		callbackPart := args[commaIdx+1:]
		// Find the callback's "(" for its params.
		cbParenIdx := strings.Index(callbackPart, "(")
		if cbParenIdx >= 0 {
			params = extractParamNames(callbackPart[cbParenIdx:])
		}
	}

	return name, params, true
}

// detectJavaFunc detects Java/C# method declarations.
func detectJavaFunc(line string) (string, []string, bool) {
	// Skip if it's a class/interface/enum declaration.
	for _, kw := range []string{"class ", "interface ", "enum ", "import ", "package "} {
		if strings.Contains(line, kw) && !strings.Contains(line, "(") {
			return "", nil, false
		}
	}

	// Look for pattern: [modifiers] [type] name(
	parenIdx := strings.Index(line, "(")
	if parenIdx < 0 {
		return "", nil, false
	}

	before := strings.TrimSpace(line[:parenIdx])
	tokens := strings.Fields(before)
	if len(tokens) < 2 {
		return "", nil, false
	}

	// Last token is the method name, second-to-last is return type.
	name := tokens[len(tokens)-1]

	// Skip constructors that look like class declarations.
	if !isValidIdentifier(name) {
		return "", nil, false
	}

	// Must have modifiers or return type.
	hasModifier := false
	for _, tok := range tokens[:len(tokens)-1] {
		switch tok {
		case "public", "private", "protected", "static", "final",
			"abstract", "synchronized", "native", "void",
			"int", "long", "double", "float", "boolean", "byte", "char", "short",
			"override", "virtual", "internal", "async", "Task":
			hasModifier = true
		default:
			// Could be a return type (String, List<X>, etc.).
			if len(tok) > 0 && unicode.IsUpper(rune(tok[0])) {
				hasModifier = true
			}
		}
	}
	if !hasModifier {
		return "", nil, false
	}

	params := extractParamNames(line[parenIdx:])
	return name, params, true
}

// detectPHPFunc detects PHP function/method declarations.
func detectPHPFunc(line string) (string, []string, bool) {
	// "function name(" or "[public|private|protected] [static] function name("
	funcIdx := strings.Index(line, "function ")
	if funcIdx < 0 {
		return "", nil, false
	}

	rest := line[funcIdx+9:]
	parenIdx := strings.Index(rest, "(")
	if parenIdx < 0 {
		return "", nil, false
	}
	name := strings.TrimSpace(rest[:parenIdx])
	if name == "" {
		name = "__anon__"
	}

	params := extractParamNames(rest[parenIdx:])
	return name, params, true
}

// detectShellFunc detects shell function declarations.
func detectShellFunc(line string) (string, []string, bool) {
	// "function name" or "name()"
	if strings.HasPrefix(line, "function ") {
		rest := strings.TrimSpace(line[9:])
		// Remove optional () and {
		name := strings.TrimRight(rest, " {()")
		name = strings.TrimSpace(name)
		if isValidIdentifier(name) {
			return name, nil, true
		}
	}

	// "name()" or "name ()"
	if strings.Contains(line, "()") {
		name := strings.TrimSpace(strings.Split(line, "(")[0])
		if isValidIdentifier(name) && !strings.Contains(name, " ") {
			return name, nil, true
		}
	}

	return "", nil, false
}

// detectRustFunc detects Rust function declarations.
func detectRustFunc(line string) (string, []string, bool) {
	// "fn name(" or "pub fn name(" or "pub(crate) fn name(" or "async fn name("
	fnIdx := strings.Index(line, "fn ")
	if fnIdx < 0 {
		return "", nil, false
	}

	rest := line[fnIdx+3:]
	parenIdx := strings.Index(rest, "(")
	if parenIdx < 0 {
		return "", nil, false
	}
	name := strings.TrimSpace(rest[:parenIdx])
	// Remove generic parameters.
	if genIdx := strings.Index(name, "<"); genIdx >= 0 {
		name = name[:genIdx]
	}
	if name == "" {
		return "", nil, false
	}

	params := extractParamNames(rest[parenIdx:])
	return name, params, true
}

// detectCFunc detects C/C++ function and method declarations.
// Handles:
//   - Standard functions: "type name(params) {"
//   - Pointer returns: "type *name(params) {"
//   - C++ methods: "type ClassName::methodName(params) {"
//   - Modifiers: "static inline type name(params) {"
func detectCFunc(line string) (string, []string, bool) {
	// Skip preprocessor directives.
	if strings.HasPrefix(strings.TrimSpace(line), "#") {
		return "", nil, false
	}

	// Skip control flow keywords that look like function calls.
	for _, kw := range []string{"if", "for", "while", "switch", "return", "sizeof", "alignof", "typedef"} {
		if strings.HasPrefix(strings.TrimSpace(line), kw+"(") || strings.HasPrefix(strings.TrimSpace(line), kw+" (") {
			return "", nil, false
		}
	}

	parenIdx := strings.Index(line, "(")
	if parenIdx < 0 {
		return "", nil, false
	}

	before := strings.TrimSpace(line[:parenIdx])
	tokens := strings.Fields(before)
	if len(tokens) < 2 {
		return "", nil, false
	}

	name := tokens[len(tokens)-1]
	// Handle pointer return types: remove leading *.
	name = strings.TrimLeft(name, "*")

	// Handle C++ scope operator: ClassName::methodName
	if scopeIdx := strings.LastIndex(name, "::"); scopeIdx >= 0 {
		className := name[:scopeIdx]
		methodName := name[scopeIdx+2:]
		if !isValidIdentifier(className) || !isValidIdentifier(methodName) {
			return "", nil, false
		}
		// Use ClassName::methodName as the scope name.
	} else if !isValidIdentifier(name) {
		return "", nil, false
	}

	// The tokens before the name should include a type or modifier.
	// Skip known C/C++ modifiers to find the type token.
	cModifiers := map[string]bool{
		"static": true, "inline": true, "extern": true, "virtual": true,
		"explicit": true, "constexpr": true, "const": true, "volatile": true,
		"unsigned": true, "signed": true, "register": true, "auto": true,
		"__attribute__": true, "__declspec": true, "override": true,
		"noexcept": true, "friend": true, "template": true,
	}
	hasType := false
	for _, tok := range tokens[:len(tokens)-1] {
		cleaned := strings.TrimRight(tok, "*&")
		if cModifiers[cleaned] {
			continue
		}
		if isValidIdentifier(cleaned) || cleaned == "void" {
			hasType = true
			break
		}
	}
	if !hasType {
		return "", nil, false
	}

	params := extractParamNames(line[parenIdx:])
	return name, params, true
}

// detectScopesPython handles indentation-based scope detection for Python.
func detectScopesPython(lines []string) []Scope {
	type pending struct {
		name      string
		startLine int
		params    []string
		indent    int
	}

	var scopes []Scope
	var stack []*pending
	var topLevelLines []string

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if len(stack) == 0 {
				topLevelLines = append(topLevelLines, line)
			}
			continue
		}

		indent := countIndent(line)

		// Close scopes that have ended (line at same or lower indentation).
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			if indent <= top.indent {
				endLine := lineNum - 1
				// Find the last non-empty line.
				for endLine > top.startLine && strings.TrimSpace(lines[endLine-1]) == "" {
					endLine--
				}
				bodyLines := extractLines(lines, top.startLine, endLine)
				scope := Scope{
					Name:      top.name,
					StartLine: top.startLine,
					EndLine:   endLine,
					Params:    top.params,
					Body:      strings.Join(bodyLines, "\n"),
					Lines:     bodyLines,
				}
				scopes = append(scopes, scope)
				stack = stack[:len(stack)-1]
			} else {
				break
			}
		}

		// Detect function/method start.
		defLine := trimmed
		isAsync := false
		if strings.HasPrefix(defLine, "async ") {
			isAsync = true
			defLine = defLine[6:]
			_ = isAsync
		}
		if strings.HasPrefix(defLine, "def ") {
			rest := defLine[4:]
			parenIdx := strings.Index(rest, "(")
			if parenIdx >= 0 {
				name := strings.TrimSpace(rest[:parenIdx])
				params := extractParamNames(rest[parenIdx:])
				// Remove 'self' and 'cls' from params.
				params = filterPythonParams(params)
				stack = append(stack, &pending{
					name:      name,
					startLine: lineNum,
					params:    params,
					indent:    indent,
				})
				continue
			}
		}

		if len(stack) == 0 {
			topLevelLines = append(topLevelLines, line)
		}
	}

	// Close any remaining open scopes.
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		endLine := len(lines)
		bodyLines := extractLines(lines, top.startLine, endLine)
		scope := Scope{
			Name:      top.name,
			StartLine: top.startLine,
			EndLine:   endLine,
			Params:    top.params,
			Body:      strings.Join(bodyLines, "\n"),
			Lines:     bodyLines,
		}
		scopes = append(scopes, scope)
		stack = stack[:len(stack)-1]
	}

	// Set parent pointers for nested scopes.
	for i := range scopes {
		for j := range scopes {
			if i == j {
				continue
			}
			if scopes[i].StartLine > scopes[j].StartLine && scopes[i].EndLine <= scopes[j].EndLine {
				if scopes[i].Parent == nil || scopes[j].StartLine > scopes[i].Parent.StartLine {
					scopes[i].Parent = &scopes[j]
				}
			}
		}
	}

	if hasNonTrivialContent(topLevelLines) {
		topScope := Scope{
			Name:      "__top_level__",
			StartLine: 1,
			EndLine:   len(lines),
			Body:      strings.Join(topLevelLines, "\n"),
			Lines:     topLevelLines,
		}
		scopes = append(scopes, topScope)
	}

	return scopes
}

// detectScopesRuby handles Ruby's def/end based scope detection.
func detectScopesRuby(lines []string) []Scope {
	type pending struct {
		name      string
		startLine int
		params    []string
		depth     int // nesting depth
	}

	var scopes []Scope
	var stack []*pending
	var topLevelLines []string
	depth := 0

	blockStarters := []string{
		"class ", "module ", "if ", "unless ", "while ", "until ",
		"for ", "case ", "begin", "do",
	}

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if len(stack) == 0 {
				topLevelLines = append(topLevelLines, line)
			}
			continue
		}

		// Detect function start.
		if strings.HasPrefix(trimmed, "def ") {
			rest := trimmed[4:]
			name := rest
			var params []string
			if parenIdx := strings.Index(rest, "("); parenIdx >= 0 {
				name = strings.TrimSpace(rest[:parenIdx])
				params = extractParamNames(rest[parenIdx:])
			} else if spaceIdx := strings.Index(rest, " "); spaceIdx >= 0 {
				name = rest[:spaceIdx]
			}
			// Handle trailing newline content.
			name = strings.TrimSpace(name)
			stack = append(stack, &pending{
				name:      name,
				startLine: lineNum,
				params:    params,
				depth:     depth,
			})
			depth++
			continue
		}

		// Track depth for other block starters.
		isBlockStart := false
		for _, bs := range blockStarters {
			if strings.HasPrefix(trimmed, bs) {
				isBlockStart = true
				break
			}
		}
		if isBlockStart {
			depth++
		}

		// "end" closes a block.
		if trimmed == "end" || strings.HasPrefix(trimmed, "end ") || strings.HasPrefix(trimmed, "end;") {
			depth--
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				if depth == top.depth {
					bodyLines := extractLines(lines, top.startLine, lineNum)
					scope := Scope{
						Name:      top.name,
						StartLine: top.startLine,
						EndLine:   lineNum,
						Params:    top.params,
						Body:      strings.Join(bodyLines, "\n"),
						Lines:     bodyLines,
					}
					scopes = append(scopes, scope)
					stack = stack[:len(stack)-1]
				}
			}
			continue
		}

		if len(stack) == 0 {
			topLevelLines = append(topLevelLines, line)
		}
	}

	// Set parent pointers.
	for i := range scopes {
		for j := range scopes {
			if i == j {
				continue
			}
			if scopes[i].StartLine > scopes[j].StartLine && scopes[i].EndLine < scopes[j].EndLine {
				if scopes[i].Parent == nil || scopes[j].StartLine > scopes[i].Parent.StartLine {
					scopes[i].Parent = &scopes[j]
				}
			}
		}
	}

	if hasNonTrivialContent(topLevelLines) {
		topScope := Scope{
			Name:      "__top_level__",
			StartLine: 1,
			EndLine:   len(lines),
			Body:      strings.Join(topLevelLines, "\n"),
			Lines:     topLevelLines,
		}
		scopes = append(scopes, topScope)
	}

	return scopes
}

// --- Helpers ---

// extractLines returns the slice of lines from startLine to endLine (1-indexed, inclusive).
func extractLines(allLines []string, startLine, endLine int) []string {
	if startLine < 1 {
		startLine = 1
	}
	if endLine > len(allLines) {
		endLine = len(allLines)
	}
	if startLine > endLine {
		return nil
	}
	result := make([]string, endLine-startLine+1)
	copy(result, allLines[startLine-1:endLine])
	return result
}

// extractParamNames extracts parameter names from a parenthesized parameter list.
// Input starts with "(" and may not include the closing ")".
func extractParamNames(s string) []string {
	// Find the parameter list between ( and ).
	start := strings.Index(s, "(")
	if start < 0 {
		return nil
	}
	end := strings.Index(s[start:], ")")
	if end < 0 {
		// Might be a multi-line signature; take what we have.
		end = len(s) - start
	}
	inner := s[start+1 : start+end]
	if strings.TrimSpace(inner) == "" {
		return nil
	}

	parts := splitParams(inner)
	var names []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := extractParamName(part)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// splitParams splits a parameter string by commas, respecting nested parens and generics.
func splitParams(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '<', '{':
			depth++
		case ')', ']', '>', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// extractParamName extracts the parameter name from a single parameter declaration.
func extractParamName(param string) string {
	param = strings.TrimSpace(param)

	// Remove default values: name = default
	if eqIdx := strings.Index(param, "="); eqIdx >= 0 {
		param = strings.TrimSpace(param[:eqIdx])
	}

	// Remove type annotations (Python: name: type, TS: name: type).
	if colonIdx := strings.Index(param, ":"); colonIdx >= 0 {
		param = strings.TrimSpace(param[:colonIdx])
	}

	// For typed languages like Go/Java: type name or name type.
	// Heuristic: take the last identifier-like token.
	tokens := strings.Fields(param)
	if len(tokens) == 0 {
		return ""
	}

	// If the last token looks like a name (starts with lowercase or underscore).
	last := tokens[len(tokens)-1]
	last = strings.TrimLeft(last, "*&$")  // Remove pointer/ref/PHP-var markers.
	last = strings.TrimRight(last, "?!,") // Remove Ruby/TS optional markers.
	// Remove trailing C array brackets (e.g., argv[] -> argv).
	if idx := strings.Index(last, "["); idx >= 0 {
		last = last[:idx]
	}

	if isValidIdentifier(last) {
		return last
	}
	// Fall back to first token.
	first := tokens[0]
	first = strings.TrimLeft(first, "*&$")
	if isValidIdentifier(first) {
		return first
	}
	return ""
}

// countIndent returns the number of leading whitespace characters (spaces count as 1, tabs as 4).
func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 4
		} else {
			break
		}
	}
	return count
}

// filterPythonParams removes 'self' and 'cls' from Python parameter lists.
func filterPythonParams(params []string) []string {
	var out []string
	for _, p := range params {
		if p != "self" && p != "cls" {
			out = append(out, p)
		}
	}
	return out
}

// isIdentStart returns true if the byte can start an identifier (ASCII fast path).
func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_' || b == '$'
}

// isIdentStartRune returns true if the rune can start an identifier,
// including unicode letters for languages that use non-ASCII identifiers.
func isIdentStartRune(r rune) bool {
	return unicode.IsLetter(r) || r == '_' || r == '$'
}

// isIdentCharRune returns true if the rune can appear in an identifier
// (after the first character), including unicode letters and digits.
func isIdentCharRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$'
}

// isValidIdentifier checks if a string is a valid identifier.
// Supports unicode identifiers (e.g., variable names in non-Latin scripts).
func isValidIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	runes := []rune(s)
	if !isIdentStartRune(runes[0]) {
		return false
	}
	for _, r := range runes[1:] {
		if !isIdentCharRune(r) {
			return false
		}
	}
	return true
}

// isJSKeyword returns true if the identifier is a JavaScript keyword
// that shouldn't be treated as a function name.
func isJSKeyword(s string) bool {
	switch s {
	case "if", "else", "for", "while", "do", "switch", "case", "break",
		"continue", "return", "throw", "try", "catch", "finally",
		"new", "delete", "typeof", "instanceof", "void", "in", "of",
		"with", "class", "extends", "super", "import", "export",
		"default", "yield", "await", "debugger":
		return true
	}
	return false
}

// hasNonTrivialContent returns true if the lines contain actual code (not just blanks/comments/imports).
func hasNonTrivialContent(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "package ") ||
			strings.HasPrefix(trimmed, "from ") || strings.HasPrefix(trimmed, "require(") ||
			strings.HasPrefix(trimmed, "use ") || strings.HasPrefix(trimmed, "require ") {
			continue
		}
		return true
	}
	return false
}
