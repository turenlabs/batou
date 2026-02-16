package goast

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// GoASTAnalyzer performs deep semantic analysis of Go source code using the
// go/ast package. It parses the file once and runs all AST-based checks in a
// single walk, yielding findings with precise file positions.
type GoASTAnalyzer struct{}

func init() {
	rules.Register(&GoASTAnalyzer{})
}

func (g *GoASTAnalyzer) ID() string              { return "BATOU-AST" }
func (g *GoASTAnalyzer) Name() string             { return "Go AST Security Analyzer" }
func (g *GoASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (g *GoASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangGo} }

func (g *GoASTAnalyzer) Description() string {
	return "Deep AST-based analysis of Go source code for security vulnerabilities including unsafe usage, SQL injection, command injection, unchecked errors, weak crypto, HTTP misconfiguration, defer-in-loop, and goroutine leaks."
}

// Scan parses the Go source and runs all AST-based security checks.
func (g *GoASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangGo {
		return nil
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, ctx.FilePath, ctx.Content, parser.AllErrors)
	if err != nil {
		return nil
	}

	c := &astChecker{
		fset:     fset,
		file:     file,
		filePath: ctx.FilePath,
		content:  ctx.Content,
	}

	c.collectImports()
	c.walkAST()

	return c.findings
}

// astChecker holds state for a single file analysis pass.
type astChecker struct {
	fset     *token.FileSet
	file     *ast.File
	filePath string
	content  string
	findings []rules.Finding

	// Cached import data.
	imports     map[string]string // import path -> local name (or "")
	hasMathRand bool
	hasCryptoRand bool
}

// collectImports pre-processes the import declarations.
func (c *astChecker) collectImports() {
	c.imports = make(map[string]string)
	for _, imp := range c.file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		var name string
		if imp.Name != nil {
			name = imp.Name.Name
		}
		c.imports[path] = name

		if path == "math/rand" || path == "math/rand/v2" {
			c.hasMathRand = true
		}
		if path == "crypto/rand" {
			c.hasCryptoRand = true
		}
	}
}

// walkAST performs a single-pass walk over the AST, running all checks.
func (c *astChecker) walkAST() {
	// Check import-level rules first.
	c.checkUnsafeImport()
	c.checkDeprecatedCryptoImports()

	// Walk the full AST for statement/expression-level rules.
	ast.Inspect(c.file, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			c.checkSQLStringConcat(node)
			c.checkExecCommandInjection(node)
			c.checkHTTPListenAndServe(node)
		case *ast.AssignStmt:
			c.checkUncheckedError(node)
		case *ast.ExprStmt:
			c.checkDiscardedError(node)
		case *ast.CompositeLit:
			c.checkHTTPServerMisconfig(node)
		case *ast.ForStmt:
			c.checkDeferInLoop(node)
		case *ast.RangeStmt:
			c.checkDeferInLoop(node)
		case *ast.GoStmt:
			c.checkGoroutineLeak(node)
		case *ast.SelectorExpr:
			c.checkUnsafePointerUsage(node)
		}
		return true
	})
}

// --------------------------------------------------------------------
// BATOU-AST-001: UnsafePackageUsage
// --------------------------------------------------------------------

func (c *astChecker) checkUnsafeImport() {
	for _, imp := range c.file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path == "unsafe" {
			pos := c.fset.Position(imp.Pos())
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "BATOU-AST-001",
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Unsafe package imported",
				Description:   "The 'unsafe' package bypasses Go's type safety guarantees and can lead to memory corruption vulnerabilities.",
				FilePath:      c.filePath,
				LineNumber:    pos.Line,
				Column:        pos.Column,
				MatchedText:   `import "unsafe"`,
				Suggestion:    "Avoid unsafe package unless absolutely necessary for FFI/low-level operations.",
				CWEID:         "CWE-242",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      rules.LangGo,
				Confidence:    "high",
				Tags:          []string{"unsafe", "memory-safety"},
			})
		}
	}
}

func (c *astChecker) checkUnsafePointerUsage(sel *ast.SelectorExpr) {
	if ident, ok := sel.X.(*ast.Ident); ok {
		localName := c.localNameFor("unsafe")
		if localName != "" && ident.Name == localName && sel.Sel.Name == "Pointer" {
			pos := c.fset.Position(sel.Pos())
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "BATOU-AST-001",
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Usage of unsafe.Pointer",
				Description:   "Direct use of unsafe.Pointer can cause memory corruption and undefined behavior.",
				FilePath:      c.filePath,
				LineNumber:    pos.Line,
				Column:        pos.Column,
				MatchedText:   "unsafe.Pointer",
				Suggestion:    "Avoid unsafe.Pointer unless absolutely necessary for FFI/low-level operations.",
				CWEID:         "CWE-242",
				OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
				Language:      rules.LangGo,
				Confidence:    "high",
				Tags:          []string{"unsafe", "memory-safety"},
			})
		}
	}
}

// --------------------------------------------------------------------
// BATOU-AST-002: SQLStringConcat
// --------------------------------------------------------------------

// sqlReceiverMethods lists method names on database handles that accept queries.
var sqlQueryMethods = map[string]bool{
	"Query":    true,
	"QueryRow": true,
	"Exec":     true,
	"QueryContext":    true,
	"QueryRowContext": true,
	"ExecContext":     true,
}

func (c *astChecker) checkSQLStringConcat(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if !sqlQueryMethods[sel.Sel.Name] {
		return
	}

	// Determine the query argument index: *Context methods have context as first arg.
	queryArgIdx := 0
	if strings.HasSuffix(sel.Sel.Name, "Context") {
		queryArgIdx = 1
	}
	if queryArgIdx >= len(call.Args) {
		return
	}
	queryArg := call.Args[queryArgIdx]

	if c.isStringConcat(queryArg) || c.isFmtSprintf(queryArg) {
		pos := c.fset.Position(call.Pos())
		matchText := c.nodeSource(call)
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-AST-002",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL query built with string concatenation",
			Description:   "Building SQL queries with string concatenation or fmt.Sprintf enables SQL injection attacks.",
			FilePath:      c.filePath,
			LineNumber:    pos.Line,
			Column:        pos.Column,
			MatchedText:   matchText,
			Suggestion:    "Use parameterized queries with ? or $1 placeholders: db.Query(\"SELECT * FROM users WHERE id = ?\", id)",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangGo,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection"},
		})
	}
}

// isStringConcat returns true if the expression is a binary + involving a non-literal.
func (c *astChecker) isStringConcat(expr ast.Expr) bool {
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op != token.ADD {
		return false
	}
	// At least one side must be a non-literal (variable) for it to be a real concat risk.
	_, leftLit := bin.X.(*ast.BasicLit)
	_, rightLit := bin.Y.(*ast.BasicLit)
	if leftLit && rightLit {
		return false // constant folding, not injection
	}
	return true
}

// isFmtSprintf returns true if expr is a call to fmt.Sprintf.
func (c *astChecker) isFmtSprintf(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	fmtName := c.localNameFor("fmt")
	return ident.Name == fmtName && sel.Sel.Name == "Sprintf"
}

// --------------------------------------------------------------------
// BATOU-AST-003: ExecCommandInjection
// --------------------------------------------------------------------

func (c *astChecker) checkExecCommandInjection(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}

	execName := c.localNameFor("os/exec")
	if ident.Name != execName {
		return
	}

	isCommand := sel.Sel.Name == "Command"
	isCommandContext := sel.Sel.Name == "CommandContext"
	if !isCommand && !isCommandContext {
		return
	}

	// For CommandContext, the first arg is context; shift index.
	argOffset := 0
	if isCommandContext {
		argOffset = 1
	}

	if len(call.Args) <= argOffset {
		return
	}

	// Pattern 1: exec.Command("sh"/bash, "-c", variable)
	if c.isShellExecPattern(call.Args, argOffset) {
		pos := c.fset.Position(call.Pos())
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-AST-003",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Shell command injection via exec.Command",
			Description:   "Passing a variable to sh/bash -c allows arbitrary command injection. An attacker who controls the variable can execute any system command.",
			FilePath:      c.filePath,
			LineNumber:    pos.Line,
			Column:        pos.Column,
			MatchedText:   c.nodeSource(call),
			Suggestion:    "Avoid shell invocation. Use exec.Command with explicit command and arguments: exec.Command(\"program\", \"arg1\", \"arg2\").",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangGo,
			Confidence:    "high",
			Tags:          []string{"command-injection", "injection", "rce"},
		})
		return
	}

	// Pattern 2: command name itself is a variable (not a string literal).
	cmdArg := call.Args[argOffset]
	if !c.isStringLiteral(cmdArg) {
		pos := c.fset.Position(call.Pos())
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-AST-003",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Command execution with variable command name",
			Description:   "The command name passed to exec.Command is a variable, not a string literal. If attacker-controlled, this enables arbitrary command execution.",
			FilePath:      c.filePath,
			LineNumber:    pos.Line,
			Column:        pos.Column,
			MatchedText:   c.nodeSource(call),
			Suggestion:    "Use a string literal for the command name and validate/sanitize any variable arguments.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangGo,
			Confidence:    "medium",
			Tags:          []string{"command-injection", "injection"},
		})
		return
	}

	// Pattern 3: literal command but variable arguments.
	for i := argOffset + 1; i < len(call.Args); i++ {
		if !c.isStringLiteral(call.Args[i]) {
			pos := c.fset.Position(call.Pos())
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "BATOU-AST-003",
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Command execution with variable arguments",
				Description:   "Variable arguments to exec.Command may allow command argument injection if attacker-controlled.",
				FilePath:      c.filePath,
				LineNumber:    pos.Line,
				Column:        pos.Column,
				MatchedText:   c.nodeSource(call),
				Suggestion:    "Validate and sanitize all variable arguments passed to exec.Command.",
				CWEID:         "CWE-78",
				OWASPCategory: "A03:2021-Injection",
				Language:      rules.LangGo,
				Confidence:    "low",
				Tags:          []string{"command-injection", "injection"},
			})
			return
		}
	}
}

// isShellExecPattern checks for exec.Command("sh", "-c", var) or bash equivalent.
func (c *astChecker) isShellExecPattern(args []ast.Expr, offset int) bool {
	// Need at least 3 args after offset: shell, "-c", command.
	if len(args) < offset+3 {
		return false
	}
	shell := c.stringLitValue(args[offset])
	if shell != "sh" && shell != "bash" && shell != "/bin/sh" && shell != "/bin/bash" {
		return false
	}
	flag := c.stringLitValue(args[offset+1])
	if flag != "-c" {
		return false
	}
	// The third arg (the command string) should be a variable for it to be injection.
	return !c.isStringLiteral(args[offset+2])
}

// --------------------------------------------------------------------
// BATOU-AST-004: UncheckedError
// --------------------------------------------------------------------

// securityCriticalFunctions that must have errors checked.
var securityCriticalFuncs = map[string]bool{
	"os.Open":                      true,
	"os.Create":                    true,
	"os.Remove":                    true,
	"os.RemoveAll":                 true,
	"os.Chmod":                     true,
	"os.Chown":                     true,
	"os.Mkdir":                     true,
	"os.MkdirAll":                  true,
	"http.ListenAndServe":          true,
	"http.ListenAndServeTLS":       true,
	"tls.Listen":                   true,
	"tls.Dial":                     true,
	"sql.Open":                     true,
	"bcrypt.CompareHashAndPassword": true,
	"bcrypt.GenerateFromPassword":  true,
}

func (c *astChecker) checkUncheckedError(assign *ast.AssignStmt) {
	// Look for assignments where the error value is discarded with _.
	// Pattern: _, _ = someFunc() or result, _ := securityFunc()
	if len(assign.Rhs) != 1 {
		return
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return
	}

	funcName := c.callExprName(call)
	if funcName == "" {
		return
	}

	if !c.isSecurityCriticalFunc(funcName) {
		return
	}

	// Check if any LHS identifier is blank (_).
	hasBlank := false
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "_" {
			hasBlank = true
			break
		}
	}
	if !hasBlank {
		return
	}

	// Verify the blank is in the error position (last return value typically).
	// For simplicity, any blank identifier with a security-critical call is flagged.
	pos := c.fset.Position(assign.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-004",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Unchecked error from security-critical function",
		Description:   "The error return value from " + funcName + " is discarded. Ignoring errors from security-critical functions can mask failures and lead to vulnerabilities.",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(assign),
		Suggestion:    "Always check the error return: if err != nil { return err }",
		CWEID:         "CWE-252",
		OWASPCategory: "A04:2021-Insecure Design",
		Language:      rules.LangGo,
		Confidence:    "high",
		Tags:          []string{"error-handling", "unchecked-error"},
	})
}

// checkDiscardedError detects calls to security-critical functions where the
// return value is completely ignored (expression statement, not assigned at all).
func (c *astChecker) checkDiscardedError(stmt *ast.ExprStmt) {
	call, ok := stmt.X.(*ast.CallExpr)
	if !ok {
		return
	}
	funcName := c.callExprName(call)
	if funcName == "" {
		return
	}
	if !c.isSecurityCriticalFunc(funcName) {
		return
	}

	pos := c.fset.Position(stmt.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-004",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Discarded return value from security-critical function",
		Description:   "The return value of " + funcName + " is completely discarded. This function returns an error that must be checked.",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(stmt),
		Suggestion:    "Capture and check the return value: if err := " + funcName + "(...); err != nil { ... }",
		CWEID:         "CWE-252",
		OWASPCategory: "A04:2021-Insecure Design",
		Language:      rules.LangGo,
		Confidence:    "high",
		Tags:          []string{"error-handling", "unchecked-error"},
	})
}

func (c *astChecker) isSecurityCriticalFunc(name string) bool {
	if securityCriticalFuncs[name] {
		return true
	}
	lower := strings.ToLower(name)
	// Check for functions with "auth" or "crypt" in the name.
	parts := strings.Split(lower, ".")
	funcPart := parts[len(parts)-1]
	return strings.Contains(funcPart, "auth") || strings.Contains(funcPart, "crypt")
}

// --------------------------------------------------------------------
// BATOU-AST-005: DeprecatedCrypto
// --------------------------------------------------------------------

var weakCryptoPackages = map[string]string{
	"crypto/des": "DES is a weak cipher with a 56-bit key, easily brute-forced.",
	"crypto/rc4": "RC4 has known biases and is considered broken.",
	"crypto/md5": "MD5 is cryptographically broken and should not be used for security purposes.",
	"crypto/sha1": "SHA-1 is vulnerable to collision attacks and should not be used for security.",
}

func (c *astChecker) checkDeprecatedCryptoImports() {
	for _, imp := range c.file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if reason, ok := weakCryptoPackages[path]; ok {
			pos := c.fset.Position(imp.Pos())
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "BATOU-AST-005",
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Weak/deprecated cryptographic package imported",
				Description:   "Import of " + path + ": " + reason,
				FilePath:      c.filePath,
				LineNumber:    pos.Line,
				Column:        pos.Column,
				MatchedText:   imp.Path.Value,
				Suggestion:    "Use crypto/aes for encryption, crypto/sha256 or crypto/sha512 for hashing, and golang.org/x/crypto for modern algorithms.",
				CWEID:         "CWE-327",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      rules.LangGo,
				Confidence:    "high",
				Tags:          []string{"crypto", "weak-cipher"},
			})
		}
	}

	// Check for math/rand without crypto/rand.
	if c.hasMathRand && !c.hasCryptoRand {
		// Find the math/rand import for position.
		for _, imp := range c.file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "math/rand" || path == "math/rand/v2" {
				pos := c.fset.Position(imp.Pos())
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "BATOU-AST-005",
					Severity:      rules.High,
					SeverityLabel: rules.High.String(),
					Title:         "Non-cryptographic random number generator without crypto/rand",
					Description:   "math/rand is imported without crypto/rand. If random values are used for security purposes (tokens, keys, nonces), math/rand is predictable and insecure.",
					FilePath:      c.filePath,
					LineNumber:    pos.Line,
					Column:        pos.Column,
					MatchedText:   imp.Path.Value,
					Suggestion:    "Use crypto/rand for security-sensitive random number generation.",
					CWEID:         "CWE-338",
					OWASPCategory: "A02:2021-Cryptographic Failures",
					Language:      rules.LangGo,
					Confidence:    "medium",
					Tags:          []string{"crypto", "weak-random"},
				})
			}
		}
	}
}

// --------------------------------------------------------------------
// BATOU-AST-006: HttpServerMisconfig
// --------------------------------------------------------------------

func (c *astChecker) checkHTTPListenAndServe(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	httpName := c.localNameFor("net/http")
	if ident.Name != httpName {
		return
	}
	if sel.Sel.Name != "ListenAndServe" {
		return
	}

	pos := c.fset.Position(call.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-006",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "HTTP server without TLS",
		Description:   "http.ListenAndServe starts an unencrypted HTTP server. All traffic including credentials and session tokens will be sent in plaintext.",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(call),
		Suggestion:    "Use http.ListenAndServeTLS with a valid TLS certificate, or use a reverse proxy that terminates TLS.",
		CWEID:         "CWE-319",
		OWASPCategory: "A02:2021-Cryptographic Failures",
		Language:      rules.LangGo,
		Confidence:    "medium",
		Tags:          []string{"http", "tls", "cleartext"},
	})
}

func (c *astChecker) checkHTTPServerMisconfig(lit *ast.CompositeLit) {
	// Check if this is an http.Server{} literal.
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}
	httpName := c.localNameFor("net/http")
	if ident.Name != httpName || sel.Sel.Name != "Server" {
		return
	}

	// Check which timeout fields are set.
	hasReadTimeout := false
	hasWriteTimeout := false
	hasIdleTimeout := false
	hasReadHeaderTimeout := false

	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "ReadTimeout":
			hasReadTimeout = true
		case "WriteTimeout":
			hasWriteTimeout = true
		case "IdleTimeout":
			hasIdleTimeout = true
		case "ReadHeaderTimeout":
			hasReadHeaderTimeout = true
		}
	}

	var missing []string
	if !hasReadTimeout && !hasReadHeaderTimeout {
		missing = append(missing, "ReadTimeout (or ReadHeaderTimeout)")
	}
	if !hasWriteTimeout {
		missing = append(missing, "WriteTimeout")
	}
	if !hasIdleTimeout {
		missing = append(missing, "IdleTimeout")
	}

	if len(missing) > 0 {
		pos := c.fset.Position(lit.Pos())
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-AST-006",
			Severity:      rules.High,
			SeverityLabel: rules.High.String(),
			Title:         "HTTP server missing timeout configuration",
			Description:   "http.Server is missing timeout fields: " + strings.Join(missing, ", ") + ". Without timeouts, the server is vulnerable to slowloris and other denial-of-service attacks.",
			FilePath:      c.filePath,
			LineNumber:    pos.Line,
			Column:        pos.Column,
			MatchedText:   c.nodeSource(lit),
			Suggestion:    "Set ReadTimeout, WriteTimeout, and IdleTimeout on http.Server: &http.Server{ReadTimeout: 10*time.Second, WriteTimeout: 10*time.Second, IdleTimeout: 120*time.Second}",
			CWEID:         "CWE-400",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      rules.LangGo,
			Confidence:    "high",
			Tags:          []string{"http", "dos", "timeout"},
		})
	}
}

// --------------------------------------------------------------------
// BATOU-AST-007: DeferInLoop
// --------------------------------------------------------------------

func (c *astChecker) checkDeferInLoop(loopNode ast.Node) {
	// Walk the loop body looking for defer statements.
	// We do NOT recurse into nested function literals (closures) since
	// defer inside a closure inside a loop is fine.
	var body *ast.BlockStmt
	switch n := loopNode.(type) {
	case *ast.ForStmt:
		body = n.Body
	case *ast.RangeStmt:
		body = n.Body
	default:
		return
	}
	if body == nil {
		return
	}

	c.findDeferInBlock(body)
}

// findDeferInBlock searches a block for defer statements, not descending
// into function literals (which create their own scope).
func (c *astChecker) findDeferInBlock(block *ast.BlockStmt) {
	for _, stmt := range block.List {
		c.findDeferInStmt(stmt)
	}
}

func (c *astChecker) findDeferInStmt(stmt ast.Stmt) {
	switch s := stmt.(type) {
	case *ast.DeferStmt:
		pos := c.fset.Position(s.Pos())
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-AST-007",
			Severity:      rules.Medium,
			SeverityLabel: rules.Medium.String(),
			Title:         "Defer statement inside loop",
			Description:   "Defer inside a loop does not execute until the function returns, not at the end of each iteration. This causes resource leaks (unclosed files, connections, locks).",
			FilePath:      c.filePath,
			LineNumber:    pos.Line,
			Column:        pos.Column,
			MatchedText:   c.nodeSource(s),
			Suggestion:    "Move the deferred operation into an immediately-invoked function literal, or manually close/release the resource before the next iteration.",
			CWEID:         "CWE-775",
			OWASPCategory: "A04:2021-Insecure Design",
			Language:      rules.LangGo,
			Confidence:    "high",
			Tags:          []string{"resource-leak", "defer"},
		})
	case *ast.BlockStmt:
		c.findDeferInBlock(s)
	case *ast.IfStmt:
		if s.Body != nil {
			c.findDeferInBlock(s.Body)
		}
		if s.Else != nil {
			c.findDeferInStmt(s.Else)
		}
	case *ast.SwitchStmt:
		if s.Body != nil {
			c.findDeferInBlock(s.Body)
		}
	case *ast.TypeSwitchStmt:
		if s.Body != nil {
			c.findDeferInBlock(s.Body)
		}
	case *ast.SelectStmt:
		if s.Body != nil {
			c.findDeferInBlock(s.Body)
		}
	case *ast.CaseClause:
		for _, st := range s.Body {
			c.findDeferInStmt(st)
		}
	case *ast.CommClause:
		for _, st := range s.Body {
			c.findDeferInStmt(st)
		}
	case *ast.LabeledStmt:
		c.findDeferInStmt(s.Stmt)
	// Do NOT recurse into ast.FuncLit - defer in a closure is fine.
	}
}

// --------------------------------------------------------------------
// BATOU-AST-008: GoroutineLeak
// --------------------------------------------------------------------

func (c *astChecker) checkGoroutineLeak(goStmt *ast.GoStmt) {
	// Check if the goroutine function accepts context.Context.
	funcLit, ok := goStmt.Call.Fun.(*ast.FuncLit)
	if !ok {
		// go someFunc() - harder to analyze without type info. Flag if it's
		// a selector or ident call without context argument.
		c.checkGoroutineCallLeak(goStmt)
		return
	}

	// go func() { ... }() - check if context.Context is a parameter.
	hasContext := false
	if funcLit.Type.Params != nil {
		for _, field := range funcLit.Type.Params.List {
			if c.isContextType(field.Type) {
				hasContext = true
				break
			}
		}
	}

	if !hasContext {
		// Also check if a context variable is captured from outer scope.
		// We can check if context is used inside the body as a heuristic.
		if c.usesContextInBody(funcLit.Body) {
			return // Context is captured from outer scope, likely fine.
		}

		pos := c.fset.Position(goStmt.Pos())
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-AST-008",
			Severity:      rules.Medium,
			SeverityLabel: rules.Medium.String(),
			Title:         "Goroutine launched without context for cancellation",
			Description:   "A goroutine is launched with go func() without a context.Context parameter or captured context variable. Without cancellation support, this goroutine may leak if the parent operation completes or fails.",
			FilePath:      c.filePath,
			LineNumber:    pos.Line,
			Column:        pos.Column,
			MatchedText:   c.nodeSource(goStmt),
			Suggestion:    "Pass a context.Context to the goroutine and use it for cancellation: go func(ctx context.Context) { ... }(ctx)",
			CWEID:         "CWE-404",
			OWASPCategory: "A04:2021-Insecure Design",
			Language:      rules.LangGo,
			Confidence:    "medium",
			Tags:          []string{"goroutine-leak", "concurrency"},
		})
	}
}

func (c *astChecker) checkGoroutineCallLeak(goStmt *ast.GoStmt) {
	// For go someFunc(args...) - check if any argument looks like a context.
	for _, arg := range goStmt.Call.Args {
		if c.isContextType(arg) {
			return
		}
		// Check if argument is a variable named "ctx" (common convention).
		if ident, ok := arg.(*ast.Ident); ok && ident.Name == "ctx" {
			return
		}
	}

	pos := c.fset.Position(goStmt.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-008",
		Severity:      rules.Medium,
		SeverityLabel: rules.Medium.String(),
		Title:         "Goroutine launched without context for cancellation",
		Description:   "A goroutine is launched without passing a context.Context. Without cancellation support, this goroutine may leak.",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(goStmt),
		Suggestion:    "Pass a context.Context to the goroutine and select on ctx.Done() to support cancellation.",
		CWEID:         "CWE-404",
		OWASPCategory: "A04:2021-Insecure Design",
		Language:      rules.LangGo,
		Confidence:    "low",
		Tags:          []string{"goroutine-leak", "concurrency"},
	})
}

// isContextType checks if an expression refers to context.Context.
func (c *astChecker) isContextType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "context" && sel.Sel.Name == "Context"
}

// usesContextInBody checks if a function body references a context variable.
func (c *astChecker) usesContextInBody(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.Ident:
			if node.Name == "ctx" {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if c.isContextType(node) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// --------------------------------------------------------------------
// Helper functions
// --------------------------------------------------------------------

// localNameFor returns the local name used for an import path. If the import
// has no alias, it returns the last path element. Returns empty string if the
// package is not imported.
func (c *astChecker) localNameFor(path string) string {
	alias, ok := c.imports[path]
	if !ok {
		return ""
	}
	if alias != "" && alias != "." && alias != "_" {
		return alias
	}
	// Default: last element of the import path.
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

// callExprName returns a dotted name for a call expression, e.g. "os.Open"
// or "bcrypt.CompareHashAndPassword". Returns "" for complex expressions.
func (c *astChecker) callExprName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := fun.X.(*ast.Ident); ok {
			return ident.Name + "." + fun.Sel.Name
		}
	case *ast.Ident:
		return fun.Name
	}
	return ""
}

// isStringLiteral returns true if the expression is a string literal.
func (c *astChecker) isStringLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// stringLitValue returns the unquoted value of a string literal, or "".
func (c *astChecker) stringLitValue(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	return strings.Trim(lit.Value, `"` + "`")
}

// nodeSource extracts the source text for an AST node from the original content.
// Returns a truncated version for display if the source is too long.
func (c *astChecker) nodeSource(node ast.Node) string {
	start := c.fset.Position(node.Pos())
	end := c.fset.Position(node.End())

	startOff := start.Offset
	endOff := end.Offset
	if startOff < 0 || endOff < 0 || startOff >= len(c.content) || endOff > len(c.content) {
		return ""
	}

	src := c.content[startOff:endOff]

	// Truncate for display.
	if len(src) > 200 {
		src = src[:200] + "..."
	}

	// Collapse to single line for findings.
	src = strings.ReplaceAll(src, "\n", " ")
	src = strings.ReplaceAll(src, "\t", " ")
	return src
}
