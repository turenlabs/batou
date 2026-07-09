package goast

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
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
	// batou:ignore BATOU-AST-004 -- void method, nothing to check; remove once isSecurityCriticalFunc fuzzy-match tightening ships
	c.checkDeprecatedCryptoImports()
	c.checkDebugAndCGIImports()

	// Walk the full AST for statement/expression-level rules. Track the
	// enclosing function name so AST-008 can suppress goroutines launched
	// from lifecycle/shutdown handlers (where one-shot fire-and-forget is
	// intentional).
	var enclosingFunc []string // stack of enclosing function names
	push := func(name string) { enclosingFunc = append(enclosingFunc, name) }
	pop := func() {
		if len(enclosingFunc) > 0 {
			enclosingFunc = enclosingFunc[:len(enclosingFunc)-1]
		}
	}
	current := func() string {
		if len(enclosingFunc) == 0 {
			return ""
		}
		return enclosingFunc[len(enclosingFunc)-1]
	}

	ast.Inspect(c.file, func(n ast.Node) bool {
		if n == nil {
			// pop on the way back up (Inspect calls f(nil) at the end of a
			// subtree when the previous call returned true).
			pop()
			return false
		}
		// Push the enclosing-function name for FuncDecl/FuncLit and pop
		// when we leave the subtree. We use ast.Inspect's nil-callback
		// convention to detect ascent. To make push/pop balanced we push
		// for every node and pop on every nil — push a placeholder for
		// non-func nodes so the stack stays in sync.
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name != nil {
				push(node.Name.Name)
			} else {
				push("")
			}
		case *ast.FuncLit:
			// Function literals inherit the enclosing func name; keep the
			// top of stack stable but push a duplicate so pop balances.
			push(current())
		default:
			push(current())
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			c.checkSQLStringConcat(node)
			c.checkExecCommandInjection(node)
			c.checkHTTPListenAndServe(node)
			c.checkDecompressionBomb(node)
			c.checkWeakCryptoAndFileServer(node)
		case *ast.AssignStmt:
			c.checkUncheckedError(node)
		case *ast.ExprStmt:
			c.checkDiscardedError(node)
		case *ast.CompositeLit:
			c.checkHTTPServerMisconfig(node)
			c.checkTLSConfigMisconfig(node)
			c.checkSSHInsecureHostKey(node)
			c.checkInsecureCookie(node)
			c.checkReverseProxyDirector(node)
			c.checkServerAddrAllInterfaces(node)
		case *ast.ForStmt:
			c.checkDeferInLoop(node)
		case *ast.RangeStmt:
			c.checkDeferInLoop(node)
		case *ast.GoStmt:
			c.checkGoroutineLeakIn(node, current())
		case *ast.SelectorExpr:
			c.checkUnsafePointerUsage(node)
		}
		return true
	})
}

// isLifecycleFuncName returns true when name looks like a lifecycle /
// shutdown handler. Goroutines launched from these functions are typically
// one-shot fire-and-forget (run a single shutdown hook, kick a hammer
// timer, etc.) and don't need a context for cancellation.
func isLifecycleFuncName(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	prefixes := []string{
		"shutdown", "doshutdown", "onshutdown",
		"atshutdown", "runatshutdown",
		"stop", "dostop", "onstop", "cancel", "docancel", "oncancel",
		"cleanup", "docleanup", "oncleanup",
		"finalize", "dofinalize",
		"close", "doclose", "onclose",
		"terminate", "doterminate",
	}
	for _, p := range prefixes {
		if lower == p || strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
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
		// DDL with identifier interpolation is the standard Go pattern —
		// SQL doesn't let you parameterize table/column names, so migration
		// and admin code uses Sprintf for the identifier and ? for the
		// values. Without taint, we can't tell whether the interpolated
		// identifier is user-controlled. Demote to Medium so this stops
		// dominating Critical findings on schema-management code (gitea
		// had 60+ Critical hits in models/db/*); a real exploitable case
		// also surfaces via the taint layer.
		severity := rules.Critical
		conf := "high"
		if isLikelyDDLQuery(c.staticStringPart(queryArg)) {
			severity = rules.Medium
			conf = "medium"
		}
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-AST-002",
			Severity:      severity,
			SeverityLabel: severity.String(),
			Title:         "SQL query built with string concatenation",
			Description:   "Building SQL queries with string concatenation or fmt.Sprintf enables SQL injection attacks. DDL queries (CREATE/ALTER/DROP/MERGE) commonly interpolate identifiers because SQL doesn't allow parameterizing them — confirm the interpolated parts come from internal Go constants, not user input.",
			FilePath:      c.filePath,
			LineNumber:    pos.Line,
			Column:        pos.Column,
			MatchedText:   matchText,
			Suggestion:    "Use parameterized queries with ? or $1 placeholders: db.Query(\"SELECT * FROM users WHERE id = ?\", id). For DDL identifier interpolation, ensure the identifier comes from an allowlisted Go constant, not request input.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangGo,
			Confidence:    conf,
			Tags:          []string{"sql-injection", "injection"},
		})
	}
}

// isGoTestOrMigrationPath returns true if the file path is a Go test file
// or a migration file. Both routinely discard errors on cleanup/setup
// paths and shouldn't be flagged for unchecked errors the same way
// production code is.
func isGoTestOrMigrationPath(path string) bool {
	low := strings.ToLower(path)
	return strings.HasSuffix(low, "_test.go") ||
		strings.Contains(low, "/migrations/") ||
		strings.Contains(low, "/testutil/") ||
		strings.Contains(low, "/testdb")
}

// isNonSecurityCryptoPath returns true if the file path strongly suggests
// the file uses md5/sha1 for non-security purposes — Git protocol,
// avatars, haveibeenpwned, package fingerprints, etc.
func isNonSecurityCryptoPath(path string) bool {
	low := strings.ToLower(path)
	for _, marker := range []string{
		"/git/", "/avatar", "/gravatar", "/etag", "/cache_key",
		"/fingerprint", "/hibp/", "/pwn/", "/object_format",
		"haveibeenpwned",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// isDaemonNamedCall returns true if the called function's name starts with
// a daemon-style verb. Used to suppress AST-008 (goroutine leak) findings
// on patterns like `go serveX()`, `go startWorker()`, `go runQueue()` —
// these are almost always intentional process-lifetime workers.
func isDaemonNamedCall(fun ast.Expr) bool {
	var name string
	switch fn := fun.(type) {
	case *ast.Ident:
		name = fn.Name
	case *ast.SelectorExpr:
		name = fn.Sel.Name
	default:
		return false
	}
	lower := strings.ToLower(name)
	for _, prefix := range []string{"serve", "start", "run", "listen", "monitor", "watch", "process", "handle", "consume", "poll", "loop"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// isLikelyDDLQuery returns true if the static string portion of the query
// contains DDL keywords OR has a format placeholder in an identifier slot
// (table/column/database name). These are the operations that commonly
// need identifier interpolation in Go because SQL doesn't let you
// parameterize identifiers — the value-bearing positions still use ? / $N.
func isLikelyDDLQuery(s string) bool {
	if s == "" {
		return false
	}
	upper := strings.ToUpper(s)

	// Pure DDL / admin keywords — identifier interpolation is standard.
	// SQL DDL forbids parameterising names; database-management code uses
	// Sprintf for the identifier and ? for the values. The list also covers
	// engine-specific session/sequence ops (Postgres SETVAL / ALTER SEQUENCE,
	// MSSQL SET IDENTITY_INSERT) which take an identifier in the same slot
	// as DDL and are routinely emitted by ORM internals.
	for _, kw := range []string{
		"ALTER ", "CREATE ", "DROP ", "RENAME ", "TRUNCATE ",
		"MERGE INTO", "DELETE FROM ",
		// Postgres sequence administration.
		"ALTER SEQUENCE", "SETVAL(", "CURRVAL(", "NEXTVAL(",
		// MSSQL session-mode identifier-targeted commands.
		"SET IDENTITY_INSERT", "DBCC ", "EXEC SP_",
		// Generic admin verbs that always target an identifier.
		"GRANT ", "REVOKE ", "VACUUM ", "ANALYZE ", "REINDEX ",
		"COMMENT ON",
	} {
		if strings.Contains(upper, kw) {
			return true
		}
	}

	// DML with a placeholder in an identifier slot. xorm/ent-style code
	// frequently does `UPDATE %s SET col=?`, `INSERT INTO %s VALUES (?,?)`,
	// or `SELECT * FROM %s WHERE id=?` — the %s is the table name from a
	// typed Go constant, not user input. Detect "<KEYWORD> %s" patterns
	// where the placeholder follows an identifier-bearing keyword and the
	// statement also has value placeholders (? or $N), which is the
	// telltale signature that values *are* being parameterized.
	identKeywords := []string{
		"INTO %S", "INTO `%S`", "INTO \"%S\"",
		"FROM %S", "FROM `%S`", "FROM \"%S\"",
		"UPDATE %S", "UPDATE `%S`", "UPDATE \"%S\"",
		"JOIN %S",
		"TABLE %S",
	}
	hasIdentPlaceholder := false
	for _, kw := range identKeywords {
		if strings.Contains(upper, kw) {
			hasIdentPlaceholder = true
			break
		}
	}
	if hasIdentPlaceholder {
		// Also require value placeholders (? or $N) — that proves the
		// developer knows about parameterization and is using %s only for
		// the identifier. If there's no value placeholder, this might be a
		// fully-interpolated query, which is a real injection sink.
		if strings.Contains(s, "?") || hasPostgresPlaceholder(s) {
			return true
		}
	}
	return false
}

// hasPostgresPlaceholder reports whether the string contains a $N
// PostgreSQL-style parameter placeholder (e.g. $1, $2).
func hasPostgresPlaceholder(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '$' && s[i+1] >= '1' && s[i+1] <= '9' {
			return true
		}
	}
	return false
}

// staticStringPart returns the literal-string portion of a query argument:
// for `fmt.Sprintf("...", a, b)` the format string; for `"..." + x` the
// concatenated literals. Returns "" when none can be extracted.
//
// Recursively unwraps the format-arg side so that
//
//	fmt.Sprintf("INSERT INTO %s " + "VALUES (?,?)", t, ...)
//
// yields the joined static string (its identifier-slot heuristic can then
// see both the keyword and the `?` placeholder).
func (c *astChecker) staticStringPart(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.CallExpr:
		// fmt.Sprintf — first arg is the format string. Recurse into it
		// so concat/literal/parenthesized forms are all handled.
		if len(e.Args) > 0 {
			return c.staticStringPart(e.Args[0])
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return c.staticStringPart(e.X) + c.staticStringPart(e.Y)
		}
	case *ast.ParenExpr:
		return c.staticStringPart(e.X)
	case *ast.BasicLit:
		return strings.Trim(e.Value, "`\"")
	}
	return ""
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
	// Skip test files and migrations — both routinely discard errors on
	// cleanup/setup paths (test fixtures, schema-version state) which are
	// not security-critical the same way production code is.
	if isGoTestOrMigrationPath(c.filePath) {
		return
	}

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

	// Check if the error return value is discarded with _.
	// In Go, the error is conventionally the last return value.
	// Pattern to FLAG:   _, _ = someFunc()  (all blanks, error discarded)
	//                    result, _ := securityFunc()  (error position is blank)
	// Pattern to SKIP:   _, err := someFunc()  (first value discarded, error captured)
	//                    _, _, err := someFunc()  (multiple values discarded, error captured)
	if len(assign.Lhs) == 0 {
		return
	}

	// Check the last LHS position (error position). If it's NOT blank,
	// the error IS being captured — this is safe even if other values use _.
	lastLhs := assign.Lhs[len(assign.Lhs)-1]
	if ident, ok := lastLhs.(*ast.Ident); ok && ident.Name != "_" {
		// Error is captured (e.g., _, err := f()). Not a finding.
		return
	}

	// Also ensure at least one LHS is blank (handles edge case of single return).
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
	// Fuzzy match for names containing "auth" or "crypt" is too broad when
	// applied to arbitrary calls — a helper method like
	// c.checkDeprecatedCryptoImports() shares the "crypt" substring but is
	// not security-critical. Restrict fuzzy matching to calls whose qualifier
	// matches an imported package, so bcrypt.Compare still matches but a
	// method on a local struct does not.
	parts := strings.Split(name, ".")
	if len(parts) != 2 {
		return false
	}
	if !c.isImportedPackage(parts[0]) {
		return false
	}
	funcPart := strings.ToLower(parts[1])
	return strings.Contains(funcPart, "auth") || strings.Contains(funcPart, "crypt")
}

// isImportedPackage returns true if name matches the (possibly aliased) name
// of a package imported by the file under analysis.
func (c *astChecker) isImportedPackage(name string) bool {
	if c.file == nil {
		return false
	}
	for _, imp := range c.file.Imports {
		if imp.Name != nil {
			if imp.Name.Name == name {
				return true
			}
			continue
		}
		path := strings.Trim(imp.Path.Value, `"`)
		pkg := path
		if idx := strings.LastIndex(path, "/"); idx >= 0 {
			pkg = path[idx+1:]
		}
		if pkg == name {
			return true
		}
	}
	return false
}

// hasRawHashUse reports whether the file calls the named hash package
// (e.g. "sha1" or "md5") in a way that produces a raw digest:
//
//	pkg.Sum(...)                              // one-shot digest
//	pkg.New().Write(...).Sum(...)             // streaming digest
//
// It does NOT count usage as the inner constructor of hmac.New
// (e.g. hmac.New(sha1.New, key)) because RFC 6151 considers HMAC-SHA1
// and HMAC-MD5 acceptable MAC constructions even when the underlying
// hash is broken for collision resistance.
//
// The walk treats every CallExpr.Fun and any non-call SelectorExpr that
// references `pkg.New` as a use UNLESS it is the first argument of an
// hmac.New (or hmac.NewEqual) call. The first arg of hmac.New is the
// hash constructor (a `func() hash.Hash`).
func (c *astChecker) hasRawHashUse(pkg string) bool {
	if c.file == nil {
		return false
	}

	// hmacArgs collects the *ast.Expr nodes that appear as the constructor
	// arg of an hmac.New(...) call so the walker can skip them.
	hmacArgs := map[ast.Expr]struct{}{}
	ast.Inspect(c.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name == "hmac" && (sel.Sel.Name == "New" || sel.Sel.Name == "NewEqual") && len(call.Args) > 0 {
			hmacArgs[call.Args[0]] = struct{}{}
		}
		return true
	})

	rawUse := false
	ast.Inspect(c.file, func(n ast.Node) bool {
		if rawUse {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name != pkg {
			return true
		}
		// Sum / Sum224 / Sum256 / etc — raw digest.
		if strings.HasPrefix(sel.Sel.Name, "Sum") {
			rawUse = true
			return false
		}
		// New / New224 / etc — could be HMAC (skip) or raw (flag).
		if strings.HasPrefix(sel.Sel.Name, "New") {
			if _, skip := hmacArgs[ast.Expr(sel)]; skip {
				return true
			}
			rawUse = true
			return false
		}
		return true
	})
	return rawUse
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
	// Skip when the file path indicates a non-security use of weak hashes:
	// Git protocol (sha1 for object IDs), avatars (md5 fingerprints),
	// haveibeenpwned API (sha1 hashprefix). CRY-001 already flags actual
	// uses with full context — flagging the import here is just noise.
	if isNonSecurityCryptoPath(c.filePath) {
		return
	}

	for _, imp := range c.file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		reason, ok := weakCryptoPackages[path]
		if !ok {
			continue
		}
		// For crypto/sha1 and crypto/md5, distinguish between RAW-hash use
		// (sha1.Sum, sha1.New().Write().Sum, md5.Sum, md5.New().Write...) —
		// which is the broken pattern — and HMAC use (hmac.New(sha1.New, ...)
		// or hmac.New(md5.New, ...)) which is still secure per RFC 6151.
		// If the file only ever passes sha1.New / md5.New into hmac.New
		// (never calls .Sum directly), suppress the import-level finding.
		if path == "crypto/sha1" || path == "crypto/md5" {
			pkg := "sha1"
			if path == "crypto/md5" {
				pkg = "md5"
			}
			if !c.hasRawHashUse(pkg) {
				continue
			}
		}
		pos := c.fset.Position(imp.Pos())
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-AST-005",
			Severity:      rules.Medium,
			SeverityLabel: rules.Medium.String(),
			Title:         "Weak/deprecated cryptographic package imported",
			Description:   "Import of " + path + ": " + reason + " (CRY-001 will flag actual security-critical uses; importing alone is informational).",
			FilePath:      c.filePath,
			LineNumber:    pos.Line,
			Column:        pos.Column,
			MatchedText:   imp.Path.Value,
			Suggestion:    "Use crypto/aes for encryption, crypto/sha256 or crypto/sha512 for hashing, and golang.org/x/crypto for modern algorithms.",
			CWEID:         "CWE-327",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Language:      rules.LangGo,
			Confidence:    "low",
			Tags:          []string{"crypto", "weak-cipher"},
		})
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

	// The threat this rule guards against (CWE-400 / Slowloris) is mitigated
	// once ANY request-phase timeout bounds how long a connection can tie up
	// the server. ReadHeaderTimeout is the specific, Go-documented Slowloris
	// defense; ReadTimeout subsumes it; WriteTimeout/IdleTimeout cap the other
	// phases. Real services routinely set just one or two of these on purpose
	// (e.g. ReadHeaderTimeout against Slowloris while a streaming body handler
	// deliberately omits WriteTimeout). Demanding all three flooded well-
	// defended servers with false positives (Grafana sets ReadHeaderTimeout/
	// ReadTimeout). Only the genuinely unbounded server — no timeout field set
	// at all — is the real, exploitable misconfiguration worth flagging.
	hasAnyTimeout := hasReadTimeout || hasReadHeaderTimeout || hasWriteTimeout || hasIdleTimeout

	var missing []string
	if !hasAnyTimeout {
		missing = append(missing, "ReadTimeout (or ReadHeaderTimeout)", "WriteTimeout", "IdleTimeout")
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
// BATOU-AST-009: Insecure TLS configuration (CWE-295 / CWE-327)
// --------------------------------------------------------------------

// checkTLSConfigMisconfig flags a crypto/tls.Config struct literal that
// disables certificate verification (InsecureSkipVerify: true) or pins a
// downgraded minimum protocol version (MinVersion: tls.VersionTLS10/11).
//
// This is a constant-misconfiguration with zero source/sink ambiguity, so
// it is an AST detector (blocks) rather than a taint sink. The regex rule in
// crypto_ext.go fires the same shapes only as a low-confidence HINT; resolving
// the literal's static type to crypto/tls.Config here removes the regex FP
// where `InsecureSkipVerify` appears as a field name on an unrelated config
// struct, in a comment, or as `: false` (verification ENABLED). It also only
// fires when the value is the literal `true` ident — a value computed from a
// variable (e.g. `InsecureSkipVerify: cfg.SkipTLSVerify`) is out of scope for
// a constant-misconfig rule, so operator-configurable transports do not FP.
func (c *astChecker) checkTLSConfigMisconfig(lit *ast.CompositeLit) {
	if !c.litTypeIs(lit, "crypto/tls", "Config") {
		return
	}

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
		case "InsecureSkipVerify":
			// Only `: true` (a literal true ident) is the misconfiguration.
			// `: false` means verification is ENABLED; a variable means the
			// value is dynamic and out of scope for a constant-misconfig rule.
			if id, ok := kv.Value.(*ast.Ident); ok && id.Name == "true" {
				c.addTLSFinding(kv, "InsecureSkipVerify: true disables TLS certificate verification, allowing man-in-the-middle attacks.",
					"Remove InsecureSkipVerify (or set it to false). If you must pin a self-signed cert, set RootCAs/VerifyPeerCertificate instead.",
					"CWE-295")
			}
		case "MinVersion":
			if c.isOldTLSVersion(kv.Value) {
				c.addTLSFinding(kv, "TLS MinVersion is set to a deprecated protocol (TLS 1.0/1.1) which has known weaknesses (BEAST, POODLE).",
					"Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13.",
					"CWE-327")
			}
		}
	}
}

// isOldTLSVersion returns true when the expression is a TLS 1.0 / 1.1 version
// constant — either `tls.VersionTLS10`/`tls.VersionTLS11` or the raw wire
// values 0x0301 (769) / 0x0302 (770).
func (c *astChecker) isOldTLSVersion(expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.SelectorExpr:
		if ident, ok := v.X.(*ast.Ident); ok {
			tlsName := c.localNameFor("crypto/tls")
			if ident.Name == tlsName && (v.Sel.Name == "VersionTLS10" || v.Sel.Name == "VersionTLS11") {
				return true
			}
		}
	case *ast.BasicLit:
		if v.Kind == token.INT {
			// TLS 1.0 = 0x0301 (769), TLS 1.1 = 0x0302 (770).
			return v.Value == "0x0301" || v.Value == "0x0302" || v.Value == "769" || v.Value == "770"
		}
	}
	return false
}

func (c *astChecker) addTLSFinding(node ast.Node, desc, suggestion, cwe string) {
	pos := c.fset.Position(node.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-009",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Insecure TLS configuration",
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(node),
		Suggestion:    suggestion,
		CWEID:         cwe,
		OWASPCategory: "A02:2021-Cryptographic Failures",
		Language:      rules.LangGo,
		Confidence:    "high",
		Tags:          []string{"tls", "crypto", "mitm"},
	})
}

// --------------------------------------------------------------------
// BATOU-AST-010: SSH InsecureIgnoreHostKey / missing HostKeyCallback (CWE-322)
// --------------------------------------------------------------------

// checkSSHInsecureHostKey flags an golang.org/x/crypto/ssh.ClientConfig struct
// literal whose HostKeyCallback accepts any host key — either by assigning
// ssh.InsecureIgnoreHostKey() or by omitting the field on an otherwise
// populated config. Accepting any host key defeats the protection against
// man-in-the-middle attacks (CWE-322: key exchange without entity
// authentication).
//
// Anchored on the exact package-qualified type ssh.ClientConfig + field
// HostKeyCallback, so it cannot match an unrelated HostKeyCallback field on a
// different type.
func (c *astChecker) checkSSHInsecureHostKey(lit *ast.CompositeLit) {
	if !c.litTypeIs(lit, "golang.org/x/crypto/ssh", "ClientConfig") {
		return
	}
	sshName := c.localNameFor("golang.org/x/crypto/ssh")

	var hostKeyVal ast.Expr
	hasHostKeyField := false
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "HostKeyCallback" {
			continue
		}
		hasHostKeyField = true
		hostKeyVal = kv.Value
	}

	// Field present and assigned ssh.InsecureIgnoreHostKey(...) — the
	// unambiguous accept-any-host-key misconfiguration.
	if hasHostKeyField {
		if call, ok := hostKeyVal.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok &&
					ident.Name == sshName && sel.Sel.Name == "InsecureIgnoreHostKey" {
					c.addSSHFinding(call, "ssh.ClientConfig uses InsecureIgnoreHostKey() — the SSH host key is accepted unconditionally, enabling man-in-the-middle attacks.",
						"Use ssh.FixedHostKey(knownKey) or knownhosts.New(...) as the HostKeyCallback so unexpected host keys are rejected.")
					return
				}
			}
		}
		return
	}

	// Field absent — flag the literal ONLY when it is a real inline config
	// (at least one keyed field is set, e.g. User/Auth), not a bare
	// zero-value `ssh.ClientConfig{}` placeholder that is populated later via
	// field assignment or only used as a type reference. This avoids a false
	// positive on partial-initialization patterns while still catching the
	// common `&ssh.ClientConfig{User: ..., Auth: ...}` that simply forgot to
	// set HostKeyCallback (no host-key verification at all).
	if !c.litHasKeyedFields(lit) {
		return
	}
	c.addSSHFinding(lit, "ssh.ClientConfig has no HostKeyCallback set — the SSH host key is not verified, enabling man-in-the-middle attacks.",
		"Set HostKeyCallback to ssh.FixedHostKey(knownKey) or knownhosts.New(...) so unexpected host keys are rejected.")
}

// litHasKeyedFields reports whether a composite literal has at least one
// keyed (Field: value) element. A bare `T{}` zero-value literal returns false.
func (c *astChecker) litHasKeyedFields(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		if _, ok := elt.(*ast.KeyValueExpr); ok {
			return true
		}
	}
	return false
}

func (c *astChecker) addSSHFinding(node ast.Node, desc, suggestion string) {
	pos := c.fset.Position(node.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-010",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Insecure SSH host key verification",
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(node),
		Suggestion:    suggestion,
		CWEID:         "CWE-322",
		OWASPCategory: "A07:2021-Identification and Authentication Failures",
		Language:      rules.LangGo,
		Confidence:    "high",
		Tags:          []string{"ssh", "mitm", "host-key"},
	})
}

// --------------------------------------------------------------------
// BATOU-AST-011: Decompression bomb — unbounded io.Copy from a
//                decompressing reader (CWE-409)
// --------------------------------------------------------------------

// checkDecompressionBomb flags `io.Copy(dst, src)` where src is a decompressing
// reader (gzip.Reader / flate / zlib / bzip2 / a tar.Reader) and the file does
// NOT bound the copy with io.LimitReader or io.CopyN. A 1 KB malicious archive
// can decompress to gigabytes, exhausting memory/disk (decompression bomb).
//
// Precision: we anchor on io.Copy specifically (package-qualified) AND require
// the source argument to be a *decompressing reader by constructor/name; a
// guard (io.LimitReader / io.CopyN anywhere in the same file, or a LimitReader
// wrapping the source) suppresses the finding — well-written extractors that
// cap the output never fire.
func (c *astChecker) checkDecompressionBomb(call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Copy" {
		return
	}
	ioName := c.localNameFor("io")
	if ioName == "" {
		return
	}
	if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != ioName {
		return
	}
	if len(call.Args) < 2 {
		return
	}

	srcArg := call.Args[1]
	// If the source is itself wrapped in io.LimitReader, it is bounded.
	if c.isLimitReaderCall(srcArg) {
		return
	}
	if !c.isDecompressingReader(srcArg) {
		return
	}

	// A LimitReader/CopyN guard anywhere in the file disarms the finding (the
	// extractor caps total bytes). Conservative: favours suppression to avoid
	// false positives on extractors that do cap output.
	if c.fileHasCopyBound() {
		return
	}

	pos := c.fset.Position(call.Pos())
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-AST-011",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Unbounded decompression (decompression bomb)",
		Description:   "io.Copy reads from a decompressing reader with no size limit. A small malicious archive can decompress to an enormous size, exhausting memory and disk (decompression bomb, CWE-409).",
		FilePath:      c.filePath,
		LineNumber:    pos.Line,
		Column:        pos.Column,
		MatchedText:   c.nodeSource(call),
		Suggestion:    "Bound the copy: use io.CopyN(dst, src, maxBytes) or wrap the reader with io.LimitReader(src, maxBytes) before io.Copy.",
		CWEID:         "CWE-409",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Language:      rules.LangGo,
		Confidence:    "high",
		Tags:          []string{"dos", "decompression-bomb", "zip"},
	})
}

// isDecompressingReader reports whether expr is (or names) a reader produced by
// a decompression constructor: gzip.NewReader / flate.NewReader /
// zlib.NewReader / bzip2.NewReader / tar.NewReader.
func (c *astChecker) isDecompressingReader(expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.CallExpr:
		// Inline-constructed reader: io.Copy(dst, gzip.NewReader(f)) shape.
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok {
				if c.isDecompressPkgReaderCtor(pkg.Name, sel.Sel.Name) {
					return true
				}
			}
		}
	case *ast.Ident:
		// Named local: `gr, _ := gzip.NewReader(f); io.Copy(w, gr)`.
		return c.identAssignedFromDecompressor(v.Name)
	}
	return false
}

// isDecompressPkgReaderCtor reports whether pkg.method is a decompression
// reader constructor we recognise. The package alias is compared against the
// conventional name for each compress/archive package actually imported.
func (c *astChecker) isDecompressPkgReaderCtor(pkgAlias, method string) bool {
	type pkgCtor struct {
		path  string
		ctors []string
	}
	candidates := []pkgCtor{
		{"compress/gzip", []string{"NewReader"}},
		{"compress/flate", []string{"NewReader"}},
		{"compress/zlib", []string{"NewReader"}},
		{"compress/bzip2", []string{"NewReader"}},
		{"archive/tar", []string{"NewReader"}},
	}
	for _, cand := range candidates {
		if c.localNameFor(cand.path) != pkgAlias {
			continue
		}
		for _, m := range cand.ctors {
			if m == method {
				return true
			}
		}
	}
	return false
}

// identAssignedFromDecompressor scans the file for an assignment
// `name, ... := pkg.NewReader(...)` where pkg is a decompression package.
// Conservative: only matches a direct constructor RHS on the same identifier.
func (c *astChecker) identAssignedFromDecompressor(name string) bool {
	found := false
	ast.Inspect(c.file, func(n ast.Node) bool {
		if found {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		// The target ident must be one of the LHS names.
		targeted := false
		for _, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
				targeted = true
				break
			}
		}
		if !targeted {
			return true
		}
		for _, rhs := range assign.Rhs {
			if call, ok := rhs.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok &&
						c.isDecompressPkgReaderCtor(pkg.Name, sel.Sel.Name) {
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

// isLimitReaderCall reports whether expr is an io.LimitReader(...) call.
func (c *astChecker) isLimitReaderCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "LimitReader" {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == c.localNameFor("io")
}

// fileHasCopyBound reports whether the file uses io.LimitReader or io.CopyN
// anywhere — a heuristic that a bounded-copy guard is present.
func (c *astChecker) fileHasCopyBound() bool {
	ioName := c.localNameFor("io")
	if ioName == "" {
		return false
	}
	found := false
	ast.Inspect(c.file, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == ioName {
			if sel.Sel.Name == "LimitReader" || sel.Sel.Name == "CopyN" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// litTypeIs reports whether a composite literal's type is the package-qualified
// type `pkgPath.typeName`. The package alias is resolved through the file's
// imports so an aliased import (e.g. `import xtls "crypto/tls"`) still matches.
func (c *astChecker) litTypeIs(lit *ast.CompositeLit, pkgPath, typeName string) bool {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if sel.Sel.Name != typeName {
		return false
	}
	// The import must actually be present and the alias must match.
	localName := c.localNameFor(pkgPath)
	return localName != "" && ident.Name == localName
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
//
// When the block unconditionally returns at the end (find-and-return
// pattern: `for ... { if match { open(); defer close(); return ... } }`),
// any defer inside this block fires AT MOST ONCE per function invocation —
// the same as if it were outside the loop. Skip the block in that case to
// avoid the most common AST-007 false positive.
func (c *astChecker) findDeferInBlock(block *ast.BlockStmt) {
	if blockEndsWithReturn(block) {
		return
	}
	for _, stmt := range block.List {
		c.findDeferInStmt(stmt)
	}
}

// blockEndsWithReturn reports whether the block's final statement is an
// unconditional return / continue / break that exits the enclosing loop.
// Conservatively only `return` is treated as exiting; `break`/`continue`
// still let the loop iterate (deferred resources accumulate).
func blockEndsWithReturn(block *ast.BlockStmt) bool {
	if block == nil || len(block.List) == 0 {
		return false
	}
	last := block.List[len(block.List)-1]
	_, ok := last.(*ast.ReturnStmt)
	return ok
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

// checkGoroutineLeakIn dispatches to checkGoroutineLeak after applying the
// "lifecycle-handler" suppression: goroutines launched from a function
// whose name matches a shutdown/cancel/cleanup verb (see isLifecycleFuncName)
// are intentionally fire-and-forget and don't need a context.
func (c *astChecker) checkGoroutineLeakIn(goStmt *ast.GoStmt, enclosingFunc string) {
	if isLifecycleFuncName(enclosingFunc) {
		return
	}
	c.checkGoroutineLeak(goStmt)
}

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

		// Check if the goroutine creates its own context with a timeout/cancel.
		// This is the standard pattern for intentional background work:
		//   go func() {
		//       ctx, cancel := context.WithTimeout(context.Background(), ...)
		//       defer cancel()
		//       ...
		//   }()
		if c.createsOwnContext(funcLit.Body) {
			return // Goroutine manages its own context lifecycle.
		}

		// Check if the goroutine is bounded by a sync.WaitGroup. The idiomatic
		// pattern pairs `defer wg.Done()` in the body with `wg.Wait()` in the
		// parent — the parent cannot return until the goroutine exits, so it
		// cannot leak. This matches the scanner's own concurrent rule
		// execution in scanner.scanCore().
		if c.isWaitGroupBounded(funcLit.Body) {
			return
		}

		// Bounded by an external blocking call. Common idioms:
		//   go func() { err := cmd.Wait(); ... }()           — process bound
		//   go func() { _ = w.CloseWithError(...) }()        — io closure
		//   go func() { ...; close(done) }()                 — channel signal
		//   go func() { for range ch { ... } }()             — channel-driven
		// These are bounded by the underlying resource lifecycle.
		if c.isBoundedByExternal(funcLit.Body) {
			return
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

	// Daemon-naming convention: `go serveX()`, `go startX()`, `go runX()`,
	// `go listenX()`, `go monitorX()`, `go watchX()`, `go processX()` are
	// almost always intentional process-lifetime workers, not leak risks.
	// gitea (and most Go services) launch dozens of these for debug
	// servers, queue workers, hook handlers, etc. Without taint or human
	// review we can't be sure, but the prefix is a strong signal.
	if isDaemonNamedCall(goStmt.Call.Fun) {
		return
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

// isWaitGroupBounded returns true if a goroutine body contains a deferred
// Done() call, indicating it is coordinated by a sync.WaitGroup. The common
// pattern is:
//
//	wg.Add(1)
//	go func() {
//	    defer wg.Done()
//	    ...
//	}()
//	wg.Wait()
//
// A goroutine that pairs with Wait() in its parent cannot leak — the parent
// blocks until it exits. We match on `defer <ident>.Done()` rather than on
// type information (which go/ast alone doesn't have), which is narrow enough
// to avoid confusion with channel receives like <-ctx.Done() (those wouldn't
// appear as CallExpr under a DeferStmt anyway).
func (c *astChecker) isWaitGroupBounded(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	// Helper: matches `<ident>.Done()` (with zero args) — the WaitGroup
	// signature. Doesn't enforce the receiver name to be `wg` since
	// codebases use various names (g, group, wg, w).
	matchesDone := func(call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if _, ok := sel.X.(*ast.Ident); !ok {
			return false
		}
		return sel.Sel.Name == "Done" && len(call.Args) == 0
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		// Idiomatic: `defer wg.Done()`
		if def, ok := n.(*ast.DeferStmt); ok {
			if matchesDone(def.Call) {
				found = true
				return false
			}
			return true
		}
		// Tightening 2026-04-26: also accept bare `wg.Done()` as the
		// last statement / any statement of the goroutine. ocis uses
		// `go func() { ...; wg.Done() }()` (no defer) which is still
		// waitgroup-bounded — the parent's wg.Wait() blocks until this
		// returns, so the goroutine cannot leak.
		if exprStmt, ok := n.(*ast.ExprStmt); ok {
			if call, ok := exprStmt.X.(*ast.CallExpr); ok && matchesDone(call) {
				found = true
				return false
			}
		}
		return true
	})
	return found
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

// isBoundedByExternal returns true when the goroutine body's lifetime is
// implicitly bounded by an external resource: a process Wait/Close call, a
// channel close, or a `for range chan` consumer. None of these are leak
// patterns — they exit when the underlying resource closes.
func (c *astChecker) isBoundedByExternal(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	bounded := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bounded {
			return false
		}
		switch x := n.(type) {
		case *ast.CallExpr:
			// Recognize: cmd.Wait(), cmd.WaitWithStderr(), w.Close(),
			// w.CloseWithError(), close(ch).
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "close" {
				bounded = true
				return false
			}
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				name := sel.Sel.Name
				if name == "Wait" || name == "WaitWithStderr" ||
					name == "Close" || name == "CloseWithError" ||
					strings.HasSuffix(name, "Wait") {
					bounded = true
					return false
				}
			}
		case *ast.RangeStmt:
			// for range channel — exits when channel closes.
			if x.Key == nil && x.Value == nil {
				if _, ok := x.X.(*ast.UnaryExpr); ok {
					// for range <-ch (rare) — channel-bound
					bounded = true
				}
			}
			if x.Tok == token.DEFINE || x.Tok == token.ASSIGN || x.Key == nil {
				// for x := range ch — if X is a chan it's bound. We can't
				// fully verify type without type info, but a `for range`
				// over a channel-typed expression is the common Go idiom.
				bounded = true
			}
		}
		return true
	})
	return bounded
}

// createsOwnContext checks if a function body creates its own context via
// context.WithTimeout, context.WithCancel, or context.WithDeadline called
// with context.Background() or context.TODO(). This is the standard Go
// pattern for intentional background work that manages its own lifecycle.
func (c *astChecker) createsOwnContext(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}

	// contextCreators are methods on the context package that create
	// a derived context with cancellation/timeout.
	contextCreators := map[string]bool{
		"WithTimeout":  true,
		"WithCancel":   true,
		"WithDeadline": true,
	}

	// backgroundCtx are context constructors that create a root context
	// for intentional background work.
	backgroundCtx := map[string]bool{
		"Background": true,
		"TODO":       true,
	}

	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Match context.WithTimeout(...), context.WithCancel(...), etc.
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if ident.Name != "context" || !contextCreators[sel.Sel.Name] {
			return true
		}

		// Check that the first argument is context.Background() or context.TODO().
		if len(call.Args) == 0 {
			return true
		}
		argCall, ok := call.Args[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		argSel, ok := argCall.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		argIdent, ok := argSel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if argIdent.Name == "context" && backgroundCtx[argSel.Sel.Name] {
			found = true
			return false
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
