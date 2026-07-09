package pyast

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// sqlKeywordRe matches SQL keywords that begin a statement (after the string's
// opening quote / Python prefix, or after a `;` clause separator inside the
// string). This avoids substring matches like `DELETE` in `delete_selected`,
// HTML `<select>` elements in test fixtures, and error messages like
// "Cannot truncate DateField".
var sqlKeywordRe = regexp.MustCompile(`(?im)(?:^|[;\n])[\s"'rfbuRFBU]*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+(?:TABLE|DATABASE|INDEX)|ALTER\s+TABLE|CREATE\s+TABLE|TRUNCATE\s+TABLE|MERGE\s+INTO)\b[\s*(]`)

// PythonASTAnalyzer performs AST-based security analysis of Python source code.
type PythonASTAnalyzer struct{}

func init() {
	rules.Register(&PythonASTAnalyzer{})
}

func (p *PythonASTAnalyzer) ID() string                      { return "BATOU-PYAST" }
func (p *PythonASTAnalyzer) Name() string                    { return "Python AST Security Analyzer" }
func (p *PythonASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (p *PythonASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangPython} }
func (p *PythonASTAnalyzer) Description() string {
	return "AST-based analysis of Python source for eval/exec injection, subprocess shell injection, pickle deserialization, os.system command injection, SQL string formatting, and path traversal via open()."
}

func (p *PythonASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPython {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	// origContent preserves un-preprocessed line numbering so AST-derived
	// line indices (which point into the original source) line up with
	// line-by-line helpers like rules.PySinkVarIsSafe. Fall back to
	// ctx.Content for legacy callers that don't populate OriginalContent.
	origContent := ctx.OriginalContent
	if origContent == "" {
		origContent = ctx.Content
	}
	c := &pyChecker{
		filePath:    ctx.FilePath,
		tree:        tree,
		content:     ctx.Content,
		origContent: origContent,
	}
	c.walk()
	return c.findings
}

type pyChecker struct {
	filePath    string
	tree        *ast.Tree
	content     string // preprocessed (multi-line continuations joined)
	origContent string // original source — aligned with AST line numbers
	findings    []rules.Finding

	// Per-file memos for whole-file work that is identical on every
	// open()-call node (depends only on c.content / c.origContent, not the
	// node). Computed lazily so files with no open() calls pay nothing.
	pathGuardComputed bool
	pathGuardResult   bool
	origLinesCache    []string
}

// reOpenPathTraversalGuard matches in-file path-traversal guards that make a
// `open(var, ...)` call structurally safe regardless of whether `var` is
// user-derived. When any of these patterns is present, BATOU-PYAST-004 is
// suppressed because the regex/taint layers already cover the residual risk
// with greater precision (and the AST rule, which has no flow awareness,
// otherwise misclassifies the file as a path-traversal sink).
//
// Patterns covered:
//   - explicit `'../' in path` / `".." in path` denylist with early return
//   - werkzeug.utils.secure_filename() / safe_join() sanitizers
//   - pathlib `.resolve()` (or os.path.realpath/abspath/normpath) combined
//     with a startswith() containment check against an expected root
var reOpenPathTraversalGuard = regexp.MustCompile(
	`'\.\.[/\\]?'\s+in\b|"\.\.[/\\]?"\s+in\b|` +
		`\bsecure_filename\s*\(|\bsafe_join\s*\(|` +
		`\.resolve\s*\([^)]*\)[\s\S]{0,200}\bstartswith\s*\(|` +
		`\bos\.path\.(?:realpath|abspath|normpath)\s*\([^)]*\)[\s\S]{0,200}\bstartswith\s*\(`,
)

func (c *pyChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "call" {
			c.checkCall(n)
		}
		if n.Type() == "binary_operator" {
			c.checkSQLFormatOp(n)
		}
		if n.Type() == "string" {
			c.checkFStringSQLInjection(n)
		}
		return true
	})
}

// checkCall inspects function calls for dangerous patterns.
func (c *pyChecker) checkCall(n *ast.Node) {
	funcName := callFuncName(n)
	switch funcName {
	case "eval":
		c.checkDangerousBuiltin(n, funcName, "Code injection via eval()", "eval() executes arbitrary Python code. If the argument is user-controlled, an attacker can execute any code on the server.", "CWE-95")
	case "exec":
		c.checkDangerousBuiltin(n, funcName, "Code injection via exec()", "exec() executes arbitrary Python code. If the argument is user-controlled, an attacker can execute any code on the server.", "CWE-95")
	case "os.system":
		c.checkDangerousBuiltin(n, funcName, "Command injection via os.system()", "os.system() passes a command string to the system shell. If the argument contains user input, an attacker can inject shell commands.", "CWE-78")
	case "open", "codecs.open", "io.open":
		c.checkOpenCall(n)
	}

	// subprocess.call/run/Popen with shell=True
	if isSubprocessCall(funcName) {
		c.checkSubprocessShell(n, funcName)
	}

	// pickle.loads/load
	if funcName == "pickle.loads" || funcName == "pickle.load" {
		c.checkPickle(n, funcName)
	}
}

// checkDangerousBuiltin flags calls where the first argument is not a string literal.
func (c *pyChecker) checkDangerousBuiltin(n *ast.Node, funcName, title, desc, cwe string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-PYAST-001",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         title,
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Never pass user-controlled data to " + funcName + "(). Use a safe alternative or validate input strictly.",
		CWEID:         cwe,
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangPython,
		Confidence:    "high",
		Tags:          []string{"injection", "ast"},
	})
}

// checkSubprocessShell detects subprocess calls with shell=True and non-literal command.
func (c *pyChecker) checkSubprocessShell(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	hasShellTrue := false
	for _, child := range args.NamedChildren() {
		if child.Type() == "keyword_argument" {
			key := firstNamedChild(child)
			if key != nil && key.Text() == "shell" {
				val := lastNamedChild(child)
				if val != nil && (val.Type() == "true" || val.Text() == "True") {
					hasShellTrue = true
				}
			}
		}
	}
	if !hasShellTrue {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-PYAST-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Shell injection via " + funcName + " with shell=True",
		Description:   funcName + " is called with shell=True and a non-literal command. An attacker who controls the command string can execute arbitrary shell commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Remove shell=True and pass the command as a list: subprocess.run(['cmd', 'arg1', 'arg2']).",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangPython,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "ast"},
	})
}

// checkPickle flags pickle.loads/load with non-literal data.
func (c *pyChecker) checkPickle(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-PYAST-003",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Unsafe deserialization via " + funcName,
		Description:   funcName + " deserializes untrusted data, which can lead to arbitrary code execution. Pickle is inherently unsafe for untrusted input.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use a safe serialization format like JSON. If pickle is required, use hmac to verify data integrity before deserializing.",
		CWEID:         "CWE-502",
		OWASPCategory: "A08:2021-Software and Data Integrity Failures",
		Language:      rules.LangPython,
		Confidence:    "high",
		Tags:          []string{"deserialization", "rce", "ast"},
	})
}

// pyArgparseReceivers are conventional names of the parsed-args object in
// Python CLI scripts. `open(args.input, ...)` / `open(opts.output)` is the
// canonical argparse-driven CLI pattern — the path argument *is* user
// input by design, but the user is the developer running the script,
// not a remote attacker. Reading the variable as "argparse-shaped"
// avoids firing path-traversal on every CLI tool's main().
var pyArgparseReceivers = map[string]bool{
	"args":      true,
	"arguments": true,
	"opts":      true,
	"options":   true,
	"cli":       true,
	"flags":     true,
	"argv":      true, // distinct from sys.argv — argparse Namespace too
}

// pyArgIsArgparseAttribute returns true when the firstArg of open() is a
// tree-sitter `attribute` node whose object is one of the conventional
// argparse receivers (args.input, opts.path, etc.).
func pyArgIsArgparseAttribute(arg *ast.Node) bool {
	if arg == nil || arg.Type() != "attribute" {
		return false
	}
	children := arg.NamedChildren()
	if len(children) == 0 {
		return false
	}
	receiver := children[0]
	if receiver.Type() != "identifier" {
		return false
	}
	return pyArgparseReceivers[receiver.Text()]
}

// hasOpenPathTraversalGuard memoizes the whole-file path-traversal guard
// regex match. The result depends only on c.content, so it is identical on
// every open()-call node — computing it once avoids O(open_calls * filesize).
func (c *pyChecker) hasOpenPathTraversalGuard() bool {
	if !c.pathGuardComputed {
		c.pathGuardResult = reOpenPathTraversalGuard.MatchString(c.content)
		c.pathGuardComputed = true
	}
	return c.pathGuardResult
}

// origContentLines memoizes the split of c.origContent into lines. The result
// depends only on c.origContent, so it is identical on every open()-call node.
// strings.Split never returns nil for a string, so the nil check correctly
// memoizes even for empty content.
func (c *pyChecker) origContentLines() []string {
	if c.origLinesCache == nil {
		c.origLinesCache = strings.Split(c.origContent, "\n")
	}
	return c.origLinesCache
}

// checkOpenCall flags open() with non-literal path.
func (c *pyChecker) checkOpenCall(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isLiteral(firstArg) {
		return
	}
	// CLI argparse idiom: open(args.input, ...), open(opts.path), ...
	// Surfaced via scan_harness on shadowsocks-android, bannedbook,
	// magisk build scripts — 17.5 hits/repo, all on top-level CLI
	// tools where the developer-author intentionally takes a path arg.
	if pyArgIsArgparseAttribute(firstArg) {
		return
	}
	// File-level guard suppression: this AST rule cannot reason about
	// control flow, so it would otherwise fire on every `open(var, ...)`
	// in files that explicitly reject path traversal (e.g. werkzeug's
	// secure_filename, an `'../' in path` denylist, or a
	// `.resolve()`-then-`startswith(root)` containment check). The taint
	// pipeline still inspects these paths with flow awareness; only the
	// blind AST signal is silenced. CWE-22 coverage is preserved by the
	// taint sinks `py.pathlib.read_text`, `py.open`, etc.
	if c.hasOpenPathTraversalGuard() {
		return
	}
	line := int(n.StartRow()) + 1
	// Variable-level safety check (PR-PATHpy): if the path argument
	// resolves to a variable that was last assigned from a safe source
	// (an always-true ternary, a constant default, or an always-case
	// match), suppress. This covers the OWASP Python
	// pathtraver "safe with prefix" pattern:
	//   fileName = f'{TESTFILES_DIR}/{bar}'
	//   open(fileName, ...)
	// where bar was overwritten with a literal in the last assignment.
	// The taint pipeline still inspects the path with flow awareness; only
	// the blind AST signal is silenced.
	lineIdx := line - 1
	// AST line numbers index into the ORIGINAL source. Pair them with
	// origContent so PySinkVarIsSafe sees the same indentation / control
	// structure the AST does — preprocessed content joins multi-line
	// continuations and would misalign the scan.
	contentLines := c.origContentLines()
	if rules.PySinkVarIsSafe(contentLines, lineIdx) {
		return
	}
	// Variable-scoped containment guard (pyast-fpr): extend the same
	// containment/allowlist/startswith reasoning the taint layer applies to
	// path sinks so it also silences this blind AST signal. When ANY
	// identifier feeding the open() path argument is validated by a
	// membership (`p in ALLOWED` / `p not in DENY`) or prefix
	// (`p.startswith(BASE)`) guard near the sink, the file read/write is
	// already gated — suppress. Pinned to the actual sink variable(s) so an
	// unrelated guard never over-suppresses; a truly-tainted
	// `open(request.args["f"])` with no guard still fires.
	for _, ident := range pyArgIdentifiers(firstArg) {
		if rules.PyHasContainmentGuard(contentLines, lineIdx, ident) {
			return
		}
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-PYAST-004",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Path traversal via open() with variable path",
		Description:   "open() is called with a non-literal path argument. If the path is user-controlled, an attacker could read or write arbitrary files on the filesystem.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the path against an allowlist, use os.path.realpath() to resolve symlinks, and ensure the resolved path is within an expected directory.",
		CWEID:         "CWE-22",
		OWASPCategory: "A01:2021-Broken Access Control",
		Language:      rules.LangPython,
		Confidence:    "medium",
		Tags:          []string{"path-traversal", "ast"},
	})
}

// pyArgIdentifiers collects the distinct simple identifier names referenced in
// an open() path-argument sub-tree. It descends through string concatenation
// (`'/srv/' + bar`), str()/os.path.join() wrappers, subscripts, and attribute
// receivers so the variable feeding the sink can be matched against a
// containment guard. Only bare identifiers used as *values* are collected — the
// function name of a call (e.g. the `open` in `open(...)` or `join` in
// `os.path.join`) is skipped so a guard check never keys off a builtin name.
//
// The traversal is bounded and deduplicated; for a typical path argument it
// yields one or two names (e.g. ["bar"] or ["real", "BASE"]).
func pyArgIdentifiers(arg *ast.Node) []string {
	if arg == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	var visit func(n *ast.Node)
	visit = func(n *ast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "identifier":
			name := n.Text()
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
			return
		case "call":
			// Visit the arguments, but skip the function expression so the
			// callee name (open / str / join / get) is not collected as a
			// guarded value.
			if al := findChild(n, "argument_list"); al != nil {
				for _, ch := range al.NamedChildren() {
					visit(ch)
				}
			}
			return
		case "attribute":
			// For `obj.field`, the guarded value is the base object identifier
			// (request, args, ...). Recurse into the receiver only.
			children := n.NamedChildren()
			if len(children) > 0 {
				visit(children[0])
			}
			return
		}
		for _, ch := range n.NamedChildren() {
			visit(ch)
		}
	}
	visit(arg)
	return out
}

// checkSQLFormatOp detects "SELECT ... %s" % var patterns.
func (c *pyChecker) checkSQLFormatOp(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	// Check for % operator (modulo used for string formatting)
	text := n.Text()
	if !strings.Contains(text, "%") {
		return
	}
	left := named[0]
	if left.Type() != "string" {
		return
	}
	if containsSQLKeyword(left.Text()) {
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-PYAST-005",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL injection via string % formatting",
			Description:   "A SQL query is built using Python's % string formatting operator with a variable. This enables SQL injection attacks.",
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = %s', (name,)).",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangPython,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection", "ast"},
		})
	}
}

// checkFStringSQLInjection detects f"SELECT ... {var}" patterns.
func (c *pyChecker) checkFStringSQLInjection(n *ast.Node) {
	text := n.Text()
	if !strings.HasPrefix(text, "f\"") && !strings.HasPrefix(text, "f'") {
		return
	}
	// Check for interpolation children
	hasInterpolation := false
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "interpolation" {
			hasInterpolation = true
			return false
		}
		return true
	})
	if !hasInterpolation {
		return
	}
	if containsSQLKeyword(text) {
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-PYAST-005",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "SQL injection via f-string interpolation",
			Description:   "A SQL query is built using Python f-string interpolation with embedded variables. This enables SQL injection attacks.",
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(text, 200),
			Suggestion:    "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = %s', (name,)).",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangPython,
			Confidence:    "high",
			Tags:          []string{"sql-injection", "injection", "ast"},
		})
	}
}

// --- helpers ---

func callFuncName(n *ast.Node) string {
	if n == nil || n.Type() != "call" {
		return ""
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return ""
	}
	funcNode := named[0]
	switch funcNode.Type() {
	case "identifier":
		return funcNode.Text()
	case "attribute":
		parts := funcNode.NamedChildren()
		if len(parts) == 2 {
			return parts[0].Text() + "." + parts[1].Text()
		}
	}
	return ""
}

func isSubprocessCall(name string) bool {
	return name == "subprocess.call" || name == "subprocess.run" ||
		name == "subprocess.Popen" || name == "subprocess.check_output" ||
		name == "subprocess.check_call"
}

func findChild(n *ast.Node, nodeType string) *ast.Node {
	if n == nil {
		return nil
	}
	for _, c := range n.NamedChildren() {
		if c.Type() == nodeType {
			return c
		}
	}
	return nil
}

func firstNamedChild(n *ast.Node) *ast.Node {
	if n == nil {
		return nil
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return nil
	}
	return named[0]
}

func lastNamedChild(n *ast.Node) *ast.Node {
	if n == nil {
		return nil
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return nil
	}
	return named[len(named)-1]
}

func isLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "integer", "float", "true", "false", "none",
		"string_literal", "number_literal":
		return true
	}
	return false
}

func containsSQLKeyword(s string) bool {
	return sqlKeywordRe.MatchString(s)
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
