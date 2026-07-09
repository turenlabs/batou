package cast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// CASTAnalyzer performs AST-based security analysis of C and C++ source code.
type CASTAnalyzer struct{}

func init() {
	rules.Register(&CASTAnalyzer{})
}

func (a *CASTAnalyzer) ID() string                      { return "BATOU-CAST" }
func (a *CASTAnalyzer) Name() string                    { return "C/C++ AST Security Analyzer" }
func (a *CASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (a *CASTAnalyzer) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}
func (a *CASTAnalyzer) Description() string {
	return "AST-based analysis of C/C++ source for format string vulnerabilities, banned buffer overflow functions, system() command injection, and unsafe memory patterns."
}

func (a *CASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangC && ctx.Language != rules.LangCPP {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &cChecker{
		filePath: ctx.FilePath,
		language: ctx.Language,
		tree:     tree,
	}
	c.walk()
	return c.findings
}

type cChecker struct {
	filePath string
	language rules.Language
	tree     *ast.Tree
	findings []rules.Finding
}

// bannedFuncs maps dangerous C functions to their safe alternatives and CWEs.
var bannedFuncs = map[string]struct {
	title      string
	desc       string
	suggestion string
	cwe        string
	severity   rules.Severity
}{
	"gets": {
		title:      "Use of banned function gets()",
		desc:       "gets() reads input without bounds checking, always causing a buffer overflow if input exceeds buffer size. It has been removed from C11.",
		suggestion: "Use fgets(buf, sizeof(buf), stdin) instead.",
		cwe:        "CWE-120",
		severity:   rules.Critical,
	},
	"strcpy": {
		title:      "Use of unbounded string copy strcpy()",
		desc:       "strcpy() copies without bounds checking. If the source is longer than the destination buffer, a buffer overflow occurs.",
		suggestion: "Use strncpy(dest, src, sizeof(dest)-1) or strlcpy() where available.",
		cwe:        "CWE-120",
		severity:   rules.High,
	},
	"strcat": {
		title:      "Use of unbounded string concatenation strcat()",
		desc:       "strcat() concatenates without bounds checking. If the combined string exceeds the buffer, a buffer overflow occurs.",
		suggestion: "Use strncat(dest, src, sizeof(dest)-strlen(dest)-1) or strlcat() where available.",
		cwe:        "CWE-120",
		severity:   rules.High,
	},
	"sprintf": {
		title:      "Use of unbounded sprintf()",
		desc:       "sprintf() writes formatted output without bounds checking. If the output exceeds the buffer, a buffer overflow occurs.",
		suggestion: "Use snprintf(buf, sizeof(buf), fmt, ...) instead.",
		cwe:        "CWE-120",
		severity:   rules.High,
	},
	"vsprintf": {
		title:      "Use of unbounded vsprintf()",
		desc:       "vsprintf() writes formatted output without bounds checking, leading to potential buffer overflow.",
		suggestion: "Use vsnprintf(buf, sizeof(buf), fmt, args) instead.",
		cwe:        "CWE-120",
		severity:   rules.High,
	},
}

// formatFuncs are functions where the format string should be a literal.
var formatFuncs = map[string]int{
	"printf":   0,
	"fprintf":  1,
	"sprintf":  1,
	"snprintf": 2,
	"syslog":   1,
}

// memWriteSinks maps the C buffer-write intrinsics to the index of their
// size/length argument. These write `size` bytes into the destination
// (argument 0); when `size` is attacker-controlled and the destination is a
// fixed-size buffer, this is an out-of-bounds write (CWE-787).
var memWriteSinks = map[string]int{
	"memcpy":  2, // memcpy(dst, src, n)
	"memmove": 2, // memmove(dst, src, n)
	"memset":  2, // memset(dst, c, n)
	"strncpy": 2, // strncpy(dst, src, n) — n larger than dst overflows
	"strncat": 2, // strncat(dst, src, n)
	"bcopy":   2, // bcopy(src, dst, n)
}

// allocSinks maps the C allocation intrinsics to the index of their size
// argument. A size computed as `a * b` (or `a << b`) of two non-constant
// operands can wrap around (integer overflow), under-allocating the buffer
// (CWE-190 -> CWE-787 heap overflow on the subsequent write).
var allocSinks = map[string]int{
	"malloc":  0, // malloc(n)
	"alloca":  0, // alloca(n)
	"calloc":  1, // calloc(nmemb, size) — size is the per-element width
	"realloc": 1, // realloc(ptr, n)
}

func (c *cChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "call_expression" {
			c.checkCallExpression(n)
			c.checkTaintedSizeWrite(n)
			c.checkAllocOverflow(n)
			c.checkUncheckedPrivDrop(n)
			// TLS cert-verification disabled via explicit flag
			// (CAST-010/011/012: OpenSSL/libcurl/GnuTLS).
			c.checkTLSVerifyDisabled(n)
			// libc misuse hardening (CAST-013 strtok / CAST-014 temp-file /
			// CAST-015 unbounded scanf / CAST-016 secret-scrub memset).
			c.checkLibcHardening(n)
		}
		return true
	})
	// Per-function flow pass: intraprocedural UAF / double-free (CAST-006/007).
	// Needs per-function ordered state, so it's a separate traversal from the
	// stateless call-site pass above. Don't recurse into nested function_-
	// definitions twice (checkFunctionFlow scans the whole body subtree).
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "function_definition" {
			c.checkFunctionFlow(n)
			// Supplementary-group drop ordering (CAST-017). Per-function: needs
			// to see every set*id call in the body together.
			c.checkPrivDropGroupOrder(n)
			return false
		}
		return true
	})
	// OpenSSL always-accept verify-callback detection (CAST-009). Two-pass over
	// the whole tree: collect SSL_CTX_set_verify callbacks, then flag trivial
	// always-return-1 definitions.
	c.checkTLSVerifyCallbacks()
	// /dev/random fd-exhaustion loop (CAST-018). Scans loop bodies, so it runs
	// as its own whole-tree pass.
	c.checkDevRandomLoop()
}

// checkTaintedSizeWrite detects CWE-787 out-of-bounds writes where the length
// argument of a memory-copy intrinsic is an attacker-controllable function
// parameter and the destination is a fixed-size stack buffer. This is the
// dominant C memory-corruption shape (e.g. `void f(int n, char *s){ char
// b[64]; memcpy(b, s, n); }`) — regex layers cannot connect the parameter to
// the size argument or know the destination is bounded.
func (c *cChecker) checkTaintedSizeWrite(n *ast.Node) {
	funcName := cCallName(n)
	sizeIdx, ok := memWriteSinks[funcName]
	if !ok {
		return
	}
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	named := args.NamedChildren()
	if sizeIdx >= len(named) || len(named) == 0 {
		return
	}

	// The size argument must reduce to a bare identifier (or a simple
	// arithmetic expression) that names a function parameter. A literal size
	// (memcpy(b, s, 64)) or a sizeof() expression is safe and must not fire.
	sizeArg := named[sizeIdx]
	sizeNames := identifiersIn(sizeArg)
	if len(sizeNames) == 0 {
		return // literal / sizeof-only size — bounded, no taint
	}
	params := c.enclosingParams(n)
	if len(params) == 0 {
		return
	}
	if !anyIn(sizeNames, params) {
		return // size is a local, not a caller-controlled parameter
	}

	// The destination (argument 0) must be a fixed-size buffer declared in the
	// enclosing function. Copying a parameter-controlled length into a bounded
	// buffer is the out-of-bounds write; copying into a heap buffer of unknown
	// size is a weaker signal we leave to the size-allocation checks.
	dst := named[0]
	dstName := baseIdentifier(dst)
	if dstName == "" || !c.isFixedSizeBuffer(n, dstName) {
		return
	}

	// Bounds-guard suppression: a preceding length/bounds check in the same
	// function that rejects the over-long case (`if (sdslen(o) > sizeof(buf)-1)
	// goto invalid;`) makes this copy bounded — the out-of-bounds-write finding
	// is a false positive. Mirrors the Python eval-guard idea for the C memory
	// sink class. Only suppresses when the guard is an early-exit size
	// comparison referencing this copy (see hasPrecedingBoundsGuard).
	if c.hasPrecedingBoundsGuard(n, named) {
		return
	}

	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-004",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Out-of-bounds write: attacker-controlled size in " + funcName + "()",
		Description: funcName + "() copies a caller-controlled length into the fixed-size buffer '" + dstName +
			"'. When the length exceeds the buffer's capacity, memory past the buffer is overwritten (stack/heap buffer overflow).",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Bound the copy length to the destination size: " + funcName + "(" + dstName + ", src, sizeof(" + dstName + ")). Validate the length against the buffer capacity before copying.",
		CWEID:         "CWE-787",
		OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"buffer-overflow", "out-of-bounds-write", "memory-safety", "taint", "ast"},
	})
}

// checkAllocOverflow detects CWE-190 integer-overflow-to-allocation-size:
// an allocation whose size is a multiplication or left-shift of two
// non-constant operands (e.g. `malloc(a * b)`). On a 32/64-bit `size_t` this
// product can wrap, under-allocating the buffer; the subsequent fill then
// overflows it. A constant operand (`a * sizeof(T)`, `n * 16`) is the common
// safe shape and is excluded.
func (c *cChecker) checkAllocOverflow(n *ast.Node) {
	funcName := cCallName(n)
	sizeIdx, ok := allocSinks[funcName]
	if !ok {
		return
	}
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	named := args.NamedChildren()
	if sizeIdx >= len(named) {
		return
	}
	sizeArg := unwrapParens(named[sizeIdx])
	if sizeArg == nil || sizeArg.Type() != "binary_expression" {
		return
	}
	op := sizeArg.ChildByFieldName("operator")
	if op == nil {
		return
	}
	opTxt := op.Text()
	if opTxt != "*" && opTxt != "<<" {
		return
	}
	left := sizeArg.ChildByFieldName("left")
	right := sizeArg.ChildByFieldName("right")
	// Both operands must be non-constant for the product to be capable of
	// wrapping under attacker influence. `a * 16` or `a * sizeof(int)` is
	// bounded by the constant factor and is the dominant safe pattern.
	if isConstOperand(left) || isConstOperand(right) {
		return
	}

	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-005",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Integer overflow in allocation size for " + funcName + "()",
		Description: funcName + "() computes its allocation size as '" + truncate(sizeArg.Text(), 80) +
			"'. Multiplying two unchecked values can overflow size_t and wrap to a small allocation; writing the intended number of bytes then overflows the undersized buffer (CWE-190 -> heap overflow).",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Check for multiplication overflow before allocating (e.g. if (b != 0 && a > SIZE_MAX / b) fail), or use calloc()/reallocarray() which detect the overflow internally.",
		CWEID:         "CWE-190",
		OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"integer-overflow", "allocation", "memory-safety", "ast"},
	})
}

func (c *cChecker) checkCallExpression(n *ast.Node) {
	funcName := cCallName(n)
	if funcName == "" {
		return
	}

	// Check banned functions
	if info, ok := bannedFuncs[funcName]; ok {
		line := int(n.StartRow()) + 1
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-CAST-001",
			Severity:      info.severity,
			SeverityLabel: info.severity.String(),
			Title:         info.title,
			Description:   info.desc,
			FilePath:      c.filePath,
			LineNumber:    line,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    info.suggestion,
			CWEID:         info.cwe,
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
			Language:      c.language,
			Confidence:    "high",
			Tags:          []string{"buffer-overflow", "memory-safety", "ast"},
		})
	}

	// Check format string vulnerabilities
	if fmtArgIdx, ok := formatFuncs[funcName]; ok {
		c.checkFormatString(n, funcName, fmtArgIdx)
	}

	// Check system() with variable argument
	if funcName == "system" {
		c.checkSystemCall(n)
	}

	// Check popen() with variable argument
	if funcName == "popen" {
		c.checkSystemCall(n)
	}
}

// checkFormatString detects printf-family calls where the format string is not a literal.
func (c *cChecker) checkFormatString(n *ast.Node, funcName string, fmtArgIdx int) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	named := args.NamedChildren()
	if fmtArgIdx >= len(named) {
		return
	}
	fmtArg := named[fmtArgIdx]
	if isLikelyConstFormat(fmtArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Format string vulnerability in " + funcName + "()",
		Description:   funcName + "() is called with a non-literal format string. An attacker who controls the format string can read from or write to arbitrary memory locations.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Always use a string literal as the format string: " + funcName + "(\"...%s...\", variable). Never pass user input as the format argument.",
		CWEID:         "CWE-134",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"format-string", "memory-safety", "ast"},
	})
}

// checkSystemCall detects system()/popen() with non-literal argument.
func (c *cChecker) checkSystemCall(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isCLiteral(firstArg) {
		return
	}
	funcName := cCallName(n)
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-003",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via " + funcName + "()",
		Description:   funcName + "() passes a command to the system shell. If the argument contains user input, an attacker can inject arbitrary commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid " + funcName + "() with user input. Use exec-family functions (execve, execvp) with separate arguments.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "ast"},
	})
}

// --- helpers ---

func cCallName(n *ast.Node) string {
	if n == nil || n.Type() != "call_expression" {
		return ""
	}
	named := n.NamedChildren()
	if len(named) == 0 {
		return ""
	}
	funcNode := named[0]
	if funcNode.Type() == "identifier" {
		return funcNode.Text()
	}
	return ""
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

func isCLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string_literal", "number_literal", "char_literal",
		"concatenated_string", "true", "false", "null":
		return true
	}
	// Check if it's a string content wrapped in quotes
	if strings.HasPrefix(n.Text(), "\"") || strings.HasPrefix(n.Text(), "'") {
		return true
	}
	return false
}

// isLikelyConstFormat reports whether a node is something we treat as a
// compile-time-constant format string for BATOU-CAST-002 purposes.
//
// This is intentionally permissive — the rule's only signal is "format arg is
// not a literal", which produces heavy false positives on real C code that
// uses #defines, const char* tables, and pre-validated format strings (e.g.
// Lua's scanformat). We suppress when the format arg is:
//
//  1. A literal (string/char/number).
//  2. A parenthesized literal or const-format expression.
//  3. A ternary where both branches are themselves const-format expressions
//     (e.g. cond ? "%s=%llu" : ",%s=%llu").
//  4. An identifier whose name follows the macro convention (ALL_CAPS, with
//     digits/underscores) — e.g. LUA_NUMBER_FMT, CLUSTER_MANAGER_INVALID_HOST_ARG,
//     LOG_COLOR_BOLD, CLASSIC_FOOTER.
//  5. An identifier whose name strongly suggests a constant format string —
//     "fmt", "format", "*_fmt", "*_format", "*format*", "*_str", "branch",
//     "ascii_logo". This catches Redis/Lua/hdr_histogram local const tables
//     (format_str, head_format, line_format, ascii_logo).
//
// We accept a small risk of missing a true positive where a developer passes
// user input through a variable named "fmt" — the rule has no dataflow to
// disambiguate, and the regex/AST-only signal is too weak to justify shouting
// about every const-format call site.
func isLikelyConstFormat(n *ast.Node) bool {
	if n == nil {
		return true // be conservative on missing nodes
	}
	if isCLiteral(n) {
		return true
	}
	switch n.Type() {
	case "parenthesized_expression":
		// Unwrap (...) and recurse on the inner expression.
		for _, child := range n.NamedChildren() {
			if isLikelyConstFormat(child) {
				return true
			}
		}
		return false
	case "conditional_expression":
		// cond ? a : b — suppress when both branches look const.
		named := n.NamedChildren()
		if len(named) < 3 {
			return false
		}
		// tree-sitter-c lays out conditional_expression as
		// [condition, consequence, alternative].
		then, els := named[1], named[2]
		return isLikelyConstFormat(then) && isLikelyConstFormat(els)
	case "identifier":
		return isConstLikeIdentifier(n.Text())
	}
	return false
}

// isConstLikeIdentifier reports whether an identifier looks like it refers to
// a macro or local const format string. Pattern matches:
//   - ALL_CAPS / digits / underscores (macro convention) — at least one letter.
//   - Common format-name suffixes/contains: fmt, format, _str.
//   - A small named allowlist of patterns seen across the wild (ascii_logo,
//     branch — Redis-specific but harmless).
func isConstLikeIdentifier(name string) bool {
	if name == "" {
		return false
	}

	// Allowlist of exact / substring matches for common const-format names.
	lower := strings.ToLower(name)
	if lower == "fmt" || lower == "format" ||
		strings.HasSuffix(lower, "_fmt") || strings.HasSuffix(lower, "_format") ||
		strings.HasPrefix(lower, "fmt_") || strings.HasPrefix(lower, "format_") ||
		strings.HasSuffix(lower, "_str") || strings.HasSuffix(lower, "_string") ||
		strings.Contains(lower, "format") {
		return true
	}
	// Specific Redis/Lua local-const names that recur across our FP corpus.
	switch lower {
	case "ascii_logo", "branch", "form", "head_format", "line_format",
		"classic_footer", "classic_header":
		return true
	}

	// Macro convention: ALL_CAPS [+ digits/underscores], must have at least
	// one ASCII letter and contain no lowercase letters.
	hasLetter := false
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			// allowed
		case r == '_':
			// allowed
		default:
			// Any lowercase letter or other char disqualifies.
			return false
		}
	}
	return hasLetter
}

// enclosingParams returns the parameter names of the function_definition that
// contains node n. Parameters are the trust boundary in C: a value flowing in
// from a caller is, in the general (interprocedural) case, attacker-reachable.
func (c *cChecker) enclosingParams(n *ast.Node) []string {
	for _, anc := range n.Ancestors() {
		if anc.Type() == "function_definition" {
			return paramNames(anc)
		}
	}
	return nil
}

// paramNames extracts the declared parameter identifier names from a
// function_definition node (handles plain and pointer-declared parameters).
func paramNames(fnDef *ast.Node) []string {
	decl := fnDef.ChildByFieldName("declarator")
	// Unwrap pointer_declarator (e.g. `void *h(...)`).
	for decl != nil && decl.Type() == "pointer_declarator" {
		decl = decl.ChildByFieldName("declarator")
	}
	if decl == nil || decl.Type() != "function_declarator" {
		return nil
	}
	plist := decl.ChildByFieldName("parameters")
	if plist == nil {
		return nil
	}
	var names []string
	for _, p := range plist.NamedChildren() {
		if p.Type() != "parameter_declaration" {
			continue
		}
		if id := declaratorIdentifier(p.ChildByFieldName("declarator")); id != "" {
			names = append(names, id)
		}
	}
	return names
}

// declaratorIdentifier walks a (possibly pointer/array-wrapped) declarator down
// to the underlying identifier name.
func declaratorIdentifier(d *ast.Node) string {
	for d != nil {
		switch d.Type() {
		case "identifier":
			return d.Text()
		case "pointer_declarator", "array_declarator":
			d = d.ChildByFieldName("declarator")
		default:
			return ""
		}
	}
	return ""
}

// identifiersIn returns every plain identifier appearing in an expression
// subtree. Used to test whether a size expression references a parameter.
// A pure literal / sizeof expression yields no identifiers.
func identifiersIn(n *ast.Node) []string {
	if n == nil {
		return nil
	}
	var ids []string
	n.Walk(func(c *ast.Node) bool {
		// Do not descend into sizeof(type) — that "identifier" is a type name,
		// not a runtime value, and never carries taint.
		if c.Type() == "sizeof_expression" {
			return false
		}
		if c.Type() == "identifier" {
			ids = append(ids, c.Text())
		}
		return true
	})
	return ids
}

// baseIdentifier returns the underlying object name of a destination argument,
// unwrapping a leading `&` (address-of) and casts so `&buf` and `(char*)buf`
// both resolve to `buf`.
func baseIdentifier(n *ast.Node) string {
	for n != nil {
		switch n.Type() {
		case "identifier":
			return n.Text()
		case "pointer_expression", "parenthesized_expression", "cast_expression":
			named := n.NamedChildren()
			if len(named) == 0 {
				return ""
			}
			n = named[len(named)-1]
		default:
			return ""
		}
	}
	return ""
}

// isFixedSizeBuffer reports whether `name` is declared as a fixed-size array
// (`char name[N]`) somewhere in the enclosing function of node n. A bounded
// stack buffer is what turns a tainted-length copy into an out-of-bounds write.
func (c *cChecker) isFixedSizeBuffer(n *ast.Node, name string) bool {
	var fnDef *ast.Node
	for _, anc := range n.Ancestors() {
		if anc.Type() == "function_definition" {
			fnDef = anc
			break
		}
	}
	if fnDef == nil {
		return false
	}
	found := false
	fnDef.Walk(func(d *ast.Node) bool {
		if found {
			return false
		}
		if d.Type() == "array_declarator" {
			id := d.ChildByFieldName("declarator")
			size := d.ChildByFieldName("size")
			if id != nil && id.Type() == "identifier" && id.Text() == name &&
				size != nil && size.Type() == "number_literal" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// unwrapParens strips a parenthesized_expression wrapper.
func unwrapParens(n *ast.Node) *ast.Node {
	for n != nil && n.Type() == "parenthesized_expression" {
		named := n.NamedChildren()
		if len(named) == 0 {
			return nil
		}
		n = named[0]
	}
	return n
}

// isConstOperand reports whether an arithmetic operand is a compile-time
// constant: a numeric literal, a sizeof expression, or a constant-folded
// product/shift thereof. Such an operand bounds the multiplication and removes
// the integer-overflow concern.
func isConstOperand(n *ast.Node) bool {
	n = unwrapParens(n)
	if n == nil {
		return false
	}
	switch n.Type() {
	case "number_literal", "sizeof_expression", "char_literal":
		return true
	case "binary_expression":
		return isConstOperand(n.ChildByFieldName("left")) &&
			isConstOperand(n.ChildByFieldName("right"))
	}
	return false
}

// anyIn reports whether any element of needles appears in haystack.
func anyIn(needles, haystack []string) bool {
	set := make(map[string]bool, len(haystack))
	for _, h := range haystack {
		set[h] = true
	}
	for _, nd := range needles {
		if set[nd] {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
