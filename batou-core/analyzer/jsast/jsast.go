package jsast

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// JSASTAnalyzer performs AST-based security analysis of JavaScript/TypeScript source.
type JSASTAnalyzer struct{}

func init() {
	rules.Register(&JSASTAnalyzer{})
}

func (j *JSASTAnalyzer) ID() string                      { return "BATOU-JSAST" }
func (j *JSASTAnalyzer) Name() string                    { return "JavaScript AST Security Analyzer" }
func (j *JSASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (j *JSASTAnalyzer) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}
func (j *JSASTAnalyzer) Description() string {
	return "AST-based analysis of JavaScript/TypeScript source for eval injection, innerHTML XSS, child_process command injection, document.write XSS, new Function code injection, and SQL template literal injection."
}

func (j *JSASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJavaScript && ctx.Language != rules.LangTypeScript {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &jsChecker{
		filePath: ctx.FilePath,
		language: ctx.Language,
		tree:     tree,
	}
	c.walk()
	c.checkDynamicProperty()
	return c.findings
}

type jsChecker struct {
	filePath string
	language rules.Language
	tree     *ast.Tree
	findings []rules.Finding
}

func (c *jsChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "call_expression":
			c.checkCallExpression(n)
		case "assignment_expression":
			c.checkAssignment(n)
		case "new_expression":
			c.checkNewExpression(n)
		case "variable_declarator":
			c.checkVariableDeclarator(n)
		}
		return true
	})
}

func (c *jsChecker) checkCallExpression(n *ast.Node) {
	funcName := jsCallName(n)

	// eval(variable)
	if funcName == "eval" {
		c.checkEval(n)
	}

	// document.write(variable)
	if funcName == "document.write" || funcName == "document.writeln" {
		c.checkDocumentWrite(n)
	}

	// child_process.exec / execSync / spawn
	if isChildProcessExec(n) {
		c.checkChildProcess(n)
	}
}

// checkEval detects eval() with non-literal arguments.
func (c *jsChecker) checkEval(n *ast.Node) {
	args := findChild(n, "arguments")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJSLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JSAST-001",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Code injection via eval()",
		Description:   "eval() executes a string as JavaScript code. If the argument is user-controlled, an attacker can execute arbitrary code in the application context.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid eval() entirely. Use JSON.parse() for JSON data, or a safe expression evaluator for math expressions.",
		CWEID:         "CWE-95",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"injection", "eval", "ast"},
	})
}

// checkAssignment detects innerHTML/outerHTML assignments from variables.
func (c *jsChecker) checkAssignment(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	left := named[0]
	right := named[1]

	if left.Type() == "member_expression" {
		propName := memberProperty(left)
		if propName == "innerHTML" || propName == "outerHTML" {
			if isJSSafeHTMLExpression(right) {
				return
			}
			line := int(n.StartRow()) + 1
			c.findings = append(c.findings, rules.Finding{
				RuleID:        "BATOU-JSAST-002",
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "XSS via " + propName + " assignment",
				Description:   propName + " is assigned a non-literal value. If the value contains user input, this enables cross-site scripting (XSS) attacks.",
				FilePath:      c.filePath,
				LineNumber:    line,
				MatchedText:   truncate(n.Text(), 200),
				Suggestion:    "Use textContent instead of " + propName + " for text content, or use DOMPurify.sanitize() before setting HTML.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      c.language,
				Confidence:    "high",
				Tags:          []string{"xss", "dom", "ast"},
			})
		}
	}
}

// checkDocumentWrite detects document.write with non-literal arguments.
func (c *jsChecker) checkDocumentWrite(n *ast.Node) {
	args := findChild(n, "arguments")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJSLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JSAST-003",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "XSS via document.write()",
		Description:   "document.write() injects content directly into the DOM. If the argument contains user input, this enables cross-site scripting (XSS) attacks.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid document.write(). Use DOM manipulation methods (createElement, textContent) instead.",
		CWEID:         "CWE-79",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"xss", "dom", "ast"},
	})
}

// checkChildProcess detects child_process.exec/execSync with variable command.
func (c *jsChecker) checkChildProcess(n *ast.Node) {
	args := findChild(n, "arguments")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isJSLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JSAST-004",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via child_process",
		Description:   "A child_process execution function is called with a non-literal command. If the command contains user input, an attacker can execute arbitrary system commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use child_process.execFile() or child_process.spawn() with an array of arguments instead of a command string.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "rce", "ast"},
	})
}

// checkNewExpression detects new Function(variable).
func (c *jsChecker) checkNewExpression(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) == 0 {
		return
	}
	constructor := named[0]
	if constructor.Type() == "identifier" && constructor.Text() == "Function" {
		args := findChild(n, "arguments")
		if args == nil {
			return
		}
		for _, arg := range args.NamedChildren() {
			if !isJSLiteral(arg) {
				line := int(n.StartRow()) + 1
				c.findings = append(c.findings, rules.Finding{
					RuleID:        "BATOU-JSAST-005",
					Severity:      rules.Critical,
					SeverityLabel: rules.Critical.String(),
					Title:         "Code injection via new Function()",
					Description:   "new Function() creates a function from a string, similar to eval(). If the argument is user-controlled, an attacker can execute arbitrary code.",
					FilePath:      c.filePath,
					LineNumber:    line,
					MatchedText:   truncate(n.Text(), 200),
					Suggestion:    "Avoid new Function() with dynamic content. Use a safe expression evaluator or precompiled functions.",
					CWEID:         "CWE-95",
					OWASPCategory: "A03:2021-Injection",
					Language:      c.language,
					Confidence:    "high",
					Tags:          []string{"injection", "eval", "ast"},
				})
				return
			}
		}
	}
}

// checkVariableDeclarator detects SQL template literals with interpolation.
func (c *jsChecker) checkVariableDeclarator(n *ast.Node) {
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	value := named[1]

	// Check for template_string with SQL content and interpolation
	if value.Type() == "template_string" {
		c.checkSQLTemplateString(value)
	}

	// Check for binary_expression (string concat) with SQL content
	if value.Type() == "binary_expression" {
		c.checkSQLBinaryExpression(value)
	}
}

func (c *jsChecker) checkSQLTemplateString(n *ast.Node) {
	// Only the *literal* parts of the template — `string_fragment` children —
	// count as the "SQL text". The interpolated `${...}` parts are the
	// dynamic values; including them in the keyword scan was the source of
	// FPs (`\`done ${SELECT_OPTION}\``-style identifiers, etc.).
	var litParts []string
	hasInterpolation := false
	n.Walk(func(child *ast.Node) bool {
		switch child.Type() {
		case "string_fragment":
			litParts = append(litParts, child.Text())
		case "template_substitution":
			hasInterpolation = true
		}
		return true
	})
	if !hasInterpolation {
		return
	}
	if !looksLikeSQLFragment(strings.Join(litParts, " ")) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JSAST-006",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "SQL injection via template literal interpolation",
		Description:   "A SQL query is built using a template literal with ${} interpolation. If the interpolated value contains user input, this enables SQL injection.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId]).",
		CWEID:         "CWE-89",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"sql-injection", "injection", "ast"},
	})
}

// checkSQLBinaryExpression flags `+`-concatenation that builds a SQL string.
// E6-T5: this used to call strings.Contains-style keyword checks on the whole
// expression text, which fired on numeric addition like
// `latestSelectedResourceIndex + step` (the `Selected` substring) and on log
// messages like `"Update failed for " + id`. The check is now AST-grounded:
//
//   - the binary operator must be `+`;
//   - the operands are flattened (a `+`-chain nests as nested
//     binary_expressions), and only `string` literal operands contribute to
//     the "SQL text" — their literal value (sans quotes), not identifiers or
//     calls;
//   - that concatenated literal text must look like a SQL fragment
//     (looksLikeSQLFragment: a DML verb paired with a structural keyword, or
//     a standalone structural keyword that's rare in prose) — a bare verb
//     like "Update"/"Delete" in an English sentence does not qualify;
//   - at least one operand must be non-literal (the dynamic value being
//     concatenated in) — a `+` between two numeric/identifier operands never
//     fires.
func (c *jsChecker) checkSQLBinaryExpression(n *ast.Node) {
	if jsBinaryOperator(n) != "+" {
		return
	}
	operands := flattenJSConcat(n)
	var litParts []string
	hasDynamic := false
	for _, op := range operands {
		switch op.Type() {
		case "string":
			litParts = append(litParts, jsStringValue(op))
		case "number", "true", "false", "null", "undefined":
			// static, non-string operand — contributes nothing
		default:
			// identifier, member_expression, call_expression, etc.
			hasDynamic = true
		}
	}
	if !hasDynamic {
		return
	}
	if !looksLikeSQLFragment(strings.Join(litParts, " ")) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-JSAST-006",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "SQL injection via string concatenation",
		Description:   "A SQL query is built by concatenating strings with variables. This enables SQL injection attacks.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId]).",
		CWEID:         "CWE-89",
		OWASPCategory: "A03:2021-Injection",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"sql-injection", "injection", "ast"},
	})
}

// flattenJSConcat returns the leaf operands of a `+`-chain. A chain like
// `"a" + b + "c"` parses as `(("a" + b) + "c")` — a nested binary_expression
// whose left is itself a `+` binary_expression — so we recurse only through
// `+`-operator binary_expressions and treat everything else as a leaf.
func flattenJSConcat(n *ast.Node) []*ast.Node {
	if n == nil {
		return nil
	}
	if n.Type() == "binary_expression" && jsBinaryOperator(n) == "+" {
		var out []*ast.Node
		for _, side := range []*ast.Node{n.ChildByFieldName("left"), n.ChildByFieldName("right")} {
			out = append(out, flattenJSConcat(side)...)
		}
		return out
	}
	if n.Type() == "parenthesized_expression" {
		if inner := firstNamedChild(n); inner != nil {
			return flattenJSConcat(inner)
		}
	}
	return []*ast.Node{n}
}

// jsBinaryOperator returns the operator token of a binary_expression
// (e.g. "+", "-", "*", "&&"), or "" if it can't be determined.
func jsBinaryOperator(n *ast.Node) string {
	if n == nil || n.Type() != "binary_expression" {
		return ""
	}
	if op := n.ChildByFieldName("operator"); op != nil {
		return op.Text()
	}
	return ""
}

// jsStringValue returns the textual value of a `string` literal node,
// concatenating its `string_fragment` children (so escape sequences and the
// surrounding quote characters are excluded). An empty string is returned for
// quote-only literals like `”`.
func jsStringValue(n *ast.Node) string {
	if n == nil {
		return ""
	}
	var parts []string
	for _, ch := range n.NamedChildren() {
		if ch.Type() == "string_fragment" {
			parts = append(parts, ch.Text())
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "")
	}
	// No string_fragment child (empty literal, or a parser that doesn't emit
	// fragments) — fall back to trimming the surrounding quotes.
	t := n.Text()
	if len(t) >= 2 {
		q := t[0]
		if (q == '\'' || q == '"' || q == '`') && t[len(t)-1] == q {
			return t[1 : len(t)-1]
		}
	}
	return t
}

// --- helpers ---

func jsCallName(n *ast.Node) string {
	if n == nil || n.Type() != "call_expression" {
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
	case "member_expression":
		obj := firstNamedChild(funcNode)
		prop := memberProperty(funcNode)
		if obj != nil && prop != "" {
			return obj.Text() + "." + prop
		}
	}
	return ""
}

func memberProperty(n *ast.Node) string {
	if n == nil || n.Type() != "member_expression" {
		return ""
	}
	named := n.NamedChildren()
	for _, child := range named {
		if child.Type() == "property_identifier" {
			return child.Text()
		}
	}
	return ""
}

func isChildProcessExec(n *ast.Node) bool {
	text := n.Text()
	if !strings.Contains(text, "exec") {
		return false
	}
	return strings.Contains(text, "child_process") ||
		strings.Contains(text, "require('child_process')") ||
		strings.Contains(text, "require(\"child_process\")")
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

func isJSLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "number", "true", "false", "null", "undefined":
		return true
	}
	return false
}

// jsSafeHTMLHelpers lists callable names that, when they appear as the
// right-hand side of an innerHTML/outerHTML assignment, mean the value is
// not attacker-derived raw HTML. svg() is the standard typed-icon helper;
// the others are common app-level wrappers around DOMPurify / static
// templates, localization helpers (which return developer-authored strings
// keyed by a constant message id), typed-icon builders (a fixed snippet keyed
// by a constant icon name), and numeric-coercion functions (whose result is a
// Number, never raw HTML).
var jsSafeHTMLHelpers = map[string]bool{
	"svg":           true, // typed SVG-icon constructor (Gitea, Octicon-style)
	"html":          true, // htm-style tagged template helper (returns vnode/string)
	"htmlsafe":      true, // hand-written sanitizer
	"sanitize":      true,
	"sanitizehtml":  true,
	"sanitize_html": true,
	"dompurify":     true, // DOMPurify(input) one-liner alias
	"trustedhtml":   true, // Trusted Types policy wrapper
	"sanitizedhtml": true,
	// Localization helpers: the visible text is a developer-authored template
	// selected by a constant message id, not attacker-controlled HTML.
	"i18n":      true, // Ember/Discourse I18n.t alias
	"t":         true, // Nextcloud / i18next translate
	"translate": true,
	"gettext":   true,
	// Typed-icon / static-fragment builders: a fixed SVG/HTML snippet keyed by
	// a constant icon name.
	"iconhtml":         true, // Discourse iconHTML("name")
	"rendericon":       true,
	"escapeexpression": true, // Handlebars / Ember escapeExpression
	// Numeric-coercion functions: the result is a Number, never HTML.
	"parseint":   true,
	"parsefloat": true,
	"number":     true,
}

// isJSSafeHTMLExpression returns true when the right-hand side of an
// `el.innerHTML = X` assignment is one of:
//
//   - a plain literal (string/number/etc.)
//   - a parenthesized safe expression
//   - a template literal with no ${} substitutions, or whose every
//     substitution is itself a safe expression
//   - a tagged template literal with a safe tag (html`...`, svg`...`)
//   - a binary expression whose every operand is itself safe (covers
//     `iconHTML("x") + " " + i18n("y")` and numeric `parseInt(s) + 1`)
//   - a call to a known safe-HTML helper (svg(...), sanitize(...), i18n(...),
//     iconHTML(...), parseInt(...), ...)
//   - a call to <something>.sanitize(...) or <something>.escape(...)
//
// This is NOT a taint analysis — the analyzer has no taint engine. It only
// recognises RHS shapes that are *constant or developer-authored by
// construction* and so cannot carry attacker HTML, eliminating the dominant
// false-positive classes (numeric results, i18n/icon builders, literals)
// while still firing on bare variables, member accesses, and templates that
// interpolate a variable.
//
// Conservative: returns false for anything it doesn't recognise.
func isJSSafeHTMLExpression(n *ast.Node) bool {
	if n == nil {
		return false
	}
	if isJSLiteral(n) {
		return true
	}
	switch n.Type() {
	case "parenthesized_expression":
		// `(expr)` — unwrap and judge the inner expression.
		if inner := firstNamedChild(n); inner != nil {
			return isJSSafeHTMLExpression(inner)
		}
		return false
	case "template_string", "template_literal":
		// Tree-sitter exposes ${...} as a `template_substitution` named child.
		// A template_string with NO substitutions is a constant; one WITH
		// substitutions is safe only when every interpolated expression is
		// itself safe (e.g. `${iconHTML("pause")}${iconHTML("play")}`). A bare
		// `${tagText}` or `${emojiUnescape(data.text)}` is unsafe and fires.
		for _, child := range n.NamedChildren() {
			if child.Type() == "template_substitution" {
				expr := firstNamedChild(child)
				if !isJSSafeHTMLExpression(expr) {
					return false
				}
			}
		}
		return true
	case "binary_expression":
		// Concatenation / arithmetic. Safe only when both operands are safe.
		// Covers `iconHTML("x") + " " + i18n("y")` (nested binary, all safe
		// builders/literals) and numeric `parseInt(html, 10) + 1`. A `"<p>" +
		// userVar` still fires because the variable operand is not safe.
		named := n.NamedChildren()
		if len(named) < 2 {
			return false
		}
		return isJSSafeHTMLExpression(named[0]) && isJSSafeHTMLExpression(named[1])
	case "tagged_template_expression", "tagged_template_literal":
		// tag is the first named child, template is the second.
		named := n.NamedChildren()
		if len(named) == 0 {
			return false
		}
		tagName := strings.ToLower(strings.TrimSpace(named[0].Text()))
		// Accept html`...` and svg`...` regardless of substitutions — these
		// htm/lit-html style tags handle their own escaping. Demote
		// confidence elsewhere if the project disagrees.
		return tagName == "html" || tagName == "svg"
	case "call_expression":
		// Recognise svg('octicon-...'), htmlSafe(x), sanitize(x), iconHTML(x),
		// i18n(x), parseInt(x), etc.
		named := n.NamedChildren()
		if len(named) == 0 {
			return false
		}
		callee := named[0]
		var name string
		switch callee.Type() {
		case "identifier":
			name = strings.ToLower(strings.TrimSpace(callee.Text()))
		case "member_expression":
			// foo.sanitize(x) / DOMPurify.sanitize(x) — match on the method.
			name = strings.ToLower(strings.TrimSpace(memberProperty(callee)))
		}
		if jsSafeHTMLHelpers[name] {
			return true
		}
		// Method-name-suffix heuristic: anything ending in "sanitize",
		// "purify", or "escape" is, by convention, a sanitizer.
		if strings.HasSuffix(name, "sanitize") || strings.HasSuffix(name, "purify") || strings.HasSuffix(name, "escape") {
			return true
		}
	}
	return false
}

// sqlFragmentShape recognises text that has the *shape* of a SQL statement
// or clause, not merely an English word that happens to also be a SQL verb.
//
// SQL keywords are whitespace-or-quote delimited (`SELECT *`, `* FROM x`,
// `WHERE id`), never adjacent to `.`, `-`, `/`, or other identifier/path
// characters. RE2 has no lookbehind, so the leading delimiter is the
// alternation `(^|[\s'"`+])` (string start, whitespace, quote, or `+` from
// concat); the trailing delimiter is a char class. These delimiters keep
// `Selected`/`selectedIndex` from matching `SELECT`, `inserted` from
// matching `INSERT`, and path/CSS fragments like `/select-all/` or
// `select-from-here` from matching `SELECT ... FROM`.
//
// On top of the boundaries, a bare DML verb is not enough: it must be paired
// with a structural keyword (FROM/INTO/SET/WHERE/VALUES), or be a structural
// keyword that is itself rare in prose (a JOIN variant, UNION SELECT,
// GROUP/ORDER BY), or a WHERE-comparison, or a DDL statement. Bounded
// repetition (`{0,N}?`) is supported by RE2, so the "verb ... keyword"
// shapes are expressed directly.
const (
	// sqlKwL is the leading delimiter for a SQL keyword.
	sqlKwL = "(^|[\\s'\"`+])"
	// sqlKwR is the trailing delimiter for a SQL keyword.
	sqlKwR = "([\\s,;)('\"`+*=<>]|$)"
)

var sqlFragmentShape = regexp.MustCompile(`(?i)(` +
	sqlKwL + `(SELECT|DELETE)` + sqlKwR + `[\s\S]{0,200}?` + sqlKwL + `FROM` + sqlKwR +
	`|` + sqlKwL + `INSERT` + sqlKwR + `[\s\S]{0,40}?` + sqlKwL + `INTO` + sqlKwR +
	`|` + sqlKwL + `UPDATE` + sqlKwR + `[\s\S]{0,80}?` + sqlKwL + `SET` + sqlKwR +
	`|` + sqlKwL + `WHERE` + sqlKwR + `[\s\S]{0,200}?(=|<|>|!=|` + sqlKwL + `LIKE\s|` + sqlKwL + `IN\s*\(|` + sqlKwL + `IS\s+(NOT\s+)?NULL)` +
	`|` + sqlKwL + `(LEFT|RIGHT|INNER|OUTER|CROSS|FULL)\s+(OUTER\s+)?JOIN` + sqlKwR +
	`|` + sqlKwL + `UNION\s+(ALL\s+)?SELECT` + sqlKwR +
	`|` + sqlKwL + `GROUP\s+BY` + sqlKwR + `|` + sqlKwL + `ORDER\s+BY` + sqlKwR +
	`|` + sqlKwL + `INTO` + sqlKwR + `[\s\S]{0,80}?` + sqlKwL + `VALUES` + sqlKwR +
	`|` + sqlKwL + `TRUNCATE\s+TABLE` + sqlKwR +
	`|` + sqlKwL + `DROP\s+(TABLE|INDEX|DATABASE|VIEW|SCHEMA)` + sqlKwR +
	`|` + sqlKwL + `ALTER\s+TABLE` + sqlKwR +
	`|` + sqlKwL + `CREATE\s+(TABLE|INDEX|VIEW|DATABASE|SCHEMA)` + sqlKwR +
	`)`)

// looksLikeSQLFragment reports whether s (the concatenated *literal* parts of
// a template literal or string concat) has the shape of a SQL fragment.
func looksLikeSQLFragment(s string) bool {
	return sqlFragmentShape.MatchString(s)
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
