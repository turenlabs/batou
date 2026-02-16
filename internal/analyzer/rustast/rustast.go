package rustast

import (
	"strings"

	"github.com/turenlabs/batou/internal/ast"
	"github.com/turenlabs/batou/internal/rules"
)

// RustASTAnalyzer performs AST-based security analysis of Rust source code.
type RustASTAnalyzer struct{}

func init() {
	rules.Register(&RustASTAnalyzer{})
}

func (r *RustASTAnalyzer) ID() string                        { return "BATOU-RUST-AST" }
func (r *RustASTAnalyzer) Name() string                      { return "Rust AST Security Analyzer" }
func (r *RustASTAnalyzer) DefaultSeverity() rules.Severity   { return rules.High }
func (r *RustASTAnalyzer) Languages() []rules.Language        { return []rules.Language{rules.LangRust} }
func (r *RustASTAnalyzer) Description() string {
	return "AST-based analysis of Rust code for unsafe blocks, command injection, SQL formatting, and unsafe unwrap usage."
}

func (r *RustASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRust {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &rustChecker{
		tree:     tree,
		filePath: ctx.FilePath,
		content:  ctx.Content,
	}
	c.walk()
	return c.findings
}

type rustChecker struct {
	tree     *ast.Tree
	filePath string
	content  string
	findings []rules.Finding
}

func (c *rustChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "unsafe_block":
			c.checkUnsafeBlock(n)
		case "macro_invocation":
			c.checkFormatSQLInjection(n)
		case "call_expression":
			c.checkCommandInjection(n)
			c.checkUnsafeUnwrap(n)
		}
		return true
	})
}

// checkUnsafeBlock flags unsafe blocks containing dangerous operations:
// raw pointer dereferences (*ptr) or transmute calls.
func (c *rustChecker) checkUnsafeBlock(n *ast.Node) {
	hasTransmute := false
	hasRawPtrDeref := false

	n.Walk(func(child *ast.Node) bool {
		switch child.Type() {
		case "scoped_identifier":
			if strings.Contains(child.Text(), "transmute") {
				hasTransmute = true
			}
		case "unary_expression":
			text := child.Text()
			if strings.HasPrefix(text, "*") {
				// Check if dereferencing a raw pointer
				hasRawPtrDeref = true
			}
		}
		return true
	})

	if hasTransmute {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-RUST-AST-001",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "std::mem::transmute in unsafe block",
			Description:   "transmute reinterprets bits of one type as another, bypassing all type safety. Incorrect use causes undefined behavior.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Use safe alternatives like From/Into traits, as_bytes(), to_ne_bytes(), or TryFrom.",
			CWEID:         "CWE-843",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
			Language:      rules.LangRust,
			Confidence:    "high",
			Tags:          []string{"unsafe", "memory-safety", "transmute"},
		})
	}

	if hasRawPtrDeref {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-RUST-AST-001",
			Severity:      rules.High,
			SeverityLabel: rules.High.String(),
			Title:         "Raw pointer dereference in unsafe block",
			Description:   "Dereferencing a raw pointer can cause undefined behavior if the pointer is null, dangling, or misaligned.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(n.Text(), 200),
			Suggestion:    "Ensure pointer validity before dereferencing. Prefer safe references (&T, &mut T) when possible.",
			CWEID:         "CWE-476",
			OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
			Language:      rules.LangRust,
			Confidence:    "high",
			Tags:          []string{"unsafe", "memory-safety", "raw-pointer"},
		})
	}
}

// checkFormatSQLInjection detects format!() macros with SQL content containing
// interpolation placeholders ({}).
func (c *rustChecker) checkFormatSQLInjection(n *ast.Node) {
	// macro_invocation has an identifier child with the macro name
	named := n.NamedChildren()
	if len(named) < 2 {
		return
	}
	macroName := ""
	for _, child := range named {
		if child.Type() == "identifier" {
			macroName = child.Text()
			break
		}
	}
	if macroName != "format" {
		return
	}

	// Look for a string_literal inside the token_tree
	for _, child := range named {
		if child.Type() == "token_tree" {
			child.Walk(func(inner *ast.Node) bool {
				if inner.Type() == "string_content" {
					text := strings.ToUpper(inner.Text())
					if containsSQLKeyword(text) && strings.Contains(inner.Text(), "{}") {
						c.findings = append(c.findings, rules.Finding{
							RuleID:        "BATOU-RUST-AST-002",
							Severity:      rules.Critical,
							SeverityLabel: rules.Critical.String(),
							Title:         "SQL injection via format!() macro",
							Description:   "Building SQL queries with format!() and variable interpolation enables SQL injection attacks.",
							FilePath:      c.filePath,
							LineNumber:    int(n.StartRow()) + 1,
							MatchedText:   truncate(n.Text(), 200),
							Suggestion:    "Use parameterized queries with query builder or ORM (e.g., sqlx::query with bind parameters).",
							CWEID:         "CWE-89",
							OWASPCategory: "A03:2021-Injection",
							Language:      rules.LangRust,
							Confidence:    "high",
							Tags:          []string{"sql-injection", "injection"},
						})
						return false
					}
				}
				return true
			})
		}
	}
}

// checkCommandInjection detects Command::new().arg() chains with variable arguments,
// and std::process::Command with shell execution.
func (c *rustChecker) checkCommandInjection(n *ast.Node) {
	text := n.Text()

	// Look for Command::new patterns with method chains
	if !strings.Contains(text, "Command") {
		return
	}

	// Check for the full text to contain Command::new
	if !strings.Contains(text, "::new") {
		return
	}

	// Find if there's a shell invocation: Command::new("sh") or Command::new("bash")
	isShell := false
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "string_content" {
			t := child.Text()
			if t == "sh" || t == "bash" || t == "/bin/sh" || t == "/bin/bash" {
				isShell = true
				return false
			}
		}
		return true
	})

	// Check if .arg() is called with a non-literal
	hasVarArg := false
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "field_identifier" && child.Text() == "arg" {
			// Look at the arguments of the parent call_expression
			parent := child.Parent()
			if parent != nil {
				gp := parent.Parent()
				if gp != nil && gp.Type() == "call_expression" {
					for _, gpChild := range gp.NamedChildren() {
						if gpChild.Type() == "arguments" {
							for _, arg := range gpChild.NamedChildren() {
								if arg.Type() == "identifier" {
									hasVarArg = true
								}
							}
						}
					}
				}
			}
		}
		return true
	})

	if isShell && hasVarArg {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-RUST-AST-003",
			Severity:      rules.Critical,
			SeverityLabel: rules.Critical.String(),
			Title:         "Shell command injection via Command::new",
			Description:   "Passing variable arguments to a shell (sh/bash) via Command::new enables command injection.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(text, 200),
			Suggestion:    "Avoid shell invocation. Use Command::new with the program directly and pass arguments via .arg().",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangRust,
			Confidence:    "high",
			Tags:          []string{"command-injection", "injection", "rce"},
		})
	} else if hasVarArg {
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-RUST-AST-003",
			Severity:      rules.High,
			SeverityLabel: rules.High.String(),
			Title:         "Command execution with variable arguments",
			Description:   "Variable arguments to std::process::Command may allow argument injection if attacker-controlled.",
			FilePath:      c.filePath,
			LineNumber:    int(n.StartRow()) + 1,
			MatchedText:   truncate(text, 200),
			Suggestion:    "Validate and sanitize all variable arguments passed to Command.",
			CWEID:         "CWE-78",
			OWASPCategory: "A03:2021-Injection",
			Language:      rules.LangRust,
			Confidence:    "medium",
			Tags:          []string{"command-injection", "injection"},
		})
	}
}

// checkUnsafeUnwrap detects .unwrap() on call expressions that might come from
// network/user input contexts.
func (c *rustChecker) checkUnsafeUnwrap(n *ast.Node) {
	// call_expression > field_expression > field_identifier == "unwrap"
	named := n.NamedChildren()
	if len(named) < 1 {
		return
	}
	// Check if it's a method call ending in .unwrap()
	fieldExpr := named[0]
	if fieldExpr.Type() != "field_expression" {
		return
	}

	fChildren := fieldExpr.NamedChildren()
	if len(fChildren) < 2 {
		return
	}
	methodName := fChildren[len(fChildren)-1]
	if methodName.Type() != "field_identifier" || methodName.Text() != "unwrap" {
		return
	}

	// Check if the receiver is a function call (not just a simple variable)
	receiver := fChildren[0]
	if receiver.Type() != "call_expression" {
		return
	}

	receiverText := receiver.Text()
	// Only flag unwrap on network/IO/parsing calls
	dangerousPatterns := []string{
		"parse", "read", "recv", "accept", "connect",
		"get", "post", "fetch", "request", "from_str",
		"from_utf8", "decode", "deserialize",
	}
	lowerText := strings.ToLower(receiverText)
	isDangerous := false
	for _, p := range dangerousPatterns {
		if strings.Contains(lowerText, p) {
			isDangerous = true
			break
		}
	}
	if !isDangerous {
		return
	}

	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-RUST-AST-004",
		Severity:      rules.Medium,
		SeverityLabel: rules.Medium.String(),
		Title:         "Unsafe .unwrap() on fallible operation",
		Description:   "Calling .unwrap() on a Result/Option from a network, I/O, or parsing operation will panic on failure, potentially causing a denial of service.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use proper error handling with match, if let, or the ? operator instead of .unwrap().",
		CWEID:         "CWE-252",
		OWASPCategory: "A04:2021-Insecure Design",
		Language:      rules.LangRust,
		Confidence:    "medium",
		Tags:          []string{"error-handling", "unwrap", "panic"},
	})
}

func containsSQLKeyword(upper string) bool {
	keywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC"}
	for _, kw := range keywords {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
