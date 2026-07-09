package rubyast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// RubyASTAnalyzer performs AST-based security analysis of Ruby source code.
type RubyASTAnalyzer struct{}

func init() {
	rules.Register(&RubyASTAnalyzer{})
}

func (r *RubyASTAnalyzer) ID() string                      { return "BATOU-RUBYAST" }
func (r *RubyASTAnalyzer) Name() string                    { return "Ruby AST Security Analyzer" }
func (r *RubyASTAnalyzer) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RubyASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangRuby} }
func (r *RubyASTAnalyzer) Description() string {
	return "AST-based analysis of Ruby source for eval/instance_eval/class_eval code injection, system/exec/backtick command injection, send/public_send dynamic dispatch, ERB template injection, and IO.popen command injection."
}

func (r *RubyASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	c := &rubyChecker{
		filePath: ctx.FilePath,
		tree:     tree,
	}
	c.walk()
	return c.findings
}

type rubyChecker struct {
	filePath string
	tree     *ast.Tree
	findings []rules.Finding
}

// evalFuncs are Ruby functions that execute code from strings.
var evalFuncs = map[string]bool{
	"eval":          true,
	"instance_eval": true,
	"class_eval":    true,
	"module_eval":   true,
}

// cmdFuncs are Ruby functions that execute system commands.
var cmdFuncs = map[string]bool{
	"system": true,
	"exec":   true,
}

// dynamicDispatch functions allow calling arbitrary methods.
var dynamicDispatch = map[string]bool{
	"send":        true,
	"public_send": true,
	"__send__":    true,
}

func (c *rubyChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "call" {
			c.checkCall(n)
		}
		return true
	})
}

func (c *rubyChecker) checkCall(n *ast.Node) {
	funcName, receiverName := rubyCallInfo(n)

	// eval/instance_eval/class_eval/module_eval with variable.
	//
	// For bare `eval(...)` we require receiverName == "" — a method
	// call like `redis.eval(script, keys)` (Redis Lua script invocation)
	// or `engine.eval(template)` (template engine) is NOT Ruby's
	// Kernel#eval. Same gate shape as system/exec above. The other
	// *_eval methods are metaprogramming on the receiver itself and
	// legitimately take any receiver.
	if funcName == "eval" && receiverName == "" {
		c.checkEvalCall(n, funcName)
	} else if funcName != "eval" && evalFuncs[funcName] {
		c.checkEvalCall(n, funcName)
	}

	// system/exec with variable.
	//
	// Only fire when the call is a bare Kernel#system / Kernel#exec — i.e.
	// has no receiver. Method calls like DB.exec(sql, params), connection
	// .exec(sql), redis.exec, pipeline.exec are SQL/RPC client helpers that
	// happen to share the name, not OS command execution.
	if cmdFuncs[funcName] && receiverName == "" {
		c.checkCommandCall(n, funcName)
	}

	// send/public_send with variable method name
	if dynamicDispatch[funcName] {
		c.checkDynamicDispatch(n, funcName)
	}

	// IO.popen / Open with variable
	if funcName == "popen" && receiverName == "IO" {
		c.checkIOPopen(n)
	}
	if funcName == "open" && receiverName == "IO" {
		c.checkIOPopen(n)
	}

	// ERB.new with variable template
	if funcName == "new" && receiverName == "ERB" {
		c.checkERBNew(n)
	}
}

// checkEvalCall detects eval/instance_eval/class_eval with non-literal argument.
//
// Demotes (does NOT fire) when the call is a framework DSL pattern:
//   - block argument: class_eval(&block) / instance_eval(&block)
//   - block literal: class_eval { ... } / class_eval do ... end
//   - HEREDOC argument whose interpolations only reference framework-internal
//     identifiers (no params/request/cookies/etc.)
//   - constant string literal with no interpolation
//
// Still fires Critical when the argument is a non-block, non-literal expression
// or when a string/HEREDOC interpolates obvious user-input tokens.
func (c *rubyChecker) checkEvalCall(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	// Pure block form: class_eval { ... } / class_eval do ... end — no argument_list.
	if args == nil {
		// If the call has a block/do_block child, it's the DSL pattern — skip.
		if findChild(n, "block") != nil || findChild(n, "do_block") != nil {
			return
		}
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil {
		return
	}

	// Pattern 1: block-pass argument (&block) — developer-controlled DSL block.
	if firstArg.Type() == "block_argument" {
		return
	}

	// Pattern 2: HEREDOC argument. The heredoc_beginning sits in argument_list,
	// but the actual heredoc_body is a sibling of the call node (tree-sitter
	// quirk for Ruby). Inspect that body for user-input interpolations.
	if firstArg.Type() == "heredoc_beginning" {
		if !heredocBodyHasUserInput(n) {
			return
		}
		// Falls through to fire as Critical.
	} else if firstArg.Type() == "string" {
		// Pattern 3: string literal — fire only if it contains an interpolation
		// that touches user-input tokens.
		if !stringHasUserInput(firstArg) {
			return
		}
		// Falls through to fire.
	} else if isRubyLiteral(firstArg) {
		// Other pure literals (int, symbol, hash, etc.) — safe.
		return
	}

	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-RUBYAST-001",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Code injection via " + funcName + "()",
		Description:   funcName + "() executes a string as Ruby code. If the argument is user-controlled, an attacker can execute arbitrary code on the server.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Avoid " + funcName + "() with user input. Use a safe alternative like a case/when dispatch or method allowlist.",
		CWEID:         "CWE-95",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"injection", "eval", "rce", "ast"},
	})
}

// userInputTokens are identifiers that, when reached inside an interpolation,
// strongly indicate the eval'd string is built from request data.
var userInputTokens = map[string]bool{
	"params":     true,
	"request":    true,
	"cookies":    true,
	"session":    true,
	"env":        true,
	"ENV":        true,
	"STDIN":      true,
	"$stdin":     true,
	"gets":       true,
	"input":      true,
	"user_input": true,
	"body":       true,
}

// heredocBodyHasUserInput finds the heredoc_body sibling of `call` and returns
// true if any interpolation inside it contains a user-input identifier.
func heredocBodyHasUserInput(call *ast.Node) bool {
	parent := call.Parent()
	if parent == nil {
		return false
	}
	siblings := parent.NamedChildren()
	// Find the call in the parent's children, then look forward for heredoc_body.
	idx := -1
	for i, s := range siblings {
		if s == call {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	for i := idx + 1; i < len(siblings); i++ {
		s := siblings[i]
		if s.Type() == "heredoc_body" {
			return interpolationsHaveUserInput(s)
		}
		// Stop scanning once we hit another statement-level node.
		if s.Type() == "call" || s.Type() == "method" || s.Type() == "class" {
			break
		}
	}
	return false
}

// stringHasUserInput returns true if a `string` node contains an interpolation
// that references user-input tokens.
func stringHasUserInput(s *ast.Node) bool {
	return interpolationsHaveUserInput(s)
}

// interpolationsHaveUserInput walks all `interpolation` descendants of root
// and returns true if any one contains an identifier in userInputTokens.
func interpolationsHaveUserInput(root *ast.Node) bool {
	if root == nil {
		return false
	}
	found := false
	root.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		if n.Type() != "interpolation" {
			return true
		}
		// Within this interpolation, look for any identifier/constant matching
		// a user-input token.
		n.Walk(func(inner *ast.Node) bool {
			if found {
				return false
			}
			t := inner.Type()
			if t == "identifier" || t == "constant" || t == "global_variable" {
				if userInputTokens[inner.Text()] {
					found = true
					return false
				}
			}
			return true
		})
		// Don't descend further into the interpolation; the inner Walk above
		// already covered it.
		return false
	})
	return found
}

// checkCommandCall detects system/exec with non-literal argument.
//
// Skips the multi-argument exec-form — `system("cmd", arg1, arg2)` and
// `exec(*args)` invoke the program directly without spawning a shell,
// so user-controlled arg values can't be interpreted as shell
// metacharacters. The scan_harness Ruby sample produced 7 Critical
// FPs on Homebrew/discourse exec-form calls before this skip:
//   exec(*ARGV)                                     # splat first arg
//   system(HOMEBREW_BREW_FILE, *args, verbose:)     # 3+ args
//   system(@redis_server_bin, "--port", port.to_s, ...)
//
// Only the single-argument shell-form is dangerous — that's the case
// where Ruby passes the string to /bin/sh -c and shell metacharacters
// in interpolations can inject commands.
func (c *rubyChecker) checkCommandCall(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	named := args.NamedChildren()
	if len(named) == 0 {
		return
	}
	firstArg := named[0]
	// Multi-arg exec-form: `system("cmd", "arg1", "arg2")`. Ruby
	// invokes the program via execve(2), not via the shell — argv
	// values cannot inject commands.
	if len(named) >= 2 {
		return
	}
	// Single splat: `exec(*args)` / `system(*command)`. The splat
	// expands at runtime; semantically it's still multi-arg exec-form
	// when len(args) >= 2, and even when len(args) == 1 the single
	// element is treated as the entire argv (no shell parsing).
	if firstArg.Type() == "splat_argument" {
		return
	}
	if isRubyLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-RUBYAST-002",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via " + funcName + "()",
		Description:   funcName + "() executes a system command. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use the array form: system('cmd', 'arg1', 'arg2') to avoid shell interpretation, and validate all user input.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "rce", "ast"},
	})
}

// checkDynamicDispatch detects send/public_send with non-literal method name.
// rubyVarLikelyUserInput returns true when an identifier name hints that
// it carries data crossing a trust boundary. Used by checkDynamicDispatch
// to narrow BATOU-RUBYAST-003 — the previous "any variable arg" version
// fired on every metaprogramming send/public_send call (89 hits/repo
// across Ruby OSS samples; e.g. `send synchronized_getter`,
// `singleton_class.send name`, `YAML.send(load_method, ...)`). Without
// flow analysis we can't prove the variable is untrusted, so we lean on
// the conventional naming of "external input" variables in Ruby code.
func rubyVarLikelyUserInput(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range []string{
		"param", "params", "request", "input", "untrust", "external",
		"remote", "header", "query", "body", "client_input",
	} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func (c *rubyChecker) checkDynamicDispatch(n *ast.Node, funcName string) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isRubyLiteral(firstArg) {
		return
	}
	// Also allow symbol literals
	if firstArg.Type() == "simple_symbol" {
		return
	}
	// Narrow: only fire when the method-name variable looks like it
	// could carry user input. Without that the rule fires on routine
	// Ruby metaprogramming (Rails ActiveRecord macros, Sidekiq job
	// dispatch, YAML.send(load_method, ...), etc.).
	//
	// 89 hits/repo across 4 Ruby OSS repos in the scan-harness sample
	// pre-narrow → expected ~0 on developer-controlled metaprogramming
	// shapes post-narrow.
	if firstArg.Type() == "identifier" && !rubyVarLikelyUserInput(firstArg.Text()) {
		return
	}
	// Allowlist-guard suppression: a preceding membership / validation check in
	// the same method that constrains the dispatched method name
	// (`raise unless ALLOWED.include?(name)`, `if ops.exclude?(@op[:type]) raise`)
	// proves the value is one of a known set — the dynamic-dispatch finding is a
	// false positive. Mirrors the Python eval-guard idea for the Ruby dispatch
	// sink class; only suppresses when the guard clearly references this value
	// (see rubyDispatchGuarded).
	if rubyDispatchGuarded(n, firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-RUBYAST-003",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Dynamic method dispatch via " + funcName + "() with variable",
		Description:   funcName + "() calls an arbitrary method on an object. If the method name is user-controlled, an attacker can invoke dangerous methods like system, eval, or destroy.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Validate the method name against an allowlist before calling " + funcName + "().",
		CWEID:         "CWE-470",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"injection", "dynamic-dispatch", "ast"},
	})
}

// checkIOPopen detects IO.popen with non-literal argument.
func (c *rubyChecker) checkIOPopen(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isRubyLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-RUBYAST-004",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Command injection via IO.popen()",
		Description:   "IO.popen() opens a subprocess with a shell command. If the argument is user-controlled, an attacker can execute arbitrary OS commands.",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use the array form: IO.popen(['cmd', 'arg1', 'arg2']) to avoid shell interpretation.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"command-injection", "injection", "rce", "ast"},
	})
}

// checkERBNew detects ERB.new with non-literal template.
func (c *rubyChecker) checkERBNew(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	firstArg := firstNamedChild(args)
	if firstArg == nil || isRubyLiteral(firstArg) {
		return
	}
	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-RUBYAST-005",
		Severity:      rules.Critical,
		SeverityLabel: rules.Critical.String(),
		Title:         "Template injection via ERB.new()",
		Description:   "ERB.new() creates a template from a string. If the template string is user-controlled, an attacker can execute arbitrary Ruby code via ERB template tags (<%= %>).",
		FilePath:      c.filePath,
		LineNumber:    line,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Never pass user input as the ERB template source. Load templates from files and pass user data as variables.",
		CWEID:         "CWE-1336",
		OWASPCategory: "A03:2021-Injection",
		Language:      rules.LangRuby,
		Confidence:    "high",
		Tags:          []string{"template-injection", "ssti", "rce", "ast"},
	})
}

// --- helpers ---

// rubyCallInfo returns the method name and receiver name for a call node.
func rubyCallInfo(n *ast.Node) (method, receiver string) {
	if n == nil || n.Type() != "call" {
		return "", ""
	}
	named := n.NamedChildren()
	// Ruby call node structure varies:
	// Simple call: [identifier("eval"), argument_list]
	// Method call: [identifier("obj")/constant("IO"), identifier("method"), argument_list]
	for i, child := range named {
		if child.Type() == "identifier" || child.Type() == "constant" {
			// If the next named child is also identifier or argument_list
			if i+1 < len(named) {
				next := named[i+1]
				if next.Type() == "identifier" {
					receiver = child.Text()
					method = next.Text()
					return method, receiver
				}
				if next.Type() == "argument_list" {
					method = child.Text()
					return method, ""
				}
			} else {
				// Last named child and it's an identifier - it's the method name
				method = child.Text()
				return method, ""
			}
		}
	}
	return "", ""
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

func isRubyLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "integer", "float", "true", "false", "nil",
		"symbol", "simple_symbol", "hash", "array", "regex":
		return true
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
