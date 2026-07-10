// Package shellast performs tree-sitter (bash grammar) AST-based security
// analysis of Shell/Bash scripts.
//
// Shell is unusual among Batou's supported languages: a command is just a bare
// word followed by word-split arguments, with no method receiver to anchor a
// taint sink, and the variables a script consumes (`$userpath`, `$dst`, a CI
// env var) are frequently NOT among the catalog's known taint *sources*. As a
// result the generic taint walker (tsflow) is nearly inert on the most common
// shell-injection shapes: an unquoted expansion that the shell word-splits and
// glob-expands before the command ever runs, or an `eval`/`source`/`sh -c`
// that re-parses a string as code.
//
// Two distinct rule families live here, with deliberately different gating:
//
//   - eval / source / sh -c of *dynamic* data (rules 002/003/004) re-parse a
//     runtime string as shell CODE. That is dangerous whenever the data is
//     non-literal regardless of its provenance — a developer who eval's a
//     constructed string has already lost the argument. These remain purely
//     structural (any dynamic argument), mirroring analyzer/luaast's loadstring
//     handling. They were NOT part of the real-repo false-positive flood.
//
//   - unquoted word-splitting (rule 001) and a variable command name (rule 005)
//     are dangerous only when the expanded value is EXTERNALLY derived. On real
//     build/test scripts almost every `cp $TMP_FILE …`, `$CLANG_FORMAT …`,
//     `kill $(cat ${PID_FILE})`, `git archive $TAG …` uses a LOCAL script
//     variable (a constant, a path literal, $(mktemp), a positional build
//     argument) — flagging those produced 39 findings on redis, ~all false
//     positives. These two rules are therefore GATED: they emit only when a
//     bounded, intra-file external-origin analysis can establish that the
//     expanded variable plausibly carries user/attacker-controlled input —
//     mirroring how analyzer/pyast reasons about a sink variable's last
//     assignment (PySinkVarIsSafe) before emitting.
//
// It is gated strictly to rules.LangShell.
package shellast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// ShellASTAnalyzer performs AST-based security analysis of Shell/Bash source.
type ShellASTAnalyzer struct{}

func init() {
	rules.Register(&ShellASTAnalyzer{})
}

func (s *ShellASTAnalyzer) ID() string                      { return "BATOU-SH-AST" }
func (s *ShellASTAnalyzer) Name() string                    { return "Shell AST Security Analyzer" }
func (s *ShellASTAnalyzer) DefaultSeverity() rules.Severity { return rules.High }
func (s *ShellASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangShell} }
func (s *ShellASTAnalyzer) Description() string {
	return "AST-based analysis of Shell/Bash for unquoted-variable word-splitting & glob injection, eval/source of dynamic data, sh -c inline-code execution, and variable-named command execution — structural detection independent of taint sources."
}

func (s *ShellASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangShell {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	root := tree.Root()
	c := &shellChecker{filePath: ctx.FilePath}
	// First pass: classify every variable's plausible external origin from the
	// whole file (assignments, `read`, env-var derivation, fetch substitution).
	// The word-split (001) and variable-command-name (005) rules consult this
	// map so they fire only on externally-derived operands — not the ubiquitous
	// local/constant/positional build-script variables that caused the flood.
	c.external = buildExternalOrigin(root)
	c.walk(root)
	return c.findings
}

type shellChecker struct {
	filePath string
	findings []rules.Finding
	// external maps a bare variable name (e.g. "userpath", "QUERY_STRING") to
	// true when intra-file analysis established it as plausibly user-controlled.
	external map[string]bool
}

func (c *shellChecker) walk(root *ast.Node) {
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() == "command" {
			c.checkCommand(n)
		}
		return true
	})
}

// commandName returns the (trimmed, lower-cased) command word of a `command`
// node, e.g. "eval", "cp", "." — and also the raw (un-lowered) text so callers
// that care about exact tokens still have it.
func commandName(n *ast.Node) (lower, raw string) {
	for _, child := range n.NamedChildren() {
		if child.Type() == "command_name" {
			raw = strings.TrimSpace(child.Text())
			return strings.ToLower(raw), raw
		}
	}
	return "", ""
}

// commandNameNode returns the command_name child node, or nil.
func commandNameNode(n *ast.Node) *ast.Node {
	for _, child := range n.NamedChildren() {
		if child.Type() == "command_name" {
			return child
		}
	}
	return nil
}

// allChildren returns every child node (named and anonymous) of n. The ast.Node
// API exposes Child(i)/ChildCount but no slice accessor for all children, so we
// materialise one here. Argument nodes in the bash grammar are named, but we
// iterate all children to be robust to grammar quirks.
func allChildren(n *ast.Node) []*ast.Node {
	out := make([]*ast.Node, 0, n.ChildCount())
	for i := 0; i < n.ChildCount(); i++ {
		out = append(out, n.Child(i))
	}
	return out
}

// expansionNodeTypes are the bash node types that represent a parameter/variable
// expansion ($x, ${x}) — the things the shell word-splits & glob-expands when
// they appear *unquoted*.
func isExpansionNode(t string) bool {
	switch t {
	case "simple_expansion", "expansion":
		return true
	}
	return false
}

// isDynamicNode reports whether a node represents data computed at runtime
// (a variable expansion or a command/process substitution) — i.e. NOT a fixed
// literal. Used to decide whether eval/source/sh -c is being handed code that
// could be attacker-influenced.
func isDynamicNode(t string) bool {
	switch t {
	case "simple_expansion", "expansion", "command_substitution", "process_substitution":
		return true
	}
	return false
}

// argHasDynamic reports whether an argument node (which may be a bare
// expansion, a quoted string wrapping expansions, or a concatenation) contains
// any dynamic (expansion / substitution) sub-node.
func argHasDynamic(arg *ast.Node) bool {
	found := false
	arg.Walk(func(inner *ast.Node) bool {
		if found {
			return false
		}
		if isDynamicNode(inner.Type()) {
			found = true
			return false
		}
		return true
	})
	return found
}

// unquotedExpansionArgs returns the argument-position child nodes of a command
// that are an *unquoted* expansion (bare $x / ${x}, possibly inside a
// concatenation like ${dir}/sub). Quoted forms ("$x", '$x') are excluded —
// quoting is precisely the defence against word-splitting & globbing.
func unquotedExpansionArgs(n *ast.Node) []*ast.Node {
	var out []*ast.Node
	for _, child := range allChildren(n) {
		if child.FieldName() != "argument" {
			continue
		}
		switch {
		case isExpansionNode(child.Type()):
			// Bare $x / ${x} directly in argument position → unquoted.
			out = append(out, child)
		case child.Type() == "concatenation":
			// e.g. ${dir}/file or $base.$ext — a concatenation that splices an
			// unquoted expansion with adjacent words. If any *direct* child is a
			// bare expansion (not wrapped in a string), it is unquoted.
			for _, cc := range child.NamedChildren() {
				if isExpansionNode(cc.Type()) {
					out = append(out, child)
					break
				}
			}
		}
	}
	return out
}

// wordSplitDangerousCmds is the curated allow-list of commands for which an
// unquoted, word-splittable / glob-expandable argument is a genuine security
// concern (path traversal, arbitrary file access, command/argument injection,
// SSRF). Restricting rule 001 to these keeps the ubiquitous-but-low-value
// `echo $x` / `printf $fmt` cases quiet while still catching the high-impact
// shapes the probe targets (`cp $userpath /dest`).
var wordSplitDangerousCmds = map[string]bool{
	// filesystem mutation / access (CWE-22 / CWE-78 / CWE-88)
	"cp": true, "mv": true, "rm": true, "ln": true, "cat": true, "dd": true,
	"chmod": true, "chown": true, "chgrp": true, "touch": true, "mkdir": true,
	"rmdir": true, "install": true, "tee": true, "truncate": true, "shred": true,
	"rsync": true, "tar": true, "unzip": true, "zip": true, "gzip": true,
	"find": true, "xargs": true,
	// command execution wrappers (CWE-78)
	"bash": true, "sh": true, "dash": true, "ksh": true, "zsh": true,
	"env": true, "nohup": true, "timeout": true, "sudo": true, "exec": true,
	"ssh": true, "su": true, "setsid": true, "nice": true, "ionice": true,
	// network fetch (CWE-918 / CWE-78)
	"curl": true, "wget": true, "scp": true, "sftp": true, "nc": true,
	"ncat": true, "netcat": true, "ftp": true, "git": true,
	// package / interpreter invocation (CWE-78)
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true,
	"php": true, "awk": true,
}

// --- External-origin (taint) gating for rules 001 & 005 -------------------
//
// The shapes these two rules detect (unquoted word-splitting; a variable used
// as the command name) are only a vulnerability when the value is attacker /
// user-controlled. Real build & test scripts overwhelmingly use them on LOCAL
// values — a constant, a path literal, $(mktemp), a positional build argument,
// another internal variable — for which they are benign. To distinguish, we
// run a bounded intra-file analysis (no cross-file, no control-flow modelling)
// that recognises the concrete ways a shell value becomes external:
//
//   1. assigned the value of a CGI / web environment variable by NAME
//      ($QUERY_STRING, $HTTP_*, $REQUEST_*, $PATH_INFO, $CONTENT_*, $REMOTE_*,
//      $GATEWAY_*, $REDIRECT_*, $AUTH_TYPE, …);
//   2. read from stdin via `read` (read x / read -p … x / while read x / IFS=… read a b);
//   3. assigned a command substitution of a network fetch ($(curl …) / $(wget …));
//   4. assigned (transitively, one or more hops) from a variable that is itself
//      external by one of the above.
//
// A value that is a literal, a path, $(mktemp …), or an expansion of a non-
// external local is NOT external. A *bare positional parameter* ($1, $@, $*) is
// deliberately treated as AMBIGUOUS — build scripts pass safe build arguments
// positionally — so it does not by itself mark a variable external.

// cgiEnvExactNames are CGI / web-server environment variables whose value is
// derived directly from the HTTP request (RFC 3875 + common web additions).
var cgiEnvExactNames = map[string]bool{
	"QUERY_STRING": true, "PATH_INFO": true, "PATH_TRANSLATED": true,
	"REQUEST_URI": true, "REQUEST_METHOD": true, "REQUEST_SCHEME": true,
	"CONTENT_TYPE": true, "CONTENT_LENGTH": true,
	"REMOTE_ADDR": true, "REMOTE_HOST": true, "REMOTE_USER": true,
	"REMOTE_IDENT": true, "REMOTE_PORT": true,
	"AUTH_TYPE": true, "SERVER_NAME": true, "SERVER_PROTOCOL": true,
	"SCRIPT_NAME": true, "SCRIPT_FILENAME": true, "DOCUMENT_URI": true,
}

// cgiEnvPrefixes are CGI / web-server environment-variable name PREFIXES whose
// value is request-derived: HTTP_* (request headers), REQUEST_*, CONTENT_*,
// REMOTE_*, GATEWAY_*, REDIRECT_* (rewritten request env), QUERY_*.
var cgiEnvPrefixes = []string{
	"HTTP_", "REQUEST_", "CONTENT_", "REMOTE_", "GATEWAY_", "REDIRECT_", "QUERY_",
}

// isExternalEnvName reports whether a bare variable name denotes a CGI / web
// request-derived environment variable (so a script that consumes it without an
// explicit assignment is still handling external data).
func isExternalEnvName(name string) bool {
	if cgiEnvExactNames[name] {
		return true
	}
	up := strings.ToUpper(name)
	for _, p := range cgiEnvPrefixes {
		if strings.HasPrefix(up, p) {
			return true
		}
	}
	return false
}

// fetchCommands are network-fetch commands whose command substitution yields a
// remotely-controlled value: var=$(curl …) / var=$(wget …).
var fetchCommands = map[string]bool{
	"curl": true, "wget": true, "fetch": true,
}

// expansionVarName returns the variable name of a simple_expansion / expansion
// node ($x → "x", ${x} → "x", ${x:-default} → "x"). Empty for anything that is
// not a plain parameter expansion (e.g. $(...) command substitution).
func expansionVarName(n *ast.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "simple_expansion", "expansion":
		for _, ch := range n.NamedChildren() {
			if ch.Type() == "variable_name" {
				return ch.Text()
			}
			// ${#x}, special_variable etc. — not a plain name we track.
			if ch.Type() == "special_variable" {
				return ""
			}
		}
	}
	return ""
}

// buildExternalOrigin walks the whole tree and returns the set of variable
// names that intra-file analysis marks as plausibly external (see the family
// comment above). It iterates to a fixed point so transitive assignments
// (b=$a where a is external) propagate regardless of source order.
func buildExternalOrigin(root *ast.Node) map[string]bool {
	external := map[string]bool{}
	if root == nil {
		return external
	}

	// Records a single `name = <rhs>` style fact for the propagation pass.
	type assign struct {
		name string
		rhs  *ast.Node // the `value` field node, may be nil
	}
	var assigns []assign

	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "variable_assignment":
			nameNode := n.ChildByFieldName("name")
			if nameNode == nil {
				return true
			}
			name := strings.TrimSpace(nameNode.Text())
			valNode := n.ChildByFieldName("value")
			if name != "" {
				assigns = append(assigns, assign{name: name, rhs: valNode})
				if assignValueIsExternal(valNode) {
					external[name] = true
				}
			}
		case "command":
			// `read` reads from stdin → every variable it targets is external.
			if isReadCommand(n) {
				for _, v := range readTargetVars(n) {
					external[v] = true
				}
			}
		}
		return true
	})

	// Direct CGI/web env names are external wherever they are referenced even
	// without a local assignment (the shell inherits them from the web server).
	root.Walk(func(n *ast.Node) bool {
		if v := expansionVarName(n); v != "" && isExternalEnvName(v) {
			external[v] = true
		}
		return true
	})

	// Fixed-point propagation through `b=$a` chains.
	for changed := true; changed; {
		changed = false
		for _, a := range assigns {
			if external[a.name] {
				continue
			}
			if rhsRefsExternal(a.rhs, external) {
				external[a.name] = true
				changed = true
			}
		}
	}
	return external
}

// assignValueIsExternal reports whether the RHS of a variable assignment is a
// *primary* external source: a CGI/web env-var expansion, or a command
// substitution of a network fetch. (Transitive `b=$a` is handled separately by
// the fixed-point pass so it can see the full external set.)
func assignValueIsExternal(val *ast.Node) bool {
	if val == nil {
		return false
	}
	// Direct expansion of a request-derived env var: x=$QUERY_STRING.
	if v := expansionVarName(val); v != "" && isExternalEnvName(v) {
		return true
	}
	// x=$(curl …) / x=$(wget …) — and the same nested inside a concatenation
	// or string interpolation.
	external := false
	val.Walk(func(n *ast.Node) bool {
		if external {
			return false
		}
		switch n.Type() {
		case "command_substitution", "process_substitution":
			if substitutionIsFetch(n) {
				external = true
				return false
			}
		case "simple_expansion", "expansion":
			if v := expansionVarName(n); v != "" && isExternalEnvName(v) {
				external = true
				return false
			}
		}
		return true
	})
	return external
}

// rhsRefsExternal reports whether the RHS references (any-depth) an already-
// external variable — the transitive `b="$a/x"` / `b=$a` case.
func rhsRefsExternal(val *ast.Node, external map[string]bool) bool {
	if val == nil {
		return false
	}
	found := false
	val.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		if v := expansionVarName(n); v != "" && external[v] {
			found = true
			return false
		}
		return true
	})
	return found
}

// substitutionIsFetch reports whether a command_substitution / process_-
// substitution node runs a network-fetch command (curl/wget/…) as its (first)
// command — i.e. $(curl …) yields remote content.
func substitutionIsFetch(n *ast.Node) bool {
	fetch := false
	n.Walk(func(inner *ast.Node) bool {
		if fetch {
			return false
		}
		if inner.Type() == "command" {
			if l, _ := commandName(inner); fetchCommands[l] {
				fetch = true
				return false
			}
		}
		return true
	})
	return fetch
}

// isReadCommand reports whether a command node is a `read` builtin invocation
// (read … / IFS=… read …). The prefix-assignment form keeps command_name as
// `read`, so a single command_name check suffices.
func isReadCommand(n *ast.Node) bool {
	l, _ := commandName(n)
	return l == "read"
}

// readTargetVars returns the variable names a `read` command assigns to: the
// trailing word arguments after any flags / -p prompt string. e.g.
//
//	read x            → [x]
//	read -r a b c     → [a b c]
//	read -p "Name: " n → [n]      (the quoted prompt is a `string`, not a word)
func readTargetVars(n *ast.Node) []string {
	var out []string
	prevWasPromptFlag := false
	for _, child := range allChildren(n) {
		if child.FieldName() != "argument" {
			continue
		}
		txt := strings.TrimSpace(child.Text())
		// -p/-i take a following value (prompt / initial text) that is NOT a
		// target variable; skip the flag and its operand.
		if child.Type() == "word" && strings.HasPrefix(txt, "-") {
			if strings.Contains(txt, "p") || strings.Contains(txt, "i") {
				prevWasPromptFlag = true
			}
			continue
		}
		if prevWasPromptFlag {
			// This argument is the prompt / initial-text operand for -p/-i.
			prevWasPromptFlag = false
			continue
		}
		// A bare word in trailing position is a target variable name. Quoted
		// strings and expansions are not valid `read` targets.
		if child.Type() == "word" {
			out = append(out, txt)
		}
	}
	return out
}

// nodeRefsExternal reports whether the node (a bare expansion or a concatenation
// containing one) references an external variable, or directly names a CGI/web
// env var.
func (c *shellChecker) nodeRefsExternal(n *ast.Node) bool {
	if n == nil {
		return false
	}
	found := false
	n.Walk(func(inner *ast.Node) bool {
		if found {
			return false
		}
		if v := expansionVarName(inner); v != "" {
			if c.external[v] || isExternalEnvName(v) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func (c *shellChecker) checkCommand(n *ast.Node) {
	lower, raw := commandName(n)

	// (A) Command name is itself a variable expansion: `$cmd arg1 arg2`.
	// The command word being attacker-influenced is arbitrary command
	// execution — but build/test scripts very commonly dispatch on a LOCAL
	// variable ($CLANG_FORMAT, $msys_shell_cmd, a positional build target),
	// which is benign. GATE on external origin: only emit when the command-name
	// variable was established as user/attacker-controlled by the intra-file
	// origin analysis (or directly names a CGI/web env var).
	if nameNode := commandNameNode(n); nameNode != nil {
		if t := strings.TrimSpace(nameNode.Text()); strings.HasPrefix(t, "$") {
			if c.nodeRefsExternal(nameNode) {
				c.add(n, "BATOU-SH-AST-005", rules.Critical,
					"Command name from an externally-derived variable: "+truncate(t, 40),
					"The command to execute is taken from a shell variable ("+truncate(t, 40)+") that intra-file analysis traced to external/user-controlled input (a CGI/web env var, stdin via read, or a network fetch). An attacker who controls that value runs an arbitrary program.",
					"Use a fixed command name. If dispatch is required, validate the value against a strict allow-list (case statement) before invoking.",
					"CWE-78", []string{"command-injection", "injection", "rce"})
			}
			// fall through: still inspect arguments below.
		}
	}

	switch lower {
	case "eval":
		// (B) eval of any dynamic data → re-parses a runtime string as shell code.
		if c.commandHasDynamicArg(n) {
			c.add(n, "BATOU-SH-AST-002", rules.Critical,
				"eval of dynamic data",
				"eval re-parses its argument string as shell code. Passing a variable or command-substitution result enables arbitrary command execution if any part is attacker-influenced.",
				"Avoid eval. Use arrays for dynamic argument lists, or a case/allow-list to dispatch. If eval is unavoidable, never pass externally-derived data into it.",
				"CWE-78", []string{"command-injection", "injection", "rce", "eval"})
		}
		return
	case "source", ".":
		// (C) source / . of a dynamic path → executes the target file in-process.
		if c.commandHasDynamicArg(n) {
			c.add(n, "BATOU-SH-AST-003", rules.Critical,
				"source/. of a dynamic path",
				"source (or .) executes the target file in the current shell. A variable-controlled path lets an attacker load and run arbitrary script code.",
				"Source only fixed, trusted paths. Validate any dynamic component against a strict allow-list before sourcing.",
				"CWE-95", []string{"code-injection", "injection", "rce"})
		}
		return
	case "bash", "sh", "dash", "ksh", "zsh":
		// (D) sh -c / bash -c "<dynamic>" → inline shell-code execution.
		if c.hasDashCWithDynamic(n) {
			c.add(n, "BATOU-SH-AST-004", rules.Critical,
				lower+" -c with dynamic inline code",
				lower+" -c runs its argument string as a shell program. Building that string from a variable or command substitution enables arbitrary command execution.",
				"Pass data as positional arguments to a fixed script ("+lower+" script.sh \"$arg\") instead of interpolating it into -c. Validate untrusted input.",
				"CWE-78", []string{"command-injection", "injection", "rce"})
			// sh/bash also fall through to word-split check below.
		}
	}

	// (E) Unquoted variable expansion in argument position of a consequential
	// command → word-splitting / glob injection (CWE-78 / CWE-88).
	//
	// GATE on external origin: the unquoted shape is ubiquitous and almost
	// always benign on real scripts (`cp $TMP_FILE …`, `git archive $TAG …`,
	// `kill $(cat ${PID_FILE})`, `rm $TARNAME`) where the variable is a local
	// constant / path / positional build argument. Emit only when at least one
	// of the unquoted expansions references a variable the intra-file origin
	// analysis established as external (CGI/web env, stdin, or a fetch). Bare
	// positional params ($1/$@) are treated as ambiguous and do not qualify.
	if wordSplitDangerousCmds[lower] {
		if args := unquotedExpansionArgs(n); len(args) > 0 {
			// Pick the first argument that is actually external so the finding
			// points at the tainted operand (not merely the first expansion).
			var arg *ast.Node
			for _, a := range args {
				if c.nodeRefsExternal(a) {
					arg = a
					break
				}
			}
			if arg != nil {
				c.add(arg, "BATOU-SH-AST-001", rules.High,
					"Unquoted externally-derived variable in "+raw+" argument (word-splitting / glob injection)",
					"Unquoted expansion "+truncate(strings.TrimSpace(arg.Text()), 40)+" passed to "+raw+" undergoes word-splitting and pathname (glob) expansion before the command runs. Intra-file analysis traced this value to external/user-controlled input (a CGI/web env var, stdin via read, or a network fetch), so a value containing spaces, globs, or leading dashes injects extra arguments / paths (path traversal, argument injection, command misuse).",
					"Double-quote the expansion: "+raw+" \"$var\" ... — and use `--` to terminate option parsing when the value could start with a dash.",
					"CWE-78", []string{"word-splitting", "glob-injection", "argument-injection", "injection"})
			}
		}
	}
}

// commandHasDynamicArg reports whether any argument-position child of the
// command contains a dynamic (expansion / substitution) sub-node.
func (c *shellChecker) commandHasDynamicArg(n *ast.Node) bool {
	for _, child := range allChildren(n) {
		if child.FieldName() == "argument" && argHasDynamic(child) {
			return true
		}
	}
	return false
}

// hasDashCWithDynamic reports whether the command has a `-c` flag argument and
// a subsequent dynamic argument (the inline program string).
func (c *shellChecker) hasDashCWithDynamic(n *ast.Node) bool {
	sawDashC := false
	for _, child := range allChildren(n) {
		if child.FieldName() != "argument" {
			continue
		}
		txt := strings.TrimSpace(child.Text())
		if !sawDashC {
			// -c, or a combined short flag bundle ending in c (e.g. -lc / -ic).
			if strings.HasPrefix(txt, "-") && !strings.HasPrefix(txt, "--") && strings.Contains(txt, "c") {
				sawDashC = true
			}
			continue
		}
		// First argument after -c that carries dynamic data is the program.
		if argHasDynamic(child) {
			return true
		}
	}
	return false
}

func (c *shellChecker) add(n *ast.Node, id string, sev rules.Severity, title, desc, fix, cwe string, tags []string) {
	owasp := "A03:2021-Injection"
	if cwe == "CWE-22" {
		owasp = "A01:2021-Broken Access Control"
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        id,
		Severity:      sev,
		SeverityLabel: sev.String(),
		Title:         title,
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		Column:        int(n.StartCol()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    fix,
		CWEID:         cwe,
		OWASPCategory: owasp,
		Language:      rules.LangShell,
		Confidence:    "high",
		Tags:          tags,
	})
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
