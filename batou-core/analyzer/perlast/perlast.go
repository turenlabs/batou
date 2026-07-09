// Package perlast provides Layer-2 (AST) structural security analysis for
// Perl source code. Until now Perl leaned entirely on Layer-1 regex rules plus
// the Layer-3 tsflow taint engine; it had no dedicated AST analyzer. This
// package mirrors the structure of analyzer/luaast and analyzer/pyast: it
// self-registers via init() -> rules.Register, gates on
// ctx.Language == rules.LangPerl, walks the tree-sitter Perl tree, and emits
// structural findings for the classic Perl injection sinks.
//
// EXTERNAL-ORIGIN GATING (the precision fix)
//
// An earlier purely-structural version of this analyzer fired on every
// occurrence of a dangerous *shape* "independent of whether the data
// originates from a recognised taint source". On a real Mojolicious checkout
// that produced 6 findings, all false positives: list-form `open '-|', $^X,
// ...` pipes (which never reach a shell) and an `s///e` whose replacement was a
// fixed `_entity($1, $2, $attr)` call. The blind shape signal cannot tell a
// SAFE local/constant operand from a user-controlled one, so it floods on the
// overwhelmingly common safe uses.
//
// The fix mirrors how analyzer/pyast reasons about safety before emitting:
// before flagging a flood-prone sink, the analyzer establishes (via a bounded
// intra-file backward scan + a name/shape allowlist of known Perl external
// sources) that the interpolated operand is plausibly EXTERNAL / user
// controlled. If external origin cannot be established, the finding is
// suppressed. This keeps the genuine catch — user input reaching a shell /
// code-reparse sink, including through a hand-rolled %FORM hash the taint
// catalog doesn't model — while dropping the safe-shape noise.
//
// TWO STRUCTURAL BUG FIXES that the flood exposed:
//   - open(): the LIST / exec form `open my $fh, '-|', $^X, $script` (3+ args,
//     or a literal '-|'/'|-' mode argument) does NOT pass through a shell and
//     is therefore NOT shell-injectable. It is never flagged. Only the SHELL
//     form is flagged: 2-arg piped open `open(FH, "cmd $var |")`.
//   - s///e: a replacement that is a FIXED function call over regex captures /
//     static arguments (e.g. `_entity($1, $2, $attr)`) is not eval injection —
//     $1/$2 are captures and the callee is static. Only an /e replacement that
//     interpolates a variable directly into code (e.g. `$expr`, `"do_$cmd()"`)
//     is flagged.
//
// Comment/POD text never reaches the analyzer because we only ever inspect real
// AST sink nodes — never raw lines.
package perlast

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// PerlASTAnalyzer performs AST-based structural security analysis of Perl code.
type PerlASTAnalyzer struct{}

func init() {
	rules.Register(&PerlASTAnalyzer{})
}

func (p *PerlASTAnalyzer) ID() string                      { return "BATOU-PERL-AST" }
func (p *PerlASTAnalyzer) Name() string                    { return "Perl AST Security Analyzer" }
func (p *PerlASTAnalyzer) DefaultSeverity() rules.Severity { return rules.High }
func (p *PerlASTAnalyzer) Languages() []rules.Language     { return []rules.Language{rules.LangPerl} }
func (p *PerlASTAnalyzer) Description() string {
	return "AST-based structural analysis of Perl for OS command injection (system/exec/backticks/qx), " +
		"path/command injection via open() (2-arg and piped forms), and code execution via the s///e substitution modifier. " +
		"Findings are gated on plausibly-external (user-controlled) operands established by a bounded intra-file backward scan."
}

func (p *PerlASTAnalyzer) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangPerl {
		return nil
	}
	tree := ast.TreeFromContext(ctx)
	if tree == nil {
		return nil
	}
	content := ctx.Content
	if content == "" {
		content = ctx.OriginalContent
	}
	c := &perlChecker{
		tree:     tree,
		filePath: ctx.FilePath,
		content:  content,
		// externalHashes is the set of hash names (e.g. "FORM") that this file
		// populates from an external source — the hand-rolled-request-hash
		// idiom. Computed lazily on first external-origin check.
	}
	c.walk()
	return c.findings
}

type perlChecker struct {
	tree     *ast.Tree
	filePath string
	content  string
	findings []rules.Finding

	// externalHashes maps a Perl hash base-name ("FORM" for %FORM / $FORM{...})
	// to true when this file assigns into that hash from an external source.
	// nil until computed by ensureExternalHashes().
	externalHashes map[string]bool
}

func (c *perlChecker) walk() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "function_call_expression", "ambiguous_function_call_expression":
			c.checkCommandFunc(n)
			c.checkOpen(n)
		case "command_string":
			// Backticks `...` and qx// — command execution via the shell.
			c.checkBacktick(n)
		case "binary_expression":
			// $x =~ s/.../.../e  parses as a binary_expression whose right
			// child is a substitution_regexp with an /e modifier.
			c.checkSubstEval(n)
		}
		return true
	})
}

// perlFuncName returns the called function/builtin name for a
// function_call_expression / ambiguous_function_call_expression node.
func perlFuncName(n *ast.Node) string {
	fn := n.ChildByFieldName("function")
	if fn != nil {
		return strings.TrimSpace(fn.Text())
	}
	return ""
}

// argsNode returns the node holding the call's arguments, or nil. Perl wraps
// multiple args in a list_expression; a single arg may be attached directly
// (e.g. an interpolated_string_literal) under the "arguments" field.
func argsNode(n *ast.Node) *ast.Node {
	return n.ChildByFieldName("arguments")
}

// ---------------------------------------------------------------------------
// External-origin gating
// ---------------------------------------------------------------------------

// reExternalSource is a name/shape allowlist of known Perl external (user
// controlled) sources, mirroring the Perl taint source catalog
// (taint/languages/perl_sources.go). A sink operand whose value flows from one
// of these is treated as plausibly external. This is deliberately broad on the
// "is it user-controlled" question because the alternative (the held analyzer)
// was broad on the "is it a dangerous shape" question, which flooded.
var reExternalSource = regexp.MustCompile(
	// CGI.pm
	`\$\w+->param\s*\(` + `|` + `->Vars\b` +
		// Plack / PSGI / Dancer / Catalyst / Mojolicious request objects
		`|->param\s*\(` + `|->params\b` + `|->parameters\b` +
		`|->query_parameters\b` + `|->body_parameters\b` + `|->every_param\b` +
		`|->req(?:uest)?->` + `|->res->` +
		`|->body\b` + `|->raw_body\b` + `|->content\b` +
		`|->cookies?\b` + `|->upload\b` + `|->uploads\b` +
		`|->path(?:_info)?\b` + `|->request_uri\b` +
		`|->referer\b` + `|->user_agent\b` + `|->header(?:s)?\b` +
		`|\bparams->\{` + `|\bparam\s*\(` +
		// CLI / stdin / environment
		`|\@ARGV\b` + `|\$ARGV\[` + `|<STDIN>` + `|\bSTDIN\b` + `|\$ENV\{` +
		// PSGI env hash
		`|\$env->\{` +
		// decoded request payloads
		`|\bdecode_json\s*\(` + `|\bfrom_json\s*\(` +
		// network reads
		`|->recv\s*\(` + `|->decoded_content\s*\(`,
)

// hashAssignRe and friends recognise the hand-rolled request-hash idiom:
//
//	foreach my $pair (split /&/, $ENV{'QUERY_STRING'}) { $FORM{$k} = $v }
//
// We treat %FORM as external when ANY assignment into it (or the split that
// feeds it) is fed by an external source on the same line.
var (
	// `$FORM{...} = ...`  (assignment INTO a hash element)
	reHashElemAssign = regexp.MustCompile(`\$(\w+)\s*\{[^}]*\}\s*=`)
	// `%FORM = ...`        (whole-hash assignment, e.g. = $cgi->Vars / split ...)
	reHashWholeAssign = regexp.MustCompile(`%(\w+)\s*=`)
	// `my ($k,$v) = split /=/, $pair` style helpers don't matter; we look at the
	// loop header `foreach ... ($ENV{'QUERY_STRING'})` separately via the line.
)

// scalarAssignRe captures `my $foo = RHS` / `$foo = RHS` so we can backward-scan
// for the last assignment to a sink variable.
func assignRHSFor(content, name string) (rhs string, found bool) {
	// Match the LAST `[my] $name = ...` up to end of statement (`;` or newline).
	re := regexp.MustCompile(`(?m)(?:^|[^>\w])(?:my\s+)?\$` + regexp.QuoteMeta(name) + `\s*=\s*([^;\n]*)`)
	ms := re.FindAllStringSubmatch(content, -1)
	if len(ms) == 0 {
		return "", false
	}
	// last assignment wins
	return strings.TrimSpace(ms[len(ms)-1][1]), true
}

// ensureExternalHashes scans the whole file once for hashes populated from an
// external source (the %FORM idiom). A hash base-name lands in the set when an
// assignment INTO it, or a foreach/while loop body around such an assignment,
// references an external source on a nearby line.
func (c *perlChecker) ensureExternalHashes() {
	if c.externalHashes != nil {
		return
	}
	c.externalHashes = map[string]bool{}
	lines := strings.Split(c.content, "\n")
	for i, ln := range lines {
		// whole-hash assignment: %H = <external> or %H = $cgi->Vars
		if m := reHashWholeAssign.FindStringSubmatch(ln); m != nil {
			if reExternalSource.MatchString(ln) {
				c.externalHashes[m[1]] = true
			}
		}
		// element assignment: $H{...} = ...  — external if the RHS, or the
		// enclosing loop header (a few lines up), reads an external source.
		if m := reHashElemAssign.FindStringSubmatch(ln); m != nil {
			window := ln
			// look back up to 4 lines for a foreach/while loop header feeding it
			for j := i - 1; j >= 0 && j >= i-4; j-- {
				window += "\n" + lines[j]
				t := strings.TrimSpace(lines[j])
				if strings.HasPrefix(t, "foreach") || strings.HasPrefix(t, "for ") ||
					strings.HasPrefix(t, "while") || strings.HasPrefix(t, "for(") {
					break
				}
			}
			if reExternalSource.MatchString(window) {
				c.externalHashes[m[1]] = true
			}
		}
	}
}

// exprIsExternal reports whether a raw expression string is (directly) an
// external source: e.g. `$cgi->param('x')`, `$ENV{'Q'}`, `$ARGV[0]`, or an
// element of a hash this file populated from an external source (`$FORM{'x'}`).
func (c *perlChecker) exprIsExternal(expr string) bool {
	if expr == "" {
		return false
	}
	if reExternalSource.MatchString(expr) {
		return true
	}
	// element of an externally-populated hash: $FORM{'host'}
	if m := regexp.MustCompile(`\$(\w+)\s*\{`).FindStringSubmatch(expr); m != nil {
		c.ensureExternalHashes()
		if c.externalHashes[m[1]] {
			return true
		}
	}
	return false
}

// varIsExternal establishes, via a bounded intra-file backward scan, whether a
// scalar variable named `name` (no leading $) plausibly holds external data.
// depth guards against assignment cycles. It returns true when the variable's
// last assignment RHS is an external source, the element of an externally
// populated hash, or another variable that is itself external.
func (c *perlChecker) varIsExternal(name string, depth int) bool {
	if name == "" || depth > 4 {
		return false
	}
	rhs, ok := assignRHSFor(c.content, name)
	if !ok {
		return false
	}
	if c.exprIsExternal(rhs) {
		return true
	}
	// RHS is `$other` or interpolates `$other` / `$other->...`: follow it.
	for _, m := range regexp.MustCompile(`\$(\w+)`).FindAllStringSubmatch(rhs, -1) {
		next := m[1]
		if next == name || isAllDigits(next) {
			continue
		}
		if c.varIsExternal(next, depth+1) {
			return true
		}
	}
	return false
}

// nodeHasExternalOperand reports whether ANY scalar/array variable interpolated
// inside the subtree n is plausibly external (user-controlled). This is the
// gate the flood-prone rules consult before emitting. A bare external-source
// expression spliced directly into the string (e.g. `$ENV{...}` inside the
// command) also counts.
func (c *perlChecker) nodeHasExternalOperand(n *ast.Node) bool {
	if n == nil {
		return false
	}
	// Direct splice of an external source into the node text (covers
	// `system("ping $ENV{X}")` and similar where the source IS the operand).
	if c.exprIsExternal(n.Text()) {
		return true
	}
	external := false
	n.Walk(func(d *ast.Node) bool {
		if external {
			return false
		}
		if d.Type() == "scalar" || d.Type() == "array" {
			name := varBareName(d)
			if name == "" || isAllDigits(name) {
				return true
			}
			if c.varIsExternal(name, 0) {
				external = true
				return false
			}
		}
		// hash/array element directly interpolated: $FORM{'host'}
		if d.Type() == "hash_element_expression" || d.Type() == "array_element_expression" {
			if c.exprIsExternal(d.Text()) {
				external = true
				return false
			}
		}
		return true
	})
	return external
}

// hasInterpolatedVar reports whether the subtree rooted at n contains a Perl
// variable interpolation (a scalar/array variable that is NOT a pure literal).
func hasInterpolatedVar(n *ast.Node) bool {
	if n == nil {
		return false
	}
	found := false
	n.Walk(func(inner *ast.Node) bool {
		if found {
			return false
		}
		switch inner.Type() {
		case "scalar", "array", "hash_element_expression", "array_element_expression":
			found = true
			return false
		}
		return true
	})
	return found
}

// hasStringInterpolatedVar reports whether n contains an interpolated_string_literal
// or command_string that itself interpolates a real (non-digit) variable — i.e.
// a shell/format string with a $var spliced in.
func hasStringInterpolatedVar(n *ast.Node) bool {
	if n == nil {
		return false
	}
	found := false
	n.Walk(func(inner *ast.Node) bool {
		if found {
			return false
		}
		if inner.Type() == "interpolated_string_literal" || inner.Type() == "command_string" {
			inner.Walk(func(d *ast.Node) bool {
				if found {
					return false
				}
				if d.Type() == "scalar" || d.Type() == "array" {
					name := varBareName(d)
					if name != "" && !isAllDigits(name) {
						found = true
						return false
					}
				}
				return true
			})
		}
		return true
	})
	return found
}

func varBareName(scalarNode *ast.Node) string {
	vn := scalarNode.ChildByFieldName("name")
	if vn == nil {
		for _, c := range scalarNode.NamedChildren() {
			if c.Type() == "varname" {
				return strings.TrimSpace(c.Text())
			}
		}
		return ""
	}
	return strings.TrimSpace(vn.Text())
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// checkCommandFunc detects system()/exec() with a SHELL-interpolated, plausibly
// EXTERNAL variable — the canonical Perl OS command injection (CWE-78).
//
// Only the shell form is flagged: a single command STRING that splices in a
// variable. The list form system($prog, @args) does not go through a shell and
// is never flagged (no shell-interpolated string). Additionally the
// interpolated operand must be plausibly external (gate), so `system("cp
// $src $dst")` over local paths is not flagged.
func (c *perlChecker) checkCommandFunc(n *ast.Node) {
	name := perlFuncName(n)
	if name != "system" && name != "exec" {
		return
	}
	args := argsNode(n)
	if args == nil {
		return
	}
	// Shell form requires a single interpolated command string. The list form
	// (multiple comma-separated args) does not produce a shell-interpolated
	// string and so is filtered here.
	if !hasStringInterpolatedVar(args) {
		return
	}
	// List form guard: if the call has more than one top-level argument, it is
	// the safe exec form (system($prog, @args)) even if one happens to be a
	// string — the shell is bypassed.
	if isMultiArgList(args) {
		return
	}
	// External-origin gate.
	if !c.nodeHasExternalOperand(args) {
		return
	}
	c.add(rules.Finding{
		RuleID:        "BATOU-PERL-AST-001",
		Severity:      rules.Critical,
		Title:         "OS command injection via " + name + "()",
		Description:   name + "() with a shell-interpolated, user-controlled variable passes the argument through /bin/sh. The interpolated value flows from an external source (CGI/Plack/Dancer request, @ARGV, %ENV, STDIN, or a request-populated hash), enabling arbitrary command execution.",
		Suggestion:    "Use the list form (" + name + " $prog, @args) which bypasses the shell, or validate/escape the variable. Never interpolate untrusted data into a single command string.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Tags:          []string{"command-injection", "injection", "rce"},
	}, n)
}

// isMultiArgList reports whether the call's argument node is a list with more
// than one top-level argument (the safe list/exec form for system/exec).
func isMultiArgList(args *ast.Node) bool {
	if args.Type() != "list_expression" {
		return false
	}
	return len(args.NamedChildren()) > 1
}

// checkBacktick detects backtick `...` and qx// command execution with a
// plausibly-external interpolated variable (CWE-78).
func (c *perlChecker) checkBacktick(n *ast.Node) {
	if !backtickInterpolatesVar(n) {
		return
	}
	if !c.nodeHasExternalOperand(n) {
		return
	}
	c.add(rules.Finding{
		RuleID:        "BATOU-PERL-AST-002",
		Severity:      rules.Critical,
		Title:         "OS command injection via backticks/qx",
		Description:   "Backtick (`...`) and qx// command execution run the string through the shell. A user-controlled variable (flowing from a request/CLI/env source) interpolated into the command enables arbitrary command execution.",
		Suggestion:    "Avoid backticks/qx with untrusted data. Use the list form of system()/open() with explicit arguments, or validate and escape the input.",
		CWEID:         "CWE-78",
		OWASPCategory: "A03:2021-Injection",
		Tags:          []string{"command-injection", "injection", "rce"},
	}, n)
}

func backtickInterpolatesVar(n *ast.Node) bool {
	found := false
	n.Walk(func(d *ast.Node) bool {
		if found {
			return false
		}
		if d.Type() == "scalar" || d.Type() == "array" {
			name := varBareName(d)
			if name != "" && !isAllDigits(name) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// checkOpen detects the SHELL-form dangerous open(): 2-arg piped open
// ("cmd $var |" / "| cmd") and 2-arg open whose filename string carries the
// mode and an interpolated variable (path traversal). The interpolated operand
// must be plausibly external.
//
// The LIST / exec form is NEVER flagged:
//   - 3+ argument open (open my $fh, '-|', $^X, $prog, @args) — even when the
//     mode argument is a literal '-|'/'|-' pipe — does NOT pass through a shell.
//     It execs the program directly (list form), so it is not shell-injectable.
//   - the safe 3-arg open(my $fh, '<', $path) idiom — the mode is a separate
//     literal, so the filename can't smuggle a pipe; the taint layer covers
//     path-traversal on the clean cases.
func (c *perlChecker) checkOpen(n *ast.Node) {
	if perlFuncName(n) != "open" {
		return
	}
	args := argsNode(n)
	if args == nil {
		return
	}

	var argList []*ast.Node
	if args.Type() == "list_expression" {
		argList = append(argList, args.NamedChildren()...)
	} else {
		argList = append(argList, args)
	}
	if len(argList) == 0 {
		return
	}

	// LIST / exec form: 3+ arguments. The mode (2nd arg) is a SEPARATE literal,
	// so the filename cannot smuggle a pipe and a literal '-|'/'|-' mode is the
	// direct-exec list form that bypasses the shell. Never flag (this was the
	// AST-003 flood: `open my $fh, '-|', $^X, $script`).
	if len(argList) >= 3 {
		return
	}

	// 2-arg (or 1-arg) open: the single filename string carries the mode AND can
	// contain a leading/trailing pipe — the shell form.
	for i := 0; i < len(argList); i++ {
		arg := argList[i]
		// Skip the bareword/lexical filehandle (FH, my $fh) — it's the handle.
		if arg.Type() == "variable_declaration" || arg.Type() == "bareword" {
			continue
		}
		if !hasInterpolatedVar(arg) {
			continue
		}
		// External-origin gate.
		if !c.nodeHasExternalOperand(arg) {
			return
		}
		text := arg.Text()
		pipe := strings.Contains(text, "|")
		if pipe {
			c.addOpen(n, "CWE-78", "command injection via 2-arg piped open()",
				"2-arg open() with a pipe and an interpolated, user-controlled variable runs a shell command. External input enables command injection.")
		} else {
			c.addOpen(n, "CWE-22", "path traversal / mode injection via 2-arg open()",
				"2-arg open() lets the filename string carry the access mode and shell pipes. A user-controlled variable enables path traversal (../) and mode/command injection.")
		}
		return
	}
}

func (c *perlChecker) addOpen(n *ast.Node, cwe, title, desc string) {
	sev := rules.High
	if cwe == "CWE-78" {
		sev = rules.Critical
	}
	owasp := "A01:2021-Broken Access Control"
	tags := []string{"path-traversal", "traversal"}
	if cwe == "CWE-78" {
		owasp = "A03:2021-Injection"
		tags = []string{"command-injection", "injection", "rce"}
	}
	c.add(rules.Finding{
		RuleID:        "BATOU-PERL-AST-003",
		Severity:      sev,
		Title:         title,
		Description:   desc,
		Suggestion:    "Use the 3-arg open(my $fh, '<', $path) form with an explicit literal mode, and validate $path against directory traversal. Never pass user input to a 2-arg open.",
		CWEID:         cwe,
		OWASPCategory: owasp,
		Tags:          tags,
	}, n)
}

// checkSubstEval detects the s///e substitution modifier (Perl's "evaluate the
// replacement as code") where the replacement DYNAMICALLY builds code from a
// variable — a classic Perl RCE vector (CWE-94).
//
// It does NOT flag a replacement that is a fixed function call applied to regex
// captures / static arguments (e.g. `_entity($1, $2, $attr)`): $1/$2 are
// captures, the callee is static, and the arguments are not interpolated into
// new code. That was the AST-004 flood on Mojo::Util::_html.
func (c *perlChecker) checkSubstEval(n *ast.Node) {
	right := n.ChildByFieldName("right")
	if right == nil || right.Type() != "substitution_regexp" {
		return
	}
	hasEvalMod := false
	var replacement *ast.Node
	for _, ch := range right.NamedChildren() {
		switch ch.Type() {
		case "substitution_regexp_modifiers":
			for _, r := range ch.Text() {
				if r == 'e' {
					hasEvalMod = true
				}
			}
		case "replacement":
			replacement = ch
		}
	}
	if !hasEvalMod || replacement == nil {
		return
	}
	// The replacement must interpolate a variable directly into code (dynamic
	// code build) — NOT be a fixed function call over captures/static args.
	if !replacementBuildsDynamicCode(replacement) {
		return
	}
	// External-origin gate: the variable spliced into the /e code should be
	// plausibly user-controlled.
	if !c.nodeHasExternalOperand(replacement) {
		return
	}
	c.add(rules.Finding{
		RuleID:        "BATOU-PERL-AST-004",
		Severity:      rules.Critical,
		Title:         "Code execution via s///e substitution",
		Description:   "The /e modifier evaluates the substitution replacement as Perl code. A user-controlled variable interpolated directly into the replacement lets attacker-controlled data execute as code.",
		Suggestion:    "Remove the /e modifier, or never interpolate untrusted data into an /e replacement. Use a code reference with validated inputs if dynamic replacement is required.",
		CWEID:         "CWE-94",
		OWASPCategory: "A03:2021-Injection",
		Tags:          []string{"code-injection", "injection", "rce"},
	}, n)
}

// reStaticFuncCall matches a replacement that is (entirely) a single function
// call: `name(...)` possibly with leading/trailing whitespace. When the
// replacement IS such a call, the callee is static and the dynamic-code risk
// comes only from arguments that are themselves interpolated code — which is
// rare. We treat a fixed-call replacement whose arguments are only captures /
// simple scalars as NON-dynamic.
var reStaticFuncCall = regexp.MustCompile(`^\s*&?\w[\w:]*\s*\([^)]*\)\s*;?\s*$`)

// replacementBuildsDynamicCode reports whether an /e replacement interpolates a
// variable directly into code, rather than being a fixed function call over
// captures / static arguments.
//
//	$expr                     -> dynamic (bare scalar IS the code)
//	"do_$cmd()"               -> dynamic (string interpolation builds code)
//	$a + $b                   -> dynamic (expression over scalars, no fixed call)
//	_entity($1, $2, $attr)    -> NOT dynamic (fixed callee, capture/scalar args)
//	uc($1)                    -> NOT dynamic
//	2 + 2                     -> NOT dynamic (no variable; handled by var check)
func replacementBuildsDynamicCode(replacement *ast.Node) bool {
	text := strings.TrimSpace(replacement.Text())

	// A replacement that interpolates a variable INSIDE a string literal builds
	// code dynamically: s/RE/"system('$cmd')"/e.
	if hasStringInterpolatedVar(replacement) {
		return true
	}

	// A bare scalar replacement ($expr) executes that variable's contents as
	// code: this is the textbook s///e injection.
	if named := replacement.NamedChildren(); len(named) == 1 {
		ch := named[0]
		if ch.Type() == "scalar" {
			name := varBareName(ch)
			if name != "" && !isAllDigits(name) {
				return true
			}
		}
	}

	// A fixed function call over captures/args is NOT dynamic. _entity($1,$2,$x)
	// has a static callee; the captures and $attr are data, not new code.
	if reStaticFuncCall.MatchString(text) {
		return false
	}

	// Otherwise: an expression that mixes a non-capture scalar into code
	// (e.g. `$a . qx/$x/`, `$base * $n`) is treated as dynamic.
	return replacementHasNonCaptureVar(replacement)
}

// replacementHasNonCaptureVar reports whether the replacement references a
// scalar/array variable that is NOT a numeric regex capture ($1..$9).
func replacementHasNonCaptureVar(n *ast.Node) bool {
	found := false
	n.Walk(func(d *ast.Node) bool {
		if found {
			return false
		}
		if d.Type() == "scalar" || d.Type() == "array" {
			name := varBareName(d)
			if name != "" && !isAllDigits(name) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// add finalises a finding: it fills the position/match fields from the node and
// appends to the result set.
func (c *perlChecker) add(f rules.Finding, n *ast.Node) {
	f.SeverityLabel = f.Severity.String()
	f.FilePath = c.filePath
	f.Language = rules.LangPerl
	f.Confidence = "high"
	if n != nil {
		f.LineNumber = int(n.StartRow()) + 1
		f.Column = int(n.StartCol()) + 1
		f.MatchedText = truncate(n.Text(), 200)
	}
	c.findings = append(c.findings, f)
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
