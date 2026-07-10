package tsflow

// Exported assignment-fact pass (cross-file caller-side sanitizer gate).
//
// The cross-file taint walk in package graph (Path A of the per-language
// checkXCallerPassesTaintToCallee analyzers) fires block-eligible findings
// when a caller passes a tainted argument into a callee whose signature
// says that param reaches a sink. Its caller-side sanitizer knowledge is a
// coarse per-language name regex applied to the ARG EXPRESSION only — so
// the canonical safe shape
//
//	y = escape(x)
//	callee_that_sinks(y)
//
// still fires: the sanitizer call sits on a PREVIOUS line, not inside the
// arg text. The real sanitizer knowledge lives here in tsflow: catalog
// SanitizerDef entries are category-paired (Neutralizes) and the tsMatcher
// matches sanitizer calls precisely (receiver/ObjectType gating, Swift
// arg-label gating, @argpattern mode).
//
// AssignmentFacts exposes that knowledge as a flat, line-ordered list of
// per-file assignment facts so package graph can implement a
// last-assignment-wins lookback without duplicating the matcher.
//
// Conservatism contract: a false "sanitizing" label causes recall loss
// (a real finding suppressed), while a false "plain" label is safe (the
// finding survives). Every ambiguous shape below therefore resolves to
// PLAIN: compound assignments (`y += escape(x)` keeps prior taint),
// destructuring targets (no single base var), sanitizer calls that are not
// the OUTERMOST call of the RHS (mirroring matchSanitizer's semantics in
// processAssignInterproc), and unparseable/unsupported inputs (nil facts).

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// AssignFact records one assignment discovered in a file, keyed by the
// base LHS variable name (field paths and sigils stripped: `obj.attr = …`
// yields Var "obj", PHP `$y = …` yields "y"). Line is 1-based and
// file-absolute. SanitizedCats is non-nil only when the assignment's RHS
// is (after unwrapping casts/parens/await/try) a call matching a catalog
// sanitizer entry; the map holds the union of Neutralizes categories
// across every matching entry. nil = plain assignment. Plain assignments
// matter: a later plain rebind revokes an earlier sanitize
// (last-assignment-wins in the consumer).
type AssignFact struct {
	Var           string
	Line          int
	SanitizedCats map[taint.SinkCategory]bool
}

// AssignmentFacts returns every single-target assignment and variable
// declaration in the file, in tree-walk (roughly line) order, marking
// which are catalog-sanitizing. Returns nil when the language has no
// tsflow config, no registered grammar, no catalog, or the content fails
// to parse — callers must treat nil as "no facts" (fail-open: keep the
// finding).
//
// tree may be a pre-parsed tree-sitter tree for content (the shared-parse
// pattern AnalyzeWithTree uses); pass nil to parse internally.
func AssignmentFacts(content, filePath string, lang rules.Language, tree *ast.Tree) []AssignFact {
	_ = filePath // reserved for symmetry with Analyze; facts are content-derived
	cfg := getConfig(lang)
	if cfg == nil {
		return nil
	}
	if tree == nil {
		tree = ast.Parse([]byte(content), lang)
		if tree == nil {
			return nil
		}
	}
	root := tree.Root()
	if root == nil {
		return nil
	}
	cat := taint.GetCatalog(lang)
	if cat == nil {
		return nil
	}
	matcher := newTSMatcher(cat.Sources(), cat.Sinks(), cat.Sanitizers(), cfg)

	var out []AssignFact
	var visit func(n *ast.Node)
	visit = func(n *ast.Node) {
		if n == nil {
			return
		}
		t := n.Type()
		switch {
		case cfg.assignTypes[t]:
			if lhs := cfg.extractAssignLHS(n); lhs != "" && lhs != "_" {
				if v := assignFactBaseVar(lhs); v != "" {
					var cats map[taint.SinkCategory]bool
					// Compound assignments (`y += …`, `y ||= …`, `$y .= …`)
					// merge into the prior value, so a sanitizer on the RHS
					// does NOT neutralize earlier taint — record as plain.
					if !isCompoundAssignNode(n, t) {
						cats = sanitizingAssignCats(cfg.extractAssignRHS(n), cfg, matcher)
					}
					out = append(out, AssignFact{Var: v, Line: int(n.StartRow()) + 1, SanitizedCats: cats})
				}
			}
		case cfg.varDeclTypes[t]:
			if lhs, rhs := extractVarDeclParts(n, cfg); lhs != "" && lhs != "_" {
				if v := assignFactBaseVar(lhs); v != "" {
					out = append(out, AssignFact{Var: v, Line: int(n.StartRow()) + 1, SanitizedCats: sanitizingAssignCats(rhs, cfg, matcher)})
				}
			}
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
	return out
}

// compoundAssignNodeTypes are the tree-sitter node types that are
// dedicated compound-assignment nodes (the operator is baked into the
// node type rather than an operator child token).
var compoundAssignNodeTypes = map[string]bool{
	"augmented_assignment":            true, // Python
	"augmented_assignment_expression": true, // JS/TS, PHP
	"operator_assignment":             true, // Ruby
	"compound_assignment_expression":  true, // (defensive)
	"compound_assignment_expr":        true, // Rust
}

// plainAssignOperators are the operator tokens of a simple (whole-value)
// assignment. `:=` is Python's walrus / Go-style bind; `=` everything else.
var plainAssignOperators = map[string]bool{"=": true, ":=": true}

// comparisonOperators are `=`-suffixed tokens that are comparisons, not
// assignments; seeing one at the top level of an assignment node must not
// classify it as compound.
var comparisonOperators = map[string]bool{
	"==": true, "===": true, "!=": true, "!==": true,
	"<=": true, ">=": true, "<=>": true,
}

// isCompoundAssignNode reports whether an assignment node is a compound
// assignment (`+=`, `||=`, `.=`, …). Languages whose grammar reuses one
// assignment node type for both forms (Java/C/C++/C#/Kotlin
// assignment_expression carries the operator as an unnamed child token)
// are resolved by scanning the top-level unnamed children for the
// operator. Unknown shapes resolve to false (treated as plain), which is
// the conservative direction ONLY in combination with sanitizingAssignCats
// still requiring a whole-RHS sanitizer call — a compound RHS is a
// binary/merge expression for those grammars only when the operator says
// so, and when we can't tell, a plain fact merely participates in
// last-assignment-wins.
func isCompoundAssignNode(n *ast.Node, nodeType string) bool {
	if compoundAssignNodeTypes[nodeType] {
		return true
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c == nil || c.IsNamed() {
			continue
		}
		tok := strings.TrimSpace(c.Text())
		if plainAssignOperators[tok] {
			return false
		}
		if len(tok) >= 2 && strings.HasSuffix(tok, "=") && !comparisonOperators[tok] {
			return true
		}
	}
	return false
}

// sanitizingAssignCats returns the union of Neutralizes categories across
// every catalog sanitizer entry matching the assignment's RHS call, or nil
// when the RHS is not a whole-value sanitizer call. The RHS is unwrapped
// through casts/parens/await/try (unwrapToCall — the same unwrap
// processAssignInterproc applies before its matchSanitizer check); the
// sanitizer must be the OUTERMOST call, mirroring the per-file walker's
// assignment semantics. Categories are unioned across all matching
// entries (several sanitizers can share a method name with different
// Neutralizes lists) — the exact set matchSanitizerForCategory would
// approve one category at a time.
func sanitizingAssignCats(rhs *ast.Node, cfg *langConfig, m *tsMatcher) map[taint.SinkCategory]bool {
	if rhs == nil {
		return nil
	}
	call := unwrapToCall(rhs, cfg)
	if call == nil || !cfg.callTypes[call.Type()] {
		return nil
	}
	methodName := cfg.extractCallName(call)
	if methodName == "" {
		return nil
	}
	candidates := m.sanitizersByMethod[methodName]
	if short := unqualifyName(methodName); short != methodName {
		candidates = append(candidates, m.sanitizersByMethod[short]...)
	}
	if len(candidates) == 0 {
		return nil
	}
	receiver := cfg.extractCallReceiver(call)
	var cats map[taint.SinkCategory]bool
	for _, san := range candidates {
		if !m.sanitizerCandidateMatches(san, receiver, methodName, call) {
			continue
		}
		for _, c := range san.Neutralizes {
			if cats == nil {
				cats = make(map[taint.SinkCategory]bool)
			}
			cats[c] = true
		}
	}
	return cats
}

// assignFactBaseVar normalizes an LHS (or an argument-expression base) to
// the bare variable identifier the fact is keyed under: surrounding
// whitespace and quotes stripped, leading sigils ($ PHP/Perl/Shell,
// @ Ruby ivar, % Perl hash, & references, * Perl glob) stripped, and the
// name truncated at the first field/subscript/member separator
// (`.`, `[`, `->`, `::`, `(`). Returns "" when what remains is not a
// plain identifier — the caller must then decline to gate (fail-open).
func assignFactBaseVar(lhs string) string {
	s := strings.TrimSpace(lhs)
	s = strings.Trim(s, "\"'`")
	s = strings.TrimLeft(s, "$@%&*")
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' || c == '[' || c == '-' || c == ':' || c == '(' || c == ' ' || c == '\t' {
			s = s[:i]
			break
		}
	}
	if s == "" {
		return ""
	}
	// Must be a plain ASCII identifier; anything fancier (unicode names,
	// operators that slipped through) declines the gate.
	for i := 0; i < len(s); i++ {
		c := s[i]
		isIdent := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !isIdent {
			return ""
		}
	}
	return s
}
