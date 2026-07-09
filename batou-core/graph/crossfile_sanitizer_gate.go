// Catalog-backed caller-side sanitizer gate for the cross-file walk.
//
// Path A of the per-language cross-file analyzers
// (checkXCallerPassesTaintToCallee) checks the ARG EXPRESSION against a
// coarse per-language sanitizer name regex, but has no previous-line
// lookback: the canonical safe shape
//
//	y = escape(x)
//	callee_that_sinks(y)
//
// still fires a block-eligible finding (conf 0.8, SrcExternal,
// High-severity floor). This file adds a purely-suppressive gate backed
// by the real sanitizer knowledge — the category-paired taint catalogs,
// matched precisely by tsflow's tsMatcher via tsflow.AssignmentFacts.
//
// Semantics (last-assignment-wins): the arg's base variable must have a
// catalog-sanitizing assignment BEFORE the call line, with no later plain
// rebind in between, and the sanitizer's Neutralizes set must cover the
// matched sink's category. Everything else keeps the finding.
//
// Fail-open policy: parse failure, unsupported language, missing
// language on the caller node, or a complex arg expression all return
// false (keep the finding). Suppression happens only on positive
// catalog evidence.
package graph

import (
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/tsflow"
	"github.com/turenlabs/batou-rules/rules"
)

// sanitizerFactsMemo caches per-file AssignmentFacts for the duration of
// one walk run (WalkCrossFileTaintFlows / WalkCrossFileTaintFlowsForCaller
// / signature-propagation / two-hop passes). Keyed by file path — content
// per path is stable within a run (loadCallerFile memoizes into
// fileContents). Like the per-language call-index caches it lives next
// to, it is pass-scoped and NOT goroutine-safe; each walk invocation
// creates its own.
type sanitizerFactsMemo struct {
	byFile map[string][]tsflow.AssignFact
}

func newSanitizerFactsMemo() *sanitizerFactsMemo {
	return &sanitizerFactsMemo{byFile: make(map[string][]tsflow.AssignFact)}
}

// factsFor returns the assignment facts for a caller file, computing and
// caching them on first access. A nil memo computes without caching
// (single-shot callers). Negative results (nil facts) are cached too so a
// parse failure isn't retried per candidate finding.
func (m *sanitizerFactsMemo) factsFor(path, content string, lang rules.Language) []tsflow.AssignFact {
	if m == nil {
		return tsflow.AssignmentFacts(content, path, lang, nil)
	}
	if f, ok := m.byFile[path]; ok {
		return f
	}
	f := tsflow.AssignmentFacts(content, path, lang, nil)
	if f == nil {
		f = []tsflow.AssignFact{}
	}
	m.byFile[path] = f
	return f
}

// callerSanitizerGate bundles everything the per-pair check functions
// need to consult the catalog gate for one (caller, callerContent) pair:
// the walk-scoped memo (may be nil), the caller's file identity and
// language, and the caller function's start line (facts outside the
// caller's body are ignored so a same-named variable in ANOTHER function
// can't suppress this caller's finding). A nil gate is inert.
type callerSanitizerGate struct {
	memo      *sanitizerFactsMemo
	path      string
	content   string
	lang      rules.Language
	startLine int

	// Per-gate fallback memo used when memo == nil, so a single analyzer
	// invocation with several candidate findings still parses at most once.
	localComputed bool
	localFacts    []tsflow.AssignFact
}

// newCallerSanitizerGate builds a gate for one caller function. memo may
// be nil (uncached single-shot behaviour).
func newCallerSanitizerGate(memo *sanitizerFactsMemo, callerNode *FuncNode, callerContent string) *callerSanitizerGate {
	if callerNode == nil || callerContent == "" {
		return nil
	}
	return &callerSanitizerGate{
		memo:      memo,
		path:      callerNode.FilePath,
		content:   callerContent,
		lang:      callerNode.Language,
		startLine: callerNode.StartLine,
	}
}

// argSanitized reports whether argExpr's base variable was sanitized for
// sinkCat by a catalog sanitizer before beforeLine (1-based,
// file-absolute) within this caller's body, with no plain rebind in
// between. Nil-gate and unknown-language calls return false (keep the
// finding).
func (g *callerSanitizerGate) argSanitized(argExpr string, beforeLine int, sinkCat taint.SinkCategory) bool {
	if g == nil || g.lang == "" {
		return false
	}
	return callerArgSanitizedScoped(g, argExpr, beforeLine, sinkCat)
}

// facts returns the caller file's assignment facts through the walk memo
// when present, else through the per-gate local memo.
func (g *callerSanitizerGate) facts() []tsflow.AssignFact {
	if g.memo != nil {
		return g.memo.factsFor(g.path, g.content, g.lang)
	}
	if !g.localComputed {
		g.localComputed = true
		g.localFacts = tsflow.AssignmentFacts(g.content, g.path, g.lang, nil)
	}
	return g.localFacts
}

// callerArgSanitizedByCatalog reports whether argExpr's base variable was
// sanitized for sinkCat by a catalog sanitizer before callLine in the
// caller file, with no plain rebind in between (last-assignment-wins).
// memo may be nil (uncached). Parse failure / unsupported language / no
// matching fact → false (fail-open: keep the finding).
func callerArgSanitizedByCatalog(memo *sanitizerFactsMemo, callerPath, callerContent string, lang rules.Language, argExpr string, callLine int, sinkCat taint.SinkCategory) bool {
	g := &callerSanitizerGate{memo: memo, path: callerPath, content: callerContent, lang: lang}
	if lang == "" {
		return false
	}
	return callerArgSanitizedScoped(g, argExpr, callLine, sinkCat)
}

// callerArgSanitizedScoped is the shared implementation: find the LAST
// assignment fact for argExpr's base variable with startLine <= fact.Line
// < beforeLine and return true only when that fact is sanitizing AND its
// categories cover sinkCat.
func callerArgSanitizedScoped(g *callerSanitizerGate, argExpr string, beforeLine int, sinkCat taint.SinkCategory) bool {
	base := sanitizerGateBaseVar(argExpr)
	if base == "" {
		return false
	}
	facts := g.facts()
	if len(facts) == 0 {
		return false
	}
	var last *tsflow.AssignFact
	for i := range facts {
		f := &facts[i]
		if f.Line >= beforeLine || f.Line < g.startLine {
			continue
		}
		if f.Var != base {
			continue
		}
		if last == nil || f.Line >= last.Line {
			last = f
		}
	}
	if last == nil || last.SanitizedCats == nil {
		return false
	}
	return last.SanitizedCats[sinkCat]
}

// sanitizerGateBaseVar extracts the base variable identifier from an
// argument expression, or "" when the expression is too complex to gate
// safely. Accepted shapes: a bare identifier, a sigiled variable
// ($y, @user), a quoted variable ("$y" in shell), or a simple
// field/subscript path (obj.field, row["k"], p->name) whose BASE is
// returned. Any call, operator, interpolation, or other compound
// expression declines (returns "") so the gate fails open. The
// normalization mirrors tsflow's fact-side base-var stripping so lookups
// compare like with like.
func sanitizerGateBaseVar(argExpr string) string {
	s := strings.TrimSpace(argExpr)
	s = strings.Trim(s, "\"'`")
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "$@")
	if s == "" {
		return ""
	}
	// The whole expression must be a simple access path — reject calls,
	// operators, spaces, string interpolation, etc.
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
		case c == '.' || c == '[' || c == ']' || c == '\'' || c == '"' || c == '$' || c == '@' || c == ':':
		case c == '-' && i+1 < len(s) && s[i+1] == '>': // C/C++/PHP arrow member access
		case c == '>' && i > 0 && s[i-1] == '-':
		default:
			return ""
		}
	}
	// Truncate to the base identifier.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' || c == '[' || c == '-' || c == ':' {
			s = s[:i]
			break
		}
	}
	if s == "" {
		return ""
	}
	c0 := s[0]
	if c0 != '_' && (c0 < 'a' || c0 > 'z') && (c0 < 'A' || c0 > 'Z') {
		return ""
	}
	return s
}
