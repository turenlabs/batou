// Cross-file taint-signature propagation.
//
// After PR-B (cross-file edges) and PR-G (the walk that consumes them),
// the bottleneck on the coder/coder data was that 1,635 of 1,651
// cross-file destinations are delegating/glue functions whose own
// ComputeTaintSig produced an empty taint_sig — they call further
// downstream but don't have direct sinks of their own. So even though
// the walk reached them, AnalyzeCallerImpact had no sink to fire on.
//
// PropagateSignaturesAcrossCallgraph fixes this by lifting downstream
// sinks UP through the callgraph: when F calls G and G has a sink at
// position i, AND F passes one of its own parameters to G's position i
// at the call site, F gains an inherited sink at the matching param
// position. Iterate to a fixed point (or a small iteration cap) so
// multi-hop chains (F→G→H sink) reach F.
//
// Language coverage:
//   - Go: uses Go-specific helpers from interprocedural.go (regex call
//     match, argument parsing) — propagateForCaller.
//   - Python (PR-Hpy): mirrors the algorithm using tree-sitter call
//     discovery and the typed TaintSig.Params populated by the Python
//     extractor — propagateForPythonCaller. Same fixed-point loop, same
//     "(via X)" provenance annotation on lifted sinks.
//   - JavaScript / TypeScript (PR-Hjs): mirrors the Python path using
//     the JS tree-sitter call-site index and the typed Params populated
//     by the JS extractor — propagateForJavaScriptCallerCached. Same
//     fixed-point loop and OriginFile/OriginLine plumbing so JS leaf
//     sinks render through multi-hop chains.
//
// Other languages stay unchanged for now; their adapters will mirror the
// Python path once their crossfile walkers land.
package graph

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// formatSinkLocation renders the location half of a matched_text/finding
// label for a SinkRef.
//
// For sinks lifted up the call graph by
// PropagateSignaturesAcrossCallgraph the SinkRef.Line points at the
// "(via X)" hop in the inheriting function, not the actual dangerous
// call — that lives at (OriginFile, OriginLine). Without preferring
// OriginFile/OriginLine here, lifted findings render as "-> [] (line N)"
// where N is the lift's call site and the leaf sink's location is lost.
//
// Direct (non-lifted) sinks leave OriginFile empty. Per the SinkRef
// contract (see callgraph.go) consumers fall back to (FilePath, Line)
// of the SinkRef's owning node — the file containing the dangerous
// call. We accept calleeFile as that fallback so the cross-file walker
// can pass calleeNode.FilePath without the helper needing graph
// lookups. When calleeFile is empty (rare — only callers that don't
// have a callee context, e.g. ad-hoc rendering tests) the helper
// degrades to the legacy "(line N)" form so the function stays usable
// in isolation.
func formatSinkLocation(sink SinkRef, calleeFile string) string {
	if sink.OriginFile != "" {
		return fmt.Sprintf("(in %s:%d)", sink.OriginFile, sink.OriginLine)
	}
	if calleeFile != "" {
		return fmt.Sprintf("(in %s:%d)", calleeFile, sink.Line)
	}
	return fmt.Sprintf("(line %d)", sink.Line)
}

// PropagationStats counts what the propagation pass did for diagnostics.
type PropagationStats struct {
	Iterations   int // fixed-point loops executed
	SinksLifted  int // SinkRef entries newly added to caller sigs
	NodesUpdated int // distinct nodes that gained at least one sink
}

// sigPropagationMaxIters caps the fixed-point loop. On a converged
// graph the algorithm typically settles in 2–4 iterations; the cap is
// set high enough that any practically-sized chain reaches fixed
// point. If the algorithm hasn't converged by this many iterations the
// remaining unpropagated sinks are almost certainly cycles we don't
// want to lift through (mutually recursive functions where every node
// would inherit every downstream sink).
const sigPropagationMaxIters = 12

// PropagateSignaturesAcrossCallgraph mutates cg.Nodes[*].TaintSig in
// place, adding inherited SinkCalls entries that reflect taint flows
// crossing into downstream sinks. Returns counters so the dirscan
// finalize can print a one-line metric.
//
// fileContents is an optional map of file_path → content; pass nil to
// have the loader read from disk on demand.
func PropagateSignaturesAcrossCallgraph(cg *CallGraph, fileContents map[string]string) PropagationStats {
	stats := PropagationStats{}
	if cg == nil {
		return stats
	}
	if fileContents == nil {
		fileContents = map[string]string{}
	}
	updated := map[string]bool{}

	// Iterate node IDs in lexicographic order so the propagation
	// result is reproducible across runs. Go's map iteration is
	// randomised, and the iteration cap (sigPropagationMaxIters)
	// means visit order leaks into the final state when chains are
	// deeper than the cap. Sort once outside the loop — node IDs
	// don't change during propagation.
	ids := make([]string, 0, len(cg.Nodes))
	for id := range cg.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// Python pre-pass: populate SinkCalls on every Python leaf via the
	// crossfile walker's lazy helper. computeTaintSigInner's Go sink
	// regex never matches Python call shapes (cursor.execute,
	// subprocess.run, ...), so without this pre-pass leaf Python
	// callees arrive with empty SinkCalls and the lift loop has nothing
	// to propagate. AnalyzeCallerImpactPython does the same population
	// lazily, but it runs AFTER propagation in the dirscan finalize
	// path — too late to feed multi-hop chains.
	for _, id := range ids {
		n := cg.Nodes[id]
		if n == nil || n.Language != rules.LangPython {
			continue
		}
		ensurePythonCalleeSinks(cg, n)
	}

	// JS/TS pre-pass: same rationale as the Python pre-pass. The
	// Go-default sink regex doesn't match JS shapes (child_process.exec,
	// res.send, eval, ...), so leaf JS/TS callees arrive with empty
	// SinkCalls. ensureJavaScriptCalleeSinks lazily populates them via
	// the JS taint catalog. Without this pre-pass, the lift loop has
	// nothing to propagate up multi-hop JS chains.
	for _, id := range ids {
		n := cg.Nodes[id]
		if n == nil {
			continue
		}
		if n.Language != rules.LangJavaScript && n.Language != rules.LangTypeScript {
			continue
		}
		ensureJavaScriptCalleeSinks(cg, n)
		// Return-lift pre-pass (#31, multi-hop): the single-body producer
		// (scanJavaScriptBodyForTaintedReturn) recognises `return <source>`
		// but NOT `return otherFn(...)`. Seed leaf TaintedReturns/-
		// TaintedReturnPaths here so the fixed-point's return-lift loop has
		// a base case to propagate up multi-hop return chains. Mirrors the
		// sink pre-pass above; idempotent (skips populated nodes).
		ensureJavaScriptCalleeReturns(cg, n)
	}

	// Per-pass tree-sitter parse cache for Python callers. Each caller
	// file is parsed at most once and the resulting basename → call
	// sites index is reused across every iteration and every (caller,
	// callee) pair. Without this cache, findPythonCallSites reparses
	// the same file content for every callee in every iteration —
	// dominant cost on real Python codebases (Django: ~30k full-file
	// parses on a single sig-propagation pass).
	pyCallIdx := newPythonCallIndexCache()
	// Per-pass tree-sitter parse cache for JavaScript / TypeScript
	// callers. Same shape and motivation as pyCallIdx; on a Node
	// monorepo the savings compound across the propagation fixed-point
	// iterations.
	jsCallIdx := newJavaScriptCallIndexCache()

	// Generic per-language adapters (#37): C#, Swift, PHP, Ruby, Rust,
	// Kotlin, Groovy, Perl, Shell, Lua, C/C++. Each carries its own
	// per-pass parse cache, so the parse-once-per-file contract holds for
	// these languages too. Built once outside the fixed-point loop.
	genericPasses := newGenericPropagatorPasses()

	// Generic leaf pre-pass: mirror the Python/JS pre-passes for every
	// generalized language. The Go-default sink regex doesn't match these
	// languages' call shapes, so leaf callees arrive with empty SinkCalls /
	// TaintedReturns and the lift loop would have nothing to propagate.
	// ensureXCalleeSinks / ensureXCalleeReturns populate them lazily via
	// each language's own walker producers. Each producer self-gates on
	// callee.Language and is idempotent (skips populated nodes), so calling
	// the pass that owns a node's language is sufficient and safe.
	for _, id := range ids {
		n := cg.Nodes[id]
		if n == nil {
			continue
		}
		gp, ok := genericPasses[n.Language]
		if !ok {
			continue
		}
		if gp.prop.ensureSinks != nil {
			gp.prop.ensureSinks(cg, n)
		}
		if gp.prop.ensureReturns != nil {
			gp.prop.ensureReturns(cg, n)
		}
	}

	converged := false
	for iter := 0; iter < sigPropagationMaxIters; iter++ {
		stats.Iterations++
		changedThisIter := false

		for _, id := range ids {
			caller := cg.Nodes[id]
			if caller == nil {
				continue
			}
			if len(caller.Calls) == 0 {
				continue
			}
			var added int
			switch caller.Language {
			case rules.LangGo:
				added = propagateForCaller(cg, caller, fileContents)
			case rules.LangPython:
				added = propagateForPythonCallerCached(cg, caller, fileContents, pyCallIdx)
			case rules.LangJavaScript, rules.LangTypeScript:
				added = propagateForJavaScriptCallerCached(cg, caller, fileContents, jsCallIdx)
			default:
				// Generalized cross-file languages (#37): C#, Swift, PHP,
				// Ruby, Rust, Kotlin, Groovy, Perl, Shell, Lua, C/C++.
				// Dispatch by the caller's language to the matching adapter;
				// languages without an adapter fall through to no lift.
				gp, ok := genericPasses[caller.Language]
				if !ok {
					continue
				}
				added = gp.run(cg, caller, fileContents)
			}
			if added > 0 {
				stats.SinksLifted += added
				updated[caller.ID] = true
				changedThisIter = true
			}
		}
		if !changedThisIter {
			converged = true
			break
		}
	}
	if !converged {
		// Diagnostics only: the fixpoint exhausted sigPropagationMaxIters
		// while the last iteration still lifted sinks — remaining
		// unpropagated chains were truncated (usually cycles; see the
		// constant's docstring).
		capHits.fixpoint.Add(1)
	}
	stats.NodesUpdated = len(updated)
	return stats
}

// propagateForCaller examines a single caller for new inherited sinks.
// Returns the number of new SinkRef entries appended to caller.TaintSig.
func propagateForCaller(cg *CallGraph, caller *FuncNode, fileContents map[string]string) int {
	content, ok := loadCallerFile(cg, caller.FilePath, fileContents)
	if !ok {
		return 0
	}
	body := extractFuncBody(content, caller.StartLine, caller.EndLine)
	if body == "" {
		return 0
	}
	lines := strings.Split(body, "\n")

	paramNames := callerParamNames(caller, lines)
	if len(paramNames) == 0 {
		return 0
	}

	added := 0
	for _, calleeID := range caller.Calls {
		callee := cg.GetNode(calleeID)
		if callee == nil || len(callee.TaintSig.SinkCalls) == 0 {
			continue
		}

		calleeBaseName := extractBaseName(callee.Name)
		if calleeBaseName == "" {
			continue
		}
		callPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(calleeBaseName) + `\s*\(`)

		for lineIdx, line := range lines {
			if !callPattern.MatchString(line) {
				continue
			}
			argsOpen := strings.Index(line, "(")
			if argsOpen < 0 {
				continue
			}
			args := extractArgList(line[argsOpen:])
			if len(args) == 0 {
				continue
			}

			for _, sink := range callee.TaintSig.SinkCalls {
				// Determine which of the caller's args reach the sink.
				// ArgFromParam == -1 means "any arg of the sink call is
				// dangerous"; otherwise it's a specific position.
				switch {
				case sink.ArgFromParam < 0:
					// Walk every arg the caller passes. For each that's
					// one of the caller's own params, propagate.
					for _, arg := range args {
						pIdx := matchDerivedParamName(strings.TrimSpace(arg), paramNames, sink.SinkCategory, lines, lineIdx)
						if pIdx < 0 {
							continue
						}
						if appendInheritedSink(caller, sink, callee, pIdx, caller.StartLine+lineIdx) {
							added++
						}
					}
				default:
					if sink.ArgFromParam >= len(args) {
						continue
					}
					arg := strings.TrimSpace(args[sink.ArgFromParam])
					pIdx := matchDerivedParamName(arg, paramNames, sink.SinkCategory, lines, lineIdx)
					if pIdx < 0 {
						continue
					}
					if appendInheritedSink(caller, sink, callee, pIdx, caller.StartLine+lineIdx) {
						added++
					}
				}
			}
		}
	}

	// Return-lift loop (#31, multi-hop): mirror the sink-lift loop. Lift a
	// tainted callee return into the caller when the caller returns the
	// call result.
	added += liftGoCallerReturns(cg, caller, lines)
	return added
}

// liftGoCallerReturns is the Go analog of liftJavaScriptCallerReturns.
// Lifts a callee's tainted return into the caller's signature when the
// caller body does `return callee(...)` or `v := callee(...); return v`.
// Uses the same regex call-discovery as propagateForCaller (no call-site
// index for Go); the assignedTo target is parsed from the call line's LHS.
func liftGoCallerReturns(cg *CallGraph, caller *FuncNode, lines []string) int {
	added := 0
	for _, calleeID := range caller.Calls {
		callee := cg.GetNode(calleeID)
		if callee == nil {
			continue
		}
		if len(callee.TaintSig.TaintedReturns) == 0 && len(callee.TaintSig.TaintedReturnPaths) == 0 {
			continue
		}
		if callee.Language != rules.LangGo {
			continue
		}
		calleeBase := extractBaseName(callee.Name)
		if calleeBase == "" {
			continue
		}
		callPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(calleeBase) + `\s*\(`)
		for lineIdx, line := range lines {
			if !callPattern.MatchString(line) {
				continue
			}
			// Parse the assignment target (LHS of `v := callee(...)` /
			// `v = callee(...)`), if any. Empty for a bare/inline call.
			assignedTo := goAssignTarget(line)
			if callerReturnsCalleeResult(lines, calleeBase, lineIdx, assignedTo) {
				if appendInheritedReturn(caller, callee) {
					added++
				}
				break
			}
		}
	}
	return added
}

// goAssignTarget returns the single-identifier assignment target on the
// LHS of a Go assignment line (`v := f(...)` or `v = f(...)`), or "" when
// the line isn't a single-target assignment (multi-return, bare call,
// etc.). Conservative: a multi-value assignment (`a, b := f()`) returns ""
// so we never mis-attribute the wrong return slot.
func goAssignTarget(line string) string {
	trimmed := strings.TrimSpace(line)
	idx := strings.Index(trimmed, ":=")
	if idx < 0 {
		// Plain `=` (not ==, <=, >=, !=) via jsAssignEq's operator logic.
		eq := jsAssignEq(trimmed)
		if eq < 0 {
			return ""
		}
		idx = eq
	}
	lhs := strings.TrimSpace(trimmed[:idx])
	if lhs == "" || strings.Contains(lhs, ",") {
		return ""
	}
	// LHS must be a bare identifier.
	for _, r := range lhs {
		if r != '_' && r != '$' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return ""
		}
	}
	return lhs
}

// callerParamNames returns the caller's parameter names (in declaration
// order) using the typed Params on TaintSig when available, and falling
// back to a light parse of the function-decl line.
func callerParamNames(node *FuncNode, lines []string) []string {
	if len(node.TaintSig.Params) > 0 {
		out := make([]string, len(node.TaintSig.Params))
		for i, p := range node.TaintSig.Params {
			out[i] = p.Name
		}
		return out
	}
	if len(lines) == 0 {
		return nil
	}
	// First line of the body is the func signature. Parse "(...) returnType".
	declLine := lines[0]
	open := strings.Index(declLine, "(")
	close := strings.Index(declLine, ")")
	if open < 0 || close <= open {
		return nil
	}
	inner := declLine[open+1 : close]
	parts := strings.Split(inner, ",")
	var names []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// "name type" or "type" alone (rare in Go but possible in
		// interfaces). Take the first token.
		toks := strings.Fields(p)
		if len(toks) == 0 {
			continue
		}
		names = append(names, toks[0])
	}
	return names
}

// matchExactParamName returns the index of paramNames whose element
// exactly equals arg, or -1 when arg is not a bare-param reference.
// We deliberately avoid fuzzy matching here: callers that derive a new
// value from a param (`derived := process(p)`) should not propagate the
// param's taint through derived without dataflow tracking — that's
// what the per-file taint engine is for.
func matchExactParamName(arg string, paramNames []string) int {
	// Strip trailing comma / closing paren / whitespace.
	arg = strings.TrimRight(arg, " ,)")
	for i, name := range paramNames {
		if name == "" {
			continue
		}
		if arg == name {
			return i
		}
	}
	return -1
}

// maxDerivDepth bounds matchDerivedParamName's expression-unwrap recursion so
// adversarial / deeply-nested call expressions cannot blow the stack. Failing
// closed (returning -1) past the cap means "no lift", never a false lift.
const maxDerivDepth = 4

// matchDerivedParamName generalizes matchExactParamName past the bare-name gate
// (which was the one-transform interprocedural recall ceiling: any reshape like
// sink(parse(p)) / sink(p.trim()) failed the string-equality check and the sink
// was never lifted into the caller). It returns the index of the caller param
// that `arg` is DERIVED FROM, or -1.
//
// "Derived-from-param" is defined recursively over the expression text:
//   - a bare param token              -> that param        (base case, == matchExactParamName)
//   - f(EXPR)  (single top-level arg)  -> derived iff EXPR is derived (pass-through)
//   - RECV.method(...)                -> derived iff the receiver RECV is derived
//
// It is bounded (maxDerivDepth unwrap steps), builds NO points-to graph, and
// tracks NO heap state. It mirrors the engine's existing 0.8x unknown-function
// propagation policy: an unknown single-arg call is assumed to pass its argument
// through, so parse/trim/format/decode/wrap all propagate without a catalog.
//
// PRECISION GUARD: a call whose method/function name is a known sanitizer for
// the sink category (isSanitizerByName) does NOT propagate — sink(escape(p)) is
// correctly NOT lifted. This keeps the change FPR-flat (recall-only).
//
// Concat (p + x) and the local-assignment lookback (q := build(p); sink(q))
// are both implemented below; the lookback only runs when the caller supplies
// bodyLines/callLineIdx and applies the same sanitizer guard to the looked-back
// RHS, so a rebind through escape(...) never lifts.
// maxAssignLookback bounds how many caller-body lines above the call site the
// local-assignment lookback scans for a binding (q := build(p)). A hard cap so a
// huge function body can't make the pass quadratic.
const maxAssignLookback = 80

// bodyLines/callLineIdx enable the local-assignment lookback (q := build(p);
// sink(q)); pass nil/0 to disable it (the bare-name + transform + concat cases
// don't need the body).
func matchDerivedParamName(arg string, paramNames []string, sinkCat taint.SinkCategory, bodyLines []string, callLineIdx int) int {
	return deriveParamIndex(arg, paramNames, sinkCat, bodyLines, callLineIdx, 0)
}

func deriveParamIndex(expr string, paramNames []string, sinkCat taint.SinkCategory, bodyLines []string, callLineIdx, depth int) int {
	if depth > maxDerivDepth {
		capHits.deriv.Add(1) // diagnostics only: unwrap recursion bailed at the depth cap
		return -1
	}
	expr = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expr), ","))
	expr = stripBalancedOuterParens(expr)

	// (base) bare param — also handles trailing " ,)" via matchExactParamName.
	if i := matchExactParamName(expr, paramNames); i >= 0 {
		return i
	}

	// (concat) A + B / A || B: derived iff ANY operand is derived — standard
	// taint semantics (concatenating tainted data with a literal stays tainted),
	// and the canonical injection shape sink("SELECT ... " + p). Checked before
	// the call form so `"x" + p` and `f(p) + g(q)` are split into operands
	// rather than mis-parsed as a single trailing call. A string-literal operand
	// derives to -1 and contributes nothing; the per-operand recursion still
	// applies the sanitizer guard (operand escape(p) is not lifted).
	if ops := splitTopLevelConcat(expr); len(ops) > 1 {
		for _, o := range ops {
			if j := deriveParamIndex(o, paramNames, sinkCat, bodyLines, callLineIdx, depth+1); j >= 0 {
				return j
			}
		}
		return -1
	}

	// (lookback) a local bound earlier in the caller body to a derived RHS:
	// `q := build(p); sink(q)`. Only for a bare identifier (not a param). Scans
	// upward from the call site for the NEAREST single-target binding of expr,
	// bounded by maxAssignLookback. No tracking through control flow or
	// reassignment (nearest binding wins) — under-fires, never invents a flow.
	if bodyLines != nil && callLineIdx > 0 && isBareIdent(expr) {
		lo := callLineIdx - maxAssignLookback
		if lo < 0 {
			lo = 0
		}
		hi := callLineIdx - 1
		if hi >= len(bodyLines) {
			hi = len(bodyLines) - 1
		}
		for i := hi; i >= lo; i-- {
			if isLookbackCommentLine(bodyLines[i]) {
				continue // a commented-out binding must not resurrect a flow
			}
			if rhs, ok := assignmentRHS(bodyLines[i], expr); ok {
				return deriveParamIndex(rhs, paramNames, sinkCat, bodyLines, callLineIdx, depth+1)
			}
		}
		if callLineIdx-maxAssignLookback > 0 {
			// Diagnostics only: the lookback window was clipped by the cap
			// (lines above lo were never scanned) and no binding was found
			// inside it — a binding beyond the window may have been missed.
			capHits.lookback.Add(1)
		}
		return -1 // bare identifier with no param-derived binding
	}

	// The single-outermost-call form: the whole expression must be
	// CALLEE_EXPR( ARGS ) with the final ')' matching the outermost '('.
	if !strings.HasSuffix(expr, ")") {
		return -1
	}
	open := matchingOpenParen(expr)
	if open <= 0 {
		return -1
	}
	calleeExpr := strings.TrimSpace(expr[:open])

	// Split CALLEE_EXPR into receiver + method (last top-level '.').
	var mname, recv string
	if dot := lastTopLevelDot(calleeExpr); dot >= 0 {
		mname = strings.TrimSpace(calleeExpr[dot+1:])
		recv = strings.TrimSpace(calleeExpr[:dot])
	} else {
		mname = calleeExpr
	}

	// PRECISION GUARD: a sanitizer call cleans the value — do not lift through it.
	if isSanitizerByName(mname, sinkCat) {
		return -1
	}

	// (1) single-arg pass-through transform: f(INNER) / json.parse(INNER).
	if inner := extractArgList(expr[open:]); len(inner) == 1 {
		if j := deriveParamIndex(inner[0], paramNames, sinkCat, bodyLines, callLineIdx, depth+1); j >= 0 {
			return j
		}
	}
	// (2) method call on a param-derived receiver: p.trim() / p.replace(...).
	if recv != "" {
		if j := deriveParamIndex(recv, paramNames, sinkCat, bodyLines, callLineIdx, depth+1); j >= 0 {
			return j
		}
	}
	return -1
}

// isLookbackCommentLine reports whether a looked-back body line is (the start
// of) a comment in any language the lookback is wired for (Go, Python, JS/TS,
// and the generalized adapters): //, #, /*, a block-comment continuation "*",
// --, and <!--. A commented-out binding (`# q = build(p)`) must never
// resurrect a flow. Skipping "*"-led lines also rejects the C-family
// `*q = ...` deref-store shape — that under-fires (no lift, fail closed)
// rather than mis-binding the pointee write to the identifier.
func isLookbackCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	for _, p := range []string{"//", "#", "/*", "*", "--", "<!--"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// isBareIdent reports whether s is a single identifier token (letters, digits,
// '_', '$') not starting with a digit.
func isBareIdent(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && c != '$' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// assignmentRHS returns the right-hand side if `line` binds `varName` via a
// single-target '=' or ':=' assignment (including `const/let/var/T q = ...`),
// or ("", false). Compound assignments, comparisons, and field/index targets
// (q.x =, q[i] =) are rejected.
func assignmentRHS(line, varName string) (string, bool) {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		if i+1 < len(line) && line[i+1] == '=' { // ==
			i++
			continue
		}
		lhsEnd := i
		if i > 0 {
			switch line[i-1] {
			case ':': // walrus := / Go :=
				lhsEnd = i - 1
			case '<', '>', '!', '+', '-', '*', '/', '%', '&', '|', '^', '~', '=':
				continue // comparison or compound assignment — not a plain rebind
			}
		}
		lhs := strings.TrimSpace(line[:lhsEnd])
		if lhsRebindsVar(lhs, varName) {
			rhs := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[i+1:]), ";"))
			return rhs, true
		}
		return "", false // the first assignment operator isn't our binding
	}
	return "", false
}

// lhsRebindsVar reports whether the LHS text rebinds the whole variable
// `varName` (allowing a leading decl keyword / type / '*'/'&'), and not a
// field/index/call target.
func lhsRebindsVar(lhs, varName string) bool {
	if lhs == "" || strings.ContainsAny(lhs, ".[(),") || strings.Contains(lhs, "->") {
		return false
	}
	fields := strings.FieldsFunc(lhs, func(r rune) bool { return r == ' ' || r == '\t' || r == '*' || r == '&' })
	return len(fields) > 0 && fields[len(fields)-1] == varName
}

// stripBalancedOuterParens removes one layer of fully-enclosing parens
// ("(p)" -> "p") but leaves a call expression ("parse(p)") intact.
func stripBalancedOuterParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		matched := true
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i != len(s)-1 {
					matched = false // the opening '(' closes before the end
				}
			}
			if !matched {
				break
			}
		}
		if !matched {
			return s
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// matchingOpenParen returns the index of the '(' that matches the final ')'
// of expr (expr must end with ')'), or -1.
func matchingOpenParen(expr string) int {
	depth := 0
	for i := len(expr) - 1; i >= 0; i-- {
		switch expr[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitTopLevelConcat splits expr on binary concatenation operators ('+' and
// '||') at paren/bracket depth 0 and outside string/char/template literals.
// Returns a single-element slice when there is no top-level concat operator.
// Used by deriveParamIndex so a concatenation lifts iff one operand is param-
// derived (standard taint semantics).
func splitTopLevelConcat(expr string) []string {
	var parts []string
	depth := 0
	start := 0
	var quote byte // 0 == not in a string literal
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if quote != 0 {
			if ch == quote && (i == 0 || expr[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'', '`':
			quote = ch
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '+':
			// Only split a lone binary '+': skip '++' and a '+' that follows a
			// '+' (e.g. unary, or the exponent in 1e+5 — preceding char a digit).
			if depth == 0 && (i+1 >= len(expr) || expr[i+1] != '+') && (i <= 0 || (expr[i-1] != '+' && expr[i-1] != 'e' && expr[i-1] != 'E')) {
				parts = append(parts, expr[start:i])
				start = i + 1
			}
		case '|':
			if depth == 0 && i+1 < len(expr) && expr[i+1] == '|' {
				parts = append(parts, expr[start:i])
				i++ // consume the second '|'
				start = i + 1
			}
		}
	}
	parts = append(parts, expr[start:])
	return parts
}

// lastTopLevelDot returns the index of the last '.' at paren-depth 0, or -1.
func lastTopLevelDot(s string) int {
	depth := 0
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case ')', ']':
			depth++
		case '(', '[':
			depth--
		case '.':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// appendInheritedSink adds an inherited SinkRef to caller.TaintSig if
// an equivalent entry doesn't already exist. Returns true on insert.
// The inherited entry's MethodName is decorated so downstream readers
// know it came from a downstream call, not a direct sink in the caller.
//
// callee is the FuncNode the sink is being lifted FROM — its FilePath
// becomes the inherited sink's OriginFile when the parent sink doesn't
// already carry one. This preserves the leaf-sink location through
// multi-hop chains so consumers (the cross-file walker, JSON consumers)
// can render an accurate "sink lives in <file>" step even when the
// SinkRef has been hoisted several levels up the call graph.
func appendInheritedSink(caller *FuncNode, sink SinkRef, callee *FuncNode, paramIdx int, line int) bool {
	calleeBaseName := extractBaseName(callee.Name)
	originFile := sink.OriginFile
	originLine := sink.OriginLine
	if originFile == "" {
		// First lift: the sink's true home is the callee's file.
		originFile = callee.FilePath
		originLine = sink.Line
	}
	inherited := SinkRef{
		SinkCategory: sink.SinkCategory,
		MethodName:   sink.MethodName + " (via " + calleeBaseName + ")",
		Line:         line,
		ArgFromParam: paramIdx,
		OriginFile:   originFile,
		OriginLine:   originLine,
	}
	for _, existing := range caller.TaintSig.SinkCalls {
		if existing.SinkCategory == inherited.SinkCategory &&
			existing.ArgFromParam == inherited.ArgFromParam &&
			existing.MethodName == inherited.MethodName {
			return false
		}
	}
	caller.TaintSig.SinkCalls = append(caller.TaintSig.SinkCalls, inherited)
	return true
}

// appendInheritedReturn lifts a tainted RETURN up the call graph (#31,
// multi-hop). It is the return-value analog of appendInheritedSink: when
// a caller's body does `return callee(...)` (inline) or `v = callee(...);
// ...; return v;`, and callee.TaintSig marks its result as tainted, the
// caller's own return becomes tainted too. Without this lift the
// fixed-point composes SINKS transitively but drops tainted RETURNS at
// the first relay, so a controller→service→repository
// `return db.find(userId)` chain silently loses taint at hop 2.
//
// It unions callee.TaintSig.TaintedReturns into caller.TaintSig.-
// TaintedReturns[0] (the caller returns a single value composed from the
// callee result) AND copies callee.TaintSig.TaintedReturnPaths into the
// caller's TaintedReturnPaths. BOTH must lift: the field-gating (#1058)
// in checkJavaScriptCallerUsesTaintedReturn consults TaintedReturnPaths,
// so dropping them at a relay would break field-sensitive composition at
// hop 2.
//
// Idempotent: a node inherits each return category / path at most once,
// which neutralises cycles (mutually-recursive relays don't accumulate
// unbounded). Returns true when the lift added something NEW (so the
// fixed-point keeps converging), false when nothing changed.
func appendInheritedReturn(caller *FuncNode, callee *FuncNode) bool {
	changed := false

	// Whole-return categories → caller's return index 0.
	if len(callee.TaintSig.TaintedReturns) > 0 {
		if caller.TaintSig.TaintedReturns == nil {
			caller.TaintSig.TaintedReturns = make(map[int][]taint.SourceCategory)
		}
		for _, cats := range callee.TaintSig.TaintedReturns {
			for _, c := range cats {
				before := len(caller.TaintSig.TaintedReturns[0])
				caller.TaintSig.TaintedReturns[0] = appendUniqueCat(caller.TaintSig.TaintedReturns[0], c)
				if len(caller.TaintSig.TaintedReturns[0]) != before {
					changed = true
				}
			}
		}
	}

	// Field-sensitive return paths (#1058) — copy each "retIdx.field..."
	// key so hop-2 callers can still gate `sink(r.user.id)` precisely.
	if len(callee.TaintSig.TaintedReturnPaths) > 0 {
		if caller.TaintSig.TaintedReturnPaths == nil {
			caller.TaintSig.TaintedReturnPaths = make(map[string][]taint.SourceCategory)
		}
		for k, cats := range callee.TaintSig.TaintedReturnPaths {
			before := len(caller.TaintSig.TaintedReturnPaths[k])
			caller.TaintSig.TaintedReturnPaths[k] = appendUniqueCatList(caller.TaintSig.TaintedReturnPaths[k], cats)
			if len(caller.TaintSig.TaintedReturnPaths[k]) != before {
				changed = true
			}
		}
	}

	if changed {
		// A function that propagates user data through its return value is
		// not pure; keep IsPure consistent with the single-body producers
		// (scanJavaScriptBodyForTaintedReturn sets the same).
		caller.TaintSig.IsPure = false
	}
	return changed
}

// callerReturnsCalleeResult reports whether the caller's body returns the
// result of calling callee — the precondition for lifting a tainted
// return up the call graph (#31, multi-hop). Two shapes qualify:
//
//  1. Inline:   `return callee(...)`            (any line whose return
//     expression contains a `callee(` call)
//  2. Via var:  `v = callee(...); ...; return v` (assignedTo == v AND a
//     later body line returns exactly v)
//
// bodyLines are the caller's body lines (lines[0] is the func-decl line,
// i.e. extractFuncBody output split on "\n"). calleeBase is the callee's
// base name. callLineIdx is the call site's 0-based index INTO bodyLines.
// assignedTo is the call site's assignment target ("" for inline calls).
//
// Comment-only lines (`// ...`) are skipped. The match is intentionally
// conservative on BOTH shapes:
//   - inline: the return expression must START with `calleeBase(` — the
//     callee is the OUTERMOST call being returned (`return getA(req)`). A
//     wrapped return (`return escape(getA(req))` / `return getA(req) + x`)
//     does NOT lift, which keeps a sanitizer or any derivation between the
//     call and the return from leaking taint (FPR-flat gate for #31).
//   - via var: a bare-identifier `return v` matching the assignment target.
//
// so we never lift taint through a value the caller derived from the result.
func callerReturnsCalleeResult(bodyLines []string, calleeBase string, callLineIdx int, assignedTo string) bool {
	if calleeBase == "" {
		return false
	}
	callTok := calleeBase + "("

	// Shape 1: inline `return callee(...)`. Scan the call line (the call and
	// the return share one line). The callee call must be the outermost call
	// in the return expression — i.e. the trimmed expression begins with
	// `calleeBase(` — so a wrapped/sanitized/derived return doesn't lift.
	if callLineIdx >= 0 && callLineIdx < len(bodyLines) {
		line := bodyLines[callLineIdx]
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//") {
			for _, m := range jsReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
				expr := strings.TrimSpace(m[1])
				if strings.HasPrefix(expr, callTok) {
					return true
				}
			}
		}
	}

	// Shape 2: `v = callee(...)` then a later `return v`. Require a
	// non-empty assignment target and a subsequent bare-identifier return.
	if assignedTo == "" {
		return false
	}
	for i := callLineIdx + 1; i < len(bodyLines); i++ {
		trimmed := strings.TrimSpace(bodyLines[i])
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, m := range jsReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			// Strip a trailing `;` so `return v;` matches.
			expr = strings.TrimRight(expr, "; \t)")
			if expr == assignedTo {
				return true
			}
		}
	}
	return false
}

// propagateForPythonCallerCached is the Python analog of
// propagateForCaller. It uses tree-sitter (via findPythonCallSitesIndexed)
// to find call expressions inside the caller's body and the typed
// TaintSig.Params populated by the Python extractor to identify which
// arguments are bare caller-param references. For each cross-file callee
// whose TaintSig.SinkCalls contains a sink reachable from param[i], it
// registers an inherited sink on the caller annotated with "(via <callee>)".
//
// Returns the number of new SinkRef entries appended.
//
// Reuses the Python crossfile walker's call-site discovery to avoid
// duplicating tree-sitter plumbing. The caller content is loaded the
// same way the Go path does it (loadCallerFile from interprocedural.go).
//
// callIdx is an optional per-pass tree-sitter parse cache. Pass non-nil
// when invoking inside a hot loop (sig-propagation iterates this for
// every caller × every iteration); pass nil for one-shot use (tests, ad
// hoc calls) — both yield identical results.
func propagateForPythonCallerCached(cg *CallGraph, caller *FuncNode, fileContents map[string]string, callIdx *pythonCallIndexCache) int {
	content, ok := loadCallerFile(cg, caller.FilePath, fileContents)
	if !ok {
		return 0
	}

	// Use TaintSig.Params for param names. Unlike Go, the Python
	// extractor populates Params from the def signature directly, so we
	// don't need a regex fallback against the first body line. If the
	// extractor didn't run yet (rare in dirscan but possible in unit
	// fixtures) there's nothing to match against — skip.
	if len(caller.TaintSig.Params) == 0 {
		return 0
	}
	paramNames := make([]string, len(caller.TaintSig.Params))
	for i, p := range caller.TaintSig.Params {
		paramNames[i] = p.Name
	}

	// Caller body lines for matchDerivedParamName's local-assignment
	// lookback (`q = build(p)` then `G(q)`). Same line convention as
	// liftPythonCallerReturns: bodyLines[0] is the def line, so
	// cs.line-caller.StartLine indexes the call line. Left nil (lookback
	// disabled, fail closed) when the body can't be extracted.
	var bodyLines []string
	if body := extractFuncBody(content, caller.StartLine, caller.EndLine); body != "" {
		bodyLines = strings.Split(body, "\n")
	}

	added := 0
	for _, calleeID := range caller.Calls {
		callee := cg.GetNode(calleeID)
		if callee == nil || len(callee.TaintSig.SinkCalls) == 0 {
			continue
		}
		// Only lift Python sinks; mixing a Go callee's positional
		// argument convention into a Python caller's sig would corrupt
		// downstream consumers. Cross-language edges (if any exist after
		// PR-Gpy's resolver) stay outside this pass.
		if callee.Language != rules.LangPython {
			continue
		}

		if extractBaseName(callee.Name) == "" {
			continue
		}

		callSites := findPythonCallSitesIndexed(callIdx, content, caller, callee.Name)
		if len(callSites) == 0 {
			continue
		}

		for _, cs := range callSites {
			for _, sink := range callee.TaintSig.SinkCalls {
				switch {
				case sink.ArgFromParam < 0:
					// Wildcard: any caller arg that is one of the
					// caller's own params lifts the sink.
					for _, arg := range cs.args {
						pIdx := matchDerivedParamName(strings.TrimSpace(arg), paramNames, sink.SinkCategory, bodyLines, cs.line-caller.StartLine)
						if pIdx < 0 {
							continue
						}
						if appendInheritedSink(caller, sink, callee, pIdx, cs.line) {
							added++
						}
					}
				default:
					if sink.ArgFromParam >= len(cs.args) {
						continue
					}
					arg := strings.TrimSpace(cs.args[sink.ArgFromParam])
					pIdx := matchDerivedParamName(arg, paramNames, sink.SinkCategory, bodyLines, cs.line-caller.StartLine)
					if pIdx < 0 {
						continue
					}
					if appendInheritedSink(caller, sink, callee, pIdx, cs.line) {
						added++
					}
				}
			}
		}
	}

	// Return-lift loop (#31, multi-hop): mirror the JS path. Lift a tainted
	// callee return into the caller when the caller returns the call result.
	added += liftPythonCallerReturns(cg, caller, content, callIdx)
	return added
}

// liftPythonCallerReturns is the Python analog of
// liftJavaScriptCallerReturns. Lifts a callee's tainted return into the
// caller's signature when the caller body does `return callee(...)` or
// `v = callee(...); return v`. Gated to same-language (Python) callees.
func liftPythonCallerReturns(cg *CallGraph, caller *FuncNode, content string, callIdx *pythonCallIndexCache) int {
	body := extractFuncBody(content, caller.StartLine, caller.EndLine)
	if body == "" {
		return 0
	}
	bodyLines := strings.Split(body, "\n")

	added := 0
	for _, calleeID := range caller.Calls {
		callee := cg.GetNode(calleeID)
		if callee == nil {
			continue
		}
		if len(callee.TaintSig.TaintedReturns) == 0 && len(callee.TaintSig.TaintedReturnPaths) == 0 {
			continue
		}
		if callee.Language != rules.LangPython {
			continue
		}
		calleeBase := extractBaseName(callee.Name)
		if calleeBase == "" {
			continue
		}
		callSites := findPythonCallSitesIndexed(callIdx, content, caller, callee.Name)
		if len(callSites) == 0 {
			continue
		}
		for _, cs := range callSites {
			callLineIdx := cs.line - caller.StartLine
			if !callerReturnsCalleeResult(bodyLines, calleeBase, callLineIdx, cs.assignedTo) {
				continue
			}
			if appendInheritedReturn(caller, callee) {
				added++
			}
			break
		}
	}
	return added
}

// propagateForJavaScriptCallerCached is the JavaScript / TypeScript
// analog of propagateForPythonCallerCached. Uses tree-sitter (via
// findJavaScriptCallSitesIndexed) to discover call expressions in the
// caller's body and the typed TaintSig.Params populated by the JS
// extractor to identify which arguments are bare caller-param
// references. For each cross-file callee whose TaintSig.SinkCalls
// contains a sink reachable from param[i], it registers an inherited
// sink on the caller annotated with "(via <callee>)".
//
// Returns the number of new SinkRef entries appended.
//
// callIdx is the per-pass parse cache from
// PropagateSignaturesAcrossCallgraph. Pass nil for one-shot use; the
// helper still works (uncached) and yields identical results.
//
// JavaScript and TypeScript callers go through the same code path
// because the JS taint catalog is shared at the language layer
// (rules.LangJavaScript) and the tree-sitter call shapes are
// identical for the cross-file walk's purposes.
func propagateForJavaScriptCallerCached(cg *CallGraph, caller *FuncNode, fileContents map[string]string, callIdx *javascriptCallIndexCache) int {
	content, ok := loadCallerFile(cg, caller.FilePath, fileContents)
	if !ok {
		return 0
	}

	// Use TaintSig.Params for param names. The JS extractor populates
	// Params from the function signature directly; absent that there's
	// nothing to match against — skip.
	if len(caller.TaintSig.Params) == 0 {
		return 0
	}
	paramNames := make([]string, len(caller.TaintSig.Params))
	for i, p := range caller.TaintSig.Params {
		paramNames[i] = p.Name
	}

	// Caller body lines for matchDerivedParamName's local-assignment
	// lookback (`const q = build(p)` / bare `q = build(p)` then `G(q)`).
	// Same line convention as liftJavaScriptCallerReturns: bodyLines[0] is
	// the function-decl line, so cs.line-caller.StartLine indexes the call
	// line. Left nil (lookback disabled, fail closed) when the body can't
	// be extracted.
	var bodyLines []string
	if body := extractFuncBody(content, caller.StartLine, caller.EndLine); body != "" {
		bodyLines = strings.Split(body, "\n")
	}

	added := 0
	for _, calleeID := range caller.Calls {
		callee := cg.GetNode(calleeID)
		if callee == nil || len(callee.TaintSig.SinkCalls) == 0 {
			continue
		}
		// Only lift JS/TS sinks; mixing a Go or Python callee's
		// positional argument convention into a JS caller's sig would
		// corrupt downstream consumers. Cross-language edges (if any
		// land via the resolver) stay outside this pass.
		if callee.Language != rules.LangJavaScript && callee.Language != rules.LangTypeScript {
			continue
		}

		if extractBaseName(callee.Name) == "" {
			continue
		}

		callSites := findJavaScriptCallSitesIndexed(callIdx, content, caller, callee.Name, caller.Language)
		if len(callSites) == 0 {
			continue
		}

		for _, cs := range callSites {
			for _, sink := range callee.TaintSig.SinkCalls {
				switch {
				case sink.ArgFromParam < 0:
					// Wildcard: any caller arg that is one of the
					// caller's own params lifts the sink.
					for _, arg := range cs.args {
						pIdx := matchDerivedParamName(strings.TrimSpace(arg), paramNames, sink.SinkCategory, bodyLines, cs.line-caller.StartLine)
						if pIdx < 0 {
							continue
						}
						if appendInheritedSink(caller, sink, callee, pIdx, cs.line) {
							added++
						}
					}
				default:
					if sink.ArgFromParam >= len(cs.args) {
						continue
					}
					arg := strings.TrimSpace(cs.args[sink.ArgFromParam])
					pIdx := matchDerivedParamName(arg, paramNames, sink.SinkCategory, bodyLines, cs.line-caller.StartLine)
					if pIdx < 0 {
						continue
					}
					if appendInheritedSink(caller, sink, callee, pIdx, cs.line) {
						added++
					}
				}
			}
		}
	}

	// Return-lift loop (#31, multi-hop). Separate from the sink-lift loop
	// because a callee may carry ONLY a tainted return and NO sink (the
	// canonical `function getA(req){ return req.query.x }` relay target) —
	// the sink guard above would skip it. For each callee the caller calls
	// whose result the caller RETURNS, lift the callee's tainted return
	// into the caller's signature so the next hop up the chain sees it.
	added += liftJavaScriptCallerReturns(cg, caller, content, callIdx)
	return added
}

// liftJavaScriptCallerReturns scans caller.Calls for callees whose
// tainted return value the caller returns (`return callee(...)` or
// `v = callee(...); return v`) and lifts that taint into the caller's own
// signature via appendInheritedReturn. Returns the number of callers'
// return categories/paths newly added (so the fixed-point keeps
// converging). Gated to same-language callees, identical to the sink path.
func liftJavaScriptCallerReturns(cg *CallGraph, caller *FuncNode, content string, callIdx *javascriptCallIndexCache) int {
	body := extractFuncBody(content, caller.StartLine, caller.EndLine)
	if body == "" {
		return 0
	}
	bodyLines := strings.Split(body, "\n")

	added := 0
	for _, calleeID := range caller.Calls {
		callee := cg.GetNode(calleeID)
		if callee == nil {
			continue
		}
		// Nothing to lift unless the callee's result is tainted.
		if len(callee.TaintSig.TaintedReturns) == 0 && len(callee.TaintSig.TaintedReturnPaths) == 0 {
			continue
		}
		// Same-language gate, identical to the sink path.
		if callee.Language != rules.LangJavaScript && callee.Language != rules.LangTypeScript {
			continue
		}
		calleeBase := extractBaseName(callee.Name)
		if calleeBase == "" {
			continue
		}
		callSites := findJavaScriptCallSitesIndexed(callIdx, content, caller, callee.Name, caller.Language)
		if len(callSites) == 0 {
			continue
		}
		for _, cs := range callSites {
			callLineIdx := cs.line - caller.StartLine
			if !callerReturnsCalleeResult(bodyLines, calleeBase, callLineIdx, cs.assignedTo) {
				continue
			}
			if appendInheritedReturn(caller, callee) {
				added++
			}
			// One successful lift per (caller, callee) is enough — the lift
			// is idempotent, further call sites add nothing.
			break
		}
	}
	return added
}
