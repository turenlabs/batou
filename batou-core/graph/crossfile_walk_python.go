// Python cross-file interprocedural walker (PR-Gpy).
//
// AnalyzeCallerImpact in interprocedural.go is Go-specific: it scans
// the caller's body with Go regex sink/source patterns (e.g.
// http.Request, sql.Query) and uses Go's argument syntax. Re-using
// that path on Python emits zero findings — Python doesn't have any of
// the Go regex hits and the tree-sitter call walker never runs.
//
// This file mirrors AnalyzeCallerImpact's contract but uses tree-sitter
// to find call expressions in the Python caller, the Python taint
// catalog (SinksForLanguage / SourcesForLanguage) to identify sinks
// inside the callee body, and pythonTypeCatalog (extractor_python.go)
// to recognise framework request source types.
//
// Scope of this PR:
//
//   - Path A: caller passes a tainted argument to a Python callee that
//     forwards it into a sink. Source-typed parameters on the caller
//     (e.g. `def handler(req: Request)`) plus direct source expressions
//     in the call site (e.g. `helper(request.args.get('q'))`) are both
//     recognised.
//   - Path B: callee returns tainted data and the caller passes the
//     result into a sink. Recognised when the callee has TaintedReturns
//     set (the Python extractor flags request-typed returns).
//   - 1-hop interproc only — multi-module relays are PR-Hpy's scope.
//
// The walker IS allowed to populate a Python callee's TaintSig on the
// fly when it's empty. The same-file PropagateInterproc path doesn't
// do regex sink detection for Python (computeTaintSigInner runs the
// Go sink regex list, which never matches `cursor.execute(` or
// `subprocess.run(...)`), so most Python callees arrive at the
// cross-file walk with SinkCalls == nil. Computing them here is a
// "best-effort fix forward" that mirrors how PR-G's signature
// propagation lifts sinks up the call graph for Go.

package graph

import (
	"regexp"
	"strings"
	"sync"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// pythonSinkPattern is a compiled SinkDef plus its category metadata so
// AnalyzePython* helpers can scan callee bodies without hitting the
// catalog every time. Alias of the shared crossfileSinkPattern
// (crossfile_walk_core.go) so the stored-state consumers of
// loadPythonSinkPatterns and the shared walk core interoperate without
// conversion.
type pythonSinkPattern = crossfileSinkPattern

var (
	pythonSinkPatternsCache   []pythonSinkPattern
	pythonSinkPatternsCacheMu sync.Mutex
)

// loadPythonSinkPatterns compiles and caches the Python taint sink
// catalog into regex form. Returns the cached slice on second + calls.
func loadPythonSinkPatterns() []pythonSinkPattern {
	pythonSinkPatternsCacheMu.Lock()
	defer pythonSinkPatternsCacheMu.Unlock()
	if pythonSinkPatternsCache != nil {
		return pythonSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangPython)
	out := make([]pythonSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, pythonSinkPattern{
			pattern:       re,
			category:      s.Category,
			method:        s.MethodName,
			dangerousArgs: s.DangerousArgs,
			module:        s.Module,
			requireModule: s.RequireModule,
		})
	}
	pythonSinkPatternsCache = out
	return out
}

// pythonSourceExprRe matches inline taint source expressions in a
// Python argument position. Mirrors directSourcePatterns from
// interprocedural.go but for the Python catalog's most common request
// shapes. Used by isArgTaintedInPythonCaller when no source-typed
// param is in scope.
//
// These are intentionally loose: anything mentioning `request.X` or a
// known framework attribute access counts as a source. Precise per-
// framework attribution belongs in the per-file taint engine (tsflow),
// not here — at the cross-file boundary we just need "is this argument
// reachable from untrusted input?"
var pythonSourceExprRe = regexp.MustCompile(
	`\brequest\.(args|form|data|json|values|headers|cookies|files|query_string|get_json|POST|GET)\b` +
		`|\bself\.request\.(args|form|data|json|values|headers|cookies|files)\b` +
		`|\bflask\.request\b` +
		`|\binput\s*\(` +
		`|\bsys\.argv\b` +
		`|\bos\.environ\b`,
)

// pythonSanitizerRe matches the common Python sanitizer-call shapes.
// Used by both Path A (caller-side sanitization of an arg) and Path B
// (caller wraps callee's return in a sanitizer before sinking it).
// Tracks the most defensible sanitizers — the Python taint catalog has
// dozens more but at the cross-file boundary a coarse net is fine.
//
// The intent matches PR-HH (Go): give the caller a chance to declare
// "I sanitized this" without exhaustively re-running the per-file
// sanitizer detection in the cross-file pass.
//
// PR-CAT2py additions:
//   - render_to_string / render_to_response / django.shortcuts.render —
//     Django templates auto-escape by default; the rendered HTML is safe
//     for downstream HttpResponse / web.Response sinks. Removes ~9
//     Sentry false positives where `render_to_response(...) ->
//     HttpResponse(...)` was lifted as a cross-file XSS flow.
//   - is_valid_redirect / url_has_allowed_host_and_scheme / is_safe_url —
//     redirect URL validators (Django stdlib + Sentry-style app guards).
//     Removes ~4 Sentry false positives where login flows wrap the
//     `next` URL in a validator before issuing the redirect.
//
// #1262 cross-file sanitizer drift alignment: the single-file
// SnkHTMLOutput catalog (taint/languages/python_sanitizers.go) lists
// several common HTML escapers/strippers that this regex's `escape`
// catch-all does NOT cover, because `\bescape\(` requires a word
// boundary immediately before `escape` (so `conditional_escape(` and
// `force_escape(` slip through) and the strip/clean family share no
// substring with `escape`/`sanitize`/`quote`. A value wrapped in one
// of these and passed across a function boundary into an HTML/redirect/
// template sink was wrongly flagged as a cross-file XSS flow. These are
// only ever consulted for the categories `sinkLineSanitizerNeutralises`
// approves (HTMLOutput/Redirect/Template/TrustBoundary), so they cannot
// over-suppress SQL/command injection. `Markup`/`markupsafe.Markup` is
// deliberately NOT added — it is also an HTML *sink* (py.jinja2.markup),
// so treating it as a sanitizer would silence a real XSS bypass.
//   - strip_tags / django.utils.html.strip_tags — Django HTML tag
//     stripper (py.django.strip_tags).
//   - nh3.clean / nh3.clean_text / clean_html — nh3/lxml HTML
//     sanitizers (py.nh3.clean, py.nh3.clean_text, py.lxml.clean_html).
//   - conditional_escape / force_escape — Django escapers
//     (py.django.conditional_escape, py.django.escapers) the `escape`
//     catch-all misses on the word boundary.
var pythonSanitizerRe = regexp.MustCompile(
	`\b(?:` +
		`shlex\.quote` +
		`|html\.escape` +
		`|urllib\.parse\.quote` +
		`|urllib\.parse\.quote_plus` +
		`|markupsafe\.escape` +
		`|re\.escape` +
		`|json\.dumps` +
		`|bleach\.clean` +
		`|nh3\.clean(?:_text)?` +
		`|clean_html` +
		`|strip_tags` +
		`|conditional_escape` +
		`|force_escape` +
		`|werkzeug\.utils\.secure_filename` +
		`|secure_filename` +
		`|render_to_string` +
		`|render_to_response` +
		`|django\.shortcuts\.render` +
		`|is_valid_redirect` +
		`|url_has_allowed_host_and_scheme` +
		`|is_safe_url` +
		`|escape` +
		`|sanitize` +
		`|quote` +
		`)\s*\(`,
)

// AnalyzeCallerImpactPython mirrors AnalyzeCallerImpact (interprocedural.go)
// but uses tree-sitter to find Python call expressions in the caller
// body and the Python taint catalog to identify sinks inside the
// callee. Returns findings keyed by the same BATOU-INTERPROC-<CAT>
// rule IDs the Go path uses so downstream consumers don't need
// language-specific dispatch.
//
// The callee's TaintSig.SinkCalls is computed on the fly when empty
// (see ensurePythonCalleeSinks) — same-file PropagateInterproc never
// populated them for Python because computeTaintSigInner's sink regex
// list is Go-specific. This is the "fix forward" PR-G uses for the
// cross-file pass.
func AnalyzeCallerImpactPython(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactPythonCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactPythonCached is AnalyzeCallerImpactPython with an
// optional per-pass tree-sitter parse cache. The cache lets
// WalkCrossFileTaintFlows avoid reparsing the same caller file for every
// callee that lives in a separate file. Pass nil for the uncached
// (single-shot) behaviour.
//
// The walk template itself (ensure sinks -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core
// (crossfile_walk_core.go); this wrapper only supplies the Python config
// and the tree-sitter call-site finder bound to the typed cache.
func analyzeCallerImpactPythonCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *pythonCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		pythonCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return pythonCallSitesToShared(findPythonCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// pythonCallSitesToShared converts pythonCallSite rows to the shared
// crossfileCallSite shape. The keywordArg map is dropped — the shared
// Path A / Path B checks only consume positional args and assignedTo
// (exactly what the historical checkPythonCaller* functions read).
func pythonCallSitesToShared(in []pythonCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite{line: cs.line, args: cs.args, assignedTo: cs.assignedTo}
	}
	return out
}

// pythonCallSite captures a single call expression discovered inside a
// caller's body. line is 1-based file-absolute; args lists positional
// argument expressions in order; assignedTo, when non-empty, is the
// variable receiving the call's return value (`x = foo(...)` form).
type pythonCallSite struct {
	line       int
	args       []string
	keywordArg map[string]string
	assignedTo string
}

// findPythonCallSites parses callerContent with tree-sitter and returns
// every call expression to a function whose simple name equals
// calleeBaseName (after stripping any class/module qualifier from
// calleeName via extractBaseName). Falls back to an empty slice if the
// caller can't be parsed — we don't want a bad parse to silently
// destroy findings.
func findPythonCallSites(callerContent string, callerNode *FuncNode, calleeName string) []pythonCallSite {
	tree := tsast.Parse([]byte(callerContent), rules.LangPython)
	if tree == nil || tree.Root() == nil {
		return nil
	}
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}

	var out []pythonCallSite

	var visit func(n *tsast.Node, parentAssignTarget string)
	visit = func(n *tsast.Node, parentAssignTarget string) {
		if n == nil {
			return
		}
		// Constrain to the caller's line range; skip subtrees fully
		// outside it.
		if int(n.StartRow())+1 > callerNode.EndLine {
			return
		}
		if int(n.EndRow())+1 < callerNode.StartLine {
			return
		}

		switch n.Type() {
		case "call":
			if matchesPythonCallName(n, baseName) {
				cs := pythonCallSite{
					line:       int(n.StartRow()) + 1,
					assignedTo: parentAssignTarget,
				}
				if argList := n.ChildByFieldName("arguments"); argList != nil {
					cs.args, cs.keywordArg = extractPythonCallArgs(argList)
				}
				// Only record call sites within the caller's range.
				if cs.line >= callerNode.StartLine && cs.line <= callerNode.EndLine {
					out = append(out, cs)
				}
			}
		case "assignment":
			// Detect `x = callee(...)`. tree-sitter Python `assignment`
			// has `left` (target) + `right` (expression). When the RHS
			// is a direct call, propagate the target name down so the
			// call visit knows it's being assigned.
			lhs := n.ChildByFieldName("left")
			rhs := n.ChildByFieldName("right")
			if lhs != nil && rhs != nil && lhs.Type() == "identifier" {
				name := strings.TrimSpace(lhs.Text())
				// Recurse into RHS only, with the assigned name.
				visit(rhs, name)
				return
			}
		}
		for _, c := range n.NamedChildren() {
			visit(c, "")
		}
	}
	visit(tree.Root(), "")
	return out
}

// matchesPythonCallName reports whether a tree-sitter `call` node's
// function reference resolves to a simple name equal to baseName.
// Handles bare identifiers (`foo(...)`), single-level attribute access
// (`mod.foo(...)`), and chained access where the final attribute is
// foo (`a.b.foo(...)` — last segment match).
func matchesPythonCallName(call *tsast.Node, baseName string) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text()) == baseName
	case "attribute":
		attr := fn.ChildByFieldName("attribute")
		if attr != nil && strings.TrimSpace(attr.Text()) == baseName {
			return true
		}
	}
	return false
}

// extractPythonCallArgs returns positional and keyword arguments from
// a tree-sitter `argument_list` node. Positional args appear in the
// order they were passed; *splat / **kwarg unpacking is treated as a
// single positional arg with its expression text.
func extractPythonCallArgs(argList *tsast.Node) ([]string, map[string]string) {
	var args []string
	kw := map[string]string{}
	for _, child := range argList.NamedChildren() {
		switch child.Type() {
		case "keyword_argument":
			nameNode := child.ChildByFieldName("name")
			valNode := child.ChildByFieldName("value")
			if nameNode != nil && valNode != nil {
				kw[strings.TrimSpace(nameNode.Text())] = strings.TrimSpace(valNode.Text())
			}
		default:
			args = append(args, strings.TrimSpace(child.Text()))
		}
	}
	return args, kw
}

// ensurePythonCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls
// when it's empty. Same-file PropagateInterproc for Python only sets
// SourceParams via the extractor; sink detection in computeTaintSigInner
// is Go-regex and never matches Python call shapes. Walking the callee
// body here with the Python catalog fills that gap so the cross-file
// walker has something to match against.
//
// Idempotent: skips work when SinkCalls is already populated.
func ensurePythonCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangPython {
		return
	}
	if len(calleeNode.TaintSig.SinkCalls) > 0 {
		return
	}
	content, ok := loadCallerFile(cg, calleeNode.FilePath, map[string]string{})
	if !ok {
		return
	}
	body := extractFuncBody(content, calleeNode.StartLine, calleeNode.EndLine)
	if body == "" {
		return
	}
	sinks, dangerousArgs := scanPythonBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	// Map each sink to a param index by checking if any caller-visible
	// param name appears in the sink call's args. The Python extractor
	// runs in ComputeTaintSigTyped above; we don't repeat it here, but
	// we do know SourceParams from the cached sig. For sinks whose arg
	// expression mentions a param name, set ArgFromParam to that index.
	// Otherwise leave it at -1 (wildcard "any caller arg") which keeps
	// behaviour aligned with the Go path's same-file fallback.
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		// PR-CAT6py fix A: when a SnkTrustBoundary sink is a session
		// subscript write whose RHS is a bare identifier matching a
		// callee parameter name (e.g. `request.session[k] = org_slug`),
		// the dangerous arg position is the RHS param's index — NOT
		// the request param. The default findPythonParamFlowToSink
		// matches `request` first and would set ArgFromParam=0, which
		// then over-fires for every caller passing a tainted request
		// regardless of whether the value-side arg was tainted. By
		// anchoring ArgFromParam to the RHS param, the cross-file
		// positional check in checkPythonCallerPassesTaintToCallee
		// only fires when the caller's matching arg is itself tainted.
		if sinks[i].SinkCategory == taint.SnkTrustBoundary && lineIdx >= 0 && lineIdx < len(bodyLines) {
			if rhsIdx := pythonTrustBoundarySinkRHSParamIdx(bodyLines[lineIdx], &calleeNode.TaintSig); rhsIdx >= 0 {
				sinks[i].ArgFromParam = rhsIdx
				continue
			}
		}
		// PR-CAT6py fix B1: honor the catalog's DangerousArgs so a
		// sink like `re.match(constPattern, taintedValue)` (DangerousArgs=[0])
		// doesn't bind ArgFromParam to the haystack param at position 1.
		// Without this filter, findPythonParamFlowToSink matches any
		// param name in the line and over-flags ReDoS on parser
		// functions whose subject (not pattern) is user input.
		sinks[i].ArgFromParam = findPythonParamFlowToSinkFiltered(
			bodyLines, lineIdx, &calleeNode.TaintSig, dangerousArgs[i],
		)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	// Persist (best-effort; concurrent dirscan locks the graph mutex).
	if cg != nil {
		_ = cg // The caller already holds cg in scope; explicit save is
		//        not needed since the in-memory mutation is enough for
		//        the rest of WalkCrossFileTaintFlows.
	}
}

// scanPythonBodyForSinks walks the body line-by-line with each cached
// pythonSinkPattern. Returns SinkRef rows with file-absolute line
// numbers. Multiple distinct sinks on the same line each produce their
// own row.
//
// PR-CAT2py: a sink line whose arguments contain an HTMLOutput-class
// inline sanitizer call (render_to_string, html.escape, bleach.clean,
// etc.) is suppressed *only for HTML_OUTPUT*. This mirrors the per-file
// tsflow walker's containsInlineSanitizer check; without it, the
// Sentry shape `HttpResponse(render_to_string(template, ctx, request))`
// surfaces as a cross-file XSS finding even though the inner
// render_to_string fully auto-escapes the context.
//
// PR-CAT5py: the body is run through joinPythonParenContinuations
// before line scanning so multi-line parenthesised call shapes are
// inspected as a single logical line. Without this, structured logger
// calls split across physical lines (`logger.info(\n  "event",\n  extra=ctx)`)
// escape pythonLogFirstArgIsStaticLiteral because the helper only sees
// `logger.info(`. The line-number map preserves the original startLine
// anchor so emitted findings still point at the call's opening line.
// scanPythonBodyForSinks returns the discovered sinks and a parallel
// slice of DangerousArgs (the catalog-declared dangerous-position list
// for each sink). The parallel slice lets callers honor positional
// danger constraints (e.g. re.match's pattern is arg 0) when assigning
// ArgFromParam — see PR-CAT6py fix B1.
func scanPythonBodyForSinks(body string, startLine int) ([]SinkRef, [][]int) {
	patterns := loadPythonSinkPatterns()
	if len(patterns) == 0 {
		return nil, nil
	}
	// PR-CAT5py fix 2: join parenthesised multi-line continuations so a
	// sink call's full first-argument list is visible in a single logical
	// line. The offsets slice maps each joined line back to its first
	// physical-line index (0-based within body), which we use to anchor
	// findings to the original line numbering.
	lines, offsets := joinPythonParenContinuations(body)
	var out []SinkRef
	var dangerousArgs [][]int
	for i, line := range lines {
		// Skip comment-only lines so `# os.system(...) is dangerous`
		// in a docstring doesn't fire as a sink.
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			if p.requireModule && p.module != "" {
				// Cheap textual gate — the line must contain the
				// module name. Mirrors the bare-name collision guard
				// in SinkDef.RequireModule for tree-sitter languages.
				if !strings.Contains(line, p.module) {
					continue
				}
			}
			// PR-CAT2py: inline-sanitizer suppression on the sink line.
			// Only applies to categories where the catalog sanitizer is
			// expected to neutralise the danger end-to-end. HTMLOutput
			// is the canonical case (render_to_string auto-escape);
			// Redirect handles the Django/Sentry url-validator wrap.
			if pythonSanitizerRe.MatchString(line) {
				if sinkLineSanitizerNeutralises(p.category) {
					continue
				}
			}
			// PR-CAT5py fix 1: `del request.session[k]`, `.session.pop(k)`,
			// and `.session.clear()` are session REMOVALS, not trust-
			// boundary writes. The catalog regex matches the subscript
			// shape but doesn't distinguish ops; we filter the delete /
			// pop / clear ops at the walker level. ~5 Sentry production
			// FPs (auth.py:434, sudo/utils.py:65, etc.).
			if p.category == taint.SnkTrustBoundary {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "del ") ||
					strings.Contains(line, ".session.pop(") ||
					strings.Contains(line, ".session.clear(") {
					continue
				}
			}
			// PR-CAT3py: trust-boundary RHS recognises the server-side
			// random / signing primitives that the catalog lists as
			// SnkTrustBoundary sanitizers but that pythonSanitizerRe
			// (a coarser net) doesn't include. Subscript writes like
			// `request.session[k] = secrets.token_hex(32)` are the
			// motivating Sentry shape.
			if p.category == taint.SnkTrustBoundary &&
				pythonTrustBoundarySafeRHSRe.MatchString(line) {
				continue
			}
			// PR-CAT5py fix 3: prev-line RHS sanitizer lookback. When the
			// sink line's RHS is a bare identifier (`session[k] = token`),
			// scan up to 3 prior non-blank / non-comment lines for the
			// last assignment to that identifier; if the prior RHS matches
			// pythonTrustBoundarySafeRHSRe, the value is server-generated
			// and the sink is safe. Motivating Sentry shape:
			//   token = get_random_string(12)
			//   request.session["_sudo"] = token
			if p.category == taint.SnkTrustBoundary &&
				prevLineTrustBoundarySanitizes(lines, i) {
				continue
			}
			// PR-CAT3py: structured logging with a constant format
			// string is NOT log injection. `logger.info("event.foo",
			// extra=ctx)` and `logger.warning("query.%s", x)` both pass
			// the format string through the stdlib `logging` formatter
			// server-side, which renders control characters inert. The
			// adversary-controlled `x` lives in a single field of the
			// formatted record, not the format string. The dominant
			// Sentry log_output FP shape.
			if p.category == taint.SnkLog &&
				pythonLogFirstArgIsStaticLiteral(line) {
				continue
			}
			// PR-CAT6py fix B1: when the catalog declares
			// DangerousArgs=[N] and the sink call's position-N arg is
			// a string / numeric literal, no taint can flow into the
			// dangerous slot. The motivating case is
			//
			//   re.match(r"^(\d+)([hdmsw]?)$", value)   # ReDoS arg=0
			//
			// where arg 0 is a hardcoded constant pattern. Without
			// this gate the wildcard `ArgFromParam=-1` fallback in
			// checkPythonCallerPassesTaintToCallee fires on the
			// haystack arg regardless of DangerousArgs.
			if pythonDangerousArgIsLiteral(line, p.dangerousArgs) {
				continue
			}
			// PR-CAT5py: anchor line number to the first physical line of
			// the (possibly joined) logical line so findings point at
			// where the call starts in the source.
			lineOffset := i
			if i < len(offsets) {
				lineOffset = offsets[i]
			}
			out = append(out, SinkRef{
				SinkCategory: p.category,
				MethodName:   p.method,
				Line:         startLine + lineOffset,
				ArgFromParam: -1, // refined by caller if a param flows in
			})
			dangerousArgs = append(dangerousArgs, p.dangerousArgs)
		}
	}
	return out, dangerousArgs
}

// joinPythonParenContinuations is a small, dependency-free preprocessor
// that joins physical lines inside an unclosed `(` / `[` / `{` into a
// single logical line. Mirrors the parenthesis-balance behaviour of
// scanner.JoinContinuationLines for Python but lives in `graph/` so
// we don't have to pull in the scanner package (which would create a
// dependency cycle — scanner imports graph for the call graph).
//
// Returns the joined lines (as a slice, not a single string — saves
// callers an extra Split) and an offset map where offsets[i] is the
// 0-based index within the original `body` of the FIRST physical line
// that became joined line i. Findings reported against logical line i
// anchor to body line offsets[i] so reported file positions still
// match the source.
//
// Triple-quoted string state is intentionally NOT tracked here: the
// cross-file walker only inspects function bodies (not module-level
// docstrings), and embedded triple-quotes inside function bodies are
// rare enough that the worst case is one or two harmless joins. The
// scanner's full joinPythonContinuations is more conservative — we
// trade a sliver of accuracy for keeping `graph/` dependency-free.
func joinPythonParenContinuations(body string) ([]string, []int) {
	src := strings.Split(body, "\n")
	out := make([]string, 0, len(src))
	offsets := make([]int, 0, len(src))
	depth := 0
	groupStart := 0
	var pending strings.Builder
	flush := func() {
		out = append(out, pending.String())
		offsets = append(offsets, groupStart)
		pending.Reset()
	}
	for i, line := range src {
		if depth == 0 {
			groupStart = i
			pending.WriteString(line)
		} else {
			// Continuation line: separate with a single space so
			// adjacent tokens don't accidentally fuse.
			pending.WriteByte(' ')
			pending.WriteString(strings.TrimSpace(line))
		}
		depth += pythonBracketDelta(line)
		if depth < 0 {
			depth = 0
		}
		if depth == 0 {
			flush()
		}
	}
	// Flush any unclosed remainder (malformed input — still emit so
	// scanning doesn't silently drop the tail).
	if pending.Len() > 0 {
		flush()
	}
	return out, offsets
}

// pythonBracketDelta returns the net change in (), [], {} nesting depth
// produced by `line`. Single-line string literals (' or ") are skipped
// so brackets inside strings don't perturb the count. Triple-quoted
// strings are out of scope (see joinPythonParenContinuations doc).
func pythonBracketDelta(line string) int {
	delta := 0
	inStr := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inStr {
			if c == '\\' && i+1 < len(line) {
				i++
				continue
			}
			if c == quote {
				inStr = false
			}
			continue
		}
		switch c {
		case '#':
			// Rest of the line is a comment — stop counting.
			return delta
		case '\'', '"':
			// Skip triple-quoted opens on the same line — counting
			// brackets inside a long-string is wrong, but for the
			// scope of a function body the simpler single-quote
			// handling below is enough.
			if i+2 < len(line) && line[i+1] == c && line[i+2] == c {
				// Find closing triple — bail if not on same line.
				end := strings.Index(line[i+3:], string([]byte{c, c, c}))
				if end < 0 {
					return delta
				}
				i += 3 + end + 2
				continue
			}
			inStr = true
			quote = c
		case '(', '[', '{':
			delta++
		case ')', ']', '}':
			delta--
		}
	}
	return delta
}

// prevLineTrustBoundarySanitizes implements PR-CAT5py fix 3: when the
// sink line on `lines[idx]` has a bare-identifier RHS, walk up to 3
// prior non-blank / non-comment lines for the last assignment to that
// identifier. Returns true iff such an assignment exists and its RHS
// matches pythonTrustBoundarySafeRHSRe (i.e. server-generated token).
//
// Conservative: only single-identifier RHS shapes are matched. Anything
// with operators, calls, or attribute access on the RHS of the sink
// line is treated as "too complex to reason about" and the lookback is
// not applied — keeps the suppression narrow.
func prevLineTrustBoundarySanitizes(lines []string, idx int) bool {
	if idx <= 0 || idx >= len(lines) {
		return false
	}
	ident := extractBareIdentRHS(lines[idx])
	if ident == "" {
		return false
	}
	// Walk up to 3 prior non-blank / non-comment lines.
	scanned := 0
	for j := idx - 1; j >= 0 && scanned < 3; j-- {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		scanned++
		// Look for `ident = <rhs>` (not == / != / <= / >=).
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx <= 0 {
			continue
		}
		if eqIdx+1 < len(trimmed) && trimmed[eqIdx+1] == '=' {
			continue
		}
		prev := trimmed[eqIdx-1]
		if prev == '!' || prev == '<' || prev == '>' || prev == '=' {
			continue
		}
		lhs := strings.TrimSpace(trimmed[:eqIdx])
		if lhs != ident {
			continue
		}
		rhs := trimmed[eqIdx+1:]
		if pythonTrustBoundarySafeRHSRe.MatchString(rhs) {
			return true
		}
		// Found an assignment to `ident` but RHS isn't a sanitizer —
		// further lookback would be unsound (intermediate reassignment).
		return false
	}
	return false
}

// extractBareIdentRHS pulls the single-identifier RHS from a Python
// subscript assignment of the form
//
//	<receiver>[<key>] = <ident>
//
// Returns the identifier when the RHS is exactly one word (no
// operators, no calls). Returns "" otherwise.
var pythonSubscriptBareIdentRHSRe = regexp.MustCompile(
	`[\w\.]+\s*\[[^\]]*\]\s*=\s*([A-Za-z_][\w]*)\s*$`,
)

func extractBareIdentRHS(line string) string {
	m := pythonSubscriptBareIdentRHSRe.FindStringSubmatch(strings.TrimRight(line, " \t"))
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// pythonTrustBoundarySinkRHSParamIdx implements PR-CAT6py fix A: when a
// SnkTrustBoundary sink line is a session subscript write whose RHS is
// a bare identifier (`request.session[<lit>] = org_slug`), return the
// index of the callee parameter whose name matches that RHS identifier
// — if any. Returns -1 when:
//   - the line doesn't match the bare-ident subscript-write shape, OR
//   - the RHS ident doesn't match any callee parameter (could be a
//     local variable; let the existing checks run unchanged).
//
// The point of identifying the RHS param is that an assignment
// `session[k] = <param>` is only dangerous if THAT param carried tainted
// data from the caller. If the caller passed a literal / constant for
// that param, the assignment is benign even though the request param
// (and other args) are still in scope. Without this disambiguation the
// walker fires whenever ANY tainted arg is passed at any position,
// producing the Sentry auth.py:170 / 337 / 434 false positives.
func pythonTrustBoundarySinkRHSParamIdx(line string, sig *TaintSignature) int {
	if sig == nil || len(sig.Params) == 0 {
		return -1
	}
	ident := extractBareIdentRHS(line)
	if ident == "" {
		return -1
	}
	for _, p := range sig.Params {
		if p.Name == ident {
			return p.Index
		}
	}
	return -1
}

// sinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
// Kept conservative — only the categories where a wrap-style sanitizer
// makes the downstream call unambiguously safe. Categories like
// SQLQuery, Command, Deserialize don't apply (a single safe-looking
// `escape()` call on the line tells us nothing about whether the SQL
// query itself is parameterised).
func sinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkTemplate, taint.SnkTrustBoundary:
		return true
	}
	return false
}

// pythonTrustBoundarySafeRHSRe matches the RHS shapes that are safe to
// assign into a session/cookie/identity store without considering the
// LHS arg "user-controlled": server-generated tokens, server-signed
// payloads, and host-allowlist-validated redirect URLs. The
// corresponding catalog sanitizer entries live in
// `taint/languages/python_sanitizers.go` (py.trust.*).
//
// Used by scanPythonBodyForSinks alongside `sinkLineSanitizerNeutralises`
// so the cross-file walker mirrors the same-file tsflow walker's
// decision for the SnkTrustBoundary category on real Sentry shapes:
//
//	request.session["_sudo"]      = get_random_string(12)
//	request.session["csrf_token"] = secrets.token_hex(32)
//	request.session["sid"]        = str(uuid.uuid4())
//	request.session["_next"]      = is_valid_redirect(next_url, ...)
var pythonTrustBoundarySafeRHSRe = regexp.MustCompile(
	`\b(?:` +
		`secrets\.token_(?:hex|bytes|urlsafe)` +
		`|uuid\.uuid[14]` +
		`|os\.urandom` +
		`|get_random_string` +
		`|hashlib\.\w+\([^)]*\)\.(?:hex)?digest` +
		`|hmac\.(?:new|HMAC)\([^)]*\)\.(?:hex)?digest` +
		`|jwt\.encode` +
		`|signing\.(?:dumps|TimestampSigner|Signer)` +
		`)\s*\(`,
)

// pythonLogFirstArgIsStaticLiteral reports whether the first positional
// argument of a logger.<level>(...) call on `line` is a plain string
// literal — i.e. a constant format string. Structured logging shapes
// that Python's stdlib logger handles safely:
//
//	logger.info("event.foo")
//	logger.info("event.foo", extra=ctx)
//	logger.warning("query.deprecated.%s", dataset_label)
//
// All return true. Dynamic / interpolated first-arg shapes return false
// because the format string itself is user-influenced (which IS log
// injection):
//
//	logger.info(f"User {uid} acted")
//	logger.info("user {0}".format(name))
//	logger.info("user %s" % name)
//	logger.info(msg)                    # bare identifier
//	logger.info("user " + name)         # concat
//
// Anchored on `logger.<method>(` / `log.<method>(` / `<name>.<method>(`
// patterns where `<method>` is a stdlib logging level. Lines that don't
// resemble a log call return false; the caller already filtered by
// SnkLog category, so we don't need to re-validate the call shape.
func pythonLogFirstArgIsStaticLiteral(line string) bool {
	// Locate the opening paren of the first log-method call on the line.
	loc := pythonLogCallOpenParenRe.FindStringIndex(line)
	if loc == nil {
		return false
	}
	rest := line[loc[1]:]
	// Strip leading whitespace inside the parens.
	for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return false
	}
	// Recognise the f/F/r/R/b/B string prefixes. An `f`/`F` prefix
	// (including combinations like `rf"..."`, `fr"..."`, `bf"..."`)
	// means an f-string — interpolated, NOT a static literal.
	if pythonFStringPrefixRe.MatchString(rest) {
		return false
	}
	// Walk past any non-f string prefix (r"...", b"...", u"...").
	for len(rest) > 0 && (isASCIILetter(rest[0])) {
		c := rest[0]
		if c == 'f' || c == 'F' {
			return false
		}
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return false
	}
	// The first non-prefix char must be a quote to be a string literal.
	q := rest[0]
	if q != '"' && q != '\'' {
		return false
	}
	// Find the matching close-quote (respect simple backslash escapes).
	idx := 1
	for idx < len(rest) {
		c := rest[idx]
		if c == '\\' && idx+1 < len(rest) {
			idx += 2
			continue
		}
		if c == q {
			break
		}
		idx++
	}
	if idx >= len(rest) {
		return false
	}
	// After the close-quote the next non-whitespace char must be one of
	// `,`, `)`, or `%` for `"…%s" % name`. A trailing `.format(`,
	// `.format_map(`, or a `+` concat disqualifies the literal because
	// the runtime format string is then dynamic.
	tail := rest[idx+1:]
	for len(tail) > 0 && (tail[0] == ' ' || tail[0] == '\t') {
		tail = tail[1:]
	}
	if len(tail) == 0 {
		// `logger.info("foo"` with no closing paren on this physical
		// line — conservatively treat as static; multi-line shapes are
		// stitched by the preprocessor before sinks run.
		return true
	}
	switch tail[0] {
	case ',', ')':
		return true
	case '.':
		// `"…".format(` / `"…".format_map(` — runtime substitution into
		// the literal, not a static format string.
		if strings.HasPrefix(tail, ".format") {
			return false
		}
		return true
	case '%':
		// `"…%s" % name` — the Python `%` operator builds the dynamic
		// format string BEFORE the logger sees it; the literal that
		// reaches `logger.info(...)` is already
		// `"…<user-controlled name>"`. The structured-logging shape
		// (`logger.info("…%s", name)`) is a comma at this point, not
		// a `%`, so the comma branch above handles it.
		return false
	case '+':
		// String concatenation builds a dynamic format string.
		return false
	}
	return true
}

var (
	// pythonLogCallOpenParenRe matches `<receiver>.<level>(` where
	// <level> is a stdlib logging method. Anchors the helper above on
	// the actual log call (and not a `logger.bind(...)` or similar).
	pythonLogCallOpenParenRe = regexp.MustCompile(
		`\b(?:log|logger|logging|LOG|_log|self\.log|self\.logger)\.` +
			`(?:debug|info|warn|warning|error|exception|critical|fatal|log)\s*\(`,
	)
	// pythonFStringPrefixRe matches Python f-string prefixes (any of
	// `f`, `F`, optionally combined with `r`/`R`/`b`/`B`) immediately
	// followed by a quote. Order-independent: `rf"..."` and `fr"..."`
	// both qualify.
	pythonFStringPrefixRe = regexp.MustCompile(`^[rRbB]?[fF][rRbB]?["']|^[fF]["']`)
)

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// findPythonParamFlowToSink is the Python analog of findParamFlowToSink:
// returns the source-param index whose name appears in the sink line's
// argument expression, or -1 when none do. Uses token-matching so
// short names like `q` don't substring into unrelated identifiers.
func findPythonParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
	if len(sig.SourceParams) == 0 || sinkLineIdx < 0 || sinkLineIdx >= len(lines) {
		return -1
	}
	sinkLine := lines[sinkLineIdx]
	for paramIdx := range sig.SourceParams {
		paramName := paramNameFromSig(sig, paramIdx)
		if paramName == "" {
			continue
		}
		if containsToken(sinkLine, paramName) {
			return paramIdx
		}
	}
	return -1
}

// findPythonParamFlowToSinkFiltered is the Python analog of
// findParamFlowToSinkFiltered (interprocedural.go). When dangerousArgs
// is non-empty, the trace is restricted to those positional arg slots
// of the sink call — mirroring catalog DangerousArgs annotations like
// re.match's `[0]` (pattern arg, not haystack). Falls back to the
// legacy "any arg position" behaviour when dangerousArgs is nil/empty
// or has the wildcard sentinel `-1`.
func findPythonParamFlowToSinkFiltered(
	lines []string, sinkLineIdx int, sig *TaintSignature, dangerousArgs []int,
) int {
	if len(dangerousArgs) == 0 || hasWildcardDangerousArg(dangerousArgs) {
		return findPythonParamFlowToSink(lines, sinkLineIdx, sig)
	}
	if len(sig.SourceParams) == 0 || sinkLineIdx < 0 || sinkLineIdx >= len(lines) {
		return -1
	}
	sinkLine := lines[sinkLineIdx]
	parenIdx := strings.Index(sinkLine, "(")
	if parenIdx < 0 {
		return -1
	}
	args := extractArgList(sinkLine[parenIdx:])
	if len(args) == 0 {
		return -1
	}
	wanted := make(map[int]bool, len(dangerousArgs))
	for _, i := range dangerousArgs {
		wanted[i] = true
	}
	for paramIdx := range sig.SourceParams {
		paramName := paramNameFromSig(sig, paramIdx)
		if paramName == "" {
			continue
		}
		for callArgIdx, arg := range args {
			if !wanted[callArgIdx] {
				continue
			}
			arg = strings.TrimSpace(arg)
			if arg == paramName {
				return paramIdx
			}
			if containsToken(arg, paramName) {
				return paramIdx
			}
		}
	}
	return -1
}

// hasWildcardDangerousArg reports whether the dangerous-args list
// includes the wildcard sentinel `-1` ("any arg may be dangerous"). The
// catalog uses `[-1]` for sinks whose taint-sensitive positions are
// shape-dependent (e.g. ES `.sql.query(body=...)` where the query
// string can appear positionally OR as a keyword).
func hasWildcardDangerousArg(args []int) bool {
	for _, a := range args {
		if a == -1 {
			return true
		}
	}
	return false
}

// pythonDangerousArgIsLiteral reports whether ALL of the catalog-
// declared DangerousArgs positions on the given sink call line are
// string / numeric / boolean literals (i.e. cannot carry taint). Used
// by scanPythonBodyForSinks to suppress sinks like
//
//	re.match(r"^const$", value)            # DangerousArgs=[0]
//
// where the dangerous position is unambiguously constant. Returns false
// when:
//   - dangerousArgs is empty or has the `-1` wildcard sentinel,
//   - the line has no `(` (couldn't extract args),
//   - the dangerous position is missing or non-literal.
//
// Conservative: only the explicit dangerous positions are checked. A
// regex pattern stored in a module-level constant like
// `RE = re.compile(STATS_PATTERN); RE.match(value)` is NOT suppressed
// here — STATS_PATTERN is an identifier and the catalog can't tell
// without taint flow whether it's a literal upstream.
func pythonDangerousArgIsLiteral(line string, dangerousArgs []int) bool {
	if len(dangerousArgs) == 0 || hasWildcardDangerousArg(dangerousArgs) {
		return false
	}
	parenIdx := strings.Index(line, "(")
	if parenIdx < 0 {
		return false
	}
	args := extractArgList(line[parenIdx:])
	if len(args) == 0 {
		return false
	}
	for _, pos := range dangerousArgs {
		if pos < 0 || pos >= len(args) {
			return false
		}
		arg := strings.TrimSpace(args[pos])
		if arg == "" {
			return false
		}
		if !isPythonLiteralArg(arg) {
			return false
		}
	}
	return true
}

// isPythonLiteralArg reports whether arg is a *pure* Python literal —
// a single string (any quote style + prefix), numeric, boolean, or
// None expression with no operators, concatenations, formatting, or
// trailing identifiers. Used by pythonDangerousArgIsLiteral to decide
// whether a dangerous-position arg can carry taint at all.
//
// Conservative: identifier-shaped args (even capitalised constants
// like `STATS_PATTERN`), string concatenations
// (`"prefix" + tainted_var`), f-strings (`f"x{taint}"`), `.format(...)`,
// `%` interpolation, and parenthesised expressions all return false so
// we don't suppress real vulnerabilities.
func isPythonLiteralArg(arg string) bool {
	if arg == "" {
		return false
	}

	// Boolean / None.
	switch arg {
	case "True", "False", "None":
		return true
	}

	// Numeric literal (digits, optional sign, optional decimal). The
	// arg must consist of ONLY numeric characters / sign / dot / 'e'
	// (exponent) / 'j' (imaginary) / '_' (digit separator) — anything
	// else (operator, identifier suffix) disqualifies it.
	first := arg[0]
	if (first >= '0' && first <= '9') || first == '-' || first == '+' || first == '.' {
		allNumeric := true
		for i := 0; i < len(arg); i++ {
			c := arg[i]
			if (c >= '0' && c <= '9') || c == '.' || c == '_' ||
				c == 'e' || c == 'E' || c == 'j' || c == 'J' ||
				c == 'x' || c == 'X' || c == 'b' || c == 'B' ||
				c == 'o' || c == 'O' ||
				((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				continue
			}
			if i == 0 && (c == '-' || c == '+') {
				continue
			}
			allNumeric = false
			break
		}
		if allNumeric {
			return true
		}
	}

	// String literal — handle optional prefix (r/R/b/B/u/U/f/F up to
	// 2 chars), then the opening quote. An f-string is NOT a pure
	// literal (it interpolates expressions) so reject when the
	// prefix contains 'f' / 'F'.
	prefixEnd := 0
	for prefixEnd < 2 && prefixEnd < len(arg) {
		c := arg[prefixEnd]
		if c == 'r' || c == 'R' || c == 'b' || c == 'B' || c == 'u' || c == 'U' {
			prefixEnd++
			continue
		}
		if c == 'f' || c == 'F' {
			return false // f-string interpolates → not pure literal
		}
		break
	}
	if prefixEnd >= len(arg) {
		return false
	}
	q := arg[prefixEnd]
	if q != '"' && q != '\'' {
		return false
	}
	// Find the matching closing quote, respecting backslash escapes.
	// Triple-quoted strings are handled by the same loop (the first
	// closing quote terminates a single-quoted literal; triples are
	// rare in arg position).
	i := prefixEnd + 1
	for i < len(arg) {
		c := arg[i]
		if c == '\\' && i+1 < len(arg) {
			i += 2
			continue
		}
		if c == q {
			// The string closes at i. Anything after — operators,
			// concatenation, .format(...), % — means this is NOT a
			// pure literal.
			rest := strings.TrimSpace(arg[i+1:])
			return rest == ""
		}
		i++
	}
	return false
}

// paramNameFromSig returns the Name of the typed Param at idx, or "".
// Used in place of findParamName (which only works on Go-style decl
// lines) because Python's def signature spans multiple parsing rules
// and the extractor already gave us the typed names.
func paramNameFromSig(sig *TaintSignature, idx int) string {
	for _, p := range sig.Params {
		if p.Index == idx {
			return p.Name
		}
	}
	return ""
}

// isArgTaintedInPythonCaller checks whether argExpr is tainted in the
// caller's context. The Go version regex-scans for *http.Request and
// friends; here we check the caller's typed Params (the extractor
// sets IsSourceType for `req: Request` etc.) and the catalog-derived
// pythonSourceExprRe for inline source expressions. Thin wrapper over
// the shared crossfileIsArgTaintedInCaller (crossfile_walk_core.go).
func isArgTaintedInPythonCaller(argExpr string, callerLines []string, callLineIdx int, callerSig *TaintSignature) bool {
	return crossfileIsArgTaintedInCaller(pythonCrossfileWalkCfg, argExpr, callerLines, callLineIdx, callerSig)
}
