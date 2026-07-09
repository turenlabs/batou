// Ruby cross-file interprocedural walker (PR-Gruby).
//
// Like the JS / Python equivalents, the Go-default AnalyzeCallerImpact in
// interprocedural.go scans the caller body with the Go sink regex table
// and uses Go arg parsing. Routing Ruby through that path emits zero
// findings — Ruby calls never match Go sink shapes.
//
// This file mirrors crossfile_walk_javascript.go. It uses tree-sitter to
// find call expressions in the caller, the Ruby taint catalog
// (SinksForLanguage / SourcesForLanguage) to identify sinks inside callee
// bodies, and a coarse direct-source regex for typical Rails / Sinatra /
// Roda request shapes (`params[`, `request.headers[`, `ENV[`, etc.).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a Ruby callee that
//     forwards it into a sink. Direct source expressions in the call
//     site (`params[:url]`, `request.body`, ...) are recognised.
//   - Path B: callee returns tainted data and the caller passes the
//     result to a sink. Recognised when the callee has TaintedReturns
//     set (the builder doesn't tag these automatically yet — tests plant
//     them where needed; future work tightens automatic propagation).
//   - 1-hop interproc only — multi-module relays are out of scope for
//     this PR.
//
// As with the JS and Python walkers, the Ruby walker IS allowed to
// populate a callee's TaintSig.SinkCalls on the fly when it's empty.
// The same-file PropagateInterproc path doesn't run Ruby sink regex
// either, so most Ruby callees arrive at the cross-file walk with
// SinkCalls == nil.

package graph

import (
	"regexp"
	"strings"
	"sync"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// rubySinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadRubySinkPatterns
// and its stored-state consumer (loadRubyStoredStateSinks) interoperate with
// the shared walk core without conversion (mirrors pythonSinkPattern).
type rubySinkPattern = crossfileSinkPattern

var (
	rubySinkPatternsCache   []rubySinkPattern
	rubySinkPatternsCacheMu sync.Mutex
)

// loadRubySinkPatterns compiles and caches the Ruby taint sink catalog
// into regex form. Returns the cached slice on second+ calls.
func loadRubySinkPatterns() []rubySinkPattern {
	rubySinkPatternsCacheMu.Lock()
	defer rubySinkPatternsCacheMu.Unlock()
	if rubySinkPatternsCache != nil {
		return rubySinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangRuby)
	out := make([]rubySinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, rubySinkPattern{
			pattern:       re,
			category:      s.Category,
			method:        s.MethodName,
			dangerousArgs: s.DangerousArgs,
			module:        s.ObjectType,
			requireModule: false,
		})
	}
	rubySinkPatternsCache = out
	return out
}

// rubySourceExprRe matches taint source expressions in a Ruby arg
// position. Conservative — Rails / Sinatra / Rack / Roda request shapes
// in the canonical reads. Mirrors javascriptSourceExprRe.
var rubySourceExprRe = regexp.MustCompile(
	`\bparams\s*\[` +
		`|\brequest\.headers\s*\[` +
		`|\brequest\.body\b` +
		`|\brequest\.cookies\s*\[` +
		`|\brequest\.query_string\b` +
		`|\brequest\.params\b` +
		`|\brequest\.env\s*\[` +
		`|\bENV\s*\[` +
		`|\bSTDIN\b` +
		`|\bARGV\b` +
		`|\bcookies\s*\[` +
		`|\bsession\s*\[`,
)

// rubySanitizerRe matches common Ruby sanitizer-call shapes. Coarse net
// for the cross-file pass — the per-file tsflow walker is the source of
// truth. Kept narrow to avoid swallowing the canonical-fix path before
// the sink fires.
//
// Coverage (intentionally small):
//   - Rack::Utils.escape* / ERB::Util.html_escape — HTML escaping
//   - CGI.escape / CGI.escapeHTML — URL / HTML escaping
//   - URI.encode_www_form_component — URL encoding
//   - Shellwords.escape — shell quoting
//   - JSON.parse — switches to safe deserialization (defense)
//   - sanitize() — Rails sanitizer helper
var rubySanitizerRe = regexp.MustCompile(
	`\b(?:` +
		`Rack::Utils\.escape(?:_html|_path)?` +
		`|ERB::Util\.(?:html_escape|h)` +
		`|CGI\.escape(?:HTML)?` +
		`|URI\.encode_www_form_component` +
		`|URI\.encode_www_form` +
		`|Shellwords\.escape` +
		`|Shellwords\.shellescape` +
		`|JSON\.parse` +
		`|sanitize_sql(?:_array)?` +
		`|sanitize_sql_like` +
		`|sanitize` +
		`|escape_html` +
		`|escape` +
		`)\s*[\(\.]`,
)

// AnalyzeCallerImpactRuby mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find Ruby call expressions in the caller body and
// the Ruby taint catalog to identify sinks inside the callee. Returns
// findings keyed by the same BATOU-INTERPROC-<CAT> rule IDs the Go,
// Python, and JS paths use so downstream consumers don't need
// language-specific dispatch.
func AnalyzeCallerImpactRuby(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactRubyCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactRubyCached is the cached variant for the
// cross-file pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks -> extract caller body -> call sites ->
// Path A / Path B) lives in the shared core (crossfile_walk_core.go); this
// wrapper only supplies the Ruby config (rubyCrossfileWalkCfg) and the
// call-site finder bound to the typed cache.
func analyzeCallerImpactRubyCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *rubyCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		rubyCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return rubyCallSitesToShared(findRubyCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// rubyCallSitesToShared converts rubyCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func rubyCallSitesToShared(in []rubyCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureRubyCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls
// when it's empty. Idempotent — skips work when already populated.
func ensureRubyCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangRuby {
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
	sinks := scanRubyBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	// Map each sink to a param index by checking if any caller-visible
	// param name appears in the sink call's args. Same shape as the
	// Python / JS fallback path.
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findRubyParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// scanRubyBodyForSinks walks the body line-by-line with each cached
// rubySinkPattern. Returns SinkRef rows with file-absolute line numbers.
// Multiple distinct sinks on the same line each produce their own row.
func scanRubyBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadRubySinkPatterns()
	if len(patterns) == 0 {
		return nil
	}
	lines := strings.Split(body, "\n")
	var out []SinkRef
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comment-only lines (`# ...`) so commented dangerous calls
		// don't fire.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			// Inline sanitizer suppression for HTML output / redirect
			// categories. Same rationale as the JS helper.
			if rubySanitizerRe.MatchString(line) {
				if rubySinkLineSanitizerNeutralises(p.category) {
					continue
				}
			}
			out = append(out, SinkRef{
				SinkCategory: p.category,
				MethodName:   p.method,
				Line:         startLine + i,
				ArgFromParam: -1,
			})
		}
	}
	return out
}

// rubySinkLineSanitizerNeutralises returns true for sink categories
// whose matched-on-the-same-line sanitiser call should suppress the
// sink. Mirrors jsSinkLineSanitizerNeutralises.
func rubySinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkTemplate:
		return true
	}
	return false
}

// findRubyParamFlowToSink returns the source-param index whose name
// appears in the sink line's argument expression, or -1 when none do.
// Uses token-matching so short names don't substring into unrelated
// identifiers.
func findRubyParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
	if sig == nil || sinkLineIdx < 0 || sinkLineIdx >= len(lines) {
		return -1
	}
	sinkLine := lines[sinkLineIdx]
	if len(sig.SourceParams) > 0 {
		for paramIdx := range sig.SourceParams {
			name := paramNameFromSig(sig, paramIdx)
			if name == "" {
				continue
			}
			if containsToken(sinkLine, name) {
				return paramIdx
			}
		}
		return -1
	}
	for _, p := range sig.Params {
		if p.Name == "" {
			continue
		}
		if containsToken(sinkLine, p.Name) {
			return p.Index
		}
	}
	return -1
}

// findRubyCallSites parses callerContent with tree-sitter and returns
// every call expression to a function whose simple name equals
// extractBaseName(calleeName). Falls back to nil when parsing fails.
//
// Ruby-specific gotchas:
//   - The call node type is `call`.
//   - Method name is on the `method` field; receiver on the `receiver`
//     field (may be nil for bare calls).
//   - Assignments are `assignment` nodes: identifier `=` <expr>.
//   - `Foo.bar(...)` parses as call with receiver=constant("Foo"),
//     method=identifier("bar"). We match `bar` against the callee
//     basename (after the last `.`) so `Foo.bar` reaches a callee
//     declared as `Foo.bar`.
func findRubyCallSites(callerContent string, callerNode *FuncNode, calleeName string) []rubyCallSite {
	tree := tsast.Parse([]byte(callerContent), rules.LangRuby)
	if tree == nil || tree.Root() == nil {
		return nil
	}
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}

	var out []rubyCallSite
	var visit func(n *tsast.Node, parentAssignTarget string)
	visit = func(n *tsast.Node, parentAssignTarget string) {
		if n == nil {
			return
		}
		if int(n.StartRow())+1 > callerNode.EndLine {
			return
		}
		if int(n.EndRow())+1 < callerNode.StartLine {
			return
		}

		switch n.Type() {
		case "call":
			if matchesRubyCallName(n, baseName) {
				cs := rubyCallSite{
					line:       int(n.StartRow()) + 1,
					assignedTo: parentAssignTarget,
				}
				if argList := n.ChildByFieldName("arguments"); argList != nil {
					cs.args = extractRubyCallArgs(argList)
				}
				if cs.line >= callerNode.StartLine && cs.line <= callerNode.EndLine {
					out = append(out, cs)
				}
			}
		case "assignment":
			lhs := n.ChildByFieldName("left")
			rhs := n.ChildByFieldName("right")
			if lhs != nil && rhs != nil && lhs.Type() == "identifier" {
				name := strings.TrimSpace(lhs.Text())
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

// matchesRubyCallName reports whether a call node's method-name field
// equals baseName. Handles bare calls (`foo(...)`) and receiver-method
// calls (`Foo.bar(...)`, `obj.baz(...)`).
func matchesRubyCallName(call *tsast.Node, baseName string) bool {
	m := call.ChildByFieldName("method")
	if m == nil {
		return false
	}
	return strings.TrimSpace(m.Text()) == baseName
}

// extractRubyCallArgs returns positional argument text from a
// tree-sitter `argument_list` node. Hash splats, block-pass, and
// keyword args are returned as their raw text. The walker treats every
// non-block child as a positional arg — Ruby doesn't have a hard
// language-level boundary between positional and keyword args.
func extractRubyCallArgs(argList *tsast.Node) []string {
	var args []string
	for _, child := range argList.NamedChildren() {
		args = append(args, strings.TrimSpace(child.Text()))
	}
	return args
}
