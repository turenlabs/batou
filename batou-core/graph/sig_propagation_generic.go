// Generic cross-file taint-signature propagation (#37, multi-hop).
//
// The Go / Python / JS branches in PropagateSignaturesAcrossCallgraph
// share one shape: for each caller, find the call sites of each callee
// (via the per-language findXCallSitesIndexed), and for every callee that
// carries lifted-up sinks OR a tainted return, lift those up into the
// caller's signature via the shared appendInheritedSink / appendInherited-
// Return helpers. Only the call-site discovery, the leaf-sink/-return
// producers, and the call-index cache type differ per language.
//
// Every non-Go/Py/JS cross-file language already ships:
//   - a findXCallSitesIndexed returning []xCallSite{line, args, assignedTo}
//     with an identical field shape across all 11 languages, and
//   - ensureXCalleeSinks / ensureXCalleeReturns leaf producers.
//
// This file factors the shared loop into propagateForGenericCaller, driven
// by a small per-language adapter (genericLangPropagator). Wiring a
// language into the multi-hop fixpoint is now one table entry — no new
// per-language propagateFor<Lang>Caller copy of the ~80-line loop.
//
// Same-language gating is enforced at two layers: the dispatch only invokes
// a propagator for callers of that language, and every lift is additionally
// gated callee.Language == caller.Language so a (e.g.) Go convention can
// never lift into a Swift caller.
package graph

import (
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// genericCallSite is the common projection of every per-language
// xCallSite. All 11 generalized languages use the identical
// {line, args, assignedTo} shape, so the adapter's findCallSites closure
// flattens its concrete slice into this type with no information loss.
type genericCallSite struct {
	line       int
	args       []string
	assignedTo string
}

// genericLangPropagator adapts one language's call-site discovery and leaf
// producers to the shared propagateForGenericCaller loop. It is the ENTIRE
// per-language surface needed to join the multi-hop fixpoint.
//
// langs is the set of FuncNode.Language values this propagator owns. It is
// usually a single language; C/C++ share one walker (LangC and LangCPP) so
// it carries both, matching the same-language gate used by the cross-file
// walk dispatch. A lift is allowed only when callee.Language is in langs
// AND equals the caller's own language is NOT required across the C-family
// pair — see langMatches.
type genericLangPropagator struct {
	// langs are the FuncNode.Language values this adapter handles.
	langs []rules.Language

	// findCallSites returns the call sites of calleeName inside the
	// caller's body. The cache is the per-pass parse cache returned by
	// newCache; callers pass it through so each file is parsed once.
	findCallSites func(cache interface{}, content string, caller *FuncNode, calleeName string) []genericCallSite

	// ensureSinks / ensureReturns lazily populate a leaf callee's
	// SinkCalls / TaintedReturns the first time it is seen, mirroring the
	// Python/JS pre-passes. ensureReturns may be nil for languages whose
	// walker does not yet produce tainted returns (Ruby).
	ensureSinks   func(cg *CallGraph, callee *FuncNode)
	ensureReturns func(cg *CallGraph, callee *FuncNode)
}

// langMatches reports whether l is one of this propagator's languages.
func (p *genericLangPropagator) langMatches(l rules.Language) bool {
	for _, want := range p.langs {
		if l == want {
			return true
		}
	}
	return false
}

// genericDeclScanWindow bounds how many leading body lines
// genericCallerParamNames scans for the function-declaration header. A
// node's StartLine lands on or within a couple of lines of the signature
// for every generalized language; keeping the window tight prevents a `(`
// deeper in the body (a call) from being mistaken for the signature.
const genericDeclScanWindow = 3

// genericCallerParamNames returns the caller's parameter names. It prefers
// the typed TaintSig.Params when populated (Go/Py/JS) and otherwise parses
// the function-declaration line — the first body line returned by
// extractFuncBody, which for every generalized language is the signature.
//
// The decl parser is intentionally permissive across language syntaxes so a
// single helper serves all 11 generalized languages:
//
//   - C# / Java / C++ / Rust: `Type name` / `Type& name` / `name: Type`
//   - Swift / Kotlin:        `label name: Type` / `name: Type`
//   - PHP:                    `$name` / `Type $name`
//   - Ruby / Lua / Python:    `name` / `name = default`
//
// For each comma-separated parameter we extract the bound NAME identifier:
// the token AFTER a `:` if present (Swift/Kotlin `name: Type`), else the
// LAST bare identifier (covers `Type name`, `Type& name`, `$name`, plain
// `name`, and `name = default` once the default is stripped). A `$` prefix
// (PHP) is preserved on the name so it matches the `$n` argument tokens the
// call site carries. Tokens that don't yield an identifier (e.g. `*`, `&`,
// `...`) are skipped — a conservative omission only drops a lift, never
// invents one.
func genericCallerParamNames(node *FuncNode, bodyLines []string) []string {
	if node != nil && len(node.TaintSig.Params) > 0 {
		out := make([]string, len(node.TaintSig.Params))
		for i, p := range node.TaintSig.Params {
			out[i] = p.Name
		}
		return out
	}
	if len(bodyLines) == 0 {
		return nil
	}
	// Locate the function-declaration line. extractFuncBody returns body
	// lines starting at the node's StartLine, but StartLine does not always
	// land EXACTLY on the signature: some builders (e.g. the Lua
	// table-method builder) record the line above the `function X.y(...)`
	// header. Scan the first few lines for the first one carrying a `(` so
	// the param parse is robust to a small StartLine offset. The window is
	// tight (a handful of lines) so a deeper `(` inside the body — e.g. a
	// call — can't be mistaken for the signature.
	declLine := ""
	open := -1
	for i := 0; i < len(bodyLines) && i < genericDeclScanWindow; i++ {
		if o := strings.Index(bodyLines[i], "("); o >= 0 {
			declLine = bodyLines[i]
			open = o
			break
		}
	}
	if open < 0 {
		return nil
	}
	// Walk to the matching close paren so a parameter default that itself
	// contains a `(` doesn't truncate the list early.
	depth := 0
	closeIdx := -1
	for i := open; i < len(declLine); i++ {
		switch declLine[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				closeIdx = i
			}
		}
		if closeIdx >= 0 {
			break
		}
	}
	if closeIdx <= open {
		return nil
	}
	inner := declLine[open+1 : closeIdx]
	if strings.TrimSpace(inner) == "" {
		return nil
	}
	var names []string
	for _, part := range splitTopLevelCommas(inner) {
		name := genericParamName(part)
		// Keep a placeholder for unparseable params so positional indices
		// stay aligned with the call site's positional args.
		names = append(names, name)
	}
	return names
}

// splitTopLevelCommas splits s on commas that are not nested inside
// (), [], <>, or {} — so a parameter whose type carries a generic argument
// (`Map<String, Int> m`) or a default (`f(a, b = (1, 2))`) is not split
// mid-type. Used by genericCallerParamNames to separate parameters.
func splitTopLevelCommas(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// genericParamName extracts the bound parameter NAME from one comma-split
// parameter declaration. Returns "" when no identifier can be recovered
// (the caller keeps the slot as a placeholder so positions stay aligned).
func genericParamName(part string) string {
	part = strings.TrimSpace(part)
	if part == "" {
		return ""
	}
	// Strip a default value (`name = expr`, `Type name = expr`).
	if eq := strings.Index(part, "="); eq >= 0 {
		part = strings.TrimSpace(part[:eq])
	}
	if part == "" {
		return ""
	}
	// Swift / Kotlin `name: Type` (and `label name: Type`): the name is the
	// last identifier BEFORE the first SINGLE colon. A DOUBLE colon is the
	// C++/Rust scope operator (`const std::string& c`) — NOT a name:type
	// separator — so we must not split on it, or we'd return `std` instead
	// of the real parameter name `c`. Find the first colon that is not part
	// of a `::`.
	if colon := firstSingleColon(part); colon > 0 {
		left := strings.TrimSpace(part[:colon])
		if id := lastIdentifier(left, true); id != "" {
			return id
		}
	}
	// Otherwise the name is the last identifier in the declaration
	// (`Type name`, `Type& name`, `$name`, bare `name`).
	return lastIdentifier(part, true)
}

// lastIdentifier returns the last identifier-looking token in s. When
// allowDollar is true a leading `$` (PHP variable sigil) is preserved so the
// result matches the `$n` argument tokens the PHP call site carries.
// Identifier characters are [A-Za-z0-9_] plus an optional leading `$`.
func lastIdentifier(s string, allowDollar bool) string {
	end := len(s)
	// Trim trailing non-identifier chars.
	for end > 0 && !isIdentChar(s[end-1]) {
		end--
	}
	if end == 0 {
		return ""
	}
	start := end
	for start > 0 && isIdentChar(s[start-1]) {
		start--
	}
	name := s[start:end]
	if allowDollar && start > 0 && s[start-1] == '$' {
		name = "$" + name
	}
	return name
}

// firstSingleColon returns the index of the first `:` in s that is NOT part
// of a `::` token, or -1 when none exists. Used to tell the Swift/Kotlin
// `name: Type` separator from the C++/Rust `::` scope operator so a typed
// parameter like `const std::string& c` is not mis-split at `std::`.
func firstSingleColon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] != ':' {
			continue
		}
		// Part of a `::`? Skip both colons.
		if i+1 < len(s) && s[i+1] == ':' {
			i++
			continue
		}
		if i > 0 && s[i-1] == ':' {
			continue
		}
		return i
	}
	return -1
}

// isIdentChar reports whether b is a C-family identifier character.
func isIdentChar(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// propagateForGenericCaller is the per-language-agnostic analog of
// propagateForPythonCallerCached / propagateForJavaScriptCallerCached. It
// runs the shared sink-lift + return-lift composition for one caller using
// the adapter's call-site discovery and the shared appendInheritedSink /
// appendInheritedReturn helpers. Returns the number of new sink/return
// entries appended (so the fixed-point keeps converging).
//
// cache is the adapter's per-pass parse cache (opaque to this function).
func propagateForGenericCaller(cg *CallGraph, caller *FuncNode, fileContents map[string]string, p *genericLangPropagator, cache interface{}) int {
	content, ok := loadCallerFile(cg, caller.FilePath, fileContents)
	if !ok {
		return 0
	}

	// Param names: prefer the typed TaintSig.Params the extractor
	// populated (Go/Py/JS use this), and fall back to parsing the
	// function-declaration line. The generalized languages (C#, Swift,
	// PHP, Ruby, Rust, Kotlin, Groovy, Perl, Shell, Lua, C/C++) do NOT
	// populate typed Params on their FuncNodes, so without the decl-line
	// fallback the sink-lift would never find a matching param name and the
	// whole multi-hop sink composition would be inert for them. Unlike the
	// Py/JS paths we therefore do NOT early-return when Params is empty:
	// the return-lift below needs no param names at all, and the sink-lift
	// uses the decl-derived names.
	body := extractFuncBody(content, caller.StartLine, caller.EndLine)
	bodyLines := strings.Split(body, "\n")
	paramNames := genericCallerParamNames(caller, bodyLines)

	added := 0
	for _, calleeID := range caller.Calls {
		callee := cg.GetNode(calleeID)
		if callee == nil {
			continue
		}
		// Same-language gate: never lift one language's argument
		// convention into another's signature. The gate is on the
		// adapter's language set; for the C-family pair (LangC/LangCPP)
		// both members match, which is correct since they share a walker.
		if !p.langMatches(callee.Language) {
			continue
		}
		if extractBaseName(callee.Name) == "" {
			continue
		}

		// Sink-lift: only relevant when the callee carries (possibly
		// already-lifted) sinks AND we have caller param names to match the
		// forwarded argument against. bodyLines (decl line at index 0, same
		// convention as liftGenericCallerReturns) enables matchDerivedParamName's
		// local-assignment lookback (`q = build(p)` then `sink(q)`).
		if len(paramNames) > 0 && len(callee.TaintSig.SinkCalls) > 0 {
			callSites := p.findCallSites(cache, content, caller, callee.Name)
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
	}

	// Return-lift loop (#31/#37, multi-hop). Separate from the sink-lift
	// loop because a callee may carry ONLY a tainted return and NO sink
	// (the canonical `func relay(req) { return leaf(req) }` relay target) —
	// the sink guard above would skip it.
	added += liftGenericCallerReturns(cg, caller, content, p, cache)
	return added
}

// liftGenericCallerReturns is the language-agnostic analog of
// liftJavaScriptCallerReturns / liftPythonCallerReturns. Lifts a callee's
// tainted return into the caller's signature when the caller body does
// `return callee(...)` or `v = callee(...); return v`. Gated to the
// adapter's language set, identical to the sink path.
func liftGenericCallerReturns(cg *CallGraph, caller *FuncNode, content string, p *genericLangPropagator, cache interface{}) int {
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
		if !p.langMatches(callee.Language) {
			continue
		}
		calleeBase := extractBaseName(callee.Name)
		if calleeBase == "" {
			continue
		}
		callSites := p.findCallSites(cache, content, caller, callee.Name)
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
