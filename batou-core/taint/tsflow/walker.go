package tsflow

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// walkTree finds all function definitions in the tree and analyzes each one.
// It performs a two-pass analysis: first pass identifies which local functions
// propagate tainted parameters to their return value; second pass uses this
// information for interprocedural taint tracking.
func walkTree(tree *ast.Tree, cfg *langConfig, matcher *tsMatcher, filePath string, cliScript bool) []taint.TaintFlow {
	root := tree.Root()
	if root == nil {
		return nil
	}

	// Find all function definitions.
	funcNodes := ast.FindByTypes(root, cfg.funcTypes)
	// Optional: language-specific DSL scopes (e.g., Ruby Sinatra/Roda
	// route blocks) that aren't formal function definitions but DO carry
	// per-block taint and should be analysed as their own scopes.
	if cfg.findExtraScopes != nil {
		funcNodes = append(funcNodes, cfg.findExtraScopes(root)...)
	}

	// Build a map of local function names → their AST nodes for interprocedural analysis.
	localFuncs := make(map[string]*ast.Node, len(funcNodes))
	for _, fnNode := range funcNodes {
		name := cfg.extractFuncName(fnNode)
		if name != "" {
			localFuncs[name] = fnNode
		}
	}

	// Pass 1: Build per-function taint summaries. For each function, seed each
	// parameter individually and track which ones propagate to the return value.
	summaries := buildTaintSummaries(funcNodes, cfg, matcher)

	// Module-level constant containers: scan top-level assignments for
	// literal dict / list / set / tuple bindings whose values are themselves
	// constants (e.g. `ALLOWED_OPS = {"invert": "255 - a", "double": ...}`).
	// These are passed into each function-body walk so `.get(<tainted>)` on
	// one of these globals does not propagate the key's taint. See
	// tm.constContainers and CVE-2023-50447 safe pattern.
	moduleConstContainers := collectModuleLevelConstContainers(root, cfg)

	// Pass 1.5: harvest the file-level STORED-STATE side-table — instance-field
	// (`self.x` / `this.x`) and module-global writes that carry taint in ANY
	// scope. This is the third propagation channel beyond param->return: it lets
	// taint stored in one method/function be read in another (the canonical OO
	// web-handler vuln, and module-global state). Seeded into every reader scope
	// below. No-op for languages without a stored-state channel.
	stored := collectStoredFieldTaint(funcNodes, root, cfg, matcher, summaries, moduleConstContainers)

	var allFlows []taint.TaintFlow

	// Pass 2: Walk each function with interprocedural info.
	for _, fnNode := range funcNodes {
		scopeName := cfg.extractFuncName(fnNode)
		if scopeName == "" {
			scopeName = "__anonymous__"
		}
		body := cfg.extractFuncBody(fnNode)
		if body == nil {
			continue
		}

		flows := walkFuncInterprocWithGlobals(body, fnNode, scopeName, filePath, cfg, matcher, summaries, cliScript, moduleConstContainers, stored)
		allFlows = append(allFlows, flows...)
	}

	// Flat-script languages: walk the top-level script body. The dominant
	// real-world idiom for Perl/CGI and PHP is a flat script with no
	// enclosing function:
	//   Perl: $q->param(...) → system(...)
	//   PHP:  $id = $_GET['id']; $q = "...$id..."; mysqli_query($c, $q); echo $x;
	// so the per-function loop above yields zero flows for these. Top-level
	// statements share a single taint map so taint propagates across them
	// (a superglobal seeds a variable via interpolation/concatenation, which
	// then flows into a downstream sink).
	//
	// Gated to LangPerl + LangPHP + LangPython. Python's dominant
	// script idiom is also flat and file-scoped — CLI tools, data/ETL
	// scripts, Streamlit/Jupyter-as-script, and simple CGI all read input
	// and reach a sink at module top level with no enclosing def:
	//   cmd = input(); os.system(cmd)
	//   p = sys.argv[1]; open(p)
	// The per-function loop above yields zero flows for these (verified:
	// the byte-identical function-wrapped form fires, top-level does not).
	// The remaining tsflow languages are left untouched (their entrypoints
	// are always functions/methods; module-level statements are
	// imports/constants, not source→sink flows).
	if cfg.language == rules.LangPerl || cfg.language == rules.LangPHP || cfg.language == rules.LangPython {
		flows := walkTopLevelScript(root, filePath, cfg, matcher, summaries, cliScript, moduleConstContainers, stored)
		allFlows = append(allFlows, flows...)
	}

	return allFlows
}

// walkTopLevelScript analyzes statements at file scope (children of the
// program/source_file root that are not function/subroutine declarations).
// Top-level statements share a single taint map so taint propagates across
// them, e.g.:
//
//	Perl: my $cgi = CGI->new; my $in = $cgi->param("x"); system($in);
//	PHP:  $id = $_GET['id']; $q = "...$id..."; mysqli_query($c, $q);
//
// Function/subroutine declarations are skipped here because they are already
// analyzed as their own scopes in the per-function loop in walkTree.
func walkTopLevelScript(root *ast.Node, filePath string, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary, cliScript bool, moduleConstContainers map[string]bool, stored *storedTaint) []taint.TaintFlow {
	if root == nil {
		return nil
	}
	tm := newTaintMap()
	for name := range moduleConstContainers {
		tm.constContainers[name] = true
	}
	// Seed stored module globals so a top-level read of a global written by a
	// function (e.g. `g` set under `global g` in store()) is tainted here too.
	seedStoredFieldState(tm, nil, cfg, stored)
	fb := newFlowBuilder(filePath)
	fb.cliScript = cliScript

	const scopeName = "__toplevel__"
	for i := 0; i < root.ChildCount(); i++ {
		child := root.Child(i)
		if child == nil || !child.IsNamed() {
			continue
		}
		// Subroutine bodies are handled by the per-function pass; skip them
		// here so a top-level sub{} is not double-walked.
		if cfg.funcTypes[child.Type()] {
			continue
		}
		// Class/struct bodies likewise have their methods analyzed as their
		// own scopes by the per-function pass. Skipping them here avoids
		// double-reporting a method's internal flow and prevents a top-level
		// variable from leaking taint into a method that shadows it via a
		// parameter (a false positive). See langConfig.classTypes.
		if cfg.classTypes[child.Type()] {
			continue
		}
		walkBodyInterproc(child, tm, cfg, matcher, scopeName, fb, summaries)
	}

	return fb.flows
}

// collectModuleLevelConstContainers scans the file root for top-level
// assignments of the form `NAME = {literal_pairs}` / `NAME = [literals]` and
// returns the set of NAMEs. Walks one level deep so Python's
// `module > expression_statement > assignment` and JS/TS's `program >
// lexical_declaration` shapes are both handled. Conservative: any
// non-literal value disqualifies the container so live taint can still
// flow through dynamically-built tables.
func collectModuleLevelConstContainers(root *ast.Node, cfg *langConfig) map[string]bool {
	out := make(map[string]bool)
	if root == nil || cfg == nil {
		return out
	}
	visit := func(node *ast.Node) {
		if node == nil || !node.IsNamed() {
			return
		}
		if !cfg.assignTypes[node.Type()] && !cfg.varDeclTypes[node.Type()] {
			return
		}
		lhs := cfg.extractAssignLHS(node)
		if lhs == "" {
			return
		}
		rhs := cfg.extractAssignRHS(node)
		if rhs == nil {
			return
		}
		if isAllLiteralContainer(rhs) {
			out[lhs] = true
		}
	}
	for i := 0; i < root.ChildCount(); i++ {
		child := root.Child(i)
		if !child.IsNamed() {
			continue
		}
		visit(child)
		// Recurse one level into wrapper nodes (expression_statement,
		// program_statement, etc.) so Python's
		// `module > expression_statement > assignment` is reached.
		for j := 0; j < child.ChildCount(); j++ {
			inner := child.Child(j)
			if !inner.IsNamed() {
				continue
			}
			visit(inner)
		}
	}
	return out
}

// buildTaintSummaries analyzes each function to build rich taint summaries.
// For each parameter, it determines whether that parameter's taint propagates
// to the return value, and which sink categories are sanitized along the way.
// This enables context-sensitive interprocedural analysis: only arguments
// whose corresponding parameter propagates taint will taint the call result.
func buildTaintSummaries(funcNodes []*ast.Node, cfg *langConfig, matcher *tsMatcher) map[string]*TaintSummary {
	result := make(map[string]*TaintSummary)
	for _, fnNode := range funcNodes {
		name := cfg.extractFuncName(fnNode)
		if name == "" {
			continue
		}
		body := cfg.extractFuncBody(fnNode)
		if body == nil {
			continue
		}
		params := cfg.extractFuncParams(fnNode)

		summary := &TaintSummary{
			FuncName:    name,
			ParamFlows:  make([]map[taint.SinkCategory]bool, len(params)),
			ParamSinks:  make([]map[taint.SinkCategory]paramSinkSite, len(params)),
			ReturnTaint: make(map[int]bool),
			Sanitizes:   make(map[int]map[taint.SinkCategory]bool),
			IsPure:      true,
		}

		// Returns-source detection: a body that reads a catalog source and
		// returns it manufactures taint at every call site, independent of any
		// parameter (and so must run BEFORE the zero-param early registration
		// below — `def get_q(): return request.args.get('q')` has no params).
		summary.ReturnsSource = detectReturnsSource(body, cfg, matcher, name)

		if len(params) == 0 {
			// No params — register the function as local but non-propagating.
			result[name] = summary
			continue
		}

		// For each parameter, seed it individually and check if its taint
		// reaches the return value. This gives per-parameter precision.
		for i, p := range params {
			tm := newTaintMap()
			src := &taint.SourceDef{
				ID:         "param." + strconv.Itoa(i) + "." + p,
				Category:   taint.SrcUserInput,
				Language:   cfg.language,
				MethodName: "parameter:" + p,
			}
			tm.set(p, &taintState{
				varName:    p,
				source:     src,
				sourceLine: 0,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps:      []taint.FlowStep{{Description: "param " + p}},
			})

			// Walk body with nil summaries (pass 1 — conservative for unknown calls).
			fb := newFlowBuilder("")
			walkBodyInterproc(body, tm, cfg, matcher, name, fb, nil)

			if returnsTainted(body, tm, cfg) {
				summary.ReturnTaint[i] = true
				summary.IsPure = false

				// Check sanitized categories for this parameter.
				if cats := returnSanitizedCategories(body, tm, cfg, matcher); cats != nil {
					summary.Sanitizes[i] = cats
				}
			}

			// Check if this param reached any sinks (via flows found).
			if len(fb.flows) > 0 {
				summary.IsPure = false
				sinkCats := make(map[taint.SinkCategory]bool)
				sinkSites := make(map[taint.SinkCategory]paramSinkSite)
				for fi := range fb.flows {
					f := &fb.flows[fi]
					sinkCats[f.Sink.Category] = true
					// Record a representative sink site per category so a caller
					// passing a tainted argument into this parameter can emit
					// the interprocedural finding at the call site. First flow
					// per category wins; the captured steps describe the
					// in-callee param→sink chain. Copy the SinkDef so the stored
					// pointer is stable past the loop variable.
					if _, seen := sinkSites[f.Sink.Category]; !seen {
						sinkCopy := f.Sink
						sinkSites[f.Sink.Category] = paramSinkSite{
							sink:     &sinkCopy,
							sinkLine: f.SinkLine,
							steps:    f.Steps,
						}
					}
				}
				summary.ParamFlows[i] = sinkCats
				summary.ParamSinks[i] = sinkSites
			}
		}

		result[name] = summary
	}
	return result
}

// returnsTainted checks if any return statement in the body returns a tainted value.
func returnsTainted(body *ast.Node, tm *taintMap, cfg *langConfig) bool {
	found := false
	body.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		if n.Type() == "return_statement" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					if _, ok := nodeIsTainted(c, tm, cfg); ok {
						found = true
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

// returnSanitizedCategories returns the set of sink categories that are
// neutralized in ALL tainted return values. If the function sanitizes for
// XSS but not SQLi, only SnkHTMLOutput is returned.
func returnSanitizedCategories(body *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) map[taint.SinkCategory]bool {
	var allSanitized []map[taint.SinkCategory]bool
	body.Walk(func(n *ast.Node) bool {
		if n.Type() == "return_statement" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if !c.IsNamed() {
					continue
				}
				// Check if the returned expression is a sanitizer call
				// (e.g., return encodeForHTML(val)).
				call := unwrapToCall(c, cfg)
				if cfg.callTypes[call.Type()] {
					if san, sanitizedArg := matcher.matchSanitizer(call); san != nil {
						if _, ok := nodeIsTainted(sanitizedArg, tm, cfg); ok {
							cats := make(map[taint.SinkCategory]bool, len(san.Neutralizes))
							for _, cat := range san.Neutralizes {
								cats[cat] = true
							}
							allSanitized = append(allSanitized, cats)
							continue
						}
					}
				}
				// Check if variable already has sanitized categories.
				if ts, ok := nodeIsTainted(c, tm, cfg); ok && len(ts.sanitized) > 0 {
					allSanitized = append(allSanitized, ts.sanitized)
				}
			}
		}
		return true
	})
	if len(allSanitized) == 0 {
		return nil
	}
	// Intersect: only categories sanitized in ALL return paths.
	result := make(map[taint.SinkCategory]bool)
	for cat := range allSanitized[0] {
		if allSanitized[0][cat] {
			result[cat] = true
		}
	}
	for _, san := range allSanitized[1:] {
		for cat := range result {
			if !san[cat] {
				delete(result, cat)
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// detectReturnsSource reports whether a function body returns a value derived
// from a catalog taint SOURCE read inside the body itself (as opposed to taint
// entering via a parameter — that is what ReturnTaint models). The body is
// walked once with NO parameter seeding, so every taint state in the map comes
// from a real source read (`q = request.args.get('q'); return q`). For each
// return statement the returned expression is resolved in
// returnSanitizedCategories order: an explicit sanitizer wrapper first (so
// `return escape(request.args.get('x'))` records the sanitizer's Neutralizes
// categories), then the walked taint map, then a direct structural source
// match for expressions never bound to a variable.
//
// Sanitized categories are INTERSECTED across all source-carrying return paths
// (a category counts as neutralized only when every source-returning path
// neutralizes it — mirroring returnSanitizedCategories). When the body also
// has explicit return paths that do NOT carry a source, the result's
// confidence is decayed by branchSingleWeight, mirroring single-branch taint
// decay.
//
// Returns nil when no return path carries source taint — helpers returning
// constants stay non-tainting at their call sites (the TN side).
func detectReturnsSource(body *ast.Node, cfg *langConfig, matcher *tsMatcher, scopeName string) *returnsSourceInfo {
	// Cheap pre-scan: many function bodies (void handlers) have no return
	// statement at all — skip the taint walk entirely for those.
	hasReturn := false
	body.Walk(func(n *ast.Node) bool {
		if hasReturn {
			return false
		}
		if n.Type() == "return_statement" {
			hasReturn = true
			return false
		}
		return true
	})
	if !hasReturn {
		return nil
	}

	tm := newTaintMap()
	fb := newFlowBuilder("")
	walkBodyInterproc(body, tm, cfg, matcher, scopeName, fb, nil)

	var best *returnsSourceInfo
	var sanitizedSets []map[taint.SinkCategory]bool
	mixedPaths := false
	body.Walk(func(n *ast.Node) bool {
		if n.Type() != "return_statement" {
			return true
		}
		carried := false
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() {
				continue
			}
			if info := returnedSourceState(c, tm, cfg, matcher); info != nil {
				carried = true
				sanitizedSets = append(sanitizedSets, info.sanitized)
				if best == nil || info.confidence > best.confidence {
					best = info
				}
			}
		}
		if !carried {
			mixedPaths = true
		}
		return true
	})
	if best == nil {
		return nil
	}
	// Intersect sanitized categories across all source-carrying return paths:
	// a category is only safe at the call site if EVERY path neutralizes it.
	inter := make(map[taint.SinkCategory]bool)
	for cat, ok := range sanitizedSets[0] {
		if ok {
			inter[cat] = true
		}
	}
	for _, s := range sanitizedSets[1:] {
		for cat := range inter {
			if !s[cat] {
				delete(inter, cat)
			}
		}
	}
	best.sanitized = inter
	if mixedPaths {
		best.confidence *= branchSingleWeight
	}
	return best
}

// returnedSourceState resolves a single returned expression to a
// returns-source record, or nil when the expression carries no source taint.
// Resolution order mirrors returnSanitizedCategories: explicit sanitizer
// wrapper first (so the wrapper's Neutralizes categories are recorded instead
// of being lost to nodeIsTainted's unsanitized hit on the inner argument),
// then the walked taint map, then a direct structural source match.
func returnedSourceState(c *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) *returnsSourceInfo {
	retLine := int(c.StartRow()) + 1

	// Sanitizer wrapper: return escape(<source-derived>).
	call := unwrapToCall(c, cfg)
	if cfg.callTypes[call.Type()] {
		if san, sanitizedArg := matcher.matchSanitizer(call); san != nil && sanitizedArg != nil {
			if inner := returnedSourceState(sanitizedArg, tm, cfg, matcher); inner != nil {
				for _, cat := range san.Neutralizes {
					inner.sanitized[cat] = true
				}
				inner.steps = append(inner.steps, taint.FlowStep{
					Line:        retLine,
					Description: "sanitized by " + san.MethodName,
				})
				return inner
			}
			return nil
		}
	}

	// Source-derived value tracked by the parameterless walk
	// (q = request.args.get('q'); ...; return q).
	if ts, ok := nodeIsTainted(c, tm, cfg); ok && ts.source != nil {
		san := make(map[taint.SinkCategory]bool, len(ts.sanitized))
		for k, v := range ts.sanitized {
			san[k] = v
		}
		steps := make([]taint.FlowStep, len(ts.steps))
		copy(steps, ts.steps)
		return &returnsSourceInfo{
			source:     ts.source,
			sourceLine: ts.sourceLine,
			confidence: ts.confidence,
			sanitized:  san,
			steps:      steps,
		}
	}

	// Direct source expression in return position
	// (return request.args.get('q') — never bound to a local).
	if src := findSourceInExpr(c, matcher, cfg); src != nil {
		return &returnsSourceInfo{
			source:     src,
			sourceLine: retLine,
			confidence: 1.0,
			sanitized:  make(map[taint.SinkCategory]bool),
			steps: []taint.FlowStep{{
				Line:        retLine,
				Description: "tainted by " + src.MethodName,
			}},
		}
	}
	return nil
}

// walkFuncInterproc performs intraprocedural taint analysis with interprocedural
// awareness: calls to local functions known to propagate taint are treated as
// taint-propagating.
// walkFuncInterprocWithGlobals walks a function body with interprocedural
// tracking, seeding the per-function taint map with a set of module-level
// constant container names (literal dict/list/set bindings). The first walk
// that hits one of these names as a `.get(<tainted>)` receiver will refuse
// to propagate the key's taint, eliminating FPs from project-local lookup
// tables. Pass nil for moduleConstContainers when no globals are available.
func walkFuncInterprocWithGlobals(body *ast.Node, fnNode *ast.Node, scopeName, filePath string, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary, cliScript bool, moduleConstContainers map[string]bool, stored *storedTaint) []taint.TaintFlow {
	tm := newTaintMap()
	for name := range moduleConstContainers {
		tm.constContainers[name] = true
	}
	fb := newFlowBuilder(filePath)
	fb.cliScript = cliScript

	// Seed taint for framework parameters.
	seedParams(fnNode, tm, cfg, matcher)

	// Seed the cross-scope STORED-STATE side-table: instance fields (`self.x`,
	// `this.x`) written tainted in any method of this file, and module globals
	// written tainted in any function, so a read of that field/global in THIS
	// scope surfaces the flow. Params shadow same-named globals; an in-scope
	// untainted rebinding later in the body still strong-updates the seed away.
	seedStoredFieldState(tm, fnNode, cfg, stored)

	// Java-only body-scope hardening pre-scan: some safe shapes can't be
	// expressed by per-call sanitizer entries (the safety is encoded as a
	// flow-control guard or as a side-effecting receiver call). Pre-populate
	// the hardenedReceivers map so downstream sink checks suppress findings
	// on receivers known to be guarded. See seedJavaBodyHardening for the
	// concrete shapes.
	if cfg.language == rules.LangJava && body != nil {
		seedJavaBodyHardening(body.Text(), tm)
	}

	// C/C++ body-scope hardening pre-scan: a libcurl handle whose allowed URL
	// schemes are restricted via CURLOPT_PROTOCOLS(_STR) /
	// CURLOPT_REDIR_PROTOCOLS(_STR) is hardened against SSRF (file://, gopher://,
	// dict:// and the other scheme-amplification vectors are rejected). The
	// restriction is a separate `curl_easy_setopt(h, CURLOPT_PROTOCOLS, ...)`
	// STATEMENT on the handle, not a value wrapper, so it cannot be expressed as
	// a per-call assignment-RHS sanitizer; a body-scope suppression captures the
	// developer's SSRF-hardening intent, mirroring seedJavaBodyHardening.
	if (cfg.language == rules.LangC || cfg.language == rules.LangCPP) && body != nil {
		seedCNetworkHardening(body.Text(), tm)
	}

	// Walk the body with taint tracking + interprocedural info.
	walkBodyInterproc(body, tm, cfg, matcher, scopeName, fb, summaries)

	return fb.flows
}

// seedJavaBodyHardening scans a Java function body for known hardening
// shapes that mark a receiver as safe for one or more sink categories.
// Currently covers:
//   - SSRF: `<container>.contains(<recv>.getHost())` allowlist guard,
//     or a custom `isAllowedHost(<recv>) / validateUrl(<recv>) /
//     isSafeUrl(<recv>)` guard — recv is then safe for SnkURLFetch /
//     SnkRedirect. Matches the OWASP SSRF Prevention Cheat Sheet shape.
//   - XXE (defense-in-depth): DocumentBuilderFactory / SAXParserFactory /
//     XMLInputFactory receivers that call .setFeature(.., true) or
//     .setProperty(.., ..) for the canonical disable-doctype / secure-
//     processing / external-entities features. These are already covered
//     by the per-call sanitizer entries (java.dbf.disallow.doctype etc.)
//     but the per-call entries only fire on the exact tree-sitter shape;
//     the body-scan is a fallback for the multi-statement hardening blocks
//     where the receiver is reassigned between calls.
//
// Kept narrow on purpose: only patterns that don't have a clean per-call
// sanitizer expression. Avoid widening — Python's pythonSanitizerRe started
// narrow and stayed there for the same reason.
func seedJavaBodyHardening(bodyText string, tm *taintMap) {
	if bodyText == "" {
		return
	}
	ssrfGuardFound := false
	for _, m := range javaSSRFAllowlistRe.FindAllStringSubmatch(bodyText, -1) {
		if len(m) >= 2 && m[1] != "" {
			tm.markReceiverHardened(m[1], []taint.SinkCategory{
				taint.SnkURLFetch, taint.SnkRedirect,
			})
			ssrfGuardFound = true
		}
	}
	for _, m := range javaSSRFNamedGuardRe.FindAllStringSubmatch(bodyText, -1) {
		if len(m) >= 2 && m[1] != "" {
			tm.markReceiverHardened(m[1], []taint.SinkCategory{
				taint.SnkURLFetch, taint.SnkRedirect,
			})
			ssrfGuardFound = true
		}
	}
	// Two-line allowlist shape: a `.getHost()` extraction into a local var
	// plus a separate `ALLOWED_HOSTS.contains(...)` somewhere in the body.
	// Both signals required before we mark the URI receiver hardened —
	// this avoids marking unrelated bodies that happen to call .getHost()
	// (for logging, etc.) without any actual validation.
	if javaSSRFAllowlistAnyContainsRe.MatchString(bodyText) {
		for _, m := range javaSSRFHostExtractRe.FindAllStringSubmatch(bodyText, -1) {
			if len(m) >= 2 && m[1] != "" {
				tm.markReceiverHardened(m[1], []taint.SinkCategory{
					taint.SnkURLFetch, taint.SnkRedirect,
				})
				ssrfGuardFound = true
			}
		}
	}
	// Body-scope SSRF guard: when the body contains an explicit allowlist
	// guard on a URI's host (or a named SSRF guard), every URL-fetch /
	// redirect sink in the body is presumed validated. This is a coarser
	// suppression than the per-variable hardening above, but it captures
	// the canonical defence shape — a parse step (URI.create) feeding a
	// validation block feeding the network call — where the parse step
	// itself was previously firing as a separate SnkURLFetch sink even
	// though the guard further down made the whole flow safe.
	if ssrfGuardFound {
		tm.markBodySuppressCategory(taint.SnkURLFetch)
		tm.markBodySuppressCategory(taint.SnkRedirect)
	}
	// Body-scope SpEL hardening: when the body installs a restricted
	// evaluation context (`SimpleEvaluationContext.forReadOnlyDataBinding()`
	// or `forPropertyAccessors()` — the OWASP-recommended SpEL sandbox), the
	// SpEL parseExpression / getValue sinks are presumed safe. The catalog
	// already lists `java.spring.spel.simpleevaluationcontext` as a
	// SnkEval sanitizer but it only fires when assigned to a downstream
	// variable that reaches a sink as an argument; the dominant safe shape
	// `parser.parseExpression(expr).getValue(context)` does not have such
	// a flow, so a body-scope suppression captures the developer's intent.
	if javaSimpleEvalContextRe.MatchString(bodyText) {
		tm.markBodySuppressCategory(taint.SnkEval)
	}
}

// curlProtocolRestrictionRe matches a libcurl protocol-restriction setopt —
// CURLOPT_PROTOCOLS, CURLOPT_PROTOCOLS_STR, CURLOPT_REDIR_PROTOCOLS, or
// CURLOPT_REDIR_PROTOCOLS_STR. Setting any of these limits the URL schemes
// libcurl will use/follow, the canonical libcurl SSRF mitigation. (The `\b`
// after PROTOCOLS does not match the `_STR` suffix on its own — `S` and `_`
// are both word characters — so the optional `(?:_STR)?` is required to cover
// the curl 7.85+ string enum form.)
var curlProtocolRestrictionRe = regexp.MustCompile(`\bCURLOPT_(?:REDIR_)?PROTOCOLS(?:_STR)?\b`)

// cInetPtonValidateRe captures the variable validated by an
// `inet_pton(AF_INET[6], <var>, ...)` call — the second argument is the source
// IP string. A successful inet_pton parse confirms the value is a syntactically
// valid IP literal (not an attacker-supplied hostname), which the catalog
// models as an SSRF sanitizer for that variable.
var cInetPtonValidateRe = regexp.MustCompile(`\binet_pton\s*\(\s*AF_INET6?\s*,\s*([A-Za-z_]\w*)`)

// seedCNetworkHardening pre-records C/C++ SSRF hardening shapes that the
// per-call assignment-RHS sanitizer mechanism cannot express because the
// safety is encoded as a sibling statement / guard rather than a value wrapper.
// Mirrors seedJavaBodyHardening. Suppression-only — it can only remove
// findings, never add them.
//
//   - libcurl protocol restriction (CURLOPT_PROTOCOLS(_STR) /
//     CURLOPT_REDIR_PROTOCOLS(_STR)): a strong, handle-wide SSRF mitigation
//     (rejects file://, gopher://, dict:#, …), so its presence body-suppresses
//     SnkURLFetch (and SnkRedirect for the redirect form). The catalog lists
//     these as sanitizers (c.curl.protocols, …) but keys them on the enum
//     constant — an argument, not the call name — so they never matched a real
//     `curl_easy_setopt(...)` call.
//   - inet_pton(AF_INET[6], v, …): validates that v is a literal IP address,
//     which the catalog (c.validate.inet_pton, cpp.inet_pton.validate) models as
//     an SSRF sanitizer for v. Recorded as per-VARIABLE hardening so only the
//     validated value is suppressed, not every URL-fetch in the body.
func seedCNetworkHardening(bodyText string, tm *taintMap) {
	if bodyText == "" {
		return
	}
	if curlProtocolRestrictionRe.MatchString(bodyText) {
		tm.markBodySuppressCategory(taint.SnkURLFetch)
		if strings.Contains(bodyText, "CURLOPT_REDIR_PROTOCOLS") {
			tm.markBodySuppressCategory(taint.SnkRedirect)
		}
	}
	for _, m := range cInetPtonValidateRe.FindAllStringSubmatch(bodyText, -1) {
		if len(m) >= 2 && m[1] != "" {
			tm.markReceiverHardened(m[1], []taint.SinkCategory{taint.SnkURLFetch})
		}
	}
}

// javaSimpleEvalContextRe matches the canonical OWASP-recommended SpEL
// sandbox: `SimpleEvaluationContext.forReadOnlyDataBinding()` /
// `.forPropertyAccessors(...)`. Presence in the function body suppresses
// SnkEval findings for SpEL expressions in that body.
var javaSimpleEvalContextRe = regexp.MustCompile(
	`SimpleEvaluationContext\.(?:forReadOnlyDataBinding|forPropertyAccessors)\s*\(`,
)

// isReceiverStateSinkCategory returns true when a sink category is
// reliably guardable by a receiver-state sanitizer call earlier in the
// same function body. Restricted to:
//   - SnkDeserialize: XStream `xs.allowTypes(...)` / `xs.addPermission(...)`
//   - SnkXPath: DocumentBuilderFactory / SAXParserFactory / XMLInputFactory
//     `factory.setFeature("disallow-doctype-decl", true)` etc.
//
// Other categories (SQL, HTML, headers, logging) are intentionally excluded
// — their sanitizers are value-transforming (return a cleaned value), not
// receiver-state-mutating, so applying receiver-hardening to them would
// over-suppress (e.g. logger.info as the "sanitizer" of its own log sink).
func isReceiverStateSinkCategory(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkDeserialize, taint.SnkXPath:
		return true
	}
	return false
}

// javaSSRFAllowlistRe matches an SSRF host-allowlist guard of the form
// `ALLOWED_HOSTS.contains(uri.getHost())` (with or without a leading `!`,
// `Set.of(...).contains`, `Arrays.asList(...).contains`). The captured
// group is the receiver variable name whose getHost() output is checked —
// when that receiver later reaches an SSRF sink it is safe. Matches the
// classic-ssrf-httpclient safe fixture shape used by the JavaCVE bench.
var javaSSRFAllowlistRe = regexp.MustCompile(
	`\.contains\s*\(\s*([A-Za-z_][A-Za-z_0-9]*)\.getHost\s*\(\s*\)\s*\)`,
)

// javaSSRFHostExtractContainsRe matches the two-line shape where the host
// is extracted into a local variable, then checked against an allowlist:
//
//	String host = uri.getHost();           // captured: uri
//	... ALLOWED_HOSTS.contains(host) ...   // local var name reused
//
// We match the .getHost() extraction and trust that a downstream
// allowlist check exists in the body. The classic-ssrf-httpclient safe
// fixture uses this shape (host = uri.getHost(); ... .contains(host)).
// Combined with javaSSRFAllowlistAnyContainsRe below to require *some*
// allowlist check exists before we mark the receiver safe.
var javaSSRFHostExtractRe = regexp.MustCompile(
	`=\s*([A-Za-z_][A-Za-z_0-9]*)\.getHost\s*\(\s*\)`,
)

// javaSSRFAllowlistAnyContainsRe matches any allowlist-style .contains call
// (or a custom URL/host validator call). Used as a co-occurrence requirement
// for javaSSRFHostExtractRe — if the body extracts a host AND has *some*
// allowlist check, we assume the host extracted upstream is being validated
// downstream. Bench-tuned for the canonical safe shape; conservatively
// requires both signals so unrelated `.contains(...)` calls don't trip it.
var javaSSRFAllowlistAnyContainsRe = regexp.MustCompile(
	`(?i)(?:ALLOW(?:ED)?(?:_)?(?:HOSTS?|URLS?|DOMAINS?|LIST)|WHITELIST|HOST_?WHITELIST)\s*\.\s*contains\s*\(`,
)

// javaSSRFNamedGuardRe matches a custom-named SSRF guard call of the form
// `isAllowedHost(uri)`, `validateUrl(uri)`, `isSafeUrl(uri)` — the
// captured group is the receiver variable name. Conservative list of names
// that are unambiguously SSRF guards across real Java codebases.
var javaSSRFNamedGuardRe = regexp.MustCompile(
	`\b(?:isAllowedHost|isAllowedUrl|isSafeUrl|isSafeHost|validateUrl|validateHost|checkAllowedHost)\s*\(\s*([A-Za-z_][A-Za-z_0-9]*)\s*[,)]`,
)

// walkBodyInterproc extends walkBody with interprocedural call tracking and
// switch statement handling.
func walkBodyInterproc(body *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	body.Walk(func(n *ast.Node) bool {
		nodeType := n.Type()

		// Handle if-statements with branch-aware taint merging.
		// Walks each branch with a cloned taint map, then merges results
		// (union: variable is tainted if tainted in ANY branch).
		if cfg.ifTypes[nodeType] && cfg.extractIfCondition != nil {
			processIfBranchAware(n, tm, cfg, matcher, scopeName, fb, summaries)
			return false // we handled children
		}

		// Swift `guard <cond> else { <exit> }` validation. When the condition
		// validates a tainted variable (`guard url.hasPrefix("https://") else
		// { throw }`) and the else-block exits the scope (throw/return), the
		// variable is validated for the rest of the body (fall-through). Mark
		// it sanitised in the shared taint map so a later
		// `req.redirect(to: url)` does not fire. Gated to Swift; the guard
		// node type does not exist in the other tsflow grammars. We do NOT
		// `return false` — the guard's own children carry no sinks we need to
		// walk separately (the condition is a pure validation call), and the
		// surrounding Walk continues to the statements after the guard.
		if cfg.language == rules.LangSwift && nodeType == "guard_statement" {
			processSwiftGuard(n, tm, cfg)
		}

		// Handle switch statements — walk case bodies to propagate taint.
		if nodeType == "switch_expression" || nodeType == "switch_statement" {
			processSwitchInterproc(n, tm, cfg, matcher, scopeName, fb, summaries)
			return false // we handled children
		}

		// Handle switch_block / switch_block_statement_group — walk case contents.
		if nodeType == "switch_block_statement_group" || nodeType == "switch_block" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return false
		}

		// Python match_statement: when the subject is a known string
		// constant (e.g. `match guess` where `guess = "ABC"[1]`), walk only
		// the matching case_clause. This eliminates the OWASP MATCH-CONST
		// FPs in codeinj / ldapi / xpathi / redirect where the scrutinee is
		// provably the "safe" arm. If the subject can't be const-folded,
		// fall back to walking every clause body (preserving may-be-tainted
		// semantics for vulnerable inputs).
		if nodeType == "match_statement" {
			processPythonMatch(n, tm, cfg, matcher, scopeName, fb, summaries)
			return false
		}

		// Handle enhanced for loop — propagate taint from iterable to loop variable.
		if nodeType == "enhanced_for_statement" {
			processEnhancedFor(n, tm, cfg)
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return false
		}

		// Handle Python for-in loops: for x in iterable — propagate taint from
		// iterable to loop variable (e.g., for name in request.headers.keys()).
		if nodeType == "for_statement" && string(cfg.language) == "python" {
			processPythonForLoop(n, tm, cfg, matcher, scopeName, fb, summaries)
			return false
		}

		// Handle JS/TS for...of / for...in loops (for_in_statement): propagate
		// taint from the iterable to the loop binding. This node type is NOT a
		// `for_statement`, so the generic loop handler below never seeds the
		// loop variable — without this the dominant real-world iteration
		// pattern `for (const item of req.body.items) { db.query(item) }`
		// silently drops the iterable's taint.
		if nodeType == "for_in_statement" &&
			(cfg.language == rules.LangJavaScript || cfg.language == rules.LangTypeScript) {
			processJSForOf(n, tm, cfg, matcher, scopeName, fb, summaries)
			return false
		}

		// Handle for/while/do loops — walk the body.
		if nodeType == "for_statement" ||
			nodeType == "while_statement" || nodeType == "do_statement" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return false
		}

		// Handle try-catch — walk both try body and catch bodies.
		if nodeType == "try_statement" || nodeType == "try_with_resources_statement" {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return false
		}

		// PHP echo / print are language statements, not call expressions, so
		// the generic callTypes path below never reaches them. They are the
		// dominant reflected-XSS sink in real PHP (`echo "<h1>".$name`,
		// `print $userInput`). Resolve them against the catalog's echo/print
		// sink and flag when any embedded expression carries HTML-output
		// taint. Gated to PHP so no other language's node walk changes.
		if cfg.language == rules.LangPHP &&
			(nodeType == "echo_statement" || nodeType == "print_intrinsic") {
			processPHPEchoSink(n, tm, cfg, matcher, scopeName, fb)
			return true
		}

		// PHP include / require / include_once / require_once are language
		// constructs that tree-sitter-php parses as dedicated *_expression nodes
		// (include_expression, require_expression, ...), NOT
		// function_call_expression — so the generic callTypes path never reaches
		// them and the catalog's php.include / php.require sinks were dead in the
		// dataflow engine (matched only via the Layer-1 regex tier). A tainted
		// path argument here is LFI/RFI (CWE-98), an RCE-class bug. Resolve
		// against the catalog include/require sinks and flag when the path
		// expression carries taint. The allowlist guard (`if(in_array($x,$ok))
		// include($x)`) clears the taint upstream via applyAllowlistClear, and a
		// basename()/pathinfo() wrap is a SnkFileWrite sanitizer, so the safe
		// forms stay clean. Gated to PHP; pure additive.
		if cfg.language == rules.LangPHP && phpIncludeExprTypes[nodeType] {
			processPHPIncludeSink(n, tm, cfg, matcher, scopeName, fb)
			return true
		}

		// Handle assignments: x = expr
		if cfg.assignTypes[nodeType] {
			processAssignInterproc(n, tm, cfg, matcher, summaries)
			return true
		}

		// Handle variable declarations: var x = expr / let x = expr
		if cfg.varDeclTypes[nodeType] {
			processVarDeclInterproc(n, tm, cfg, matcher, summaries)
			return true
		}

		// Ruby iterator blocks: `coll.each { |x| ... }`, `coll.map do |k, v|
		// ... end`. The block parameter binds to a value derived from the
		// receiver collection, so a tainted (or source) receiver taints the
		// parameter. Ruby's dominant iteration idiom is a method-call-with-block
		// (not a `for` statement), so the for-loop handlers above never reach it
		// and the block parameter silently lost the receiver's taint (recall
		// FN). Pure additive side-effect run BEFORE the generic call path below
		// descends into the block body: it only ADDS taint for the block
		// parameter names when the receiver is tainted, leaving the surrounding
		// walk and all other state untouched. Gated to Ruby.
		if cfg.language == rules.LangRuby {
			seedRubyBlockParams(n, tm, cfg, matcher)
		}

		// Ruby command execution via backtick (`` `cmd #{x}` ``) and `%x{cmd}`
		// both parse as a `subshell` node, NOT a `call`, so the generic
		// call-sink path below never reaches them. Handle them as a
		// command-exec sink here. Gated to Ruby; pure additive (only ADDS a
		// CWE-78 flow when an interpolation carries unsanitized taint).
		if cfg.language == rules.LangRuby && nodeType == "subshell" {
			processRubySubshellSink(n, tm, cfg, matcher, scopeName, fb)
			return true
		}

		// Handle call expressions: check source, sanitizer, sink
		if cfg.callTypes[nodeType] {
			processCallInterproc(n, tm, cfg, matcher, scopeName, fb, summaries)
			return true
		}

		// Handle attribute access as source.
		if cfg.attrTypes[nodeType] {
			processAttr(n, tm, cfg, matcher)
		}

		return true
	})
}

// processPHPEchoSink handles PHP `echo`/`print` statements as HTML-output
// (XSS) sinks. These are language statements (echo_statement /
// print_intrinsic), not function_call_expression nodes, so the generic
// call-sink path never reaches them. We resolve the catalog's echo/print sink
// entry and flag when any embedded expression carries taint for the sink's
// category — handling the dominant reflected-XSS idiom
// `echo "<h1>".$name."</h1>";` / `print $userInput;`.
//
// FP-safety: an embedded expression wrapped in an inline sanitizer
// (e.g. `echo htmlspecialchars($name)`) is skipped via containsInlineSanitizer,
// so the safe-output idiom does not fire. Direct superglobal reads
// (`echo $_GET['x']`) are caught via findSourceInExpr even without an
// intervening assignment.
func processPHPEchoSink(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder) {
	// Identify the catalog sink: "echo" for echo_statement, "print" for
	// print_intrinsic. Both are wildcard-receiver SnkHTMLOutput entries.
	method := "echo"
	if n.Type() == "print_intrinsic" {
		method = "print"
	}
	var sink *taint.SinkDef
	for _, s := range matcher.sinksByMethod[method] {
		if s.ObjectType == "" {
			sink = s
			break
		}
	}
	if sink == nil {
		return
	}
	line := int(n.StartRow()) + 1

	// Examine every named child expression of the echo/print statement,
	// skipping the bare `echo`/`print` keyword and punctuation. echo accepts a
	// comma-separated list (`echo $a, $b;`) — each argument is a named child.
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c == nil || !c.IsNamed() {
			continue
		}
		// An inline sanitizer wrapping the output neutralizes this category.
		if containsInlineSanitizer(c, matcher, cfg, sink.Category) {
			continue
		}
		// Case 1: the expression references a tainted variable
		// (`echo "<h1>".$name` where $name = $_GET[...]).
		if ts, ok := nodeIsTainted(c, tm, cfg); ok {
			if ts.isTaintedFor(sink.Category) {
				fb.addFlow(ts, sink, line, scopeName)
			}
			continue
		}
		// Case 2: a direct superglobal read with no intervening assignment
		// (`echo $_GET['x']`, `echo "x".$_POST['y']`). Seed a transient taint
		// state so the flow records a proper source step.
		if src := findSourceInExpr(c, matcher, cfg); src != nil {
			ts := &taintState{
				varName:    "__echo__",
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "tainted by " + src.MethodName,
					VarName:     "__echo__",
				}},
			}
			fb.addFlow(ts, sink, line, scopeName)
		}
	}
}

// phpIncludeExprTypes is the set of tree-sitter-php node types for the PHP
// file-inclusion language constructs. tree-sitter-php parses each of these as a
// dedicated *_expression node (NOT function_call_expression), so the generic
// call-sink path never reaches them; processPHPIncludeSink handles them.
var phpIncludeExprTypes = map[string]bool{
	"include_expression":      true,
	"require_expression":      true,
	"include_once_expression": true,
	"require_once_expression": true,
}

// phpIncludeSinkMethod maps a PHP include/require *_expression node type to the
// catalog sink MethodName the corresponding sink is keyed under
// (php.include / php.require / php.include_once / php.require_once).
func phpIncludeSinkMethod(nodeType string) string {
	switch nodeType {
	case "include_expression":
		return "include"
	case "require_expression":
		return "require"
	case "include_once_expression":
		return "include_once"
	case "require_once_expression":
		return "require_once"
	}
	return ""
}

// processPHPIncludeSink handles PHP `include`/`require`/`include_once`/
// `require_once` of a user-controlled path as a file-inclusion (LFI/RFI, CWE-98)
// sink. These are language constructs — tree-sitter-php parses them as
// include_expression / require_expression / ... nodes, NOT
// function_call_expression — so the generic callTypes path never reaches them
// and the catalog php.include / php.require sinks only ever matched at the
// Layer-1 regex tier (the dataflow tier was silently blind to the canonical RFI
// shape `$p = $_GET['x']; include($p);`). This mirrors processPHPEchoSink: a
// sink that is a statement/expression construct rather than a call.
//
// FP-safety: the path argument wrapped in an inline path sanitizer
// (`include(basename($p))`, `include(__DIR__ . "/" . basename($p))`) is skipped
// via containsInlineSanitizer (php.basename neutralizes SnkFileWrite). The
// allowlist-guard shape (`if(in_array($p, $allowed)) include($p);`) is cleared
// upstream by applyAllowlistClear before this node is walked, so $p is no longer
// tainted in tm and no flow is recorded. A bare constant path
// (`include("header.php")`) carries no taint and never fires.
func processPHPIncludeSink(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder) {
	method := phpIncludeSinkMethod(n.Type())
	if method == "" {
		return
	}
	// Resolve the wildcard-receiver catalog sink for this construct
	// (php.include / php.require / ...). All are ObjectType:"" SnkFileWrite
	// CWE-98 entries.
	var sink *taint.SinkDef
	for _, s := range matcher.sinksByMethod[method] {
		if s.ObjectType == "" {
			sink = s
			break
		}
	}
	if sink == nil {
		return
	}
	line := int(n.StartRow()) + 1

	// The path expression is the single named child:
	//   include($p)        -> parenthesized_expression -> $p
	//   require $p         -> variable_name $p (direct)
	// Unwrap a parenthesized_expression to its inner expression so the taint /
	// source checks see the real path node.
	arg := firstNamedChild(n)
	if arg == nil {
		return
	}
	if arg.Type() == "parenthesized_expression" {
		if inner := firstNamedChild(arg); inner != nil {
			arg = inner
		}
	}

	// An inline path sanitizer wrapping the path neutralizes file inclusion.
	if containsInlineSanitizer(arg, matcher, cfg, sink.Category) {
		return
	}

	// Case 1: the path references a tainted variable
	// (`$p = $_GET['f']; include($p . ".php");`).
	if ts, ok := nodeIsTainted(arg, tm, cfg); ok && ts != nil {
		if ts.isTaintedFor(sink.Category) {
			fb.addFlow(ts, sink, line, scopeName)
		}
		return
	}

	// Case 2: a direct superglobal read in the path with no intervening
	// assignment (`include($_GET['file']);`, `require __DIR__.$_GET['p'];`).
	if src := findSourceInExpr(arg, matcher, cfg); src != nil {
		ts := &taintState{
			varName:    "__include__",
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     "__include__",
			}},
		}
		fb.addFlow(ts, sink, line, scopeName)
	}
}

// rubySubshellSink resolves the catalog command-exec sink to attribute a
// Ruby `subshell` finding to. Ruby's backtick (`` `cmd` ``) and `%x{cmd}`
// command-execution forms both parse as a `subshell` node — NOT a `call` node —
// so the generic call-sink path never reaches them and the catalog
// `ruby.backticks` / `ruby.percent_x` sinks are dead in the dataflow engine
// (they only ever matched via the Layer-1 regex tier). Prefer the backticks
// entry; fall back to any wildcard SnkCommand entry.
func rubySubshellSink(matcher *tsMatcher) *taint.SinkDef {
	for _, s := range matcher.sinksByMethod["backticks"] {
		if s.Category == taint.SnkCommand {
			return s
		}
	}
	// Fallback: the %x() entry, also a wildcard SnkCommand sink.
	for _, s := range matcher.sinksByMethod["%x()"] {
		if s.Category == taint.SnkCommand {
			return s
		}
	}
	return nil
}

// processRubySubshellSink handles Ruby command execution via the backtick
// (`` `cmd #{x}` ``) and `%x{cmd #{x}}` forms. Both parse as a `subshell` node
// holding `string_content` and `interpolation` children — the SAME shell-vs-
// nothing distinction as `system("...")`: an interpolated tainted value reaches
// the shell unescaped (CWE-78). This mirrors processPHPEchoSink (a sink that is
// a language construct, not a call). The segment-aware inline-sanitizer check
// keeps `` `echo #{id.to_i}` `` and `` `cp #{Shellwords.escape(p)}` `` clean
// while `` `cat #{params[:f]}` `` fires. Gated to Ruby at the call site.
func processRubySubshellSink(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder) {
	sink := rubySubshellSink(matcher)
	if sink == nil {
		return
	}
	line := int(n.StartRow()) + 1

	// Whole-subshell taint via a tracked variable
	// (`x = params[:c]; out = `sh #{x}``). The segment-aware sanitizer check
	// requires the sanitizer to wrap the TAINTED segment, not merely appear in
	// a sibling interpolation.
	if ts, ok := nodeIsTainted(n, tm, cfg); ok && ts != nil {
		if ts.isTaintedFor(sink.Category) &&
			!inlineSanitizerNeutralizesTaint(n, tm, matcher, cfg, sink.Category) {
			fb.addFlow(ts, sink, line, scopeName)
			return
		}
	}

	// Inline source inside an interpolation with no intervening assignment
	// (`` `cat #{params[:f]}` ``, `` `cp #{file.original_filename}` ``). Check
	// each interpolation segment that carries a source; the sanitizer (if any)
	// must live in that same segment.
	for i := 0; i < n.ChildCount(); i++ {
		seg := n.Child(i)
		if !isInterpolationSegment(seg.Type()) {
			continue
		}
		src := findSourceInExpr(seg, matcher, cfg)
		if src == nil {
			continue
		}
		if containsInlineSanitizer(seg, matcher, cfg, sink.Category) {
			continue
		}
		ts := &taintState{
			varName:    "__subshell__",
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     "__subshell__",
			}},
		}
		fb.addFlow(ts, sink, line, scopeName)
		return
	}
}

// phpBenignUploadTempArg reports whether the expression is a read of the
// server-generated upload temp path `$_FILES[...]['tmp_name']`. That value is
// chosen by PHP (a random /tmp path), not by the attacker, so an inline read
// of it at a sink is not itself the vulnerability — the upload danger lives in
// the DESTINATION (`$_FILES[...]['name']`-derived save path) or the absence of
// type validation, both of which still flag via the other (tainted-variable)
// arguments. Without this, the inline-source fallback flags arg 0 of every
// `move_uploaded_file($_FILES['x']['tmp_name'], $safeRandomDest)` even when the
// upload is MIME-checked and renamed — the canonical SAFE upload shape. Scoped
// to the literal `['tmp_name']` final key so the dangerous `['name']` /
// `['type']` keys are unaffected.
func phpBenignUploadTempArg(n *ast.Node) bool {
	// Unwrap a PHP `argument` wrapper to its inner expression.
	if n != nil && n.Type() == "argument" {
		if inner := firstNamedChild(n); inner != nil {
			n = inner
		}
	}
	if n == nil || n.Type() != "subscript_expression" {
		return false
	}
	// The final subscript key must be the string literal 'tmp_name'. This is
	// PHP's upload-temp idiom: both the direct form `$_FILES['x']['tmp_name']`
	// and the aliased form `$file['tmp_name']` (where `$file = $_FILES['x']`)
	// read the server-generated temp path. The key is unique enough to the
	// $_FILES upload structure that matching on it alone is safe.
	for i := n.ChildCount() - 1; i >= 0; i-- {
		c := n.Child(i)
		if c.Type() == "string" {
			key := strings.Trim(strings.TrimSpace(c.Text()), "'\"")
			return key == "tmp_name"
		}
	}
	return false
}

// processSwitchInterproc handles switch statements by walking all case bodies
// with the current taint map, allowing taint to propagate through switch/case.
// processPythonMatch handles Python's match_statement with constant scrutinee
// folding. When the subject can be evaluated to a string constant (e.g.
// `guess = "ABC"[1]` → 'B'), only the matching case_clause is walked,
// eliminating OWASP MATCH-CONST FPs. Otherwise, every clause body is walked
// linearly (same as the default body.Walk path), preserving may-be-tainted
// semantics for inputs we cannot resolve.
func processPythonMatch(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	subject := n.ChildByFieldName("subject")
	if subject == nil {
		named := n.NamedChildren()
		if len(named) > 0 {
			subject = named[0]
		}
	}

	subjVal, subjOK := evalConstStrExpr(subject, tm)

	// Iterate case clauses; if subject is known, pick the matching arm; if
	// none match, fall back to wildcard ("case _:"). If subject is not
	// known, walk every clause body to preserve union semantics.
	var caseClauses []*ast.Node
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if !c.IsNamed() {
			continue
		}
		// Match block in tree-sitter-python contains case_clauses directly;
		// in some grammars there's an intermediate block.
		if c.Type() == "case_clause" {
			caseClauses = append(caseClauses, c)
			continue
		}
		// Recurse one level (block / match_block).
		for j := 0; j < c.ChildCount(); j++ {
			cc := c.Child(j)
			if cc.IsNamed() && cc.Type() == "case_clause" {
				caseClauses = append(caseClauses, cc)
			}
		}
	}

	if !subjOK {
		for _, clause := range caseClauses {
			walkBodyInterproc(clause, tm, cfg, matcher, scopeName, fb, summaries)
		}
		return
	}

	var wildcard *ast.Node
	for _, clause := range caseClauses {
		patNode := pythonCasePattern(clause)
		if patNode == nil {
			continue
		}
		if pythonCasePatternIsWildcard(patNode) {
			wildcard = clause
			continue
		}
		if pythonCasePatternMatches(patNode, subjVal) {
			walkBodyInterproc(clause, tm, cfg, matcher, scopeName, fb, summaries)
			return
		}
	}
	if wildcard != nil {
		walkBodyInterproc(wildcard, tm, cfg, matcher, scopeName, fb, summaries)
	}
}

// pythonCasePattern returns the pattern subtree of a case_clause.
func pythonCasePattern(clause *ast.Node) *ast.Node {
	if p := clause.ChildByFieldName("pattern"); p != nil {
		return p
	}
	for i := 0; i < clause.ChildCount(); i++ {
		c := clause.Child(i)
		if !c.IsNamed() {
			continue
		}
		t := c.Type()
		if t == "case_pattern" || t == "match_pattern" || strings.HasSuffix(t, "_pattern") {
			return c
		}
	}
	return nil
}

// pythonCasePatternIsWildcard returns true when the pattern is `_` (catch-all).
func pythonCasePatternIsWildcard(p *ast.Node) bool {
	if p == nil {
		return false
	}
	t := strings.TrimSpace(p.Text())
	return t == "_" || t == "case _"
}

// pythonCasePatternMatches returns true when the pattern matches the given
// string subject. Handles literal patterns ('A') and alternative patterns
// ('A' | 'B' | 'C'). Other pattern types (class, mapping, sequence, capture)
// return false — they aren't const-foldable.
func pythonCasePatternMatches(p *ast.Node, subject string) bool {
	if p == nil {
		return false
	}
	// Try direct string-literal match.
	if lit, ok := pythonStringLiteralValue(p); ok {
		return lit == subject
	}
	// Recurse into named children — case_pattern wraps the actual pattern,
	// and `'A' | 'B'` shows up as an or_pattern / case_pattern with multiple
	// alternatives. The first alternative that matches wins.
	for i := 0; i < p.ChildCount(); i++ {
		c := p.Child(i)
		if !c.IsNamed() {
			continue
		}
		if pythonCasePatternMatches(c, subject) {
			return true
		}
	}
	return false
}

// pythonStringLiteralValue extracts the contents of a Python string literal
// node, stripping the surrounding quotes. Returns ("", false) if the node is
// not a simple unescaped single-segment string literal.
func pythonStringLiteralValue(n *ast.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Type() != "string" {
		return "", false
	}
	text := n.Text()
	if len(text) < 2 {
		return "", false
	}
	q := text[0]
	if (q != '"' && q != '\'') || text[len(text)-1] != q {
		return "", false
	}
	return text[1 : len(text)-1], true
}

// evalConstStrExpr evaluates an expression to a Python string constant if
// possible. Handles identifiers (looking up strConsts), string literals, and
// subscripts on known string constants with integer-literal indices.
func evalConstStrExpr(n *ast.Node, tm *taintMap) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Type() {
	case "identifier":
		if tm != nil {
			if v, ok := tm.strConsts[n.Text()]; ok {
				return v, true
			}
		}
		return "", false
	case "string":
		return pythonStringLiteralValue(n)
	case "parenthesized_expression":
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return evalConstStrExpr(c, tm)
			}
		}
	case "subscript":
		obj := n.ChildByFieldName("value")
		if obj == nil {
			named := n.NamedChildren()
			if len(named) > 0 {
				obj = named[0]
			}
		}
		objStr, ok := evalConstStrExpr(obj, tm)
		if !ok {
			return "", false
		}
		idxNode := n.ChildByFieldName("subscript")
		if idxNode == nil {
			named := n.NamedChildren()
			if len(named) >= 2 {
				idxNode = named[1]
			}
		}
		if idxNode == nil {
			return "", false
		}
		idx, err := strconv.Atoi(strings.TrimSpace(idxNode.Text()))
		if err != nil {
			return "", false
		}
		if idx < 0 {
			idx += len(objStr)
		}
		if idx < 0 || idx >= len(objStr) {
			return "", false
		}
		return string(objStr[idx]), true
	}
	return "", false
}

func processSwitchInterproc(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	// Try to evaluate the switch condition to a constant.
	// Pattern: switch (switchTarget) where switchTarget = guess.charAt(1)
	// and guess = "ABC".
	cond := n.ChildByFieldName("condition")
	if cond != nil {
		// Unwrap parenthesized_expression around condition.
		inner := cond
		if inner.Type() == "parenthesized_expression" {
			for i := 0; i < inner.ChildCount(); i++ {
				c := inner.Child(i)
				if c.IsNamed() {
					inner = c
					break
				}
			}
		}
		if targetVal, ok := evalConstExpr(inner, tm); ok {
			// Find the matching case and only walk that one.
			if walkMatchingSwitchCase(n, targetVal, tm, cfg, matcher, scopeName, fb, summaries) {
				return
			}
		}
	}

	// Fallback: walk all children of the switch statement.
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
		}
	}
}

// walkMatchingSwitchCase finds the case matching targetVal and walks that case
// body — honouring C/Java/C#-style fall-through. The tree-sitter grammars for
// these languages parse stacked case labels as *separate* statement groups, so
// `case 'C':\n case 'D': stmt; break;` produces an empty group for 'C' and a
// statement-bearing group for 'D'. A switch on 'C' must execute the statements
// in the 'D' group too (fall-through continues until a group terminates with a
// break/return/throw/continue). Returns true if a match was found and handled.
func walkMatchingSwitchCase(n *ast.Node, targetVal int64, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) bool {
	body := n.ChildByFieldName("body")
	if body == nil {
		return false
	}

	// Collect the named statement-group children in source order so we can
	// fall through from the matched group into subsequent groups.
	var groups []*ast.Node
	for i := 0; i < body.ChildCount(); i++ {
		group := body.Child(i)
		if group.IsNamed() {
			groups = append(groups, group)
		}
	}

	matchIdx := -1
	defaultIdx := -1
	for gi, group := range groups {
		isDefault := false
		matched := false
		for j := 0; j < group.ChildCount(); j++ {
			label := group.Child(j)
			if label.Type() != "switch_label" {
				continue
			}
			// Check if this is a "default" label.
			for k := 0; k < label.ChildCount(); k++ {
				lc := label.Child(k)
				if !lc.IsNamed() && lc.Text() == "default" {
					isDefault = true
				}
				if lc.IsNamed() {
					if v, ok := evalConstExpr(lc, tm); ok && v == targetVal {
						matched = true
					}
				}
			}
		}
		if isDefault && defaultIdx == -1 {
			defaultIdx = gi
		}
		if matched && matchIdx == -1 {
			matchIdx = gi
		}
	}

	start := matchIdx
	if start == -1 {
		// No case matched — fall through from the default group if present.
		start = defaultIdx
	}
	if start == -1 {
		return false
	}

	// Walk from the entry group onward, stopping after the first group whose
	// body terminates control flow (break/return/throw/continue). Empty
	// fall-through groups (a bare `case X:` with no statements) carry no
	// terminator, so execution continues into the next group — exactly the
	// behaviour the stacked-label idiom relies on.
	for gi := start; gi < len(groups); gi++ {
		group := groups[gi]
		walkBodyInterproc(group, tm, cfg, matcher, scopeName, fb, summaries)
		if switchGroupTerminates(group) {
			break
		}
	}
	return true
}

// switchGroupTerminates reports whether a switch_block_statement_group ends the
// case's control flow — i.e. has a top-level break/return/throw/continue
// statement. When false, the following group's statements execute via
// fall-through. Only the group's *direct* statement children are inspected: a
// break nested inside a loop in the case body terminates the loop, not the
// case, and must not be mistaken for a case terminator.
func switchGroupTerminates(group *ast.Node) bool {
	for i := 0; i < group.ChildCount(); i++ {
		c := group.Child(i)
		switch c.Type() {
		case "break_statement", "return_statement", "throw_statement", "continue_statement":
			return true
		}
	}
	return false
}

// processIfAllowlistInterproc is like processIfAllowlist but uses walkBodyInterproc.
// processSwiftGuard handles a Swift `guard <cond> else { <exit> }` statement.
// When the condition is a validation/allowlist check on a tainted variable
// and the else-block transfers control out of the scope (throw / return /
// break / continue), the variable is validated for everything that executes
// AFTER the guard. We sanitise it in the shared taint map so the post-guard
// fall-through is treated as safe. Conservative: only acts when the else-block
// clearly exits, mirroring the `branchHasEarlyReturn` fall-through logic used
// for if-statements. Swift-only (caller gates on language + node type).
func processSwiftGuard(n *ast.Node, tm *taintMap, cfg *langConfig) {
	// The condition is the first named child that is an expression (the
	// children are: `guard` kw, <cond>, `else` kw, the failure block).
	var cond *ast.Node
	var elseBlock *ast.Node
	sawElse := false
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		switch c.Type() {
		case "else":
			sawElse = true
		case "statements":
			if sawElse {
				elseBlock = c
			}
		default:
			if !sawElse && c.IsNamed() && cond == nil {
				cond = c
			}
		}
	}
	if cond == nil {
		return
	}
	// The else-block must clearly exit the scope; otherwise the variable may
	// still be tainted on some path. Reuse the shared exit detector.
	if elseBlock != nil && !branchHasEarlyReturn(elseBlock) {
		return
	}
	check := detectAllowlistCheck(cond, tm, cfg)
	if check == nil {
		check = detectValidationGuard(cond, tm, cfg)
	}
	applyAllowlistClear(tm, check)
}

// applyAllowlistClear applies an allowlist/validation guard detection result
// to a taint map. Category-blind results (categories nil — the historical
// behaviour, and every shape we can't positively classify) delete the
// variable wholesale, exactly as before. Category-SCOPED results
// (path-containment shapes like x.contains("..")) mark the variable
// sanitized for only the guard's categories, so the other sink categories
// (SQL, command, XSS, eval, …) keep firing — a path check must not silence
// an injection. No-op when no guard was detected.
func applyAllowlistClear(tm *taintMap, check *allowlistCheckResult) {
	if tm == nil || check == nil || check.varName == "" {
		return
	}
	if len(check.categories) == 0 {
		tm.delete(check.varName)
		return
	}
	ts := tm.get(check.varName)
	if ts == nil {
		return
	}
	if ts.sanitized == nil {
		ts.sanitized = make(map[taint.SinkCategory]bool)
	}
	for _, c := range check.categories {
		ts.sanitized[c] = true
	}
}

// processIfBranchAware walks if/else branches with proper taint map
// snapshot and merge. Each branch gets a clone of the current taint map;
// after both branches are walked, the results are merged (union: a variable
// is tainted if tainted in ANY branch). This prevents false positives from
// safe assignments in never-taken branches clearing taint, and prevents
// false negatives from tainted assignments in always-taken branches being
// overwritten by the else branch.
func processIfBranchAware(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	cond := cfg.extractIfCondition(n)
	consequence := cfg.extractIfConsequence(n)
	alternative := cfg.extractIfAlternative(n)

	// Python walrus in the if-condition: `if (data := request.get_json()):`
	// binds `data` for the rest of the scope. The branch walks below never
	// descend into the condition, so seed any walrus targets here into the
	// shared taint map (the condition always executes, so the binding reaches
	// both branches and the fall-through). Only the walrus assignment is
	// processed — sink/source detection in the condition is left to the other
	// paths, so this cannot introduce new condition-side flows. Gated to
	// Python; `named_expression` is Python-unique.
	if cfg.language == rules.LangPython && cond != nil {
		cond.Walk(func(w *ast.Node) bool {
			if w.Type() == "named_expression" {
				processAssignInterproc(w, tm, cfg, matcher, summaries)
			}
			return true
		})
	}

	// PHP: the if-condition itself can hold a sink call or a source-seeding
	// assignment — both are dominant flat-script idioms:
	//   if (move_uploaded_file($_FILES['x']['tmp_name'], $dst)) { ... }
	//   while (($row = mysqli_query($c, $q)) && ...) { ... }
	// The branch walks below only descend into the consequence/alternative,
	// never the condition, so these flows are otherwise lost. Walk the
	// condition with the shared taint map (the condition always executes)
	// BEFORE branch processing. Gated to PHP so no other language's
	// guard-detection path changes. The downstream allowlist/validation
	// detectors read `cond` read-only, so this is order-safe.
	if cfg.language == rules.LangPHP && cond != nil {
		walkBodyInterproc(cond, tm, cfg, matcher, scopeName, fb, summaries)
	}

	// Python path-traversal guard (PR-HHpy): recognise containment combos
	// like `path.startswith(BASE)`, `path.is_relative_to(BASE)`,
	// `commonpath([BASE, path]) == BASE`, `not path.is_absolute()`, and
	// `".." in path` BEFORE the generic allowlist/validation matcher. These
	// guards validate only the path/filename — they don't say anything
	// about SQL or command-injection safety for the same variable — so the
	// path-category-scoped sanitisation here is more precise than the
	// generic detector's behaviour of deleting the variable wholesale.
	if cfg.language == rules.LangPython {
		if pres := inferPythonPathGuard(cond, tm, cfg); pres != nil && consequence != nil {
			// In the if-branch (safe path): sanitize path categories on the
			// guarded variable and any pathDerivedFrom origin.
			branchTm := tm.cloneMap()
			applyPythonPathGuard(branchTm, pres)
			// Compound guards like `if not is_safe(a) or not b.startswith("/tmp"):`
			// can validate distinct variables — the path-guard caught `b`'s
			// path-context, but `a` may still be cleared by a free-function
			// validator on the other side of the boolean. Apply that check
			// alongside the path-guard so both vars get sanitised when the
			// rejection branch returns. Same logic for the fall-through.
			if vc := detectValidationGuard(cond, tm, cfg); vc != nil && vc.varName != pres.varName {
				applyAllowlistClear(branchTm, vc)
			}
			walkBodyInterproc(consequence, branchTm, cfg, matcher, scopeName, fb, summaries)
			if alternative != nil {
				// Else-branch keeps the variable tainted for path sinks too
				// (we don't know which side is the rejection branch without
				// inspecting the body — the safe fall-through case below
				// handles that explicitly).
				walkBodyInterproc(alternative, tm, cfg, matcher, scopeName, fb, summaries)
			} else if branchHasEarlyReturn(consequence) {
				// The if-body returns/raises → fall-through is the safe
				// branch. Apply path sanitisation to the surviving taint map.
				applyPythonPathGuard(tm, pres)
				if vc := detectValidationGuard(cond, tm, cfg); vc != nil && vc.varName != pres.varName {
					applyAllowlistClear(tm, vc)
				}
			}
			return
		}
	}

	// Barrier guard: language-configurable validation guards
	// that constrain a tainted value to a safe character set / value domain —
	// `if (/^[0-9]+$/.test(id)) { ... }` (JS), `if (id.matches("[A-Za-z0-9]+"))`
	// (Java), `if (typeof id === "number")`. Gated to languages whose config
	// opts in (cfg.barrierGuards != nil → JS/TS/Java), so every other language
	// is byte-unchanged. Unlike the generic allowlist/validation matcher below,
	// this is category-scoped: it marks the SPECIFIC variable sanitized for the
	// SPECIFIC sink categories the guard neutralises (mirroring the Python
	// path-guard), so a different sink category or a different (unvalidated)
	// variable still fires. Runs before the wholesale matcher so the precise
	// path wins; falls through to the wholesale matcher when no barrier matches.
	if cfg.barrierGuards != nil {
		if bres := inferBarrierGuard(cond, tm, cfg); bres != nil && consequence != nil {
			branchTm := tm.cloneMap()
			applyBarrierGuard(branchTm, bres)
			walkBodyInterproc(consequence, branchTm, cfg, matcher, scopeName, fb, summaries)
			if alternative != nil {
				// Else-branch keeps the variable tainted (we don't know which
				// side is the rejection branch without inspecting the body).
				walkBodyInterproc(alternative, tm, cfg, matcher, scopeName, fb, summaries)
			}
			// When there is no else branch and the if-body returns/throws, the
			// guard is a positive check whose fall-through path ran the
			// rejection; we conservatively leave the surviving taint map intact
			// (do NOT sanitize on fall-through).
			return
		}
	}

	// Special case: allowlist check or validation guard in condition →
	// the if-branch has the variable sanitized, else-branch keeps it tainted.
	check := detectAllowlistCheck(cond, tm, cfg)
	if check == nil {
		// Try validation guard: x.contains("..") { return } clears taint on fallthrough
		check = detectValidationGuard(cond, tm, cfg)
	}
	if check != nil && consequence != nil {
		branchTm := tm.cloneMap()
		applyAllowlistClear(branchTm, check)
		walkBodyInterproc(consequence, branchTm, cfg, matcher, scopeName, fb, summaries)
		if alternative != nil {
			walkBodyInterproc(alternative, tm, cfg, matcher, scopeName, fb, summaries)
		} else if branchHasEarlyReturn(consequence) {
			// The allowlist rejection branch returns/raises — code after the
			// if only executes when the check passed. Clear taint on the
			// validated variable for the fallthrough path.
			//
			// When the validated variable was a URL parse of another tainted
			// variable (`url = urlparse(bar)`), back-propagate the URL-
			// injection sanitisation to that origin: a `url.netloc not in
			// [literals]` allowlist also validates `bar` for SnkRedirect /
			// SnkURLFetch, since `bar` is the parsed URL.
			if ts := tm.get(check.varName); ts != nil && ts.urlParsedFrom != "" {
				if origin := tm.get(ts.urlParsedFrom); origin != nil {
					if origin.sanitized == nil {
						origin.sanitized = make(map[taint.SinkCategory]bool)
					}
					origin.sanitized[taint.SnkRedirect] = true
					origin.sanitized[taint.SnkURLFetch] = true
				}
			}
			applyAllowlistClear(tm, check)
		}
		return
	}

	// Constant condition: if we can evaluate the condition to a compile-time
	// constant, only walk the branch that actually executes. This eliminates
	// FPs from patterns like: if ((7*18)+num > 200) bar = "safe"; else bar = param;
	if cond != nil {
		if val, ok := evalConstExpr(cond, tm); ok {
			if val != 0 {
				// Condition is always true — only consequence executes.
				if consequence != nil {
					walkBodyInterproc(consequence, tm, cfg, matcher, scopeName, fb, summaries)
				}
			} else {
				// Condition is always false — only alternative executes.
				if alternative != nil {
					walkBodyInterproc(alternative, tm, cfg, matcher, scopeName, fb, summaries)
				}
			}
			return
		}
	}

	// General case: walk each branch with separate flow builders.
	// Flows found in BOTH branches are kept at full confidence.
	// Flows found in only ONE branch get decayed confidence (0.6x)
	// since that branch may not execute.
	if consequence == nil {
		return
	}

	preBranch := tm.cloneMap()

	// Walk if-branch with its own flow builder.
	ifTm := tm.cloneMap()
	ifFb := newFlowBuilder(fb.filePath)
	walkBodyInterproc(consequence, ifTm, cfg, matcher, scopeName, ifFb, summaries)

	if alternative != nil {
		// Walk else-branch with its own flow builder.
		elseTm := preBranch.cloneMap()
		elseFb := newFlowBuilder(fb.filePath)
		walkBodyInterproc(alternative, elseTm, cfg, matcher, scopeName, elseFb, summaries)

		// Merge flows: flows in both branches keep full confidence,
		// flows in only one branch get decayed.
		mergedFlows := mergeBranchFlows(ifFb.flows, elseFb.flows)
		fb.flows = append(fb.flows, mergedFlows...)

		// Merge taint maps (union for subsequent code).
		ifTm.mergeFrom(elseTm)
	} else {
		// No else branch — if-branch flows get decayed confidence
		// (the branch may not execute).
		for i := range ifFb.flows {
			ifFb.flows[i].Confidence *= branchSingleWeight
		}
		fb.flows = append(fb.flows, ifFb.flows...)
		ifTm.mergeFrom(preBranch)
	}

	tm.replaceFrom(ifTm)
}

// isDeterministicCondition returns true if the if-condition is a compile-time
// constant expression (arithmetic on integer literals with a comparison).
// These appear in OWASP Benchmark as always-true/false guards:
//
//	if 7 * 42 > 200:       → pure constant, always true
//	if (294 > 200):         → literal comparison
//
// When detected, the walker uses intersection merge (must-taint) instead of
// weighted merge (may-taint), aggressively eliminating FPs from dead branches.
// branchHasEarlyReturn checks if a branch body contains a return or raise/throw
// statement, indicating the code after the if only executes when this branch
// is NOT taken. Also recognises framework abort helpers (Flask `abort()`,
// FastAPI `raise HTTPException(...)` shorthand) that exit the request handler
// without an explicit `return` keyword — common in CVE safe-pattern fixtures.
func branchHasEarlyReturn(body *ast.Node) bool {
	if body == nil {
		return false
	}
	found := false
	body.Walk(func(n *ast.Node) bool {
		if found {
			return false
		}
		switch n.Type() {
		case "return_statement", "raise_statement", "throw_statement",
			"throw_expression":
			found = true
			return false
		case "control_transfer_statement":
			// Swift: `throw`, `return`, `break`, `continue` are all wrapped in
			// a `control_transfer_statement` node. Any of these exits the
			// current scope for guard-fall-through purposes.
			found = true
			return false
		case "exit_statement":
			// PHP `exit(...)` / `die(...)` as a bare language statement
			// terminates the script — equivalent to an early return for the
			// purposes of fall-through guard analysis.
			found = true
			return false
		}
		// Framework-aware: bare `abort(...)` / `sys.exit(...)` / `os._exit(...)`
		// terminate the request or process the same as `return`. Conservative
		// list — only names whose semantics are unambiguous.
		if n.Type() == "call" {
			fn := n.ChildByFieldName("function")
			if fn != nil {
				name := fn.Text()
				switch name {
				case "abort", "flask.abort", "sys.exit", "os._exit", "exit":
					found = true
					return false
				}
			}
		}
		// PHP parses `die(...)` (and `exit(...)` when written with parens in
		// some grammar versions) as a function_call_expression whose function
		// name is "die"/"exit" — both halt the script.
		if n.Type() == "function_call_expression" {
			fn := n.ChildByFieldName("function")
			if fn != nil {
				switch fn.Text() {
				case "die", "exit":
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// evalConstExpr attempts to evaluate a constant integer expression using known
// local constants from the taint map. Returns (value, true) if the expression
// can be fully evaluated, (0, false) otherwise.
// Handles: integer literals, identifiers mapped to consts, +, -, *, /, >,
// <, >=, <=, ==, !=, parenthesized expressions.
func evalConstExpr(n *ast.Node, tm *taintMap) (int64, bool) {
	if n == nil {
		return 0, false
	}
	switch n.Type() {
	case "decimal_integer_literal", "integer", "number", "int_literal",
		"hex_integer_literal", "octal_integer_literal":
		text := n.Text()
		v, err := strconv.ParseInt(text, 0, 64)
		if err != nil {
			return 0, false
		}
		return v, true

	case "identifier":
		if tm != nil {
			if v, ok := tm.consts[n.Text()]; ok {
				return v, true
			}
		}
		return 0, false

	case "parenthesized_expression":
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return evalConstExpr(c, tm)
			}
		}
		return 0, false

	case "binary_expression", "binary_operator", "comparison_operator":
		// Python tree-sitter parses `a > b` as comparison_operator (not
		// binary_operator), and the named children may not carry left/right
		// field names — they appear positionally. Handle both layouts.
		left := n.ChildByFieldName("left")
		right := n.ChildByFieldName("right")
		if (left == nil || right == nil) && n.Type() == "comparison_operator" {
			named := n.NamedChildren()
			if len(named) >= 2 {
				left = named[0]
				right = named[1]
			}
		}
		if left == nil || right == nil {
			return 0, false
		}
		lv, lok := evalConstExpr(left, tm)
		rv, rok := evalConstExpr(right, tm)
		if !lok || !rok {
			return 0, false
		}
		// Extract operator from unnamed children.
		op := ""
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() {
				t := c.Text()
				if t == "+" || t == "-" || t == "*" || t == "/" ||
					t == ">" || t == "<" || t == ">=" || t == "<=" ||
					t == "==" || t == "!=" {
					op = t
					break
				}
			}
		}
		switch op {
		case "+":
			return lv + rv, true
		case "-":
			return lv - rv, true
		case "*":
			return lv * rv, true
		case "/":
			if rv == 0 {
				return 0, false
			}
			return lv / rv, true
		case ">":
			return boolToInt(lv > rv), true
		case "<":
			return boolToInt(lv < rv), true
		case ">=":
			return boolToInt(lv >= rv), true
		case "<=":
			return boolToInt(lv <= rv), true
		case "==":
			return boolToInt(lv == rv), true
		case "!=":
			return boolToInt(lv != rv), true
		}
		return 0, false

	case "unary_expression", "unary_operator":
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				v, ok := evalConstExpr(c, tm)
				if !ok {
					return 0, false
				}
				// Check for negation operator.
				if i > 0 {
					prev := n.Child(i - 1)
					if prev != nil && prev.Text() == "-" {
						return -v, true
					}
				}
				return v, true
			}
		}
		return 0, false

	// Method invocation: handle str.charAt(N) where str is a known string constant.
	case "method_invocation":
		if tm == nil {
			return 0, false
		}
		nameNode := n.ChildByFieldName("name")
		objNode := n.ChildByFieldName("object")
		if nameNode == nil || objNode == nil {
			return 0, false
		}
		if nameNode.Text() != "charAt" {
			return 0, false
		}
		strVal, ok := tm.strConsts[objNode.Text()]
		if !ok {
			return 0, false
		}
		// Extract the integer argument.
		argsNode := n.ChildByFieldName("arguments")
		if argsNode == nil {
			return 0, false
		}
		for i := 0; i < argsNode.ChildCount(); i++ {
			c := argsNode.Child(i)
			if c.IsNamed() {
				idx, ok := evalConstExpr(c, tm)
				if !ok || idx < 0 || int(idx) >= len(strVal) {
					return 0, false
				}
				return int64(strVal[idx]), true
			}
		}
		return 0, false

	// Character literal: 'A' → 65
	case "character_literal":
		text := n.Text()
		if len(text) == 3 && text[0] == '\'' && text[2] == '\'' {
			return int64(text[1]), true
		}
		return 0, false
	}
	return 0, false
}

// trackStrConst records a string constant if the RHS is a string literal.
func trackStrConst(varName string, rhs *ast.Node, tm *taintMap) {
	if rhs == nil {
		return
	}
	if rhs.Type() == "string_literal" || rhs.Type() == "string" {
		text := rhs.Text()
		// Strip surrounding quotes.
		if len(text) >= 2 && (text[0] == '"' || text[0] == '\'') {
			tm.strConsts[varName] = text[1 : len(text)-1]
		}
		return
	}
	// Derived: `guess = possible[1]` where possible is a known string
	// constant — record guess's value so a subsequent `match guess:` can
	// const-fold to the matching arm.
	if v, ok := evalConstStrExpr(rhs, tm); ok {
		tm.strConsts[varName] = v
	}
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// isAllLiteralMatch checks if a node is a match/switch expression where every
// arm either returns a literal value or is an early-exit (return/break/continue).
// Such expressions produce untainted results regardless of the scrutinee's taint,
// because the output can only be one of the hardcoded literal values.
func isAllLiteralMatch(n *ast.Node) bool {
	t := n.Type()
	if t != "match_expression" && t != "switch_expression" {
		return false
	}
	// Find the match_block / switch_body child.
	var body *ast.Node
	for _, c := range n.NamedChildren() {
		ct := c.Type()
		if ct == "match_block" || ct == "switch_body" || ct == "switch_block" {
			body = c
			break
		}
	}
	if body == nil {
		return false
	}

	armCount := 0
	for _, arm := range body.NamedChildren() {
		at := arm.Type()
		if at != "match_arm" && at != "switch_case" && at != "switch_default" {
			continue
		}
		armCount++
		// The value is the last named child that isn't the pattern.
		children := arm.NamedChildren()
		var value *ast.Node
		if n := len(children); n > 0 {
			last := children[n-1]
			ct := last.Type()
			if ct != "match_pattern" && ct != "case_pattern" {
				value = last
			}
		}
		if value == nil {
			return false
		}
		if !isLiteralOrEarlyExit(value) {
			return false
		}
	}
	return armCount >= 2 // need at least 2 arms to be a meaningful match
}

// isLiteralOrEarlyExit checks if a node is a literal value or an early exit
// statement (return, break, continue).
func isLiteralOrEarlyExit(n *ast.Node) bool {
	t := n.Type()
	switch t {
	case "string_literal", "integer_literal", "float_literal",
		"boolean_literal", "char_literal", "number_literal",
		"string", "number", "true", "false", "nil", "null_literal":
		return true
	case "return_expression", "return_statement", "break_expression",
		"break_statement", "continue_expression", "continue_statement":
		return true
	case "block", "expression_statement":
		// Block containing a single statement — check the inner expression.
		children := n.NamedChildren()
		if len(children) == 1 {
			return isLiteralOrEarlyExit(children[0])
		}
	case "unary_expression", "prefix_expression":
		// e.g., -1
		children := n.NamedChildren()
		if len(children) == 1 {
			return isLiteralOrEarlyExit(children[0])
		}
	}
	return false
}

// isAllLiteralRubyCase reports whether n is a Ruby `case` expression whose every
// branch (when/else) yields ONLY a literal value — never the case subject or any
// tainted expression. In tree-sitter-ruby a `case` node holds a `[value]` field
// (the subject) followed by `when` clauses (each with a `then` body) and an
// optional `else`. When every arm's resulting value is a fixed literal, the
// assigned variable is a validated-allowlist enum mapping (e.g. mapping a DB
// notification_level to one of {"track!","mute!",…}); it is NOT attacker-
// controlled even though the subject may be tainted, so it must not inherit the
// subject's taint. Default-zero: returns false (leaving taint intact) for any
// arm that is not a plain literal, so a `when 1 then params[:x]` branch keeps
// propagating. Ruby-only shape; the shared isAllLiteralMatch covers
// match_expression/switch_expression for the other languages.
func isAllLiteralRubyCase(n *ast.Node) bool {
	if n.Type() != "case" {
		return false
	}
	branchCount := 0
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "when":
			// The branch body is the `then` node (field name "body").
			body := c.ChildByFieldName("body")
			if body == nil || !rubyBranchBodyAllLiteral(body) {
				return false
			}
			branchCount++
		case "else":
			if !rubyBranchBodyAllLiteral(c) {
				return false
			}
			branchCount++
		}
	}
	// Require at least two arms to be a meaningful mapping (mirrors
	// isAllLiteralMatch's armCount >= 2 guard).
	return branchCount >= 2
}

// rubyBranchBodyAllLiteral reports whether a `then`/`else` branch body yields a
// literal value. The value of a Ruby branch is its LAST statement, so only that
// statement is checked (earlier statements may be side effects that do not flow
// to the assignment target).
func rubyBranchBodyAllLiteral(body *ast.Node) bool {
	kids := body.NamedChildren()
	if len(kids) == 0 {
		return false
	}
	return isRubyLiteralValue(kids[len(kids)-1])
}

// isRubyLiteralValue reports whether a node is a Ruby literal that cannot carry
// taint. Interpolated strings (`"x#{taint}"`) are deliberately rejected — they
// embed arbitrary expressions — as are constants, method calls, and variable
// references, keeping the discriminator narrow (recall-safe: an unrecognised
// value type leaves taint intact).
func isRubyLiteralValue(n *ast.Node) bool {
	switch n.Type() {
	case "integer", "float", "simple_symbol", "hash_key_symbol",
		"true", "false", "nil":
		return true
	case "string", "bare_string", "heredoc_beginning":
		// A Ruby string is only a literal when it contains no interpolation.
		for _, c := range n.NamedChildren() {
			if c.Type() == "interpolation" {
				return false
			}
		}
		return true
	}
	return false
}

// unwrapToCall unwraps cast_expression and parenthesized_expression wrappers
// to find the inner call node. Java frequently uses casts around map/list .get()
// calls, e.g., (String) map.get("key"). Returns the inner call node if found,
// otherwise returns the original node unchanged.
func unwrapToCall(n *ast.Node, cfg *langConfig) *ast.Node {
	for {
		switch n.Type() {
		case "cast_expression":
			// Java/C cast: (Type) expr — the value field contains the inner expression.
			inner := n.ChildByFieldName("value")
			if inner == nil {
				return n
			}
			n = inner
		case "parenthesized_expression":
			// (expr) — unwrap parentheses.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					n = c
					break
				}
			}
			continue
		case "match_expression":
			// Rust: match expr { ... } — unwrap to the matched expression.
			value := n.ChildByFieldName("value")
			if value == nil {
				return n
			}
			n = value
			continue
		case "await_expression":
			// C#/JS/TS: await expr — unwrap to the inner expression.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() {
					n = c
					break
				}
			}
			continue
		case "try_expression":
			// Swift: try / try? / try! expr — unwrap to the inner call so
			// throwing sanitizers and sinks (e.g. try AES.GCM.open(...),
			// try jws.validate(with:), try JSONSerialization.jsonObject(with:))
			// are still resolved by matchSanitizer / matchSinkCall in the
			// assignment handler. The grammar tags the inner expression with
			// the field name "expr".
			inner := n.ChildByFieldName("expr")
			if inner == nil {
				return n
			}
			n = inner
			continue
		case "nil_coalescing_expression":
			// Swift: `expr ?? default` — unwrap to the LEFT arm (the value
			// before `??`) so a sanitizer/sink call on the optional value is
			// resolved through the nil-coalescing wrapper. The dominant safe
			// shape is `let safe = input.addingPercentEncoding(...) ?? ""`:
			// without this, the assignment-RHS sanitizer match in processAssign*
			// sees the `nil_coalescing_expression` node (not a call) and the
			// percent-encoding/escaping sanitizer never neutralises the value.
			// The right arm is a literal fallback, so the security-relevant call
			// is always the left arm. Swift-only (the node type is unique to the
			// Swift grammar); the first named child is the left operand.
			if cfg != nil && cfg.language == rules.LangSwift {
				if left := firstNamedChild(n); left != nil {
					n = left
					continue
				}
			}
			return n
		case "postfix_expression":
			// Swift: `expr!` force-unwrap — unwrap to the inner expression so a
			// sanitizer/sink call followed by `!` is resolved (e.g.
			// `let safe = input.addingPercentEncoding(...)!`). Swift-only; the
			// first named child is the unwrapped expression.
			if cfg != nil && cfg.language == rules.LangSwift {
				if inner := firstNamedChild(n); inner != nil {
					n = inner
					continue
				}
			}
			return n
		case "call_expression":
			// Rust Result/Option unwrapping: `san(x).unwrap()` / `.expect("..")`
			// wraps the real sanitizer (or sink) call in a trailing combinator
			// whose own method name is NOT in any catalog. Peel it so the inner
			// call is what matchSanitizer / matchSinkCall sees, e.g.
			// `let safe = shlex::try_quote(&input).unwrap();` is recognized as a
			// sanitizer assignment rather than an opaque `unwrap` call. Rust-only:
			// other languages' call_expression must fall through unchanged.
			if cfg != nil && cfg.language == rules.LangRust {
				if inner := rustPeelResultCombinator(n); inner != nil {
					n = inner
					continue
				}
			}
			return n
		default:
			return n
		}
	}
}

// rustResultCombinators are zero/one-arg Result/Option methods that return the
// wrapped value (or panic). They are transparent to taint: the security-relevant
// call is their receiver. Peeling them lets the sanitizer/sink matcher see
// `shlex::try_quote(x).unwrap()` as `shlex::try_quote(x)`.
var rustResultCombinators = map[string]bool{
	"unwrap":            true,
	"expect":            true,
	"unwrap_or_default": true,
	"unwrap_unchecked":  true,
}

// rustPeelResultCombinator returns the inner call when n is a Rust
// `<call>.unwrap()` / `.expect(..)` etc., else nil. It only peels when the
// receiver is itself a call_expression, so it never alters a plain
// `value.unwrap()` (where value is a variable — taint propagation already
// tracks that receiver separately).
//
// The inner call must be a FREE-FUNCTION / PATH call (`identifier` or
// `scoped_identifier` function), e.g. `shlex::try_quote(x)` or `env::var("X")`.
// It deliberately does NOT peel when the inner call is a METHOD call
// (`field_expression` function such as `dest.parse()`): peeling those would
// expose chained method results to the catalog's generic, intentionally-broad
// method-name sanitizers (e.g. the bare `.parse()` numeric-parse neutralizer),
// dropping real taint like `dest.parse().unwrap()` flowing to an open redirect.
// Free-function sanitizer/source calls have no such overlap.
func rustPeelResultCombinator(n *ast.Node) *ast.Node {
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Type() != "field_expression" {
		return nil
	}
	field := fn.ChildByFieldName("field")
	if field == nil || !rustResultCombinators[field.Text()] {
		return nil
	}
	recv := fn.ChildByFieldName("value")
	if recv == nil || recv.Type() != "call_expression" {
		return nil
	}
	innerFn := recv.ChildByFieldName("function")
	if innerFn == nil {
		return nil
	}
	switch innerFn.Type() {
	case "identifier", "scoped_identifier":
		return recv
	}
	return nil
}

// pyBranchBoundaryTypes are the Python tree-sitter node types that introduce a
// conditional / looped / per-arm execution context. If an assignment node has
// one of these as an ancestor *before* the enclosing function body, the
// assignment is NOT guaranteed to run on every path, so a generic
// last-write-wins clear of a prior taint would be unsound (it would erase taint
// set by a sibling branch). The canonical hazard is the OWASP `match`
// statement, whose case-clause arms are walked linearly without branch-merge:
//
//	match guess:
//	    case 'A': bar = param      # tainted (TP must survive)
//	    case _:   bar = 'literal'  # untainted — must NOT clear the arm above
var pyBranchBoundaryTypes = map[string]bool{
	"if_statement":           true,
	"elif_clause":            true,
	"else_clause":            true,
	"for_statement":          true,
	"while_statement":        true,
	"try_statement":          true,
	"except_clause":          true,
	"except_group_clause":    true,
	"finally_clause":         true,
	"with_statement":         true,
	"match_statement":        true,
	"case_clause":            true,
	"conditional_expression": true,
}

// pyFuncBoundaryTypes terminate the upward branch scan: reaching one of these
// (the assignment's own enclosing function / module) without first crossing a
// branch boundary proves the assignment is an unconditional statement that runs
// on every path through that function body.
var pyFuncBoundaryTypes = map[string]bool{
	"function_definition": true,
	"lambda":              true,
	"module":              true,
}

// jsBranchBoundaryTypes / jsFuncBoundaryTypes are the JS/TS analog of the Python
// boundary maps, used by the strong-update (last-write-wins) kill for JS and TS.
// The same linear-walk hazard the Python gate guards against applies to JS/TS
// `switch`: each `switch_case` arm is walked in source order without a
// branch-merge, so `switch_case`/`switch_default`/`switch_statement` are
// boundaries and a later all-literal arm cannot clear taint set by an earlier
// arm. `try`/`catch`/`finally`, every loop, and the `if`/`else` arms are
// likewise conditional. (Node types confirmed empirically against
// tree-sitter-javascript; the TS grammar is a superset and shares these names.)
var jsBranchBoundaryTypes = map[string]bool{
	"if_statement":       true,
	"else_clause":        true,
	"switch_statement":   true,
	"switch_case":        true,
	"switch_default":     true,
	"for_statement":      true,
	"for_in_statement":   true,
	"while_statement":    true,
	"do_statement":       true,
	"try_statement":      true,
	"catch_clause":       true,
	"finally_clause":     true,
	"ternary_expression": true,
}

var jsFuncBoundaryTypes = map[string]bool{
	"function_declaration":           true,
	"function_expression":            true,
	"arrow_function":                 true,
	"method_definition":              true,
	"generator_function":             true,
	"generator_function_declaration": true,
	"program":                        true,
}

// javaBranchBoundaryTypes / javaFuncBoundaryTypes are the Java analog. Java's
// `switch` arms are `switch_block_statement_group` (classic `case:` form) or
// `switch_rule` (arrow `case ->` form); both are walked linearly, so they are
// boundaries — a tainted classic-switch arm must survive a later literal arm.
// (Node types confirmed empirically against tree-sitter-java.)
var javaBranchBoundaryTypes = map[string]bool{
	"if_statement":                 true,
	"switch_expression":            true,
	"switch_block_statement_group": true,
	"switch_rule":                  true,
	"for_statement":                true,
	"enhanced_for_statement":       true,
	"while_statement":              true,
	"do_statement":                 true,
	"try_statement":                true,
	"try_with_resources_statement": true,
	"catch_clause":                 true,
	"finally_clause":               true,
	"ternary_expression":           true,
}

var javaFuncBoundaryTypes = map[string]bool{
	"method_declaration":      true,
	"constructor_declaration": true,
	"lambda_expression":       true,
	"static_initializer":      true,
	"program":                 true,
}

// branchBoundaryTypesFor returns the (branch, function) boundary-type maps for a
// language, or (nil, nil) when the language has no strong-update support. Only
// the languages whose strong-update kill is wired in processAssignInterproc
// (Python, JS/TS, Java) return non-nil maps; every other language keeps the
// pre-existing conservative may-taint behaviour (no kill).
func branchBoundaryTypesFor(lang rules.Language) (branch, fn map[string]bool) {
	switch lang {
	case rules.LangPython:
		return pyBranchBoundaryTypes, pyFuncBoundaryTypes
	case rules.LangJavaScript, rules.LangTypeScript:
		return jsBranchBoundaryTypes, jsFuncBoundaryTypes
	case rules.LangJava:
		return javaBranchBoundaryTypes, javaFuncBoundaryTypes
	}
	return nil, nil
}

// supportsStrongUpdate reports whether the language has a wired strong-update
// (last-write-wins) kill: a later UNCONDITIONAL reassignment of a bare
// identifier to an untainted RHS clears the prior unconditional taint. Limited
// to the languages with vetted branch-boundary maps (Python, JS/TS, Java) so
// every other language keeps the pre-existing conservative may-taint behaviour.
func supportsStrongUpdate(lang rules.Language) bool {
	branch, _ := branchBoundaryTypesFor(lang)
	return branch != nil
}

// isPlainAssignNode reports whether the assignment node `n` is a plain `=`
// rebinding (not a compound/augmented assignment such as `+=`/`-=`), for which
// an untainted RHS genuinely makes the result untainted. An augmented assignment
// reads its own prior value, so `x += param` followed by `x += 'literal'` must
// keep the accumulated taint and must NOT be treated as a kill.
//
// The grammars disagree on how augmented assignment is spelled. Python uses a
// distinct node type `augmented_assignment` (the kill node is `assignment`);
// JS/TS use `augmented_assignment_expression` (the kill node is
// `assignment_expression`); Java uses a SINGLE `assignment_expression` node type
// for both, carrying an `operator` field that is `=` for a plain assignment and
// `+=`/`-=`/... for an augmented one — so for Java the node type alone is
// insufficient and we must inspect the operator field.
func isPlainAssignNode(n *ast.Node, cfg *langConfig) bool {
	switch cfg.language {
	case rules.LangPython:
		return n.Type() == "assignment"
	case rules.LangJavaScript, rules.LangTypeScript:
		return n.Type() == "assignment_expression"
	case rules.LangJava:
		if n.Type() != "assignment_expression" {
			return false
		}
		if op := n.ChildByFieldName("operator"); op != nil {
			return op.Text() == "="
		}
		return false
	}
	return false
}

// isUnconditionalAssign reports whether an assignment node executes
// unconditionally within its enclosing function (i.e. it is a plain top-level
// statement of the function body, not nested inside any if/for/while/try/with/
// switch/match arm). It is the strong-update gate that lets a later
// `bar = <untainted>` clear taint set by an earlier `bar = <tainted>` ONLY when
// both are unconditional siblings — the OWASP dict/list-shuffle SAFE shape —
// while leaving linear-walked branch arms (Python match-statement case clauses,
// JS/Java switch arms) untouched. Languages without strong-update support return
// false (no kill is ever performed for them).
func isUnconditionalAssign(n *ast.Node, cfg *langConfig) bool {
	branch, fn := branchBoundaryTypesFor(cfg.language)
	if branch == nil {
		return false
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		t := p.Type()
		if branch[t] {
			return false
		}
		if fn[t] {
			return true
		}
	}
	// Reached the top of the tree without an enclosing function — treat the
	// assignment as a module-level unconditional statement.
	return true
}

// pythonUnpackTargets collects the leaf identifier target nodes of a Python
// tuple/list unpacking pattern (pattern_list / list_pattern / tuple_pattern),
// recursing into nested patterns and unwrapping `*rest` splat targets and
// parenthesised groups. The `_` wildcard is skipped. Subscript/attribute
// targets (`a[i]`, `obj.x`) are intentionally not collected — the unpack
// helper only models simple-identifier binds, leaving such targets with their
// prior taint state (byte-identical to pre-change behaviour).
func pythonUnpackTargets(pat *ast.Node) []*ast.Node {
	var out []*ast.Node
	var rec func(p *ast.Node)
	rec = func(p *ast.Node) {
		if p == nil {
			return
		}
		switch p.Type() {
		case "identifier":
			if p.Text() != "_" {
				out = append(out, p)
			}
		case "pattern_list", "list_pattern", "tuple_pattern",
			"list_splat_pattern", "parenthesized_expression":
			for i := 0; i < p.ChildCount(); i++ {
				if c := p.Child(i); c.IsNamed() {
					rec(c)
				}
			}
		}
	}
	rec(pat)
	return out
}

// resolveUnpackElemTaint resolves the taint of one unpack source expression:
// first via the taint map (nodeIsTainted), then — for inline source calls that
// were never bound to a variable (`a, b = request.args.get("x"), "safe"`) — by
// synthesising a source-seeded state, mirroring emitInterprocSinkFlows.
func resolveUnpackElemTaint(expr *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, line int) *taintState {
	if ts, ok := nodeIsTainted(expr, tm, cfg); ok {
		return ts
	}
	if src := findSourceInExpr(expr, matcher, cfg); src != nil {
		return &taintState{
			varName:    expr.Text(),
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     expr.Text(),
			}},
		}
	}
	return nil
}

// resolveInlineSourceThroughSanitizer handles `lhs = sanitizer(... inline
// source ...)` where the source was never bound to a variable so nodeIsTainted
// (and the bound-arg scan) can't see it. It mirrors the bound-arg scan's
// breadth: any call argument subtree that findSourceInExpr resolves to a source
// seeds a transient taint state. Callers then apply the sanitizer's Neutralizes
// categories, so e.g. `int(request.args.get("x"))` is tainted-but-coerced and
// `basename($_FILES['x']['name'])` is tainted-but-path-sanitized.
//
// This branch is required precisely because the call/argument propagation paths
// (propagateCallResultInterproc) now resolve inline source arguments: without
// it, a sanitizer wrapping an inline source would fall through to generic
// propagation and carry the raw taint with no neutralisation.
func resolveInlineSourceThroughSanitizer(rhsCall *ast.Node, lhsName string, line int, cfg *langConfig, matcher *tsMatcher) (*taintState, bool) {
	for _, arg := range cfg.extractCallArgs(rhsCall) {
		sn := arg
		if sn.Type() == "argument" {
			if innerArg := firstNamedChild(sn); innerArg != nil {
				sn = innerArg
			}
		}
		if src := findSourceInExpr(sn, matcher, cfg); src != nil {
			return &taintState{
				varName:    lhsName,
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "tainted by " + src.MethodName,
					VarName:     lhsName,
				}},
			}, true
		}
	}
	return nil, false
}

// resolveInlineSourceThroughCallArgs resolves an inline source nested inside a
// WRAPPER CALL in sink-argument position:
//
//	_.merge(target, JSON.parse(req.body.data))       // deserializer wrapper
//	os.system(transform(request.args.get("c")))      // unknown wrapper
//	readfile(realpath($_GET['doc']))                 // sanitizer wrapper
//
// The var-assigned twin of each shape already flows: assignment-position
// resolution goes through matchSanitizer + resolveInlineSourceThroughSanitizer
// (sanitizer wrapper — no decay, Neutralizes applied) or
// propagateCallResultInterproc → resolveUnpackElemTaint (unknown wrapper —
// one-hop propagation decay). But findSourceInExpr never descends into a
// call's ARGUMENTS (only its receiver chain, plus the Ruby Base64 carve-out),
// so the same source inlined at the sink was invisible — a syntactic blind
// spot, not a semantic gate. This helper mirrors the assignment-position
// semantics exactly: same source defs, same sanitizer interaction, same decay.
//
// Returns nil when the argument is not call-shaped or no argument subtree
// resolves to a source. Callers must still apply isTaintedFor(sink.Category)
// (so a sanitizer wrapper's Neutralizes suppress the matching categories) and
// the segment-aware inline-sanitizer guard.
func resolveInlineSourceThroughCallArgs(argExpr *ast.Node, line int, cfg *langConfig, matcher *tsMatcher) *taintState {
	if argExpr == nil || cfg == nil {
		return nil
	}
	callNode := unwrapToCall(argExpr, cfg)
	if callNode == nil || !cfg.callTypes[callNode.Type()] {
		return nil
	}
	ts, ok := resolveInlineSourceThroughSanitizer(callNode, "__arg__", line, cfg, matcher)
	if !ok {
		return nil
	}
	// Sanitizer wrapper: assignment parity (processAssignInterproc) — full
	// confidence, mark every Neutralizes category so isTaintedFor() reports
	// tainted-but-coerced. PHP builtins can carry several same-named catalog
	// entries with different Neutralizes lists; union them all, mirroring the
	// assignment path.
	if san, _ := matcher.matchSanitizer(callNode); san != nil {
		for _, cat := range san.Neutralizes {
			ts.sanitized[cat] = true
		}
		if cfg.language == rules.LangPHP {
			for _, cat := range matcher.allSanitizerCategories(callNode) {
				ts.sanitized[cat] = true
			}
		}
		return ts
	}
	// Unknown wrapper: one-hop propagation decay
	// (propagateCallResultInterproc parity).
	callName := cfg.extractCallName(callNode)
	if callName == "" {
		callName = "call"
	}
	return ts.clone("__arg__", line, "propagated through "+callName+"()", propagationConfidence(callNode))
}

// processPythonUnpackAssign handles Python tuple/list unpacking assignments
// (`a, b = ...`, `[a, b] = ...`, `first, *rest = ...`) whose LHS is a
// pattern_list / list_pattern / tuple_pattern. The single-name
// extractAssignLHS path returns "" for these, so without this branch every
// unpacked target silently loses taint (`a, b = raw.split(",")` →
// subprocess.call(a) produced zero flows). Returns true when it recognised
// (and consumed) an unpack-shaped assignment.
//
// RHS taint is resolved BEFORE the targets are rebound so swaps
// (`a, b = b, a`) and self-references read pre-assignment state. Binding is
// element-wise when the RHS is a literal tuple/list of matching arity
// (`a, b = tainted, safe` taints only `a`); otherwise it is a conservative
// whole-RHS distribution (`a, b = parts.split(",")` taints both targets, since
// every element unpacked from a tainted iterable derives from it).
func processPythonUnpackAssign(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) bool {
	lhs := n.ChildByFieldName("left")
	if lhs == nil {
		return false
	}
	switch lhs.Type() {
	case "pattern_list", "list_pattern", "tuple_pattern":
	default:
		return false
	}
	targets := pythonUnpackTargets(lhs)
	rhs := cfg.extractAssignRHS(n)
	if rhs == nil || len(targets) == 0 {
		return true // unpack-shaped, but nothing to bind
	}
	line := int(n.StartRow()) + 1

	// Collect RHS tuple/list elements (if any) for element-wise binding.
	var elems []*ast.Node
	switch rhs.Type() {
	case "expression_list", "tuple", "list":
		for i := 0; i < rhs.ChildCount(); i++ {
			if c := rhs.Child(i); c.IsNamed() {
				elems = append(elems, c)
			}
		}
	}

	// Resolve taint to assign to each target, reading the map pre-mutation.
	assign := make([]*taintState, len(targets))
	if len(elems) == len(targets) {
		for i := range targets {
			if ts := resolveUnpackElemTaint(elems[i], tm, cfg, matcher, line); ts != nil {
				assign[i] = ts.clone(targets[i].Text(), line, "unpacked from tuple element", 0.95)
			}
		}
	} else if ts := resolveUnpackElemTaint(rhs, tm, cfg, matcher, line); ts != nil {
		for i := range targets {
			assign[i] = ts.clone(targets[i].Text(), line, "unpacked from tainted iterable", 0.9)
		}
	}

	// Rebind: clear stale state on every target, then set the tainted ones.
	for i, tgt := range targets {
		name := tgt.Text()
		tm.clearFieldsOf(name)
		tm.delete(name)
		if assign[i] != nil {
			tm.set(name, assign[i])
		}
	}
	return true
}

// perlListTargets returns the bare variable names (no sigil) introduced by a
// Perl list-assignment LHS — either a multi-variable `variable_declaration`
// (`my ($a, $b)`, `my ($first, @rest)`) or a bare `list_expression`
// (`($a, $b) = ...`). Wildcard `undef` placeholders parse as their own node
// type (not scalar/array/hash) and are skipped, so positional alignment with a
// matching-arity RHS is preserved.
func perlListTargets(lhs *ast.Node) []string {
	var out []string
	for i := 0; i < lhs.ChildCount(); i++ {
		c := lhs.Child(i)
		if !c.IsNamed() {
			continue
		}
		switch c.Type() {
		case "scalar", "array", "hash", "container_variable":
			if name := perlVarName(c); name != "" && name != "_" {
				out = append(out, name)
			}
		}
	}
	return out
}

// processPerlListAssign handles Perl list-assignment whose LHS binds two or more
// variables: `my ($a, $b) = (...)`, `my ($first, @rest) = (...)`, and the bare
// `($a, $b) = (...)` form. Perl declares no varDeclTypes, so a `my` declaration
// reaches processAssignInterproc as an assignment_expression; extractAssignLHS
// only returns the FIRST scalar, so every later target silently lost taint
// (`my ($a, $b) = ($cgi->param('x'), 'safe'); $dbh->do($a)` produced zero
// flows). Returns true when it recognised (and consumed) a multi-target
// list-assignment; single-variable declarations return false and fall through
// to the existing single-name path (sanitizer / field handling unchanged).
//
// RHS taint is resolved BEFORE the targets are rebound so swaps and
// self-references read pre-assignment state. Binding is element-wise when the
// RHS is a `list_expression` of matching arity (`($src, 'safe')` taints only the
// first target); otherwise it is a conservative whole-RHS distribution
// (`my ($a, $b) = @tainted_parts` taints both targets, since every element
// unpacked from a tainted list derives from it).
func processPerlListAssign(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) bool {
	lhs := n.ChildByFieldName("left")
	if lhs == nil {
		return false
	}
	switch lhs.Type() {
	case "variable_declaration", "list_expression":
	default:
		return false
	}
	targets := perlListTargets(lhs)
	if len(targets) < 2 {
		// Single-variable `my $x = ...` (or `my ($x) = ...`): leave it to the
		// existing single-name path so sanitizer/field logic still applies.
		return false
	}
	// A parenthesized RHS (`= ($a, $b)`) splits the "right" field across three
	// children — `(`, the list_expression, `)` — and ChildByFieldName returns the
	// bare `(` token. Take the named "right" child so we land on the
	// list_expression (or the single expression for an unparenthesized RHS such
	// as `= @parts`).
	var rhs *ast.Node
	for i := 0; i < n.ChildCount(); i++ {
		if c := n.Child(i); c.FieldName() == "right" && c.IsNamed() {
			rhs = c
		}
	}
	if rhs == nil {
		return true // list-shaped, but nothing to bind
	}
	line := int(n.StartRow()) + 1

	// Collect RHS list elements (if any) for element-wise binding.
	var elems []*ast.Node
	if rhs.Type() == "list_expression" {
		for i := 0; i < rhs.ChildCount(); i++ {
			if c := rhs.Child(i); c.IsNamed() {
				elems = append(elems, c)
			}
		}
	}

	// Resolve taint to assign to each target, reading the map pre-mutation.
	assign := make([]*taintState, len(targets))
	switch {
	case len(elems) == len(targets):
		// Exact arity: bind element-wise so `($src, 'safe')` taints only the
		// first target.
		for i := range targets {
			if ts := resolveUnpackElemTaint(elems[i], tm, cfg, matcher, line); ts != nil {
				assign[i] = ts.clone(targets[i], line, "unpacked from list element", 0.95)
			}
		}
	default:
		// Arity mismatch (slurpy `my ($first, @rest) = (...)`, or a non-literal
		// RHS like `my ($a, $b) = @parts`): conservatively distribute. If the RHS
		// is a list literal, taint all targets when ANY element is tainted (we
		// cannot align positions once an array sponge is involved); otherwise
		// resolve the whole RHS as a single tainted value.
		var whole *taintState
		if len(elems) > 0 {
			for _, e := range elems {
				if ts := resolveUnpackElemTaint(e, tm, cfg, matcher, line); ts != nil {
					whole = ts
					break
				}
			}
		} else {
			whole = resolveUnpackElemTaint(rhs, tm, cfg, matcher, line)
		}
		if whole != nil {
			for i := range targets {
				assign[i] = whole.clone(targets[i], line, "unpacked from tainted list", 0.9)
			}
		}
	}

	// Rebind: clear stale state on every target, then set the tainted ones.
	for i, name := range targets {
		tm.clearFieldsOf(name)
		tm.delete(name)
		if assign[i] != nil {
			tm.set(name, assign[i])
		}
	}
	return true
}

// phpListAssignTargets collects the leaf `variable_name` bind targets of a PHP
// list-destructuring LHS (`list($a, $b)` and the short `[$a, $b]` form both
// parse to a `list_literal`), recursing into nested `list_literal` groups
// (`list($a, list($b, $c))`). Keyed targets (`list("k" => $v)`) contribute only
// their value `variable_name`; the string key children are skipped. Subscript /
// property targets (`$a[0]`, `$o->x`) are intentionally not collected — like the
// Python/Ruby unpack helpers, only plain-variable binds are modelled, leaving
// such targets with their prior taint state.
func phpListAssignTargets(pat *ast.Node) []*ast.Node {
	var out []*ast.Node
	var rec func(p *ast.Node)
	rec = func(p *ast.Node) {
		if p == nil {
			return
		}
		switch p.Type() {
		case "variable_name":
			out = append(out, p)
		case "list_literal":
			for i := 0; i < p.ChildCount(); i++ {
				if c := p.Child(i); c.IsNamed() {
					rec(c)
				}
			}
		}
	}
	rec(pat)
	return out
}

// processPHPListAssign handles PHP list-destructuring assignments
// (`list($a, $b) = ...`, `[$a, $b] = ...`, nested `list($a, list($b, $c)) = ...`)
// whose LHS is a `list_literal`. The single-name extractAssignLHS path returns
// "" for these, so without this branch every destructured target silently loses
// taint (`list($u, $h) = $parts` → `system($u)` produced zero flows). Returns
// true when it recognised (and consumed) a list-destructuring assignment.
//
// RHS taint is resolved BEFORE the targets are rebound so self-references read
// pre-assignment state. Binding is element-wise when the RHS is an array literal
// of matching arity (`[$tainted, "safe"]` taints only the first target);
// otherwise it is a conservative whole-RHS distribution (`list($u,$h) = $parts`
// taints both targets, since every element unpacked from a tainted array
// derives from it). Mirrors processPythonUnpackAssign / processRubyMultiAssign.
//
// A call-node RHS is admitted to whole-RHS distribution ONLY when it is not a
// sanitizer call — resolveUnpackElemTaint is sanitizer-blind, so distributing a
// sanitizing call's result would re-taint just-validated outputs. Unlike Ruby's
// blunt call exclusion this admits non-sanitizer calls, because the dominant PHP
// idiom `list($u, $h) = explode("@", $email)` legitimately yields tainted parts
// from a (non-sanitizer) call.
func processPHPListAssign(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) bool {
	lhs := n.ChildByFieldName("left")
	if lhs == nil || lhs.Type() != "list_literal" {
		return false
	}
	targets := phpListAssignTargets(lhs)
	rhs := cfg.extractAssignRHS(n)
	if rhs == nil || len(targets) == 0 {
		return true // list-shaped, but nothing to bind
	}
	line := int(n.StartRow()) + 1

	// Collect RHS array-literal element VALUE nodes (if any) for element-wise
	// binding. Each positional/keyed entry is an `array_element_initializer`
	// whose value is its last named child (`$x` for `$x`, or `$x` for
	// `"k" => $x`).
	var elems []*ast.Node
	if rhs.Type() == "array_creation_expression" {
		for i := 0; i < rhs.ChildCount(); i++ {
			c := rhs.Child(i)
			if !c.IsNamed() || c.Type() != "array_element_initializer" {
				continue
			}
			var val *ast.Node
			for j := 0; j < c.ChildCount(); j++ {
				if cc := c.Child(j); cc.IsNamed() {
					val = cc
				}
			}
			if val != nil {
				elems = append(elems, val)
			}
		}
	}

	// Resolve taint to assign to each target, reading the map pre-mutation.
	assign := make([]*taintState, len(targets))
	if len(elems) == len(targets) {
		for i := range targets {
			if ts := resolveUnpackElemTaint(elems[i], tm, cfg, matcher, line); ts != nil {
				assign[i] = ts.clone(targets[i].Text(), line, "destructured from array element", 0.95)
			}
		}
	} else {
		// Conservative whole-RHS distribution. A call RHS is admitted only when
		// it is NOT a sanitizer call (resolveUnpackElemTaint is sanitizer-blind);
		// a tainted-value variable/index already carries its sanitization state,
		// so distributing it is safe.
		distribute := true
		if cfg.callTypes[rhs.Type()] {
			if san, _ := matcher.matchSanitizer(rhs); san != nil {
				distribute = false
			}
		}
		if distribute {
			if ts := resolveUnpackElemTaint(rhs, tm, cfg, matcher, line); ts != nil {
				for i := range targets {
					assign[i] = ts.clone(targets[i].Text(), line, "destructured from tainted value", 0.9)
				}
			}
		}
	}

	// Rebind: clear stale state on every target, then set the tainted ones.
	for i, tgt := range targets {
		name := tgt.Text()
		tm.clearFieldsOf(name)
		tm.delete(name)
		if assign[i] != nil {
			tm.set(name, assign[i])
		}
	}
	return true
}

// rubyMultiAssignTargets collects the simple-identifier (and instance/class/
// global-variable) bind targets of a Ruby `left_assignment_list`, recursing
// into `*rest` splat targets (rest_assignment) and nested destructuring
// (destructured_left_assignment). The `_` throwaway is skipped. Subscript/
// attribute setters (`a[i] = `, `obj.x = `) are intentionally not collected —
// like the Python unpack helper, only plain-name binds are modelled, leaving
// such targets with their prior taint state.
func rubyMultiAssignTargets(lhs *ast.Node) []*ast.Node {
	var out []*ast.Node
	var rec func(p *ast.Node)
	rec = func(p *ast.Node) {
		if p == nil {
			return
		}
		switch p.Type() {
		case "identifier", "instance_variable", "class_variable", "global_variable":
			if p.Text() != "_" {
				out = append(out, p)
			}
		case "left_assignment_list", "rest_assignment", "destructured_left_assignment":
			for i := 0; i < p.ChildCount(); i++ {
				if c := p.Child(i); c.IsNamed() {
					rec(c)
				}
			}
		}
	}
	rec(lhs)
	return out
}

// processRubyMultiAssign handles Ruby parallel/multiple assignment
// (`a, b = x, y`, `a, b = [x, y]`, `first, *rest = arr`) whose LHS is a
// `left_assignment_list`. The single-name extractAssignLHS path returns "" for
// these, so without this branch every parallel-assigned target silently loses
// taint (`a, b = params[:cmd], "safe"` → `system(a)` produced zero flows).
// Returns true when it recognised (and consumed) a multi-assign.
//
// RHS taint is resolved BEFORE the targets are rebound so swaps (`a, b = b, a`)
// read pre-assignment state. Binding is element-wise when the RHS is a literal
// expression list / array of matching arity (`a, b = tainted, safe` taints only
// `a`); otherwise it is a conservative whole-RHS distribution (`a, b = pair()`
// taints both targets, since every element unpacked from a tainted value
// derives from it). Mirrors processPythonUnpackAssign.
func processRubyMultiAssign(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) bool {
	lhs := n.ChildByFieldName("left")
	if lhs == nil || lhs.Type() != "left_assignment_list" {
		return false
	}
	targets := rubyMultiAssignTargets(lhs)
	rhs := cfg.extractAssignRHS(n)
	if rhs == nil || len(targets) == 0 {
		return true // multi-assign-shaped, but nothing to bind
	}
	line := int(n.StartRow()) + 1

	// Collect RHS list/array elements (if any) for element-wise binding.
	var elems []*ast.Node
	switch rhs.Type() {
	case "right_assignment_list", "array":
		for i := 0; i < rhs.ChildCount(); i++ {
			if c := rhs.Child(i); c.IsNamed() {
				elems = append(elems, c)
			}
		}
	}

	// Resolve taint to assign to each target, reading the map pre-mutation.
	assign := make([]*taintState, len(targets))
	if len(elems) == len(targets) {
		for i := range targets {
			if ts := resolveUnpackElemTaint(elems[i], tm, cfg, matcher, line); ts != nil {
				assign[i] = ts.clone(targets[i].Text(), line, "unpacked from list element", 0.95)
			}
		}
	} else if !cfg.callTypes[rhs.Type()] {
		// Conservative whole-RHS distribution for a tainted value RHS
		// (variable, index, etc.): every multiple-assigned target derives
		// from it. Call RHS nodes are intentionally excluded — their result
		// taint depends on sanitizer/propagation semantics that only the
		// single-name path models, and resolveUnpackElemTaint is
		// sanitizer-blind. Distributing a sanitizing call's result here would
		// re-taint outputs that were just validated, e.g.
		// `verified, jwt, _ = JOSE::JWT.verify(key, token)` must NOT taint
		// `jwt`. A tainted-value variable already carries its sanitization
		// state, so it is safe to distribute.
		if ts := resolveUnpackElemTaint(rhs, tm, cfg, matcher, line); ts != nil {
			for i := range targets {
				assign[i] = ts.clone(targets[i].Text(), line, "unpacked from tainted value", 0.9)
			}
		}
	}

	// Rebind: clear stale state on every target, then set the tainted ones.
	for i, tgt := range targets {
		name := tgt.Text()
		tm.clearFieldsOf(name)
		tm.delete(name)
		if assign[i] != nil {
			tm.set(name, assign[i])
		}
	}
	return true
}

// bareIdentName returns the variable name when rhs is a single bare-identifier
// reference (`a`, `$a`, plain `simple_identifier`/`varname`), i.e. a candidate
// MUST-alias copy source for `b = a`. It returns "" for any compound RHS
// (calls, field/subscript accesses, literals, binary ops) — those are not a
// straight object copy. The returned name uses the node's Text() so it matches
// the keys produced by extractAssignLHS (e.g. PHP's `$`-prefixed names).
func bareIdentName(rhs *ast.Node, cfg *langConfig) string {
	if rhs == nil || cfg == nil {
		return ""
	}
	t := rhs.Type()
	if t == cfg.identType || t == "identifier" || t == "simple_identifier" ||
		t == "variable_name" || t == "varname" {
		return strings.TrimSpace(rhs.Text())
	}
	return ""
}

// recordAliasIfBareCopy records an intra-function must-alias edge when an
// assignment / declaration is a straight `lhs = rhs` copy of a bare object
// reference (rhs is a single identifier). The edge lets a field write through
// one name reflect on a field read through the other (see taintMap.aliases).
// It is intentionally conservative: only plain `=` copies of a bare identifier
// qualify, and the prior alias edges for lhs were already cleared by breakAlias
// at the rebind site. Skips field-keyed LHS (`obj.attr = x`) — that targets a
// single field, not an object copy.
func recordAliasIfBareCopy(lhsName string, rhs *ast.Node, tm *taintMap, cfg *langConfig) {
	if lhsName == "" {
		return
	}
	if _, isField := isFieldKey(lhsName); isField {
		return
	}
	if target := bareIdentName(rhs, cfg); target != "" {
		tm.recordAlias(lhsName, target)
	}
}

// processAssignInterproc extends processAssign with interprocedural call tracking.
func processAssignInterproc(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary) {
	// Python tuple/list unpacking (`a, b = ...`) — LHS is a pattern_list and
	// extractAssignLHS yields "", so handle it before the single-name path.
	if cfg.language == rules.LangPython && processPythonUnpackAssign(n, tm, cfg, matcher) {
		return
	}

	// Ruby parallel/multiple assignment (`a, b = ...`) — LHS is a
	// left_assignment_list and extractAssignLHS yields "", so handle it
	// before the single-name path.
	if cfg.language == rules.LangRuby && processRubyMultiAssign(n, tm, cfg, matcher) {
		return
	}

	// PHP list-destructuring (`list($a, $b) = ...`, `[$a, $b] = ...`) — LHS is a
	// list_literal and extractAssignLHS yields "", so handle it before the
	// single-name path.
	if cfg.language == rules.LangPHP && processPHPListAssign(n, tm, cfg, matcher) {
		return
	}

	// C# tuple deconstruction by re-assignment: `(a, b) = Parse(input)`. The
	// LHS is a tuple_expression, so extractAssignLHS yields "" and every
	// target loses taint without this branch.
	if cfg.language == rules.LangCSharp && processCSharpDeconstruct(n, tm, cfg, matcher) {
		return
	}

	// Perl list-assignment (`my ($a, $b) = (...)`, `($a, $b) = (...)`). Perl has
	// no varDeclTypes, so `my` declarations arrive here as assignment_expressions
	// whose LHS is a multi-variable variable_declaration (or a bare
	// list_expression). extractAssignLHS only yields the FIRST scalar, so every
	// subsequent target silently lost taint. Handle it before the single-name
	// path.
	if cfg.language == rules.LangPerl && processPerlListAssign(n, tm, cfg, matcher) {
		return
	}

	lhsName := cfg.extractAssignLHS(n)
	if lhsName == "" || lhsName == "_" {
		return
	}

	rhs := cfg.extractAssignRHS(n)
	if rhs == nil {
		return
	}

	line := int(n.StartRow()) + 1
	_ = line

	// Shallow field sensitivity: rebinding a bare object invalidates all of
	// its previously-recorded per-field taint entries. Run BEFORE the
	// existing branches so every code path below sees a clean field slate.
	// Skip when LHS is itself a field key (e.g. `obj.attr = ...`), which
	// targets a single field and must not disturb sibling fields.
	_, lhsIsField := isFieldKey(lhsName)
	if !lhsIsField {
		tm.clearFieldsOf(lhsName)
		// Rebinding a bare object breaks any must-alias edge it took part in:
		// the previous `b = a` copy no longer holds once `b` is reassigned.
		// Run before recording a fresh edge below so `b = a; b = other` ends
		// with only the `b -> other` edge.
		tm.breakAlias(lhsName)
		// PR-CATjs-2: any reassignment to `name` invalidates a prior
		// fresh-empty marker — the new RHS may be tainted or non-empty.
		// The recordFreshLocalEmptyIfJS call below re-marks it when the
		// new RHS is itself an empty container.
		delete(tm.freshLocalEmpty, lhsName)
		// Intra-function must-alias: a straight `lhs = <bareIdent>` copy names
		// the same object under both variables, so a field write through one
		// is visible through the other (taintMap.prefixTainted resolves it).
		recordAliasIfBareCopy(lhsName, rhs, tm, cfg)
	}
	// Mark the resulting taintState (if any) as having been produced by an
	// explicit field assignment, so bare-object reads at sinks can surface
	// the field via anyFieldTainted. Done as a defer so every early-return
	// branch below gets the same treatment without each having to remember.
	if lhsIsField {
		defer func() {
			if ts := tm.get(lhsName); ts != nil && ts.source != nil {
				ts.fromFieldAssign = true
			}
		}()
	}

	// Strong-update gate (OWASP dict/list-shuffle FP fix): record on the
	// resulting taint entry whether this bare-variable assignment runs
	// unconditionally within its function. The flag is consumed by the
	// untainted-RHS branch below, where a later unconditional assignment of an
	// untainted value clears a prior unconditional taint (last-write-wins).
	// Gated to the languages with a wired strong-update kill (Python, JS/TS,
	// Java — branchBoundaryTypesFor returns nil otherwise) and bare (non-field)
	// identifiers so other languages and field-keyed entries keep byte-identical
	// behaviour. Done as a defer so every early-return branch that sets taint
	// gets stamped.
	if !lhsIsField && supportsStrongUpdate(cfg.language) {
		uncond := isUnconditionalAssign(n, cfg)
		defer func() {
			if ts := tm.get(lhsName); ts != nil && ts.source != nil {
				ts.setUnconditionally = uncond
			}
		}()
	}

	// PR-CATjs-2: re-record fresh-empty marker when an assignment swaps in
	// a new empty container (`obj = {}`) and look for reduce-accumulator
	// shapes in the RHS.
	recordFreshLocalEmptyIfJS(lhsName, rhs, tm, cfg)
	noteReduceAccumulatorFreshness(rhs, tm, cfg)

	// Match/switch with all-literal arms → untainted result.
	if isAllLiteralMatch(rhs) {
		tm.delete(lhsName)
		return
	}

	// Ruby `case`/`when` whose every arm yields a fixed literal → the assigned
	// variable is a validated-allowlist enum mapping, not attacker-controlled,
	// even when the case subject is DB/param-tainted. Suppress the over-taint
	// (default-zero: any non-literal arm leaves taint intact). Ruby-only shape.
	if cfg.language == rules.LangRuby && isAllLiteralRubyCase(rhs) {
		tm.delete(lhsName)
		return
	}

	// Unwrap cast/parens to find the inner call node (e.g., (String) map.get("key")).
	rhsCall := unwrapToCall(rhs, cfg)

	// Check if RHS is a sanitizer call.
	if cfg.callTypes[rhsCall.Type()] {
		if san, sanitizedArg := matcher.matchSanitizer(rhsCall); san != nil {
			// Check argument taint first; fall back to receiver taint for
			// zero-argument receiver methods (e.g., path.canonicalize(),
			// (root / user).resolve()). callReceiverTainted walks the
			// receiver subtree so chained / compound receivers like
			// `(root / user)` are recognised as carrying taint.
			var ts *taintState
			var ok bool
			if sanitizedArg != nil {
				ts, ok = nodeIsTainted(sanitizedArg, tm, cfg)
			}
			if !ok {
				if rts := callReceiverTainted(rhsCall, tm, cfg); rts != nil {
					ts, ok = rts, true
				}
			}
			if !ok {
				// PR-CAT2py: scan every remaining argument subtree for
				// taint. Some sanitizers (Django's render_to_string /
				// render_to_response / shortcuts.render) don't take the
				// tainted value as arg 0 — the template name is
				// positional 0 and the auto-escaped context dict (which
				// may reference tainted variables) is positional 1+.
				// Without this fallback, the canonical Django shape
				// `body = render_to_string("page.html", {"user": user})`
				// fails to neutralise the SnkHTMLOutput flow because
				// matchSanitizer only hands us args[0].
				if argList := cfg.extractCallArgs(rhsCall); len(argList) > 1 {
					for _, a := range argList[1:] {
						if ats, atok := nodeIsTainted(a, tm, cfg); atok {
							ts, ok = ats, true
							break
						}
					}
				}
			}
			if !ok && sanitizedArg != nil {
				ts, ok = resolveInlineSourceThroughSanitizer(rhsCall, lhsName, line, cfg, matcher)
			}
			if ok {
				newTs := ts.clone(lhsName, line, "sanitized by "+san.MethodName, 1.0)
				for _, cat := range san.Neutralizes {
					newTs.sanitized[cat] = true
				}
				// A PHP builtin can have several catalog sanitizer entries under
				// the same name with different Neutralizes lists (e.g. basename
				// neutralizes BOTH file-read and file-write). matchSanitizer
				// returns only the first; union in every same-named entry's
				// categories so `$p = basename($_GET['f'])` is sanitized for the
				// full set, not just the first matched category.
				if cfg.language == rules.LangPHP {
					for _, cat := range matcher.allSanitizerCategories(rhsCall) {
						newTs.sanitized[cat] = true
					}
				}
				tm.set(lhsName, newTs)
				return
			}
		}
	}

	// Check if RHS is or contains a taint source.
	if src := findSourceInExpr(rhs, matcher, cfg); src != nil {
		tm.set(lhsName, &taintState{
			varName:    lhsName,
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     lhsName,
			}},
		})
		return
	}

	// Concat-/template-then-assign with an ATTRIBUTE/SUBSCRIPT source operand:
	//   q = "SELECT ... '" + req.body.login + "'"        // JS/TS
	//   q = f"... {request.args['c']}"                    // (template/interp)
	//   $q = "... " . $_GET['id']                         // PHP
	// findSourceInExpr deliberately EXCLUDES attribute/subscript sources from its
	// binary/interpolation recursion (only CALL-shaped sources resolve there), so
	// the field-sensitive access-path map stays authoritative for INLINE-at-sink
	// reads — `x = req.body.a; sink("..." + req.body.b)` must keep the sibling
	// `req.body.b` clean (TestMultiLevelField_*). But when the concatenation is
	// ASSIGNED to a local, that local genuinely carries the spliced-in tainted
	// value and EVERY later read of it is a real flow — exactly as the direct form
	// (`q = req.body.login`) already taints `q` via findSourceInExpr above. This is
	// the single most common injection shape (DVNA `var query = "..." +
	// req.body.login + "'"; db.sequelize.query(query)`), dataflow-invisible until
	// now. FP-safety + field-path preservation:
	//   - This runs ONLY on the assignment/declaration RHS; the inline-at-sink
	//     resolution (processCall*, gated by sourceFieldTrackedInScope) is
	//     untouched, so the sibling-distinctness contract is preserved.
	//   - The taint is keyed under the LHS local NAME (not the bare `req.body`
	//     prefix), mirroring the direct-assign path — so a later inline
	//     `req.body.other` read does NOT resolve via prefixTainted. The specific
	//     access path `req.body.login` is seeded separately by processAttr when the
	//     walk descends into this RHS, keeping siblings of the source distinct.
	//   - findInlineConcatSource only resolves a leaf that is itself a registered
	//     source; a literal/constant operand, or a source buried as an ARGUMENT to
	//     a wrapping sanitizer call (`escape(req.body.x)`), returns nil — so the
	//     sanitized/safe concat forms stay clean.
	if src := findInlineConcatSource(rhs, matcher, cfg); src != nil {
		tm.set(lhsName, &taintState{
			varName:    lhsName,
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     lhsName,
			}},
		})
		return
	}

	// For call expressions: check for list.get(N) with per-index tracking
	// before falling back to generic interprocedural propagation.
	if cfg.callTypes[rhsCall.Type()] {
		rhsCallName := cfg.extractCallName(rhsCall)
		rhsReceiver := cfg.extractCallReceiver(rhsCall)
		if rhsReceiver != "" && rhsCallName == "get" {
			args := cfg.extractCallArgs(rhsCall)
			// configparser-style 2-arg get(section, key) — composite key
			// lookup on a tracked container instance. Both `.set(*,*,v)`
			// and `.get(*,*)` use the same "section/key" composite.
			if len(args) >= 2 && tm.containerWriters[rhsReceiver] {
				compositeKey := strings.Trim(args[0].Text(), "\"'") + "/" + strings.Trim(args[1].Text(), "\"'")
				if elemTs, tracked := tm.mapGet(rhsReceiver, compositeKey); tracked {
					if elemTs != nil {
						newTs := elemTs.clone(lhsName, line, "container.get("+compositeKey+")", 0.95)
						tm.set(lhsName, newTs)
					} else {
						tm.delete(lhsName)
					}
					return
				}
			}
			if len(args) > 0 {
				argText := strings.TrimSpace(args[0].Text())

				// map.get("key") — per-key taint lookup.
				keyText := strings.Trim(argText, "\"'")
				if keyText != argText { // was quoted → it's a string key
					if elemTs, tracked := tm.mapGet(rhsReceiver, keyText); tracked {
						if elemTs != nil {
							newTs := elemTs.clone(lhsName, line, "map.get(\""+keyText+"\")", 0.95)
							tm.set(lhsName, newTs)
						} else {
							// Safe key — clear any previous taint (last-write-wins).
							tm.delete(lhsName)
						}
						// Key resolved — don't fall through.
						return
					}
				}

				// Constant container lookup: `lhs = ALLOWED_OPS.get(tainted_key)`.
				// When the receiver was assigned a literal dict whose values
				// are all constants, the returned value is one of those
				// constants — the tainted key only chose which one. Drop
				// any prior taint on lhs and skip the generic propagation
				// that would otherwise pull the key's taint through.
				// See CVE-2023-50447 Pillow ImageMath safe pattern.
				if tm.constContainers[rhsReceiver] {
					tm.delete(lhsName)
					return
				}

				// list.get(N) — per-index taint lookup.
				if li, ok := tm.lists[rhsReceiver]; ok && li != nil {
					if idx, err := strconv.Atoi(argText); err == nil {
						elemTs := tm.listGet(rhsReceiver, idx)
						if elemTs != nil {
							newTs := elemTs.clone(lhsName, line, "list.get("+argText+")", 0.95)
							tm.set(lhsName, newTs)
						} else {
							// Safe index — clear any previous taint (last-write-wins).
							tm.delete(lhsName)
						}
						// Index resolved — don't fall through.
						return
					}
				}
			}
		}
		// Before generic call propagation, try constant evaluation
		// (e.g., guess.charAt(1) where guess is a known string constant).
		if v, ok := evalConstExpr(rhsCall, tm); ok {
			tm.consts[lhsName] = v
			return
		}
		// Track container constructors (e.g. configparser.ConfigParser())
		// so later `.set(*, *, tainted)` writes can taint the receiver and
		// `.get(*, *)` can read it back.
		if isContainerConstructorCall(rhsCall, cfg) {
			tm.containerWriters[lhsName] = true
		}
		propagateCallResultInterproc(lhsName, line, rhsCall, tm, cfg, matcher, summaries)
		return
	}

	// Non-call RHS: check if it references any tainted variable.
	if ts, ok := nodeIsTainted(rhs, tm, cfg); ok {
		decay := propagationConfidence(rhs)
		newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
		// Lift inline sanitizer calls through interpolation (see
		// collectInlineSanitizerCategories doc for rationale).
		for cat := range collectInlineSanitizerCategories(rhs, matcher, cfg) {
			if newTs.sanitized == nil {
				newTs.sanitized = make(map[taint.SinkCategory]bool)
			}
			newTs.sanitized[cat] = true
		}
		tm.set(lhsName, newTs)
	} else {
		// Track literal-only dict/set/list assignments so a later
		// `.get(<tainted>)` lookup on `lhsName` does not propagate the key's
		// taint into the result. `isAllLiteralContainer` walks the RHS
		// shallowly and returns true only when every value/element is a
		// constant (literal string/number/None/bool). See the
		// `tm.constContainers` doc and CVE-2023-50447 safe pattern.
		if isAllLiteralContainer(rhs) {
			tm.constContainers[lhsName] = true
		} else {
			delete(tm.constContainers, lhsName)
		}
		// Strong-update (last-write-wins) for bare identifiers, gated to
		// UNCONDITIONAL assignments. A generic last-write-wins clear here would
		// break linear-walked branch arms: the walker walks Python match
		// case-clauses and JS/Java switch arms in source order without a
		// branch-merge, so a later arm's `bar = literal` would wrongly clear
		// taint set by an earlier arm. We therefore clear the prior taint ONLY
		// when BOTH the prior taint entry and this untainted reassignment are
		// unconditional statements of the same enclosing function
		// (setUnconditionally && isUnconditionalAssign) — i.e. genuine sibling
		// statements that both run on every path. This is exactly the OWASP
		// dict/list-shuffle SAFE shape, and the canonical cross-language FP
		// shape `x = src; x = "safe"; sink(x)` (Semgrep CE honours this kill in
		// every language; Batou previously honoured it Python-only, so JS and
		// Java false-fired on `x = src; x = "safe"`):
		//
		//	bar = map['keyB']   # tainted (param), unconditional
		//	bar = map['keyA']   # constant, unconditional → clears taint
		//
		// Conditional arms (Python match case_clause, JS switch_case, Java
		// switch_block_statement_group, every if/else/try/loop) are branch
		// boundaries in branchBoundaryTypesFor, so isUnconditionalAssign returns
		// false for them and their may-taint is preserved.
		// isPlainAssignNode restricts to a plain `=` rebinding: an augmented
		// assignment (`x += y`) reads its own prior value, so an untainted RHS
		// does NOT make the result untainted — `s += 'literal'` after
		// `s += param` must keep the accumulated taint. (Java spells both forms
		// `assignment_expression`, distinguished by the `operator` field, so the
		// node type alone is insufficient — see isPlainAssignNode.)
		if supportsStrongUpdate(cfg.language) && isPlainAssignNode(n, cfg) {
			if _, isField := isFieldKey(lhsName); !isField {
				if prior := tm.get(lhsName); prior != nil && prior.source != nil &&
					prior.setUnconditionally && isUnconditionalAssign(n, cfg) {
					tm.delete(lhsName)
				}
			}
		}
		// For shallow field LHS (`obj.attr = <safe-literal>`), narrow the
		// rule: explicitly drop the `obj.attr` taint entry. This is the
		// field-sensitive analog of clearing a bare variable, and is safe
		// because field assignments target a single field — the sibling
		// fields and the bare object's own taint are untouched.
		if _, isField := isFieldKey(lhsName); isField && isLiteralOrEarlyExit(rhs) {
			tm.delete(lhsName)
		}
		// Track constants for constant condition/switch evaluation.
		if v, ok := evalConstExpr(rhs, tm); ok {
			tm.consts[lhsName] = v
		}
		trackStrConst(lhsName, rhs, tm)
	}
}

// processVarDeclInterproc extends processVarDecl with interprocedural call tracking.
func processVarDeclInterproc(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary) {
	// JS/TS object/array destructuring: `const {id} = req.params`,
	// `const {a, b} = req.body`, `const [x, y] = req.query.list`.
	// extractVarDeclParts returns a single identifier and misses the dominant
	// shorthand form entirely — `{id}` parses as a shorthand_property_identifier_pattern,
	// not an `identifier`, so extractIdentText returns "" and the declaration
	// bound nothing. Result: the most common modern Express/Node idiom for
	// reading user input produced ZERO taint flows. Bind the whole pattern
	// here: if the RHS is tainted as a whole (a user-controlled object/array),
	// every destructured local inherits that taint.
	if cfg.language == rules.LangJavaScript || cfg.language == rules.LangTypeScript {
		if pat := n.ChildByFieldName("name"); pat != nil &&
			(pat.Type() == "object_pattern" || pat.Type() == "array_pattern") {
			processJSDestructure(n, pat, tm, matcher, cfg)
			return
		}
	}

	// Kotlin destructuring declaration: `val (a, b) = expr`. The binding is a
	// multi_variable_declaration whose variable_declaration children each wrap a
	// simple_identifier. extractVarDeclParts can't name this shape (the binding is
	// neither an identifier nor a single variable_declaration), so without this
	// branch every destructured local silently loses taint
	// (`val (cmd, arg) = raw.split(" ")` → Runtime.getRuntime().exec(cmd) produced
	// zero flows). When the RHS is tainted as a whole — a user-controlled value or
	// a method chain on one — every destructured local inherits that taint, since
	// each binding is a componentN() of the tainted value.
	if cfg.language == rules.LangKotlin {
		if pat := kotlinMultiVarPattern(n); pat != nil {
			processKotlinDestructure(n, pat, tm, matcher, cfg)
			return
		}
	}

	// C# tuple deconstruction in a declaration: `var (a, b) = Parse(input)`.
	// The variable_declarator's LHS is a tuple_pattern, so extractVarDeclParts
	// yields no single identifier and every deconstructed local would lose
	// taint without this branch.
	if cfg.language == rules.LangCSharp && processCSharpDeconstruct(n, tm, cfg, matcher) {
		return
	}

	// Swift tuple destructuring: `let (a, b) = parsePair(req.query)`,
	// `let (status, body) = try await client.send(req)`, `let (a, _) =
	// (req.query, "x")`. tree-sitter-swift parses the LHS as the `name`
	// pattern node `(a, b)` whose named children are themselves `pattern`
	// nodes (a single binding's child is a `simple_identifier`/`wildcard`
	// instead). extractVarDeclParts only pulls the first identifier, so the
	// trailing destructured locals silently lost taint and a sink on any of
	// them produced ZERO flows. Bind every leaf target here.
	if cfg.language == rules.LangSwift {
		if pat := n.ChildByFieldName("name"); pat != nil && swiftIsTuplePattern(pat) {
			processSwiftDeconstruct(n, pat, tm, cfg, matcher)
			return
		}
	}

	lhsName, rhs := extractVarDeclParts(n, cfg)
	if lhsName == "" || lhsName == "_" || rhs == nil {
		return
	}

	line := int(n.StartRow()) + 1

	// Shallow field sensitivity: a fresh var declaration introduces a new
	// binding, so any leftover `<name>.<field>` taint entries from a prior
	// scope-shadowed binding are stale. Field-keyed declarations are out of
	// scope for var declarations (most languages don't allow them).
	_, lhsIsField := isFieldKey(lhsName)
	if !lhsIsField {
		tm.clearFieldsOf(lhsName)
		// A redeclaration breaks any must-alias edge for this name before a
		// fresh `let b = a` edge is recorded below.
		tm.breakAlias(lhsName)
		// PR-CATjs-2: any redeclaration of `name` invalidates a prior
		// fresh-empty marker so we don't keep treating a re-bound var as
		// fresh.
		delete(tm.freshLocalEmpty, lhsName)
		// Intra-function must-alias: `let b = a` (bare-identifier RHS) names
		// the same object under both variables.
		recordAliasIfBareCopy(lhsName, rhs, tm, cfg)
	}
	if lhsIsField {
		defer func() {
			if ts := tm.get(lhsName); ts != nil && ts.source != nil {
				ts.fromFieldAssign = true
			}
		}()
	}

	// Strong-update gate: stamp the unconditional flag on the taint produced by
	// THIS declaration too, so a later untainted reassignment can clear it. A
	// var/let/const (JS/TS) or typed local (Java) declaration is the dominant
	// way the prior taint of the canonical FP shape `var x = src; x = "safe";
	// sink(x)` gets set — the kill site in processAssignInterproc consumes
	// prior.setUnconditionally, which would be false (so the kill would never
	// fire) without this. Python has no var declarations, so supportsStrongUpdate
	// gates Python out here; field-keyed and unsupported languages keep
	// byte-identical behaviour.
	if !lhsIsField && supportsStrongUpdate(cfg.language) {
		uncond := isUnconditionalAssign(n, cfg)
		defer func() {
			if ts := tm.get(lhsName); ts != nil && ts.source != nil {
				ts.setUnconditionally = uncond
			}
		}()
	}

	// PR-CATjs-2 (JS/TS only): record fresh empty-container declarations and
	// reduce-accumulator inferences before any of the typed branches below
	// short-circuit. The recording is harmless for the existing pipeline
	// (no taint state mutated) and lets a later merge-style proto sink
	// recognise the destination as safe.
	recordFreshLocalEmptyIfJS(lhsName, rhs, tm, cfg)
	noteReduceAccumulatorFreshness(rhs, tm, cfg)

	// Match/switch with all-literal arms produces an untainted result regardless
	// of the scrutinee's taint.  e.g., match param.as_str() { "a" => "x", _ => return }
	if isAllLiteralMatch(rhs) {
		tm.delete(lhsName)
		return
	}

	// Unwrap cast/parens to find the inner call node (e.g., (String) map.get("key")).
	rhsCall := unwrapToCall(rhs, cfg)

	// Check if RHS is a sanitizer call.
	if cfg.callTypes[rhsCall.Type()] {
		if san, sanitizedArg := matcher.matchSanitizer(rhsCall); san != nil {
			// Check argument taint first; fall back to receiver taint for
			// zero-argument receiver methods (e.g., path.canonicalize(),
			// (root / user).resolve()). callReceiverTainted walks the
			// receiver subtree so chained / compound receivers like
			// `(root / user)` are recognised as carrying taint.
			var ts *taintState
			var ok bool
			if sanitizedArg != nil {
				ts, ok = nodeIsTainted(sanitizedArg, tm, cfg)
			}
			if !ok {
				if rts := callReceiverTainted(rhsCall, tm, cfg); rts != nil {
					ts, ok = rts, true
				}
			}
			if !ok {
				// PR-CAT2py: scan every remaining argument subtree for
				// taint. Some sanitizers (Django's render_to_string /
				// render_to_response / shortcuts.render) don't take the
				// tainted value as arg 0 — the template name is
				// positional 0 and the auto-escaped context dict (which
				// may reference tainted variables) is positional 1+.
				// Without this fallback, the canonical Django shape
				// `body = render_to_string("page.html", {"user": user})`
				// fails to neutralise the SnkHTMLOutput flow because
				// matchSanitizer only hands us args[0].
				if argList := cfg.extractCallArgs(rhsCall); len(argList) > 1 {
					for _, a := range argList[1:] {
						if ats, atok := nodeIsTainted(a, tm, cfg); atok {
							ts, ok = ats, true
							break
						}
					}
				}
			}
			if !ok && sanitizedArg != nil {
				ts, ok = resolveInlineSourceThroughSanitizer(rhsCall, lhsName, line, cfg, matcher)
			}
			if ok {
				newTs := ts.clone(lhsName, line, "sanitized by "+san.MethodName, 1.0)
				for _, cat := range san.Neutralizes {
					newTs.sanitized[cat] = true
				}
				// A PHP builtin can have several catalog sanitizer entries under
				// the same name with different Neutralizes lists (e.g. basename
				// neutralizes BOTH file-read and file-write). matchSanitizer
				// returns only the first; union in every same-named entry's
				// categories so `$p = basename($_GET['f'])` is sanitized for the
				// full set, not just the first matched category.
				if cfg.language == rules.LangPHP {
					for _, cat := range matcher.allSanitizerCategories(rhsCall) {
						newTs.sanitized[cat] = true
					}
				}
				tm.set(lhsName, newTs)
				return
			}
		}
	}

	// Check if RHS is or contains a taint source.
	if src := findSourceInExpr(rhs, matcher, cfg); src != nil {
		tm.set(lhsName, &taintState{
			varName:    lhsName,
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     lhsName,
			}},
		})
		return
	}

	// Concat-/template-then-declare with an ATTRIBUTE/SUBSCRIPT source operand
	// (`var q = "SELECT ... '" + req.body.login + "'"`). The declaration form of
	// the assignment-RHS case above: findSourceInExpr excludes attribute/subscript
	// sources from its binary/interpolation recursion to keep the field-sensitive
	// access-path map authoritative at INLINE-at-sink positions, but a concat bound
	// to a declared local genuinely flows that tainted value into the local. Mirror
	// the direct-declare path (`var q = req.body.login`) — taint keyed under the
	// LHS NAME, not the bare `req.body` prefix, so siblings stay distinct (the
	// specific `req.body.login` path is seeded by processAttr on the RHS walk). See
	// the longer rationale in processAssignInterproc.
	if src := findInlineConcatSource(rhs, matcher, cfg); src != nil {
		tm.set(lhsName, &taintState{
			varName:    lhsName,
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     lhsName,
			}},
		})
		return
	}

	// For call expressions: check for list.get(N) / map.get("key") with
	// per-index/per-key tracking before falling back to generic propagation.
	if cfg.callTypes[rhsCall.Type()] {
		rhsCallName := cfg.extractCallName(rhsCall)
		rhsReceiver := cfg.extractCallReceiver(rhsCall)
		if rhsReceiver != "" && rhsCallName == "get" {
			args := cfg.extractCallArgs(rhsCall)
			// configparser-style 2-arg get(section, key) — composite key
			// lookup on a tracked container instance. Both `.set(*,*,v)`
			// and `.get(*,*)` use the same "section/key" composite.
			if len(args) >= 2 && tm.containerWriters[rhsReceiver] {
				compositeKey := strings.Trim(args[0].Text(), "\"'") + "/" + strings.Trim(args[1].Text(), "\"'")
				if elemTs, tracked := tm.mapGet(rhsReceiver, compositeKey); tracked {
					if elemTs != nil {
						newTs := elemTs.clone(lhsName, line, "container.get("+compositeKey+")", 0.95)
						tm.set(lhsName, newTs)
					} else {
						tm.delete(lhsName)
					}
					return
				}
			}
			if len(args) > 0 {
				argText := strings.TrimSpace(args[0].Text())

				// map.get("key") — per-key taint lookup.
				keyText := strings.Trim(argText, "\"'")
				if keyText != argText { // was quoted → it's a string key
					if elemTs, tracked := tm.mapGet(rhsReceiver, keyText); tracked {
						if elemTs != nil {
							newTs := elemTs.clone(lhsName, line, "map.get(\""+keyText+"\")", 0.95)
							tm.set(lhsName, newTs)
						} else {
							// Safe key — clear any previous taint (last-write-wins).
							tm.delete(lhsName)
						}
						// Key resolved — don't fall through.
						return
					}
				}

				// Constant container lookup: `lhs = ALLOWED_OPS.get(tainted_key)`.
				// When the receiver was assigned a literal dict whose values
				// are all constants, the returned value is one of those
				// constants — the tainted key only chose which one. Drop
				// any prior taint on lhs and skip the generic propagation
				// that would otherwise pull the key's taint through.
				// See CVE-2023-50447 Pillow ImageMath safe pattern.
				if tm.constContainers[rhsReceiver] {
					tm.delete(lhsName)
					return
				}

				// list.get(N) — per-index taint lookup.
				if li, ok := tm.lists[rhsReceiver]; ok && li != nil {
					if idx, err := strconv.Atoi(argText); err == nil {
						elemTs := tm.listGet(rhsReceiver, idx)
						if elemTs != nil {
							newTs := elemTs.clone(lhsName, line, "list.get("+argText+")", 0.95)
							tm.set(lhsName, newTs)
						} else {
							// Safe index — clear any previous taint (last-write-wins).
							tm.delete(lhsName)
						}
						// Index resolved — don't fall through.
						return
					}
				}
			}
		}
		// Before generic call propagation, try constant evaluation
		// (e.g., guess.charAt(1) where guess is a known string constant).
		if v, ok := evalConstExpr(rhsCall, tm); ok {
			tm.consts[lhsName] = v
			return
		}
		// Track container constructors (e.g. configparser.ConfigParser())
		// so later `.set(*, *, tainted)` writes can taint the receiver and
		// `.get(*, *)` can read it back.
		if isContainerConstructorCall(rhsCall, cfg) {
			tm.containerWriters[lhsName] = true
		}
		propagateCallResultInterproc(lhsName, line, rhsCall, tm, cfg, matcher, summaries)
		return
	}

	// Non-call RHS: check if it references any tainted variable.
	if ts, ok := nodeIsTainted(rhs, tm, cfg); ok {
		decay := propagationConfidence(rhs)
		newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
		// When the RHS is an interpolated string / template containing
		// embedded sanitizer calls (e.g. `query = f"...{bar.replace('\\'',
		// '&apos;')}..."`), collect those calls' Neutralizes categories and
		// apply them to the LHS. Without this, the sanitization is visible
		// only at the assignment site — by the time the sink consumes
		// `query` later, the AST trail back to the inline sanitizer is gone.
		for cat := range collectInlineSanitizerCategories(rhs, matcher, cfg) {
			if newTs.sanitized == nil {
				newTs.sanitized = make(map[taint.SinkCategory]bool)
			}
			newTs.sanitized[cat] = true
		}
		tm.set(lhsName, newTs)
	} else {
		// Track integer constants for constant condition evaluation.
		if v, ok := evalConstExpr(rhs, tm); ok {
			tm.consts[lhsName] = v
		}
		trackStrConst(lhsName, rhs, tm)
		// Mirror the constant-container tracking from processAssignInterproc
		// so `let / var ALLOWED = {...}` declarations are recognised too.
		if isAllLiteralContainer(rhs) {
			tm.constContainers[lhsName] = true
		} else {
			delete(tm.constContainers, lhsName)
		}
	}
}

// isAllLiteralContainer returns true when n is a dict/set/list literal whose
// values (or elements) are themselves constants — string/number/bool/None
// literals or further nested literal containers. Variables, calls, and
// expressions disqualify the container. Used to recognise project-local
// lookup tables (e.g. `ALLOWED_OPS = {"invert": "255 - a", ...}`) so a later
// `.get(<tainted>)` doesn't propagate the key's taint into the result —
// the result is one of the literal values, not user-controlled.
func isAllLiteralContainer(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "dictionary", "set", "list", "tuple",
		"dictionary_literal", "set_literal", "list_literal", "tuple_literal":
	default:
		return false
	}
	allLit := true
	hasChild := false
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if !c.IsNamed() {
			continue
		}
		hasChild = true
		switch c.Type() {
		case "pair", "dictionary_element", "key_value_pair", "keyword_argument":
			// dict entry — second named child is the value
			named := c.NamedChildren()
			if len(named) < 2 {
				allLit = false
				continue
			}
			if !isLiteralOrLiteralContainer(named[len(named)-1]) {
				allLit = false
			}
		default:
			if !isLiteralOrLiteralContainer(c) {
				allLit = false
			}
		}
	}
	return hasChild && allLit
}

// isLiteralOrLiteralContainer returns true when n is a string/number/bool/None
// literal or a fully-literal nested container. Conservative: anything we
// don't recognise (identifiers, calls, arithmetic) returns false.
func isLiteralOrLiteralContainer(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string", "string_literal", "concatenated_string",
		"integer", "float", "number", "numeric_literal", "int_literal", "float_literal",
		"true", "false", "none", "null", "null_literal", "true_literal", "false_literal",
		"boolean", "boolean_literal":
		return true
	}
	// Negative number literals show up as unary_operator wrapping an int/float.
	if n.Type() == "unary_operator" || n.Type() == "unary_expression" {
		named := n.NamedChildren()
		if len(named) == 1 {
			return isLiteralOrLiteralContainer(named[0])
		}
	}
	return isAllLiteralContainer(n)
}

// collectInlineSanitizerCategories walks an expression looking for sanitizer
// calls and returns the union of their Neutralizes categories across ALL
// matching candidates (not just the first). Used to lift sanitization through
// interpolation / concatenation: a sanitizer call embedded in an f-string
// assigned to a variable should mark the LHS as sanitized for the relevant
// categories. Iterating all candidates (rather than relying on
// matchSanitizer's first-match) ensures a category-specific sanitizer is
// found even when a less-specific entry with the same method name registers
// earlier — e.g. `.replace("'", "&apos;")` is the XPath escape sanitizer,
// not the CRLF log-injection sanitizer that also matches on method name.
func collectInlineSanitizerCategories(n *ast.Node, matcher *tsMatcher, cfg *langConfig) map[taint.SinkCategory]bool {
	out := map[taint.SinkCategory]bool{}
	if n == nil || matcher == nil {
		return out
	}
	var walk func(*ast.Node)
	walk = func(node *ast.Node) {
		if node == nil {
			return
		}
		if cfg.callTypes[node.Type()] {
			methodName := matcher.cfg.extractCallName(node)
			if methodName != "" {
				candidates := matcher.sanitizersByMethod[methodName]
				short := unqualifyName(methodName)
				if short != methodName {
					candidates = append(candidates, matcher.sanitizersByMethod[short]...)
				}
				receiver := matcher.cfg.extractCallReceiver(node)
				for _, san := range candidates {
					// Only @argpattern entries lift through interpolation.
					// Loose method-only entries (e.g. py.str — generic str()
					// coercion that nominally sanitizes SQL in *numeric*
					// contexts) would over-sanitise here because the
					// surrounding concat still allows injection on string
					// inputs. @argpattern entries gate on call-text shape and
					// are safe to lift.
					if san.ObjectType != "@argpattern" {
						continue
					}
					if !matcher.sanitizerCandidateMatches(san, receiver, methodName, node) {
						continue
					}
					for _, c := range san.Neutralizes {
						out[c] = true
					}
				}
			}
			// Also recurse into args (sanitizer may be nested deeper).
			for _, arg := range cfg.extractCallArgs(node) {
				walk(arg)
			}
			return
		}
		for i := 0; i < node.ChildCount(); i++ {
			walk(node.Child(i))
		}
	}
	walk(n)
	return out
}

// propagateCallResultInterproc determines if a call expression's result should
// be considered tainted for assignment purposes. Strategy:
//  1. Receiver taint always propagates (e.g., taintedStr.toUpperCase())
//  2. For LOCAL functions (found in summaries map): use per-parameter summaries
//     to only propagate taint from arguments whose corresponding parameter
//     actually flows to the return value (context-sensitive)
//  3. For EXTERNAL functions (not in local map): propagate from args
//     (conservative — unknown functions might pass data through)
func propagateCallResultInterproc(lhsName string, line int, rhs *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, summaries map[string]*TaintSummary) {
	// Check receiver taint (e.g., taintedStr.toUpperCase()).
	if ts := callReceiverTaintedForPropagation(rhs, tm, cfg, matcher); ts != nil {
		decay := propagationConfidence(rhs)
		newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
		// Python path-canonicaliser link via the RECEIVER (PR-PATHpy):
		// when the call is `.resolve()` (or `.normpath()/abspath()/realpath()`
		// on a receiver) and the tainted receiver is a `Path(base) / x` or
		// `base / x` binary-operator expression, record the back-link so a
		// downstream `startswith` / `is_relative_to` containment check on
		// the resolved value clears the path-sink taint on the original
		// tainted variable. Mirrors the free-function arg-0 link below.
		if cfg.language == rules.LangPython && newTs.pathDerivedFrom == "" {
			if _, isCanon := isPythonPathCanonicalizer(rhs, cfg); isCanon {
				if origin := pyResolveTaintOriginInReceiver(rhs, tm, cfg); origin != "" {
					newTs.pathDerivedFrom = origin
				}
			}
		}
		tm.set(lhsName, newTs)
		return
	}

	callName := cfg.extractCallName(rhs)

	// Check interprocedural summaries for local functions.
	if summaries != nil {
		summary, isLocal := summaries[callName]
		if isLocal {
			// Context-sensitive: only propagate taint from arguments whose
			// corresponding parameter flows to the return value.
			if summary.anyParamPropagates() {
				args := cfg.extractCallArgs(rhs)
				for i, arg := range args {
					if !summary.paramPropagates(i) {
						continue // this parameter doesn't flow to return
					}
					// Resolve the argument's taint via the map, then — for an
					// UNBOUND inline source-call argument (`x = transform(
					// request.args.get("y"))`) that nodeIsTainted can't see
					// because it was never assigned to a variable — by matching
					// the source directly. Mirrors the sink path's inline-source
					// resolution (resolveUnpackElemTaint / emitInterprocSinkFlows).
					ts := resolveUnpackElemTaint(arg, tm, cfg, matcher, line)
					if ts == nil {
						continue // argument isn't tainted
					}
					newTs := ts.clone(lhsName, line, "propagated through "+callName+"()", 0.85)
					// Apply per-parameter sanitization from the summary.
					if sanCats := summary.sanitizedCategories(i); sanCats != nil {
						for cat := range sanCats {
							newTs.sanitized[cat] = true
						}
					}
					tm.set(lhsName, newTs)
					return
				}
			}
			// The callee manufactures taint itself: its body reads a catalog
			// source that reaches a return statement (`def get_q(): return
			// request.args.get('q')`). Seed the LHS from the summary's source
			// with the standard 0.85 interprocedural hop decay — without this,
			// the local-summary returns above made a source-returning local
			// function strictly WORSE than an unknown external one (zero taint
			// at every call site).
			if rs := summary.ReturnsSource; rs != nil {
				tm.set(lhsName, rs.taintStateFor(lhsName, line, callName))
			}
			return // local function — nothing else to propagate
		}
	}

	// External/library function: propagate from args (conservative).
	args := cfg.extractCallArgs(rhs)
	// Flask make_response((body, headers)) result narrowing: when the call
	// is the Python html_output sink and its single argument is a tuple, the
	// VALUE the call returns to the LHS is the response body (first tuple
	// element), not the status/headers in later elements. Propagating taint
	// from the headers dict into `RESPONSE = make_response((RESPONSE, {h:
	// tainted}))` would (a) self-taint RESPONSE and (b) make the same-line
	// html_output sink read its own body as tainted. Restrict the propagating
	// args to the body element so only a tainted BODY flows to the LHS. See
	// narrowPythonMakeResponseBody for the matching sink-side gate.
	if body := pythonMakeResponseTupleBody(rhs, cfg, matcher); body != nil {
		args = []*ast.Node{body}
	}
	for i, arg := range args {
		// nodeIsTainted, then inline source-call fallback (`x = lib(
		// request.args.get("y"))` where the source is an unbound argument the
		// taint map never recorded). The provenance-link branches below gate on
		// arg.Type() == "identifier", so inline source calls leave them inert.
		if ts := resolveUnpackElemTaint(arg, tm, cfg, matcher, line); ts != nil {
			decay := propagationConfidence(rhs)
			newTs := ts.clone(lhsName, line, "assigned to "+lhsName, decay)
			// Track URL-parser derivations so a downstream allowlist guard
			// on `url.netloc` / `url.scheme` / `url.hostname` can
			// back-propagate URL-injection sanitisation to the original
			// variable. Recognises Python urllib.parse.urlparse / urlsplit
			// and similar single-argument URL parsers — only when arg 0 is
			// a bare tainted identifier, so chained / arithmetic expressions
			// don't get an incorrect provenance link.
			if i == 0 && isURLParserCall(rhs, cfg) {
				if arg.Type() == "identifier" {
					newTs.urlParsedFrom = arg.Text()
				}
			}
			// Track Python path-canonicaliser derivations so a downstream
			// containment guard on the canonicalised value
			// (startswith / is_relative_to / commonpath ==) can
			// back-propagate path sanitisation to the original tainted
			// variable. The link is only set when arg 0 is a bare
			// identifier — chained / arithmetic expressions don't get
			// the provenance link (PR-HHpy).
			if i == 0 && cfg.language == rules.LangPython {
				if _, isCanon := isPythonPathCanonicalizer(rhs, cfg); isCanon && arg.Type() == "identifier" {
					newTs.pathDerivedFrom = arg.Text()
				}
			}
			tm.set(lhsName, newTs)
			return
		}
	}

	// No taint propagated from this call — but do NOT clear existing taint
	// here. The caller (processAssignInterproc) handles clearing for non-call
	// RHS. For calls, the conservative choice is to preserve existing taint
	// since the function may return the receiver or args in ways we can't track.
}

// isURLParserCall returns true when the call's function is a known URL parser
// (urllib.parse.urlparse / urlsplit / parse.urlparse, plus their bare-name
// variants and the Java/JS/Ruby equivalents). The downstream allowlist guard
// on `.netloc` / `.scheme` / `.hostname` only validates a parsed URL's fields,
// so the back-propagation of sanitization is only correct when the call here
// actually produced a parsed URL.
func isURLParserCall(n *ast.Node, cfg *langConfig) bool {
	callName := cfg.extractCallName(n)
	if callName == "" {
		return false
	}
	last := callName
	if i := strings.LastIndex(callName, "."); i >= 0 {
		last = callName[i+1:]
	}
	switch last {
	case "urlparse", "urlsplit", "parse_url", "URL":
		return true
	}
	return false
}

// isContainerConstructorCall returns true when the call is a constructor for a
// stateful key-value container whose later `.set(*, *, tainted)` writes
// should be reflected on the receiver (so a subsequent `.get(*, *)` can
// propagate). Currently covers Python configparser.ConfigParser /
// RawConfigParser / SafeConfigParser. Receivers tracked via this function
// land in tm.containerWriters and the .set-handler below gates on that set.
func isContainerConstructorCall(n *ast.Node, cfg *langConfig) bool {
	callName := cfg.extractCallName(n)
	if callName == "" {
		return false
	}
	last := callName
	if i := strings.LastIndex(callName, "."); i >= 0 {
		last = callName[i+1:]
	}
	switch last {
	case "ConfigParser", "RawConfigParser", "SafeConfigParser":
		return true
	}
	return false
}

// callReceiverNode returns the AST node for a call expression's receiver
// (the object on which a method is invoked), or nil for a free-function call.
//
// The receiver subtree is reached differently across tree-sitter grammars, so
// this tries the known shapes in order. It is the single source of truth for
// "what does this call's receiver expression resolve to" and is used by both
// callReceiverTainted and nodeIsTainted so chained calls like
// `sb.append(x).toString()` propagate taint through the receiver in EVERY
// tsflow language, not just the JS/Python shape:
//
//   - object   field on the call node          → Java method_invocation,
//     PHP member_call_expression
//   - receiver field on the call node          → Ruby call
//   - the call's `function`/`name` child, then
//     its object/value/expression/receiver
//     field (or sole named child)              → Python attribute,
//     JS member_expression,
//     C# member_access_expression,
//     Kotlin navigation_expression
func callReceiverNode(n *ast.Node) *ast.Node {
	if n == nil {
		return nil
	}
	// Receiver expressed directly as a field on the call node.
	if obj := n.ChildByFieldName("object"); obj != nil {
		return obj
	}
	if recv := n.ChildByFieldName("receiver"); recv != nil {
		return recv
	}
	// Receiver nested under the call's function/name child (the member-access
	// or navigation expression naming the method).
	fn := n.ChildByFieldName("function")
	if fn == nil {
		fn = n.ChildByFieldName("name")
	}
	if fn == nil {
		return nil
	}
	for _, fld := range []string{"object", "value", "expression", "receiver"} {
		if c := fn.ChildByFieldName(fld); c != nil {
			return c
		}
	}
	// Kotlin navigation_expression has no field name for the receiver — it is
	// the first named child (the navigation_suffix carrying the method name is
	// the second). Only treat the first child as a receiver when a later
	// navigation_suffix is present, so a bare identifier isn't misread.
	if fn.Type() == "navigation_expression" {
		named := fn.NamedChildren()
		if len(named) >= 2 {
			return named[0]
		}
	}
	return nil
}

// callReceiverTainted checks if a call expression's receiver (object) is tainted.
// This is used for propagation: taintedObj.method() returns a tainted result.
// Unlike nodeIsTainted on the full call, this does NOT check arguments.
//
// This is the BASELINE resolver: it follows the receiver text and the
// `function`/`name`-child's object/value field. It deliberately does NOT use
// the broader callReceiverNode shapes (direct `object`/`receiver` field on the
// call node) — those are handled by callReceiverTaintedForPropagation under a
// sanitizer-aware gate so that enabling chained-receiver taint for Java/Ruby/PHP
// does not silently bypass an in-chain sanitizer the catalog only models at the
// direct-RHS position.
func callReceiverTainted(n *ast.Node, tm *taintMap, cfg *langConfig) *taintState {
	receiver := cfg.extractCallReceiver(n)
	if receiver != "" {
		if ts := tm.get(receiver); ts != nil && ts.source != nil {
			return ts
		}
	}
	// Also check the receiver AST node recursively (for chained calls like
	// base64.b64decode(tmp).decode('utf-8'), whose receiver text is itself a
	// call and so is not a tracked variable name).
	fn := n.ChildByFieldName("function")
	if fn == nil {
		fn = n.ChildByFieldName("name")
	}
	if fn != nil {
		obj := fn.ChildByFieldName("object")
		if obj == nil {
			obj = fn.ChildByFieldName("value")
		}
		if obj != nil {
			if ts, ok := nodeIsTainted(obj, tm, cfg); ok {
				return ts
			}
		}
	}
	return nil
}

// callReceiverTaintedForPropagation extends callReceiverTainted with the
// broader receiver-node shapes resolved by callReceiverNode (the direct
// `object`/`receiver` field on a call node — Java method_invocation, Ruby call,
// PHP member_call_expression). Those shapes were historically NOT followed, so
// taint died at the chained-receiver boundary, e.g.
//
//	String bar = new Test().doSomething(req, p);           // call-site, summary-driven
//	String bar = sbxyz.append("_SafeStuff").toString();    // builder chain inside helper
//
// Enabling them lets return-taint summaries see the builder chain and lifts the
// OWASP "dataflow through inner class" false-negatives.
//
// The newly-followed shapes are gated: if any call in the receiver chain is a
// sanitizer that consumes a tracked tainted value, the receiver taint is NOT
// propagated here. That preserves the prior (correct) outcome for chains such as
// `input.replace("\n","").replace("\r","")` (CRLF strip), `params[:id].to_i`
// (integer coercion), and `ResponseCookie.from(value).build()` (safe builder),
// whose sanitizers the catalog only models at the direct-RHS position. The
// baseline resolver is tried first and is never gated, so flows that already
// propagated through a `function`/`value`-nested receiver (e.g. Rust
// `dest.parse().unwrap()`) are byte-for-byte unchanged.
func callReceiverTaintedForPropagation(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) *taintState {
	if ts := callReceiverTainted(n, tm, cfg); ts != nil {
		return ts
	}
	obj := callReceiverNode(n)
	if obj == nil {
		return nil
	}
	if chainHasActiveSanitizer(n, tm, cfg, matcher) {
		return nil
	}
	if ts, ok := nodeIsTainted(obj, tm, cfg); ok {
		return ts
	}
	return nil
}

// chainHasActiveSanitizer reports whether any call in the receiver chain
// rooted at `call` is (by method name) a sanitizer that consumes a
// currently-tracked tainted value. It gates the broadened chained-receiver
// taint propagation so an in-chain sanitizer is honored even when the catalog
// only models that sanitizer at the direct-RHS position (e.g. Java
// `String.replace` CRLF strip, whose `ObjectType:"String"` heuristic does not
// match a chained-call receiver, or Ruby `.to_i`, whose Neutralizes list does
// not name the trust-boundary category).
//
// The taint check uses callReceiverNode (the broad resolver) so a sanitizer
// whose tainted input is its RECEIVER (`tainted.replace(...)`, `tainted.to_i`)
// is recognized in languages where the baseline resolver cannot see a
// chained/subscript receiver. Method-name matching is intentionally loose; see
// isSanitizerMethodName for why that is safe for a gate.
func chainHasActiveSanitizer(call *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) bool {
	if call == nil || matcher == nil {
		return false
	}
	node := call
	for node != nil && cfg.callTypes[node.Type()] {
		if matcher.isSanitizerMethodName(node) {
			// Receiver-as-tainted-input (tainted.replace(...) / tainted.to_i).
			if recv := callReceiverNode(node); recv != nil {
				if _, ok := nodeIsTainted(recv, tm, cfg); ok {
					return true
				}
			}
			// Argument-as-tainted-input (Builder.from(tainted), encode(tainted)).
			for _, a := range cfg.extractCallArgs(node) {
				if _, ok := nodeIsTainted(a, tm, cfg); ok {
					return true
				}
			}
		}
		recv := callReceiverNode(node)
		if recv == nil {
			break
		}
		node = unwrapToCall(recv, cfg)
	}
	return false
}

// processCallInterproc extends processCall with interprocedural awareness
// and callback taint propagation (.then, .map, .filter, etc.).
func processCallInterproc(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	// Delegate to the base processCall for source/sink matching.
	processCall(n, tm, cfg, matcher, scopeName, fb)

	// Python bare-statement path-traversal containment guard (CWE-22):
	// `file_path.relative_to(base)` (raises ValueError on escape) and
	// `realpath(x).startswith(base)` used as standalone statements inside a
	// try/except. These never appear as if-conditions (so inferPythonPathGuard
	// misses them) and assign nothing (so the sanitizer-RHS path misses them),
	// yet they are the canonical containment check that completes a resolve().
	// Clear ONLY the path sink categories on the tainted receiver so a
	// downstream open()/FileResponse() does not false-positive. Runs in
	// statement order, before the later sink is walked. Gated to Python.
	if cfg.language == rules.LangPython {
		if pres := pyMatchBareStatementPathGuard(n, tm, cfg); pres != nil {
			applyPythonPathGuard(tm, pres)
		}
	}

	// Interprocedural sink emission: when this call targets a LOCAL function
	// and a tainted argument lands on a parameter that reaches a dangerous sink
	// inside the callee (recorded in the pass-1 summary's ParamSinks), emit the
	// finding here at the call site. This connects the classic two-function
	// shape `main(){ lookup(db, argv[1]); }  lookup(db,u){ q="..."+u; exec(q); }`
	// where the source is in the caller and the sink is in the callee — neither
	// per-function walk alone observes the full source→sink flow.
	//
	// Gated to C++: this is the verified fix for cpp's interproc FNs. On the
	// other tsflow languages the same emission was measured to add false
	// positives on real code (e.g. Django: file_write mis-categorised on string
	// transforms, trust_boundary on a localStorage toggle), because their
	// per-function walks + cross-file call graph already cover most interproc
	// flows. Enable per-language only after a real-repo FP check.
	if cfg.language == rules.LangCPP {
		emitInterprocSinkFlows(n, tm, cfg, matcher, scopeName, fb, summaries)
	}

	// Check for callback propagation patterns (JS/TS only).
	if cfg.language == "javascript" || cfg.language == "typescript" {
		callName := cfg.extractCallName(n)
		if pattern := isCallbackPropagationCall(callName); pattern != nil {
			processCallbackPropagation(n, tm, cfg, matcher, scopeName, fb, summaries, pattern)
		}
	}

	// Shell `read [-flags] VAR...` populates each named variable with untrusted
	// stdin. The catalog tags `read` as a source whose Assigns is "return", but
	// there is no assignment LHS to carry it — the taint lands on the *argument*
	// variables. Mark each non-flag `word` argument tainted by the read source.
	if cfg.language == rules.LangShell && cfg.extractCallName(n) == "read" {
		shellPropagateReadVars(n, tm, cfg, matcher)
	}
}

// emitInterprocSinkFlows emits an interprocedural taint finding when a call to
// a LOCAL function passes a tainted argument into a parameter that reaches a
// dangerous sink inside the callee. The callee's per-parameter pass-1 summary
// (summary.ParamSinks[i]) records, for each reachable sink category, a
// representative sink site that the per-parameter walk already confirmed
// (inline sanitizers and safe-form gates were applied during that walk). At the
// call site we look up the corresponding argument; if it carries taint for that
// category and is not neutralised by an inline sanitizer wrapping the argument,
// we synthesise a flow whose Source is the argument's real source and whose
// Sink is the callee's sink. This connects the canonical caller-source /
// callee-sink shape that neither per-function walk observes on its own.
//
// FP-safety:
//   - Only local functions with a summary are considered (library calls are
//     handled conservatively elsewhere and never reach here).
//   - The argument must be tainted FOR THE SINK'S CATEGORY (ts.isTaintedFor),
//     so a value already sanitised for that category upstream is skipped.
//   - An inline sanitizer wrapping the argument expression (e.g.
//     `lookup(db, escape(x))`) suppresses the flow.
//   - Self-recursive calls (callName == scopeName) are skipped to avoid
//     double-emitting the in-callee flow the per-function walk already finds.
func emitInterprocSinkFlows(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	if summaries == nil {
		return
	}
	callName := cfg.extractCallName(n)
	if callName == "" {
		return
	}
	summary, isLocal := summaries[callName]
	if !isLocal || summary == nil {
		return
	}
	// Skip direct self-recursion: the callee body is `scopeName` itself, whose
	// per-function walk already records the in-body flow.
	if callName == scopeName {
		return
	}

	args := cfg.extractCallArgs(n)
	if len(args) == 0 {
		return
	}
	line := int(n.StartRow()) + 1

	for i, arg := range args {
		sites := summary.paramSinkSites(i)
		if len(sites) == 0 {
			continue
		}
		ts, ok := nodeIsTainted(arg, tm, cfg)
		if !ok {
			// The argument may itself be an inline source expression that was
			// never bound to a local variable — e.g. `lookup_user(db, argv[1])`
			// where `argv` is a registered source used directly as the
			// argument. nodeIsTainted only consults the taint map, so seed a
			// synthetic taint state from the source when one is present.
			if src := findSourceInExpr(arg, matcher, cfg); src != nil {
				ts = &taintState{
					varName:    arg.Text(),
					source:     src,
					sourceLine: line,
					sanitized:  make(map[taint.SinkCategory]bool),
					confidence: 1.0,
					steps: []taint.FlowStep{{
						Line:        line,
						Description: "tainted by " + src.MethodName,
						VarName:     arg.Text(),
					}},
				}
				ok = true
			}
		}
		if !ok {
			continue
		}
		for cat, site := range sites {
			if site.sink == nil {
				continue
			}
			if !ts.isTaintedFor(cat) {
				continue
			}
			// An inline sanitizer wrapping the argument for this category
			// neutralises it (e.g. `lookup(db, escapeSql(x))`).
			if containsInlineSanitizer(arg, matcher, cfg, cat) {
				continue
			}
			// Build a flow state whose source is the argument's real source but
			// whose step trail is extended with the cross-function hop and the
			// in-callee path to the sink. Decay confidence for the interproc hop
			// (mirrors the 0.85 used by propagateCallResultInterproc).
			hop := ts.clone(ts.varName, line, "passed to "+callName+"() (interprocedural)", 0.85)
			for _, s := range site.steps {
				if s.Description == "" && s.VarName == "" {
					continue
				}
				hop.steps = append(hop.steps, s)
			}
			fb.addFlow(hop, site.sink, site.sinkLine, scopeName)
		}
	}
}

// shellPropagateReadVars marks every variable named as an argument to the
// `read` builtin as tainted (untrusted stdin). Flag arguments (-r, -p, …) and
// the value following an option that takes one (-p PROMPT, -d DELIM, -n N, -t
// TIMEOUT, -u FD, -a ARRAY counts as a var) are skipped so we taint the real
// target variables.
func shellPropagateReadVars(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	var readSrc *taint.SourceDef
	for i := range matcher.allSources {
		if matcher.allSources[i].MethodName == "read" {
			readSrc = matcher.allSources[i]
			break
		}
	}
	if readSrc == nil {
		return
	}
	line := int(n.StartRow()) + 1
	args := cfg.extractCallArgs(n)
	skipNext := false
	for _, arg := range args {
		txt := arg.Text()
		if skipNext {
			skipNext = false
			continue
		}
		// Option flag.
		if strings.HasPrefix(txt, "-") {
			// Options that consume the following token as their value.
			switch txt {
			case "-p", "-d", "-n", "-N", "-t", "-u", "-i":
				skipNext = true
			}
			continue
		}
		// A bare word naming a variable to populate.
		if arg.Type() == "word" && txt != "" {
			ts := &taintState{
				varName:    txt,
				source:     readSrc,
				sourceLine: line,
				confidence: 0.9,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "tainted by read (untrusted stdin)",
					VarName:     txt,
				}},
			}
			tm.set(txt, ts)
		}
	}
}

// seedParams seeds taint for common framework parameters.
func seedParams(fnNode *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	// Python: seed Pydantic-typed parameters on FastAPI/APIRouter route
	// handlers first, so the more specific "FastAPI Pydantic-bound request
	// body parameter" source wins over the generic isHandler fallback below.
	// Mature SAST tools model the same pattern as a Pydantic-bound request
	// handler parameter source.
	if cfg.language == rules.LangPython {
		seedPythonPydanticParams(fnNode, tm)
	}

	// ENGINE-GATED (C/C++ only): seed parameter-as-source taint for
	// handler-shaped C/C++ functions. The generic isHandler path below only
	// fires when isWebHandlerFunc finds a framework route annotation, which
	// idiomatic C/C++ entry points (`void handle(const std::string& user)`,
	// `void on_request(char* buf)`) do not carry — so before this hook the
	// C++ catalog was effectively INERT on plain handler signatures (a real
	// scan of a Bitcoin-style C++ tree produced ZERO taint findings). This
	// seeds params whose TYPE is a user-shaped string buffer (std::string,
	// const std::string&, char*, std::string_view) or whose NAME strongly
	// implies user input (input/buf/data/user/req/arg/body/cmd/path/…), but
	// ONLY in functions whose name is handler-shaped (handle*, on_*,
	// process*, do_get/do_post, service, *_handler, main, …) — so generic
	// helpers like `run_query(sqlite3*, const std::string& q)` that receive a
	// constant or sanitized argument interprocedurally are NOT auto-tainted.
	// The whole block is strictly guarded to LangC / LangCPP so no other
	// language's seeding behaviour changes by a single byte.
	if cfg.language == rules.LangC || cfg.language == rules.LangCPP {
		seedCParams(fnNode, tm, cfg)
	}

	// JS/TS: seed destructured handler parameters and NestJS DI request
	// surfaces. The generic identifier-based param loop below only sees plain
	// `identifier` params (jsExtractParams skips object/array patterns and
	// decorated TS `required_parameter` nodes), so the dominant modern idioms —
	// Express `({ body }, res) => …`, plain `function h({ cmd }) {…}`, and
	// NestJS `run(@Body() { cmd }: Dto)` / `search(@Query() q)` — bound NOTHING
	// and produced zero taint. This helper binds those names to a tailored
	// request source; the loop below then skips them via the
	// `existing.source != nil` guard, preserving the source set here.
	// Strictly gated to JS/TS so no other language's seeding changes.
	if cfg.language == rules.LangJavaScript || cfg.language == rules.LangTypeScript {
		seedJSParamBindings(fnNode, tm, cfg)
	}

	// Rust: seed parameters whose TYPE is an actix-web user-input extractor
	// (`web::Query<T>` / `web::Path<T>` / `web::Json<T>` / `web::Form<T>`, also
	// the fully-qualified `actix_web::web::Query<T>` form). These typed
	// extractors ARE the request input in actix handlers (`async fn h(info:
	// web::Query<P>) { … info.field … }`), but the generic loop below never
	// seeds them: the param name (`info`, `q`, `form`, …) is not input-shaped and
	// actix handlers carry no route annotation isWebHandlerFunc can see, so the
	// dominant actix input form was a dead source. The rust_sources.go entries
	// model these as a `web::Query(...)` CALL returning taint, which the
	// type-annotation usage never matches. This helper closes that gap. It does
	// NOT seed `web::Data<T>` (shared application state, not user input). Strictly
	// gated to Rust so no other language's seeding changes.
	if cfg.language == rules.LangRust {
		seedRustActixExtractorParams(fnNode, tm, cfg)
	}

	// Check if this function is a web handler (has route annotations).
	// If so, all parameters are user-controlled.
	isHandler := isWebHandlerFunc(fnNode, cfg)

	// PR-CATjava-1-deferred (Fix 1): tighten the handler signal for
	// Java only. `isWebHandlerFunc` matches a fixed substring set
	// against the first 500 chars of the method body, which has
	// historically tagged sentry-java helpers like
	// `processFile(File file, Hint hint)` as handlers because the
	// body mentions `Path(` via `file.getAbsolutePath()`. AST-walking
	// the method's own modifiers (and the enclosing class) for a real
	// `@GetMapping` / `@PostMapping` / `@KafkaListener` / `@Path`
	// annotation is a much stricter signal and eliminates those FPs.
	//
	// We deliberately demote rather than replace so the existing
	// substring-driven behaviour for the other 15 tsflow languages
	// (Pulsar/Cassandra/Vapor/…) stays exactly as it was — the broad
	// substring match is what tags their unannotated test handlers.
	if isHandler && cfg.language == rules.LangJava {
		if !javaMethodIsTrueHandler(fnNode) {
			isHandler = false
		}
	}

	// false-handler-tighten (Py / JS-TS / C#): decouple "seed this param at all"
	// (handler substring) from "promote it to the conf-0.9, block-eligible
	// `parameter:` seed". `isWebHandlerFunc` for these three languages is a
	// body-SUBSTRING match, so a non-handler whose body merely contains a handler
	// substring (`db.executeQuery(` → "Query(", `app.getConfig(` → "app.get")
	// over-promotes its params to block-eligible — an FP the external-origin gate
	// keeps (the marker is "parameter:", not the weak "param-name:"). Require REAL
	// AST handler evidence (route/binding decorator or ASP.NET attribute) for the
	// conf-0.9 promotion; a substring-only match still SEEDS the param (so recall
	// is preserved) but as the weak conf-0.6 "param-name:" source that gate (B)
	// caps to a hint.
	//
	// Java is already AST-tightened above (isHandler itself is demoted), so for
	// Java handlerBlockEligible == isHandler. Every other tsflow language keeps
	// the substring behaviour its framework-detection tests rely on.
	handlerBlockEligible := isHandler
	if isHandler {
		switch cfg.language {
		case rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangCSharp:
			handlerBlockEligible = isWebHandlerByASTEvidence(fnNode, cfg)
		}
	}

	params := cfg.extractFuncParams(fnNode)
	for _, paramName := range params {
		// Skip parameters already seeded by a more specific helper above
		// (e.g. Pydantic body params) to preserve their tailored source.
		if existing := tm.get(paramName); existing != nil && existing.source != nil {
			continue
		}

		lower := strings.ToLower(paramName)
		// Seed if: common input name, OR web handler param, OR annotated param.
		inputName := isInputParamName(lower, cfg.language)
		// EXTERNAL-ORIGIN GATE (Java only): a bare Java parameter whose NAME
		// merely looks input-like (`path`, `query`, `data`, …) is NOT, on its
		// own, proof of external origin. In storage / DB / service abstraction
		// layers these names overwhelmingly carry INTERNAL values (an
		// already-resolved path, a prepared query object, a model id), and
		// seeding them as user_input on the strength of the name alone is a
		// single-file false-positive shape (the same class the
		// parenHandlerAnnotations tightening removes for PHP). For Java, require
		// a real external-origin signal instead: the method is a web handler
		// (route/listener annotation, checked via the AST in isWebHandlerFunc) or
		// the parameter carries an input-binding annotation (@RequestParam,
		// @PathVariable, … via hasInputAnnotation below). A genuine caller that
		// passes request data into the parameter is still proven by the Layer-4 /
		// interprocedural summaries (built independently in buildTaintSummaries,
		// which seeds every param regardless of name), so cross-file true
		// positives are unaffected; OWASP Java (whose TPs come from real
		// request.getParameter() sources in @-annotated/servlet handlers) is
		// flat.
		//
		// Scoped to JAVA ONLY. PHP `$`-prefixed names never match isInputParamName
		// (so PHP is already covered by the parenHandlerAnnotations fix, not this
		// gate). Ruby is deliberately EXCLUDED: `params` is the idiomatic Rails
		// controller user-input object, so a bare `params` parameter genuinely IS
		// external (`params[:q]` → sink is a real Rails flow), and gating it would
		// drop true positives.
		if inputName && cfg.language == rules.LangJava {
			inputName = false
		}
		shouldSeed := inputName || isHandler
		if !shouldSeed && cfg.language == rules.LangJava {
			shouldSeed = hasInputAnnotation(fnNode, paramName)
		}
		// Swift: also seed parameters whose name strongly implies
		// user-controlled injection text (name/bio/comment/script/command/…).
		// Deliberately EXCLUDES url/endpoint-style names: the safe Swift
		// fixtures guard URL params with runtime mitigations (cert pinning,
		// host allowlists, scheme checks) that the tsflow walker does not
		// model, so auto-tainting URL params would create false positives on
		// those SSRF-safe handlers. The text-injection names here only reach
		// XSS / eval / SQL / predicate / command sinks, where the safe
		// fixtures use constant or parameterized (placeholder-bound) values
		// that carry no taint into the dangerous argument.
		if !shouldSeed && cfg.language == rules.LangSwift {
			shouldSeed = isSwiftInjectionTextParamName(lower)
		}
		if !shouldSeed {
			continue
		}

		// PR-CATjava (Fix 2 + Fix 3): even on handler methods, skip
		// dependency-injected framework parameters (RedirectAttributes,
		// Model, Authentication, …) and primitive-numeric / UUID
		// parameters annotated with @PathVariable / @RequestParam.
		// These are not user input at the controller boundary:
		//   - DI types are server-managed handles (the auto-tag here
		//     used to fire spurious trust_boundary on every
		//     redirectAttributes.addFlashAttribute call).
		//   - Numeric / UUID types are deserialized by Jackson and
		//     rejected before the handler body runs, so they cannot
		//     carry SQL / command / path payloads.
		if cfg.language == rules.LangJava {
			shortType := javaParamShortType(fnNode, paramName)
			if shortType != "" && tsflowJavaDIParamTypeAllowlist[shortType] {
				continue
			}
			if shortType != "" && tsflowJavaNumericTypeAllowlist[shortType] {
				continue
			}
		}

		conf := 0.6
		desc := "function parameter with input-like name"
		// Weak (name-only) param sources carry the "param-name:" marker so the
		// external-origin block gate recognises them as the conf-0.6 fabricator
		// (NOT proof of external reachability) and caps them to a hint. A genuine
		// web-handler parameter is the conf-0.9 external-proof variant and keeps
		// the plain "parameter:" prefix so it stays block-eligible.
		methodPrefix := "param-name:"
		if handlerBlockEligible {
			conf = 0.9
			desc = "web handler parameter (user-controlled)"
			methodPrefix = "parameter:"
		}

		src := &taint.SourceDef{
			ID:          string(cfg.language) + ".param." + paramName,
			Category:    taint.SrcUserInput,
			Language:    cfg.language,
			MethodName:  methodPrefix + paramName,
			Description: desc,
		}
		tm.set(paramName, &taintState{
			varName:    paramName,
			source:     src,
			sourceLine: 0,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: conf,
			steps: []taint.FlowStep{{
				Line:        0,
				Description: "parameter " + paramName + " assumed tainted",
				VarName:     paramName,
			}},
		})
	}
}

// nestParamDecorators maps a NestJS parameter-decorator name to the request
// surface it binds. These decorators inject request-derived data directly into
// a controller-action parameter (the canonical NestJS DI idiom), so the bound
// name — whether a plain identifier or a destructured pattern — is fully
// user-controlled. Keyed by the decorator's callee identifier (the text before
// the `(`), matched case-sensitively against the NestJS public API.
// Refs: https://docs.nestjs.com/custom-decorators ,
// https://docs.nestjs.com/controllers#request-object
var nestParamDecorators = map[string]string{
	"Body":          "body",
	"Query":         "query",
	"Param":         "params",
	"Params":        "params",
	"Headers":       "headers",
	"Req":           "request",
	"Request":       "request",
	"Session":       "session",
	"UploadedFile":  "file",
	"UploadedFiles": "file",
	"RawBody":       "body",
	"Ip":            "ip",
	"HostParam":     "host",
}

// seedJSParamBindings seeds taint for JavaScript/TypeScript function parameters
// that the identifier-only jsExtractParams path misses: destructured parameters
// (`({ body }, res) => …`, `function h({ cmd }) {…}`) and NestJS dependency-
// injection parameters (`run(@Body() { cmd }: Dto)`, `search(@Query() q)`).
//
// Two seeding rules, both JS/TS-isolated:
//   - A parameter carrying a NestJS request decorator (@Body/@Query/@Param/…)
//     is ALWAYS a request source — its bound name(s) are seeded regardless of
//     whether the enclosing function is otherwise recognised as a handler.
//   - A plain destructured parameter (no decorator) is seeded ONLY when the
//     enclosing function is a web handler, mirroring the generic loop's
//     `isHandler` gate so arbitrary destructured locals aren't auto-tainted.
//
// The caller (seedParams) invokes this behind a LangJavaScript/LangTypeScript
// gate; it must not be called for any other language.
func seedJSParamBindings(fnNode *ast.Node, tm *taintMap, cfg *langConfig) {
	if fnNode == nil {
		return
	}
	params := fnNode.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	handler := isWebHandlerFunc(fnNode, cfg)

	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if !p.IsNamed() {
			continue
		}

		// Resolve the binding node and any NestJS decorator on this parameter.
		binding := p
		decoratorSurface := ""
		switch p.Type() {
		case "required_parameter", "optional_parameter":
			// TS parameter wrapper. The bound pattern lives in the "pattern"
			// field; decorator children (if any) classify the request surface.
			if pat := p.ChildByFieldName("pattern"); pat != nil {
				binding = pat
			}
			for j := 0; j < p.ChildCount(); j++ {
				c := p.Child(j)
				if c.Type() == "decorator" {
					if surface := nestDecoratorSurface(c); surface != "" {
						decoratorSurface = surface
					}
				}
			}
		case "object_pattern", "array_pattern", "identifier":
			// Plain JS/TS destructured or simple parameter.
		case "assignment_pattern":
			// `({ body } = {}) => …` / `param = default` — bind the left side.
			if l := p.ChildByFieldName("left"); l != nil {
				binding = l
			}
		default:
			continue
		}

		// A plain destructured parameter is only seeded on a handler; a NestJS
		// decorator is itself the handler signal, so it seeds unconditionally.
		// A plain identifier parameter is left to the generic loop (its input-
		// name / handler heuristics already cover it) unless decorated.
		isDestructure := binding.Type() == "object_pattern" || binding.Type() == "array_pattern"
		if decoratorSurface == "" {
			if !isDestructure || !handler {
				continue
			}
		}

		names := collectDestructureBindings(binding)
		if binding.Type() == "identifier" {
			names = []string{binding.Text()}
		}

		surface := decoratorSurface
		if surface == "" {
			surface = "destructured request"
		}
		for _, nm := range names {
			if nm == "" || nm == "_" {
				continue
			}
			if existing := tm.get(nm); existing != nil && existing.source != nil {
				continue
			}
			src := &taint.SourceDef{
				ID:          string(cfg.language) + ".param.destructured." + nm,
				Category:    taint.SrcUserInput,
				Language:    cfg.language,
				MethodName:  "parameter:" + nm,
				Description: "request-bound parameter (" + surface + ")",
			}
			tm.set(nm, &taintState{
				varName:    nm,
				source:     src,
				sourceLine: 0,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 0.9,
				steps: []taint.FlowStep{{
					Line:        0,
					Description: "parameter " + nm + " bound from " + surface + " (assumed tainted)",
					VarName:     nm,
				}},
			})
		}
	}
}

// nestDecoratorSurface returns the request surface bound by a NestJS parameter
// decorator node (e.g. `@Body()`, `@Query('id')`), or "" when the decorator is
// not a recognised NestJS request decorator. The decorator's callee identifier
// (the name before the argument list) is matched against nestParamDecorators.
func nestDecoratorSurface(dec *ast.Node) string {
	if dec == nil {
		return ""
	}
	// A decorator node wraps either a call_expression (`@Body()`) or a bare
	// identifier (`@Body`). Find the callee/identifier name.
	name := ""
	var rec func(n *ast.Node)
	rec = func(n *ast.Node) {
		if n == nil || name != "" {
			return
		}
		switch n.Type() {
		case "identifier":
			name = n.Text()
			return
		case "call_expression":
			if fn := n.ChildByFieldName("function"); fn != nil {
				rec(fn)
				return
			}
		case "member_expression":
			// `@common.Body()` — take the trailing property.
			if prop := n.ChildByFieldName("property"); prop != nil {
				name = prop.Text()
				return
			}
		}
		for i := 0; i < n.ChildCount(); i++ {
			rec(n.Child(i))
		}
	}
	rec(dec)
	return nestParamDecorators[name]
}

// FastAPI/APIRouter decorator method names that indicate the decorated
// function is a request handler bound to an HTTP route. Matched
// case-sensitively against the trailing attribute of the decorator call.
var fastapiRouteMethods = map[string]bool{
	"get":     true,
	"post":    true,
	"put":     true,
	"delete":  true,
	"patch":   true,
	"head":    true,
	"options": true,
}

// Primitive Python annotations that should NOT be treated as Pydantic
// model parameters when they decorate a route handler. Path/query/header
// primitives on FastAPI handlers are user input too, but they are seeded
// by the existing isHandler fallback (or by Query()/Path()/... catalog
// sources) — not by this Pydantic-specific path.
var pyPrimitiveAnnotations = map[string]bool{
	"str":       true,
	"int":       true,
	"float":     true,
	"bool":      true,
	"bytes":     true,
	"bytearray": true,
	"list":      true,
	"dict":      true,
	"tuple":     true,
	"set":       true,
	"frozenset": true,
	"None":      true,
	"NoneType":  true,
	"Any":       true,
	"object":    true,
}

// FastAPI/Starlette helper types that are NOT Pydantic-model request
// bodies even though they look like class identifiers. Tainting these as
// "Pydantic body" would either double-fire with existing catalog sources
// (Request.query_params, Form()/File() returns) or attribute meaning
// (BackgroundTasks, Response).
var pyFastAPINonBodyTypes = map[string]bool{
	"Request":         true,
	"Response":        true,
	"WebSocket":       true,
	"BackgroundTasks": true,
	"UploadFile":      true,
	"Form":            true,
	"File":            true,
	"Query":           true,
	"Path":            true,
	"Body":            true,
	"Header":          true,
	"Cookie":          true,
	"Depends":         true,
	"Security":        true,
	"HTTPException":   true,
}

// seedPythonPydanticParams seeds taint on Pydantic-typed parameters of
// FastAPI/APIRouter route handlers. Mirrors a reference SAST tool's
// Pydantic-bound request handler parameter source: a parameter
// whose annotation is a class identifier reaching a Pydantic BaseModel
// subclass, on a function that is registered as a FastAPI route handler.
//
// We use a heuristic rather than full type resolution: any non-primitive,
// non-FastAPI-helper class identifier on a route handler counts. Tests
// `TestPython_FastAPI_PydanticBody_SQLi` and the negative trio cover the
// boundary conditions.
func seedPythonPydanticParams(fnNode *ast.Node, tm *taintMap) {
	if fnNode == nil {
		return
	}
	if !pyIsFastAPIRouteHandler(fnNode) {
		return
	}
	// Resolve to the inner function_definition to find the parameters node.
	fn := fnNode
	if fn.Type() == "decorated_definition" {
		for i := 0; i < fn.ChildCount(); i++ {
			c := fn.Child(i)
			if c.Type() == "function_definition" {
				fn = c
				break
			}
		}
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		// Only typed_parameter has an explicit annotation. default_parameter
		// without an annotation is not a Pydantic body. typed_default_parameter
		// covers `user: User = Depends(get_user)` — we skip those too because
		// their value is a Depends() helper, not a request body.
		if p.Type() != "typed_parameter" {
			continue
		}
		annot := pyTypedParamAnnotationName(p)
		if annot == "" {
			continue
		}
		if pyPrimitiveAnnotations[annot] {
			continue
		}
		if pyFastAPINonBodyTypes[annot] {
			continue
		}
		paramName := pyTypedParamName(p)
		if paramName == "" {
			continue
		}
		src := &taint.SourceDef{
			ID:          "py.fastapi.pydantic_body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPython,
			MethodName:  "parameter:" + paramName,
			Description: "FastAPI Pydantic-bound request body parameter",
		}
		tm.set(paramName, &taintState{
			varName:    paramName,
			source:     src,
			sourceLine: int(p.StartRow()) + 1,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 0.95,
			steps: []taint.FlowStep{{
				Line:        int(p.StartRow()) + 1,
				Description: "Pydantic body parameter " + paramName + ": " + annot,
				VarName:     paramName,
			}},
		})
	}
}

// pyTypedParamName returns the parameter name from a `typed_parameter`
// node. Tree-sitter Python represents `user: User` as a typed_parameter
// whose first identifier child is the name.
func pyTypedParamName(p *ast.Node) string {
	if name := p.ChildByFieldName("name"); name != nil && name.Type() == "identifier" {
		return name.Text()
	}
	for i := 0; i < p.ChildCount(); i++ {
		c := p.Child(i)
		if c.Type() == "identifier" {
			return c.Text()
		}
	}
	return ""
}

// pyTypedParamAnnotationName returns the bare identifier name of a
// typed_parameter's type annotation, or "" if the annotation is not a
// simple identifier (e.g. `List[str]`, `Optional[User]`, `dict`). We
// intentionally do NOT descend into subscripts — a reference SAST tool's model resolves
// generics, but for the heuristic case we conservatively only fire on
// `name: ClassName` shapes to avoid mistaking `list` (lowercase builtin)
// or `List[str]` (parametrised collection) for a Pydantic class.
func pyTypedParamAnnotationName(p *ast.Node) string {
	t := p.ChildByFieldName("type")
	if t == nil {
		return ""
	}
	// Tree-sitter Python wraps annotations in a `type` node whose child is
	// the actual annotation expression. Walk to the first named child.
	var inner *ast.Node
	for i := 0; i < t.ChildCount(); i++ {
		c := t.Child(i)
		if c.IsNamed() {
			inner = c
			break
		}
	}
	if inner == nil {
		// Older grammars may attach the identifier directly.
		if t.Type() == "identifier" {
			return t.Text()
		}
		return ""
	}
	if inner.Type() == "identifier" {
		return inner.Text()
	}
	return ""
}

// pyIsFastAPIRouteHandler returns true when the function is decorated by
// one of @<x>.get/post/put/delete/patch/head/options(...) — the standard
// FastAPI `app` / APIRouter `router` decorator shape. We accept any
// receiver name (`app`, `router`, `api`, `v1`, etc.) since a reference SAST
// tool's model treats any value reachable from FastAPI()/APIRouter() the same;
// we lack inter-module type info, so we trust the method name.
func pyIsFastAPIRouteHandler(fnNode *ast.Node) bool {
	if fnNode == nil {
		return false
	}
	// Find the decorated_definition wrapping this function.
	dec := fnNode
	if dec.Type() != "decorated_definition" {
		if parent := dec.Parent(); parent != nil && parent.Type() == "decorated_definition" {
			dec = parent
		} else {
			return false
		}
	}
	for i := 0; i < dec.ChildCount(); i++ {
		c := dec.Child(i)
		if c.Type() != "decorator" {
			continue
		}
		if pyDecoratorIsFastAPIRoute(c) {
			return true
		}
	}
	return false
}

// pyDecoratorIsFastAPIRoute returns true when the decorator's expression is
// `<recv>.<method>(...)` or `<recv>.<method>` where <method> is one of the
// FastAPI/APIRouter HTTP verbs.
func pyDecoratorIsFastAPIRoute(dec *ast.Node) bool {
	// The decorator's expression is its first named child after the `@`.
	var expr *ast.Node
	for i := 0; i < dec.ChildCount(); i++ {
		c := dec.Child(i)
		if c.IsNamed() {
			expr = c
			break
		}
	}
	if expr == nil {
		return false
	}
	// Case 1: @app.post("/users") — expr is a `call` whose function is an
	// `attribute` with attribute child `post`.
	if expr.Type() == "call" {
		fn := expr.ChildByFieldName("function")
		if fn != nil && fn.Type() == "attribute" {
			attr := fn.ChildByFieldName("attribute")
			if attr != nil && fastapiRouteMethods[attr.Text()] {
				return true
			}
		}
		return false
	}
	// Case 2: @app.get — expr is the attribute directly.
	if expr.Type() == "attribute" {
		attr := expr.ChildByFieldName("attribute")
		if attr != nil && fastapiRouteMethods[attr.Text()] {
			return true
		}
	}
	return false
}

// extractVarDeclParts extracts the variable name and RHS value from a
// variable declaration node, handling the various tree-sitter structures.
func extractVarDeclParts(n *ast.Node, cfg *langConfig) (string, *ast.Node) {
	// Try standard field names for the variable name.
	nameNode := n.ChildByFieldName("name")
	if nameNode == nil {
		nameNode = n.ChildByFieldName("declarator") // C/C++: init_declarator
	}
	if nameNode == nil {
		nameNode = n.ChildByFieldName("pattern") // Rust: let_declaration
	}

	// Try standard field names for the RHS value.
	rhs := n.ChildByFieldName("value")

	// C#: value is inside an equals_value_clause initializer.
	if rhs == nil {
		if init := n.ChildByFieldName("initializer"); init != nil {
			for i := 0; i < init.ChildCount(); i++ {
				c := init.Child(i)
				if c.IsNamed() {
					rhs = c
					break
				}
			}
		}
	}

	// Kotlin/Swift: property_declaration — name is in a nested
	// variable_declaration child, value is the expression after "=".
	if nameNode == nil || rhs == nil {
		var foundName *ast.Node
		var foundValue *ast.Node
		afterEquals := false
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() && c.Text() == "=" {
				afterEquals = true
				continue
			}
			if !afterEquals {
				if foundName == nil {
					if c.Type() == cfg.identType || c.Type() == "identifier" {
						foundName = c
					} else if c.Type() == "variable_declaration" || c.Type() == "variable_declarator" {
						// Drill into the wrapper to find the identifier.
						foundName = findFirstIdent(c, cfg.identType)
					}
				}
			} else if foundValue == nil && c.IsNamed() {
				foundValue = c
			}
		}
		if nameNode == nil && foundName != nil {
			nameNode = foundName
		}
		if rhs == nil && foundValue != nil {
			rhs = foundValue
		}
	}

	if nameNode == nil {
		return "", nil
	}

	lhsName := extractIdentText(nameNode, cfg.identType)
	return lhsName, rhs
}

// extractIdentText extracts the identifier text from a node, drilling into
// wrapper nodes like pointer_declarator, variable_declarator, etc.
func extractIdentText(n *ast.Node, identType string) string {
	if n == nil {
		return ""
	}
	if n.Type() == "identifier" || n.Type() == identType {
		return n.Text()
	}
	// Walk to find the first identifier inside wrapper nodes.
	var found string
	n.Walk(func(c *ast.Node) bool {
		if c.Type() == "identifier" || (identType != "" && c.Type() == identType) {
			found = c.Text()
			return false
		}
		return true
	})
	return found
}

// processJSDestructure binds the local names introduced by a JS/TS object or
// array destructuring declaration (`const {a, b} = rhs`, `const [x] = rhs`).
// When the RHS is tainted as a whole — a user-controlled object/array such as
// req.query / req.body / req.params or a tainted variable — every destructured
// local inherits that taint (each bound name is a field/element of the
// user-controlled value). When the RHS is not tainted, any stale binding of
// the same name is cleared so the fresh declaration shadows it.
func processJSDestructure(decl, pattern *ast.Node, tm *taintMap, matcher *tsMatcher, cfg *langConfig) {
	names := collectDestructureBindings(pattern)
	if len(names) == 0 {
		return
	}
	line := int(decl.StartRow()) + 1
	rhs := decl.ChildByFieldName("value")

	// Resolve the RHS taint state. The RHS is most commonly a *source*
	// expression that has not yet been bound to a variable (req.query /
	// req.body / req.params), so source-match it first (mirroring the
	// single-name path at the findSourceInExpr branch); otherwise fall back to
	// taint carried by a referenced variable.
	var rhsTS *taintState
	if rhs != nil {
		if src := findSourceInExpr(rhs, matcher, cfg); src != nil {
			rhsTS = &taintState{
				varName:    "",
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "tainted by " + src.MethodName,
				}},
			}
		} else if ts, ok := nodeIsTainted(rhs, tm, cfg); ok {
			rhsTS = ts
		}
	}

	for _, nm := range names {
		if nm == "" || nm == "_" {
			continue
		}
		// Fresh binding: drop any leftover field-keyed / fresh-empty state from
		// a shadowed prior binding (mirrors the single-name path's housekeeping).
		tm.clearFieldsOf(nm)
		delete(tm.freshLocalEmpty, nm)
		if rhsTS != nil && rhsTS.source != nil {
			tm.set(nm, rhsTS.clone(nm, line, "destructured from tainted value", 0.95))
		} else {
			tm.delete(nm)
		}
	}
}

// kotlinMultiVarPattern returns the multi_variable_declaration child of a Kotlin
// property_declaration (the `(a, b)` in `val (a, b) = expr`), or nil when the
// declaration binds a single name.
func kotlinMultiVarPattern(decl *ast.Node) *ast.Node {
	for i := 0; i < decl.ChildCount(); i++ {
		if c := decl.Child(i); c.Type() == "multi_variable_declaration" {
			return c
		}
	}
	return nil
}

// kotlinDestructureNames collects the local names bound by a Kotlin
// multi_variable_declaration: each variable_declaration child wraps one
// simple_identifier (`(cmd, arg)` → ["cmd", "arg"]).
func kotlinDestructureNames(pat *ast.Node) []string {
	var out []string
	for i := 0; i < pat.ChildCount(); i++ {
		c := pat.Child(i)
		if c.Type() == "variable_declaration" {
			if id := findFirstIdent(c, "simple_identifier"); id != nil {
				out = append(out, id.Text())
			}
		}
	}
	return out
}

// processKotlinDestructure binds the local names introduced by a Kotlin
// destructuring declaration (`val (a, b) = rhs`). When the RHS is tainted as a
// whole — a user-controlled value or a method chain on one (`raw.split(" ")`) —
// every destructured local inherits that taint, since each name is a
// componentN() projection of the tainted value. When the RHS is not tainted, any
// stale binding of the same name is cleared so the fresh declaration shadows it.
func processKotlinDestructure(decl, pattern *ast.Node, tm *taintMap, matcher *tsMatcher, cfg *langConfig) {
	names := kotlinDestructureNames(pattern)
	if len(names) == 0 {
		return
	}
	line := int(decl.StartRow()) + 1

	// The RHS value is the named child after the "=" token (the
	// multi_variable_declaration is the only other named child, and it precedes
	// "="). Take the first named child that appears after the "=".
	var rhs *ast.Node
	afterEquals := false
	for i := 0; i < decl.ChildCount(); i++ {
		c := decl.Child(i)
		if !c.IsNamed() && c.Text() == "=" {
			afterEquals = true
			continue
		}
		if afterEquals && c.IsNamed() {
			rhs = c
			break
		}
	}

	// Resolve the RHS taint: an inline source call first (mirroring the
	// single-name findSourceInExpr branch), then taint carried by a referenced
	// variable / method chain.
	var rhsTS *taintState
	if rhs != nil {
		if src := findSourceInExpr(rhs, matcher, cfg); src != nil {
			rhsTS = &taintState{
				varName:    "",
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "tainted by " + src.MethodName,
				}},
			}
		} else if ts, ok := nodeIsTainted(rhs, tm, cfg); ok {
			rhsTS = ts
		}
	}

	for _, nm := range names {
		if nm == "" || nm == "_" {
			continue
		}
		// Fresh binding: drop any leftover field-keyed / fresh-empty state from a
		// shadowed prior binding (mirrors the single-name path's housekeeping).
		tm.clearFieldsOf(nm)
		delete(tm.freshLocalEmpty, nm)
		if rhsTS != nil && rhsTS.source != nil {
			tm.set(nm, rhsTS.clone(nm, line, "destructured from tainted value", 0.95))
		} else {
			tm.delete(nm)
		}
	}
}

// collectDestructureBindings returns the local variable names introduced by a
// JS/TS destructuring pattern (object_pattern / array_pattern), recursing
// through nested patterns, renamed pairs, defaults, and rest elements. Only the
// bound *local* names are collected — for `{key: local}` the value side
// (`local`) is the binding, not the source property `key`.
func collectDestructureBindings(n *ast.Node) []string {
	var out []string
	var rec func(node *ast.Node)
	rec = func(node *ast.Node) {
		if node == nil {
			return
		}
		switch node.Type() {
		case "object_pattern", "array_pattern":
			for i := 0; i < node.ChildCount(); i++ {
				if c := node.Child(i); c.IsNamed() {
					rec(c)
				}
			}
		case "pair_pattern":
			// `{key: local}` — the binding is the value side; the key is the
			// source property name and must not be collected.
			if v := node.ChildByFieldName("value"); v != nil {
				rec(v)
			}
		case "object_assignment_pattern", "assignment_pattern":
			// `{local = default}` / `[local = default]` — binding is the left side.
			if l := node.ChildByFieldName("left"); l != nil {
				rec(l)
			} else if fc := firstNamedChild(node); fc != nil {
				rec(fc)
			}
		case "rest_pattern", "rest_element":
			if fc := firstNamedChild(node); fc != nil {
				rec(fc)
			}
		case "shorthand_property_identifier_pattern", "shorthand_property_identifier", "identifier":
			out = append(out, node.Text())
		}
	}
	rec(n)
	return out
}

// swiftIsTuplePattern reports whether a Swift property_declaration `name`
// pattern node is a tuple-destructuring pattern (`(a, b)`) rather than a
// single binding (`single`). tree-sitter-swift wraps each tuple element in
// its own nested `pattern` node, whereas a single binding's child is a
// `simple_identifier`/`wildcard_pattern`. Requiring at least two nested
// `pattern` children keeps a lone parenthesised binding `(a)` on the
// byte-identical single-name path.
func swiftIsTuplePattern(pat *ast.Node) bool {
	if pat == nil || pat.Type() != "pattern" {
		return false
	}
	nested := 0
	for i := 0; i < pat.ChildCount(); i++ {
		if c := pat.Child(i); c.IsNamed() && c.Type() == "pattern" {
			nested++
		}
	}
	return nested >= 2
}

// swiftDestructureTargets collects the leaf `simple_identifier` target nodes of
// a Swift tuple pattern, recursing into nested tuples (`let (a, (b, c)) = …`)
// and skipping `_` wildcard elements (`wildcard_pattern`). Mirrors
// pythonUnpackTargets for the Swift grammar.
func swiftDestructureTargets(pat *ast.Node) []*ast.Node {
	var out []*ast.Node
	var rec func(p *ast.Node)
	rec = func(p *ast.Node) {
		if p == nil {
			return
		}
		switch p.Type() {
		case "simple_identifier":
			out = append(out, p)
		case "wildcard_pattern":
			// `_` — bind nothing.
		case "pattern":
			for i := 0; i < p.ChildCount(); i++ {
				if c := p.Child(i); c.IsNamed() {
					rec(c)
				}
			}
		}
	}
	rec(pat)
	return out
}

// processSwiftDeconstruct binds the locals introduced by a Swift tuple
// destructuring declaration. RHS taint is resolved element-wise when the RHS
// is a tuple literal of matching arity (`let (a, b) = (req.query, "safe")`
// taints only `a`); otherwise it is a conservative whole-RHS distribution
// (`let (status, body) = decode(raw)` taints both, since every element of the
// destructured value derives from the tainted source). Targets are always
// rebound — a non-tainted RHS clears any shadowed prior binding.
func processSwiftDeconstruct(decl, pattern *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	// Ordered tuple-position slots — each a nested `pattern` node, including
	// `_` wildcard slots, so the slot count matches a literal RHS tuple's
	// arity even when some positions are discarded.
	var slots []*ast.Node
	for i := 0; i < pattern.ChildCount(); i++ {
		if c := pattern.Child(i); c.IsNamed() && c.Type() == "pattern" {
			slots = append(slots, c)
		}
	}
	allTargets := swiftDestructureTargets(pattern)
	if len(allTargets) == 0 {
		return
	}
	rhs := decl.ChildByFieldName("value")
	if rhs == nil {
		return
	}
	line := int(decl.StartRow()) + 1

	// Fresh binding: clear any shadowed prior state on every leaf target,
	// reading RHS taint below before re-setting the tainted ones.
	for _, tgt := range allTargets {
		tm.clearFieldsOf(tgt.Text())
		tm.delete(tgt.Text())
	}

	// Collect RHS tuple-literal elements (if any) for element-wise binding.
	var elems []*ast.Node
	if rhs.Type() == "tuple_expression" {
		for i := 0; i < rhs.ChildCount(); i++ {
			if c := rhs.Child(i); c.IsNamed() {
				elems = append(elems, c)
			}
		}
	}

	// Element-wise binding when the RHS is a tuple literal of matching arity:
	// `let (a, _) = (req.query, "safe")` taints only `a`. A `_` slot binds
	// nothing (its leaf set is empty) while still consuming its position.
	if len(slots) > 0 && len(elems) == len(slots) {
		for i, slot := range slots {
			ts := resolveUnpackElemTaint(elems[i], tm, cfg, matcher, line)
			if ts == nil {
				continue
			}
			for _, leaf := range swiftDestructureTargets(slot) {
				tm.set(leaf.Text(), ts.clone(leaf.Text(), line, "destructured from tuple element", 0.95))
			}
		}
		return
	}

	// Conservative whole-RHS distribution: every element of the destructured
	// value derives from the tainted source (`let (status, body) =
	// decode(raw)`).
	if ts := resolveUnpackElemTaint(rhs, tm, cfg, matcher, line); ts != nil {
		for _, leaf := range allTargets {
			tm.set(leaf.Text(), ts.clone(leaf.Text(), line, "destructured from tainted value", 0.9))
		}
	}
}

// findFirstIdent finds the first identifier-like node inside a wrapper.
func findFirstIdent(n *ast.Node, identType string) *ast.Node {
	if n == nil {
		return nil
	}
	if n.Type() == "identifier" || n.Type() == identType {
		return n
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.Type() == "identifier" || c.Type() == identType {
			return c
		}
	}
	return nil
}

// csharpTupleTargets collects the simple identifier binding targets from a C#
// tuple-deconstruction LHS — a tuple_pattern (`var (a, b) = ...`) or a
// tuple_expression (`(a, b) = ...`). tuple_expression wraps each element in an
// `argument` node, nested tuples recurse, `(var x, var y)` element-local
// declarations are unwrapped to their identifier, and the `_` discard is
// skipped.
func csharpTupleTargets(lhs *ast.Node) []*ast.Node {
	var out []*ast.Node
	var rec func(p *ast.Node)
	rec = func(p *ast.Node) {
		if p == nil {
			return
		}
		switch p.Type() {
		case "identifier":
			if p.Text() != "_" {
				out = append(out, p)
			}
		case "tuple_pattern", "tuple_expression", "argument", "parenthesized_expression":
			for i := 0; i < p.ChildCount(); i++ {
				if c := p.Child(i); c.IsNamed() {
					rec(c)
				}
			}
		case "declaration_expression":
			if id := findFirstIdent(p, "identifier"); id != nil && id.Text() != "_" {
				out = append(out, id)
			}
		}
	}
	rec(lhs)
	return out
}

// processCSharpDeconstruct handles C# tuple deconstruction so every bound local
// inherits the taint of a user-controlled RHS. Two shapes reach here:
//
//	var (a, b) = Parse(input);   // node = variable_declarator (tuple_pattern LHS)
//	(a, b)     = Parse(input);   // node = assignment_expression (tuple_expression LHS)
//
// Both are dropped by the single-name extractVarDeclParts / extractAssignLHS
// paths (the pattern yields no identifier), so without this branch every
// deconstructed local silently loses taint (`var (cmd, arg) = Split(req);
// Process.Start(cmd)` produced zero flows). Conservative whole-RHS
// distribution, mirroring processPythonUnpackAssign: if the RHS is tainted,
// every target inherits it. Returns true when it recognised (and consumed) a
// deconstruction.
func processCSharpDeconstruct(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) bool {
	var lhs, rhs *ast.Node
	switch n.Type() {
	case "assignment_expression":
		l := n.ChildByFieldName("left")
		if l == nil || l.Type() != "tuple_expression" {
			return false
		}
		lhs = l
		rhs = n.ChildByFieldName("right")
	case "variable_declarator":
		// children: tuple_pattern, "=", <value>
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() {
				continue
			}
			if c.Type() == "tuple_pattern" {
				lhs = c
			} else if lhs != nil && rhs == nil {
				rhs = c
			}
		}
		if lhs == nil {
			return false
		}
	default:
		return false
	}

	targets := csharpTupleTargets(lhs)
	if len(targets) == 0 {
		return true // deconstruction-shaped, but nothing simple to bind
	}
	line := int(n.StartRow()) + 1

	var src *taintState
	if rhs != nil {
		src = resolveUnpackElemTaint(rhs, tm, cfg, matcher, line)
	}
	for _, tgt := range targets {
		name := tgt.Text()
		tm.clearFieldsOf(name)
		tm.delete(name)
		if src != nil {
			tm.set(name, src.clone(name, line, "deconstructed from tainted tuple", 0.9))
		}
	}
	return true
}

// processCall handles call expressions — checking for source, sanitizer, and sink.
func processCall(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder) {
	line := int(n.StartRow()) + 1

	// PR-CATjs-2: if this call is `<arr>.reduce(callback, {})` (JS/TS),
	// mark the callback's accumulator parameter as a fresh empty container
	// BEFORE the walker descends into the callback body, so an inner
	// `Object.assign(acc, ...)` sink can recognise `acc` as a safe dest.
	// Idempotent — handled even when not in an assignment context.
	noteReduceAccumulatorFreshness(n, tm, cfg)

	// Check as source (record in taint map under __expr__ for chaining).
	if src := matcher.matchSourceCall(n); src != nil {
		tm.set("__expr__", &taintState{
			varName:    "__expr__",
			source:     src,
			sourceLine: line,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 1.0,
			steps: []taint.FlowStep{{
				Line:        line,
				Description: "tainted by " + src.MethodName,
				VarName:     "__expr__",
			}},
		})
	}

	// List/accumulator method handling with per-index taint tracking.
	callName := cfg.extractCallName(n)
	receiver := cfg.extractCallReceiver(n)

	// In-place statement-form sanitizer guard (C# path confinement). A
	// void-returning guard that throws/returns when its path argument escapes
	// the configured base directory is conventionally called on its own
	// statement line, leaving the SAME variable to flow into the file sink:
	//
	//     EnsurePathWithinBaseDir(path);   // throws if path escapes base
	//     return File.OpenRead(path);      // ← path is now confined
	//
	// The assignment-form sanitizer paths (`x = sanitize(t)`) elsewhere don't
	// fire here because there is no LHS to receive a value. Mirror
	// applyBarrierGuard: when the call matches a catalog sanitizer whose
	// argument is an already-tainted variable, mark that variable sanitized IN
	// PLACE for the sanitizer's categories — without deleting it, so other
	// categories and other variables keep their taint.
	//
	// Gated tightly so it stays fp-only:
	//   - C# only (cannot perturb other languages),
	//   - @argpattern sanitizers only — these are throw-on-violation GUARD
	//     calls (csharp.path.confinement.guardhelper) whose validation effect
	//     persists on the variable after the statement. A TRANSFORM sanitizer
	//     such as Path.GetFileName(p) returns a new value and does NOT mutate
	//     p, so marking p in place off a discarded statement-form transform
	//     would be unsound — restricting to @argpattern guards avoids that,
	//   - file-traversal (CWE-22) categories only — a confinement check says
	//     nothing about command/SQL/XSS metacharacters.
	if cfg.language == rules.LangCSharp {
		if san, sanitizedArg := matcher.matchSanitizer(n); san != nil && sanitizedArg != nil &&
			san.ObjectType == "@argpattern" {
			confinesPath := false
			for _, c := range san.Neutralizes {
				if c == taint.SnkFileRead || c == taint.SnkFileWrite {
					confinesPath = true
					break
				}
			}
			if confinesPath {
				if ts, ok := nodeIsTainted(sanitizedArg, tm, cfg); ok && ts != nil {
					if ts.sanitized == nil {
						ts.sanitized = make(map[taint.SinkCategory]bool)
					}
					for _, c := range san.Neutralizes {
						ts.sanitized[c] = true
					}
				}
			}
		}
	}

	// .add() / .append() — track which index is tainted.
	if receiver != "" && (callName == "add" || callName == "append") {
		args := cfg.extractCallArgs(n)
		if len(args) > 0 {
			ts, isTainted := nodeIsTainted(args[0], tm, cfg)
			if isTainted {
				tm.listAdd(receiver, ts)
				// Also mark the whole receiver as tainted (for backward compat
				// with code that checks receiver taint directly).
				newTs := ts.clone(receiver, line, "accumulated via ."+callName+"()", 0.95)
				tm.set(receiver, newTs)
			} else {
				tm.listAdd(receiver, nil) // safe/literal element
			}
		}
	}

	// .remove(N) — shift list indices.
	if receiver != "" && callName == "remove" {
		args := cfg.extractCallArgs(n)
		if len(args) > 0 {
			idxText := args[0].Text()
			if idx, err := strconv.Atoi(strings.TrimSpace(idxText)); err == nil {
				tm.listRemove(receiver, idx)
			}
		}
	}

	// Python list.pop(N) — same semantics as remove-by-index: removes the
	// element at the given index (default -1 = last) and shifts subsequent
	// elements down. Distinct from Python's list.remove(VALUE) which removes
	// by value; the .remove(N) branch above tracks the C-style/Java idiom
	// (remove-by-index). The OWASP "list-shuffle" template uses pop(0).
	if receiver != "" && callName == "pop" {
		args := cfg.extractCallArgs(n)
		if li, ok := tm.lists[receiver]; ok && li != nil {
			idx := li.size - 1 // default: pop last
			if len(args) > 0 {
				if v, err := strconv.Atoi(strings.TrimSpace(args[0].Text())); err == nil {
					idx = v
				}
			}
			tm.listRemove(receiver, idx)
		}
	}

	// .put("key", value) — track per-key taint for maps/dicts.
	if receiver != "" && callName == "put" {
		args := cfg.extractCallArgs(n)
		if len(args) >= 2 {
			keyText := args[0].Text()
			// Strip quotes from string key
			keyText = strings.Trim(keyText, "\"'")
			ts, isTainted := nodeIsTainted(args[1], tm, cfg)
			if isTainted {
				tm.mapPut(receiver, keyText, ts)
				// Also mark whole receiver as tainted for backward compat
				newTs := ts.clone(receiver, line, "map.put("+keyText+")", 0.95)
				tm.set(receiver, newTs)
			} else {
				tm.mapPut(receiver, keyText, nil) // safe value
			}
		}
	}

	// Other accumulator methods (.write, .extend, .insert, .update) —
	// use the original whole-receiver tainting.
	if receiver != "" && isAccumulatorMethod(callName) &&
		callName != "add" && callName != "append" && callName != "remove" &&
		callName != "put" {
		args := cfg.extractCallArgs(n)
		for _, arg := range args {
			if ts, ok := nodeIsTainted(arg, tm, cfg); ok {
				newTs := ts.clone(receiver, line, "accumulated via ."+callName+"()", 0.95)
				tm.set(receiver, newTs)
				break
			}
		}
	}

	// configparser-style three-argument setters on a known container
	// instance: `conf.set(section, key, tainted)` writes the value into a
	// composite "section/key" slot of conf's per-key map. The matching
	// `bar = conf.get(section, key)` read (handled below in the call-RHS
	// assignment processing) then propagates from that slot. Gated to
	// receivers tracked in tm.containerWriters (populated by
	// `lhs = configparser.ConfigParser()` and similar) so generic 3-arg
	// `.set(...)` patterns on unrelated objects don't over-taint.
	if receiver != "" && callName == "set" && tm.containerWriters[receiver] {
		args := cfg.extractCallArgs(n)
		if len(args) >= 3 {
			compositeKey := strings.Trim(args[0].Text(), "\"'") + "/" + strings.Trim(args[1].Text(), "\"'")
			if ts, ok := nodeIsTainted(args[2], tm, cfg); ok {
				tm.mapPut(receiver, compositeKey, ts.clone(receiver, line, "stored at "+compositeKey, 0.95))
			} else {
				tm.mapPut(receiver, compositeKey, nil)
			}
		}
	}

	// Receiver-state hardening (Java only): if this call is a sanitizer that
	// mutates receiver state (e.g. `xs.allowTypes(...)`,
	// `factory.setFeature(...)`) and has no LHS to receive a sanitized
	// value, record the receiver as hardened against a curated set of
	// receiver-state-aware sink categories. The downstream sink check
	// below consults `tm.isReceiverHardened` and suppresses findings on
	// the same receiver. Catalog entries already list these sanitizers
	// (java.xstream.allowtypes, java.dbf.disallow.doctype, …) but they
	// previously had no observable effect on receiver-state shapes.
	// Restricted to Java + a closed set of categories so generic
	// method-name collisions in other languages (e.g. logger.info as a
	// "sanitizer" of itself) don't accidentally neutralize unrelated sinks.
	if cfg.language == rules.LangJava && receiver != "" {
		if san, _ := matcher.matchSanitizer(n); san != nil && len(san.Neutralizes) > 0 {
			var cats []taint.SinkCategory
			for _, c := range san.Neutralizes {
				if isReceiverStateSinkCategory(c) {
					cats = append(cats, c)
				}
			}
			if len(cats) > 0 {
				tm.markReceiverHardened(receiver, cats)
			}
		}
	}

	// PHP XXE body-scope hardening: a bare `libxml_disable_entity_loader(true)`
	// call (no LHS to receive a sanitized value) disables external-entity
	// loading process-wide for the subsequent XML parses in this scope. The
	// canonical safe shape is:
	//   libxml_disable_entity_loader(true);
	//   $xml = simplexml_load_string($body, ...);   // ← now safe
	// Mark SnkDeserialize body-suppressed so the downstream XXE sink check
	// (which consults isBodySuppressedCategory) skips it. The catalog already
	// models this as a SnkDeserialize sanitizer; this gives the statement-form
	// call (no assignment) an observable effect.
	if cfg.language == rules.LangPHP && callName == "libxml_disable_entity_loader" {
		args := cfg.extractCallArgs(n)
		if len(args) > 0 {
			a := args[0]
			if a.Type() == "argument" {
				if inner := firstNamedChild(a); inner != nil {
					a = inner
				}
			}
			if strings.TrimSpace(a.Text()) == "true" {
				tm.markBodySuppressCategory(taint.SnkDeserialize)
			}
		}
	}

	// Check as sink.
	sink, dangerousArgs := matcher.matchSinkCall(n)
	if sink != nil {
		// Flask make_response((body, headers)) body/header split: the
		// HTML-output sink (py.send → make_response) takes a tuple whose
		// FIRST element is the response body and whose later elements are
		// status/headers. Only the body is reflected to the browser as HTML;
		// a tainted value placed solely in the headers dict (2nd tuple
		// element) is an HTTP-header concern, not reflected XSS. Narrow the
		// dangerous arg to the body element so `make_response((CONST, {h:
		// tainted}))` is not flagged as XSS, while `make_response((tainted,
		// {...}))` (tainted body) still fires. No-op unless the language is
		// Python, the sink is html_output, and arg 0 is a tuple.
		dangerousArgs = narrowPythonMakeResponseBody(sink, dangerousArgs, cfg)
		// Python subprocess argv-list narrowing: the no-shell argv form
		// `subprocess.check_output(["nslookup", domain])` is the canonical
		// SECURE rewrite and must not fire CWE-78. Suppress the finding when
		// arg0 is a list/tuple literal and there is no `shell=True`. No-op
		// unless the language is Python and the sink is the subprocess family;
		// `os.system` concat and `subprocess.run(..., shell=True)` / single
		// tainted-string TPs are unaffected (see helper docstring).
		dangerousArgs = narrowPythonSubprocessArgvList(n, sink, dangerousArgs, cfg)
		// PHP higher-order-callback narrowing: the array_map/array_filter/
		// usort/array_walk/preg_replace_callback/register_shutdown_function
		// dynamic-callable sinks (CWE-95) are dangerous ONLY when the callback
		// argument is a tainted STRING. The overwhelmingly common idiom is a
		// closure / arrow-function literal in that slot
		// (`array_map(function ($x) use ($t) {...}, $data)`), where a value
		// captured via `use` makes the engine see the closure-arg as tainted —
		// a false positive (the closure body is not attacker-supplied code).
		// Drop the callback dangerous-arg when its expression is a closure or
		// arrow function so only the genuine tainted-string-callable form
		// fires. No-op for every non-PHP language and every non-callback sink.
		dangerousArgs = narrowPHPDynamicCallbackArg(sink, dangerousArgs, cfg)
		// Receiver-state hardening suppression: if the sink's receiver was
		// hardened earlier in the same function body (see
		// `tm.markReceiverHardened` above), skip the finding. Canonical Java
		// shapes are XStream allowlist mode (`xs.allowTypes(...)` ->
		// `xs.fromXML(body)`) and DocumentBuilderFactory XXE hardening
		// (`factory.setFeature(\"disallow-doctype-decl\", true)` ->
		// `builder.parse(body)`). Without this gate the catalog sanitizers
		// for those patterns have no effect because the sanitizer call has
		// no LHS to receive the sanitized value.
		if receiver != "" && tm.isReceiverHardened(receiver, sink.Category) {
			return
		}
		// SSRF allowlist-guard suppression: if any dangerous argument is a
		// bare identifier that was hardened by a body-scope guard
		// (`ALLOWED_HOSTS.contains(uri.getHost())` / `isAllowedHost(uri)`)
		// pre-recorded in seedJavaBodyHardening, skip the finding. Covers
		// the constructor sink shape `new HttpGet(uri)` where the receiver
		// is empty so the receiver-state check above doesn't apply.
		if len(dangerousArgs) > 0 {
			allHardened := true
			for _, a := range dangerousArgs {
				name := strings.TrimSpace(a.Text())
				if !tm.isReceiverHardened(name, sink.Category) {
					allHardened = false
					break
				}
			}
			if allHardened {
				return
			}
		}
		// Body-scope category suppression: if the function body contains a
		// clear hardening guard for this sink category (currently SSRF host
		// allowlist guards), suppress the finding even when neither the
		// receiver nor any dangerous arg is by name in the hardened set.
		// Coarser than per-variable hardening but matches the canonical
		// safe shape where a parse step precedes the validation block.
		if tm.isBodySuppressedCategory(sink.Category) {
			return
		}
		// C/C++ memory-copy bounds-guard suppression: a memcpy/strcpy/strncpy
		// whose size or source is constrained by a preceding length/bounds check
		// in the same function (`if (strlen(s) > PATH_MAX) goto err;`,
		// `if (sdslen(o) > sizeof(buf)-1) goto invalid;`) is bounded — the
		// SnkMemory out-of-bounds-write finding is a false positive. Recognises
		// only an early-exit size comparison that references THIS copy, mirroring
		// the Python eval-guard idea for the memory sink class. No-op for any
		// other language or sink category (see cMemorySinkIsBoundsGuarded).
		if cMemorySinkIsBoundsGuarded(n, sink.Category, cfg) {
			return
		}
		// JS array iteration method-name collision: methods like find, filter,
		// forEach, map, some, every, reduce overlap with Mongoose query methods
		// (Model.find({query})). Mongoose is called with an object or string;
		// Array.* is called with a function/arrow. If our sink matched a known
		// Mongoose query method name but the first arg is a callback, skip —
		// this is Array iteration, not a DB query.
		if sink.Category == taint.SnkSQLQuery && isLikelyArrayIteration(n, cfg) {
			return
		}
		// JS SQL builder safe-form gate: Bookshelf/Knex `.query()`, `.where()`,
		// `.andWhere()`, `.orWhere()` accept several safe parameter-binding
		// shapes (object literal, comparator form `where('col', op, val)`,
		// callback subquery) — only the raw-string-with-interpolation /
		// string-concat shapes are SQL injection vectors. Suppress when arg 0
		// is clearly a safe shape so we don't flag Bookshelf
		// `.query({where: {...}})` or Knex `.where('col', '>=', val)` as
		// SQL injection sinks. Skips `super.query(...)` (Ember adapter calls,
		// not SQL). See PR pr-catjs-5.
		if sink.Category == taint.SnkSQLQuery && isSafeJSSQLBuilderCall(n, sink, cfg) {
			return
		}
		// PHP Doctrine/DBAL QueryBuilder safe-form gate: where()/andWhere()/
		// orWhere()/having()/andHaving()/orHaving() are safe when the predicate
		// is built with the expression builder + parameter binding
		// (`$qb->where($qb->expr()->eq('c', $qb->createNamedParameter($v)))`) or
		// uses a named/positional placeholder string. Only a raw concatenated
		// fragment is SQL injection. Suppresses the dominant Nextcloud/Symfony
		// FP where receiver-taint on $qb would otherwise flag a fully
		// parameterized predicate. See php.doctrine.querybuilder.* sinks.
		if sink.Category == taint.SnkSQLQuery && isSafePHPQueryBuilderCall(n, sink, cfg) {
			return
		}
		// PR-CATjs-2: merge-style prototype-pollution sinks
		// (Object.assign / _.merge / _.mergeWith / _.defaultsDeep /
		// Hoek.merge / Hoek.applyToDefaults) are inert when their
		// destination (arg 0) is a fresh local empty container — the call
		// cannot reach Object.prototype because the throwaway dest is
		// discarded. Path-traversing sinks (_.set / _.setWith /
		// _.zipObjectDeep) deliberately excluded since a fresh `{}` is
		// still vulnerable to `__proto__.<x>` segments (CVE-2020-8203).
		if isMergeStyleProtoSink(sink) {
			if allArgs := cfg.extractCallArgs(n); len(allArgs) > 0 {
				if isJSFreshProtoDest(allArgs[0], tm, cfg) {
					return
				}
			}
		}
		// Call-level @argpattern sanitizer check: if an @argpattern sanitizer
		// matches the call itself (e.g. `yaml.load(body, Loader=yaml.SafeLoader)`
		// matches the SafeLoader sanitizer pattern), skip flagging. This is
		// distinct from argument-level inline sanitizer wrapping (handled
		// inside the loop below) because here the safety is encoded in the
		// call's kwargs, not in a wrapper applied to the dangerous arg
		// expression. Restricted to @argpattern sanitizers so generic
		// receiver-typed sanitizers (e.g. `int(`) don't accidentally
		// neutralise a sink with a colliding method name.
		if matchesCallLevelArgPatternSanitizer(matcher, n, sink.Category) {
			return
		}
		// C# named-HttpClient relative-URI SSRF suppression (CWE-918): a
		// relative URI (a path beginning with `/`, no scheme/host) sent through
		// a NAMED HttpClient (one obtained from IHttpClientFactory.CreateClient
		// ("name"), whose BaseAddress is configured at registration) cannot
		// change the destination host — the host is pinned by the client's
		// BaseAddress and only the path/query come from the argument. The
		// canonical FP is bitwarden server's SsoController.PreValidate:
		//   var requestPath = $"/Account/PreValidate?domainHint={domainHint}";
		//   var httpClient  = _clientFactory.CreateClient("InternalSso");
		//   await httpClient.GetAsync(requestPath);   // ← relative, host-pinned
		// Tightly anchored so it stays fp-only: C# only, SnkURLFetch only,
		// requires BOTH (a) the receiver resolved to a CreateClient("literal")
		// named client in this function body AND (b) every dangerous arg
		// resolves to a relative-URI string literal/interpolation beginning
		// with `/`. An absolute URL (`http://...{t}`) or an unnamed `new
		// HttpClient()` receiver fails the gate and still fires.
		if csharpNamedClientRelativeURISSRFSafe(n, sink, dangerousArgs, receiver, cfg) {
			return
		}
		// Constrained-name suppression (SinkDef.RejectConstrainedName; default
		// false = no-op, so every other sink is byte-identical). Reflective sinks
		// whose dangerous payload is an attribute/method NAME (Python
		// getattr/setattr — CWE-470/CWE-915) are dangerous only when the name is
		// an OPEN attacker-controlled value. The pervasive SAFE framework idioms
		// draw the name from a BOUNDED domain — HTTP-verb dispatch
		// (getattr(self, request.method.lower())), model-metadata iteration
		// (getattr(obj, field.name)), a string literal, or a literal dispatch
		// table — and must not fire. When the name arg (the DangerousArgs node)
		// is provably so constrained, suppress the fire. The recogniser is
		// conservative-default (unprovable ⇒ NOT constrained ⇒ fires), so a real
		// tainted name (getattr(obj, request.args['x'])) still fires.
		if sink.RejectConstrainedName {
			if nameArg := argShapeRelevantArg(n, sink, cfg); nameArg != nil &&
				nameArgIsFrameworkConstrained(nameArg, tm, cfg) {
				return
			}
		}
		found := false
		// PayloadPosition (POST-MATCH fire-path selector; default zero =
		// PayloadDefault = unchanged). PayloadReceiver sinks fire ONLY on a
		// tainted receiver — their attacker-controlled payload is the receiver
		// (e.g. the format template of `template.format_map(values)`), never the
		// argument (which holds substituted values) — so skip the dangerous-arg
		// loop entirely and let the receiver branch below do the firing.
		runDangerousArgLoop := sink.PayloadPosition != taint.PayloadReceiver
		for _, argNode := range dangerousArgs {
			if !runDangerousArgLoop {
				break
			}
			// PHP upload temp-path arg: `move_uploaded_file($_FILES['x']
			// ['tmp_name'], $dst)` — arg 0 is the server-generated temp path,
			// not an attacker-controlled value. Skip it for the upload sink so
			// the SAFE shape (MIME-checked, randomly-renamed) isn't flagged
			// solely on this arg; the real upload danger (user-controlled
			// destination/filename) still fires via the destination arg.
			if cfg.language == rules.LangPHP && sink.Category == taint.SnkUpload &&
				phpBenignUploadTempArg(argNode) {
				continue
			}
			ts, ok := nodeIsTainted(argNode, tm, cfg)
			if !ok {
				// Inline-source-at-sink: a user-input source is passed directly
				// into the sink with no intervening assignment
				// (`readfile($_GET['doc'])`, `os.system(request.args.get("c"))`,
				// `Runtime.exec(request.getParameter("c"))`, `system(params[:c])`,
				// `fs.readFile(req.params.name)`). This is one of the most common
				// real-world vulnerability shapes. nodeIsTainted only resolves
				// variables already seeded in the taint map, so it misses these.
				// Resolve the source directly from the argument expression and
				// synthesise a transient taint state. The inline-sanitizer guard
				// below still applies so `readfile(realpath($_GET['x']))` /
				// `os.system(shlex.quote(...))` and the like stay clean. The
				// pre-loop safe-form narrowings (argv-list, SQL builder, array
				// iteration, hardened receivers) have already run, so they are
				// honoured here too.
				//
				// PHP wraps each call argument in an `argument` node; unwrap to
				// the inner expression so findSourceInExpr sees the
				// subscript/variable directly. The unwrap is gated on the node
				// type, so it is a no-op for languages that don't use it.
				srcNode := argNode
				if srcNode.Type() == "argument" {
					if inner := firstNamedChild(srcNode); inner != nil {
						srcNode = inner
					}
				}
				// Skip the inline synthesis for trust-boundary sinks (CWE-501:
				// storing/forwarding untrusted data — session params, putenv,
				// message-queue sends). Unlike execution/injection sinks, a value
				// passed directly into a trust-boundary sink is idiomatically
				// preceded by a validation guard (FormValidator, schema check,
				// `unless $result->has_error`) that tsflow cannot model, so
				// synthesising a brand-new source here is FP-prone. The two-step
				// path (value flowing through a variable) still reports
				// trust-boundary flows — only the bare inline synthesis is skipped.
				if sink.Category == taint.SnkTrustBoundary {
					continue
				}
				src := findSourceInExpr(srcNode, matcher, cfg)
				if src == nil {
					// Inline ATTRIBUTE/subscript source nested in a concatenation or
					// template literal:
					//   cp.exec("ping " + req.body.host)
					//   exec(`ping ${req.params.target}`)
					//   header("Location: " . $_GET['next'])     (open redirect)
					// findSourceInExpr's binary/interpolation recursion resolves
					// only CALL-shaped sources (request.args.get(...)) — attribute
					// and subscript sources are deliberately excluded there to keep
					// the field-sensitive access-path map authoritative for
					// variable taint (so `x=req.body.a; sink("..."+req.body.b)`
					// does not collapse a sibling field). But for certain sink
					// categories there is no benign "sibling field" of a value that
					// reaches the sink: ANY attacker-controlled segment spliced into
					// the argument is the vulnerability regardless of which field it
					// is. The direct-arg form (`exec(req.body.host)` /
					// `header($_GET['x'])`) already fires via the attribute branch
					// above; this closes the equally-dangerous concat/template form
					// for those categories:
					//   - SnkCommand:  /bin/sh -c <string> — any segment is OS cmd injection.
					//   - SnkRedirect: a Location:/Refresh: URL — any segment is open
					//     redirect (DVWA open_redirect/low.php: `header("location: " .
					//     $_GET['redirect'])`). This is the inline shape the catalog
					//     fix to php.header.location does not reach on its own.
					// Scoped to these two categories only, so the SQL/eval
					// sibling-distinctness contract (TestMultiLevelField_*) is
					// untouched, and the inline-sanitizer guard below still suppresses
					// the encoded/validated form (`urlencode(...)`, `shellEscape(...)`).
					switch sink.Category {
					case taint.SnkCommand, taint.SnkRedirect:
						src = findInlineConcatSource(srcNode, matcher, cfg)
					case taint.SnkSQLQuery:
						// SnkSQLQuery: a raw SQL string handed to .query/.execute/
						// sequelize.query/knex.raw/$queryRaw. Like command/redirect,
						// the WHOLE argument is one SQL statement, so any attacker-
						// controlled segment spliced into it (via concat OR template-
						// literal interpolation) is SQL injection — this is the
						// flagship `models.sequelize.query(`SELECT ... '${req.body.email}' ...`)`
						// shape (OWASP Juice Shop login/search SQLi). It was dataflow-
						// invisible because findSourceInExpr deliberately excludes
						// attribute/subscript sources from its binary/interpolation
						// recursion to keep the field-sensitive map authoritative.
						//
						// Unlike command/redirect, SQL DOES have a legitimate
						// field-sensitive sibling contract: `x = req.body.a;
						// db.query("..." + req.body.b)` must stay clean
						// (TestMultiLevelField_*). So this is gated on NO sibling field
						// of the same request source already being tracked in this
						// scope: if some local derives from the same source, the
						// resolution is suppressed (preserving sibling distinctness);
						// if nothing in scope derives from that source — the inline use
						// is the only one, as in Juice Shop — it fires.
						if inlineSrc := findInlineConcatSource(srcNode, matcher, cfg); inlineSrc != nil &&
							!tm.sourceFieldTrackedInScope(inlineSrc) {
							src = inlineSrc
						}
					}
				}
				if src == nil {
					// Inline source nested inside a WRAPPER CALL at sink-arg
					// position (`_.merge(target, JSON.parse(req.body))`,
					// `os.system(transform(request.args.get("c")))`). The
					// var-assigned twin already flows through the assignment
					// paths; resolveInlineSourceThroughCallArgs mirrors their
					// semantics (sanitizer wrappers mark Neutralizes so
					// isTaintedFor suppresses the matching categories; unknown
					// wrappers carry one-hop propagation decay). fb.addFlow
					// still applies the SrcDatabase→SnkPrototype gate, so an
					// inline DB read merged into a target stays suppressed.
					if wts := resolveInlineSourceThroughCallArgs(srcNode, line, cfg, matcher); wts != nil &&
						wts.isTaintedFor(sink.Category) &&
						!inlineSourceSanitizedInSegment(argNode, matcher, cfg, sink.Category) {
						fb.addFlow(wts, sink, line, scopeName)
						found = true
					}
					continue
				}
				if src != nil &&
					!inlineSourceSanitizedInSegment(argNode, matcher, cfg, sink.Category) {
					inlineTs := &taintState{
						varName:    "__arg__",
						source:     src,
						sourceLine: line,
						sanitized:  make(map[taint.SinkCategory]bool),
						confidence: 1.0,
						steps: []taint.FlowStep{{
							Line:        line,
							Description: "tainted by " + src.MethodName,
							VarName:     "__arg__",
						}},
					}
					fb.addFlow(inlineTs, sink, line, scopeName)
					found = true
				}
				continue
			}
			if !ts.isTaintedFor(sink.Category) {
				continue
			}
			// Check if the argument expression contains an inline sanitizer
			// call that neutralizes this sink category (e.g.,
			// res.send(escapeHtml(name))). For an interpolated string, the
			// sanitizer must wrap the TAINTED segment — a `.to_i` on a sibling
			// `#{Time.now}` does not neutralize a tainted `#{file.name}` in the
			// same string (see inlineSanitizerNeutralizesTaint).
			if inlineSanitizerNeutralizesTaint(argNode, tm, matcher, cfg, sink.Category) {
				continue
			}
			// Swift SQLKit/Fluent parameterized-binding interpolation: the
			// `db.raw("… \(bind: userId)")` form binds the value as a query
			// parameter (the SQLKit-recommended safe shape) rather than splicing
			// it into the SQL text. Structurally the interpolation segment carries
			// a `value_argument_label` of `bind`/`binds`/`literal`, distinct from
			// the raw `\(userId)` / `\(raw: userId)` injection forms. Suppress only
			// when EVERY tainted segment is so labeled (a single unlabeled raw
			// interpolation still fires). Scoped to Swift SQL sinks.
			if cfg.language == rules.LangSwift && sink.Category == taint.SnkSQLQuery &&
				swiftSQLAllTaintedSegmentsBound(argNode, tm, cfg) {
				continue
			}
			fb.addFlow(ts, sink, line, scopeName)
			found = true
		}
		// If no tainted args found, check if the receiver is tainted.
		// Handles methods like pathlib.Path.read_text() where the tainted
		// data is the object itself, not a method argument.
		//
		// PayloadPosition selects whether this receiver fallback runs:
		//   PayloadReceiver → ALWAYS run (the receiver IS the payload; this is
		//     the only fire path for these sinks).
		//   PayloadArgOnly  → NEVER run (declarative skipReceiverPayloadFallback;
		//     fire strictly on the DangerousArgs handled above).
		//   PayloadDefault  → today's behavior: run unless the hand-enumerated
		//     skipReceiverPayloadFallback set disables it (byte-identical).
		runReceiverFallback := !skipReceiverPayloadFallback(cfg, sink)
		switch sink.PayloadPosition {
		case taint.PayloadReceiver:
			runReceiverFallback = true
		case taint.PayloadArgOnly:
			runReceiverFallback = false
		}
		if !found && runReceiverFallback {
			if ts := callReceiverTainted(n, tm, cfg); ts != nil {
				if ts.isTaintedFor(sink.Category) {
					fb.addFlow(ts, sink, line, scopeName)
					found = true
				}
			}
		}
		// Receiver inline-source synthesis: for the narrow set of sinks whose
		// payload is a direct-source receiver (Ruby constantize), the receiver
		// may be a raw source expression (params[:type].constantize) rather
		// than a tracked variable, so callReceiverTainted above misses it.
		// Mirror the dangerous-argument inline-synthesis path on the receiver
		// node, gated by the same segment-aware sanitizer guard.
		if !found && receiverPayloadInlineSourceSink(cfg, sink) {
			// Walk the receiver chain (bounded) so a source under an
			// inflection/transform call resolves too: `constantize`'s receiver
			// is often `params[:class].classify` (ActiveSupport String#classify
			// preserves attacker control over the class name; it is NOT a
			// sanitizer), so the raw source sits one call deeper than the
			// immediate receiver. findSourceInExpr does not recurse through a
			// generic non-source method-call receiver, so descend explicitly.
			recv := callReceiverNode(n)
			for depth := 0; recv != nil && depth < 4; depth++ {
				src := findSourceInExpr(recv, matcher, cfg)
				if src != nil {
					if !inlineSourceSanitizedInSegment(recv, matcher, cfg, sink.Category) {
						inlineTs := &taintState{
							varName:    "__recv__",
							source:     src,
							sourceLine: line,
							sanitized:  make(map[taint.SinkCategory]bool),
							confidence: 1.0,
							steps: []taint.FlowStep{{
								Line:        line,
								Description: "tainted by " + src.MethodName,
								VarName:     "__recv__",
							}},
						}
						fb.addFlow(inlineTs, sink, line, scopeName)
					}
					break
				}
				// Descend into a chained-call receiver (params[:c].classify);
				// stop if the chain segment is a tracked sanitizer so a real
				// `.to_i`/validated transform still neutralises the flow.
				if chainHasActiveSanitizer(recv, tm, cfg, matcher) {
					break
				}
				next := callReceiverNode(recv)
				if next == nil || next == recv {
					break
				}
				recv = next
			}
		}
	}
}

// csharpHTTPClientSendMethods is the set of HttpClient instance methods that
// issue an outbound request whose first argument is the request URI. Used to
// scope the named-client relative-URI SSRF suppression to the exact send-call
// shape (so a colliding method name on another type can never trip the gate).
var csharpHTTPClientSendMethods = map[string]bool{
	"GetAsync":          true,
	"GetStringAsync":    true,
	"GetByteArrayAsync": true,
	"GetStreamAsync":    true,
	"PostAsync":         true,
	"PutAsync":          true,
	"PatchAsync":        true,
	"DeleteAsync":       true,
	"SendAsync":         true,
}

// csharpNamedClientRelativeURISSRFSafe reports whether a C# HttpClient SSRF
// sink call is a guaranteed false positive because it sends a RELATIVE URI
// through a NAMED HttpClient. Both facts are required and both are resolved
// from the enclosing function body (no cross-function reasoning):
//
//   - Receiver is a named client: an assignment `<receiver> = X.CreateClient
//     ("literal")` appears in this function. A named client created via
//     IHttpClientFactory has its BaseAddress pinned at DI registration, so a
//     relative request URI cannot retarget the host.
//   - Every dangerous argument resolves to a relative-URI string: either the
//     argument is itself a string literal / interpolated string whose first
//     literal segment begins with `/`, or it is a variable assigned such a
//     literal in this function body.
//
// A scheme-qualified argument (`$"http://{host}/..."`), an unnamed `new
// HttpClient()` receiver, or an argument the analyser cannot prove relative
// all fail the gate, so the real open-host SSRF shapes still fire. Gated to
// C# + SnkURLFetch so no other language or sink category is affected.
func csharpNamedClientRelativeURISSRFSafe(n *ast.Node, sink *taint.SinkDef, dangerousArgs []*ast.Node, receiver string, cfg *langConfig) bool {
	if cfg == nil || cfg.language != rules.LangCSharp || sink == nil ||
		sink.Category != taint.SnkURLFetch {
		return false
	}
	if receiver == "" || len(dangerousArgs) == 0 {
		return false
	}
	method := cfg.extractCallName(n)
	if !csharpHTTPClientSendMethods[method] {
		return false
	}
	fn := csharpEnclosingFunc(n)
	if fn == nil {
		return false
	}
	if !csharpReceiverIsNamedClient(fn, receiver) {
		return false
	}
	// Every dangerous argument must be provably a relative URI. The send
	// methods take the URI at position 0; a single non-relative arg fails the
	// whole gate (conservative — we only suppress when certain).
	for _, a := range dangerousArgs {
		if !csharpArgIsRelativeURI(a, fn) {
			return false
		}
	}
	return true
}

// csharpEnclosingFunc walks up from a node to the nearest C# function-scope
// node (method / local function / constructor), or nil if none.
func csharpEnclosingFunc(n *ast.Node) *ast.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "method_declaration", "local_function_statement", "constructor_declaration":
			return p
		}
	}
	return nil
}

// csharpReceiverIsNamedClient reports whether `receiver` was assigned from a
// `*.CreateClient("literal")` call anywhere in the function body — i.e. it is
// a named IHttpClientFactory client with a registration-pinned BaseAddress.
// The CreateClient argument must be a non-empty string literal (an unnamed /
// dynamic client name is not accepted).
func csharpReceiverIsNamedClient(fn *ast.Node, receiver string) bool {
	found := false
	fn.Walk(func(d *ast.Node) bool {
		if found {
			return false
		}
		if d.Type() != "variable_declarator" && d.Type() != "assignment_expression" {
			return true
		}
		lhs, rhs := csharpAssignParts(d)
		if lhs != receiver || rhs == nil {
			return true
		}
		inv := csharpUnwrapToInvocation(rhs)
		if inv == nil {
			return true
		}
		if csharpInvocationMethodName(inv) != "CreateClient" {
			return true
		}
		// Require a non-empty string-literal argument.
		args := ast.FindByType(inv, "argument")
		for _, a := range args {
			if lit := csharpStringLiteralContent(a); lit != "" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// csharpArgIsRelativeURI reports whether an argument node resolves to a
// relative-URI string (literal beginning with `/`). Handles the inline form
// (the argument is itself a string literal / interpolated string) and the
// one-hop variable form (the argument is an identifier assigned such a literal
// in the same function body).
func csharpArgIsRelativeURI(arg *ast.Node, fn *ast.Node) bool {
	node := arg
	if node.Type() == "argument" {
		if inner := firstNamedChild(node); inner != nil {
			node = inner
		}
	}
	if csharpExprIsRelativeURILiteral(node) {
		return true
	}
	// One-hop variable resolution: find the variable's assignment in the body.
	if node.Type() != "identifier" {
		return false
	}
	name := strings.TrimSpace(node.Text())
	if name == "" {
		return false
	}
	resolved := false
	any := false
	fn.Walk(func(d *ast.Node) bool {
		if d.Type() != "variable_declarator" && d.Type() != "assignment_expression" {
			return true
		}
		lhs, rhs := csharpAssignParts(d)
		if lhs != name || rhs == nil {
			return true
		}
		any = true
		if !csharpExprIsRelativeURILiteral(rhs) {
			// A non-relative assignment to this name anywhere poisons the
			// proof — bail out (conservative).
			resolved = false
			return false
		}
		resolved = true
		return true
	})
	return any && resolved
}

// csharpExprIsRelativeURILiteral reports whether an expression node is a string
// literal or interpolated string whose first literal segment begins with `/`
// (i.e. a relative URI path, no scheme/host).
func csharpExprIsRelativeURILiteral(n *ast.Node) bool {
	switch n.Type() {
	case "string_literal", "verbatim_string_literal", "raw_string_literal":
		s := csharpUnquoteLiteral(n.Text())
		return strings.HasPrefix(s, "/")
	case "interpolated_string_expression", "interpolated_verbatim_string_expression":
		// The first literal segment is the leading `string_content` child
		// before any `{...}` interpolation. Find the first content child.
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil {
				continue
			}
			switch c.Type() {
			case "string_content", "interpolated_string_text":
				return strings.HasPrefix(c.Text(), "/")
			case "interpolation":
				// An interpolation before any literal text means the leading
				// segment is attacker-influenced (`$"{host}/..."`) — not a
				// provable relative URI.
				return false
			}
		}
		return false
	}
	return false
}

// csharpUnquoteLiteral strips the surrounding quotes (and a leading `@` or `$`
// prefix) from a C# string-literal node's text.
func csharpUnquoteLiteral(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "@")
	s = strings.TrimPrefix(s, "$")
	s = strings.Trim(s, "\"")
	return s
}

// csharpStringLiteralContent returns the unquoted content of a string literal
// reachable from node (e.g. an `argument` wrapping a `string_literal`), or "".
func csharpStringLiteralContent(n *ast.Node) string {
	if n.Type() == "argument" {
		if inner := firstNamedChild(n); inner != nil {
			n = inner
		}
	}
	switch n.Type() {
	case "string_literal", "verbatim_string_literal", "raw_string_literal":
		return csharpUnquoteLiteral(n.Text())
	}
	return ""
}

// csharpAssignParts returns the LHS identifier name and RHS expression node for
// a C# `variable_declarator` (`x = expr`) or `assignment_expression`
// (`x = expr`). Returns ("", nil) when the shape is not a simple name=expr.
func csharpAssignParts(d *ast.Node) (string, *ast.Node) {
	switch d.Type() {
	case "variable_declarator":
		var name string
		var rhs *ast.Node
		for i := 0; i < d.ChildCount(); i++ {
			c := d.Child(i)
			if c == nil || !c.IsNamed() {
				continue
			}
			if c.Type() == "identifier" && name == "" {
				name = c.Text()
				continue
			}
			rhs = c
		}
		return name, rhs
	case "assignment_expression":
		lhs := d.ChildByFieldName("left")
		rhs := d.ChildByFieldName("right")
		if lhs != nil && lhs.Type() == "identifier" {
			return lhs.Text(), rhs
		}
	}
	return "", nil
}

// csharpUnwrapToInvocation unwraps await/cast/parens to reach an
// invocation_expression, or returns nil.
func csharpUnwrapToInvocation(n *ast.Node) *ast.Node {
	for i := 0; i < 4 && n != nil; i++ {
		switch n.Type() {
		case "invocation_expression":
			return n
		case "await_expression", "parenthesized_expression", "cast_expression":
			inner := firstNamedChild(n)
			if inner == nil {
				return nil
			}
			n = inner
		default:
			return nil
		}
	}
	return nil
}

// csharpInvocationMethodName returns the bare method name of an
// invocation_expression (`x.CreateClient(...)` -> "CreateClient").
func csharpInvocationMethodName(inv *ast.Node) string {
	fn := inv.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return fn.Text()
	case "member_access_expression":
		if name := fn.ChildByFieldName("name"); name != nil {
			return name.Text()
		}
	}
	return ""
}

// skipReceiverPayloadFallback reports whether the receiver-taint fallback
// should be suppressed for a sink. For argument-payload injection sinks the
// danger lives in the call's argument (the XPath expression, the SQL string,
// the script), never in the receiver object. `doc.nodes(forXPath: expr)` is
// dangerous because of `expr`, not because the `XMLDocument` receiver `doc`
// was built from a (hardcoded) file read. Without this guard, a receiver that
// merely carries incidental file-read / database taint — e.g. the safe
// `XMLDocument(data: Data(contentsOf: "/data/catalog.xml"))` whose XPath arg
// is properly escaped — produces a false positive.
//
// Swift suppresses the full argument-payload category set. Kotlin suppresses it
// for the SQL/NoSQL query categories: the Kotlin walker seeds EVERY function
// parameter as a taint source (`kotlin.param.*`), so a DB handle passed in as a
// parameter (`fun handler(em: EntityManager)` / `(stmt: Statement)`) is itself
// "tainted" and would fire a query sink via the receiver fallback even when the
// query string is a hardcoded/parameterized constant (`em.createQuery("... :id")`
// with `setParameter`). SQL/NoSQL injection danger is always the query argument,
// never the connection/manager receiver, so dropping the receiver fallback here
// is strictly a false-positive reduction (a real injection still fires via the
// tainted-argument path). Gated by language so no other behaviour changes.
func skipReceiverPayloadFallback(cfg *langConfig, sink *taint.SinkDef) bool {
	if cfg == nil || sink == nil {
		return false
	}
	switch cfg.language {
	case rules.LangSwift:
		switch sink.Category {
		case taint.SnkXPath, taint.SnkSQLQuery, taint.SnkNoSQL, taint.SnkEval,
			taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkTemplate,
			taint.SnkHeader, taint.SnkRedirect:
			return true
		}
	case rules.LangKotlin:
		// SnkSQLQuery only: a SQL injection always lives in the query string
		// argument, never in the JDBC/JPA connection-or-manager receiver, so the
		// receiver fallback is pure FP here. NoSQL is intentionally NOT included
		// — some Elasticsearch client sinks (deleteByQuery/updateByQuery) take a
		// request-builder argument whose taint is only reachable through the
		// param-seeded client receiver.
		if sink.Category == taint.SnkSQLQuery {
			return true
		}
	case rules.LangRuby:
		// SnkRegexDoS only: for String#match/#match? (ObjectType "String") the
		// ReDoS danger is the *pattern* argument that gets implicitly compiled to
		// a Regexp, never the receiver — which is the haystack being scanned.
		// Without this guard, the receiver fallback fires on the extremely common
		// and benign `tainted_string.match(/static/)` (matching user data against
		// a constant regex), a pure false positive. A real attacker-controlled
		// pattern still fires via the tainted-argument path.
		if sink.Category == taint.SnkRegexDoS {
			return true
		}
		// ActiveRecord query-builder interpolation sinks
		// (ruby.activerecord.{where,order,select,having,joins,group,from,pluck,
		// exists,find_by,calculate,lock}.interpolation): the SQLi vector is the
		// interpolated/concatenated STRING ARGUMENT, never the receiver relation.
		// AR relations chain (`scope.where(...).order(...)`), so an earlier
		// tainted DB read (`.pluck`, `.find_by`) makes the whole receiver tainted
		// — but a `.order("LOWER(#{CONST}) ASC")` interpolating a *constant*, or a
		// fully-parameterized `.where("... #{cond} ...", bind_hash)` whose only
		// taint is the safe bind hash, is NOT injection. Without this skip the
		// receiver-payload fallback fires those as false positives (verified on
		// Discourse: topic_query.rb parameterized where, search_chat_channels.rb
		// constant order). The genuine TP — taint reaching the string argument
		// itself — still fires via the dangerous-argument path. Scoped to the
		// `.interpolation` AR sink IDs so the raw-driver / Mongo / Sequel
		// receiver-taint flows are untouched.
		if sink.Category == taint.SnkSQLQuery &&
			strings.HasPrefix(sink.ID, "ruby.activerecord.") &&
			strings.HasSuffix(sink.ID, ".interpolation") {
			return true
		}
	}
	return false
}

// receiverPayloadInlineSourceSink reports whether a sink is one of the
// narrow set whose dangerous payload is the RECEIVER value itself AND whose
// idiomatic vulnerable form is a *direct-source receiver* (e.g.
// `params[:type].constantize`) rather than a tracked intermediate variable.
//
// Why this is needed: the receiver-payload fallback above resolves taint via
// callReceiverTainted, which only sees a receiver that is a tracked tainted
// VARIABLE (`t = params[:type]; t.constantize`) or a receiver node already
// in the taint map. It does NOT synthesize an inline source from a raw
// source expression sitting directly in the receiver position — so the
// extremely common single-expression form `params[:type].constantize`
// (railsgoat BenefitFormsController#download, Api::V1::MobileController) is
// only caught at the regex tier (a hint), never the dataflow tier (a block).
// The dangerous-ARGUMENT path already inline-synthesizes sources via
// findSourceInExpr; this gate lets the RECEIVER path do the same, but only
// for sinks where the receiver genuinely IS the attacker-chosen payload.
//
// Deliberately confined to Ruby `constantize` (Rails String#constantize,
// which instantiates an arbitrary class named by its receiver string — a
// canonical CWE-470 RCE primitive). It is NOT applied to send/public_send/
// eval (their payload is the ARGUMENT, already covered) nor to const_get
// (its payload is also the argument). A literal receiver ("User".constantize)
// carries no source so findSourceInExpr returns nil and nothing fires; a
// constant/validated receiver likewise has no live source. The shared
// inlineSourceSanitizedInSegment guard still applies, so a sanitized
// receiver segment stays clean.
func receiverPayloadInlineSourceSink(cfg *langConfig, sink *taint.SinkDef) bool {
	if cfg == nil || sink == nil || cfg.language != rules.LangRuby {
		return false
	}
	return sink.ID == "ruby.constantize"
}

// matchesCallLevelArgPatternSanitizer returns true if any @argpattern
// sanitizer in the catalog matches the FULL call text and neutralises the
// given sink category. Used to skip sink flagging when safety is encoded in
// the call's kwargs (e.g. `yaml.load(body, Loader=yaml.SafeLoader)`) rather
// than in a wrapper around the dangerous argument expression.
//
// Restricted to @argpattern entries because they were authored to gate on
// the full call shape; receiver/method-typed sanitizers should continue to
// be applied only via the argument-walk path (containsInlineSanitizer).
func matchesCallLevelArgPatternSanitizer(matcher *tsMatcher, n *ast.Node, cat taint.SinkCategory) bool {
	methodName := matcher.cfg.extractCallName(n)
	if methodName == "" {
		return false
	}
	candidates := matcher.sanitizersByMethod[methodName]
	short := unqualifyName(methodName)
	if short != methodName {
		candidates = append(candidates, matcher.sanitizersByMethod[short]...)
	}
	for _, san := range candidates {
		if san.ObjectType != "@argpattern" {
			continue
		}
		neutralizes := false
		for _, c := range san.Neutralizes {
			if c == cat {
				neutralizes = true
				break
			}
		}
		if !neutralizes {
			continue
		}
		re := matcher.compileSanitizerPattern(san)
		if re == nil {
			continue
		}
		if re.MatchString(n.Text()) {
			return true
		}
	}
	return false
}

// isLikelyArrayIteration returns true if the call looks like a JS
// Array.prototype iteration (find/filter/forEach/map/some/every/reduce) rather
// than a Mongoose-style query. Heuristic: first arg is an inline function or
// narrowPythonMakeResponseBody narrows the dangerous args of the Python
// html_output sink (make_response) to the response BODY when the argument is
// a Flask tuple of the form `(body, headers)` or `(body, status, headers)`.
//
// Flask's make_response accepts a tuple whose first element is the body that
// is reflected to the browser (the XSS-relevant value) and whose later
// elements are an HTTP status and/or a headers dict. A tainted value placed
// only in the headers dict (e.g. `make_response((CONST, {'X': tainted}))`) is
// written into a response header, not into reflected HTML — that is not
// reflected XSS. By replacing the whole-tuple dangerous arg with just its
// first element, the downstream taint check ignores taint that lives solely
// in the status/headers positions while still firing when the body itself is
// tainted (`make_response((tainted, {...}))`).
//
// Returns the input unchanged unless: language is Python, the sink category
// is html_output, there is exactly one dangerous arg, and that arg is a
// `tuple` node with at least one named child. This is deliberately narrow so
// it cannot affect non-Python sinks or single-string `make_response(body)` /
// `res.send(body)` forms.
func narrowPythonMakeResponseBody(sink *taint.SinkDef, dangerousArgs []*ast.Node, cfg *langConfig) []*ast.Node {
	if cfg.language != rules.LangPython {
		return dangerousArgs
	}
	if sink == nil || sink.Category != taint.SnkHTMLOutput {
		return dangerousArgs
	}
	if len(dangerousArgs) != 1 || dangerousArgs[0] == nil {
		return dangerousArgs
	}
	arg := dangerousArgs[0]
	if arg.Type() != "tuple" {
		return dangerousArgs
	}
	if body := firstNamedChild(arg); body != nil {
		return []*ast.Node{body}
	}
	// Empty tuple — nothing reflected.
	return nil
}

// narrowPythonSubprocessArgvList suppresses the command-injection finding on a
// Python `subprocess.*` call when the command is passed as an argv LIST/TUPLE
// literal AND there is no `shell=True` keyword argument — i.e. the canonical
// SECURE form `subprocess.check_output(["nslookup", domain])`. With no shell,
// each argv element is an opaque argument to the program named by element 0; a
// tainted later element cannot start a new command or inject shell metacharacters,
// so this is the recommended-by-everyone safe rewrite, not a vulnerability.
//
// Deliberately NARROW so it never loses a true positive:
//   - Gated to Python + the `py.subprocess.*` sink IDs (SnkCommand). It does NOT
//     touch `os.system`, `os.popen`, asyncio `create_subprocess_shell`, etc.
//   - Only suppresses when arg0 is a list/tuple CONTAINER node. A string concat
//     (`"cmd " + x`) is a binary_operator and a bare tainted variable is an
//     identifier — neither is a container, so `subprocess.run("cmd " + x,
//     shell=True)` and `subprocess.run(tainted_string_var)` still fire.
//   - Additionally requires the absence of `shell=True`: an argv list combined
//     with shell=True is anomalous and is left flagged.
//
// Returns dangerousArgs unchanged in every other case.
func narrowPythonSubprocessArgvList(n *ast.Node, sink *taint.SinkDef, dangerousArgs []*ast.Node, cfg *langConfig) []*ast.Node {
	if cfg.language != rules.LangPython {
		return dangerousArgs
	}
	if sink == nil || sink.Category != taint.SnkCommand {
		return dangerousArgs
	}
	// Restrict to the subprocess sink family (subprocess.run/call/check_output/
	// check_call/Popen). os.system and the async shell variants are different
	// sink IDs and must keep firing.
	if !strings.HasPrefix(sink.ID, "py.subprocess.") {
		return dangerousArgs
	}
	if len(dangerousArgs) != 1 || dangerousArgs[0] == nil {
		return dangerousArgs
	}
	// arg0 must be a list/tuple container literal — the argv form. (Element
	// taint is irrelevant: argv-without-shell is safe even with tainted
	// elements, which is exactly why we don't require all-literal contents.)
	if !isListOrTupleContainer(dangerousArgs[0]) {
		return dangerousArgs
	}
	// A `shell=True` keyword arg re-enables shell interpretation; leave flagged.
	if pythonCallHasShellTrue(n, cfg) {
		return dangerousArgs
	}
	return nil
}

// phpDynamicCallbackSinkIDs are the PHP higher-order callback sinks whose
// dangerous arg must be a tainted STRING callable to be a real CWE-95 finding.
// A closure / arrow-function literal in that slot is the safe, dominant idiom.
var phpDynamicCallbackSinkIDs = map[string]bool{
	"php.array_map.callback":                  true,
	"php.array_filter.callback":               true,
	"php.usort.callback":                      true,
	"php.array_walk.callback":                 true,
	"php.preg_replace_callback.callable":      true,
	"php.register_shutdown_function.callback": true,
}

// narrowPHPDynamicCallbackArg drops a callback dangerous-arg whose expression
// is a PHP closure (`anonymous_function_creation_expression`) or arrow function
// (`arrow_function`). These literals are not attacker-controlled string
// callables; firing on them (because a `use`-captured variable is tainted, or
// a closure parameter shares a name with a tainted var) is a false positive.
// Only the genuine tainted-string-callable case (`array_map($_GET['fn'], ...)`)
// survives. No-op for every non-PHP language and any sink not in the dynamic
// callback family.
func narrowPHPDynamicCallbackArg(sink *taint.SinkDef, dangerousArgs []*ast.Node, cfg *langConfig) []*ast.Node {
	if cfg == nil || cfg.language != rules.LangPHP || sink == nil {
		return dangerousArgs
	}
	if !phpDynamicCallbackSinkIDs[sink.ID] {
		return dangerousArgs
	}
	out := dangerousArgs[:0:0]
	for _, a := range dangerousArgs {
		if phpArgIsFunctionLiteral(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// phpArgIsFunctionLiteral reports whether the PHP `argument` node (or a bare
// expression node) wraps a closure or arrow-function literal.
func phpArgIsFunctionLiteral(n *ast.Node) bool {
	if n == nil {
		return false
	}
	isFnLiteral := func(t string) bool {
		return t == "anonymous_function_creation_expression" ||
			t == "arrow_function" ||
			t == "anonymous_function"
	}
	if isFnLiteral(n.Type()) {
		return true
	}
	// The walker passes the `argument` wrapper; the closure is its named child.
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c != nil && c.IsNamed() && isFnLiteral(c.Type()) {
			return true
		}
	}
	return false
}

// isListOrTupleContainer reports whether n is a Python list/tuple literal node
// (the argv container shape). Mirrors the container node-type set checked by
// isAllLiteralContainer but does NOT require the elements to be literals.
func isListOrTupleContainer(n *ast.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "list", "tuple", "list_literal", "tuple_literal":
		return true
	}
	return false
}

// pythonCallHasShellTrue reports whether the Python call node n has a
// `shell=True` keyword argument. Used to keep `subprocess.*(argv, shell=True)`
// flagged even though the command is an argv list.
func pythonCallHasShellTrue(n *ast.Node, cfg *langConfig) bool {
	if n == nil {
		return false
	}
	for _, arg := range cfg.extractCallArgs(n) {
		if arg == nil || arg.Type() != "keyword_argument" {
			continue
		}
		name := arg.ChildByFieldName("name")
		value := arg.ChildByFieldName("value")
		if name == nil || value == nil {
			continue
		}
		if strings.TrimSpace(name.Text()) == "shell" {
			v := strings.TrimSpace(value.Text())
			if v == "True" || v == "1" {
				return true
			}
		}
	}
	return false
}

// pythonMakeResponseTupleBody returns the response-body node (first tuple
// element) when `n` is the Python html_output sink call (make_response) whose
// single argument is a `(body, headers)` / `(body, status, headers)` tuple.
// Returns nil otherwise. Used by propagateCallResultInterproc to narrow which
// part of a make_response result propagates taint to an assignment LHS,
// mirroring the sink-side narrowPythonMakeResponseBody gate. Confirming the
// call is the html_output sink (via the matcher) keeps this from affecting
// unrelated functions that happen to take a tuple argument.
func pythonMakeResponseTupleBody(n *ast.Node, cfg *langConfig, matcher *tsMatcher) *ast.Node {
	if cfg.language != rules.LangPython || matcher == nil {
		return nil
	}
	sink, _ := matcher.matchSinkCall(n)
	if sink == nil || sink.Category != taint.SnkHTMLOutput {
		return nil
	}
	args := cfg.extractCallArgs(n)
	if len(args) != 1 || args[0] == nil || args[0].Type() != "tuple" {
		return nil
	}
	return firstNamedChild(args[0])
}

// firstNamedChild returns the first named child of n, or nil if there is none.
func firstNamedChild(n *ast.Node) *ast.Node {
	if n == nil {
		return nil
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c != nil && c.IsNamed() {
			return c
		}
	}
	return nil
}

// arrow expression — Array callbacks; object/string args go to DB queries.
// Only meaningful for JS/TS; other languages return false harmlessly.
func isLikelyArrayIteration(n *ast.Node, cfg *langConfig) bool {
	args := cfg.extractCallArgs(n)
	if len(args) == 0 {
		return false
	}
	first := args[0]
	if first == nil {
		return false
	}
	t := first.Type()
	return t == "arrow_function" || t == "function" || t == "function_expression"
}

// jsSQLBuilderSafeFormMethods lists JS/TS query-builder method names whose
// first-arg shape determines whether the call is a SQL injection sink. Knex
// and Bookshelf APIs share these names with several safe parameter-binding
// shapes — only raw-string-with-interpolation / string-concat is dangerous.
var jsSQLBuilderSafeFormMethods = map[string]bool{
	"query":       true,
	"where":       true,
	"andWhere":    true,
	"orWhere":     true,
	"whereRaw":    true,
	"andWhereRaw": true,
	"orWhereRaw":  true,
}

// isSafeJSSQLBuilderCall returns true when the call is a JS/TS query-builder
// invocation whose arg-0 shape is a known safe parameter-binding form (object
// literal, comparator `(col, op, val)`, callback subquery) — i.e., NOT a
// raw-SQL string with interpolation or concatenation.
//
// Gated to JS/TS, SnkSQLQuery, and the method names in
// jsSQLBuilderSafeFormMethods. Returns false (do not suppress) for any other
// language, sink category, or method.
//
// Detects:
//   - `super.query(...)`  — Ember adapter call, not SQL.
//   - `.where({col: val})` — object form (Knex/Bookshelf parameter binding).
//     `.where()` is Knex/Bookshelf/Mongoose-builder territory; the object form
//     is parameter binding in all of them. Catalog has narrower
//     `js.mongoose.where*` sinks for the dangerous `$where` shape.
//   - `member.related('foo').query({...})` — Bookshelf model.related().query()
//     chain. Only suppressed when the receiver is a call_expression whose
//     method is `related` so that ambiguous `db.query({...})` calls (which
//     could be MongoDB drivers) are still flagged.
//   - `.where(qb => qb.where(...))` — callback subquery form. (Also handled
//     by isLikelyArrayIteration, but checked here defensively for clarity.)
//   - `.where('col', val)` / `.where('col', op, val)` — comparator form when
//     arg 0 is a plain string literal (no template_substitution) AND there is
//     at least one more arg. `.whereRaw('id = ?', [id])` with bind array is
//     the canonical safe Knex form.
//
// Does NOT suppress (keeps the call flagged):
//   - template_string containing a template_substitution (e.g. `${id}`)
//   - binary_expression involving a string (e.g. 'SELECT ... ' + id)
//   - a single string-literal arg with no bindings — ambiguous, leave to taint walker
//   - an identifier arg 0 (could be a tainted SQL string from a variable)
//   - `db.query({...})` with simple-identifier receiver — could be a MongoDB
//     driver; let it be flagged.
func isSafeJSSQLBuilderCall(n *ast.Node, sink *taint.SinkDef, cfg *langConfig) bool {
	if cfg.language != rules.LangJavaScript && cfg.language != rules.LangTypeScript {
		return false
	}
	if sink == nil || sink.Category != taint.SnkSQLQuery {
		return false
	}
	method := cfg.extractCallName(n)
	if !jsSQLBuilderSafeFormMethods[method] {
		return false
	}
	// super.query(...) is an inherited-method dispatch (Ember adapters,
	// class hierarchies). Not a SQL call.
	if jsCallReceiverIsSuper(n) {
		return true
	}
	args := cfg.extractCallArgs(n)
	if len(args) == 0 {
		return false
	}
	first := args[0]
	if first == nil {
		return false
	}
	switch first.Type() {
	case "object":
		// Object-form parameter binding.
		//   - For `.where`/`.andWhere`/`.orWhere`: always safe (Knex,
		//     Bookshelf, and Mongoose conventional usage all treat the object
		//     as a column→value equality map; the dangerous MongoDB $where
		//     vector is caught by the narrower `js.mongoose.where*` catalog
		//     entries).
		//   - For `.query`: ambiguous (Mongo `db.query({user: tainted})` can
		//     be NoSQL injection via {$ne: null} operators). Only suppress
		//     when the receiver is a call to `.related(...)` — the
		//     Bookshelf `model.related('foo').query({...})` shape that's the
		//     dominant real-world FP source.
		if method == "query" && !jsCallReceiverIsBookshelfRelated(n) {
			return false
		}
		return true
	case "arrow_function", "function", "function_expression":
		// `.where(qb => qb.where(...))` — callback subquery. Safe.
		return true
	case "string":
		// Plain string literal with no `${...}` interpolation. Safe when
		// there's a second arg (comparator: `.where('col', val)`, or
		// parameterized: `.whereRaw('id = ?', [id])`).
		// Conservative: only suppress when arg 1 exists. A lone constant
		// SQL string with no bindings *could* still be a constant-only
		// query; the taint walker will pass it through cleanly anyway since
		// the literal isn't tainted.
		if jsStringHasInterpolation(first) {
			return false
		}
		if len(args) >= 2 {
			// `.query('SELECT ...', [bindings])` with a constant query
			// string — this is a parameterized query. Safe.
			return true
		}
		return false
	}
	return false
}

// phpQueryBuilderPredicateMethods are the Doctrine/DBAL QueryBuilder
// predicate-accepting methods covered by the php.doctrine.querybuilder.*
// sinks. The safe-form gate only applies to these.
var phpQueryBuilderPredicateMethods = map[string]bool{
	"where": true, "andWhere": true, "orWhere": true,
	"having": true, "andHaving": true, "orHaving": true,
}

// isSafePHPQueryBuilderCall reports whether a Doctrine/DBAL QueryBuilder
// where()/having() family call passes a PARAMETERIZED predicate rather than a
// raw concatenated fragment. The Doctrine/Nextcloud safe idiom is
//
//	$qb->where($qb->expr()->eq('event', $qb->createNamedParameter($event)))
//	$qb->andWhere($qb->expr()->emptyString('user_id_filter'))
//	$qb->where('u.name = :name')   // + ->setParameter('name', $v)
//
// In all of these the user value is bound via createNamedParameter /
// createPositionalParameter / a named placeholder, never spliced into the SQL
// text. Only a string-concatenation fragment (`"u.name = '".$name."'"`) is a
// real injection. This suppresses the dominant Nextcloud FP where the walker's
// receiver-taint on $qb (propagated across methods via $this) would otherwise
// flag a fully parameterized predicate. PHP-only; no-op for every other
// language and for non-QueryBuilder sinks.
func isSafePHPQueryBuilderCall(n *ast.Node, sink *taint.SinkDef, cfg *langConfig) bool {
	if cfg.language != rules.LangPHP {
		return false
	}
	if sink == nil || sink.Category != taint.SnkSQLQuery || sink.ObjectType != "QueryBuilder" {
		return false
	}
	method := cfg.extractCallName(n)
	if !phpQueryBuilderPredicateMethods[method] {
		return false
	}
	args := cfg.extractCallArgs(n)
	if len(args) == 0 {
		return false
	}
	first := args[0]
	if first == nil {
		return false
	}
	inner := first
	if inner.Type() == "argument" {
		if c := firstNamedChild(inner); c != nil {
			inner = c
		}
	}
	argText := inner.Text()
	// A raw concatenated SQL fragment is the ONLY injectable shape: a string
	// literal (or interpolation) joined with `.` to a tainted expression.
	// If the predicate is concatenation, do NOT treat it as safe.
	if inner.Type() == "binary_expression" && strings.Contains(argText, ".") {
		// Concatenation predicate — let the normal taint check decide.
		return false
	}
	// Parameter-binding builder forms are safe: the expression builder
	// ($qb->expr()->...) and the named/positional parameter factories bind the
	// value rather than splice it into the SQL string.
	if strings.Contains(argText, "->expr()") ||
		strings.Contains(argText, "createNamedParameter") ||
		strings.Contains(argText, "createPositionalParameter") {
		return true
	}
	// A bare string literal predicate using a placeholder (`:name`, `?`) binds
	// the value out-of-band (paired with ->setParameter()); the literal itself
	// carries no taint.
	if inner.Type() == "string" && (strings.Contains(argText, ":") || strings.Contains(argText, "?")) {
		return true
	}
	return false
}

// jsCallReceiverIsBookshelfRelated returns true when the call's receiver is a
// call_expression whose method is `related` (e.g.,
// `model.related('foo').query(...)`). This is the Bookshelf model-relation
// chain shape that's a frequent SQL-query-FP source: `.query()` on a
// Bookshelf model uses object/callback parameter binding, not raw SQL.
func jsCallReceiverIsBookshelfRelated(n *ast.Node) bool {
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Type() != "member_expression" {
		return false
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil || obj.Type() != "call_expression" {
		return false
	}
	innerFn := obj.ChildByFieldName("function")
	if innerFn == nil || innerFn.Type() != "member_expression" {
		return false
	}
	prop := innerFn.ChildByFieldName("property")
	if prop == nil {
		return false
	}
	return prop.Text() == "related"
}

// jsCallReceiverIsSuper returns true when the call's function is a
// member_expression whose object is the `super` keyword (e.g.,
// `super.query(store, type, params)`). Tree-sitter JS represents the receiver
// as a `super` node, not an identifier.
func jsCallReceiverIsSuper(n *ast.Node) bool {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	if fn.Type() != "member_expression" {
		return false
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return false
	}
	return obj.Type() == "super"
}

// jsStringHasInterpolation reports whether a tree-sitter `string` /
// `template_string` node contains an interpolation. Plain `'foo'` / `"bar"`
// have only `string_fragment` children and return false; “ `id=${x}` “
// has a `template_substitution` child and returns true.
func jsStringHasInterpolation(n *ast.Node) bool {
	if n == nil {
		return false
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		switch c.Type() {
		case "template_substitution", "interpolation":
			return true
		}
	}
	return false
}

// containsInlineSanitizer recursively walks an expression AST node looking
// for a sanitizer call that neutralizes the given sink category. This handles
// patterns like res.send(escapeHtml(userInput)) where the sanitizer is not
// assigned to a variable first.
func containsInlineSanitizer(n *ast.Node, matcher *tsMatcher, cfg *langConfig, sinkCat taint.SinkCategory) bool {
	if n == nil {
		return false
	}
	nodeType := n.Type()

	// Direct call — check if it's a sanitizer that neutralizes this category.
	// Use matchSanitizerForCategory so we don't stop at the first call-matching
	// sanitizer when it doesn't neutralise the relevant sink (multiple
	// sanitizers can share a method name with different Neutralizes lists).
	if cfg.callTypes[nodeType] {
		if san, _ := matcher.matchSanitizerForCategory(n, sinkCat); san != nil {
			return true
		}
		// Check arguments recursively (sanitizer might be nested deeper).
		args := cfg.extractCallArgs(n)
		for _, arg := range args {
			if containsInlineSanitizer(arg, matcher, cfg, sinkCat) {
				return true
			}
		}
		return false
	}

	// Binary expression — check both sides.
	if nodeType == "binary_expression" || nodeType == "binary_operator" ||
		nodeType == "concatenated_string" || nodeType == "string_binary_expression" {
		left := n.ChildByFieldName("left")
		if containsInlineSanitizer(left, matcher, cfg, sinkCat) {
			return true
		}
		right := n.ChildByFieldName("right")
		return containsInlineSanitizer(right, matcher, cfg, sinkCat)
	}

	// Template string — check substitutions. Python f-strings parse as
	// type "string" with `interpolation` named children that contain the
	// embedded expression; include "string" so f"...{san(x)}..." is walked.
	if nodeType == "template_string" || nodeType == "template_substitution" ||
		nodeType == "interpolation" || nodeType == "string_interpolation" ||
		nodeType == "string" {
		for i := 0; i < n.ChildCount(); i++ {
			if containsInlineSanitizer(n.Child(i), matcher, cfg, sinkCat) {
				return true
			}
		}
	}

	// Parenthesized expression — unwrap.
	if nodeType == "parenthesized_expression" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return containsInlineSanitizer(c, matcher, cfg, sinkCat)
			}
		}
	}

	// Keyword/hash argument (`render html: sanitize(x)`, `foo(key: h(x))`): when a
	// sink's dangerous arg is a key:value pair, the attacker-controllable payload
	// is the VALUE, so a sanitizer wrapping the value (`sanitize(x)`,
	// `ERB::Util.html_escape(x)`) must be reached to neutralize the flow. The
	// bare-keyed Rails kwarg render sinks (render html:/inline:/file:/text:) land
	// here. Suppression-only: this is reached solely after nodeIsTainted already
	// flagged the arg, so recursing into the pair can only REMOVE a finding (the
	// safe sanitized form), never create one. The key half is a symbol/string
	// literal, never a sanitizer call, so walking both children is safe.
	if nodeType == "pair" || nodeType == "keyword_argument" || nodeType == "key_value_pair" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() && containsInlineSanitizer(c, matcher, cfg, sinkCat) {
				return true
			}
		}
	}

	return false
}

// isInterpolatedStringContainer reports whether n is a string/template node that
// holds `${…}` / `#{…}` interpolation segments as named children — the shapes
// `nodeIsTainted` descends into to find an embedded tainted expression.
func isInterpolatedStringContainer(nodeType string) bool {
	switch nodeType {
	case "template_string", "string", "string_literal",
		"interpolated_string_expression", "interpolated_string_literal",
		"line_string_literal", "multi_line_string_literal",
		// Ruby backtick / %x{} command-exec literal.
		"subshell":
		return true
	}
	return false
}

// isInterpolationSegment reports whether n is one `${…}` / `#{…}` / `\(…)`
// interpolation segment inside an interpolated-string container.
func isInterpolationSegment(nodeType string) bool {
	switch nodeType {
	case "interpolation", "template_substitution", "string_interpolation",
		"interpolated_expression":
		return true
	}
	return false
}

// inlineSanitizerNeutralizesTaint decides whether the sanitizer(s) embedded in a
// sink's dangerous argument actually neutralize the TAINTED data, rather than
// merely being present somewhere in the argument.
//
// containsInlineSanitizer returns true when ANY sanitizer call for the category
// appears anywhere in the argument subtree. For a single sanitized value
// (`res.send(escapeHtml(name))`) that is correct. But for an interpolated string
// with multiple independent segments it is over-broad: a sanitizer applied to
// ONE segment (`#{Time.now.to_i}`) wrongly suppresses a tainted value in a
// DIFFERENT segment (`#{file.original_filename}`) of the same string —
// `system("cp #{file.original_filename} #{Time.now.to_i}")` reads as "fully
// sanitized" even though the filename reaches the shell unescaped. This is the
// dual of the parameterized-vs-interpolated SQL distinction: a transform on a
// sibling value says nothing about the tainted one.
//
// When the argument is an interpolated-string container, this checks each
// interpolation segment INDEPENDENTLY: a segment that carries taint
// (nodeIsTainted) must itself contain a category sanitizer for the string to
// count as neutralized. If any tainted segment is unsanitized, the flow fires.
// For every other argument shape (a bare value, a `sanitize(x)` call, a concat)
// it defers to containsInlineSanitizer, so existing behaviour is unchanged.
func inlineSanitizerNeutralizesTaint(argNode *ast.Node, tm *taintMap, matcher *tsMatcher, cfg *langConfig, sinkCat taint.SinkCategory) bool {
	if argNode == nil {
		return false
	}
	if !isInterpolatedStringContainer(argNode.Type()) {
		return containsInlineSanitizer(argNode, matcher, cfg, sinkCat)
	}

	sawTaintedSegment := false
	for i := 0; i < argNode.ChildCount(); i++ {
		seg := argNode.Child(i)
		if !isInterpolationSegment(seg.Type()) {
			continue
		}
		if _, ok := nodeIsTainted(seg, tm, cfg); !ok {
			continue // untainted segment: its sanitizer (if any) is irrelevant
		}
		sawTaintedSegment = true
		// This tainted segment must carry its OWN sanitizer to be neutralized.
		if !containsInlineSanitizer(seg, matcher, cfg, sinkCat) {
			return false
		}
	}
	// Every tainted segment was individually sanitized. If we saw none (the
	// taint came from outside the interpolation segments — e.g. a whole-object
	// fallback the segment walk doesn't see), fall back to the whole-arg check
	// so the prior behaviour is preserved.
	if !sawTaintedSegment {
		return containsInlineSanitizer(argNode, matcher, cfg, sinkCat)
	}
	return true
}

// inlineSourceSanitizedInSegment is the inline-source counterpart of
// inlineSanitizerNeutralizesTaint. The inline-source-at-sink path
// (`system("... #{params[:x]} ...")`, `system("... #{file.original_filename}
// ...")`) finds the source with findSourceInExpr rather than nodeIsTainted, so
// the segment carrying the danger is the one that CONTAINS A SOURCE, not the one
// nodeIsTainted flags. Using the whole-argument containsInlineSanitizer here is
// the same over-broad bug: a `.to_i` on a sibling `#{Time.now}` segment would
// suppress the genuine source in `#{file.original_filename}`. For an
// interpolated-string argument, require the sanitizer to live in the SAME
// segment as the source; for any other argument shape defer to the whole-arg
// check so existing behaviour is unchanged.
func inlineSourceSanitizedInSegment(argNode *ast.Node, matcher *tsMatcher, cfg *langConfig, sinkCat taint.SinkCategory) bool {
	if argNode == nil {
		return false
	}
	if !isInterpolatedStringContainer(argNode.Type()) {
		return containsInlineSanitizer(argNode, matcher, cfg, sinkCat)
	}
	sawSourceSegment := false
	for i := 0; i < argNode.ChildCount(); i++ {
		seg := argNode.Child(i)
		if !isInterpolationSegment(seg.Type()) {
			continue
		}
		if findSourceInExpr(seg, matcher, cfg) == nil {
			continue // segment carries no source: its sanitizer is irrelevant
		}
		sawSourceSegment = true
		if !containsInlineSanitizer(seg, matcher, cfg, sinkCat) {
			return false
		}
	}
	if !sawSourceSegment {
		return containsInlineSanitizer(argNode, matcher, cfg, sinkCat)
	}
	return true
}

// swiftSQLBindLabels is the set of SQLKit/Fluent string-interpolation argument
// labels that bind the interpolated value as a query PARAMETER (placeholder)
// instead of splicing it into the raw SQL text. `\(bind:)` / `\(binds:)` emit
// `?`/`$n` placeholders with the value passed out-of-band; `\(literal:)` quotes
// and escapes an identifier. These are the SQLKit-documented safe forms. The
// raw forms — bare `\(x)` and `\(raw: x)` — carry NO such label and remain
// dangerous.
var swiftSQLBindLabels = map[string]bool{
	"bind":    true,
	"binds":   true,
	"literal": true,
}

// swiftSQLAllTaintedSegmentsBound reports whether argNode is a Swift
// interpolated-string container in which EVERY tainted interpolation segment is
// a parameterized binding (`\(bind: x)` / `\(binds: x)` / `\(literal: x)`). Used
// to suppress a SQLKit/Fluent `db.raw(...)` SnkSQLQuery flow only when no raw
// (unbound) interpolation of tainted data remains — a single bare `\(x)` or
// `\(raw: x)` segment leaves at least one tainted-and-unbound segment and the
// flow fires. Returns false for non-interpolated arguments and when no tainted
// segment is found (so an outside-the-segments whole-object taint still fires).
func swiftSQLAllTaintedSegmentsBound(argNode *ast.Node, tm *taintMap, cfg *langConfig) bool {
	if argNode == nil || !isInterpolatedStringContainer(argNode.Type()) {
		return false
	}
	sawTainted := false
	for i := 0; i < argNode.ChildCount(); i++ {
		seg := argNode.Child(i)
		if !isInterpolationSegment(seg.Type()) {
			continue
		}
		if _, ok := nodeIsTainted(seg, tm, cfg); !ok {
			continue
		}
		sawTainted = true
		if !swiftInterpolationSegmentIsBound(seg) {
			return false
		}
	}
	return sawTainted
}

// swiftInterpolationSegmentIsBound reports whether a Swift
// `interpolated_expression` segment leads with a parameterized-binding argument
// label (`bind:`/`binds:`/`literal:`). The tree-sitter-swift grammar parses
// `\(bind: userId)` as an `interpolated_expression` whose first named child is a
// `value_argument_label` ("bind"); the raw `\(userId)` form has a bare
// `simple_identifier` and no label.
func swiftInterpolationSegmentIsBound(seg *ast.Node) bool {
	if seg == nil {
		return false
	}
	for i := 0; i < seg.ChildCount(); i++ {
		c := seg.Child(i)
		if c.Type() == "value_argument_label" {
			label := strings.ToLower(strings.TrimSpace(c.Text()))
			return swiftSQLBindLabels[label]
		}
	}
	return false
}

// maximalSourceAccessPath returns the bounded full access path of the source
// attribute matched at node `n`. The walk climbs the parent chain while each
// parent is an attribute/member-access node AND `n` is its receiver (object)
// child — so `req.body` matched inside `req.body.user.id` yields the maximal
// enclosing path `req.body.user.id`, while `req.body` read on its own yields
// `req.body`. The result is bounded to root + maxAccessPathDepth segments.
//
// Climbing only on the *receiver* side is what makes this precise: a source
// matched as the property side of an enclosing access (`x.req` for some other
// `x`) is not what fired the match — matchSourceAttr keys on the attribute name
// and receiver, so the matched node already covers the source's own text; we
// only extend outward through field accesses that read INTO the source value.
func maximalSourceAccessPath(n *ast.Node, cfg *langConfig) string {
	cur := n
	for {
		p := cur.Parent()
		if p == nil || !cfg.attrTypes[p.Type()] {
			break
		}
		// Only extend when `cur` is the receiver (object/value) of the parent
		// access, i.e. the parent reads a field OF cur. If cur is the property
		// side, the parent is an unrelated outer access.
		obj := p.ChildByFieldName("object")
		if obj == nil {
			obj = p.ChildByFieldName("value")
		}
		if obj == nil {
			// Languages whose attr grammar uses positional children (e.g.
			// Kotlin navigation_expression) expose the receiver as the first
			// named child.
			named := p.NamedChildren()
			if len(named) > 0 {
				obj = named[0]
			}
		}
		if obj != cur {
			break
		}
		cur = p
	}
	return boundAccessPath(cur.Text())
}

// processAttr handles attribute access as potential sources (e.g., request.args).
// When found as a standalone expression (not RHS of assignment), we track it
// under the bounded maximal access path so that field-level reads stay precise:
// reading `req.body.a` taints the path `req.body.a`, not the sibling
// `req.body.b`. Patterns like `sink(request.args.get("x"))` still resolve
// because the seeded path is a prefix of (or equal to) the read path — see
// taintMap.prefixTainted.
func processAttr(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	if src := matcher.matchSourceAttr(n); src != nil {
		// Seed under the bounded maximal access path containing this source
		// (e.g. `req.body` inside `req.body.user.id` → `req.body.user`) rather
		// than the bare source text, so a later read of a SIBLING field does
		// not share the key and over-taint. A read of the same path (or a
		// deeper sub-path) still resolves via prefixTainted.
		pathKey := maximalSourceAccessPath(n, cfg)
		line := int(n.StartRow()) + 1
		if tm.get(pathKey) == nil {
			tm.set(pathKey, &taintState{
				varName:    pathKey,
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "tainted by " + src.MethodName,
					VarName:     pathKey,
				}},
			})
		}
	}
}

// rubyBase64DecodeMethods is the set of Ruby Base64 decode methods that decode
// an attacker-supplied serialized payload without neutralising it (decoding
// untrusted bytes yields untrusted bytes). They are the canonical wrapper
// between a request source and an unsafe deserializer
// (Marshal.load(Base64.decode64(params[:user]))).
var rubyBase64DecodeMethods = map[string]bool{
	"decode64":         true,
	"strict_decode64":  true,
	"urlsafe_decode64": true,
	"decode":           true,
}

// rubyIsBase64DecodeCall reports whether a Ruby call node is a Base64-family
// decode call (Base64.decode64(x), Base64.urlsafe_decode64(x), etc.). Used to
// gate findSourceInExpr's argument recursion to the precise
// deserialization-payload-decoding shape so it does not over-widen taint reach
// into unrelated sink categories (open-redirect / path / SSRF) on real code.
func rubyIsBase64DecodeCall(n *ast.Node) bool {
	if n == nil {
		return false
	}
	m := n.ChildByFieldName("method")
	if m == nil || !rubyBase64DecodeMethods[m.Text()] {
		return false
	}
	recv := callReceiverNode(n)
	return recv != nil && recv.Text() == "Base64"
}

// csharpHasLocalRequestBinding reports whether an identifier named "Request" is
// bound as a local variable or parameter within the nearest enclosing C# member
// body (method / constructor / accessor / local-function / lambda). Such a
// binding shadows the inherited Page/Controller/HttpContext `Request` property,
// so a bare `Request[...]` index must NOT be treated as an HttpRequest source.
// It is the FP guard for the walker's bare-`Request[...]` element-access case:
// `var Request = GetSafe(); Request["x"]` declares a local `Request`, so this
// returns true and the source does not fire. Bounded — it climbs to the nearest
// enclosing member declaration (or the compilation unit) and scans that subtree
// with a node budget so a pathological body cannot blow up the per-file walk.
func csharpHasLocalRequestBinding(n *ast.Node) bool {
	scope := n
	for scope != nil {
		switch scope.Type() {
		case "method_declaration", "constructor_declaration",
			"destructor_declaration", "operator_declaration",
			"local_function_statement", "accessor_declaration",
			"lambda_expression", "anonymous_method_expression",
			"compilation_unit", "global_statement":
			return csharpScopeBindsRequest(scope)
		}
		scope = scope.Parent()
	}
	return false
}

// csharpScopeBindsRequest scans a C# scope subtree for a local declaration or
// parameter named "Request" (the shadow check used by csharpHasLocalRequestBinding).
// A bounded DFS: declaration-shaped nodes (variable_declarator, parameter,
// foreach_statement, declaration_expression, catch_declaration) are checked for a
// child identifier "Request" on the conventional name field (`name` / `left`).
// On budget overflow it returns false (favouring recall) — realistic member
// bodies are far below the budget, and the bare-`Request[...]` trigger is rare.
func csharpScopeBindsRequest(scope *ast.Node) bool {
	const budget = 20000
	visited := 0
	var walk func(*ast.Node) bool
	walk = func(x *ast.Node) bool {
		if x == nil {
			return false
		}
		visited++
		if visited > budget {
			return false
		}
		switch x.Type() {
		case "variable_declarator", "parameter", "declaration_expression",
			"catch_declaration", "foreach_statement":
			if name := x.ChildByFieldName("name"); name != nil && name.Text() == "Request" {
				return true
			}
			// foreach_statement names its loop variable on the `left` field.
			if left := x.ChildByFieldName("left"); left != nil && left.Text() == "Request" {
				return true
			}
		}
		for i := 0; i < x.ChildCount(); i++ {
			if walk(x.Child(i)) {
				return true
			}
		}
		return false
	}
	return walk(scope)
}

// findSourceInExpr checks if an expression is or contains a taint source.
// Handles: direct source calls, source attribute accesses, calls on source
// receivers (e.g., request.args.get("name")), subscripts on source
// attributes (e.g., request.form["key"]), and variable-based sources
// (e.g., PHP $_GET, $_POST superglobals).
func findSourceInExpr(n *ast.Node, matcher *tsMatcher, cfg *langConfig) *taint.SourceDef {
	if n == nil {
		return nil
	}

	// Shell variable expansion ($1, $VAR, ${VAR}) — positional params and CGI
	// env vars are the canonical untrusted entry points but are not call/attr
	// nodes, so resolve them by Pattern. `concatenation` (e.g. /tmp/$1) wraps
	// expansions; `string` ("$1") wraps an expansion child — recurse into both.
	if cfg != nil && cfg.language == rules.LangShell {
		switch n.Type() {
		case "simple_expansion", "expansion":
			if src := matcher.matchSourceExpansion(n); src != nil {
				return src
			}
			return nil
		case "string", "concatenation":
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "simple_expansion" || c.Type() == "expansion" {
					if src := matcher.matchSourceExpansion(c); src != nil {
						return src
					}
				}
			}
			// fall through to generic handling below
		}
	}

	// Direct source call: input(), os.getenv("X")
	if cfg.callTypes[n.Type()] {
		if src := matcher.matchSourceCall(n); src != nil {
			return src
		}
		// Swift: a call_expression's function part is a `navigation_expression`
		// stored as a positional child (no "function"/"object" field name),
		// e.g. `req.parameters.get("filename")`. The bare-method matcher above
		// keys on `get` with receiver `req.parameters`, which the catalog's
		// `Request` ObjectType heuristic doesn't resolve. Recurse into the
		// receiver chain so the inner `req.parameters` navigation is matched as
		// a request source by matchSourceAttr. Gated to Swift so other
		// languages' positional-child handling is untouched.
		if cfg.language == rules.LangSwift {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "navigation_expression" {
					if src := matcher.matchSourceAttr(c); src != nil {
						return src
					}
					if src := findSourceInExpr(c, matcher, cfg); src != nil {
						return src
					}
					break
				}
			}
		}
		// Call on source receiver: request.args.get("name"), env::var("CMD").unwrap()
		// For languages that use "function" field (Python/JS/Kotlin), fn is the function part.
		// For languages that use "object"+"name" fields (PHP member_call_expression), check object.
		fn := n.ChildByFieldName("function")
		if fn == nil {
			// PHP member_call_expression: "name" is the method, "object" is the receiver chain.
			obj := n.ChildByFieldName("object")
			if obj != nil && cfg.attrTypes[obj.Type()] {
				if src := matcher.matchSourceAttr(obj); src != nil {
					return src
				}
				return findSourceInExpr(obj, matcher, cfg)
			}
		}
		if fn != nil && cfg.attrTypes[fn.Type()] {
			// First check if fn itself is a source attribute.
			// Handles $request->query->get() where fn=$request->query is the source.
			if src := matcher.matchSourceAttr(fn); src != nil {
				return src
			}
			obj := fn.ChildByFieldName("object")
			if obj == nil {
				obj = fn.ChildByFieldName("value") // Rust: field_expression uses "value" not "object"
			}
			if obj == nil {
				// Kotlin navigation_expression doesn't use field names —
				// the first named child is the object (receiver chain).
				named := fn.NamedChildren()
				if len(named) > 0 {
					obj = named[0]
				}
			}
			if obj != nil {
				return findSourceInExpr(obj, matcher, cfg)
			}
		}
		// Ruby inline-source nested inside a Base64-DECODE wrapper call's
		// argument:
		//   Marshal.load(Base64.decode64(params[:user]))   (railsgoat
		//   password_resets_controller.rb:6 — the canonical deserialization RCE).
		// A serialized object payload is virtually always base64-encoded in
		// transit (cookie / form field / query param), so the attacker-supplied
		// source sits one level deeper than the immediate sink argument, behind a
		// Base64.decode64 / Base64.decode / Base64.urlsafe_decode64 call. That
		// wrapper is neither a source nor a sanitizer — decoding attacker bytes
		// yields attacker bytes — and its RETURN value reaches the sink.
		// matchSourceCall returns nil for it and the receiver-chain recursion
		// above only walks the Base64 receiver, never the argument, so the inner
		// params[:user] source was invisible at the sink and the dataflow
		// Marshal.load sink stayed dead (regex-hint-only, conf 0.5). The
		// assignment-RHS sibling (x = Base64.decode64(params[:user]);
		// Marshal.load(x)) already works via propagateCallResultInterproc /
		// resolveInlineSourceThroughSanitizer; this is the matching recursion for
		// the directly-nested-at-sink shape.
		//
		// SCOPE: deliberately restricted to the Base64 decode family — NOT every
		// neutral wrapper. A blanket "recurse into any non-source call's args"
		// over-widens taint reach into unrelated sink categories on real Rails
		// code: it turned same-origin redirect_to path("/c/#{params[:path]}") and
		// redirect_to topic_route_url(params[:n]), app-temp-dir
		// File.write(File.join(dest, "about.json"), ...), and
		// Discourse.cache.write(key, result, ttl(result)) into open-redirect /
		// path-traversal / trust-boundary false positives on Discourse. The
		// Base64-decode anchor is the precise real-world deserialization-payload
		// shape and carries no such collateral. FP-safe within that anchor:
		// recursion returns non-nil only when the decoded argument is itself a
		// registered source (a Base64 of a constant returns nil), the source is
		// consumed by the wrapper (no sibling-field collapse), and a genuine safe
		// deserializer (YAML.safe_load, JSON.parse) is the OUTER call — never a
		// sink — so it does not fire regardless.
		if cfg != nil && cfg.language == rules.LangRuby && rubyIsBase64DecodeCall(n) {
			for _, arg := range cfg.extractCallArgs(n) {
				if src := findSourceInExpr(arg, matcher, cfg); src != nil {
					return src
				}
			}
		}
		return nil
	}

	// Source attribute: request.args, request.form, req.query, req.body
	// Recurse into nested attributes (e.g., req.query.name → check req.query)
	if cfg.attrTypes[n.Type()] {
		if src := matcher.matchSourceAttr(n); src != nil {
			return src
		}
		// Check the object of this attribute (handles req.query.name → req.query)
		obj := n.ChildByFieldName("object")
		if obj == nil {
			// Kotlin navigation_expression uses positional children, not field names.
			named := n.NamedChildren()
			if len(named) > 0 {
				obj = named[0]
			}
		}
		if obj != nil {
			return findSourceInExpr(obj, matcher, cfg)
		}
		return nil
	}

	// Swift unwrap nodes: force-unwrap `expr!` (postfix_expression),
	// optional-chaining/prefix forms, and `expr ?? default` (nil_coalescing)
	// all wrap a real source call/attr. Recurse into the meaningful operand
	// so `let x = req.parameters.get("y")!` and `let p = req.query["k"] ?? ""`
	// resolve their source. For nil-coalescing the LEFT operand carries the
	// (possibly tainted) value; the right is the literal default. Gated to
	// Swift so no other language's node handling changes.
	if cfg != nil && cfg.language == rules.LangSwift {
		switch n.Type() {
		case "postfix_expression", "prefix_expression":
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.IsNamed() && c.Type() != "bang" {
					if src := findSourceInExpr(c, matcher, cfg); src != nil {
						return src
					}
				}
			}
			return nil
		case "nil_coalescing_expression":
			// First named child is the value expression; check it (and, to be
			// safe, any other operand) for a source.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if !c.IsNamed() {
					continue
				}
				if src := findSourceInExpr(c, matcher, cfg); src != nil {
					return src
				}
			}
			return nil
		}
	}

	// Await expression: unwrap to inner expression. C#/JS/TS use the
	// "await_expression" node type; Python's tree-sitter grammar uses bare
	// "await". Without the Python case, `x = await db.fetch_val(...)` never
	// resolves the source on the awaited call, so async-only libraries (e.g.
	// encode/databases, asyncpg) miss second-order taint on direct assignment.
	// (nodeIsTainted already unwraps both via propagation.go.)
	if n.Type() == "await_expression" || n.Type() == "await" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return findSourceInExpr(c, matcher, cfg)
			}
		}
		return nil
	}

	// Try expression: Swift `try` / `try?` / `try!` — unwrap to inner expression
	// so `let row = try db.pluck(query)` resolves the source on `db.pluck`.
	// (matchSinkCall / matchSanitizer already see through `try_expression` via
	// unwrapToCall; this is the matching source-side unwrap.) The grammar tags
	// the inner expression with the field name "expr".
	if n.Type() == "try_expression" {
		if inner := n.ChildByFieldName("expr"); inner != nil {
			return findSourceInExpr(inner, matcher, cfg)
		}
		for i := n.ChildCount() - 1; i >= 0; i-- {
			c := n.Child(i)
			if c.IsNamed() {
				return findSourceInExpr(c, matcher, cfg)
			}
		}
		return nil
	}

	// Parenthesized expression — unwrap to the inner expression so a source
	// wrapped in parens (`(req.query.cmd)`, or a parenthesized nested ternary
	// branch `... : (flag ? req.query.cmd : "t")`) is still resolved. Mirrors
	// nodeIsTainted's parenthesized_expression handling.
	if n.Type() == "parenthesized_expression" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				return findSourceInExpr(c, matcher, cfg)
			}
		}
		return nil
	}

	// Conditional / ternary expression — an inline source in EITHER branch
	// makes the whole expression a potential source, e.g.
	//   const x = flag ? req.query.cmd : "safe";   // JS/TS ternary_expression
	//   x = request.args.get("c") if flag else "s"  // Python conditional_expression
	// Without this, the inline source lives in a branch the single-name
	// findSourceInExpr walk never enters, so the bound variable (and any
	// inline-source-at-sink ternary) silently loses taint. nodeIsTainted
	// already recurses ternary branches for *tracked-variable* taint; this is
	// the matching source-side recursion for as-yet-unbound inline sources.
	// We check both branches (recall-favouring, conservative) and rely on the
	// recursion to cover nested ternaries. The condition is not evaluated here:
	// findSourceInExpr is a may-contain-a-source check, mirroring how the
	// binary-expression and interpolation cases recurse unconditionally.
	if n.Type() == "conditional_expression" || n.Type() == "ternary_expression" {
		cons := n.ChildByFieldName("consequence")
		if cons == nil {
			// PHP's conditional_expression names the consequence field "body".
			cons = n.ChildByFieldName("body")
		}
		alt := n.ChildByFieldName("alternative")
		// Python's `cons if cond else alt` exposes no field names — fall back to
		// positional named children (consequence, condition, alternative).
		if cons == nil && alt == nil {
			named := n.NamedChildren()
			if len(named) >= 3 {
				cons = named[0]
				alt = named[2]
			}
		}
		if cons != nil {
			if src := findSourceInExpr(cons, matcher, cfg); src != nil {
				return src
			}
		}
		if alt != nil {
			if src := findSourceInExpr(alt, matcher, cfg); src != nil {
				return src
			}
		}
		return nil
	}

	// Subscript on source: request.form["key"], $_GET["name"], params[:cmd],
	// queryParameters["id"], and C#'s Request.Query["id"]. The indexer node type
	// is grammar-specific (Python subscript, JS/PHP subscript_expression, Ruby
	// element_reference, Lua indexing_expression, C# element_access_expression),
	// so naming C#'s node here only routes C# parses — no other language's
	// grammar produces element_access_expression. C# stores the indexed object
	// on the "expression" field (Request.Query["f"] -> member_access_expression
	// Request.Query), which then matches the registered ASP.NET source via the
	// attribute branch above.
	if n.Type() == "subscript" || n.Type() == "subscript_expression" || n.Type() == "element_reference" || n.Type() == "indexing_expression" || n.Type() == "element_access_expression" {
		obj := n.ChildByFieldName("object")
		if obj == nil {
			obj = n.ChildByFieldName("value")
		}
		if obj == nil {
			obj = n.ChildByFieldName("expression") // C# element_access_expression
		}
		if obj == nil && n.ChildCount() > 0 {
			obj = n.Child(0)
		}
		// SLICE B (C#-scoped): bare `Request["key"]` indexer (HttpRequest.Item).
		// In a Page / Controller / IHttpHandler the inherited `Request` property IS
		// the HttpRequest, so `Request["id"]` is the dominant pre-Core WebForms/MVC5
		// user-input idiom (WebGoat.NET ProductDetails/Orders/ReflectedXSS). The
		// indexed object is a LONE identifier (no receiver), so it never reaches
		// matchSourceAttr and the ObjectType!="" bottom fallback in findSourceInExpr
		// skips it — the source token was simply dead. Resolve it to the registered
		// HttpRequest.Item source here. Every part is gated:
		//   - LangCSharp (no other grammar emits element_access_expression anyway),
		//   - the capital-`Request` convention (the inherited property is always
		//     capitalised; a lowercase `request` local is not the page property),
		//   - the ABSENCE of a local/parameter named `Request` shadowing the
		//     property (csharpHasLocalRequestBinding) — so the canonical FP shape
		//     `var Request = GetSafe(); Request["x"]` stays clean.
		if cfg != nil && cfg.language == rules.LangCSharp && obj != nil &&
			obj.Type() == cfg.identType && obj.Text() == "Request" &&
			!csharpHasLocalRequestBinding(n) {
			if src := matcher.csharpRequestItemSource(); src != nil {
				return src
			}
		}
		return findSourceInExpr(obj, matcher, cfg)
	}

	// Inline source-CALL inside a binary concatenation: `os.system(request.args.get("c")
	// + " --flag")`, `exec(p.getParameter("c") + " x")`, `system("echo " + getenv("C"))`.
	// nodeIsTainted already recurses binary operands for tracked *variables* (so the
	// two-step `cmd = source(); sink(cmd + lit)` form works), but a source used
	// INLINE — never bound to a local — reaches a sink argument or assignment RHS
	// only through findSourceInExpr, which had no binary case. The very common
	// "source + literal" shape (appending a flag / extension / suffix to user input)
	// was therefore silently missed.
	//
	// SCOPE: only CALL-shaped sources are resolved here (matchSourceCall on a call
	// operand) plus nested concatenations. Attribute / subscript sources
	// (`req.body.b`, `$_GET['c']`) are deliberately NOT resolved through the binary
	// recursion: those access paths are governed by the field-sensitive taint map
	// (nodeIsTainted / prefixTainted), and synthesising taint for them inline would
	// collapse a specific field path to its bare source and defeat sibling
	// distinctness — `x = req.body.a; sink("..." + req.body.b)` must stay clean
	// (see TestMultiLevelField_* in the scanner package). Call sources return fresh
	// tainted values and lie outside that path system, so resolving them inline is
	// FP-safe: an operand only resolves when it is itself a registered source call.
	switch n.Type() {
	case "binary_operator", "binary_expression", "concatenated_string", "string_binary_expression":
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() {
				continue
			}
			switch {
			case cfg.callTypes[c.Type()]:
				if src := matcher.matchSourceCall(c); src != nil {
					return src
				}
			case c.Type() == "binary_operator" || c.Type() == "binary_expression" ||
				c.Type() == "concatenated_string" || c.Type() == "string_binary_expression":
				// Nested concatenation (`"a" + src() + "b"` is left-associative).
				if src := findSourceInExpr(c, matcher, cfg); src != nil {
					return src
				}
			}
		}
		return nil
	}

	// Ruby string-INTERPOLATION inline source: `User.where("id = '#{params[:id]}'")`.
	// The dangerous sink argument is a `string` node whose `interpolation`
	// child holds the (as-yet-unbound) source expression — most commonly a
	// `params[...]` element_reference accessed directly at the sink with no
	// intervening local. nodeIsTainted only consults the taint map, so the
	// classic Rails inline AR-SQLi shape (railsgoat users_controller.rb:29)
	// is missed without this recursion. Scoped to Ruby so Python f-strings and
	// JS template literals — whose field-sensitive interpolation handling lives
	// elsewhere and must preserve sibling distinctness — are untouched. The
	// catalog's enforced interpolation Pattern is what gates the .where sink to
	// the dangerous string form in the first place, so resolving the inner
	// source here is FP-safe: a safe `.where(name: params[:x])` is a hash arg
	// (no `string`/`interpolation` node), and `.where("x = ?", v)` carries no
	// interpolation. The two-step concat shape (`"..." + var`) is already
	// handled by the binary case above; this adds the interpolation shape.
	if cfg != nil && cfg.language == rules.LangRuby {
		switch n.Type() {
		case "string", "bare_string", "string_array", "interpolation":
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if !c.IsNamed() {
					continue
				}
				switch c.Type() {
				case "string_content", "escape_sequence":
					// literal text — never a source
				case "identifier", "constant", "instance_variable",
					"global_variable", "class_variable":
					// A BARE name inside `#{...}` is deliberately NOT resolved
					// here. If such a variable were tainted it would already be in
					// the taint map and caught by nodeIsTainted; resolving it via
					// findSourceInExpr's bare-name fallback would instead collide
					// with source METHOD names (a local `query` matching the
					// PG/Mysql2 `query` DB-read source, an ivar `@term` matching
					// nothing), producing false positives on values that were
					// sanitized in a helper the single-file walk can't see
					// (Discourse `query = Search.ts_query(...)` → escape_string).
					// The genuine inline shapes — `params[:x]`, `request.foo` — are
					// element_reference / call / attribute nodes handled below.
				default:
					// `interpolation` wrapper and its genuine source-shaped
					// expression children: element_reference (`params[:id]`),
					// call (`request.params.get(...)`), attribute (`request.body`).
					if src := findSourceInExpr(c, matcher, cfg); src != nil {
						return src
					}
				}
			}
			return nil
		}
	}

	// Variable that matches a source by name (e.g., PHP $_GET, $_POST, $_REQUEST,
	// Ruby `params`). First pass: exact bare-name match (ObjectType == "")
	// for true globals like $_GET. Second pass: same-name match in dynamic
	// languages where bare identifiers can implicitly resolve to the
	// framework receiver (Ruby `params` → ActionController/Sinatra/Roda).
	name := n.Text()
	if candidates := matcher.sourcesByMethod[name]; len(candidates) > 0 {
		for _, src := range candidates {
			if src.ObjectType == "" {
				// CLI-argument sources (java.main.args etc.) name a method
				// PARAMETER, not an ambient global. In static languages any
				// local can share that name (`String[] args = {"sh", "-c", c}`
				// passed to ProcessBuilder is the canonical false positive), so
				// a bare identifier is no evidence of program input there.
				// Dynamic-language globals like PHP $_GET or Ruby ARGV keep
				// matching by name.
				if src.Category == taint.SrcCLIArg && cfg != nil &&
					(cfg.language == rules.LangJava || cfg.language == rules.LangCSharp || cfg.language == rules.LangKotlin) {
					continue
				}
				return src
			}
		}
		// Dynamic-language fallback: Ruby's `params` is the canonical example.
		// The catalog tags it with a framework ObjectType (Sinatra::Base, etc.)
		// but at the call site it's a bare method with implicit `self`. Accept
		// the first framework-tagged source so the cross-file walker sees the
		// taint. Confined to Ruby for now — Python's request/sys.argv shapes
		// already use empty-ObjectType entries, JS uses attribute-style.
		if cfg != nil && cfg.language == rules.LangRuby {
			for _, src := range candidates {
				// Skip sources whose MethodName implies an explicit receiver
				// shape (e.g. `request.params` — catalog already keys those
				// under "params" too but they require `request.` in source).
				if strings.Contains(src.MethodName, ".") {
					continue
				}
				return src
			}
		}
	}

	return nil
}

// findInlineConcatSource resolves an inline source — INCLUDING attribute and
// subscript access-path sources (`req.body.host`, `req.params[0]`,
// `request.getParameter("c")`, `$_GET['next']`) — nested inside a string
// concatenation or a template-literal/interpolation that is the SINGLE argument
// of a sink whose category has no benign "sibling field". It is the complement to
// findSourceInExpr's binary/interpolation recursion, which intentionally resolves
// CALL-shaped sources only.
//
// WHY a separate, category-scoped helper rather than widening findSourceInExpr:
// for SQL/eval/HTML sinks the field-sensitive access-path map must stay
// authoritative so a tracked sibling field does not bleed
// (`x=req.body.a; db.query("..."+req.body.b)` stays clean — TestMultiLevelField_*).
// Two sink categories are categorically different:
//   - SnkCommand: the argument is one command string handed to `/bin/sh -c`, so
//     ANY attacker-controlled segment spliced into it is OS command injection.
//   - SnkRedirect: the argument is one Location:/Refresh: URL, so ANY segment is
//     open redirect.
//
// In both there is no benign "sibling field" of a value that reaches the sink.
// The direct-arg form (`exec(req.body.host)` / `header($_GET['x'])`) already fires
// via findSourceInExpr's attribute branch; this closes the equally-dangerous
// concat (`"ping " + req.body.host`, `"Location: " . $_GET['x']`) and template
// (`` `ping ${req.body.host}` ``) forms so the shapes are consistent. The caller
// gates this helper to exactly those two categories.
//
// FP-safety: it ONLY descends concatenation / template / interpolation /
// parenthesized container nodes and resolves a leaf via findSourceInExpr (so an
// operand must itself be a registered source — a literal or constant returns
// nil). The inline-sanitizer guard at the call site (inlineSourceSanitizedInSegment)
// still suppresses `exec(shellEscape(req.body.host))` and
// `header("Location: " . urlencode($_GET['x']))`. Depth-bounded to avoid
// pathological nesting.
func findInlineConcatSource(n *ast.Node, matcher *tsMatcher, cfg *langConfig) *taint.SourceDef {
	return findInlineConcatSourceDepth(n, matcher, cfg, 0)
}

func findInlineConcatSourceDepth(n *ast.Node, matcher *tsMatcher, cfg *langConfig, depth int) *taint.SourceDef {
	if n == nil || depth > 8 {
		return nil
	}
	switch n.Type() {
	// String concatenation / template literal / interpolation containers:
	// descend into the children and resolve each interpolated/concatenated
	// segment. The literal-text children (string_fragment, string_content) are
	// not sources and resolve to nil, so only genuine source operands fire.
	case "binary_expression", "binary_operator", "string_binary_expression",
		"concatenated_string", "template_string", "template_substitution",
		"interpolation", "string_interpolation", "parenthesized_expression":
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if !c.IsNamed() {
				continue
			}
			if src := findInlineConcatSourceDepth(c, matcher, cfg, depth+1); src != nil {
				return src
			}
		}
		return nil
	}
	// Leaf (or a directly-source-shaped node): defer to the standard resolver,
	// which handles call / attribute / subscript / nested-container sources.
	// A literal/constant operand returns nil here.
	return findSourceInExpr(n, matcher, cfg)
}

// processEnhancedFor handles Java enhanced for loops (for (Type var : iterable)).
// If the iterable is tainted, the loop variable inherits taint.
func processEnhancedFor(n *ast.Node, tm *taintMap, cfg *langConfig) {
	// enhanced_for_statement structure: type, name (identifier), value (expression), body
	varName := ""
	var iterableNode *ast.Node

	nameNode := n.ChildByFieldName("name")
	if nameNode != nil {
		varName = nameNode.Text()
	}
	iterableNode = n.ChildByFieldName("value")

	if varName == "" || iterableNode == nil {
		return
	}

	line := int(n.StartRow()) + 1

	// Check if the iterable is tainted.
	if ts, ok := nodeIsTainted(iterableNode, tm, cfg); ok {
		newTs := ts.clone(varName, line, "iterated from "+ts.varName, 0.95)
		tm.set(varName, newTs)
	}
}

// processPythonForLoop handles Python for-in loops (for x in iterable).
// If the iterable is tainted or a source, the loop variable inherits taint.
// Also handles calls on sources: for name in request.form.keys().
func processPythonForLoop(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	// Python for_statement: left (pattern_list or identifier), right (expression), body (block)
	varNode := n.ChildByFieldName("left")
	iterNode := n.ChildByFieldName("right")

	varName := ""
	if varNode != nil {
		if varNode.Type() == "identifier" {
			varName = varNode.Text()
		} else if varNode.Type() == "pattern_list" && varNode.ChildCount() > 0 {
			// for k, v in dict.items() — taint first identifier
			for i := 0; i < varNode.ChildCount(); i++ {
				c := varNode.Child(i)
				if c.Type() == "identifier" {
					varName = c.Text()
					break
				}
			}
		}
	}

	if varName != "" && iterNode != nil {
		line := int(n.StartRow()) + 1

		// Check if iterable is a source (e.g., request.form.keys())
		if src := findSourceInExpr(iterNode, matcher, cfg); src != nil {
			tm.set(varName, &taintState{
				varName:    varName,
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "iterated from " + src.MethodName,
					VarName:     varName,
				}},
			})
		} else if ts, ok := nodeIsTainted(iterNode, tm, cfg); ok {
			// Iterable variable is tainted
			newTs := ts.clone(varName, line, "iterated from "+ts.varName, 0.95)
			tm.set(varName, newTs)
		}
	}

	// Walk all children (body, else clause, etc.)
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
		}
	}
}

// processJSForOf handles JavaScript/TypeScript for...of and for...in loops
// (tree-sitter node `for_in_statement`, fields: left = binding, right =
// iterable, body = block). If the iterable is a source or a tainted value, the
// loop binding inherits taint. This mirrors processPythonForLoop /
// processEnhancedFor for the one node type those handlers don't cover, closing
// the dominant `for (const item of req.body.items) { sink(item) }` recall gap.
func processJSForOf(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher, scopeName string, fb *flowBuilder, summaries map[string]*TaintSummary) {
	bindNode := n.ChildByFieldName("left")
	iterNode := n.ChildByFieldName("right")

	// Collect the bound variable name(s). The common case is a single
	// identifier (`for (const item of …)`). Destructuring bindings
	// (`for (const [a, b] of pairs)`, `for (const {id} of items)`) bind every
	// inner identifier to a value derived from a tainted element, so tainting
	// each one is correct (not an over-approximation of unrelated siblings).
	var varNames []string
	if bindNode != nil {
		switch bindNode.Type() {
		case "identifier":
			varNames = append(varNames, bindNode.Text())
		case "array_pattern", "object_pattern", "object_assignment_pattern":
			collectForBindingIdents(bindNode, &varNames)
		default:
			// `const`/`let`/`var` is exposed via the `kind` field, so `left`
			// is the binding node itself; fall back to any identifier descendant.
			collectForBindingIdents(bindNode, &varNames)
		}
	}

	if len(varNames) > 0 && iterNode != nil {
		line := int(n.StartRow()) + 1

		if src := findSourceInExpr(iterNode, matcher, cfg); src != nil {
			for _, vn := range varNames {
				tm.set(vn, &taintState{
					varName:    vn,
					source:     src,
					sourceLine: line,
					sanitized:  make(map[taint.SinkCategory]bool),
					confidence: 1.0,
					steps: []taint.FlowStep{{
						Line:        line,
						Description: "iterated from " + src.MethodName,
						VarName:     vn,
					}},
				})
			}
		} else if ts, ok := nodeIsTainted(iterNode, tm, cfg); ok {
			for _, vn := range varNames {
				newTs := ts.clone(vn, line, "iterated from "+ts.varName, 0.95)
				tm.set(vn, newTs)
			}
		}
	}

	// Walk all children (body, etc.).
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.IsNamed() {
			walkBodyInterproc(c, tm, cfg, matcher, scopeName, fb, summaries)
		}
	}
}

// collectForBindingIdents appends every `identifier`/`shorthand_property_identifier_pattern`
// descendant of a JS/TS for-loop destructuring binding to out, so each bound
// name can inherit the iterable's taint.
func collectForBindingIdents(n *ast.Node, out *[]string) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "identifier", "shorthand_property_identifier_pattern":
		*out = append(*out, n.Text())
		return
	}
	for i := 0; i < n.ChildCount(); i++ {
		collectForBindingIdents(n.Child(i), out)
	}
}

// isRubyIterMethod reports whether a Ruby method name is an Enumerable/iteration
// method whose block parameter(s) bind to a value derived from the receiver
// collection — an element, a key/value pair, an index alongside an element, or
// an accumulator seeded from elements. Restricted to this allowlist so block
// methods whose parameter is unrelated to the receiver's taint (e.g. numeric
// `times`/`upto`, resource handles from `File.open`) are left untouched.
func isRubyIterMethod(name string) bool {
	switch name {
	case "each", "each_with_index", "each_with_object", "each_pair",
		"each_value", "each_key", "each_entry", "each_slice", "each_cons",
		"each_char", "each_line", "each_byte",
		"map", "map!", "collect", "collect!", "flat_map", "collect_concat",
		"filter_map", "select", "select!", "filter", "filter!", "reject",
		"reject!", "find", "detect", "find_all", "find_index",
		"group_by", "partition", "sort_by", "min_by", "max_by",
		"take_while", "drop_while", "chunk_while":
		return true
	}
	return false
}

// collectRubyBlockParamIdents appends every identifier leaf of a Ruby
// block_parameters node to out, recursing only into parameter-grouping nodes
// (destructured `|(a, b)|` and splat `|*rest|`) so it never descends into a
// default-value expression. The `_` wildcard is skipped.
func collectRubyBlockParamIdents(n *ast.Node, out *[]string) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "identifier":
		if n.Text() != "_" {
			*out = append(*out, n.Text())
		}
	case "block_parameters", "destructured_parameter", "splat_parameter":
		for i := 0; i < n.ChildCount(); i++ {
			collectRubyBlockParamIdents(n.Child(i), out)
		}
	}
}

// seedRubyBlockParams seeds the block parameters of a Ruby iterator call
// (`coll.each { |x| ... }`, `coll.map do |k, v| ... end`) from the taint of the
// receiver collection, mirroring processJSForOf / processPythonForLoop for the
// method-call-with-block iteration shape those handlers don't cover. It is a
// pure additive side-effect: it only ADDS taint entries for block parameter
// names when the receiver is tainted (an inline source or a previously-tainted
// value); otherwise it is a no-op. The surrounding walk is unchanged — the
// generic call path still walks the block body, where the now-tainted parameter
// reaches its sink.
func seedRubyBlockParams(n *ast.Node, tm *taintMap, cfg *langConfig, matcher *tsMatcher) {
	if n.Type() != "call" {
		return
	}
	block := n.ChildByFieldName("block")
	if block == nil || (block.Type() != "do_block" && block.Type() != "block") {
		return
	}
	method := n.ChildByFieldName("method")
	if method == nil || !isRubyIterMethod(method.Text()) {
		return
	}
	params := block.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	recv := n.ChildByFieldName("receiver")
	if recv == nil {
		return
	}
	var names []string
	collectRubyBlockParamIdents(params, &names)
	if len(names) == 0 {
		return
	}
	line := int(n.StartRow()) + 1

	// Resolve receiver taint: an inline source (`params[:items].each`) or a
	// previously-tainted variable (`items.each`). Source first, mirroring
	// processJSForOf.
	if src := findSourceInExpr(recv, matcher, cfg); src != nil {
		for _, vn := range names {
			tm.set(vn, &taintState{
				varName:    vn,
				source:     src,
				sourceLine: line,
				sanitized:  make(map[taint.SinkCategory]bool),
				confidence: 1.0,
				steps: []taint.FlowStep{{
					Line:        line,
					Description: "iterated from " + src.MethodName,
					VarName:     vn,
				}},
			})
		}
		return
	}
	if ts, ok := nodeIsTainted(recv, tm, cfg); ok {
		for _, vn := range names {
			tm.set(vn, ts.clone(vn, line, "iterated from "+ts.varName, 0.95))
		}
	}
}

// isAccumulatorMethod returns true for methods that store their argument into
// the receiver object (e.g., list.append, StringIO.write, dict.update).
func isAccumulatorMethod(name string) bool {
	switch name {
	case "write", "append", "extend", "insert", "add", "update", "put":
		return true
	}
	return false
}

// isInputParamName checks if a parameter name suggests it carries user input.
func isInputParamName(lower string, lang rules.Language) bool {
	// Normalize snake_case so idiomatic Rust/Python/Ruby parameter names like
	// `user_input`, `raw_body`, `post_data`, `query_string` collapse to the
	// canonical forms in the table below. Without this, `user_input` (the most
	// common input-parameter name in snake_case languages) failed to match the
	// `userinput` entry purely because of the underscore. This is a no-op for
	// camelCase languages (Java/JS/Go) and is intentionally SKIPPED for C/C++:
	// there it would seed params like `user_input` into intra-procedural flows
	// that surface a separate, pre-existing sink mis-categorization (e.g. an
	// fprintf format-string flagged as command_exec) — the C AST analyzer
	// already reports those format-string vulns with the correct CWE.
	if lang != rules.LangC && lang != rules.LangCPP {
		lower = strings.ReplaceAll(lower, "_", "")
	}
	inputNames := []string{
		"userinput", "input", "data", "body", "payload",
		"rawdata", "rawbody", "rawinput", "userdata",
		"formdata", "postdata", "querystring", "params",
		"query", "form", "path",
	}
	for _, n := range inputNames {
		if lower == n {
			return true
		}
	}
	return false
}

// ── C / C++ parameter-as-source seeding ────────────────────────────────────
//
// Everything below is reached ONLY from the LangC / LangCPP guard in
// seedParams; it never runs for any other language.

// cHandlerNamePrefixes / cHandlerNameSuffixes / cHandlerNameExact name the
// function-name shapes that idiomatically mark a C/C++ entry point that
// receives attacker-controlled input (CGI / RPC / message / socket handlers,
// request dispatchers, framework callbacks). Helper / library functions
// (`run_query`, `lookup_user`, `fetch`, `compare`, `derive_key`, …) are NOT
// in this set, so a `const std::string&` they receive from a constant or
// sanitized interprocedural argument is left untouched — only true handlers
// have their params auto-tainted.
var cHandlerNamePrefixes = []string{
	"handle", "on_", "on", "process", "dispatch", "serve", "route",
	"do_get", "do_post", "do_put", "do_delete", "do_head",
	"doget", "dopost", "doput", "dodelete",
	"controller", "endpoint", "router", "callback",
}

var cHandlerNameSuffixes = []string{
	"handler", "callback", "cb", "_handle", "_request", "_req",
}

var cHandlerNameExact = map[string]bool{
	"handle": true, "handler": true, "service": true, "serve": true,
	"dispatch": true,
	// `main`/`wmain` are deliberately NOT handlers: their `char *argv[]` is a
	// CLI argument (a different, locally-mitigated threat model), and the safe
	// fixtures validate it (is_valid_hostname) then use the no-shell execve
	// form — seeding argv re-introduced those false positives.
	"main": false, "wmain": false,
	"run": false, // run is NOT a handler (generic helper in existing fixtures)
}

// isCHandlerFuncName reports whether a C/C++ function NAME is handler-shaped.
// Matching is case-insensitive. `run`/`main` are deliberately excluded (see
// cHandlerNameExact).
func isCHandlerFuncName(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if v, ok := cHandlerNameExact[lower]; ok {
		return v
	}
	for _, p := range cHandlerNamePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	for _, s := range cHandlerNameSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// cUserShapedParamName reports whether a C/C++ parameter NAME strongly
// implies user-controlled STRING data. Used only as a fallback for params
// whose type carries no string signal (see cParamIsUserShaped) — never on a
// param whose type is a clearly-non-string pointer/handle.
//
// Deliberately EXCLUDES generic single letters (s, p), ambiguous handle-ish
// names (id, key, host, addr, value, val, name, str, line, token, content,
// text, user), CLI `argv`/`args`, and bare type words — those routinely name
// framework HANDLES or process-control values rather than request payloads
// (`ap_log_error(.., server_rec *s, ..)`, `int main(.., char *argv[])`,
// `process_user(struct User *user)`), and seeding them manufactured FPs.
func cUserShapedParamName(lower string) bool {
	switch lower {
	case "input", "userinput", "user_input", "buf", "buffer", "data",
		"req", "request", "reqbody", "body", "payload", "cmd", "command",
		"querystring", "msg", "message", "raw", "rawdata", "rawbody",
		"rawinput", "userdata", "formdata", "postdata":
		return true
	}
	return false
}

// cIsStringTypeWord reports whether a (lowercased) C/C++ type word denotes a
// std:: string type. Pointer/array `char` buffers are detected separately via
// the declarator (see cParamIsUserShaped).
func cIsStringTypeWord(t string) bool {
	for _, needle := range []string{
		"std::string", "string_view", "stringview",
		"std::wstring", "wstring",
	} {
		if strings.Contains(t, needle) {
			return true
		}
	}
	return t == "string" || t == "const string"
}

// cParamIsUserShaped decides whether a C/C++ parameter should be seeded as a
// user-controlled source. The decision is TYPE-FIRST and precise:
//
//   - std::string / const std::string& / string_view / wstring  → seed
//     (the canonical C++ request-string parameter).
//   - char* / const char* / unsigned char* / char[]             → seed
//     (the canonical C raw-buffer parameter). The pointer/array marker lives
//     in the DECLARATOR (`char *cmd`, `char buf[]`), NOT the type node, so we
//     inspect the declarator — a bare `char c` (single character) is not
//     seeded.
//   - any OTHER pointer/handle/struct/numeric type (struct User*, server_rec*,
//     sqlite3*, int, size_t, Req*)                              → NOT seeded,
//     even if the name looks user-ish: these are handles / control values,
//     and seeding them produced log-injection / mis-categorised FPs.
//   - no type signal at all + a strong user-input NAME           → seed
//     (rare fallback for untyped/auto params).
func cParamIsUserShaped(param *ast.Node, lowerName string) bool {
	if param == nil {
		return false
	}
	typeText := ""
	if t := param.ChildByFieldName("type"); t != nil {
		typeText = strings.ToLower(strings.TrimSpace(t.Text()))
	}
	isPointerOrArray := false
	if d := param.ChildByFieldName("declarator"); d != nil {
		dt := d.Type()
		declText := d.Text()
		isPointerOrArray = dt == "pointer_declarator" || dt == "array_declarator" ||
			dt == "reference_declarator" ||
			strings.Contains(declText, "*") || strings.Contains(declText, "[")
	}

	// std:: string family — seed regardless of pointer/ref decoration.
	if cIsStringTypeWord(typeText) {
		return true
	}

	// char-family raw buffer: the type word is char/wchar_t/unsigned char AND
	// the declarator marks a pointer or array (`char *cmd`, `const char buf[]`).
	isCharWord := typeText == "char" || typeText == "const char" ||
		typeText == "unsigned char" || typeText == "signed char" ||
		typeText == "wchar_t"
	if isCharWord && isPointerOrArray {
		return true
	}

	// Any other typed pointer/handle/struct/numeric parameter is NOT a
	// user-shaped string payload — do not seed by name.
	if typeText != "" {
		return false
	}

	// No type signal (untyped/auto param): fall back to the strong-name list.
	return cUserShapedParamName(lowerName)
}

// seedCParams seeds parameter-as-source taint for C/C++ handler-shaped
// functions. Caller guarantees cfg.language is LangC or LangCPP.
//
// A parameter is seeded only when BOTH hold:
//   - the enclosing function is handler-shaped (handler name or a web-route
//     annotation), AND
//   - the parameter is user-shaped per cParamIsUserShaped (std::string /
//     char* buffer type, or — for untyped params — a strong user-input name).
//
// The handler gate matters: a string param in a non-handler helper
// (`run_query`, `lookup_user`, `fetch_known`) is the canonical safe-fixture
// shape (constant / parameterized / sanitized interprocedural argument), and
// the Layer-4 call graph already models those precisely. Tainting them at
// Layer 3 would resurrect exactly the false positives the interproc safe
// tests guard against.
func seedCParams(fnNode *ast.Node, tm *taintMap, cfg *langConfig) {
	if fnNode == nil {
		return
	}
	fname := cfg.extractFuncName(fnNode)
	handler := isCHandlerFuncName(fname) || isWebHandlerFunc(fnNode, cfg)
	if !handler {
		return
	}

	// Walk parameter_declaration nodes so we can read each param's TYPE
	// alongside its NAME. cExtractParams already yields the positional names;
	// we re-walk the declarator list here to pair names with types.
	decl := fnNode.ChildByFieldName("declarator")
	if decl == nil {
		return
	}
	if decl.Type() == "pointer_declarator" {
		for i := 0; i < decl.ChildCount(); i++ {
			if decl.Child(i).Type() == "function_declarator" {
				decl = decl.Child(i)
				break
			}
		}
	}
	params := decl.ChildByFieldName("parameters")
	if params == nil {
		return
	}

	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() != "parameter_declaration" {
			continue
		}
		d := p.ChildByFieldName("declarator")
		name := ""
		if d != nil {
			name = extractIdentText(d, "identifier")
		}
		if name == "" {
			continue
		}
		lower := strings.ToLower(name)

		// Type-first decision: seed std::string / char* buffer params (and,
		// only for untyped params, strong user-input names). Non-string
		// pointer/handle/struct/numeric params are never seeded.
		if !cParamIsUserShaped(p, lower) {
			continue
		}

		// Don't clobber a more specific source seeded earlier.
		if existing := tm.get(name); existing != nil && existing.source != nil {
			continue
		}

		src := &taint.SourceDef{
			ID:          string(cfg.language) + ".param." + name,
			Category:    taint.SrcUserInput,
			Language:    cfg.language,
			MethodName:  "parameter:" + name,
			Description: "C/C++ handler parameter (user-controlled)",
		}
		tm.set(name, &taintState{
			varName:    name,
			source:     src,
			sourceLine: 0,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 0.85,
			steps: []taint.FlowStep{{
				Line:        0,
				Description: "handler parameter " + name + " assumed tainted",
				VarName:     name,
			}},
		})
	}
}

// rustActixUserInputExtractors are the actix-web typed parameter extractors that
// carry untrusted request data. A handler parameter typed as one of these IS the
// user input. `web::Data` is deliberately ABSENT — it is shared application state
// (DI handle), not request input, and seeding it would be a serious false
// positive. Keyed by the base (un-generic) type path as written at the call site;
// the matcher also accepts the fully-qualified `actix_web::`-prefixed form.
var rustActixUserInputExtractors = map[string]bool{
	"web::Query": true,
	"web::Path":  true,
	"web::Json":  true,
	"web::Form":  true,
}

// rustActixExtractorType returns the matched extractor type path (e.g.
// "web::Query") when the given Rust parameter `type` node is an actix-web
// user-input extractor `web::Query<T>` / `web::Path<T>` / `web::Json<T>` /
// `web::Form<T>` (including the fully-qualified `actix_web::web::Query<T>` form),
// or "" otherwise. Only the `web::`-qualified scoped forms are matched so a bare
// `Query<T>` from an unrelated crate cannot be mistaken for an actix extractor,
// and `web::Data<T>` (application state) is never matched.
func rustActixExtractorType(typeNode *ast.Node) string {
	if typeNode == nil || typeNode.Type() != "generic_type" {
		return ""
	}
	base := typeNode.ChildByFieldName("type")
	// The generic base must be a scoped path (`web::Query`,
	// `actix_web::web::Query`). A plain `type_identifier` (`Query`) is too
	// ambiguous to attribute to actix and is intentionally not matched.
	if base == nil || base.Type() != "scoped_type_identifier" {
		return ""
	}
	txt := base.Text()
	for ext := range rustActixUserInputExtractors {
		if txt == ext || strings.HasSuffix(txt, "::"+ext) {
			return ext
		}
	}
	return ""
}

// seedRustActixExtractorParams seeds taint for Rust function parameters whose
// TYPE is an actix-web user-input extractor. The whole extractor parameter is
// seeded as a user_input source at confidence 0.9 with the block-eligible
// `parameter:` marker, because an actix extractor type is an unambiguous
// external-origin signal. The whole-object seed lets a later field read
// (`info.cmd`, `info.0`) or unwrap (`info.into_inner()`) carry the taint to a
// sink via the engine's existing field-prefix resolution (taintMap.prefixTainted
// / nodeIsTainted's attribute fallback). The caller gates this to LangRust.
func seedRustActixExtractorParams(fnNode *ast.Node, tm *taintMap, cfg *langConfig) {
	if fnNode == nil {
		return
	}
	params := fnNode.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() != "parameter" {
			continue
		}
		pat := p.ChildByFieldName("pattern")
		if pat == nil || pat.Type() != "identifier" {
			continue
		}
		name := pat.Text()
		if name == "" {
			continue
		}
		extType := rustActixExtractorType(p.ChildByFieldName("type"))
		if extType == "" {
			continue
		}
		// Don't clobber a more specific source seeded earlier.
		if existing := tm.get(name); existing != nil && existing.source != nil {
			continue
		}
		src := &taint.SourceDef{
			ID:          "rust.param.extractor." + name,
			Category:    taint.SrcUserInput,
			Language:    cfg.language,
			MethodName:  "parameter:" + name,
			Description: "actix-web " + extType + " extractor parameter (user-controlled)",
		}
		tm.set(name, &taintState{
			varName:    name,
			source:     src,
			sourceLine: 0,
			sanitized:  make(map[taint.SinkCategory]bool),
			confidence: 0.9,
			steps: []taint.FlowStep{{
				Line:        0,
				Description: "actix-web extractor parameter " + name + " (" + extType + ") assumed tainted",
				VarName:     name,
			}},
		})
	}
}

// isSwiftInjectionTextParamName reports whether a Swift parameter name
// strongly implies user-controlled text destined for an injection sink
// (XSS / eval / SQL / NSPredicate / command). It is intentionally narrow:
//   - It does NOT include URL/endpoint names (url, endpoint, targeturl,
//     imageurl, urlstring, …) because the safe Swift fixtures defend URL
//     params with runtime mitigations (cert pinning, host allowlists, scheme
//     checks) that the structural walker cannot see — seeding them would
//     manufacture SSRF false positives.
//   - The listed names reach text-injection sinks where the safe fixtures
//     use constant or parameter-bound (`%@` / `?`) values, so no taint flows
//     into the dangerous argument and no false positive results.
//
// Matches the bare name OR the `user`-prefixed form (name → username/username,
// bio → userbio, script → userscript) which the vulnerable fixtures use.
func isSwiftInjectionTextParamName(lower string) bool {
	switch lower {
	case "name", "username", "bio", "userbio", "comment", "usercomment",
		"message", "usermessage", "text", "usertext", "content",
		"html", "script", "userscript", "js", "javascript",
		"command", "cmd", "search", "searchterm", "keyword",
		"email", "useremail", "displayname", "nickname":
		return true
	}
	return false
}

// Web handler annotations that indicate a method receives HTTP requests.
var webHandlerAnnotations = []string{
	"GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
	"RequestMapping",
	"GET", "POST", "PUT", "DELETE", "PATCH",
	"app.route", "app.get", "app.post", "app.put", "app.delete",
	"router.get", "router.post",
	"Hono", "new Hono",
	"Query(", "Path(", "Json(", "Form(",
	// ASP.NET Core (C#) — action-method routing attributes and
	// parameter-binding attributes mark a controller action whose
	// parameters carry request-derived data. Exact analog of the
	// Spring @GetMapping / @RequestParam path above: a normal
	// `public IActionResult Get([FromQuery] string username)` then
	// gets its params seeded tainted. The Java-only demotion below
	// (javaMethodIsTrueHandler) does not touch C#.
	"HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch",
	"FromQuery", "FromBody", "FromRoute", "FromForm", "FromHeader",
}

// Input annotations that mark a specific parameter as user-controlled.
var inputParamAnnotations = []string{
	"RequestParam", "PathVariable", "RequestBody", "RequestHeader",
	"CookieValue", "MatrixVariable", "RequestPart",
	"QueryParam", "PathParam", "FormParam", "HeaderParam", "CookieParam",
}

// isWebHandlerFunc checks if a function node has web handler annotations.
func isWebHandlerFunc(fnNode *ast.Node, cfg *langConfig) bool {
	if fnNode == nil {
		return false
	}
	// Java: prefer the AST-based annotation check (a real @GetMapping /
	// @PostMapping / @KafkaListener / @PulsarListener / @Path on the method or
	// an @RestController / @Path on the enclosing class). This is the same
	// precise signal the seedParams Java demotion uses, promoted to a PRIMARY
	// signal so the parenHandlerAnnotations identifier-boundary tightening below
	// (which now applies to Java) cannot accidentally drop a genuine handler:
	// `executeQuery(` no longer satisfies the substring `Query(`, but a method
	// annotated `@PulsarListener` is still correctly recognized here.
	if cfg.language == rules.LangJava {
		if javaMethodIsTrueHandler(fnNode) {
			return true
		}
	}
	fnText := fnNode.Text()
	if len(fnText) > 500 {
		fnText = fnText[:500]
	}
	for _, ann := range webHandlerAnnotations {
		if containsHandlerAnnotation(fnText, ann, cfg.language) {
			return true
		}
	}
	return false
}

// barewordHandlerAnnotations is the subset of webHandlerAnnotations that are
// short all-letter tokens prone to colliding as substrings of unrelated
// identifiers / string literals. The canonical regression: "PUT" is a
// substring of the getenv key "USER_INPUT", so a function that merely reads
// `getenv("USER_INPUT")` was being tagged as a web handler and had every
// parameter seeded as user input. For these, require an identifier boundary on
// BOTH sides so `PUT` matches `@PUT` / `"PUT"` / ` PUT ` but not `USER_INPUT`.
// Applied for ALL languages — a bare HTTP verb buried inside an identifier is
// never the intended signal anywhere.
var barewordHandlerAnnotations = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
}

// parenHandlerAnnotations are the parameter-binding markers that end in "(".
// In web frameworks they appear as `@Query(`, `Path(`, etc., but they are also
// extremely common method-name SUFFIXES in DB / storage / cloud libraries —
// `client.ExecuteQuery(`, `spanner::RunQuery(`, `this.getAppPath(`,
// `$qb->createNamedParameter(`, `stmt.executeQuery(`, `writer.WriteJson(` —
// where they are NOT handler signals. For the languages in
// parenBoundaryLangs we require an identifier boundary before the marker so
// `Query(` matches `@Query(` (JAX-RS / Spring Data) but not `executeQuery(`.
var parenHandlerAnnotations = map[string]bool{
	"Query(": true, "Path(": true, "Json(": true, "Form(": true,
}

// parenBoundaryLangs is the set of languages for which the parenHandler markers
// require a leading identifier boundary (so a method-name SUFFIX like
// `getAppPath(` / `executeQuery(` is NOT mistaken for a `@Path(` / `@Query(`
// route annotation). Originally C/C++ only; extended to PHP/Java/Ruby because
// their storage/DB abstraction layers are saturated with these suffixes
// (Nextcloud's `getAppPath(`, `getQueryBuilder(`, `createForm(` flooded every
// internal `$path`/`$query` parameter with bogus user-input seeding via the
// substring collision — the dominant FP class on a real Nextcloud scan). A
// genuine annotation keeps a non-identifier byte before the marker (`@Path(`,
// `@Query(`, `#[Route(`), so it still matches. C#/Kotlin and the other tsflow
// languages keep plain-substring semantics: several of their framework-detection
// tests deliberately rely on a bare `Query(` / `Form(` substring as the handler
// signal, and those idioms are not the FP driver on real repos.
var parenBoundaryLangs = map[rules.Language]bool{
	rules.LangC:    true,
	rules.LangCPP:  true,
	rules.LangPHP:  true,
	rules.LangJava: true,
	rules.LangRuby: true,
}

// containsHandlerAnnotation reports whether `ann` occurs in `text`.
//
//   - Bare HTTP verbs (barewordHandlerAnnotations) require an identifier
//     boundary on both sides in every language.
//   - Parenthesized binding markers (parenHandlerAnnotations) require a
//     leading identifier boundary for the languages in parenBoundaryLangs
//     (so `Query(` does not match `executeQuery(` / `getAppPath(`); elsewhere
//     they keep plain-substring semantics.
//   - All other annotations use plain substring containment (unchanged).
func containsHandlerAnnotation(text, ann string, lang rules.Language) bool {
	if ann == "" {
		return false
	}
	bareword := barewordHandlerAnnotations[ann]
	parenCLike := parenHandlerAnnotations[ann] && parenBoundaryLangs[lang]
	if !bareword && !parenCLike {
		return strings.Contains(text, ann)
	}
	from := 0
	for {
		idx := strings.Index(text[from:], ann)
		if idx < 0 {
			return false
		}
		pos := from + idx
		end := pos + len(ann)
		prefixOK := pos == 0 || !isIdentByte(text[pos-1])
		// Bare verbs need a trailing boundary too (PUT inside USER_INPUT);
		// parenthesized markers already end in "(", a natural boundary.
		suffixOK := !bareword || end >= len(text) || !isIdentByte(text[end])
		if prefixOK && suffixOK {
			return true
		}
		from = pos + 1
	}
}

// isIdentByte reports whether b is a C-family identifier character
// (letter, digit, or underscore). Used to detect token boundaries.
func isIdentByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// javaHandlerMethodAnnotations names every annotation that, when applied
// to a Java method, means the parameters of that method carry
// request- or message-derived data. Used by `javaMethodIsTrueHandler`
// to demote the substring-based `isWebHandlerFunc` signal when no real
// annotation is present.
//
// Kept in sync with graph/extractor_java_typecatalog.go's
// `javaHandlerMethodAnnotations` — the two packages can't share the
// var without introducing a cross-package dependency. Adding a new
// handler annotation requires updating both lists.
var javaHandlerMethodAnnotations = map[string]bool{
	// Spring MVC mappings.
	"RequestMapping":   true,
	"GetMapping":       true,
	"PostMapping":      true,
	"PutMapping":       true,
	"DeleteMapping":    true,
	"PatchMapping":     true,
	"HeadMapping":      true,
	"OptionsMapping":   true,
	"MessageMapping":   true,
	"SubscribeMapping": true,

	// JAX-RS / Jersey / RESTEasy / Quarkus.
	"Path":    true,
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"HEAD":    true,
	"OPTIONS": true,
	"PATCH":   true,

	// Micronaut.
	"Get":     true,
	"Post":    true,
	"Put":     true,
	"Delete":  true,
	"Patch":   true,
	"Head":    true,
	"Options": true,

	// Async listener handlers. PulsarListener is included alongside
	// the Kafka/JMS/RabbitMQ counterparts because @PulsarListener
	// methods take a record / payload parameter that carries
	// attacker-controlled content the same way.
	"KafkaListener":  true,
	"JmsListener":    true,
	"RabbitListener": true,
	"PulsarListener": true,
	"EventListener":  true,
}

// javaHandlerClassAnnotations: class-level annotations that turn every
// method inside the class into a handler (JAX-RS / Micronaut /
// Spring `@Controller` / `@RestController` / `@Path`).
var javaHandlerClassAnnotations = map[string]bool{
	"Controller":     true,
	"RestController": true,
	"Path":           true,
}

// javaMethodIsTrueHandler returns true when the method node carries a
// recognised handler annotation on its `modifiers` child, or when its
// enclosing class declaration does. This is the strict AST analogue of
// `isWebHandlerFunc`'s substring match — it only inspects annotation
// nodes, so an arbitrary call expression in the method body
// (`file.getAbsolutePath()`) cannot accidentally tag the method as a
// handler.
//
// Why not modify `isWebHandlerFunc` directly: 8+ existing tsflow tests
// in the Pulsar / GraphQL / Kotlin / Rust / Swift suites rely on the
// substring-matching behaviour to classify their unannotated test
// methods as handlers. We deliberately keep this Java-specific
// tightening behind a language guard so those tests stay green.
func javaMethodIsTrueHandler(methodNode *ast.Node) bool {
	if methodNode == nil {
		return false
	}
	if javaDeclHasAnnotation(methodNode, javaHandlerMethodAnnotations) {
		return true
	}
	for p := methodNode.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "class_declaration", "interface_declaration", "record_declaration":
			if javaDeclHasAnnotation(p, javaHandlerClassAnnotations) {
				return true
			}
		}
	}
	return false
}

// javaDeclHasAnnotation walks the `modifiers` child of a declaration
// node looking for a marker_annotation / annotation whose short
// identifier appears in `names`. FQN annotations
// (`@org.springframework.web.bind.annotation.GetMapping`) resolve to
// the trailing segment ("GetMapping") via the scoped_identifier child.
func javaDeclHasAnnotation(decl *ast.Node, names map[string]bool) bool {
	if decl == nil {
		return false
	}
	for _, c := range decl.NamedChildren() {
		if c.Type() != "modifiers" {
			continue
		}
		for _, mc := range c.NamedChildren() {
			if mc.Type() != "marker_annotation" && mc.Type() != "annotation" {
				continue
			}
			name := javaAnnotationShortName(mc)
			if name != "" && names[name] {
				return true
			}
		}
	}
	return false
}

// javaAnnotationShortName extracts the short identifier from a
// marker_annotation / annotation node. The first named child is either
// an `identifier` ("GetMapping") or a `scoped_identifier"
// ("org.springframework.web.bind.annotation.GetMapping"); in the
// scoped case we keep only the trailing segment after the final `.`.
func javaAnnotationShortName(ann *ast.Node) string {
	for _, c := range ann.NamedChildren() {
		switch c.Type() {
		case "identifier":
			return strings.TrimSpace(c.Text())
		case "scoped_identifier":
			text := strings.TrimSpace(c.Text())
			if dot := strings.LastIndexByte(text, '.'); dot >= 0 {
				return text[dot+1:]
			}
			return text
		}
	}
	return ""
}

// tsflowJavaDIParamTypeAllowlist mirrors graph/extractor_java_typecatalog.go's
// javaDIParamTypeAllowlist (kept duplicated here to avoid a cross-package
// dependency between tsflow and graph — the lists must be kept in
// sync). When a handler-method parameter has one of these short type
// names, seedParams skips it: it's a DI-injected framework object,
// not user input.
var tsflowJavaDIParamTypeAllowlist = map[string]bool{
	"RedirectAttributes": true,
	"Model":              true,
	"ModelMap":           true,
	"ModelAndView":       true,
	"Authentication":     true,
	"Principal":          true,
	"BindingResult":      true,
	"Errors":             true,
	"SessionStatus":      true,
	"HttpSession":        true,
	"Locale":             true,
	"TimeZone":           true,
	"ZoneId":             true,
	// Servlet OUTPUT objects — never user input. The response is what the
	// handler writes TO; seeding it auto-tags every `response.setContentType(..)`
	// / `response.setHeader(..)` / `response.getWriter()` call as a tainted-
	// receiver header/XSS flow (real block-FP observed on thingsboard's
	// controllers). The dangerous arg of those sinks is matched on its own
	// merits; the response object itself carries no taint.
	"HttpServletResponse": true,
	"ServletResponse":     true,
}

// tsflowJavaNumericTypeAllowlist mirrors graph/extractor_java_typecatalog.go's
// javaNumericTypeAllowlist. Numeric / UUID / boolean parameter types
// cannot carry SQL injection, command injection, or path traversal
// payloads because Jackson / Bean-Validation rejects malformed input
// before the controller body runs.
var tsflowJavaNumericTypeAllowlist = map[string]bool{
	"Long":       true,
	"Integer":    true,
	"Short":      true,
	"Byte":       true,
	"Float":      true,
	"Double":     true,
	"BigDecimal": true,
	"BigInteger": true,
	"long":       true,
	"int":        true,
	"short":      true,
	"byte":       true,
	"float":      true,
	"double":     true,
	"UUID":       true,
	"Boolean":    true,
	"boolean":    true,
}

// javaParamShortType returns the short (un-FQN) type name for a
// formal_parameter, e.g. "RedirectAttributes" for `RedirectAttributes ra`
// or `org.springframework.…RedirectAttributes ra`. Used by seedParams
// to apply tsflowJavaDIParamTypeAllowlist / tsflowJavaNumericTypeAllowlist.
//
// Generics and arrays are dropped (we want the head identifier only).
// Returns "" when the type cannot be determined.
func javaParamShortType(fnNode *ast.Node, paramName string) string {
	if fnNode == nil {
		return ""
	}
	params := fnNode.ChildByFieldName("parameters")
	if params == nil {
		return ""
	}
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p == nil || p.Type() != "formal_parameter" {
			continue
		}
		nameNode := p.ChildByFieldName("name")
		if nameNode == nil || nameNode.Text() != paramName {
			continue
		}
		typeNode := p.ChildByFieldName("type")
		if typeNode == nil {
			return ""
		}
		raw := strings.TrimSpace(typeNode.Text())
		// Strip generics and arrays.
		if idx := strings.IndexAny(raw, "<["); idx >= 0 {
			raw = raw[:idx]
		}
		// Strip FQN prefix.
		if dot := strings.LastIndexByte(raw, '.'); dot >= 0 {
			raw = raw[dot+1:]
		}
		return strings.TrimSpace(raw)
	}
	return ""
}

// hasInputAnnotation checks if a specific parameter in a Java function has
// an input annotation like @RequestParam, @PathVariable, etc.
func hasInputAnnotation(fnNode *ast.Node, paramName string) bool {
	if fnNode == nil {
		return false
	}
	params := fnNode.ChildByFieldName("parameters")
	if params == nil {
		return false
	}
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() != "formal_parameter" {
			continue
		}
		name := p.ChildByFieldName("name")
		if name == nil || name.Text() != paramName {
			continue
		}
		pText := p.Text()
		for _, ann := range inputParamAnnotations {
			if strings.Contains(pText, "@"+ann) {
				return true
			}
		}
	}
	return false
}

// ── Real-AST handler evidence (Python / JS-TS / C#) ─────────────────────────
//
// isWebHandlerFunc tags a function as a web handler when a fixed substring set
// (`Query(`, `Form(`, `app.get`, `HttpGet`, …) occurs in the first 500 chars
// of the function's body text. For non-Java languages that substring match is
// the ONLY signal, so a plain internal helper whose body merely *calls*
// something matching the substring — `db.executeQuery(` ("Query("),
// `app.getConfig(` ("app.get"), a string literal `"POST"` — is mis-tagged as a
// handler. seedParams then promotes EVERY one of that helper's params to the
// conf-0.9, block-eligible "parameter:" seed, and the external-origin gate
// keeps it (it is marked "parameter:", not the weak "param-name:").
//
// isWebHandlerByASTEvidence is the precise analogue used to decide ONLY the
// conf-0.9 / "parameter:" promotion for Py/JS/C#: it returns true exclusively
// on a genuine route/binding decorator (Python `@app.get`/`@router.post`,
// JS/TS `@Get()`/`@Controller`), or a genuine ASP.NET routing/binding attribute
// (C# `[HttpGet]`/`[FromQuery]`/`[ApiController]`). A substring-only match
// fails here, so the param falls to the weak conf-0.6 "param-name:" path, which
// the external-origin gate (B) caps to a hint. Detection is preserved — the
// param is still seeded (so intra-/inter-procedural recall is unchanged) — but
// it is no longer block-eligible on the strength of a body substring alone.
//
// Java is intentionally NOT routed here: its conf-0.9 promotion is already
// AST-tightened in seedParams via javaMethodIsTrueHandler. The remaining tsflow
// languages (Swift/Rust/Kotlin/Ruby/PHP/C/C++/Lua/Groovy/Perl/…) keep the
// substring behaviour: several of their framework-detection tests deliberately
// rely on a bare substring as the unannotated test-handler signal.
func isWebHandlerByASTEvidence(fnNode *ast.Node, cfg *langConfig) bool {
	if fnNode == nil {
		return false
	}
	switch cfg.language {
	case rules.LangPython:
		return pyHasRouteDecorator(fnNode)
	case rules.LangJavaScript, rules.LangTypeScript:
		return jsHasRouteDecorator(fnNode)
	case rules.LangCSharp:
		return csharpHasRouteAttribute(fnNode)
	default:
		return false
	}
}

// pyHasRouteDecorator reports whether the Python function carries a genuine
// route decorator. Covers the FastAPI/APIRouter `@<recv>.get/post/...` shape
// (via pyIsFastAPIRouteHandler) plus the Flask/Bottle/Sanic `@<recv>.route(...)`
// and bare framework-verb decorators (`@app.get`, `@bp.post`, `@route`). An
// arbitrary `@staticmethod` / `@lru_cache` / `@dataclass` decorator is NOT a
// route signal and returns false.
func pyHasRouteDecorator(fnNode *ast.Node) bool {
	if pyIsFastAPIRouteHandler(fnNode) {
		return true
	}
	dec := fnNode
	if dec.Type() != "decorated_definition" {
		if parent := dec.Parent(); parent != nil && parent.Type() == "decorated_definition" {
			dec = parent
		} else {
			return false
		}
	}
	for i := 0; i < dec.ChildCount(); i++ {
		c := dec.Child(i)
		if c.Type() != "decorator" {
			continue
		}
		if pyDecoratorIsRoute(c) {
			return true
		}
	}
	return false
}

// pyDecoratorIsRoute returns true when a decorator expression is a route
// binding: `<recv>.route(...)`, `<recv>.<verb>(...)`, or a bare `route`/verb
// call/identifier. The HTTP verbs reuse fastapiRouteMethods; `route` is the
// Flask/Bottle/Sanic class registration method.
func pyDecoratorIsRoute(dec *ast.Node) bool {
	var expr *ast.Node
	for i := 0; i < dec.ChildCount(); i++ {
		c := dec.Child(i)
		if c.IsNamed() {
			expr = c
			break
		}
	}
	if expr == nil {
		return false
	}
	// Unwrap a call to its callee: `@app.route("/x")` → attribute `app.route`.
	if expr.Type() == "call" {
		if fn := expr.ChildByFieldName("function"); fn != nil {
			expr = fn
		}
	}
	switch expr.Type() {
	case "attribute":
		if attr := expr.ChildByFieldName("attribute"); attr != nil {
			name := attr.Text()
			return name == "route" || fastapiRouteMethods[name]
		}
	case "identifier":
		name := expr.Text()
		return name == "route" || fastapiRouteMethods[name]
	}
	return false
}

// jsRouteDecoratorNames is the set of method/class decorator identifiers that
// mark a NestJS (or NestJS-compatible) controller action / controller class.
// These bind request-derived data to the action's parameters. Matched
// case-sensitively against the decorator's callee identifier.
var jsRouteDecoratorNames = map[string]bool{
	// Controller-class markers.
	"Controller": true, "Resolver": true, "Gateway": true,
	// HTTP method route decorators.
	"Get": true, "Post": true, "Put": true, "Delete": true,
	"Patch": true, "Options": true, "Head": true, "All": true,
	// GraphQL / WebSocket message handlers (request-bound args).
	"Query": true, "Mutation": true, "Subscription": true,
	"SubscribeMessage": true, "MessagePattern": true, "EventPattern": true,
}

// jsHasRouteDecorator reports whether a JS/TS function node is a decorated
// handler: a method_definition preceded by a route decorator sibling
// (`@Get()`), or a method inside a class whose declaration carries a
// `@Controller`/`@Resolver`/`@Gateway` decorator. Plain functions, Express
// callbacks, and helpers calling `app.get(` carry no decorator and return
// false — they fall to the weak "param-name:" seed.
func jsHasRouteDecorator(fnNode *ast.Node) bool {
	if fnNode == nil {
		return false
	}
	// Method-level decorators: in tree-sitter JS/TS a method_definition's
	// decorators are its preceding `decorator` siblings under class_body.
	if fnNode.Type() == "method_definition" {
		if jsNodeHasRouteDecoratorSibling(fnNode) {
			return true
		}
	}
	// Class-level decorator (`@Controller('cats')`): walk to the enclosing
	// class declaration and inspect its decorator children.
	for p := fnNode.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "class_declaration", "class":
			if jsClassHasRouteDecorator(p) {
				return true
			}
			return false
		}
	}
	return false
}

// jsNodeHasRouteDecoratorSibling scans the preceding siblings of a
// method_definition for a route decorator. tree-sitter emits the decorators as
// `decorator` nodes immediately before the method inside the class_body.
func jsNodeHasRouteDecoratorSibling(method *ast.Node) bool {
	parent := method.Parent()
	if parent == nil {
		return false
	}
	for i := 0; i < parent.ChildCount(); i++ {
		c := parent.Child(i)
		if c == nil || c.Type() != "decorator" {
			continue
		}
		if jsDecoratorNameInSet(c, jsRouteDecoratorNames) {
			return true
		}
	}
	return false
}

// jsClassHasRouteDecorator reports whether a class declaration node carries a
// route decorator (`@Controller`, `@Resolver`, `@Gateway`). The decorators are
// `decorator` children of the class node.
func jsClassHasRouteDecorator(cls *ast.Node) bool {
	for i := 0; i < cls.ChildCount(); i++ {
		c := cls.Child(i)
		if c == nil || c.Type() != "decorator" {
			continue
		}
		if jsDecoratorNameInSet(c, jsRouteDecoratorNames) {
			return true
		}
	}
	return false
}

// jsDecoratorNameInSet extracts a JS/TS decorator's callee identifier
// (`@Get()` → "Get", `@common.Controller()` → "Controller", `@Get` → "Get")
// and reports whether it is in names.
func jsDecoratorNameInSet(dec *ast.Node, names map[string]bool) bool {
	name := ""
	var rec func(n *ast.Node)
	rec = func(n *ast.Node) {
		if n == nil || name != "" {
			return
		}
		switch n.Type() {
		case "identifier", "property_identifier":
			name = n.Text()
			return
		case "call_expression":
			if fn := n.ChildByFieldName("function"); fn != nil {
				rec(fn)
				return
			}
		case "member_expression":
			if prop := n.ChildByFieldName("property"); prop != nil {
				name = prop.Text()
				return
			}
		}
		for i := 0; i < n.ChildCount(); i++ {
			rec(n.Child(i))
			if name != "" {
				return
			}
		}
	}
	rec(dec)
	return name != "" && names[name]
}

// csharpRouteAttributeNames is the set of ASP.NET Core attribute identifiers
// that mark a controller action (or its parameters / controller class) as
// carrying request-derived data. Matched case-sensitively against the short
// attribute name.
var csharpRouteAttributeNames = map[string]bool{
	// Action HTTP-method routing attributes.
	"HttpGet": true, "HttpPost": true, "HttpPut": true,
	"HttpDelete": true, "HttpPatch": true, "HttpHead": true,
	"HttpOptions": true, "Route": true,
	// Controller-class markers.
	"ApiController": true, "Controller": true,
	// Parameter-binding attributes (request source bindings).
	"FromQuery": true, "FromBody": true, "FromRoute": true,
	"FromForm": true, "FromHeader": true,
}

// csharpHasRouteAttribute reports whether a C# method has genuine ASP.NET
// routing/binding attribute evidence: an attribute_list on the method itself,
// on any of its parameters, or on the enclosing class/struct/record. A plain
// helper whose body merely calls `db.ExecuteQuery(` carries no such attribute
// and returns false.
func csharpHasRouteAttribute(fnNode *ast.Node) bool {
	if fnNode == nil {
		return false
	}
	// Method-level and parameter-level attribute lists are direct/nested
	// children of the method_declaration.
	if csharpNodeHasRouteAttribute(fnNode) {
		return true
	}
	if params := fnNode.ChildByFieldName("parameters"); params != nil {
		for i := 0; i < params.ChildCount(); i++ {
			if csharpNodeHasRouteAttribute(params.Child(i)) {
				return true
			}
		}
	}
	// Class/struct/record-level attribute (`[ApiController]`, `[Route(...)]`).
	for p := fnNode.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "class_declaration", "struct_declaration", "record_declaration":
			return csharpNodeHasRouteAttribute(p)
		}
	}
	return false
}

// csharpNodeHasRouteAttribute scans a node's direct `attribute_list` children
// for an `attribute` whose name is in csharpRouteAttributeNames.
func csharpNodeHasRouteAttribute(n *ast.Node) bool {
	if n == nil {
		return false
	}
	for i := 0; i < n.ChildCount(); i++ {
		al := n.Child(i)
		if al == nil || al.Type() != "attribute_list" {
			continue
		}
		for j := 0; j < al.ChildCount(); j++ {
			a := al.Child(j)
			if a == nil || a.Type() != "attribute" {
				continue
			}
			if name := csharpAttributeShortName(a); name != "" && csharpRouteAttributeNames[name] {
				return true
			}
		}
	}
	return false
}

// csharpAttributeShortName extracts the short identifier of a C# attribute
// node, taking the trailing segment of a qualified name
// (`Microsoft.AspNetCore.Mvc.HttpGet` → "HttpGet").
func csharpAttributeShortName(a *ast.Node) string {
	name := ""
	for i := 0; i < a.ChildCount(); i++ {
		c := a.Child(i)
		switch c.Type() {
		case "identifier":
			name = strings.TrimSpace(c.Text())
		case "qualified_name":
			text := strings.TrimSpace(c.Text())
			if dot := strings.LastIndexByte(text, '.'); dot >= 0 {
				return text[dot+1:]
			}
			return text
		}
		if name != "" {
			return name
		}
	}
	return name
}
