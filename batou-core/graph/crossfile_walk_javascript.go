// JavaScript / TypeScript cross-file interprocedural walker (PR-Gjs).
//
// The Go-default AnalyzeCallerImpact in interprocedural.go scans the
// caller body with the Go sink regex table (db.Query, exec.Command,
// etc.) and uses Go arg parsing. Routing JS/TS through that path emits
// zero findings — JS calls never match Go sink shapes.
//
// This file is the JS/TS analog of crossfile_walk_python.go. It uses
// tree-sitter to find call expressions in the caller, the JS taint
// catalog (SinksForLanguage / SourcesForLanguage) to identify sinks
// inside callee bodies, and a coarse direct-source regex for typical
// Node/Express/Koa request shapes.
//
// Scope of this PR:
//
//   - Path A: caller passes a tainted argument to a JS callee that
//     forwards it into a sink. Direct source expressions in the call
//     site (`req.body`, `ctx.request.query.q`, etc.) are recognised;
//     parameter-typed sources will be tightened by PR-BBjs (framework
//     source recognition) — for now any param matching a source-typed
//     extractor flag would also flow through.
//   - Path B: callee returns tainted data and the caller passes it to
//     a sink. Recognised when the callee's TaintSig.TaintedReturns is
//     set by the extractor.
//   - 1-hop interproc only — multi-module relays are PR-Hjs's scope.
//
// The walker IS allowed to populate a JS callee's TaintSig on the fly
// when it's empty (ensureJavaScriptCalleeSinks). The same-file
// PropagateInterproc path doesn't run JS sink regex either, so most
// callees arrive at the cross-file walk with SinkCalls == nil.
// Computing them here mirrors what Python's PR-Gpy does.

package graph

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// javascriptSinkPattern is a compiled SinkDef plus metadata so
// AnalyzeJavaScript* helpers can scan callee bodies without hitting
// the catalog every time. Alias of the shared crossfileSinkPattern
// (crossfile_walk_core.go), mirroring pythonSinkPattern.
type javascriptSinkPattern = crossfileSinkPattern

var (
	javascriptSinkPatternsCache   []javascriptSinkPattern
	javascriptSinkPatternsCacheMu sync.Mutex
)

// loadJavaScriptSinkPatterns compiles and caches the JavaScript taint
// sink catalog into regex form. The JS catalog is shared between
// JavaScript and TypeScript at the catalog layer (one catalog under
// rules.LangJavaScript) — both dispatch routes call this loader.
func loadJavaScriptSinkPatterns() []javascriptSinkPattern {
	javascriptSinkPatternsCacheMu.Lock()
	defer javascriptSinkPatternsCacheMu.Unlock()
	if javascriptSinkPatternsCache != nil {
		return javascriptSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangJavaScript)
	out := make([]javascriptSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, javascriptSinkPattern{
			pattern:       re,
			category:      s.Category,
			method:        s.MethodName,
			dangerousArgs: s.DangerousArgs,
			module:        s.ObjectType,
			requireModule: false,
		})
	}
	javascriptSinkPatternsCache = out
	return out
}

// javascriptSourceExprRe matches taint source expressions in a JS arg
// position. Intentionally conservative — request body / query / headers
// / cookies shapes used by Express, Koa, Fastify, and Hapi. PR-BBjs
// will tighten framework-specific shapes (typed handler params,
// destructured `({ body })`, etc.) in parallel.
var javascriptSourceExprRe = regexp.MustCompile(
	`\breq\.(body|params|query|headers|cookies|url|path|originalUrl)\b` +
		`|\brequest\.(body|params|query|headers|cookies|url|path)\b` +
		`|\bctx\.request\.(body|params|query|headers|cookies)\b` +
		`|\bctx\.(query|params|headers|cookies|request)\b` +
		`|\bevent\.body\b` +
		`|\bprocess\.argv\b` +
		`|\bprocess\.env\b`,
)

// javascriptSanitizerRe matches common JS sanitizer-call shapes. Coarse
// net for the cross-file pass — the per-file tsflow walker is the
// source of truth. Kept narrow to avoid swallowing the canonical-fix
// path before the sink fires.
//
// Pattern coverage (intentionally <30 entries):
//   - validator.escape / validator.isURL — express-validator family
//   - DOMPurify.sanitize — XSS canonical
//   - xss(...) — Yahoo's xss filter library
//   - lodash.escape / he.encode — HTML encoders
//   - path.normalize + startsWith — path-traversal guard
//   - encodeURIComponent / encodeURI — URL escaping
//   - escapeHTML — generic
var javascriptSanitizerRe = regexp.MustCompile(
	`\b(?:` +
		`validator\.escape` +
		`|validator\.isURL` +
		`|validator\.is(?:Email|Alphanumeric|UUID)` +
		`|DOMPurify\.sanitize` +
		`|xss` +
		`|lodash\.escape` +
		`|_\.escape` +
		`|he\.encode` +
		`|he\.escape` +
		`|escapeHTML` +
		`|escape_html` +
		`|encodeURIComponent` +
		`|encodeURI` +
		`|path\.normalize` +
		`|sanitizeHtml` +
		`|sanitize_html` +
		`|sanitize` +
		`|escape` +
		`)\s*\(`,
)

// jsReturnStmtRe captures the expression of a `return <expr>` statement
// even when it does not start the line — the compact JS idiom
// `function getName(req){ return req.query.name; }` keeps the body on
// the same line as the declaration, so a line-prefix check (as in Lua,
// where multi-line bodies are idiomatic) misses it. The capture group
// stops at `;` or `}` so the trailing brace of a single-line body isn't
// swept into the expression.
var jsReturnStmtRe = regexp.MustCompile(`\breturn\s+([^;}]+)`)

// AnalyzeCallerImpactJavaScript mirrors AnalyzeCallerImpact (Go-specific)
// but uses tree-sitter to find JS/TS call expressions in the caller body
// and the JS taint catalog to identify sinks inside the callee. Returns
// findings keyed by the same BATOU-INTERPROC-<CAT> rule IDs the Go and
// Python paths use so downstream consumers don't need language-specific
// dispatch.
func AnalyzeCallerImpactJavaScript(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactJavaScriptCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactJavaScriptCached is the cached variant for the
// cross-file pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template itself (ensure sinks/returns -> extract caller body
// -> alias recovery -> call sites -> Path A / Path B with the field-
// sensitivity overlay) lives in the shared core (crossfile_walk_core.go);
// this wrapper only supplies the JS/TS config and the tree-sitter
// call-site finder bound to the typed cache. The JS-specific pieces the
// config wires in: jsCallerBindingAlias (CJS default exports / aliased
// imports), ensureJavaScriptCalleeReturns (getter-idiom Path B seeding),
// the inline `cp.exec(getA(req))` Path B shape, and the ArgFieldPath /
// TaintedReturnPaths field hooks (crossfile_walk_javascript_field.go).
func analyzeCallerImpactJavaScriptCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *javascriptCallIndexCache) []rules.Finding {
	if calleeNode == nil || callerNode == nil {
		return nil
	}
	calleeLang := calleeNode.Language
	return analyzeCallerImpactCrossfile(
		javascriptCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return findJavaScriptCallSitesIndexed(callIdx, content, caller, calleeName, calleeLang)
		},
		callIdx.sanitizerMemo(),
	)
}

// jsCallerBindingAlias returns the local name the caller actually writes
// at the call site for calleeNode, when that name differs from the callee
// NODE name. Two cases motivate this:
//
//   - CJS / ESM default export: the callee node is named "default"
//     (`module.exports = function () {}`), but the caller writes its
//     require/import binding (`const runCmd = require('./sink')`).
//   - Aliased named import: `import {runShell as doRun}` — the node is
//     "runShell" but the call is `doRun(...)`.
//
// The caller's FileScope.Imports maps each local alias to the ABSOLUTE
// resolved path of the imported module (resolver_javascript.go resolves
// specifiers with filepath.Abs); the callee's FilePath is usually
// CWD-relative, so we compare on absolute form. To disambiguate when the
// caller imports several names from the same file, we match the EXPORTED
// name behind each alias (recorded in Aux under jsImportNameAuxKey for
// renamed imports; the alias itself otherwise) against the callee's base
// name. The "default" node matches any binding from its file.
//
// Returns "" when no caller scope, no matching import, or the graph is
// unavailable — callers then fall back to the callee node name (a no-op
// for default/aliased imports, but correct for plain named imports where
// the binding equals the export).
func jsCallerBindingAlias(cg *CallGraph, callerNode, calleeNode *FuncNode) string {
	if cg == nil || callerNode == nil || calleeNode == nil {
		return ""
	}
	scope, ok := cg.FileScopes[callerNode.FilePath]
	if !ok || len(scope.Imports) == 0 {
		return ""
	}
	calleeAbs := calleeNode.FilePath
	if !filepath.IsAbs(calleeAbs) {
		if a, err := filepath.Abs(calleeAbs); err == nil {
			calleeAbs = a
		}
	}
	calleeBase := extractBaseName(calleeNode.Name)
	isDefault := calleeBase == "default"
	for alias, target := range scope.Imports {
		if alias == "" {
			continue
		}
		if target != calleeAbs && target != calleeNode.FilePath {
			continue
		}
		// Determine the export this alias actually binds to. A renamed
		// import records its original export in Aux; otherwise the binding
		// IS the export name.
		exportName := alias
		if scope.Aux != nil {
			if orig, ok := scope.Aux[jsImportNameAuxKey(alias)]; ok && orig != "" {
				exportName = orig
			}
		}
		if isDefault || exportName == calleeBase {
			return alias
		}
	}
	return ""
}

// ensureJavaScriptCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls
// when it's empty. Idempotent — skips work when already populated.
func ensureJavaScriptCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil {
		return
	}
	if calleeNode.Language != rules.LangJavaScript && calleeNode.Language != rules.LangTypeScript {
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
	sinks := scanJavaScriptBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	// Map each sink to a param index by checking if any caller-visible
	// param name appears in the sink call's args. Same shape as Python's
	// findPythonParamFlowToSink fallback path.
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		// Field-sensitive seeding (PR3): resolve both the param index AND
		// the bounded field access path the sink reads off that param
		// (e.g. "cmd" for `exec(opts.cmd)`). Falls back to whole-param
		// (-1 / "") for `exec(opts)` and destructured-but-whole shapes,
		// so legacy behaviour is unchanged.
		flow := findJavaScriptParamFlowToSinkField(bodyLines, lineIdx, &calleeNode.TaintSig)
		sinks[i].ArgFromParam = flow.paramIdx
		sinks[i].ArgFieldPath = flow.fieldPath
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensureJavaScriptCalleeReturns lazily populates calleeNode.TaintSig.-
// TaintedReturns when empty by scanning the callee body for `return
// <source>`. This handles the canonical Node/Express module idiom where
// a required module exposes a getter returning request-derived data
// (`function getName(req){ return req.query.name; }`). Without it the
// fast-skip gate in WalkCrossFileTaintFlows drops the callee before
// Path B can fire. Idempotent — skips work when already populated.
//
// Mirrors ensureLuaCalleeReturns; covers both JavaScript and TypeScript
// since they share one taint catalog and one dispatch case.
func ensureJavaScriptCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil {
		return
	}
	if calleeNode.Language != rules.LangJavaScript && calleeNode.Language != rules.LangTypeScript {
		return
	}
	if len(calleeNode.TaintSig.TaintedReturns) > 0 {
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
	// Field-sensitive return composition (PR3): when the callee returns an
	// object literal (or a field-built object) whose specific fields carry
	// sources, record the per-field tainted access paths so the caller can
	// gate `sink(r.user.id)` precisely (fires) vs `sink(r.name)` (silent).
	// This runs FIRST and is independent of the whole-return scan below —
	// a `return {user:{id:req.query.id}, name:"x"}` has no bare/whole-return
	// source but DOES have a tainted field path.
	if paths := scanJavaScriptBodyForTaintedReturnPaths(body); len(paths) > 0 {
		if calleeNode.TaintSig.TaintedReturnPaths == nil {
			calleeNode.TaintSig.TaintedReturnPaths = make(map[string][]taint.SourceCategory)
		}
		for k, v := range paths {
			calleeNode.TaintSig.TaintedReturnPaths[k] = appendUniqueCatList(calleeNode.TaintSig.TaintedReturnPaths[k], v)
		}
		calleeNode.TaintSig.IsPure = false
	}

	cat, found := scanJavaScriptBodyForTaintedReturn(body)
	if !found {
		return
	}
	if calleeNode.TaintSig.TaintedReturns == nil {
		calleeNode.TaintSig.TaintedReturns = make(map[int][]taint.SourceCategory)
	}
	calleeNode.TaintSig.TaintedReturns[0] = appendUniqueCat(calleeNode.TaintSig.TaintedReturns[0], cat)
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// scanJavaScriptBodyForTaintedReturn reports whether any `return`
// statement in the body carries a catalog source expression (directly,
// `return req.query.name`, or via an intermediate binding,
// `const v = req.body.x; return v;`). Returns the source category.
//
// Source recognition uses javascriptSourceExprRe (which also matches the
// TS `as string` form via its `req.*` alternatives) and javascript-
// SanitizerRe to drop escaped returns. Mirrors scanLuaBodyForTaintedReturn.
func scanJavaScriptBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	// Track variables bound to a source expression so `const v = source;
	// return v;` is recognised.
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Record `const x = <source>` / `let x = ...` / `var x = ...` /
		// bare `x = <source>` bindings.
		if eq := jsAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			lhs = strings.TrimPrefix(lhs, "const ")
			lhs = strings.TrimPrefix(lhs, "let ")
			lhs = strings.TrimPrefix(lhs, "var ")
			rhs := trimmed[eq+1:]
			if javascriptSourceExprRe.MatchString(rhs) && !javascriptSanitizerRe.MatchString(rhs) {
				name := jsLastIdent(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		// Match `return <expr>` anywhere on the line, not just at the
		// start — JS commonly keeps a single-line body on the same line
		// as the `function ... {` declaration. Each captured expression
		// is checked independently.
		for _, m := range jsReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" {
				continue
			}
			if javascriptSanitizerRe.MatchString(expr) {
				continue
			}
			if javascriptSourceExprRe.MatchString(expr) {
				return taint.SrcUserInput, true
			}
			// `return v` where v was bound to a source above.
			retVar := jsLastIdent(expr)
			if retVar != "" && taintedVars[retVar] {
				return taint.SrcUserInput, true
			}
		}
	}
	return "", false
}

// jsAssignEq returns the index of the single `=` assignment operator in
// a line, or -1 when the line isn't a plain assignment (skips ==, ===,
// !=, <=, >=).
func jsAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, ===.
		if i+1 < len(line) && line[i+1] == '=' {
			i++
			continue
		}
		// Skip !=, <=, >=.
		if i > 0 {
			prev := line[i-1]
			if prev == '!' || prev == '<' || prev == '>' || prev == '=' {
				continue
			}
		}
		return i
	}
	return -1
}

// jsLastIdent returns the last identifier token in s (used to pull a
// variable name out of an LHS / return expression).
func jsLastIdent(s string) string {
	s = strings.TrimSpace(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && r != '$' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// scanJavaScriptBodyForSinks walks the body line-by-line with each
// cached javascriptSinkPattern. Returns SinkRef rows with file-absolute
// line numbers. Multiple distinct sinks on the same line each produce
// their own row.
func scanJavaScriptBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadJavaScriptSinkPatterns()
	if len(patterns) == 0 {
		return nil
	}
	lines := strings.Split(body, "\n")
	var out []SinkRef
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comment-only lines (`// ...` or `/* ... */` single-line)
		// so commented dangerous calls don't fire.
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			// Inline sanitizer suppression for HTML output / redirect
			// categories — same rationale as Python's
			// sinkLineSanitizerNeutralises.
			if javascriptSanitizerRe.MatchString(line) {
				if jsSinkLineSanitizerNeutralises(p.category) {
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

// jsSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
// Kept conservative — mirrors the Python helper's coverage.
func jsSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkTemplate:
		return true
	}
	return false
}

// isArgTaintedInJavaScriptCaller checks whether argExpr is tainted in
// the caller's context. Mirrors the Python equivalent — recognises
// direct catalog source expressions in the arg, source-typed params
// (when the extractor flagged them), and backward-traces local variable
// assignments to source expressions. Thin wrapper over the shared
// crossfileIsArgTaintedInCaller (crossfile_walk_core.go).
func isArgTaintedInJavaScriptCaller(argExpr string, callerLines []string, callLineIdx int, callerSig *TaintSignature) bool {
	return crossfileIsArgTaintedInCaller(javascriptCrossfileWalkCfg, argExpr, callerLines, callLineIdx, callerSig)
}

// jsLanguageTag returns a stable tag string for findings carrying
// either JavaScript or TypeScript. Tagging keeps consumers that filter
// on "javascript" or "typescript" simple.
func jsLanguageTag(lang rules.Language) string {
	if lang == rules.LangTypeScript {
		return "typescript"
	}
	return "javascript"
}

// findJavaScriptCallSites parses callerContent with tree-sitter and
// returns every call expression to a function whose simple name equals
// extractBaseName(calleeName). Falls back to nil when parsing fails.
//
// JS-specific gotchas relative to the Python equivalent:
//   - Arrow functions live inside `variable_declarator` so the
//     containing assignment surfaces via `lexical_declaration`.
//   - The call node type is `call_expression`, not `call`. The function
//     reference is on field `function`; member calls use
//     `member_expression` whose `property` is the called name.
func findJavaScriptCallSites(callerContent string, callerNode *FuncNode, calleeName string, lang rules.Language) []javascriptCallSite {
	if lang != rules.LangJavaScript && lang != rules.LangTypeScript {
		// Default to JS for any caller — same content shape for both.
		lang = rules.LangJavaScript
	}
	// ParseFile routes a .tsx caller through the JSX-aware grammar so call
	// sites inside a React/Next component body aren't lost to ERROR nodes.
	tree := tsast.ParseFile([]byte(callerContent), lang, callerNode.FilePath)
	if tree == nil || tree.Root() == nil {
		return nil
	}
	baseName := extractBaseName(calleeName)
	if baseName == "" {
		return nil
	}

	var out []javascriptCallSite
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
		case "call_expression", "new_expression":
			if matchesJavaScriptCallName(n, baseName) {
				cs := javascriptCallSite{
					line:       int(n.StartRow()) + 1,
					assignedTo: parentAssignTarget,
				}
				if argList := n.ChildByFieldName("arguments"); argList != nil {
					cs.args = extractJavaScriptCallArgs(argList)
				}
				if cs.line >= callerNode.StartLine && cs.line <= callerNode.EndLine {
					out = append(out, cs)
				}
			}
		case "variable_declarator":
			// `const x = foo(...)` — `name` is the LHS identifier, `value`
			// is the call_expression. Propagate the assigned name into
			// the value subtree.
			name := nodeFieldText(n, "name")
			val := n.ChildByFieldName("value")
			if name != "" && val != nil {
				visit(val, strings.TrimSpace(name))
				return
			}
		case "assignment_expression":
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

// matchesJavaScriptCallName reports whether a call_expression's
// function reference resolves to a simple name equal to baseName.
// Handles bare identifiers (`foo()`), single-level member access
// (`mod.foo()`), and `new ClassName()`.
func matchesJavaScriptCallName(call *tsast.Node, baseName string) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		// new_expression uses `constructor` instead.
		fn = call.ChildByFieldName("constructor")
	}
	if fn == nil {
		return false
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text()) == baseName
	case "member_expression":
		prop := fn.ChildByFieldName("property")
		if prop != nil && strings.TrimSpace(prop.Text()) == baseName {
			return true
		}
	}
	return false
}

// extractJavaScriptCallArgs returns positional argument text from a
// tree-sitter `arguments` node. JS has no keyword arguments at the
// language level, so we don't model them — spread / object-literal /
// arrow-function args are returned as their raw text.
func extractJavaScriptCallArgs(argList *tsast.Node) []string {
	var args []string
	for _, child := range argList.NamedChildren() {
		args = append(args, strings.TrimSpace(child.Text()))
	}
	return args
}
