// Kotlin cross-file interprocedural walker.
//
// The Go-default AnalyzeCallerImpact in interprocedural.go scans the caller
// body with the Go sink regex table (db.Query, exec.Command, etc.) and uses
// Go arg parsing. Routing Kotlin through that path emits zero findings —
// Kotlin calls never match Go sink shapes.
//
// This file is the Kotlin analog of crossfile_walk_csharp.go. It uses the
// Kotlin taint catalog (SinksForLanguage) to identify sinks inside callee
// bodies, scans callee bodies for tainted `return` expressions, and a
// coarse direct-source regex for typical Ktor / Spring / servlet request
// shapes (`call.request.queryParameters`, `req.queryParameter("n")`,
// `request.getParameter(...)`, `@RequestParam`, ...).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a Kotlin callee that
//     forwards it into a sink. Direct source expressions in the call site
//     are recognised by kotlinSourceExprRe.
//   - Path B: callee returns tainted data (`return req.queryParameter("n")`)
//     and the caller stores the result then passes it to a sink. Recognised
//     when the callee has TaintedReturns set; ensureKotlinCalleeReturns
//     scans the callee body for `return <source-expr>` on the fly, so the
//     canonical Ktor/Spring helper idiom fires without planted test data.
//     This is the v1 milestone path.
//   - 1-hop interproc only.
//
// As with the JS / Lua / C# walkers, the Kotlin walker IS allowed to
// populate a callee's TaintSig.SinkCalls / TaintedReturns on the fly when
// empty — the same-file PropagateInterproc path doesn't run Kotlin sink
// regex.
//
// Every helper here is reached only for rules.LangKotlin callees: the
// dispatcher in crossfile_walk.go routes to analyzeCallerImpactKotlinCached
// solely from its `case rules.LangKotlin` arm.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// kotlinSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadKotlinSink-
// Patterns returns the shared shape the walk core's config consumes without
// conversion (mirrors rubySinkPattern). The module/requireModule fields stay
// zero-valued — the Kotlin walker doesn't use them.
type kotlinSinkPattern = crossfileSinkPattern

var (
	kotlinSinkPatternsCache   []kotlinSinkPattern
	kotlinSinkPatternsCacheMu sync.Mutex
)

// loadKotlinSinkPatterns compiles and caches the Kotlin taint sink catalog
// into regex form.
func loadKotlinSinkPatterns() []kotlinSinkPattern {
	kotlinSinkPatternsCacheMu.Lock()
	defer kotlinSinkPatternsCacheMu.Unlock()
	if kotlinSinkPatternsCache != nil {
		return kotlinSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangKotlin)
	out := make([]kotlinSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, kotlinSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	kotlinSinkPatternsCache = out
	return out
}

// kotlinSourceExprRe matches taint source expressions in a Kotlin arg /
// return position. Distilled from kotlin_sources.go (Ktor / Spring WebFlux /
// servlet request shapes, environment, JDBC ResultSet, etc.). The HTTP
// request accessors are matched on either the framework `call.request.` /
// `request.` receiver OR a common request-variable name (`req`, `request`,
// `call`) so the canonical helper idiom
// `fun getName(req: Request): String { return req.queryParameter("n")!! }`
// is recognised without type inference. Conservative on purpose — the
// two-sided source→sink gate suppresses standalone matches.
var kotlinSourceExprRe = regexp.MustCompile(
	`(?:call|req|request|httpRequest)\.(?:request\.)?(?:queryParameter|queryParameters|parameters|getParameter|getParameters|pathVariable|pathVariables|receive|receiveText|receiveParameters|receiveMultipart|cookies|getCookies|headers|getHeaders|getHeader|body|getBody|getInputStream|getReader|queryString|getQueryString)\b` +
		`|call\.parameters\b` +
		`|System\.getenv\s*\(` +
		`|System\.getProperty\s*\(` +
		`|@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|RequestPart)\b` +
		`|@(?:QueryValue|Body|Header)\b` +
		`|(?:ResultSet|rs)\.get(?:String|Object|Int)\s*\(` +
		`|readLine\s*\(\s*\)`,
)

// kotlinSanitizerRe matches common Kotlin sanitizer-call shapes for the
// cross-file pass. Distilled from kotlin_sanitizers.go. Kept narrow to
// avoid swallowing the canonical-fix path before the sink fires: integer /
// boolean coercion, path canonicalisation, HTML/regex escaping, validation
// guards, and parameterized-query builders.
var kotlinSanitizerRe = regexp.MustCompile(
	`\.(?:toInt|toIntOrNull|toLong|toLongOrNull|toDouble|toFloat|toBoolean|toBooleanStrictOrNull)\s*\(` +
		`|\.normalize\s*\(|\.canonicalPath\b|\.canonicalFile\b|\.toRealPath\s*\(|\.toAbsolutePath\s*\(` +
		`|\.escapeHTML\s*\(|Regex\.escape\s*\(|Pattern\.quote\s*\(` +
		`|\bIDN\.toASCII\s*\(|\bObjectId\s*\(|\bLdapName\s*\(` +
		`|\.setParameter\s*\(|\.replace\s*\(\s*Regex\s*\(` +
		`|\b(?:require|check)\s*\(` +
		`|@(?:Valid|Validated|NotNull|NotBlank|NotEmpty|Size|Pattern|Min|Max|Positive|Email)\b` +
		`|(?:validator|Validator)\.validate\s*\(`,
)

// kotlinReturnStmtRe captures the expression of a `return <expr>` statement
// even when it does not start the line — the compact Kotlin helper idiom
// `fun getName(req: Request): String { return req.queryParameter("n")!! }`
// keeps the body on the same line as the declaration. The capture group
// stops at `}` so the trailing brace of a single-line body isn't swept into
// the expression.
var kotlinReturnStmtRe = regexp.MustCompile(`\breturn\s+([^}]+)`)

// AnalyzeCallerImpactKotlin mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find Kotlin call expressions in the caller body and
// the Kotlin taint catalog to identify sinks / tainted returns inside the
// callee. Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule IDs
// the Go / Python / JS / Lua / C# paths use.
func AnalyzeCallerImpactKotlin(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactKotlinCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactKotlinCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core (crossfile_walk_core.go);
// this wrapper supplies the Kotlin config (kotlinCrossfileWalkCfg) and the
// call-site finder. Kotlin's Path B stays behind the config's customPathB
// hook (checkKotlinCallerUsesTaintedReturn) because it selects the single
// most-specific sink per line rather than every matching pattern.
func analyzeCallerImpactKotlinCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *kotlinCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		kotlinCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return kotlinCallSitesToShared(findKotlinCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// kotlinCallSitesToShared converts kotlinCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func kotlinCallSitesToShared(in []kotlinCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureKotlinCalleeSinks populates / re-validates calleeNode.TaintSig.Sink-
// Calls from the callee's REAL Kotlin body.
//
// Unlike the lazy "populate only when empty" pattern, this helper ALWAYS
// re-derives the Kotlin-catalog sinks present in the body and then
// RECONCILES the persisted SinkCalls against them. This is the phantom-sink
// defense (root cause 3): the same-file PropagateInterproc pass runs the
// Go sink-regex table (computeTaintSigInner) over every changed node
// regardless of language and PERSISTS the result onto the Kotlin node's
// TaintSig — so a Kotlin body can arrive here carrying a Go-derived sink
// that the Kotlin catalog would never produce. The held overload-FuncID
// collision (root cause 2) could likewise smear a genuine
// "GroovyShell.evaluate/parse" sink from one overload onto a sibling node
// whose actual body is `ConnectionOptions.parse`. In both cases the
// persisted SinkCall does NOT correspond to any sink text in THIS body.
//
// Reconciliation keeps only persisted SinkCalls whose (category, method)
// pair re-derives from the body, and adds any freshly-derived sinks the
// persisted set missed. A persisted set that survives re-derivation is
// trusted (it preserves ArgFromParam refinement); a phantom is dropped.
func ensureKotlinCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangKotlin {
		return
	}
	content, ok := loadCallerFile(cg, calleeNode.FilePath, map[string]string{})
	if !ok {
		// Can't load the body to validate. To be safe, drop any persisted
		// SinkCalls rather than trusting an unvalidatable (possibly phantom)
		// set — a missed finding is preferable to a phantom CRITICAL.
		calleeNode.TaintSig.SinkCalls = nil
		return
	}
	body := extractFuncBody(content, calleeNode.StartLine, calleeNode.EndLine)
	if body == "" {
		calleeNode.TaintSig.SinkCalls = nil
		return
	}

	derived := scanKotlinBodyForSinks(body, calleeNode.StartLine)
	bodyLines := strings.Split(body, "\n")
	for i := range derived {
		lineIdx := derived[i].Line - calleeNode.StartLine
		derived[i].ArgFromParam = findKotlinParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}

	// Reconcile any persisted SinkCalls against the freshly-derived set.
	// A persisted sink is genuine only if a derived sink shares its
	// (category, method) pair; otherwise it's a phantom and is dropped.
	derivedKey := make(map[string]bool, len(derived))
	for _, d := range derived {
		derivedKey[kotlinSinkKey(d.SinkCategory, d.MethodName)] = true
	}
	var reconciled []SinkRef
	seen := make(map[string]bool)
	for _, persisted := range calleeNode.TaintSig.SinkCalls {
		// Multi-hop INHERITED sinks (#37): a sink lifted up the call graph by
		// PropagateSignaturesAcrossCallgraph's appendInheritedSink carries an
		// OriginFile pointing at the leaf callee's file (and a "(via X)"
		// MethodName). Its dangerous call lives in a DOWNSTREAM body, not
		// THIS one, so it can never re-derive from THIS body — but it is a
		// genuine transitive flow, not a Go-regex phantom. Preserve it. The
		// phantom defense still applies to persisted sinks with an empty
		// OriginFile, which is exactly the same-file Go-regex-smear shape
		// this guards against.
		if persisted.OriginFile != "" {
			reconciled = append(reconciled, persisted)
			seen[kotlinSinkRefKey(persisted)] = true
			continue
		}
		k := kotlinSinkKey(persisted.SinkCategory, persisted.MethodName)
		if !derivedKey[k] {
			continue // phantom — not present in the real Kotlin body
		}
		reconciled = append(reconciled, persisted)
		seen[kotlinSinkRefKey(persisted)] = true
	}
	// Add freshly-derived sinks the persisted set missed (or the common
	// case where nothing was persisted yet).
	for _, d := range derived {
		if seen[kotlinSinkRefKey(d)] {
			continue
		}
		reconciled = append(reconciled, d)
		seen[kotlinSinkRefKey(d)] = true
	}

	calleeNode.TaintSig.SinkCalls = reconciled
	if len(reconciled) > 0 {
		calleeNode.TaintSig.IsPure = false
	}
	_ = cg
}

// kotlinSinkKey is the (category, method) identity of a sink, used to match
// a persisted SinkCall against a freshly-derived one during phantom
// reconciliation.
func kotlinSinkKey(cat taint.SinkCategory, method string) string {
	return string(cat) + "\x00" + method
}

// kotlinSinkRefKey adds the line so duplicate-suppression during
// reconciliation keys on the exact occurrence.
func kotlinSinkRefKey(s SinkRef) string {
	return fmt.Sprintf("%s\x00%s\x00%d", s.SinkCategory, s.MethodName, s.Line)
}

// ensureKotlinCalleeReturns populates / re-validates calleeNode.TaintSig.
// TaintedReturns from the callee's REAL Kotlin body by scanning for
// `return <source>`. This handles the canonical Ktor/Spring helper idiom
// where a method exposes a getter returning request-derived data.
//
// Like ensureKotlinCalleeSinks this ALWAYS re-derives from the body rather
// than trusting a persisted value: the same-file PropagateInterproc Go
// regex pass (computeTaintSigInner) can persist a TaintedReturns entry onto
// a Kotlin node that the Kotlin source catalog would never produce. We
// authoritatively set TaintedReturns from the Kotlin body scan — a body
// with no Kotlin-catalog source return clears any persisted phantom.
func ensureKotlinCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangKotlin {
		return
	}
	content, ok := loadCallerFile(cg, calleeNode.FilePath, map[string]string{})
	if !ok {
		// Unvalidatable — drop any persisted (possibly phantom) returns.
		calleeNode.TaintSig.TaintedReturns = nil
		return
	}
	body := extractFuncBody(content, calleeNode.StartLine, calleeNode.EndLine)
	if body == "" {
		calleeNode.TaintSig.TaintedReturns = nil
		return
	}
	cat, found := scanKotlinBodyForTaintedReturn(body)
	if !found {
		// No real tainted return in this body — clear any persisted phantom
		// so Path B doesn't fire off a Go-regex-seeded return.
		calleeNode.TaintSig.TaintedReturns = nil
		return
	}
	calleeNode.TaintSig.TaintedReturns = map[int][]taint.SourceCategory{
		0: {cat},
	}
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// scanKotlinBodyForTaintedReturn reports whether any `return` statement in
// the body carries a catalog source expression (`return req.queryParameter`,
// or `val v = req.queryParameter(...); return v`). Returns the source
// category. Also handles Kotlin's single-expression body form (no explicit
// `return`: `fun getName(req) = req.queryParameter("n")`).
func scanKotlinBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	// Track variables bound to a source expression so `val v = source;
	// return v` is recognised.
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Record `val x = <source>` / `var x = <source>` / `x = <source>`.
		if eq := kotlinAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if kotlinSourceExprRe.MatchString(rhs) && !kotlinSanitizerRe.MatchString(rhs) {
				name := kotlinLastIdent(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		// Match `return <expr>` anywhere on the line, not just at the start
		// — Kotlin commonly keeps a single-line body on the same line as the
		// declaration. Each captured expression is checked independently.
		for _, m := range kotlinReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" {
				continue
			}
			if kotlinSanitizerRe.MatchString(expr) {
				continue
			}
			if kotlinSourceExprRe.MatchString(expr) {
				return taint.SrcUserInput, true
			}
			// `return v` where v was bound to a source above.
			retVar := kotlinLastIdent(expr)
			if retVar != "" && taintedVars[retVar] {
				return taint.SrcUserInput, true
			}
		}
		// Kotlin single-expression body: `fun getName(req) = req.queryParameter("n")`.
		// The body text extracted starts at the function declaration; an `=`
		// directly binding the function to a source expression also counts.
		if eq := kotlinExprBodyEq(trimmed); eq > 0 {
			rhs := trimmed[eq+1:]
			if kotlinSourceExprRe.MatchString(rhs) && !kotlinSanitizerRe.MatchString(rhs) {
				return taint.SrcUserInput, true
			}
		}
	}
	return "", false
}

// kotlinAssignEq returns the index of the single `=` assignment operator in
// a line, or -1 when the line isn't a plain `val/var/x =` assignment (skips
// ==, !=, <=, >=, and the spread/typed forms). Only fires when the line
// looks like a binding (starts with val/var or an identifier-only LHS).
func kotlinAssignEq(line string) int {
	trimmed := strings.TrimSpace(line)
	// Only treat as an assignment when it begins with a binding keyword or a
	// bare identifier LHS (avoids matching `fun f() = ...` expression bodies,
	// which kotlinExprBodyEq handles, and comparisons).
	if !strings.HasPrefix(trimmed, "val ") && !strings.HasPrefix(trimmed, "var ") &&
		!kotlinLineLooksLikeAssign(trimmed) {
		return -1
	}
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, =>.
		if i+1 < len(line) && (line[i+1] == '=' || line[i+1] == '>') {
			i++
			continue
		}
		// Skip !=, <=, >=, ==.
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

// kotlinLineLooksLikeAssign reports whether a line that doesn't start with
// val/var still looks like a plain `x = expr` reassignment (the LHS before
// the first `=` is a single dotted/indexed identifier path with no `fun`
// keyword).
func kotlinLineLooksLikeAssign(trimmed string) bool {
	if strings.HasPrefix(trimmed, "fun ") || strings.Contains(trimmed, " fun ") {
		return false
	}
	eq := strings.IndexByte(trimmed, '=')
	if eq <= 0 {
		return false
	}
	lhs := strings.TrimSpace(trimmed[:eq])
	if lhs == "" {
		return false
	}
	// LHS must be a simple identifier / member / index path (no spaces, no
	// call parens) to qualify as an assignment target.
	if strings.ContainsAny(lhs, " (") {
		return false
	}
	return true
}

// kotlinExprBodyEq returns the index of the `=` that binds a single-
// expression function body (`fun getName(req) = expr`), or -1 when the line
// isn't an expression-body function. Requires the `fun` keyword and a `)`
// before the `=`.
func kotlinExprBodyEq(trimmed string) int {
	if !strings.HasPrefix(trimmed, "fun ") && !strings.Contains(trimmed, " fun ") {
		return -1
	}
	// Find `=` after the closing paren of the parameter list.
	rparen := strings.LastIndexByte(trimmed, ')')
	if rparen < 0 {
		return -1
	}
	for i := rparen + 1; i < len(trimmed); i++ {
		if trimmed[i] == '{' {
			return -1 // block body, not expression body
		}
		if trimmed[i] == '=' {
			if i+1 < len(trimmed) && (trimmed[i+1] == '=' || trimmed[i+1] == '>') {
				continue
			}
			return i
		}
	}
	return -1
}

// kotlinLastIdent returns the last identifier token in s (used to pull a
// variable name out of an LHS / return expression). A Kotlin binding LHS
// (`val n` or `var n: String`) yields the binding name "n".
func kotlinLastIdent(s string) string {
	s = strings.TrimSpace(s)
	// Strip a trailing type annotation (`n: String` → `n`) by cutting at the
	// first colon so the binding name, not the type, is the trailing token.
	if c := strings.IndexByte(s, ':'); c >= 0 {
		s = strings.TrimSpace(s[:c])
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// scanKotlinBodyForSinks walks the body line-by-line with each cached
// kotlinSinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanKotlinBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadKotlinSinkPatterns()
	if len(patterns) == 0 {
		return nil
	}
	lines := strings.Split(body, "\n")
	var out []SinkRef
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Select the single most-specific sink pattern matching this line
		// (not every pattern) so a `Runtime.getRuntime().exec(n)` line is
		// attributed only to the precise command-exec sink, never also to
		// the broad Exposed-ORM `\.exec\s*\(` sql_query sink. See
		// kotlinBestSinkMatch.
		p, ok := kotlinBestSinkMatch(patterns, line)
		if !ok {
			continue
		}
		// Same-line sanitizer suppression for HTML / redirect / SQL
		// categories — same rationale as the JS / Lua / C# helpers.
		if kotlinSanitizerRe.MatchString(line) && kotlinSinkLineSanitizerNeutralises(p.category) {
			continue
		}
		out = append(out, SinkRef{
			SinkCategory: p.category,
			MethodName:   p.method,
			Line:         startLine + i,
			ArgFromParam: -1,
		})
	}
	return out
}

// kotlinBestSinkMatch returns the single most-specific sink pattern matching
// `line`, or ok=false when none match. "Most specific" = the pattern whose
// regex matches the LONGEST substring of the line: a precise, anchored
// pattern like `Runtime\.getRuntime\(\)\.exec\s*\(` matches more characters
// than a bare `\.exec\s*\(`, so it wins. This collapses the catalog's
// deliberate over-broad/over-specific pattern pairs (e.g. Exposed ORM
// `.exec` vs Runtime.exec) to one finding per sink line, eliminating the
// phantom cross-category duplicate (CWE-89 on an OS-exec line). Ties (equal
// match length) keep the first pattern, which is stable across runs because
// loadKotlinSinkPatterns preserves catalog order.
func kotlinBestSinkMatch(patterns []kotlinSinkPattern, line string) (kotlinSinkPattern, bool) {
	var best kotlinSinkPattern
	bestLen := -1
	found := false
	for _, p := range patterns {
		loc := p.pattern.FindStringIndex(line)
		if loc == nil {
			continue
		}
		matchLen := loc[1] - loc[0]
		if matchLen > bestLen {
			bestLen = matchLen
			best = p
			found = true
		}
	}
	return best, found
}

// kotlinSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func kotlinSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkRedirect,
		taint.SnkTemplate, taint.SnkFileRead, taint.SnkFileWrite:
		return true
	}
	return false
}

// findKotlinParamFlowToSink returns the source-param index whose name
// appears in the sink line's argument expression, or -1 when none do.
func findKotlinParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
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

// checkKotlinCallerUsesTaintedReturn is the Kotlin analog of
// checkCSharpCallerUsesTaintedReturn (Path B). Triggers when callee has
// TaintedReturns and the caller stores the return value, then passes it to a
// sink. This is the v1 milestone path.
func checkKotlinCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs kotlinCallSite,
	callLineNum int,
	callerLines []string,
	callLineIdx int,
	sanGate *callerSanitizerGate,
) []rules.Finding {
	if len(calleeSig.TaintedReturns) == 0 {
		return nil
	}
	if isSanitizerByCalleeName(calleeNode.Name) || isSanitizerByCalleeName(callerNode.Name) {
		return nil
	}
	returnVar := cs.assignedTo
	if returnVar == "" {
		return nil
	}

	var findings []rules.Finding
	patterns := loadKotlinSinkPatterns()
	calleeBase := extractBaseName(calleeNode.Name)

	srcCatLabel := "tainted"
	srcCatJSON := string(taint.SrcExternal)
	for _, cats := range calleeSig.TaintedReturns {
		if len(cats) > 0 {
			srcCatLabel = string(cats[0])
			srcCatJSON = string(cats[0])
			break
		}
	}

	// Start at the call line itself (not callLineIdx+1) so the compact idiom
	// `val n = getName(req); exec(n)` — where the assignment and the sink
	// share one line — is covered. For the call line we additionally require
	// the returnVar sink usage to appear AFTER the callee call so a sink
	// positioned before the assignment isn't mis-attributed to this return.
	for i := callLineIdx; i < len(callerLines); i++ {
		line := callerLines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if !containsToken(line, returnVar) {
			continue
		}
		if i == callLineIdx {
			callPos := strings.Index(line, calleeBase+"(")
			if callPos < 0 || !tokenAfter(line, returnVar, callPos) {
				continue
			}
		}
		// Sanitizer between call and sink for the same variable.
		sanitized := false
		for j := callLineIdx + 1; j < i; j++ {
			if kotlinSanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
				sanitized = true
				break
			}
		}
		if sanitized {
			continue
		}

		// Select the SINGLE most-specific sink pattern that matches this
		// line, not every pattern. The Kotlin catalog has both a broad
		// `\.exec\s*\(` (Exposed ORM → sql_query) and a precise
		// `Runtime\.getRuntime\(\)\.exec\s*\(` (→ command_exec); a raw
		// `Runtime.getRuntime().exec(n)` matches BOTH, so iterating every
		// pattern emitted a phantom CWE-89 SQL finding alongside the genuine
		// CWE-78 command-exec one. The pattern with the LONGEST matched
		// substring is the most anchored / specific, so it wins.
		p, ok := kotlinBestSinkMatch(patterns, line)
		if !ok {
			continue
		}
		// Catalog-backed sanitizer gate: returnVar was rebound from a
		// catalog sanitizer neutralising this category before the sink
		// line (last-assignment-wins; the tainted call assignment
		// itself is a plain fact that revokes any earlier sanitize).
		if sanGate.argSanitized(returnVar, callerNode.StartLine+i, p.category) {
			continue
		}
		{
			sinkLineNum := callerNode.StartLine + i
			sev := severityForSinkCategory[p.category]
			if sev < rules.High {
				sev = rules.High
			}
			cwe := cweForSinkCategory[p.category]
			owasp := owaspForSinkCategory[p.category]

			taintPath := []rules.TaintStep{
				{
					File:  calleeNode.FilePath,
					Line:  calleeNode.StartLine,
					Kind:  rules.TaintStepSource,
					Label: fmt.Sprintf("%s() returns %s data", calleeNode.Name, srcCatLabel),
				},
				{
					File:  callerNode.FilePath,
					Line:  callLineNum,
					Kind:  rules.TaintStepPropagation,
					Label: fmt.Sprintf("result of %s(...) assigned to %s", calleeBase, returnVar),
				},
				{
					File:  callerNode.FilePath,
					Line:  sinkLineNum,
					Kind:  rules.TaintStepSink,
					Label: p.method,
				},
			}

			findings = append(findings, rules.Finding{
				RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(p.category))),
				Severity:      sev,
				SeverityLabel: sev.String(),
				Title: fmt.Sprintf(
					"Interprocedural taint: %s data from %s() reaches %s",
					srcCatLabel, calleeNode.Name, p.method,
				),
				Description: fmt.Sprintf(
					"Return value of %s() (called at %s:%d) carries %s taint. "+
						"The caller %s() stores it in '%s' and passes it to %s at line %d "+
						"without sanitization, creating a cross-file %s vulnerability.",
					calleeNode.Name, callerNode.FilePath, callLineNum,
					srcCatLabel,
					callerNode.Name, returnVar, p.method, sinkLineNum,
					p.category,
				),
				FilePath:   callerNode.FilePath,
				LineNumber: sinkLineNum,
				MatchedText: fmt.Sprintf(
					"%s() -> %s -> %s (line %d)",
					calleeNode.Name, returnVar, p.method, sinkLineNum,
				),
				TaintPath: taintPath,
				Suggestion: fmt.Sprintf(
					"Sanitize '%s' (returned by %s()) before passing it to %s.",
					returnVar, calleeNode.Name, p.method,
				),
				CWEID:           cwe,
				OWASPCategory:   owasp,
				Confidence:      "high",
				ConfidenceScore: 0.8,
				SourceCategory:  srcCatJSON,
				SinkCategory:    string(p.category),
				Language:        calleeNode.Language,
				Tags: []string{
					"interprocedural", "taint-analysis", "cross-function",
					"return-taint", "kotlin", string(p.category),
				},
			})
		}
	}
	return findings
}

// kotlinRootIdent returns the leading variable name of an expression,
// stripping a `.field` / `[index]` / `(args)` tail (`req.queryParameter` →
// "req").
func kotlinRootIdent(expr string) string {
	root := strings.TrimSpace(expr)
	if i := strings.IndexAny(root, ".[("); i > 0 {
		root = root[:i]
	}
	return strings.TrimSpace(root)
}
