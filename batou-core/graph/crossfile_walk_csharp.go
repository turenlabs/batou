// C# cross-file interprocedural walker.
//
// The Go-default AnalyzeCallerImpact in interprocedural.go scans the
// caller body with the Go sink regex table (db.Query, exec.Command, etc.)
// and uses Go arg parsing. Routing C# through that path emits zero
// findings — C# calls never match Go sink shapes.
//
// This file is the C# analog of crossfile_walk_javascript.go. It uses the
// C# taint catalog (SinksForLanguage) to identify sinks inside callee
// bodies, scans callee bodies for tainted `return` expressions, and a
// coarse direct-source regex for typical ASP.NET Core / MVC request shapes
// (`req.Query["n"]`, `Request.Form[...]`, `[FromQuery]`, ...).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a C# callee that
//     forwards it into a sink. Direct source expressions in the call site
//     are recognised by csharpSourceExprRe.
//   - Path B: callee returns tainted data (`return req.Query["n"];`) and
//     the caller stores the result then passes it to a sink. Recognised
//     when the callee has TaintedReturns set; ensureCSharpCalleeReturns
//     scans the callee body for `return <source-expr>` on the fly, so the
//     canonical ASP.NET helper idiom fires without planted test data.
//   - 1-hop interproc only.
//
// As with the JS / Lua walkers, the C# walker IS allowed to populate a
// callee's TaintSig.SinkCalls / TaintedReturns on the fly when empty — the
// same-file PropagateInterproc path doesn't run C# sink regex.
//
// Every helper here is reached only for rules.LangCSharp callees: the
// dispatcher in crossfile_walk.go routes to analyzeCallerImpactCSharpCached
// solely from its `case rules.LangCSharp` arm.

package graph

import (
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// csharpSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadCSharpSink-
// Patterns returns the shared shape the walk core's config + shared Path B
// consume without conversion (mirrors rubySinkPattern). The module/
// requireModule fields stay zero-valued — the C# walker doesn't use them.
type csharpSinkPattern = crossfileSinkPattern

var (
	csharpSinkPatternsCache   []csharpSinkPattern
	csharpSinkPatternsCacheMu sync.Mutex
)

// loadCSharpSinkPatterns compiles and caches the C# taint sink catalog
// into regex form.
func loadCSharpSinkPatterns() []csharpSinkPattern {
	csharpSinkPatternsCacheMu.Lock()
	defer csharpSinkPatternsCacheMu.Unlock()
	if csharpSinkPatternsCache != nil {
		return csharpSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangCSharp)
	out := make([]csharpSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, csharpSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	csharpSinkPatternsCache = out
	return out
}

// csharpSourceExprRe matches taint source expressions in a C# arg /
// return position. Distilled from csharp_sources.go (ASP.NET Core / MVC
// request shapes, environment, console, route binding). The HTTP request
// accessors are matched on either the framework `Request.` receiver OR a
// common request-variable name (`req`, `request`, `httpRequest`,
// `HttpContext.Request`) so the canonical helper idiom
// `GetName(HttpRequest req){ return req.Query["n"]; }` is recognised
// without type inference. Conservative on purpose — the two-sided
// source→sink gate suppresses standalone matches.
var csharpSourceExprRe = regexp.MustCompile(
	`(?:Request|req|request|httpRequest|HttpContext\.Request)\.(?:Query|Form|Headers|Cookies|Body|RouteValues|QueryString|Path|ContentType|Host)\b` +
		`|Console\.ReadLine\s*\(` +
		`|Environment\.GetEnvironmentVariable\s*\(` +
		`|Environment\.GetCommandLineArgs\s*\(|Environment\.CommandLine\b` +
		`|\[From(?:Query|Body|Form|Route|Header)\]` +
		`|RouteData\.Values\[` +
		`|TempData\[` +
		`|ModelState\[`,
)

// csharpSanitizerRe matches common C# sanitizer-call shapes for the
// cross-file pass. Distilled from csharp_sanitizers.go. Kept narrow to
// avoid swallowing the canonical-fix path before the sink fires: HTML / URL
// encoders, path canonicalisation, integer coercion, and parameterized-SQL
// builders.
// Two groups: encoder/helper FAMILIES (matched on the distinctive type
// prefix — `UrlEncoder.Default.Encode(...)` separates the `.Encode(` call
// from the `UrlEncoder.` prefix by an intermediate `.Default`, so we don't
// require an immediate call paren for these) and concrete CALL shapes
// (matched with a trailing `(`).
var csharpSanitizerRe = regexp.MustCompile(
	`\b(?:HtmlEncoder|UrlEncoder|AntiXssEncoder)\.` +
		`|\b(?:` +
		`WebUtility\.HtmlEncode` +
		`|HttpUtility\.HtmlEncode` +
		`|WebUtility\.UrlEncode` +
		`|HttpUtility\.UrlEncode` +
		`|Uri\.EscapeDataString` +
		`|Path\.GetFileName` +
		`|Path\.GetFullPath` +
		`|Regex\.Escape` +
		`|int\.Parse|int\.TryParse|Int32\.Parse|Int32\.TryParse|Convert\.ToInt32` +
		`|SqlParameter` +
		`|\.Parameters\.Add` +
		`|Url\.IsLocalUrl` +
		`)\s*\(`,
)

// csReturnStmtRe captures the expression of a `return <expr>;` statement
// even when it does not start the line — the compact C# helper idiom
// `string GetName(HttpRequest req){ return req.Query["n"]; }` keeps the
// body on the same line as the declaration. The capture group stops at `;`
// or `}` so the trailing brace of a single-line body isn't swept into the
// expression.
var csReturnStmtRe = regexp.MustCompile(`\breturn\s+([^;}]+)`)

// AnalyzeCallerImpactCSharp mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find C# call expressions in the caller body and the
// C# taint catalog to identify sinks / tainted returns inside the callee.
// Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule IDs the
// Go / Python / JS / Lua paths use.
func AnalyzeCallerImpactCSharp(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactCSharpCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactCSharpCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core (crossfile_walk_core.go);
// this wrapper only supplies the C# config (csharpCrossfileWalkCfg) and the
// call-site finder. Unlike the other batch-2 languages, C#'s Path B IS the
// shared forward-scan shape, so it folds fully into the shared core (no
// customPathB) via the pathBCrossFileVulnWording knob.
func analyzeCallerImpactCSharpCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *csharpCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		csharpCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return csharpCallSitesToShared(findCSharpCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// csharpCallSitesToShared converts csharpCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func csharpCallSitesToShared(in []csharpCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureCSharpCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls
// when it's empty. Idempotent.
func ensureCSharpCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangCSharp {
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
	sinks := scanCSharpBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findCSharpParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensureCSharpCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for `return <source>`.
// This handles the canonical ASP.NET helper idiom where a method exposes
// a getter returning request-derived data. Idempotent.
func ensureCSharpCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangCSharp {
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
	cat, found := scanCSharpBodyForTaintedReturn(body)
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

// scanCSharpBodyForTaintedReturn reports whether any `return` statement in
// the body carries a catalog source expression (`return req.Query["n"]`,
// or `var v = req.Form["x"]; return v;`). Returns the source category.
func scanCSharpBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	// Track variables bound to a source expression so `var v = source;
	// return v;` is recognised.
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Record `var x = <source>` / `string x = <source>` / `x = <source>`.
		if eq := csAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if csharpSourceExprRe.MatchString(rhs) && !csharpSanitizerRe.MatchString(rhs) {
				name := csLastIdent(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		// Match `return <expr>` anywhere on the line, not just at the start
		// — C# commonly keeps a single-line body on the same line as the
		// declaration. Each captured expression is checked independently.
		for _, m := range csReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" {
				continue
			}
			if csharpSanitizerRe.MatchString(expr) {
				continue
			}
			if csharpSourceExprRe.MatchString(expr) {
				return taint.SrcUserInput, true
			}
			// `return v` where v was bound to a source above.
			retVar := csLastIdent(expr)
			if retVar != "" && taintedVars[retVar] {
				return taint.SrcUserInput, true
			}
		}
	}
	return "", false
}

// csAssignEq returns the index of the single `=` assignment operator in a
// line, or -1 when the line isn't a plain assignment (skips ==, !=, <=,
// >=, =>, and the null-coalescing-assignment ??=).
func csAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, =>.
		if i+1 < len(line) && (line[i+1] == '=' || line[i+1] == '>') {
			i++
			continue
		}
		// Skip !=, <=, >=, ==, ??=.
		if i > 0 {
			prev := line[i-1]
			if prev == '!' || prev == '<' || prev == '>' || prev == '=' || prev == '?' {
				continue
			}
		}
		return i
	}
	return -1
}

// csLastIdent returns the last identifier token in s (used to pull a
// variable name out of an LHS / return expression). A C# typed
// declaration LHS (`string n`) yields the binding name "n" because it is
// the trailing token.
func csLastIdent(s string) string {
	s = strings.TrimSpace(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// scanCSharpBodyForSinks walks the body line-by-line with each cached
// csharpSinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanCSharpBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadCSharpSinkPatterns()
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
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			// Same-line sanitizer suppression for HTML / redirect / SQL
			// categories — same rationale as the JS / Lua helpers.
			if csharpSanitizerRe.MatchString(line) && csharpSinkLineSanitizerNeutralises(p.category) {
				continue
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

// csharpSinkLineSanitizerNeutralises returns true for sink categories
// whose matched-on-the-same-line sanitiser call should suppress the sink.
func csharpSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkHTMLOutput, taint.SnkRedirect,
		taint.SnkTemplate, taint.SnkFileRead, taint.SnkFileWrite:
		return true
	}
	return false
}

// findCSharpParamFlowToSink returns the source-param index whose name
// appears in the sink line's argument expression, or -1 when none do.
func findCSharpParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
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

// csRootIdent returns the leading variable name of an expression,
// stripping a `.field` / `[index]` / `(args)` tail (`req.Query` → "req").
func csRootIdent(expr string) string {
	root := strings.TrimSpace(expr)
	if i := strings.IndexAny(root, ".[("); i > 0 {
		root = root[:i]
	}
	return strings.TrimSpace(root)
}
