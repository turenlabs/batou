// Swift cross-file interprocedural walker (PR-Gswift).
//
// Like the JS / Lua / Ruby equivalents, the Go-default
// AnalyzeCallerImpact in interprocedural.go scans the caller body with
// the Go sink regex table and uses Go arg parsing. Routing Swift through
// that path emits zero findings — Swift calls never match Go sink shapes.
//
// This file mirrors crossfile_walk_lua.go (consumer half) and
// crossfile_walk_javascript.go (tainted-return producer half). It uses
// the Swift taint catalog (SinksForLanguage) to identify sinks inside
// callee bodies and tainted returns, and a coarse direct-source regex for
// typical Vapor / Hummingbird / UIKit / Foundation request shapes
// (`req.query[...]`, `CommandLine.arguments`, `ProcessInfo...`, ...).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a Swift callee (in
//     another file of the same module) that forwards it into a sink.
//   - Path B: callee returns tainted data and the caller passes the
//     result to a sink. ensureSwiftCalleeReturns scans the callee body
//     for `return <source-expr>` and populates TaintedReturns on the fly,
//     so the canonical Vapor idiom — `func getName(_ req: Request) ->
//     String { return req.query["n"]! }` in a.swift, `let n =
//     getName(req); system(n)` in b.swift — fires without planted test
//     data. THE V1 MILESTONE is Path B.
//   - 1-hop interproc only.
//
// Every helper here is reached only for rules.LangSwift callees: the
// dispatcher in crossfile_walk.go routes to analyzeCallerImpactSwiftCached
// solely from its `case rules.LangSwift` arm.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// swiftSinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadSwiftSink-
// Patterns returns the shared shape the walk core's config consumes without
// conversion (mirrors rubySinkPattern). The module/requireModule fields stay
// zero-valued — the Swift walker doesn't use them.
type swiftSinkPattern = crossfileSinkPattern

var (
	swiftSinkPatternsCache   []swiftSinkPattern
	swiftSinkPatternsCacheMu sync.Mutex
)

// loadSwiftSinkPatterns compiles and caches the Swift taint sink catalog
// into regex form.
func loadSwiftSinkPatterns() []swiftSinkPattern {
	swiftSinkPatternsCacheMu.Lock()
	defer swiftSinkPatternsCacheMu.Unlock()
	if swiftSinkPatternsCache != nil {
		return swiftSinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangSwift)
	out := make([]swiftSinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, swiftSinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	swiftSinkPatternsCache = out
	return out
}

// swiftSourceExprRe matches taint source expressions in a Swift arg
// position. Distilled from swift_sources.go — Vapor / Hummingbird request
// shapes plus Foundation / UIKit user-input sources. Conservative: only
// the high-signal attacker-controlled accessors so a standalone match in
// a non-source context does not flood (the two-sided sink gate suppresses
// spurious pairs regardless).
var swiftSourceExprRe = regexp.MustCompile(
	`req\.query\[` +
		`|req\.parameters\.get\s*\(` +
		`|req\.headers\[` +
		`|req\.cookies\[` +
		`|req\.content\b` +
		`|req\.body\.(?:string|data|collect)` +
		`|request\.body\.(?:string|data)` +
		`|request\.uri\.(?:path|queryString|string)` +
		`|request\.parameters\.get\s*\(` +
		`|CommandLine\.arguments` +
		`|ProcessInfo\.processInfo\.(?:environment|arguments)` +
		`|\bgetenv\s*\(` +
		`|UserDefaults\.standard\.(?:string|object|data)\s*\(` +
		`|(?:[tT]extField|input|[fF]ield)\.text\b` +
		`|\.queryItems\b` +
		`|\.queryParams\b`,
)

// swiftSanitizerRe matches common Swift sanitizer-call shapes for the
// cross-file pass. Distilled from swift_sanitizers.go. Kept narrow to
// avoid swallowing the canonical-fix path before the sink fires:
// numeric-coercion initializers neutralise SQL/command/path taint;
// addingPercentEncoding covers URL escaping; sqlite3_bind_* is
// parameterized-query binding; allowlist/allowedHosts.contains is
// host validation.
var swiftSanitizerRe = regexp.MustCompile(
	`\bInt\s*\(` +
		`|\bDouble\s*\(` +
		`|\bFloat\s*\(` +
		`|\bUInt\d*\s*\(` +
		`|\bInt\d+\s*\(` +
		`|\.addingPercentEncoding\s*\(` +
		`|sqlite3_bind_(?:text|int|int64|double|blob)\s*\(` +
		`|allowedHosts\.contains\s*\(` +
		`|allowlist\.contains\s*\(` +
		`|whitelist\.contains\s*\(` +
		`|UUID\(\s*uuidString:`,
)

// AnalyzeCallerImpactSwift mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find Swift call expressions in the caller body and
// the Swift taint catalog to identify sinks / tainted returns inside the
// callee. Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule
// IDs the Go / Python / JS / Lua paths use.
func AnalyzeCallerImpactSwift(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactSwiftCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactSwiftCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core (crossfile_walk_core.go);
// this wrapper supplies the Swift config (swiftCrossfileWalkCfg) and the
// call-site finder. Swift's Path B stays behind the config's customPathB
// hook (checkSwiftCallerUsesTaintedReturn) because it fires an inline-sink
// and a via-variable case independently for one call site.
func analyzeCallerImpactSwiftCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *swiftCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		swiftCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return swiftCallSitesToShared(findSwiftCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// swiftCallSitesToShared converts swiftCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func swiftCallSitesToShared(in []swiftCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureSwiftCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls
// when it's empty. Idempotent.
func ensureSwiftCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangSwift {
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
	sinks := scanSwiftBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findSwiftParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensureSwiftCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for `return <source>`.
// This handles the canonical Vapor module idiom where a helper returns
// request-derived data. Idempotent.
func ensureSwiftCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangSwift {
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
	cat, found := scanSwiftBodyForTaintedReturn(body)
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

// scanSwiftBodyForTaintedReturn reports whether any `return` statement in
// the body carries a catalog source expression (`return req.query["n"]!`,
// or `let v = req.query["n"] ... return v`). Returns the source category.
func scanSwiftBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	// Track variables bound to a source expression so `let v = source;
	// return v` is recognised.
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Record `let x = <source>` / `var x = <source>` / `x = <source>`
		// bindings.
		if eq := swiftAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if swiftSourceExprRe.MatchString(rhs) && !swiftSanitizerRe.MatchString(rhs) {
				name := swiftBindingName(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		// Match `return <expr>` anywhere on the line — Swift commonly keeps
		// a single-line body on the same line as the `func ... {`
		// declaration.
		for _, m := range swiftReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" {
				continue
			}
			if swiftSanitizerRe.MatchString(expr) {
				continue
			}
			if swiftSourceExprRe.MatchString(expr) {
				return taint.SrcUserInput, true
			}
			// `return v` where v was bound to a source above.
			retVar := swiftLastIdent(expr)
			if retVar != "" && taintedVars[retVar] {
				return taint.SrcUserInput, true
			}
		}
	}
	return "", false
}

// swiftReturnStmtRe captures the expression of a `return <expr>` statement
// even when it does not start the line — the compact Swift idiom
// `func getName(_ req: Request) -> String { return req.query["n"]! }`
// keeps the body on the same line as the declaration. The capture group
// stops at `}` so the trailing brace of a single-line body isn't swept in.
var swiftReturnStmtRe = regexp.MustCompile(`\breturn\s+([^}]+)`)

// swiftAssignEq returns the index of the single `=` assignment operator in
// a line, or -1 when the line isn't a plain assignment (skips ==, !=, <=,
// >=, ??=, and the Swift nil-coalescing `??`).
func swiftAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, ===.
		if i+1 < len(line) && line[i+1] == '=' {
			i++
			continue
		}
		// Skip !=, <=, >=, ?? prefix forms.
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

// swiftBindingName returns the bound variable name from an LHS that may
// carry a `let` / `var` keyword (`let n` → "n").
func swiftBindingName(lhs string) string {
	lhs = strings.TrimSpace(lhs)
	lhs = strings.TrimPrefix(lhs, "let ")
	lhs = strings.TrimPrefix(lhs, "var ")
	return swiftLastIdent(lhs)
}

// scanSwiftBodyForSinks walks the body line-by-line with each cached
// swiftSinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanSwiftBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadSwiftSinkPatterns()
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
			// Same-line sanitizer suppression: a SQL/command/path sink whose
			// argument is wrapped in a numeric coercion / binding is safe.
			if swiftSanitizerRe.MatchString(line) && swiftSinkLineSanitizerNeutralises(p.category) {
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

// swiftSinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func swiftSinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput,
		taint.SnkRedirect, taint.SnkTemplate, taint.SnkFileRead,
		taint.SnkFileWrite, taint.SnkURLFetch:
		return true
	}
	return false
}

// findSwiftParamFlowToSink returns the source-param index whose name
// appears in the sink line's argument expression, or -1 when none do.
func findSwiftParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
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

// checkSwiftCallerUsesTaintedReturn is the Swift analog of
// checkLuaCallerUsesTaintedReturn (Path B). Triggers when the callee has
// TaintedReturns and the caller passes the result to a sink — either via
// an intermediate variable (`let x = getName(req); system(x)`) or inlined
// directly (`system(getName(req))`).
func checkSwiftCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs swiftCallSite,
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

	srcCatLabel := "tainted"
	srcCatJSON := string(taint.SrcExternal)
	for _, cats := range calleeSig.TaintedReturns {
		if len(cats) > 0 {
			srcCatLabel = string(cats[0])
			srcCatJSON = string(cats[0])
			break
		}
	}
	calleeBaseName := extractBaseName(calleeNode.Name)
	patterns := loadSwiftSinkPatterns()

	var findings []rules.Finding

	emit := func(sinkLineNum int, sinkMethod string, cat taint.SinkCategory, propLabel string) {
		sev := severityForSinkCategory[cat]
		if sev < rules.High {
			sev = rules.High
		}
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
				Label: propLabel,
			},
			{
				File:  callerNode.FilePath,
				Line:  sinkLineNum,
				Kind:  rules.TaintStepSink,
				Label: sinkMethod,
			},
		}
		findings = append(findings, rules.Finding{
			RuleID:        fmt.Sprintf("BATOU-INTERPROC-%s", strings.ToUpper(string(cat))),
			Severity:      sev,
			SeverityLabel: sev.String(),
			Title: fmt.Sprintf(
				"Interprocedural taint: %s data from %s() reaches %s",
				srcCatLabel, calleeNode.Name, sinkMethod,
			),
			Description: fmt.Sprintf(
				"Return value of %s() (called at %s:%d) carries %s taint from another file in the module. "+
					"The caller %s() passes it to %s at line %d without sanitization, "+
					"creating a cross-file %s vulnerability.",
				calleeNode.Name, callerNode.FilePath, callLineNum,
				srcCatLabel, callerNode.Name, sinkMethod, sinkLineNum, cat,
			),
			FilePath:   callerNode.FilePath,
			LineNumber: sinkLineNum,
			MatchedText: fmt.Sprintf(
				"%s() -> %s (line %d)",
				calleeNode.Name, sinkMethod, sinkLineNum,
			),
			TaintPath: taintPath,
			Suggestion: fmt.Sprintf(
				"Sanitize the value returned by %s() (e.g. coerce to Int/UUID or use a parameterized API) before passing it to %s.",
				calleeNode.Name, sinkMethod,
			),
			CWEID:           cweForSinkCategory[cat],
			OWASPCategory:   owaspForSinkCategory[cat],
			Confidence:      "high",
			ConfidenceScore: 0.8,
			SourceCategory:  srcCatJSON,
			SinkCategory:    string(cat),
			Language:        calleeNode.Language,
			Tags: []string{
				"interprocedural", "taint-analysis", "cross-function",
				"return-taint", "swift", string(cat),
			},
		})
	}

	// Case 1: inlined sink — the callee call itself is an argument to a
	// sink on the SAME line (`system(getName(req))`).
	if callLineIdx >= 0 && callLineIdx < len(callerLines) {
		line := callerLines[callLineIdx]
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			if swiftSanitizerRe.MatchString(line) && swiftSinkLineSanitizerNeutralises(p.category) {
				continue
			}
			emit(callLineNum, p.method, p.category,
				fmt.Sprintf("result of %s(...) passed inline to sink", calleeBaseName))
		}
	}

	// Case 2: intermediate variable — `let x = getName(req)` then a later
	// line uses x in a sink.
	returnVar := cs.assignedTo
	if returnVar != "" {
		for i := callLineIdx + 1; i < len(callerLines); i++ {
			line := callerLines[i]
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !containsToken(line, returnVar) {
				continue
			}
			// Sanitizer between call and sink for the same variable.
			sanitized := false
			for j := callLineIdx + 1; j < i; j++ {
				if swiftSanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
					sanitized = true
					break
				}
			}
			if sanitized {
				continue
			}

			for _, p := range patterns {
				if !p.pattern.MatchString(line) {
					continue
				}
				// Catalog-backed sanitizer gate: returnVar was rebound from a
				// catalog sanitizer neutralising this category before the sink
				// line (last-assignment-wins; the tainted call assignment
				// itself is a plain fact that revokes any earlier sanitize).
				if sanGate.argSanitized(returnVar, callerNode.StartLine+i, p.category) {
					continue
				}
				if swiftSanitizerRe.MatchString(line) && swiftSinkLineSanitizerNeutralises(p.category) {
					continue
				}
				sinkLineNum := callerNode.StartLine + i
				emit(sinkLineNum, p.method, p.category,
					fmt.Sprintf("result of %s(...) assigned to %s", calleeBaseName, returnVar))
			}
		}
	}

	return findings
}

// swiftRootIdent returns the leading variable name of an expression,
// stripping a `.field` / `[index]` / `(args)` tail (`req.query` → "req").
func swiftRootIdent(expr string) string {
	root := strings.TrimSpace(expr)
	root = strings.TrimPrefix(root, "let ")
	root = strings.TrimPrefix(root, "var ")
	if i := strings.IndexAny(root, ".[(?!"); i > 0 {
		root = root[:i]
	}
	return strings.TrimSpace(root)
}
