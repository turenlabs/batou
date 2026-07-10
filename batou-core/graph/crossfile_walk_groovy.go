// Groovy cross-file interprocedural walker (PR-Ggroovy).
//
// Like the Swift / JS / Lua equivalents, the Go-default AnalyzeCallerImpact
// in interprocedural.go scans the caller body with the Go sink regex table
// and uses Go arg parsing. Routing Groovy through that path emits zero
// findings — Groovy calls never match Go sink shapes.
//
// This file mirrors crossfile_walk_swift.go (consumer half) and the JS
// tainted-return producer half. It uses the Groovy taint catalog
// (SinksForLanguage) to identify sinks inside callee bodies and tainted
// returns, and a coarse direct-source regex for typical Grails / Servlet /
// Jenkins / Micronaut request shapes (`req.getParameter(...)`,
// `params.x`, `request.getHeader(...)`, `System.getenv(...)`, ...).
//
// Scope:
//
//   - Path A: caller passes a tainted argument to a Groovy callee (in
//     another file of the same module) that forwards it into a sink.
//   - Path B: callee returns tainted data and the caller passes the result
//     to a sink. ensureGroovyCalleeReturns scans the callee body for
//     `return <source-expr>` and populates TaintedReturns on the fly, so
//     the canonical idiom — `String getName(req) { return
//     req.getParameter("n") }` in A.groovy, and the SCRIPT `def n =
//     getName(req); "cmd $n".execute()` in B.groovy — fires without planted
//     test data. THE V1 MILESTONE is Path B with the caller being a Groovy
//     SCRIPT (top-level statements, not a declared function).
//   - 1-hop interproc only.
//
// Every helper here is reached only for rules.LangGroovy callees: the
// dispatcher in crossfile_walk.go routes to analyzeCallerImpactGroovyCached
// solely from its `case rules.LangGroovy` arm.

package graph

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// groovySinkPattern is a compiled SinkDef plus metadata so the helpers can
// scan callee bodies without hitting the catalog every time. Alias of the
// shared crossfileSinkPattern (crossfile_walk_core.go) so loadGroovySink-
// Patterns returns the shared shape the walk core's config consumes without
// conversion (mirrors rubySinkPattern). The module/requireModule fields stay
// zero-valued — the Groovy walker doesn't use them.
type groovySinkPattern = crossfileSinkPattern

var (
	groovySinkPatternsCache   []groovySinkPattern
	groovySinkPatternsCacheMu sync.Mutex
)

// loadGroovySinkPatterns compiles and caches the Groovy taint sink catalog
// into regex form.
func loadGroovySinkPatterns() []groovySinkPattern {
	groovySinkPatternsCacheMu.Lock()
	defer groovySinkPatternsCacheMu.Unlock()
	if groovySinkPatternsCache != nil {
		return groovySinkPatternsCache
	}
	sinks := taint.SinksForLanguage(rules.LangGroovy)
	out := make([]groovySinkPattern, 0, len(sinks))
	for _, s := range sinks {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, groovySinkPattern{
			pattern:  re,
			category: s.Category,
			method:   s.MethodName,
		})
	}
	groovySinkPatternsCache = out
	return out
}

// groovySourceExprRe matches taint source expressions in a Groovy arg /
// return position. Distilled from groovy_sources.go — Grails / Servlet /
// Micronaut / Jenkins / Ratpack / Vert.x request shapes plus
// System/environment user-input sources. The HTTP request accessors are
// matched on either the framework `request.` receiver OR a common
// request-variable name (`req`), so the canonical helper idiom
// `String getName(req) { return req.getParameter("n") }` is recognised
// without type inference. Conservative on purpose — the two-sided
// source→sink gate suppresses standalone matches.
var groovySourceExprRe = regexp.MustCompile(
	`(?:request|req|httpRequest)\.getParameter\s*\(` +
		`|(?:request|req|httpRequest)\.getHeader\s*\(` +
		`|(?:request|req|httpRequest)\.getParameterMap\s*\(` +
		`|(?:request|req|httpRequest)\.getQueryString\s*\(` +
		`|(?:request|req|httpRequest)\.getInputStream\s*\(` +
		`|(?:request|req|httpRequest)\.getReader\s*\(` +
		`|(?:request|req|httpRequest)\.getParameters\s*\(` +
		`|(?:request|req|httpRequest)\.getHeaders\s*\(` +
		`|(?:request|req|httpRequest)\.getCookies\s*\(` +
		`|(?:request|req|httpRequest)\.getBody\s*\(` +
		`|(?:request|req|httpRequest)\.getParam\s*\(` +
		`|(?:request|req|httpRequest)\.getFile\s*\(` +
		`|request\.JSON\b|request\.XML\b` +
		`|request\.forwardURI\b|request\.requestURI\b|request\.queryString\b` +
		`|\bparams\.\w+|\bparams\[` +
		`|\bsession\.\w+|\bsession\[` +
		`|\bcookies\.\w+` +
		`|\bheaders\s*\[|\bheaders\.\w` +
		`|System\.getenv\s*\(` +
		`|\benv\.\w+` +
		`|@(?:QueryValue|PathVariable|Body|Header|CookieValue|QueryParam|PathParam)\b` +
		`|\.queryParam\s*\(|\.pathParams?\s*\(` +
		`|\.bodyAsJson\s*\(|\.bodyAsString\s*\(` +
		`|System\.console\s*\(\s*\)\s*\.readLine\s*\(`,
)

// groovySanitizerRe matches common Groovy sanitizer-call shapes for the
// cross-file pass. Distilled from groovy_sanitizers.go. Kept narrow to
// avoid swallowing the canonical-fix path before the sink fires: numeric
// coercion neutralises SQL/command/path taint; HTML/URL encoders and OWASP
// Encoder cover output contexts; allowlist.contains is value validation;
// path canonicalization covers traversal; single-quoted Jenkins sh strings
// are non-interpolating.
var groovySanitizerRe = regexp.MustCompile(
	`Integer\.parseInt\s*\(` +
		`|\.toInteger\s*\(|\.toLong\s*\(|\.toDouble\s*\(|\.toFloat\s*\(` +
		`|\bas\s+Integer\b|\bas\s+Long\b` +
		`|URLEncoder\.encode\s*\(` +
		`|HtmlUtils\.htmlEscape\s*\(` +
		`|StringEscapeUtils\.escape(?:Html|Xml|Java|Json|EcmaScript)\w*\s*\(` +
		`|\.encodeAs(?:HTML|URL|JavaScript|Base64)\s*\(` +
		`|Encode\.for(?:Html|JavaScript|Java|Css\w*|Uri\w*|Xml\w*)\s*\(` +
		`|ESAPI\.encoder\s*\(\s*\)` +
		`|Jsoup\.clean\s*\(` +
		`|\.getCanonicalPath\s*\(|\.getCanonicalFile\s*\(|\.toRealPath\s*\(` +
		`|FilenameUtils\.(?:getName|normalize)\s*\(` +
		`|\b(?:allowlist|whitelist|allowed|valid\w*)\s*\.\s*contains\s*\(` +
		`|Pattern\.quote\s*\(`,
)

// groovyReturnStmtRe captures the expression of a `return <expr>` statement
// even when it does not start the line — the compact Groovy idiom
// `String getName(req) { return req.getParameter("n") }` keeps the body on
// the same line as the declaration. The capture group stops at `}` so the
// trailing brace of a single-line body isn't swept into the expression.
var groovyReturnStmtRe = regexp.MustCompile(`\breturn\s+([^}]+)`)

// AnalyzeCallerImpactGroovy mirrors AnalyzeCallerImpact (Go-specific) but
// uses tree-sitter to find Groovy call expressions in the caller body and
// the Groovy taint catalog to identify sinks / tainted returns inside the
// callee. Returns findings keyed by the same BATOU-INTERPROC-<CAT> rule IDs
// the Go / Python / JS / Lua / Swift paths use.
func AnalyzeCallerImpactGroovy(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string) []rules.Finding {
	return analyzeCallerImpactGroovyCached(cg, callerNode, calleeNode, callerContent, nil)
}

// analyzeCallerImpactGroovyCached is the cached variant for the cross-file
// pass. Pass nil for the uncached single-shot behaviour.
//
// The walk template (ensure sinks/returns -> extract caller body -> call
// sites -> Path A / Path B) lives in the shared core (crossfile_walk_core.go);
// this wrapper supplies the Groovy config (groovyCrossfileWalkCfg) and the
// call-site finder. Groovy's Path B stays behind the config's customPathB
// hook (checkGroovyCallerUsesTaintedReturn) because it fires an inline-sink
// and a via-variable case independently for one call site.
func analyzeCallerImpactGroovyCached(cg *CallGraph, callerNode, calleeNode *FuncNode, callerContent string, callIdx *groovyCallIndexCache) []rules.Finding {
	return analyzeCallerImpactCrossfile(
		groovyCrossfileWalkCfg, cg, callerNode, calleeNode, callerContent,
		func(content string, caller *FuncNode, calleeName string) []crossfileCallSite {
			return groovyCallSitesToShared(findGroovyCallSitesIndexed(callIdx, content, caller, calleeName))
		},
		callIdx.sanitizerMemo(),
	)
}

// groovyCallSitesToShared converts groovyCallSite rows to the shared
// crossfileCallSite shape consumed by the walk core.
func groovyCallSitesToShared(in []groovyCallSite) []crossfileCallSite {
	if len(in) == 0 {
		return nil
	}
	out := make([]crossfileCallSite, len(in))
	for i, cs := range in {
		out[i] = crossfileCallSite(cs)
	}
	return out
}

// ensureGroovyCalleeSinks lazily populates calleeNode.TaintSig.SinkCalls
// when it's empty. Idempotent.
func ensureGroovyCalleeSinks(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangGroovy {
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
	sinks := scanGroovyBodyForSinks(body, calleeNode.StartLine)
	if len(sinks) == 0 {
		return
	}
	bodyLines := strings.Split(body, "\n")
	for i := range sinks {
		lineIdx := sinks[i].Line - calleeNode.StartLine
		sinks[i].ArgFromParam = findGroovyParamFlowToSink(bodyLines, lineIdx, &calleeNode.TaintSig)
	}
	calleeNode.TaintSig.SinkCalls = sinks
	calleeNode.TaintSig.IsPure = false
	_ = cg
}

// ensureGroovyCalleeReturns lazily populates calleeNode.TaintSig.Tainted-
// Returns when empty by scanning the callee body for `return <source>`.
// This handles the canonical helper idiom where a method returns
// request-derived data. Idempotent.
func ensureGroovyCalleeReturns(cg *CallGraph, calleeNode *FuncNode) {
	if calleeNode == nil || calleeNode.Language != rules.LangGroovy {
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
	cat, found := scanGroovyBodyForTaintedReturn(body)
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

// scanGroovyBodyForTaintedReturn reports whether any `return` statement in
// the body carries a catalog source expression (`return req.getParameter("n")`,
// or `def v = params.id ... return v`). Returns the source category.
func scanGroovyBodyForTaintedReturn(body string) (taint.SourceCategory, bool) {
	lines := strings.Split(body, "\n")
	// Track variables bound to a source expression so `def v = source;
	// return v` is recognised.
	taintedVars := map[string]bool{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Record `def x = <source>` / `x = <source>` bindings.
		if eq := groovyAssignEq(trimmed); eq > 0 {
			lhs := strings.TrimSpace(trimmed[:eq])
			rhs := trimmed[eq+1:]
			if groovySourceExprRe.MatchString(rhs) && !groovySanitizerRe.MatchString(rhs) {
				name := groovyBindingName(lhs)
				if name != "" {
					taintedVars[name] = true
				}
			}
		}
		// Match `return <expr>` anywhere on the line — Groovy commonly keeps
		// a single-line body on the same line as the `... {` declaration.
		for _, m := range groovyReturnStmtRe.FindAllStringSubmatch(trimmed, -1) {
			expr := strings.TrimSpace(m[1])
			if expr == "" {
				continue
			}
			if groovySanitizerRe.MatchString(expr) {
				continue
			}
			if groovySourceExprRe.MatchString(expr) {
				return taint.SrcUserInput, true
			}
			// `return v` where v was bound to a source above.
			retVar := groovyLastIdent(expr)
			if retVar != "" && taintedVars[retVar] {
				return taint.SrcUserInput, true
			}
		}
	}
	return "", false
}

// groovyAssignEq returns the index of the single `=` assignment operator in
// a line, or -1 when the line isn't a plain assignment (skips ==, !=, <=,
// >=, =~ and the Groovy spaceship/elvis-adjacent forms).
func groovyAssignEq(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		// Skip ==, =~, =>.
		if i+1 < len(line) && (line[i+1] == '=' || line[i+1] == '~' || line[i+1] == '>') {
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

// groovyBindingName returns the bound variable name from an LHS that may
// carry a `def` / type keyword (`def n` → "n", `String n` → "n"). The
// binding name is the trailing identifier token.
func groovyBindingName(lhs string) string {
	return groovyLastIdent(lhs)
}

// scanGroovyBodyForSinks walks the body line-by-line with each cached
// groovySinkPattern. Returns SinkRef rows with file-absolute line numbers.
func scanGroovyBodyForSinks(body string, startLine int) []SinkRef {
	patterns := loadGroovySinkPatterns()
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
			// argument is wrapped in a numeric coercion / encoder is safe.
			if groovySanitizerRe.MatchString(line) && groovySinkLineSanitizerNeutralises(p.category) {
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

// groovySinkLineSanitizerNeutralises returns true for sink categories whose
// matched-on-the-same-line sanitiser call should suppress the sink.
func groovySinkLineSanitizerNeutralises(c taint.SinkCategory) bool {
	switch c {
	case taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput,
		taint.SnkRedirect, taint.SnkTemplate, taint.SnkFileRead,
		taint.SnkFileWrite, taint.SnkURLFetch:
		return true
	}
	return false
}

// findGroovyParamFlowToSink returns the source-param index whose name
// appears in the sink line's argument expression, or -1 when none do.
func findGroovyParamFlowToSink(lines []string, sinkLineIdx int, sig *TaintSignature) int {
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

// checkGroovyCallerUsesTaintedReturn is the Groovy analog of
// checkSwiftCallerUsesTaintedReturn (Path B). Triggers when the callee has
// TaintedReturns and the caller passes the result to a sink — either via an
// intermediate variable (`def n = getName(req); run(n)`) or inlined
// directly (`run(getName(req))`). The milestone shape is the intermediate-
// variable form where the caller is a Groovy SCRIPT.
func checkGroovyCallerUsesTaintedReturn(
	callerNode, calleeNode *FuncNode,
	calleeSig *TaintSignature,
	cs groovyCallSite,
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
	patterns := loadGroovySinkPatterns()

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
				"Sanitize the value returned by %s() (e.g. coerce to a number or use a parameterized / list-arg API) before passing it to %s.",
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
				"return-taint", "groovy", string(cat),
			},
		})
	}

	// Case 1: inlined sink — the callee call itself is an argument to a sink
	// on the SAME line (`run(getName(req))`).
	if callLineIdx >= 0 && callLineIdx < len(callerLines) {
		line := callerLines[callLineIdx]
		for _, p := range patterns {
			if !p.pattern.MatchString(line) {
				continue
			}
			if groovySanitizerRe.MatchString(line) && groovySinkLineSanitizerNeutralises(p.category) {
				continue
			}
			emit(callLineNum, p.method, p.category,
				fmt.Sprintf("result of %s(...) passed inline to sink", calleeBaseName))
		}
	}

	// Case 2: intermediate variable — `def n = getName(req)` then a later
	// line uses n in a sink (the milestone: `"cmd $n".execute()`).
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
				if groovySanitizerRe.MatchString(callerLines[j]) && containsToken(callerLines[j], returnVar) {
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
				if groovySanitizerRe.MatchString(line) && groovySinkLineSanitizerNeutralises(p.category) {
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

// groovyRootIdent returns the leading variable name of an expression,
// stripping a `.field` / `[index]` / `(args)` tail (`req.query` → "req").
func groovyRootIdent(expr string) string {
	root := strings.TrimSpace(expr)
	root = strings.TrimPrefix(root, "def ")
	if i := strings.IndexAny(root, ".[("); i > 0 {
		root = root[:i]
	}
	return strings.TrimSpace(root)
}
